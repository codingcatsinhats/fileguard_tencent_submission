"""Audit upgrades tests: restricted fields (commitments, side table, purge),
audit query API (filters, pagination, CSV/JSON export), G16 scenario,
chain verification after restricted fields."""

import json
import os
import sys
import sqlite3
import time
import hashlib
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))
sys.path.insert(0, str(_REPO / "simulators"))
sys.path.insert(0, str(_REPO / "demo-seed"))

from fileguard import db, security, config  # noqa: E402
from fileguard.audit_restricted import (  # noqa: E402
    generate_salt,
    compute_commitment,
    store_restricted,
    retrieve_restricted,
    verify_commitment,
    purge_restricted,
    get_restricted_fields_for_entry,
    is_restricted_field,
    store_all_restricted,
    init_side_table,
    RESTRICTED_FIELDS,
)
from fileguard.audit_query import (  # noqa: E402
    AuditQuery,
    AuditQueryResult,
    query_audit,
    query_who_accessed,
    query_user_access,
    export_csv,
    export_json,
    resolve_restricted_fields,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def isolated_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("FILEGUARD_DATA_DIR", str(tmp_path))
    yield


@pytest.fixture
def conn():
    c = db.central()
    init_side_table(c)
    yield c
    c.close()


def _append_entry(conn, payload: dict, ts: int | None = None) -> dict:
    """Helper: append an audit log entry and return {seq, entry_hash}."""
    return db.append_log(conn, payload, ts=ts)


# ---------------------------------------------------------------------------
# Restricted field commitment tests
# ---------------------------------------------------------------------------

def test_generate_salt_unique():
    s1 = generate_salt()
    s2 = generate_salt()
    assert s1 != s2
    assert len(s1) == 64  # 32 bytes hex


def test_compute_commitment_deterministic():
    salt = "a" * 64
    text = "payment outage root cause"
    c1 = compute_commitment(salt, text)
    c2 = compute_commitment(salt, text)
    assert c1 == c2
    assert len(c1) == 64  # sha256 hex


def test_compute_commitment_different_salt():
    text = "secret answer"
    c1 = compute_commitment("salt1", text)
    c2 = compute_commitment("salt2", text)
    assert c1 != c2


def test_compute_commitment_different_text():
    salt = "b" * 64
    c1 = compute_commitment(salt, "answer one")
    c2 = compute_commitment(salt, "answer two")
    assert c1 != c2


def test_is_restricted_field():
    assert is_restricted_field("raw_user_input")
    assert is_restricted_field("search_terms")
    assert is_restricted_field("answer_text")
    assert not is_restricted_field("reason")
    assert not is_restricted_field("user_id")


def test_store_and_retrieve_restricted(conn):
    """Store a restricted field in the side table and retrieve it."""
    entry = _append_entry(conn, {
        "event": "response",
        "user_id": "maya",
        "answer_text_commit": "",  # will be replaced
    })
    entry_id = entry["seq"]

    commitment = store_restricted(conn, entry_id, "answer_text", "The root cause was pool exhaustion.")
    assert len(commitment) == 64

    retrieved = retrieve_restricted(conn, entry_id, "answer_text")
    assert retrieved == "The root cause was pool exhaustion."


def test_store_restricted_returns_commitment(conn):
    """The returned commitment matches the salt+text."""
    entry = _append_entry(conn, {"event": "response", "user_id": "maya"})
    entry_id = entry["seq"]

    salt = "c" * 64
    text = "search terms here"
    commitment = store_restricted(conn, entry_id, "search_terms", text, salt)
    expected = compute_commitment(salt, text)
    assert commitment == expected


def test_verify_commitment(conn):
    """Verify the commitment matches the side-table data."""
    entry = _append_entry(conn, {"event": "response", "user_id": "maya"})
    entry_id = entry["seq"]

    salt = "d" * 64
    text = "raw user input text"
    commitment = store_restricted(conn, entry_id, "raw_user_input", text, salt)

    assert verify_commitment(conn, entry_id, "raw_user_input", commitment)


def test_verify_commitment_wrong_value(conn):
    """A wrong commitment should not verify."""
    entry = _append_entry(conn, {"event": "response", "user_id": "maya"})
    entry_id = entry["seq"]

    store_restricted(conn, entry_id, "answer_text", "correct answer")
    wrong_commitment = "0" * 64

    assert not verify_commitment(conn, entry_id, "answer_text", wrong_commitment)


def test_purge_restricted(conn):
    """Purging removes the plaintext but the chain commitment stays."""
    entry = _append_entry(conn, {"event": "response", "user_id": "maya"})
    entry_id = entry["seq"]

    commitment = store_restricted(conn, entry_id, "answer_text", "sensitive answer")
    store_restricted(conn, entry_id, "search_terms", "search query")

    # Purge just answer_text
    count = purge_restricted(conn, entry_id, "answer_text", purged_by="admin", reason="retention")
    assert count == 1

    # Plaintext is gone
    assert retrieve_restricted(conn, entry_id, "answer_text") is None
    # search_terms still there
    assert retrieve_restricted(conn, entry_id, "search_terms") is not None

    # verify_commitment returns True for purged (commitment stays in chain)
    assert verify_commitment(conn, entry_id, "answer_text", commitment)


def test_purge_all_fields(conn):
    """Purging all restricted fields for an entry."""
    entry = _append_entry(conn, {"event": "response", "user_id": "maya"})
    entry_id = entry["seq"]

    store_restricted(conn, entry_id, "answer_text", "answer")
    store_restricted(conn, entry_id, "search_terms", "query")
    store_restricted(conn, entry_id, "raw_user_input", "prompt")

    count = purge_restricted(conn, entry_id, purged_by="admin", reason="retention")
    assert count == 3

    assert retrieve_restricted(conn, entry_id, "answer_text") is None
    assert retrieve_restricted(conn, entry_id, "search_terms") is None
    assert retrieve_restricted(conn, entry_id, "raw_user_input") is None


def test_purge_logs_audit_entry(conn):
    """Purging creates an audit log entry recording who/when/why."""
    entry = _append_entry(conn, {"event": "response", "user_id": "maya"})
    entry_id = entry["seq"]

    store_restricted(conn, entry_id, "answer_text", "answer")

    purge_restricted(conn, entry_id, "answer_text", purged_by="priya", reason="30-day retention")

    # Check the purge was logged
    rows = conn.execute(
        "SELECT payload FROM audit_log WHERE json_extract(payload, '$.event') = 'purge_restricted'"
    ).fetchall()
    assert len(rows) == 1
    payload = json.loads(rows[0][0])
    assert payload["purged_by"] == "priya"
    assert payload["reason"] == "30-day retention"
    assert payload["purged_count"] == 1
    assert payload["entry_id"] == entry_id


def test_store_all_restricted(conn):
    """Store multiple restricted fields at once."""
    entry = _append_entry(conn, {"event": "response", "user_id": "maya"})
    entry_id = entry["seq"]

    fields = {
        "answer_text": "The root cause was pool exhaustion.",
        "search_terms": "payment outage",
        "raw_user_input": "What caused the payment outage?",
    }

    commitments = store_all_restricted(conn, entry_id, fields)

    assert len(commitments) == 3
    for field in fields:
        assert field in commitments
        assert len(commitments[field]) == 64

    # Verify all can be retrieved
    for field, text in fields.items():
        assert retrieve_restricted(conn, entry_id, field) == text


def test_store_all_restricted_with_salts(conn):
    """Store with explicit salts (for reconciliation)."""
    entry = _append_entry(conn, {"event": "response", "user_id": "maya"})
    entry_id = entry["seq"]

    salt1 = "e" * 64
    salt2 = "f" * 64

    fields = {"answer_text": "answer", "search_terms": "query"}
    salts = {"answer_text": salt1, "search_terms": salt2}

    commitments = store_all_restricted(conn, entry_id, fields, salts)

    # Commitments should match the expected values
    assert commitments["answer_text"] == compute_commitment(salt1, "answer")
    assert commitments["search_terms"] == compute_commitment(salt2, "query")


def test_get_restricted_fields_for_entry(conn):
    """Get metadata about restricted fields without plaintext."""
    entry = _append_entry(conn, {"event": "response", "user_id": "maya"})
    entry_id = entry["seq"]

    store_restricted(conn, entry_id, "answer_text", "answer")
    store_restricted(conn, entry_id, "search_terms", "query")

    fields = get_restricted_fields_for_entry(conn, entry_id)
    assert len(fields) == 2
    field_names = [f["field"] for f in fields]
    assert "answer_text" in field_names
    assert "search_terms" in field_names

    # All should be available (not purged)
    for f in fields:
        assert f["available"]
        assert not f["purged"]

    # Purge one and check
    purge_restricted(conn, entry_id, "answer_text", purged_by="admin", reason="test")
    fields = get_restricted_fields_for_entry(conn, entry_id)
    for f in fields:
        if f["field"] == "answer_text":
            assert not f["available"]
            assert f["purged"]


def test_chain_verifies_after_restricted_fields(conn):
    """The hash chain still verifies after storing and purging restricted fields."""
    entry1 = _append_entry(conn, {
        "event": "response",
        "user_id": "maya",
        "answer_text_commit": store_restricted(conn, 1, "answer_text", "answer 1"),
    })
    entry2 = _append_entry(conn, {
        "event": "response",
        "user_id": "raj",
        "answer_text_commit": store_restricted(conn, 2, "answer_text", "answer 2"),
    })

    # Purge one
    purge_restricted(conn, 1, "answer_text", purged_by="admin", reason="test")

    # Chain should still verify
    ok, n = db.verify_chain(conn)
    assert ok
    assert n >= 3  # 2 entries + purge entry


# ---------------------------------------------------------------------------
# Audit query API tests
# ---------------------------------------------------------------------------

def _seed_audit_entries(conn):
    """Seed the audit log with a variety of entries for query tests."""
    now = int(time.time())

    # jdoe accessing PAYGW items (7 entries, within 30 days)
    for i in range(7):
        days_ago = i + 1
        _append_entry(conn, {
            "event": "response",
            "user_id": "jdoe",
            "session_id": f"sess-{i}",
            "tool": "get_content",
            "platform": "confluence",
            "container": "PAYGW",
            "item_id": f"CF-PAYGW-{i}",
            "item_version": f"v{i+1}",
            "entry_clearance": "confidential",
            "returned": [{"kind": "section", "start": 0, "end": 1}],
        }, ts=now - days_ago * 86400)

    # Entry 35 days ago (outside 30-day window)
    _append_entry(conn, {
        "event": "response",
        "user_id": "jdoe",
        "session_id": "sess-old",
        "tool": "get_content",
        "platform": "confluence",
        "container": "PAYGW",
        "item_id": "CF-PAYGW-OLD",
        "item_version": "v1",
        "entry_clearance": "confidential",
        "returned": [{"kind": "section", "start": 0, "end": 1}],
    }, ts=now - 35 * 86400)

    # jdoe in other spaces (3 entries)
    for i in range(3):
        _append_entry(conn, {
            "event": "response",
            "user_id": "jdoe",
            "session_id": f"sess-other-{i}",
            "tool": "get_content",
            "platform": "confluence",
            "container": "PAY-DOCS",
            "item_id": f"CF-DOC-{i}",
            "item_version": "v1",
            "entry_clearance": "confidential",
            "returned": [{"kind": "section", "start": 0, "end": 1}],
        }, ts=now - (i + 1) * 86400)

    # A denial
    _append_entry(conn, {
        "event": "rejection",
        "user_id": "tom",
        "session_id": "sess-denied",
        "tool": "get_content",
        "platform": "confluence",
        "container": "SEC",
        "item_id": "CF-SEC-Q3",
        "entry_clearance": "secret",
        "code": "NO_GROUP_ACCESS",
        "warning": False,
        "detail": "access denied",
    }, ts=now - 2 * 86400)

    # A secret access
    _append_entry(conn, {
        "event": "response",
        "user_id": "lena",
        "session_id": "sess-secret",
        "tool": "get_content",
        "platform": "confluence",
        "container": "SEC",
        "item_id": "CF-SEC-Q3",
        "item_version": "v1",
        "entry_clearance": "secret",
        "returned": [{"kind": "section", "start": 0, "end": 1}],
    }, ts=now - 1 * 86400)


def test_query_filter_by_user(conn):
    _seed_audit_entries(conn)
    result = query_audit(conn, AuditQuery(user_id="jdoe", limit=100), audit_level="top_secret")
    assert result.total >= 11  # 7 PAYGW + 1 old + 3 other
    for e in result.entries:
        assert e["user_id"] == "jdoe"


def test_query_filter_by_platform(conn):
    _seed_audit_entries(conn)
    result = query_audit(conn, AuditQuery(platform="confluence", limit=100), audit_level="top_secret")
    assert result.total >= 12
    for e in result.entries:
        assert e["platform"] == "confluence"


def test_query_filter_by_container(conn):
    _seed_audit_entries(conn)
    result = query_audit(conn, AuditQuery(container="PAYGW", limit=100), audit_level="top_secret")
    assert result.total >= 8  # 7 within 30 days + 1 old
    for e in result.entries:
        assert e["container"] == "PAYGW"


def test_query_filter_by_item_id(conn):
    _seed_audit_entries(conn)
    result = query_audit(conn, AuditQuery(item_id="CF-SEC-Q3", limit=100), audit_level="top_secret")
    assert result.total >= 2  # denial + secret access


def test_query_filter_by_decision_allowed(conn):
    _seed_audit_entries(conn)
    result = query_audit(conn, AuditQuery(decision="allowed", limit=100), audit_level="top_secret")
    for e in result.entries:
        assert e["event"] == "response"


def test_query_filter_by_decision_denied(conn):
    _seed_audit_entries(conn)
    result = query_audit(conn, AuditQuery(decision="denied", limit=100), audit_level="top_secret")
    for e in result.entries:
        assert e["event"] in ("rejection", "abuse_block")


def test_query_filter_by_event_type(conn):
    _seed_audit_entries(conn)
    result = query_audit(conn, AuditQuery(event_type="rejection", limit=100), audit_level="top_secret")
    assert result.total >= 1
    for e in result.entries:
        assert e["event"] == "rejection"


def test_query_filter_by_date_range(conn):
    """Filter by date range — G16 scenario: last 30 days only."""
    _seed_audit_entries(conn)
    now = time.time()
    result = query_audit(conn, AuditQuery(
        user_id="jdoe",
        platform="confluence",
        container="PAYGW",
        date_from=now - 30 * 86400,
        date_to=now,
        sort_by="ts",
        sort_desc=False,
        limit=100,
    ))
    # Should be exactly 7 (the old entry is 35 days ago)
    assert result.total == 7
    for e in result.entries:
        assert e["container"] == "PAYGW"
        assert e["user_id"] == "jdoe"


def test_query_pagination(conn):
    _seed_audit_entries(conn)
    page1 = query_audit(conn, AuditQuery(user_id="jdoe", limit=5, offset=0), audit_level="top_secret")
    page2 = query_audit(conn, AuditQuery(user_id="jdoe", limit=5, offset=5), audit_level="top_secret")
    assert len(page1.entries) == 5
    assert len(page2.entries) == 5
    # No overlap
    seqs1 = {e["seq"] for e in page1.entries}
    seqs2 = {e["seq"] for e in page2.entries}
    assert not (seqs1 & seqs2)


def test_query_sort_ascending(conn):
    _seed_audit_entries(conn)
    result = query_audit(conn, AuditQuery(
        sort_by="ts", sort_desc=False, limit=10,
    ), audit_level="top_secret")
    timestamps = [e["ts"] for e in result.entries]
    assert timestamps == sorted(timestamps)


def test_query_who_accessed(conn):
    """'Who retrieved this document?' query."""
    _seed_audit_entries(conn)
    entries = query_who_accessed(conn, "confluence", "CF-SEC-Q3", audit_level="top_secret")
    assert len(entries) >= 1
    for e in entries:
        assert e["event"] == "response"


def test_query_user_access(conn):
    """'What did this user access?' query — G16 scenario."""
    _seed_audit_entries(conn)
    now = time.time()
    entries = query_user_access(
        conn,
        user_id="jdoe",
        audit_level="top_secret",
        platform="confluence",
        container="PAYGW",
        date_from=now - 30 * 86400,
        date_to=now,
    )
    # G16: exactly the 7 seeded entries within 30 days
    assert len(entries) == 7
    for e in entries:
        assert e["user_id"] == "jdoe"
        assert e["container"] == "PAYGW"


def test_query_standard_auditor_hides_secret(conn):
    """Standard auditor cannot see secret-level accesses."""
    _seed_audit_entries(conn)
    result = query_audit(conn, AuditQuery(limit=100), audit_level="standard")
    # The secret entry (lena's access to SEC) should be omitted
    for e in result.entries:
        if e.get("entry_clearance") == "secret" and e.get("event") == "response":
            pytest.fail("standard auditor should not see secret accesses")


def test_query_top_secret_sees_everything(conn):
    """Top-secret auditor sees all entries including secret."""
    _seed_audit_entries(conn)
    result = query_audit(conn, AuditQuery(limit=100), audit_level="top_secret")
    has_secret = any(
        e.get("entry_clearance") == "secret" and e.get("event") == "response"
        for e in result.entries
    )
    assert has_secret


def test_query_standard_auditor_redacts_violations(conn):
    """Standard auditor sees violations but redacted."""
    _seed_audit_entries(conn)
    result = query_audit(conn, AuditQuery(
        event_type="rejection", limit=100,
    ), audit_level="standard")
    assert len(result.entries) >= 1
    for e in result.entries:
        assert e.get("redacted") is True
        # Sensitive fields should be listed as redacted
        assert "redacted_fields" in e


def test_query_no_audit_level_routine_only(conn):
    """Not signed in: routine entries only, no violations."""
    _seed_audit_entries(conn)
    result = query_audit(conn, AuditQuery(limit=100), audit_level=None)
    for e in result.entries:
        assert e.get("event") not in ("rejection", "abuse_block") or e.get("redacted")


def test_export_csv(conn):
    _seed_audit_entries(conn)
    result = query_audit(conn, AuditQuery(limit=5), audit_level="top_secret")
    csv_str = export_csv(result.entries)
    assert "user_id" in csv_str
    assert "event" in csv_str
    assert len(csv_str.splitlines()) > 1


def test_export_json(conn):
    _seed_audit_entries(conn)
    result = query_audit(conn, AuditQuery(limit=5), audit_level="top_secret")
    json_str = export_json(result.entries)
    parsed = json.loads(json_str)
    assert len(parsed) == len(result.entries)


def test_export_empty_csv():
    csv_str = export_csv([])
    assert csv_str == ""


def test_export_empty_json():
    json_str = export_json([])
    assert json.loads(json_str) == []


def test_resolve_restricted_fields(conn):
    """Resolve restricted field commitments from the side table."""
    entry_id = _append_entry(conn, {
        "event": "response",
        "user_id": "maya",
        "answer_text_commit": "",
    })["seq"]

    store_restricted(conn, entry_id, "answer_text", "The pool was exhausted.")
    store_restricted(conn, entry_id, "search_terms", "pool exhaustion")

    entry = {
        "seq": entry_id,
        "answer_text": "commitment_hash_placeholder",
        "search_terms": "another_hash",
    }
    resolved = resolve_restricted_fields(conn, entry)
    assert resolved["answer_text"] == "The pool was exhausted."
    assert resolved["search_terms"] == "pool exhaustion"


def test_resolve_restricted_fields_after_purge(conn):
    """After purge, the commitment stays (can't resolve plaintext)."""
    entry_id = _append_entry(conn, {
        "event": "response",
        "user_id": "maya",
    })["seq"]

    commitment = store_restricted(conn, entry_id, "answer_text", "secret answer")
    purge_restricted(conn, entry_id, "answer_text", purged_by="admin", reason="retention")

    entry = {"seq": entry_id, "answer_text": commitment}
    resolved = resolve_restricted_fields(conn, entry)
    # After purge, the commitment stays
    assert resolved["answer_text"] == commitment


def test_chain_verifies_after_queries(conn):
    """The hash chain verifies after all the query operations."""
    _seed_audit_entries(conn)
    ok, n = db.verify_chain(conn)
    assert ok
    assert n > 0


def test_g16_scenario(conn):
    """G16: Priya asks for everything jdoe accessed in PAYGW in the last 30 days.
    Must return exactly the 7 seeded entries."""
    _seed_audit_entries(conn)
    now = time.time()

    # Priya is a standard auditor (compliance officer)
    entries = query_user_access(
        conn,
        user_id="jdoe",
        audit_level="standard",
        platform="confluence",
        container="PAYGW",
        date_from=now - 30 * 86400,
        date_to=now,
    )
    # Standard auditor sees confidential entries (PAYGW is confidential)
    assert len(entries) == 7
    for e in entries:
        assert e["user_id"] == "jdoe"
        assert e["container"] == "PAYGW"
        # All within 30 days
        assert e["ts"] >= now - 30 * 86400
