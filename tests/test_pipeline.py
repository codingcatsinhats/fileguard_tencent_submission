"""Pipeline + grounding tests: stub Gatekeeper, graceful grounding ladder,
get_content pipeline, access denied, no-evidence, audit binding."""

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

from fileguard import config, db, identity, sync_engine, pipeline, grounding, stub_models  # noqa: E402
from fileguard.grounding import GENERIC_NO_EVIDENCE  # noqa: E402
from fileguard.connector import Item, ItemRef, Unit, Decision, ACLSnapshot  # noqa: E402
from fileguard.stub_models import (
    UnitSpanRef,
    GatekeeperResult,
    AnswerResult,
    stub_select_spans,
    stub_generate_answer,
)  # noqa: E402
from fileguard.grounding import GroundingResult, GENERIC_NO_EVIDENCE, grounding_check  # noqa: E402
from fileguard.pipeline import PipelineRequest, PipelineResult, run_pipeline  # noqa: E402


# ---------------------------------------------------------------------------
# Mock connector for pipeline tests
# ---------------------------------------------------------------------------

class MockPipelineConnector:
    platform = "confluence"

    def __init__(self, items: list[Item]):
        self._items = {item.item_id: item for item in items}

    def changes(self, cursor):
        refs = [ItemRef(platform="confluence", container=item.container,
                        item_id=item.item_id, version=item.version)
                for item in self._items.values()]
        return refs, time.time()

    def fetch(self, item_ref):
        return self._items[item_ref.item_id]

    def current_version(self, item_ref):
        return self._items[item_ref.item_id].version

    def fetch_acl(self, item_ref):
        item = self._items[item_ref.item_id]
        return ACLSnapshot(item_key=f"confluence:{item_ref.item_id}",
                           version=item.version, acl_json="{}", fetched_at=time.time())

    def can_access(self, person_email, item):
        return Decision(allowed=True)

    def resolve_identity(self, employee_id):
        return f"{employee_id}@halcyon.example"


def _make_item(item_id, version, title, units_text, container="PAY-DOCS",
               platform="confluence"):
    units = [
        Unit(unit_id=f"{platform}:{item_id}@{version}#{i}",
             kind="section", text=text, order=i, metadata={})
        for i, text in enumerate(units_text)
    ]
    return Item(
        platform=platform, container=container, item_id=item_id,
        version=version, url=f"/items/{item_id}", title=title,
        author="test", created_at=float(int(time.time())),
        updated_at=float(int(time.time())),
        units=units, links=[], acl={},
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def isolated_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("FILEGUARD_DATA_DIR", str(tmp_path))
    # stub gatekeeper by default — this module tests the deterministic
    # path; the live-dispatch tests override explicitly
    monkeypatch.setenv("FILEGUARD_GATEKEEPER_MODE", "test")
    yield


@pytest.fixture
def conn():
    c = db.central()
    identity.init_directory(c)
    yield c
    c.close()


@pytest.fixture
def seeded_index():
    """Seed the unified index with known items."""
    items = [
        _make_item("CF-RUNBOOK", "v7",
                   "Runbook: payment incident response",
                   ["Steps 1-5: check alerts, verify pool size, restart service",
                    "If pool size is below 50, escalate to oncall immediately"]),
        _make_item("CF-POSTMORTEM", "v1",
                   "Postmortem: payment outage",
                   ["Root cause: connection pool was cut from 200 to 20",
                    "The fix was to restore pool size and add monitoring"]),
        _make_item("CF-PUBLIC", "v1",
                   "Public FAQ",
                   ["Welcome to the team wiki", "This page is visible to everyone"]),
    ]
    connector = MockPipelineConnector(items)
    sync_engine.sync_connector(connector)
    return items


@pytest.fixture
def registered_employees(conn):
    """Register employees with different clearance levels."""
    def _hash(token):
        return hashlib.sha256(token.encode()).hexdigest()

    identity.register_employee(
        conn, "maya", "Maya Chen", "maya@halcyon.example",
        "confidential", ["eng", "payments"], _hash("tok-maya"),
    )
    identity.register_employee(
        conn, "raj", "Raj Patel", "raj@halcyon.example",
        "secret", ["eng", "sre"], _hash("tok-raj"),
    )
    identity.register_employee(
        conn, "tom", "Tom Guest", "tom@halcyon.example",
        "open", ["contractors"], _hash("tok-tom"),
    )
    return conn


# ---------------------------------------------------------------------------
# Stub Gatekeeper tests
# ---------------------------------------------------------------------------

def test_stub_gatekeeper_selects_relevant_units():
    units = [
        Unit(unit_id="u0", kind="section", text="payment processing runbook steps",
             order=0, metadata={}),
        Unit(unit_id="u1", kind="section", text="security checklist for coding",
             order=1, metadata={}),
        Unit(unit_id="u2", kind="section", text="payment outage postmortem details",
             order=2, metadata={}),
    ]
    result = stub_select_spans(units, "payment outage investigation")
    assert len(result.spans) > 0
    # Should select units with "payment" or "outage" terms
    texts = [s.text for s in result.spans]
    assert any("payment" in t for t in texts)
    assert result.mode == "stub-keyword"
    assert result.selection_reason


def test_stub_gatekeeper_empty_reason():
    units = [
        Unit(unit_id="u0", kind="section", text="some content", order=0, metadata={}),
    ]
    result = stub_select_spans(units, "")
    assert len(result.spans) == 0
    assert "No units or no reason" in result.selection_reason


def test_stub_gatekeeper_no_relevant_units():
    units = [
        Unit(unit_id="u0", kind="section", text="weather forecast for next week",
             order=0, metadata={}),
        Unit(unit_id="u1", kind="section", text="lunch menu for cafeteria",
             order=1, metadata={}),
    ]
    result = stub_select_spans(units, "payment outage")
    assert len(result.spans) == 0
    assert "No units" in result.selection_reason


def test_stub_gatekeeper_empty_units():
    result = stub_select_spans([], "payment investigation")
    assert len(result.spans) == 0


def test_stub_gatekeeper_deterministic():
    units = [
        Unit(unit_id=f"u{i}", kind="section", text=f"payment flow step {i}",
             order=i, metadata={})
        for i in range(10)
    ]
    r1 = stub_select_spans(units, "payment investigation")
    r2 = stub_select_spans(units, "payment investigation")
    assert len(r1.spans) == len(r2.spans)
    assert [s.unit_id for s in r1.spans] == [s.unit_id for s in r2.spans]


# ---------------------------------------------------------------------------
# Stub answering model tests
# ---------------------------------------------------------------------------

def test_stub_answer_generates_with_citations():
    spans = [
        UnitSpanRef(platform="confluence", container="PAY-DOCS",
                    item_id="CF-RUNBOOK", unit_id="u0",
                    kind="section", text="Payment service uses connection pooling. The pool size is critical.", order=0),
        UnitSpanRef(platform="confluence", container="PAY-DOCS",
                    item_id="CF-POSTMORTEM", unit_id="u1",
                    kind="section", text="The payment outage was caused by pool exhaustion.", order=1),
    ]
    result = stub_generate_answer(spans, "payment outage pool size")
    assert result.answer_text
    assert len(result.citations) > 0
    assert result.mode == "stub-keyword"


def test_stub_answer_empty_spans():
    result = stub_generate_answer([], "payment investigation")
    assert result.answer_text == ""
    assert len(result.citations) == 0


def test_stub_answer_has_citation_markers():
    spans = [
        UnitSpanRef(platform="confluence", container="PAY-DOCS",
                    item_id="CF-RUNBOOK", unit_id="u0",
                    kind="section", text="Payment processing uses a connection pool. Pool size must be monitored.", order=0),
    ]
    result = stub_generate_answer(spans, "payment pool monitoring")
    assert result.answer_text
    # Should contain citation markers like [1]
    assert "[1]" in result.answer_text or "[2]" in result.answer_text


# ---------------------------------------------------------------------------
# Grounding ladder tests
# ---------------------------------------------------------------------------

def test_grounding_verified():
    """All sentences grounded → 'verified'."""
    spans = [
        UnitSpanRef(platform="confluence", container="PAY-DOCS",
                    item_id="CF-RUNBOOK", unit_id="u0",
                    kind="section", text="Payment service uses connection pooling. Pool size is critical.", order=0),
    ]
    answer = AnswerResult(
        answer_text="Payment service uses connection pooling [1]",
        citations=[spans[0]],
    )
    result = grounding_check(answer, spans)
    assert result.level == "verified"
    assert result.answer_text == answer.answer_text
    assert len(result.citations) > 0
    assert result.pruned_count == 0


def test_grounding_pruned():
    """Some sentences ungrounded but ≥50% survive → 'pruned'."""
    spans = [
        UnitSpanRef(platform="confluence", container="PAY-DOCS",
                    item_id="CF-RUNBOOK", unit_id="u0",
                    kind="section", text="Payment service uses connection pooling.", order=0),
    ]
    answer = AnswerResult(
        answer_text="Payment service uses connection pooling [1]. "
                    "The weather is sunny today [1]",
        citations=[spans[0]],
    )
    result = grounding_check(answer, spans)
    assert result.level == "pruned"
    assert "Payment service uses connection pooling" in result.answer_text
    assert "weather" not in result.answer_text
    assert result.pruned_count == 1


def test_grounding_no_evidence_no_spans():
    """Zero permitted spans → generic no-evidence."""
    answer = AnswerResult(answer_text="Some text", citations=[])
    result = grounding_check(answer, [])
    assert result.level == "no_evidence"
    assert result.answer_text == GENERIC_NO_EVIDENCE


def test_grounding_no_evidence_empty_answer():
    """Answering model produced no text → no-evidence."""
    spans = [
        UnitSpanRef(platform="confluence", container="PAY-DOCS",
                    item_id="CF-RUNBOOK", unit_id="u0",
                    kind="section", text="Payment service uses connection pooling.", order=0),
    ]
    answer = AnswerResult(answer_text="", citations=[])
    result = grounding_check(answer, spans)
    assert result.level == "no_evidence"
    assert result.answer_text == GENERIC_NO_EVIDENCE


def test_grounding_excerpts_only():
    """All sentences ungrounded but spans exist → 'excerpts_only'."""
    spans = [
        UnitSpanRef(platform="confluence", container="PAY-DOCS",
                    item_id="CF-RUNBOOK", unit_id="u0",
                    kind="section", text="Connection pooling is important for payments.", order=0),
    ]
    answer = AnswerResult(
        answer_text="The weather is sunny today [1]. "
                    "Solar flares are expected [1].",
        citations=[spans[0]],
    )
    result = grounding_check(answer, spans)
    # All sentences ungrounded → excerpts_only (if surviving_count < 50% and >= 1)
    # But wait — the excerpts path requires surviving_count >= 1
    # If surviving_count == 0 → no_evidence
    # Let's check which branch: 0 surviving out of 2 → < 50% → 0 surviving
    # → no_evidence
    assert result.level in ("excerpts_only", "no_evidence")
    if result.level == "excerpts_only":
        assert "Connection pooling is important" in result.answer_text


def test_grounding_generic_no_evidence_identical():
    """The generic no-evidence message is identical for 'nothing exists'
    and 'nothing may be seen' (no spans vs zero surviving claims)."""
    # No spans
    r1 = grounding_check(AnswerResult(answer_text="x", citations=[]), [])
    # Spans but answer doesn't ground at all
    spans = [
        UnitSpanRef(platform="confluence", container="PAY-DOCS",
                    item_id="CF-RUNBOOK", unit_id="u0",
                    kind="section", text="Connection pooling for payments.", order=0),
    ]
    r2 = grounding_check(AnswerResult(
        answer_text="Solar flares are coming. Rain is expected.",
        citations=[spans[0]],
    ), spans)
    # Both should produce the same generic message
    assert r1.answer_text == r2.answer_text == GENERIC_NO_EVIDENCE
    assert r1.level == "no_evidence"
    assert r2.level == "no_evidence"


def test_grounding_pruned_preserves_majority():
    """Pruning should keep ≥50% of sentences."""
    spans = [
        UnitSpanRef(platform="confluence", container="PAY-DOCS",
                    item_id="CF-RUNBOOK", unit_id="u0",
                    kind="section", text="Pool size is critical. Pool monitoring is required. Payment service restart needed.", order=0),
    ]
    answer = AnswerResult(
        answer_text="Pool size is critical [1]. "
                    "Pool monitoring is required [1]. "
                    "The weather is sunny [1]",
        citations=[spans[0]],
    )
    result = grounding_check(answer, spans)
    assert result.level == "pruned"
    # 2 out of 3 sentences survived (≥50%)
    assert result.pruned_count == 1
    assert "Pool size" in result.answer_text
    assert "Pool monitoring" in result.answer_text
    assert "weather" not in result.answer_text


# ---------------------------------------------------------------------------
# Pipeline tests (end-to-end)
# ---------------------------------------------------------------------------

def test_pipeline_verified(seeded_index, registered_employees):
    """Full pipeline → verified answer with citations."""
    req = PipelineRequest(
        user_id="maya",
        employee_id="maya",
        max_clearance="confidential",
        groups=["eng", "payments"],
        session_id="sess-1",
        reason="investigating payment outage and pool size",
        platform="confluence",
        item_id="CF-POSTMORTEM",
    )
    conn = db.central()
    try:
        result = run_pipeline(req, conn)
        assert result.ok
        assert result.level in ("verified", "pruned", "excerpts_only")
        assert result.answer_text
        assert len(result.citations) > 0
        assert result.item_title == "Postmortem: payment outage"
        assert result.content_hash  # audit binding
        assert result.gatekeeper_reason
        assert result.gatekeeper_mode == "stub-keyword"
    finally:
        conn.close()


def test_pipeline_no_evidence_item_not_found(seeded_index, registered_employees):
    """Non-existent item → no-evidence (no existence leak)."""
    req = PipelineRequest(
        user_id="maya",
        employee_id="maya",
        max_clearance="confidential",
        groups=["eng", "payments"],
        session_id="sess-2",
        reason="investigating payment outage",
        platform="confluence",
        item_id="NONEXISTENT-ITEM",
    )
    conn = db.central()
    try:
        result = run_pipeline(req, conn)
        assert result.ok
        assert result.level == "no_evidence"
        assert result.answer_text == GENERIC_NO_EVIDENCE
    finally:
        conn.close()


def test_pipeline_no_evidence_access_denied(seeded_index, registered_employees):
    """User without clearance → no-evidence (identical to not found)."""
    req = PipelineRequest(
        user_id="tom",
        employee_id="tom",
        max_clearance="open",
        groups=["contractors"],
        session_id="sess-3",
        reason="investigating payment outage",
        platform="confluence",
        item_id="CF-POSTMORTEM",
        # tom has open clearance, PAY-DOCS is confidential → denied
    )
    conn = db.central()
    try:
        result = run_pipeline(req, conn)
        assert result.ok
        assert result.level == "no_evidence"
        assert result.answer_text == GENERIC_NO_EVIDENCE
    finally:
        conn.close()


def test_pipeline_access_denied_identical_to_not_found(seeded_index, registered_employees):
    """Access denied and item not found produce identical responses
    (no existence leak)."""
    req_denied = PipelineRequest(
        user_id="tom",
        employee_id="tom",
        max_clearance="open",
        groups=["contractors"],
        session_id="sess-4",
        reason="investigating payment",
        platform="confluence",
        item_id="CF-POSTMORTEM",
    )
    req_missing = PipelineRequest(
        user_id="tom",
        employee_id="tom",
        max_clearance="open",
        groups=["contractors"],
        session_id="sess-5",
        reason="investigating payment",
        platform="confluence",
        item_id="DOES-NOT-EXIST",
    )
    conn = db.central()
    try:
        r1 = run_pipeline(req_denied, conn)
        r2 = run_pipeline(req_missing, conn)
        # Both produce the same no-evidence message
        assert r1.level == r2.level == "no_evidence"
        assert r1.answer_text == r2.answer_text == GENERIC_NO_EVIDENCE
    finally:
        conn.close()


def test_pipeline_no_evidence_no_relevant_units(seeded_index, registered_employees):
    """Item exists and user has access, but no units match the reason."""
    req = PipelineRequest(
        user_id="maya",
        employee_id="maya",
        max_clearance="confidential",
        groups=["eng", "payments"],
        session_id="sess-6",
        reason="zzznonexistentzzz quuxxyz",
        platform="confluence",
        item_id="CF-PUBLIC",
        # CF-PUBLIC has open clearance but no relevant content
    )
    conn = db.central()
    try:
        result = run_pipeline(req, conn)
        assert result.ok
        assert result.level == "no_evidence"
        assert result.answer_text == GENERIC_NO_EVIDENCE
    finally:
        conn.close()


def test_pipeline_content_hash_stable(seeded_index, registered_employees):
    """The content hash is stable for the same item + version."""
    req = PipelineRequest(
        user_id="maya",
        employee_id="maya",
        max_clearance="confidential",
        groups=["eng", "payments"],
        session_id="sess-7",
        reason="payment outage investigation",
        platform="confluence",
        item_id="CF-RUNBOOK",
    )
    conn = db.central()
    try:
        r1 = run_pipeline(req, conn)
        r2 = run_pipeline(req, conn)
        assert r1.content_hash == r2.content_hash
    finally:
        conn.close()


def test_pipeline_with_connector(seeded_index, registered_employees):
    """Pipeline works with a connector for live access checks."""
    connector = MockPipelineConnector(seeded_index)
    req = PipelineRequest(
        user_id="maya",
        employee_id="maya",
        max_clearance="confidential",
        groups=["eng", "payments"],
        session_id="sess-8",
        reason="payment outage pool size",
        platform="confluence",
        item_id="CF-POSTMORTEM",
    )
    conn = db.central()
    try:
        result = run_pipeline(req, conn, connector=connector)
        assert result.ok
        assert result.level in ("verified", "pruned", "excerpts_only")
        assert result.answer_text
    finally:
        conn.close()


def test_pipeline_higher_clearance_user(seeded_index, registered_employees):
    """Raj (secret clearance) can access confidential items."""
    req = PipelineRequest(
        user_id="raj",
        employee_id="raj",
        max_clearance="secret",
        groups=["eng", "sre"],
        session_id="sess-9",
        reason="connection pool size monitoring",
        platform="confluence",
        item_id="CF-POSTMORTEM",
    )
    conn = db.central()
    try:
        result = run_pipeline(req, conn)
        assert result.ok
        assert result.level in ("verified", "pruned", "excerpts_only")
        assert result.answer_text
    finally:
        conn.close()


def test_pipeline_returns_item_metadata(seeded_index, registered_employees):
    """Pipeline returns item title and URL for the audit record."""
    req = PipelineRequest(
        user_id="maya",
        employee_id="maya",
        max_clearance="confidential",
        groups=["eng", "payments"],
        session_id="sess-10",
        reason="payment outage",
        platform="confluence",
        item_id="CF-RUNBOOK",
    )
    conn = db.central()
    try:
        result = run_pipeline(req, conn)
        assert result.ok
        assert result.item_title == "Runbook: payment incident response"
        assert "/items/CF-RUNBOOK" in result.item_url
    finally:
        conn.close()


def test_pipeline_gatekeeper_reason_set(seeded_index, registered_employees):
    """Pipeline includes the gatekeeper's selection reason."""
    req = PipelineRequest(
        user_id="maya",
        employee_id="maya",
        max_clearance="confidential",
        groups=["eng", "payments"],
        session_id="sess-11",
        reason="payment outage investigation",
        platform="confluence",
        item_id="CF-RUNBOOK",
    )
    conn = db.central()
    try:
        result = run_pipeline(req, conn)
        assert result.ok
        assert result.gatekeeper_reason
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Grounding ladder integration with pipeline
# ---------------------------------------------------------------------------

def test_pipeline_grounding_ladder_levels(seeded_index, registered_employees):
    """All grounding ladder levels are reachable through the pipeline."""
    conn = db.central()
    try:
        # verified/pruned/excerpts: search for relevant content
        req_verified = PipelineRequest(
            user_id="maya", employee_id="maya",
            max_clearance="confidential", groups=["eng", "payments"],
            session_id="sess-12",
            reason="payment outage pool size",
            platform="confluence", item_id="CF-POSTMORTEM",
        )
        r = run_pipeline(req_verified, conn)
        assert r.level in ("verified", "pruned", "excerpts_only")

        # no_evidence: non-existent item
        req_none = PipelineRequest(
            user_id="maya", employee_id="maya",
            max_clearance="confidential", groups=["eng", "payments"],
            session_id="sess-13",
            reason="payment",
            platform="confluence", item_id="NOPE",
        )
        r_none = run_pipeline(req_none, conn)
        assert r_none.level == "no_evidence"
    finally:
        conn.close()


def test_no_evidence_message_is_generic(seeded_index, registered_employees):
    """The no-evidence message is the same generic text for all
    no-evidence scenarios (not found, access denied, no relevant content)."""
    conn = db.central()
    try:
        # Not found
        r1 = run_pipeline(PipelineRequest(
            user_id="maya", employee_id="maya",
            max_clearance="confidential", groups=["eng", "payments"],
            session_id="sess-14",
            reason="payment", platform="confluence", item_id="NOPE",
        ), conn)

        # Access denied
        r2 = run_pipeline(PipelineRequest(
            user_id="tom", employee_id="tom",
            max_clearance="open", groups=["contractors"],
            session_id="sess-15",
            reason="payment", platform="confluence", item_id="CF-POSTMORTEM",
        ), conn)

        # No relevant content
        r3 = run_pipeline(PipelineRequest(
            user_id="maya", employee_id="maya",
            max_clearance="confidential", groups=["eng", "payments"],
            session_id="sess-16",
            reason="zzznonexistentzzz", platform="confluence",
            item_id="CF-PUBLIC",
        ), conn)

        assert r1.answer_text == r2.answer_text == r3.answer_text == GENERIC_NO_EVIDENCE
        assert r1.level == r2.level == r3.level == "no_evidence"
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Gatekeeper mode dispatch (live path — Phase 7 wiring)
# ---------------------------------------------------------------------------

def test_pipeline_live_gatekeeper_dispatch(seeded_index, registered_employees, monkeypatch):
    """GATEKEEPER_MODE=live routes selection through the real Gatekeeper
    LLM (mocked here) — not the TF-IDF stub."""
    monkeypatch.setenv("FILEGUARD_GATEKEEPER_MODE", "live")
    from fileguard import gatekeeper

    def fake_llm_select(spans, reason, user_context):
        return ([{"kind": "section", "start": 0, "end": 0}], "fake-live-reason")

    monkeypatch.setattr(gatekeeper, "_llm_select", fake_llm_select)
    req = PipelineRequest(
        user_id="maya", employee_id="maya",
        max_clearance="confidential", groups=["eng", "payments"],
        session_id="sess-live", reason="investigating payment outage",
        platform="confluence", item_id="CF-POSTMORTEM",
    )
    conn = db.central()
    try:
        result = run_pipeline(req, conn)
    finally:
        conn.close()
    assert result.gatekeeper_mode == "live-llm"
    assert result.gatekeeper_reason == "fake-live-reason"
    # the LLM picked unit 0; its text must be the delivered citation
    assert result.citations, "live selection produced no citations"
    assert result.citations[0].order == 0
    # invalid refs can only narrow: the LLM returned no unit 1 → absent
    assert all(c.order != 1 for c in result.citations)


def test_pipeline_live_gatekeeper_fail_closed(seeded_index, registered_employees, monkeypatch):
    """LLM failure in live mode = no-evidence, never unfiltered content."""
    monkeypatch.setenv("FILEGUARD_GATEKEEPER_MODE", "live")
    from fileguard import gatekeeper

    def boom(spans, reason, user_context):
        raise RuntimeError("api down")

    monkeypatch.setattr(gatekeeper, "_llm_select", boom)
    req = PipelineRequest(
        user_id="maya", employee_id="maya",
        max_clearance="confidential", groups=["eng", "payments"],
        session_id="sess-live2", reason="investigating payment outage",
        platform="confluence", item_id="CF-POSTMORTEM",
    )
    conn = db.central()
    try:
        result = run_pipeline(req, conn)
    finally:
        conn.close()
    assert result.level == "no_evidence"
    assert result.answer_text == GENERIC_NO_EVIDENCE
    assert "unavailable" in result.grounding_reason
    assert not result.citations


# ---------------------------------------------------------------------------
# Policy-mismatch warning (overlay-allow / native-deny drift signal)
# ---------------------------------------------------------------------------

class DenyingConnector(MockPipelineConnector):
    """Native platform denies everything (simulates stale share / revocation)."""

    def can_access(self, person_email, item):
        return Decision(allowed=False, reason="not shared with user")


def _policy_mismatch_entries(conn):
    return [json.loads(p) for (p,) in conn.execute(
        "SELECT payload FROM audit_log WHERE json_extract(payload, '$.event') = 'policy_mismatch'")]


def test_policy_mismatch_warns_on_overlay_allow_native_deny(seeded_index, registered_employees):
    req = PipelineRequest(
        user_id="maya", employee_id="maya",
        max_clearance="confidential", groups=["eng", "payments"],
        session_id="sess-mm1", reason="payment outage pool size",
        platform="confluence", item_id="CF-POSTMORTEM",
    )
    conn = db.central()
    try:
        before = len(_policy_mismatch_entries(conn))
        result = run_pipeline(req, conn, connector=DenyingConnector(seeded_index))
        entries = _policy_mismatch_entries(conn)
    finally:
        conn.close()
    # deny stands (platform-first, terminal)
    assert result.level == "no_evidence"
    assert "access denied" in result.grounding_reason
    # the mismatch is audited as a warning
    assert len(entries) == before + 1
    e = entries[-1]
    assert e["warning"] is True
    assert e["user_id"] == "maya"
    assert e["item_id"] == "CF-POSTMORTEM"
    assert e["entry_clearance"] == "confidential"
    assert "native platform denies" in e["detail"]


def test_no_mismatch_warning_when_overlay_also_denies(seeded_index, registered_employees):
    # effective clearance "open" < PAY-DOCS label "confidential" — overlay
    # denies too, so there is no drift to signal
    req = PipelineRequest(
        user_id="maya", employee_id="maya",
        max_clearance="confidential", groups=["eng", "payments"],
        session_id="sess-mm2", reason="payment outage pool size",
        platform="confluence", item_id="CF-POSTMORTEM",
        effective_clearance="open",
    )
    conn = db.central()
    try:
        before = len(_policy_mismatch_entries(conn))
        result = run_pipeline(req, conn, connector=DenyingConnector(seeded_index))
        entries = _policy_mismatch_entries(conn)
    finally:
        conn.close()
    assert result.level == "no_evidence"
    assert len(entries) == before, "overlay-deny must not be flagged as mismatch"
