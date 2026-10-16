"""Restricted-field wiring tests (D7 / Phase 9 gap closure).

End-to-end through the harness + gateway: raw_user_input (all tiers),
search_terms and answer_text must enter the chained log ONLY as
sha256(salt||text) commitments; plaintext lives in the purge-able side
table; the audit viewer resolves per tier; purging keeps the chain
verifiable; reconciliation compares commitments.

Runs fully offline: the platform simulators are replaced by a mock
connector synced into the unified index.
"""

import hashlib
import json
import os
import sys
import tempfile
import time
import types
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix="fileguard-restricted-")
os.environ["FILEGUARD_DATA_DIR"] = _TMP
os.environ["FILEGUARD_GATEKEEPER_MODE"] = "test"

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from fileguard import audit_restricted, audit_view, db, sync_engine  # noqa: E402
from fileguard.connector import Item, ItemRef, Unit, Decision, ACLSnapshot  # noqa: E402
from fileguard.gateway import app  # noqa: E402
from harness.agent_loop import AssistantHarness  # noqa: E402

client = TestClient(app, raise_server_exceptions=False)

SECRET = "what is the board of director's average salary?"
QUERY = "runbook payment"
REASON_S = "locate the incident runbook for an on-call question"
REASON_G = "read the runbook steps for the incident question"


@pytest.fixture(scope="module", autouse=True)
def _isolate():
    """Pin this module to its own data dir at fixture time and restore the
    shared globals afterwards (see test_abuse_extensions._isolate)."""
    from fileguard import checkpoint
    old_dir = os.environ.get("FILEGUARD_DATA_DIR")
    old_counter = checkpoint._since_last
    os.environ["FILEGUARD_DATA_DIR"] = tempfile.mkdtemp(prefix="fileguard-restricted-iso-")
    checkpoint._since_last = 0
    yield
    os.environ["FILEGUARD_DATA_DIR"] = old_dir
    checkpoint._since_last = old_counter
    import fileguard.gateway as gw
    from fileguard import abuse_guard
    gw.abuse = abuse_guard.AbuseGuard()


class MockConnector:
    platform = "confluence"

    def __init__(self, items):
        self._items = {item.item_id: item for item in items}

    def changes(self, cursor):
        refs = [ItemRef(platform="confluence", container=i.container,
                        item_id=i.item_id, version=i.version)
                for i in self._items.values()]
        return refs, time.time()

    def fetch(self, item_ref):
        return self._items[item_ref.item_id]

    def current_version(self, item_ref):
        return self._items[item_ref.item_id].version

    def fetch_acl(self, item_ref):
        item = self._items[item_ref.item_id]
        return ACLSnapshot(item_key=f"confluence:{item_ref.item_id}",
                           version=item.version, acl_json="{}",
                           fetched_at=time.time())

    def can_access(self, person_email, item):
        return Decision(allowed=True)

    def resolve_identity(self, employee_id):
        return f"{employee_id}@halcyon.example"


def _make_item(item_id, title, units_text):
    units = [Unit(unit_id=f"confluence:{item_id}@v1#{i}", kind="section",
                  text=t, order=i, metadata={})
             for i, t in enumerate(units_text)]
    now = float(int(time.time()))
    return Item(platform="confluence", container="PAY-DOCS", item_id=item_id,
                version="v1", url=f"/items/{item_id}", title=title,
                author="test", created_at=now, updated_at=now,
                units=units, links=[], acl={})


@pytest.fixture(scope="module", autouse=True)
def seeded(_isolate, monkeypatch_module):
    from scripts import ingest_demo, seed
    seed.main()
    ingest_demo.main()
    items = [
        _make_item("CF-RUNBOOK", "Runbook: payment incident response",
                   ["Steps 1-5: check alerts, verify pool size, restart service",
                    "If pool size is below 50, escalate to oncall immediately"]),
    ]
    connector = MockConnector(items)
    sync_engine.sync_connector(connector)
    # the gateway builds real connectors via factory; point it at the mock
    import fileguard.connectors.factory as factory
    monkeypatch_module.setattr(factory, "get_connector",
                               lambda platform: connector if platform == "confluence" else None)


@pytest.fixture(scope="module")
def monkeypatch_module():
    from _pytest.monkeypatch import MonkeyPatch
    mp = MonkeyPatch()
    yield mp
    mp.undo()


def tool_call_brain(calls):
    state = {"i": 0}

    def brain(messages, system):
        if state["i"] < len(calls):
            call = calls[state["i"]]
            state["i"] += 1
            resp = types.SimpleNamespace()
            resp.stop_reason = "tool_use"
            resp.content = [types.SimpleNamespace(
                type="tool_use", id=f"call_{state['i']}",
                name=call["name"], input=call["input"])]
            return resp
        resp = types.SimpleNamespace()
        resp.stop_reason = "end_turn"
        resp.content = [types.SimpleNamespace(type="text", text="Final answer.")]
        return resp

    return brain


def _central_entries(event):
    conn = db.central()
    try:
        out = []
        for seq, payload_json in conn.execute(
                "SELECT seq, payload FROM audit_log ORDER BY seq"):
            p = json.loads(payload_json)
            if p.get("event") == event:
                p["seq"] = seq
                out.append(p)
        return out
    finally:
        conn.close()


def _run_turn():
    grant = client.post("/session", json={"token": "token-maya"}).json()["grant"]
    h = AssistantHarness(grant=grant, brain=tool_call_brain([
        {"name": "search", "input": {
            "query": QUERY, "reason": REASON_S,
            "desired_clearance": "confidential"}},
        {"name": "get_content", "input": {
            "file_ref": "confluence:CF-RUNBOOK", "reason": REASON_G,
            "desired_clearance": "confidential"}},
    ]))
    out = h.chat(SECRET)
    return h, out


# --- commitments, never plaintext ---------------------------------------------


def test_raw_user_input_is_commitment_not_plaintext():
    _run_turn()
    requests = _central_entries("request")
    assert requests, "no request entries logged"
    assert all(e.get("raw_user_input") != SECRET for e in requests)


def test_raw_user_input_side_table_and_commitment_verify():
    _run_turn()
    requests = [e for e in _central_entries("request") if e.get("raw_user_input")]
    assert requests
    conn = db.central()
    try:
        for e in requests:
            assert audit_restricted.retrieve_restricted(
                conn, e["seq"], "raw_user_input") == SECRET
            assert audit_restricted.verify_commitment(
                conn, e["seq"], "raw_user_input", e["raw_user_input"])
    finally:
        conn.close()


def test_raw_user_input_all_tiers():
    # maya is confidential (not top secret): pre-scheme her requests carried
    # no raw_user_input at all. All tiers now carry the restricted field.
    _run_turn()
    assert any(e.get("raw_user_input") for e in _central_entries("request"))


def test_search_terms_restricted_on_search_entries():
    _run_turn()
    search_reqs = [e for e in _central_entries("request") if e["tool"] == "search"]
    assert search_reqs, "no search request logged"
    assert all(e.get("search_terms") != QUERY for e in search_reqs)
    responses = [e for e in _central_entries("response") if e["tool"] == "search"]
    assert responses, "no search response logged"
    assert all(r.get("query") != QUERY for r in responses)
    # request and response commitments agree (same salt)
    assert responses[0]["query"] == search_reqs[0]["search_terms"]


def test_answer_text_committed_in_pipeline_response():
    _run_turn()
    responses = [e for e in _central_entries("response") if e["tool"] == "get_content"]
    assert responses, "no get_content response logged"
    e = responses[0]
    assert e.get("answer_text"), "pipeline answer_text missing from response entry"
    commit = e["answer_text"]
    conn = db.central()
    try:
        assert audit_restricted.verify_commitment(conn, e["seq"], "answer_text", commit)
        text = audit_restricted.retrieve_restricted(conn, e["seq"], "answer_text")
        assert text and commit != text
    finally:
        conn.close()


def test_chain_still_verifies_with_commitments():
    _run_turn()
    ok, _ = db.verify_chain(db.central())
    assert ok


def test_local_log_carries_identical_commitments():
    from fileguard.audit_restricted import compute_commitment
    # snapshot both logs: entries accumulate across turns in this module,
    # so compare only entries written by THIS turn (fresh salts per turn)
    conn = db.local()
    try:
        before = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    finally:
        conn.close()
    conn = db.central()
    try:
        before_c = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    finally:
        conn.close()

    h, out = _run_turn()
    exp_raw = compute_commitment(h.st.restricted_salts["raw_user_input"], SECRET)
    exp_terms = compute_commitment(h.st.restricted_salts["search_terms"], QUERY)

    conn = db.local()
    try:
        local_raw = [json.loads(r[0]) for r in conn.execute(
            f"SELECT payload FROM audit_log WHERE seq > {before} ORDER BY seq")
            if json.loads(r[0]).get("event") == "outgoing_request"]
    finally:
        conn.close()
    assert local_raw, "no local outgoing_request entries"
    for l in local_raw:
        assert l.get("raw_user_input") == exp_raw
    searches = [l for l in local_raw if l["payload"]["tool"] == "search"]
    assert searches and searches[0].get("search_terms") == exp_terms

    conn = db.central()
    try:
        central_reqs = []
        for seq, payload_json in conn.execute(
                f"SELECT seq, payload FROM audit_log WHERE seq > {before_c} ORDER BY seq"):
            p = json.loads(payload_json)
            if p.get("event") == "request":
                p["seq"] = seq
                central_reqs.append(p)
    finally:
        conn.close()
    assert all(c.get("raw_user_input") == exp_raw for c in central_reqs)
    c_searches = [c for c in central_reqs if c["tool"] == "search"]
    assert c_searches and c_searches[0]["search_terms"] == exp_terms


def test_reconciliation_equivalent_with_commitments():
    _run_turn()
    import importlib
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    import scripts.reconcile as rec
    importlib.reload(rec)
    report = rec.reconcile()
    assert report["local_chain_ok"] and report["central_chain_ok"]
    assert report["equivalent"] is True, report["missing"][:3]


# --- audit viewer resolution ----------------------------------------------------


def test_standard_viewer_never_sees_raw_input_or_search_terms():
    _run_turn()
    entries = audit_view.view_entries(db.central(), "standard")
    assert entries
    assert all("raw_user_input" not in e for e in entries)
    assert all("search_terms" not in e for e in entries)


def test_top_secret_viewer_resolves_plaintext():
    _run_turn()
    entries = audit_view.view_entries(db.central(), "top_secret")
    with_raw = [e for e in entries if e.get("raw_user_input")]
    assert with_raw, "no resolved raw_user_input for top-secret viewer"
    assert any(e["raw_user_input"] == SECRET for e in with_raw)


def test_purge_keeps_chain_and_commitment():
    h, out = _run_turn()
    requests = [e for e in _central_entries("request") if e.get("raw_user_input")]
    target = requests[0]
    conn = db.central()
    try:
        n = audit_restricted.purge_restricted(
            conn, target["seq"], "raw_user_input",
            purged_by="test", reason="data-subject request")
        assert n == 1
        assert audit_restricted.retrieve_restricted(
            conn, target["seq"], "raw_user_input") is None
        # commitment in the chain unchanged — purge is a valid verified state
        assert audit_restricted.verify_commitment(
            conn, target["seq"], "raw_user_input", target["raw_user_input"])
    finally:
        conn.close()
    ok, _ = db.verify_chain(db.central())
    assert ok
    purges = [e for e in _central_entries("purge_restricted")
              if e.get("entry_id") == target["seq"]]
    assert purges

# --- audit console path (audit_query — what the /audit UI actually uses) --------


def test_console_top_secret_resolves_commitments():
    _run_turn()
    from fileguard import audit_query
    conn = db.central()
    try:
        res = audit_query.query_audit(conn, audit_query.AuditQuery(limit=1000), "top_secret")
    finally:
        conn.close()
    with_raw = [e for e in res.entries if e.get("raw_user_input")]
    assert with_raw, "no resolved raw_user_input via audit_query"
    assert any(e["raw_user_input"] == SECRET for e in with_raw)
    with_terms = [e for e in res.entries if e.get("search_terms")]
    assert with_terms and any(e["search_terms"] == QUERY for e in with_terms)
    # no unresolved 64-hex commitments rendered as values
    import re
    for e in res.entries:
        for f in ("raw_user_input", "search_terms", "answer_text"):
            v = e.get(f)
            assert not (v and re.fullmatch(r"[0-9a-f]{64}", v)), f"{f} unresolved"


def test_console_standard_viewer_strips_restricted_fields():
    _run_turn()
    from fileguard import audit_query
    conn = db.central()
    try:
        res = audit_query.query_audit(conn, audit_query.AuditQuery(limit=1000), "standard")
    finally:
        conn.close()
    assert res.entries
    assert all("raw_user_input" not in e for e in res.entries)
    assert all("search_terms" not in e for e in res.entries)
    import re
    for e in res.entries:
        v = e.get("answer_text")
        assert not (v and re.fullmatch(r"[0-9a-f]{64}", v)), "commitment leaked"


def test_console_purge_shows_marker():
    h, out = _run_turn()
    requests = [e for e in _central_entries("request") if e.get("raw_user_input")]
    target = requests[0]
    conn = db.central()
    try:
        audit_restricted.purge_restricted(conn, target["seq"], "raw_user_input",
                                          purged_by="test", reason="demo")
    finally:
        conn.close()
    from fileguard import audit_query
    conn = db.central()
    try:
        res = audit_query.query_audit(conn, audit_query.AuditQuery(limit=1000), "top_secret")
    finally:
        conn.close()
    entry = next(e for e in res.entries if e.get("seq") == target["seq"])
    assert entry["raw_user_input"] == "[purged]"


# --- live UI render smoke (list + detail through the real templates) -------------


def test_audit_console_renders_new_content():
    h, out = _run_turn()
    from fastapi.testclient import TestClient as TC
    from ui.web import app as ui_app
    ui = TC(ui_app, raise_server_exceptions=False)

    r = ui.post("/audit/login", data={"token": "audit-token-topsecret"},
                follow_redirects=False)
    assert r.status_code in (200, 303), "audit login failed"
    cookies = r.cookies

    # list page renders via audit_query resolution
    r = ui.get("/audit", cookies=cookies)
    assert r.status_code == 200
    assert "raw_user_input" not in r.text or SECRET in r.text  # resolved or absent

    # detail page for a request entry: raw input resolves to plaintext
    # (compare html-escaped: Jinja escapes the apostrophe in the fixture text)
    # pick an unpurged entry from this turn (earlier tests may have purged
    # turn-1 entries — side-table state is module-wide)
    requests = [e for e in _central_entries("request")
                if e.get("raw_user_input")
                and audit_restricted.retrieve_restricted(
                    db.central(), e["seq"], "raw_user_input") is not None]
    r = ui.get(f"/audit/detail/{requests[0]['seq']}", cookies=cookies)
    assert r.status_code == 200
    assert "Raw input" in r.text
    # compare Jinja-escaped (markupsafe escapes ' as &#39;, html.escape as &#x27;)
    from markupsafe import escape as _esc
    assert str(_esc(SECRET)) in r.text, "raw input not resolved to plaintext"

    # detail page for a get_content response: answer block renders (resolved
    # plaintext or absence — never a 64-hex commitment)
    import re
    responses = [e for e in _central_entries("response") if e["tool"] == "get_content"]
    if responses:
        r = ui.get(f"/audit/detail/{responses[0]['seq']}", cookies=cookies)
        assert r.status_code == 200
        m = re.search(r"Delivered answer", r.text)
        if m:
            assert not re.search(r"[0-9a-f]{64}", r.text.split("Delivered answer")[1][:400])


def test_response_entry_carries_delivery_term():
    # audit terminology matches the UI chips: excerpt | stitched | none
    # (this turn delivers a single continuous unit -> excerpt)
    _run_turn()
    responses = [e for e in _central_entries("response") if e["tool"] == "get_content"]
    assert responses, "no get_content response logged"
    e = responses[0]
    assert e.get("delivery") == "excerpt", e.get("delivery")
