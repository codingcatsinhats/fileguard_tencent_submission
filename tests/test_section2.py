"""Section-2 tests: agent loop (scripted brain), confirmations, mint-on-confirm,
abuse guard, audit viewer gating, reconciliation.

LEGACY — exercised via the legacy `list_files` tool and the old cast; kept
until the legacy gateway branch is removed; the branch is still
load-bearing (upload-page listing, reset-demo audit history)."""

import json
import os
import sys
import tempfile
import time
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix="fileguard-s2-")
os.environ["FILEGUARD_DATA_DIR"] = _TMP
os.environ["FILEGUARD_GATEKEEPER_MODE"] = "test"

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from fileguard import abuse_guard, audit_view, db, models, session_service, security  # noqa: E402
from fileguard.gateway import app  # noqa: E402
from harness.agent_loop import TOOLS_SPEC, AssistantHarness  # noqa: E402
from harness import local_log  # noqa: E402

client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture(scope="module", autouse=True)
def seeded():
    from scripts import ingest_demo, seed

    seed.main()
    ingest_demo.main()


def session_for(user: str) -> str:
    return client.post("/session", json={"token": f"token-{user}"}).json()["grant"]


# --- scripted brains ---------------------------------------------------------


def tool_call_brain(calls):
    """Brain that issues the given tool calls in order, then answers."""
    state = {"i": 0}

    def brain(messages, system):
        if state["i"] < len(calls):
            call = calls[state["i"]]
            state["i"] += 1
            import types
            resp = types.SimpleNamespace()
            resp.stop_reason = "tool_use"
            resp.content = [types.SimpleNamespace(
                type="tool_use", id=f"call_{state['i']}",
                name=call["name"], input=call["input"])]
            return resp
        import types
        resp = types.SimpleNamespace()
        resp.stop_reason = "end_turn"
        resp.content = [types.SimpleNamespace(type="text", text="Final answer.")]
        return resp

    return brain


# --- agent loop: top-secret parking + nonce + mint-on-confirm -----------------


def test_top_secret_parks_and_resumes():
    grant = session_for("alice")
    h = AssistantHarness(grant=grant, brain=tool_call_brain([
        {"name": "get_content", "input": {
            "file_ref": "hr_incident_report.docx", "reason": "investigate incident report",
            "desired_clearance": "top_secret"}},
    ]))
    outcome = h.chat("Read the HR incident report")
    assert outcome["status"] == "pending_confirmation"
    assert outcome["tier"] == "top_secret"

    old_exp = security.verify_grant(h.st.grant)["exp"]
    result = h.resume(True)
    assert result["status"] == "done"
    # mint-on-confirm ran: the nonce was consumed exactly once and TTL held
    conn = db.central()
    nonce_rows = conn.execute("SELECT used, decision FROM confirm_nonces").fetchall()
    assert any(used == 1 and decision == "approved" for used, decision in nonce_rows)
    assert security.verify_grant(h.st.grant)["exp"] >= old_exp
    # confirmation consumed exactly once + raw input captured in central log
    conn = db.central()
    rows = conn.execute("SELECT payload FROM audit_log").fetchall()
    payloads = [row[0] for row in rows]
    assert any('"raw_user_input"' in p and "incident" in p for p in payloads)
    assert any('"trace"' in p for p in payloads)


def test_top_secret_list_files_needs_no_confirmation():
    """Discovery reveals file names only — never gated by one-click, any tier."""
    grant = session_for("alice")
    h = AssistantHarness(grant=grant, brain=tool_call_brain([
        {"name": "list_files", "input": {
            "reason": "survey all reachable documents",
            "desired_clearance": "top_secret"}},
    ]))
    outcome = h.chat("list everything")
    assert outcome["status"] == "done"  # no pending_confirmation park
    assert h.st.pending is None


def test_top_secret_denial_feeds_cancellation():
    grant = session_for("alice")
    h = AssistantHarness(grant=grant, brain=tool_call_brain([
        {"name": "get_content", "input": {
            "file_ref": "hr_incident_report.docx", "reason": "investigate incident report",
            "desired_clearance": "top_secret"}},
    ]))
    outcome = h.chat("Read the HR incident report")
    assert outcome["status"] == "pending_confirmation"
    result = h.resume(False)
    assert result["status"] == "done"  # loop continues on the cancellation result


def test_secret_session_confirmation_only_once():
    grant = session_for("alice")
    calls = [
        {"name": "get_content", "input": {
            "file_ref": "hr_policy.pdf", "reason": "check grievance policy deadlines",
            "desired_clearance": "secret"}},
        {"name": "get_content", "input": {
            "file_ref": "hr_policy.pdf", "reason": "check escalation path details",
            "desired_clearance": "secret"}},
    ]
    h = AssistantHarness(grant=grant, brain=tool_call_brain(calls))
    outcome = h.chat("HR policy check")
    assert outcome["status"] == "pending_confirmation"
    assert outcome["tier"] == "secret"
    h.resume(True)
    # second secret request must NOT park (session flag set)
    h.st.messages.append({"role": "user", "content": "now the escalation path"})
    outcome2 = h._run_until_parked()
    assert outcome2["status"] == "done"


def test_local_group_reject_never_leaves_harness():
    grant = session_for("bob")
    n_before = _central_count()
    h = AssistantHarness(grant=grant, brain=tool_call_brain([
        {"name": "list_files", "input": {
            "reason": "find HR docs", "desired_clearance": "confidential",
            "desired_group": "HR"}},
    ]))
    result = h.chat("find HR docs")
    assert result["status"] == "done"
    # no new central request entry — rejected at the harness
    assert _central_count() == n_before
    # but the local log recorded the local rejection
    conn = db.local()
    entries = conn.execute("SELECT payload FROM audit_log").fetchall()
    assert any("local_reject_invalid_group" in p for p, in [(r[0],) for r in entries])


def test_nonce_reuse_never_re_authorizes():
    conn = db.central()
    nonce = session_service.register_pending(conn, "sess-x", "get_content hr_incident_report.docx")
    ok1, d1 = session_service.consume_nonce(conn, nonce, "sess-x")
    ok2, d2 = session_service.consume_nonce(conn, nonce, "sess-x")
    assert (ok1, d1) == (True, "approved")
    assert (ok2, d2) == (False, "duplicate")


# --- abuse guard ----------------------------------------------------------------


def _payload(**kw):
    base = {"tool": "list_files", "reason": "legitimate document search",
            "desired_clearance": "open"}
    base.update(kw)
    return base


def test_abuse_rate_block():
    guard = abuse_guard.AbuseGuard(burst=3, refill_per_min=1)
    conn = db.central()
    for _ in range(3):
        assert guard.check_request("s1", "alice", _payload(), conn).ok
    v = guard.check_request("s1", "alice", _payload(), conn)
    assert not v.ok and v.code == "ABUSE_RATE"
    # subsequent requests blocked for the window
    v2 = guard.check_request("s1", "alice", _payload(), conn)
    assert not v2.ok and v2.code == "ABUSE_BLOCKED"


def test_abuse_overclearance_escalation():
    guard = abuse_guard.AbuseGuard()
    conn = db.central()
    for i in range(abuse_guard.DEFAULTS["overclearance_before_block"]):
        db.append_log(conn, {"event": "rejection", "user_id": "dave", "session_id": "s2",
                             "tool": "list_files", "code": "OVERCLEARANCE", "warning": True})
    v = guard.check_request("s2", "dave", _payload(), conn)
    assert not v.ok and v.code == "ABUSE_OVERCLEARANCE"


def test_abuse_thin_reason_block():
    guard = abuse_guard.AbuseGuard()
    conn = db.central()
    for _ in range(abuse_guard.DEFAULTS["thin_reasons_before_block"]):
        v = guard.check_request("s3", "alice", _payload(reason="data"), conn)
    assert not v.ok and v.code == "ABUSE_PATTERN"


def test_abuse_full_doc_pull_block():
    guard = abuse_guard.AbuseGuard()
    conn = db.central()
    assert guard.check_request("s4", "alice", _payload(), conn).ok
    for _ in range(abuse_guard.DEFAULTS["full_doc_pulls_before_block"]):
        armed = guard.note_response(
            "s4", "get_content", [{"span": i} for i in range(3)],
            full_doc=True, total_spans=12)
    assert armed is not None and armed.code == "ABUSE_FULL_DOC"
    v = guard.check_request("s4", "alice", _payload(), conn)
    assert not v.ok and v.code == "ABUSE_BLOCKED"
    # the pre-flight echo names the cause that armed the block
    assert "ABUSE_FULL_DOC" in v.detail


def test_abuse_full_doc_small_document_exempt():
    guard = abuse_guard.AbuseGuard()
    conn = db.central()
    assert guard.check_request("s5", "alice", _payload(), conn).ok
    # fully returning a below-threshold document never arms a block
    for _ in range(abuse_guard.DEFAULTS["full_doc_pulls_before_block"] + 2):
        armed = guard.note_response(
            "s5", "get_content", [{"span": 0}, {"span": 1}],
            full_doc=True, total_spans=2)
    assert armed is None
    v = guard.check_request("s5", "alice", _payload(), conn)
    assert v.ok


def test_abuse_span_volume_logs_code():
    guard = abuse_guard.AbuseGuard(max_spans_per_response=2)
    conn = db.central()
    assert guard.check_request("s6", "alice", _payload(), conn).ok
    armed = guard.note_response(
        "s6", "get_content", [{"span": i} for i in range(5)],
        full_doc=False, total_spans=20)
    assert armed is not None and armed.code == "ABUSE_SPAN_VOLUME"
    v = guard.check_request("s6", "alice", _payload(), conn)
    assert not v.ok and v.code == "ABUSE_BLOCKED"
    assert "ABUSE_SPAN_VOLUME" in v.detail


def test_gateway_abuse_integration_end_to_end():
    import types
    grant = session_for("dave")
    guard = abuse_guard.AbuseGuard(burst=2, refill_per_min=1)
    from fileguard import gateway
    old = gateway.abuse
    gateway.abuse = guard
    try:
        codes = []
        for _ in range(4):
            r = client.post("/v1/request", json={
                "credentials": {"grant": grant}, "payload": _payload()})
            if r.status_code == 403:
                codes.append(r.json()["detail"]["code"])
        assert "ABUSE_BLOCKED" in codes or "ABUSE_RATE" in codes
    finally:
        gateway.abuse = old


# --- audit viewer gating -----------------------------------------------------------


def test_trace_only_for_secret_and_above():
    grant = session_for("bob")
    r = client.post("/v1/request", json={
        "credentials": {"grant": grant},
        "payload": {"tool": "get_content", "reason": "Q3 revenue questions",
                    "desired_clearance": "confidential", "file_ref": "q3_financials.xlsx"}})
    assert r.status_code == 200
    conn = db.central()
    rows = [json.loads(p) for (p,) in conn.execute("SELECT payload FROM audit_log")]
    req = [e for e in rows if e["event"] == "request"
           and e.get("file_ref") == "q3_financials.xlsx"]
    assert req and "trace" not in req[-1], "routine (confidential) request must carry no trace"


def test_response_entry_inherits_request_clearance():
    grant = session_for("alice")
    r = client.post("/v1/request", json={
        "credentials": {"grant": grant},
        "payload": {"tool": "get_content", "reason": "grievance policy deadlines",
                    "desired_clearance": "secret", "file_ref": "hr_policy.pdf"}})
    assert r.status_code == 200
    conn = db.central()
    rows = [json.loads(p) for (p,) in conn.execute("SELECT payload FROM audit_log")]
    resp = [e for e in rows if e["event"] == "response"
            and e.get("file_ref") == "hr_policy.pdf"][-1]
    assert resp.get("entry_clearance") == "secret", (
        "response entry must not fall back to open for a secret retrieval")


def test_violations_redacted_for_standard_auditor():
    grant = session_for("dave")
    r = client.post("/v1/request", json={
        "credentials": {"grant": grant},
        "payload": {"tool": "get_content", "reason": "read the incident report",
                    "desired_clearance": "open", "file_ref": "hr_incident_report.docx"}})
    assert r.status_code == 403
    standard = audit_view.view_entries(db.central(), "standard")
    viol = [e for e in standard if e["event"] == "rejection"
            and e.get("entry_clearance") == "top_secret"]
    assert viol, "standard auditor must still see that the violation happened"
    e = viol[-1]
    assert e["redacted"]
    for hidden in ("file_ref", "detail", "session_id", "reason"):
        assert hidden not in e, f"standard violation view leaked {hidden}"
    assert e["user_id"] and e["code"]  # employee + violation type remain

    full = audit_view.view_entries(db.central(), "top_secret")
    vfull = [x for x in full if x["event"] == "rejection"
             and x.get("entry_clearance") == "top_secret"]
    assert vfull and not vfull[-1].get("redacted") and "file_ref" in vfull[-1]


def test_normal_secret_access_hidden_from_standard_auditor():
    grant = session_for("alice")
    r = client.post("/v1/request", json={
        "credentials": {"grant": grant},
        "payload": {"tool": "get_content", "reason": "grievance policy deadlines",
                    "desired_clearance": "secret", "file_ref": "hr_policy.pdf"}})
    assert r.status_code == 200
    standard = audit_view.view_entries(db.central(), "standard")
    leaked = [e for e in standard
              if not e.get("redacted")
              and e.get("entry_clearance") in ("secret", "top_secret")
              and e["event"] in ("request", "response")]
    assert not leaked, "standard auditor must not see normal secret+ accesses at all"
    full = audit_view.view_entries(db.central(), "top_secret")
    seen = [e for e in full if e.get("entry_clearance") == "secret"
            and e["event"] == "request" and e.get("file_ref") == "hr_policy.pdf"]
    assert seen and not seen[-1].get("redacted"), "top-secret auditor sees it fully"


# --- reconciliation ------------------------------------------------------------------


def test_reconciliation_equivalent_then_archive():
    from scripts import reconcile as rec

    grant = session_for("bob")
    r = client.post("/v1/request", json={
        "credentials": {"grant": grant},
        "payload": {"tool": "list_files", "reason": "finance docs for reconciliation",
                    "desired_clearance": "confidential"}})
    assert r.status_code == 200

    report = rec.reconcile(apply=False)
    assert report["equivalent"] is True, report
    assert report["matched"] >= 1

    report = rec.reconcile(apply=True)
    assert "archived" in report["action"]
    assert not Path(db.config.LOCAL_DB).exists() or _local_entries() == 0


def test_reconciliation_flag_on_mismatch():
    from scripts import reconcile as rec

    # forge an unmatched local entry (simulates tampering / a bypassed request)
    conn = db.local()
    db.append_log(conn, {
        "event": "outgoing_request", "user_id": "ghost", "session_id": "forged",
        "payload": {"tool": "get_content", "reason": "bypass attempt",
                    "desired_clearance": "top_secret", "file_ref": "hr_incident_report.docx"},
    })
    conn.close()

    report = rec.reconcile(apply=True)
    assert report["equivalent"] is False
    assert "FLAG" in report["action"]
    # flag persisted centrally; local preserved
    conn = db.central()
    rows = conn.execute("SELECT payload FROM audit_log WHERE payload LIKE '%reconciliation_flag%'").fetchall()
    assert rows
    assert _local_entries() > 0


# --- session high-water mark (C1) + reason hardening -------------------------


def test_session_label_rise_rules():
    from fileguard import gateway
    conn = db.central()
    sid = "s-hwm"
    # empty delivery (nothing relevant) never raises
    db.append_log(conn, {"event": "response", "session_id": sid,
                         "tool": "get_content", "entry_clearance": "top_secret",
                         "returned": []})
    assert gateway._session_label(conn, sid) == "open"
    # attempts/rejections never raise
    db.append_log(conn, {"event": "rejection", "session_id": sid,
                         "entry_clearance": "top_secret",
                         "code": "OVERCLEARANCE"})
    assert gateway._session_label(conn, sid) == "open"
    # real delivered content raises
    db.append_log(conn, {"event": "response", "session_id": sid,
                         "tool": "get_content", "entry_clearance": "secret",
                         "returned": [{"kind": "paragraph", "start": 0, "end": 0}]})
    assert gateway._session_label(conn, sid) == "secret"
    # file-name discovery is not content delivery
    db.append_log(conn, {"event": "response", "session_id": sid,
                         "tool": "list_files", "entry_clearance": "top_secret",
                         "returned": [{"name": "x"}]})
    assert gateway._session_label(conn, sid) == "secret"


def test_hwm_later_entries_inherit_delivered_label():
    grant = session_for("alice")
    sid = security.verify_grant(grant)["session_id"]
    # deliver secret content
    r = client.post("/v1/request", json={
        "credentials": {"grant": grant},
        "payload": {"tool": "get_content", "reason": "grievance policy deadlines",
                    "desired_clearance": "secret", "file_ref": "hr_policy.pdf"}})
    assert r.status_code == 200
    # a later LOW-tier request in the same session inherits the mark —
    # the agent-written reason cannot ride in below the delivered tier
    r2 = client.post("/v1/request", json={
        "credentials": {"grant": grant},
        "payload": {"tool": "list_files", "reason": "routine follow-up discovery",
                    "desired_clearance": "open"}})
    assert r2.status_code == 200
    conn = db.central()
    rows = [json.loads(p) for (p,) in conn.execute("SELECT payload FROM audit_log")]
    later = [e for e in rows if e["event"] == "request"
             and e.get("session_id") == sid and e["tool"] == "list_files"]
    assert later and later[-1]["entry_clearance"] == "secret"


def test_hwm_not_raised_by_attempts():
    grant = session_for("bob")
    sid = security.verify_grant(grant)["session_id"]
    # over-clearance attempt: rejected and warned — must NOT raise the mark
    r = client.post("/v1/request", json={
        "credentials": {"grant": grant},
        "payload": {"tool": "get_content", "reason": "investigate incident report",
                    "desired_clearance": "top_secret",
                    "file_ref": "hr_incident_report.docx"}})
    assert r.status_code == 403
    # a later request stays at its own tier
    r2 = client.post("/v1/request", json={
        "credentials": {"grant": grant},
        "payload": {"tool": "list_files", "reason": "routine finance discovery",
                    "desired_clearance": "confidential"}})
    assert r2.status_code == 200
    conn = db.central()
    rows = [json.loads(p) for (p,) in conn.execute("SELECT payload FROM audit_log")]
    later = [e for e in rows if e["event"] == "request"
             and e.get("session_id") == sid and e["tool"] == "list_files"]
    assert later and later[-1]["entry_clearance"] == "confidential"


def test_hwm_rejection_entries_inherit_mark():
    grant = session_for("alice")
    sid = security.verify_grant(grant)["session_id"]
    assert client.post("/v1/request", json={
        "credentials": {"grant": grant},
        "payload": {"tool": "get_content", "reason": "grievance policy deadlines",
                    "desired_clearance": "secret", "file_ref": "hr_policy.pdf"}}).status_code == 200
    # a rejected request in the raised session — its reason is agent-written,
    # so the rejection entry inherits the mark too
    r = client.post("/v1/request", json={
        "credentials": {"grant": grant},
        "payload": {"tool": "get_content", "reason": "check escalation path",
                    "desired_clearance": "secret", "file_ref": "no-such-file.pdf"}})
    assert r.status_code == 403 and r.json()["detail"]["code"] == "NO_FILE"
    conn = db.central()
    rows = [json.loads(p) for (p,) in conn.execute("SELECT payload FROM audit_log")]
    rej = [e for e in rows if e["event"] == "rejection"
           and e.get("session_id") == sid and e.get("code") == "NO_FILE"][-1]
    assert rej["entry_clearance"] == "secret"


def test_reason_over_cap_rejected_not_truncated():
    grant = session_for("alice")
    r = client.post("/v1/request", json={
        "credentials": {"grant": grant},
        "payload": {"tool": "list_files", "reason": "x" * 501,
                    "desired_clearance": "open"}})
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "REASON_INVALID"
    conn = db.central()
    rows = [json.loads(p) for (p,) in conn.execute("SELECT payload FROM audit_log")]
    rej = [e for e in rows if e["event"] == "rejection"
           and e.get("code") == "REASON_INVALID"]
    assert rej and rej[-1]["warning"] is False


def test_reason_control_chars_rejected():
    grant = session_for("alice")
    r = client.post("/v1/request", json={
        "credentials": {"grant": grant},
        "payload": {"tool": "list_files", "reason": "innocent\x00reason",
                    "desired_clearance": "open"}})
    assert r.status_code == 403 and r.json()["detail"]["code"] == "REASON_INVALID"


def test_reconciliation_ignores_raised_label():
    from scripts import reconcile as rec
    from harness import local_log
    # local outgoing_request (harness side, pre-delivery label)
    local_log.log_outgoing({"user_id": "alice", "session_id": "s-raise-hwm",
                            "payload": {"tool": "get_content",
                                        "reason": "grievance policy deadlines",
                                        "desired_clearance": "secret",
                                        "file_ref": "hr_policy.pdf"}})
    # central counterpart with the label RAISED by the session high-water mark
    db.append_log(db.central(), {
        "event": "request", "user_id": "alice", "session_id": "s-raise-hwm",
        "tool": "get_content", "file_ref": "hr_policy.pdf",
        "desired_clearance": "secret", "desired_group": "default",
        "entry_clearance": "top_secret",  # raised after a top-secret delivery
        "reason": "grievance policy deadlines", "reason_label": "agent-asserted"})
    report = rec.reconcile(apply=False)
    # the raised central label must not read as a mismatch for this entry
    assert not any("s-raise-hwm" in m for m in report["missing"]), report
    assert report["matched"] >= 1


# --- signed delivery receipts (A) --------------------------------------------


def test_receipt_roundtrip_and_binding():
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    from verify_receipt import verify

    grant = session_for("alice")
    r = client.post("/v1/request", json={
        "credentials": {"grant": grant},
        "payload": {"tool": "get_content", "reason": "grievance policy deadlines",
                    "desired_clearance": "secret", "file_ref": "hr_policy.pdf"}})
    assert r.status_code == 200
    receipt = r.json()["result"]["receipt"]

    # clean receipt verifies against the log
    ok, detail = verify(receipt)
    assert ok, detail

    # any payload tamper breaks the signature first
    bad = json.loads(json.dumps(receipt))
    bad["payload"]["session_label"] = "open"   # downgrade attempt
    ok, detail = verify(bad)
    assert not ok

    # missing required fields -> cannot bind, refused before signature check
    bad2 = {"payload": {k: v for k, v in receipt["payload"].items()
                        if k != "span_hashes"},
            "signature": receipt["signature"]}
    ok, detail = verify(bad2)
    assert not ok and "missing required fields" in detail

    # the receipt binds to a real, response-type, chain-intact entry
    payload = receipt["payload"]
    conn = db.central()
    row = conn.execute("SELECT payload FROM audit_log WHERE entry_hash = ?",
                       (payload["log_entry_hash"],)).fetchone()
    entry = json.loads(row[0])
    assert entry["event"] == "response"
    assert entry["span_hashes"] == payload["span_hashes"]
    assert entry["content_hash"] == payload["content_hash"]
    assert entry["session_label"] == payload["session_label"]
    assert entry["delivered_clearance"] == payload["delivered_clearance"]
    assert entry["policy_version"] == payload["policy_version"]
    ok, _ = db.verify_chain(conn)
    assert ok


def test_harness_collects_receipts_per_turn():
    grant = session_for("alice")
    calls = [
        {"name": "get_content", "input": {
            "file_ref": "hr_policy.pdf", "reason": "check grievance policy deadlines",
            "desired_clearance": "secret"}},
        {"name": "get_content", "input": {
            "file_ref": "hr_policy.pdf", "reason": "check escalation path details",
            "desired_clearance": "secret"}},
    ]
    h = AssistantHarness(grant=grant, brain=tool_call_brain(calls))
    outcome = h.chat("HR policy check")
    assert outcome["status"] == "pending_confirmation"
    done = h.resume(True)
    assert done["status"] == "done"
    # this turn delivered both calls (the parked one + the follow-up after
    # the session flag) -> two receipts, both for the secret delivery
    assert len(done["receipts"]) == 2
    assert all(r["payload"]["delivered_clearance"] == "secret"
               for r in done["receipts"])
    # next turn makes no new get_content -> no receipts repeated or added
    h.st.messages.append({"role": "user", "content": "now the escalation path"})
    done2 = h._run_until_parked()
    assert done2["status"] == "done"
    assert done2["receipts"] == []


# --- signed checkpoints + anchor (B) ------------------------------------------


def test_checkpoint_lifecycle():
    from fileguard import checkpoint
    conn = db.central()
    # normalise: checkpoint whatever the log holds; a second call is a no-op
    checkpoint.make_checkpoint(conn)
    assert checkpoint.make_checkpoint(conn) is None
    db.append_log(conn, {"event": "request", "user_id": "alice",
                         "session_id": "s-cp", "tool": "list_files"})
    cp = checkpoint.make_checkpoint(conn)
    assert cp and cp["last_seq"] >= 1 and cp["verified"]
    assert cp["policy_version"] == "1"
    # signature is over exactly the core fields
    core = {k: cp[k] for k in ("last_seq", "last_entry_hash", "ts",
                               "policy_version")}
    assert security.receipt_verify(core, cp["signature"])
    ok, detail = checkpoint.verify_checkpoint(cp)
    assert ok and "anchored" in detail
    # idempotent: no new logs -> no duplicate checkpoint
    assert checkpoint.make_checkpoint(conn) is None
    conn.execute(
        "SELECT COUNT(*) FROM audit_log WHERE payload LIKE '%last_entry_hash%'"
    ).fetchone()
    # new entry -> new checkpoint covering it; the old one still verifies
    db.append_log(conn, {"event": "request", "user_id": "bob",
                         "session_id": "s-cp2", "tool": "list_files"})
    cp2 = checkpoint.make_checkpoint(conn)
    assert cp2 and cp2["last_seq"] > cp["last_seq"]
    assert checkpoint.verify_checkpoint(cp2)[0]
    assert checkpoint.verify_checkpoint(cp)[0]
    # external anchor ledger exists beside the DB
    assert (db.config.DATA_DIR / "checkpoints.jsonl").exists()


def test_checkpoint_detects_log_rewrite():
    import shutil
    import sqlite3
    import tempfile
    from fileguard import checkpoint
    conn = db.central()
    db.append_log(conn, {"event": "request", "user_id": "alice",
                         "session_id": "s-tamper", "tool": "list_files"})
    cp = checkpoint.make_checkpoint(conn)
    assert checkpoint.verify_checkpoint(cp)[0]

    old_dir = os.environ["FILEGUARD_DATA_DIR"]
    try:
        tampered = Path(tempfile.mkdtemp(prefix="fg-tampered-"))
        for suffix in ("", "-wal", "-shm"):
            src = Path(old_dir) / f"central.db{suffix}"
            if src.exists():
                shutil.copy(src, tampered / f"central.db{suffix}")
        (tampered / "checkpoints.jsonl").write_text(
            (Path(old_dir) / "checkpoints.jsonl").read_text())
        for f in (Path(old_dir) / "tsa").iterdir():
            (tampered / "tsa").mkdir(exist_ok=True)
            shutil.copy(f, tampered / "tsa" / f.name)
        c = sqlite3.connect(tampered / "central.db")
        c.execute("DROP TRIGGER audit_no_update")   # the real log forbids this
        (pl,) = c.execute("SELECT payload FROM audit_log WHERE seq = 1").fetchone()
        forged = json.loads(pl)
        forged["user_id"] = "ghost"
        c.execute("UPDATE audit_log SET payload = ? WHERE seq = 1",
                  (json.dumps(forged, sort_keys=True, separators=(",", ":")),))
        c.commit(); c.close()

        os.environ["FILEGUARD_DATA_DIR"] = str(tampered)
        ok, detail = checkpoint.verify_checkpoint(cp)
        assert not ok
    finally:
        os.environ["FILEGUARD_DATA_DIR"] = old_dir


def test_checkpoint_route_top_secret_only():
    from fastapi.testclient import TestClient as _TC
    from ui.web import _make_cookie, app as ui_app
    uic = _TC(ui_app, raise_server_exceptions=False)
    # no session -> refused
    assert uic.post("/audit/checkpoint").status_code == 403
    # standard auditor -> refused
    r = uic.post("/audit/checkpoint", cookies={
        "fg_audit": _make_cookie("audit", level="standard")})
    assert r.status_code == 403 and "top-secret" in r.text
    # top-secret auditor -> checkpoint or explicit no-op, never a duplicate
    r = uic.post("/audit/checkpoint", cookies={
        "fg_audit": _make_cookie("audit", level="top_secret")})
    assert r.status_code == 200
    r2 = uic.post("/audit/checkpoint", cookies={
        "fg_audit": _make_cookie("audit", level="top_secret")})
    assert "no new entries" in r2.text


def test_gateway_auto_checkpoint_cadence():
    from fileguard import checkpoint
    grant = session_for("bob")
    checkpoint._since_last = checkpoint.CHECKPOINT_EVERY - 1
    before = db.verify_chain(db.central())[1]
    r = client.post("/v1/request", json={
        "credentials": {"grant": grant},
        "payload": {"tool": "list_files", "reason": "cadence trigger probe",
                    "desired_clearance": "confidential"}})
    assert r.status_code == 200
    conn = db.central()
    rows = [json.loads(p) for (p,) in conn.execute("SELECT payload FROM audit_log")]
    cps = [e for e in rows if e["event"] == "checkpoint"]
    assert cps and any(e.get("last_entry_hash") for e in cps)


# --- helpers ---------------------------------------------------------------------------


def _central_count() -> int:
    conn = db.central()
    return conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]


def _local_entries() -> int:
    conn = db.local()
    return conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
