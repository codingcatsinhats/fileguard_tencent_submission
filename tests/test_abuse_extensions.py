"""Abuse-guard extensions + per-turn retrieval budgets (D9 / codebuddy 3a-3c).

Covers: broad-search strikes (volume AND low specificity, both required),
empty-result flood with the forced-first exemption, denied-item flood,
per-turn search/get_content budgets, near-duplicate refinement rejection.

Runs fully offline against a fresh temp data dir.
"""

import json
import os
import sys
import tempfile
import time
import types
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix="fileguard-abuse-")
os.environ["FILEGUARD_DATA_DIR"] = _TMP
os.environ["FILEGUARD_GATEKEEPER_MODE"] = "test"

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from fileguard import abuse_guard, db  # noqa: E402
from fileguard.gateway import app  # noqa: E402
from harness.agent_loop import (  # noqa: E402
    AssistantHarness, MAX_GET_CONTENT_PER_TURN, MAX_SEARCHES_PER_TURN,
    _query_tokens,
)

client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture(scope="module", autouse=True)
def _isolate():
    """Pin this module to its own data dir at fixture time (other test
    modules set FILEGUARD_DATA_DIR at import/collection; the last import
    wins for everyone, so without this our seeded abuse fixtures would
    leak into whichever module is imported last) and restore the shared
    globals (checkpoint cadence counter, gateway abuse singleton) after."""
    from fileguard import checkpoint
    old_dir = os.environ.get("FILEGUARD_DATA_DIR")
    old_counter = checkpoint._since_last
    os.environ["FILEGUARD_DATA_DIR"] = tempfile.mkdtemp(prefix="fileguard-abuse-iso-")
    checkpoint._since_last = 0
    yield
    os.environ["FILEGUARD_DATA_DIR"] = old_dir
    checkpoint._since_last = old_counter
    import fileguard.gateway as gw
    gw.abuse = abuse_guard.AbuseGuard()


@pytest.fixture(scope="module", autouse=True)
def seeded(_isolate):
    from scripts import ingest_demo, seed
    seed.main()
    ingest_demo.main()


# --- unit: specificity heuristic ------------------------------------------------


def test_low_specificity_generic_and_short():
    assert abuse_guard._low_specificity("data")
    assert abuse_guard._low_specificity("show me the files")
    assert abuse_guard._low_specificity("find all info")


def test_low_specificity_distinctive_tokens_are_specific():
    assert not abuse_guard._low_specificity("runbook failover")
    assert not abuse_guard._low_specificity("connection pool outage")
    assert not abuse_guard._low_specificity("q3 financials")


# --- unit: broad-search strikes ---------------------------------------------------


def _fresh_guard(**overrides):
    return abuse_guard.AbuseGuard(**overrides)


def test_broad_strike_requires_both_signals():
    # volume cap disabled so only the broad-search logic is under test
    g = _fresh_guard(max_files_per_session=1000)
    # high volume + specific query -> NO strike
    armed = g.note_search_response("s1", "connection pool outage",
                                   [{"item_id": i} for i in range(30)],
                                   total=30, search_seq=1)
    assert armed is None
    # low volume + generic query -> NO strike (existence leak protection:
    # few permitted matches must not look like abuse)
    armed = g.note_search_response("s1", "data", [], total=0, search_seq=1)
    assert armed is None
    # high volume + generic query -> strike, and 3 strikes arm the block
    for i in range(abuse_guard.DEFAULTS["broad_searches_before_block"]):
        armed = g.note_search_response("s1", "show the data files", [{"x": i} for i in range(30)],
                                       total=30, search_seq=1)
        if i < abuse_guard.DEFAULTS["broad_searches_before_block"] - 1:
            assert armed is None
    assert armed and armed.code == "ABUSE_BROAD_SEARCH"
    # session is now blocked
    conn = db.central()
    try:
        v = g.check_request("s1", "bob", {"reason": "a perfectly fine reason"}, conn)
    finally:
        conn.close()
    assert not v.ok and v.code == "ABUSE_BLOCKED"


def test_broad_strikes_decay_over_window():
    g = _fresh_guard(max_files_per_session=1000)
    st = g._state("s2")
    old = time.time() - abuse_guard.DEFAULTS["pattern_window_seconds"] - 5
    st["broad_strikes"] = [old, old]
    armed = g.note_search_response("s2", "generic data stuff",
                                   [{"x": i} for i in range(30)],
                                   total=30, search_seq=1)
    assert armed is None, "decayed strikes must not count toward the block"


# --- unit: empty-result flood with forced-first exemption --------------------------


def test_empty_flood_counts_and_exempts_forced_first():
    g = _fresh_guard()
    n = abuse_guard.DEFAULTS["empty_searches_before_block"]
    # forced first search empty: exempt (pending)
    assert g.note_search_response("s3", "data", [], total=0, search_seq=0) is None
    # refinements empty: each counts; when one lands, the forced first
    # retroactively counts too
    for i in range(2, n):  # refinements n-2 of them
        armed = g.note_search_response("s3", "data", [], total=0, search_seq=i)
        assert armed is None
    # one more empty refinement pushes past the threshold
    armed = g.note_search_response("s3", "data", [], total=0, search_seq=n)
    assert armed and armed.code == "ABUSE_EMPTY_FLOOD"


def test_forced_first_not_counted_when_refinement_succeeds():
    g = _fresh_guard()
    n = abuse_guard.DEFAULTS["empty_searches_before_block"]
    g.note_search_response("s4", "data", [], total=0, search_seq=0)  # forced, empty
    g.note_search_response("s4", "runbook failover", [{"x": 1}], total=1,
                           search_seq=1)  # refinement succeeds: first stays exempt
    # n-1 further empty refinements: below threshold (first was dropped)
    for i in range(2, n + 1):
        armed = g.note_search_response("s4", "data", [], total=0, search_seq=i)
    assert armed is None or armed.code != "ABUSE_EMPTY_FLOOD", \
        "forced-first exemption failed: counted an exempt search"


def test_success_does_not_reset_strike_counters():
    g = _fresh_guard()
    n = abuse_guard.DEFAULTS["empty_searches_before_block"]
    for i in range(n - 1):
        g.note_search_response("s5", "data", [], total=0, search_seq=i + 1)
    g.note_search_response("s5", "runbook failover steps", [{"x": 1}], total=1,
                           search_seq=1)  # success: no reset
    armed = g.note_search_response("s5", "data", [], total=0, search_seq=n + 1)
    assert armed and armed.code == "ABUSE_EMPTY_FLOOD"


# --- unit: denied-item flood -------------------------------------------------------


def test_denied_flood_arms_after_distinct_denials():
    g = _fresh_guard()
    n = abuse_guard.DEFAULTS["denied_items_before_block"]
    now = time.time()
    conn = db.central()
    try:
        for i in range(n):
            db.append_log(conn, {
                "event": "rejection", "tool": "get_content",
                "user_id": "bob", "session_id": "sx",
                "file_ref": f"doc_{i}.xlsx",  # distinct items
                "code": "NO_FILE", "warning": False,  # non-warning: must NOT
                # count toward the over-clearance escalation (threshold 3)
                "detail": "unknown file", "entry_clearance": "open",
            }, ts=now - 10)
        v = g.check_request("s6", "bob", {"reason": "a perfectly fine reason"}, conn)
    finally:
        conn.close()
    assert not v.ok and v.code == "ABUSE_DENIED_FLOOD"


def test_denied_flood_ignores_non_get_content_rejections():
    g = _fresh_guard()
    n = abuse_guard.DEFAULTS["denied_items_before_block"]
    now = time.time()
    conn = db.central()
    try:
        for i in range(n):
            db.append_log(conn, {
                "event": "rejection", "tool": "search",
                "user_id": "carol", "session_id": "sy",
                "file_ref": None, "code": "INVALID_GROUP",
                "warning": False, "detail": "x", "entry_clearance": "open",
            }, ts=now - 10)
        v = g.check_request("s7", "carol", {"reason": "a perfectly fine reason"}, conn)
    finally:
        conn.close()
    assert v.ok


# --- harness: per-turn budgets + near-duplicate rejection --------------------------


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


def _harness(calls, user="bob"):
    grant = client.post("/session", json={"token": f"token-{user}"}).json()["grant"]
    return AssistantHarness(grant=grant, brain=tool_call_brain(calls))


def _search(q):
    return {"name": "search", "input": {
        "query": q, "reason": "answering the user's question about their work",
        "desired_clearance": "confidential"}}


def _get(ref):
    return {"name": "get_content", "input": {
        "file_ref": ref, "reason": "reading the referenced document",
        "desired_clearance": "confidential"}}


def _turn_outputs(h):
    """Extract per-call rejection text from the harness transcript."""
    return [b.get("content", "") for m in h.st.messages
            for b in (m.get("content") if isinstance(m.get("content"), list) else [])
            if isinstance(b, dict) and b.get("type") == "tool_result"]


def test_search_budget_three_per_turn():
    calls = [_search(f"runbook failover {c}") for c in "abcd"]
    h = _harness(calls)
    h.chat("question one for the budget test")
    outs = _turn_outputs(h)
    rejected = [o for o in outs if "searches per turn" in o]
    assert len(rejected) == 1, f"expected exactly one budget rejection: {outs}"


def test_get_content_budget_five_per_turn():
    # budget raised to 5 by decision (2026-10-15) — MAX_GET_CONTENT_PER_TURN
    calls = [_search("runbook failover alpha"),
             _get("q3_financials.xlsx"), _get("employee_handbook.pdf"),
             _get("product_roadmap.docx"), _get("hr_policy.pdf"),
             _get("q3_financials.xlsx"),                     # 5th: ok (repeats allowed)
             _get("no_such_document.pdf")]                   # 6th: budget-rejected
    h = _harness(calls)
    h.st.session_confirmed_secret = True  # skip secret parking; budget is the test
    h.chat("question two for the budget test")
    outs = _turn_outputs(h)
    rejected = [o for o in outs if "content retrievals per turn" in o]
    assert len(rejected) == 1, f"expected exactly one budget rejection: {outs}"


def test_near_duplicate_refinement_rejected():
    calls = [
        _search("runbook failover procedure"),
        _search("failover procedure runbook"),  # same tokens, reordered
        _search("vendor pricing negotiation"),  # materially different
    ]
    h = _harness(calls)
    h.chat("question three for the near-duplicate test")
    outs = _turn_outputs(h)
    rejected = [o for o in outs if "repeats an earlier" in o]
    assert len(rejected) == 1, f"expected one near-duplicate rejection: {outs}"


def test_new_turn_gets_fresh_budget():
    calls1 = [_search(f"runbook failover {c}") for c in "abc"]
    h = _harness(calls1)
    h.chat("turn one fresh budget test")
    assert h.st.turn_search_count >= MAX_SEARCHES_PER_TURN
    calls2 = [_search("payroll reimbursement policy")]
    h.st = type(h.st)(grant=h.st.grant, messages=[h.st.messages[0]],
                      receipts=h.st.receipts, last_receipt_idx=h.st.last_receipt_idx)
    calls2_calls = calls2
    state = {"i": 0}

    def brain2(messages, system):
        if state["i"] < len(calls2_calls):
            c = calls2_calls[state["i"]]
            state["i"] += 1
            r = types.SimpleNamespace(stop_reason="tool_use")
            r.content = [types.SimpleNamespace(
                type="tool_use", id=f"c{state['i']}", name=c["name"], input=c["input"])]
            return r
        r = types.SimpleNamespace(stop_reason="end_turn")
        r.content = [types.SimpleNamespace(type="text", text="Final answer.")]
        return r

    h.brain = brain2
    h.chat("turn two fresh budget test")
    assert h.st.turn_search_count == 1, "new turn must reset the search budget"


def test_near_duplicate_unit():
    assert AssistantHarness._near_duplicate(
        "runbook failover procedure", ["procedure failover runbook"])
    assert not AssistantHarness._near_duplicate(
        "vendor pricing negotiation", ["runbook failover procedure"])
    assert AssistantHarness._near_duplicate("", ["anything"])


# --- discovery-volume cap: decaying window + per-turn reset (regression) --------


def test_volume_cap_allows_a_normal_turn():
    # worst legitimate turn: 3 searches x 30 refs = 90 < cap 120
    g = _fresh_guard()
    for i in range(3):
        armed = g.note_search_response(
            f"v{i}", "runbook failover steps", [{"x": j} for j in range(30)],
            total=30, search_seq=i)
        assert armed is None, "a worst-case legitimate turn must not arm"


def test_volume_cap_arms_non_harness_client_and_recovers():
    # Harness turns reset the budget per turn (search_seq == 0) and can
    # never exceed it (3 searches x 30 refs < 120) — so through the harness
    # this cap is dead code by design. It guards non-harness API clients:
    # no search_seq -> no per-turn reset -> the window accumulates.
    g = _fresh_guard()
    sid = "vol"
    armed = None
    for call in range(5):  # 5 x 30 = 150 > 120, no reset marker
        armed = g.note_search_response(
            sid, "runbook failover steps", [{"x": j} for j in range(30)],
            total=30, search_seq=None)
    assert armed and armed.code == "ABUSE_VOLUME"

    # a NEW user turn (search_seq == 0) resets the budget
    armed = g.note_search_response(sid, "runbook failover steps",
                                   [{"x": 1}], total=1, search_seq=0)
    assert armed is None


def test_volume_strikes_decay_over_window():
    g = _fresh_guard()
    sid = "voldecay"
    # saturate the window...
    for turn in range(5):
        for i in range(3):
            g.note_search_response(sid, "runbook failover steps",
                                   [{"x": j} for j in range(30)],
                                   total=30, search_seq=i)
    # ...then let every strike age out of the window
    window = g.cfg["volume_window_seconds"]
    old = time.time() - window - 5
    g._state(sid)["volume_strikes"] = [old] * g.cfg["max_files_per_session"]
    armed = g.note_search_response(sid, "runbook failover steps",
                                   [{"x": 1}], total=1, search_seq=1)
    assert armed is None, "decayed strikes must not re-arm the volume block"


def test_volume_preflight_refuses_while_window_saturated():
    g = _fresh_guard()
    sid = "volpre"
    now = time.time()
    st = g._state(sid)
    st["volume_strikes"] = [now - 1] * g.cfg["max_files_per_session"]
    conn = db.central()
    try:
        # "dave": a user whose seeded history carries no get_content
        # denials, so the denied-flood check can't fire before volume
        v = g.check_request(sid, "dave", {"reason": "a perfectly fine reason"}, conn)
    finally:
        conn.close()
    assert not v.ok and v.code == "ABUSE_VOLUME"


# --- near-duplicate gate: elevation exemption -------------------------------------


def test_same_query_higher_clearance_is_allowed():
    # the hidden_counts-recovery path: an agent re-runs the same query at a
    # higher ceiling — materially different access, must NOT be rejected
    assert not AssistantHarness._is_blocked_refinement(
        "show security vulnerabilities", "top_secret",
        [("show security vulnerabilities", "confidential")])


def test_same_query_same_or_lower_clearance_still_rejected():
    assert AssistantHarness._is_blocked_refinement(
        "show security vulnerabilities", "confidential",
        [("show security vulnerabilities", "confidential")])
    assert AssistantHarness._is_blocked_refinement(
        "show security vulnerabilities", "confidential",
        [("show security vulnerabilities", "top_secret")])
    assert AssistantHarness._is_blocked_refinement(
        "show security vulnerabilities", "top_secret",
        [("show security vulnerabilities", "top_secret")])


def test_harness_elevating_refinement_passes_the_gate():
    calls = [
        {"name": "search", "input": {
            "query": "security vulnerabilities",
            "reason": "answering the user's security question for their work",
            "desired_clearance": "confidential"}},
        {"name": "search", "input": {
            "query": "security vulnerabilities",  # identical text, elevated
            "reason": "resurface items withheld above the earlier ceiling",
            "desired_clearance": "top_secret"}},
    ]
    h = _harness(calls, user="lena")
    out = h.chat("security question elevation test")
    outs = _turn_outputs(h)
    rejected = [o for o in outs if "repeats an earlier" in o]
    assert not rejected, f"elevating refinement was rejected: {outs}"
    assert h.st.turn_search_count == 2
