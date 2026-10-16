"""Audit chat harness tests — read-only LLM assistant over the audit log.

All deterministic: a scripted brain emits fixed tool calls, the harness
executes them against a seeded central log. No live LLM, no network.

Invariants under test:
- redact-then-LLM: entries are tier-redacted/resolved BEFORE the model sees
  them (standard never receives above-tier content)
- tier is a validated, clamped FILTER (never a grant)
- higher-tier violations survive filtering in reduced form (standard)
- read-only: the log is never modified
"""

import json
import os
import sys
import tempfile
import time
import types
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix="fileguard-auditchat-")
os.environ["FILEGUARD_DATA_DIR"] = _TMP
os.environ["FILEGUARD_GATEKEEPER_MODE"] = "test"

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402

from fileguard import audit_query, audit_restricted, db  # noqa: E402
from harness.audit_chat import (  # noqa: E402
    AuditChatHarness, MAX_QUERIES_PER_TURN,
)


@pytest.fixture(scope="module", autouse=True)
def seeded():
    now = time.time()
    conn = db.central()
    try:
        def log(entry, ts):
            return db.append_log(conn, entry, ts=ts)

        # bob: confidential request/response pair (delivered, stitched)
        req = log({"event": "request", "tool": "get_content",
                   "user_id": "bob", "session_id": "s-bob",
                   "file_ref": "confluence:CF-POSTMORTEM",
                   "desired_clearance": "confidential",
                   "entry_clearance": "confidential",
                   "reason": "root cause review"}, now - 60)
        log({"event": "response", "tool": "get_content",
             "user_id": "bob", "session_id": "s-bob",
             "file_ref": "confluence:CF-POSTMORTEM",
             "entry_clearance": "confidential", "delivery": "stitched",
             "grounding_level": "verified",
             "returned": [{"kind": "section", "start": 0, "end": 0}]},
            now - 58)
        # lena: top_secret request with a committed answer (restricted)
        log({"event": "request", "tool": "get_content",
             "user_id": "lena", "session_id": "s-lena",
             "file_ref": "confluence:CF-SEC-Q3",
             "desired_clearance": "top_secret",
             "entry_clearance": "top_secret",
             "reason": "breach review"}, now - 40)
        salt = audit_restricted.generate_salt()
        answer = "The breach report: 1.2M attempts, 3400 accounts compromised."
        commit = audit_restricted.compute_commitment(salt, answer)
        # the commitment lives in the RESPONSE entry; the side-table row is
        # keyed to that same entry (as the live gateway does)
        logged_response = log({"event": "response", "tool": "get_content",
                               "user_id": "lena", "session_id": "s-lena",
                               "file_ref": "confluence:CF-SEC-Q3",
                               "entry_clearance": "top_secret",
                               "delivery": "stitched",
                               "grounding_level": "verified",
                               "answer_text": commit,
                               "returned": [{"kind": "section", "start": 0,
                                             "end": 0}]}, now - 38)
        audit_restricted.store_all_restricted(
            conn, logged_response["seq"], {"answer_text": answer},
            salts={"answer_text": salt})
        # jo: secret-tier rejection (violation)
        log({"event": "rejection", "tool": "get_content",
             "user_id": "jo", "session_id": "s-jo",
             "file_ref": "confluence:CF-SEC-Q3",
             "entry_clearance": "secret", "code": "OVERCLEARANCE",
             "warning": True, "detail": "rated secret, above user max"},
            now - 30)
    finally:
        conn.close()


def _last_seq(conn):
    return conn.execute("SELECT MAX(seq) FROM audit_log").fetchone()[0]


def scripted_brain(calls):
    """calls: list of (tool_input, final_text). Emits each tool call in
    order, then the matching final answer."""
    state = {"i": 0}

    def brain(messages, system):
        i = state["i"]
        # count tool results seen so far in the conversation to know which
        # call this iteration follows
        n_results = sum(1 for m in messages if m["role"] == "user"
                        and isinstance(m.get("content"), list))
        if n_results < len(calls) and state["i"] < len(calls):
            tool_input, final = calls[n_results]
            state["i"] += 1
            resp = types.SimpleNamespace(stop_reason="tool_use")
            resp.content = [types.SimpleNamespace(
                type="tool_use", id=f"c{n_results}", name="query_audit_log",
                input=tool_input)]
            return resp
        _, final = calls[-1]
        resp = types.SimpleNamespace(stop_reason="end_turn")
        resp.content = [types.SimpleNamespace(type="text", text=final)]
        return resp

    return brain


def _harness(level, calls):
    return AuditChatHarness(level=level, brain=scripted_brain(calls))


def _q(**kw):
    return kw


# --- basic query flow -------------------------------------------------------------


def test_query_returns_entries_and_answer_cites_seq():
    h = _harness("top_secret", [(
        _q(user_id="bob"),
        "Bob's request is at seq 1 (see above). Verified delivery.")])
    out = h.chat("What did bob access?")
    assert out["queries"] == 1
    assert out["entries"], "tool returned no entries"
    seqs = {e["seq"] for e in out["entries"]}
    assert seqs, "no seqs in compact entries"
    assert "seq 1" in out["answer"] or "seq" in out["answer"]


def test_compact_entries_carry_delivery_and_tier():
    h = _harness("top_secret", [(_q(user_id="bob"), "done")])
    out = h.chat("q")
    e = out["entries"][0]
    assert e["event"] == "response"
    assert e["tier"] == "confidential"
    assert e.get("delivery") == "stitched"


# --- redact-then-LLM invariants -----------------------------------------------------


def test_standard_never_sees_top_secret_content():
    h = _harness("standard", [(_q(user_id="lena"), "nothing found")])
    out = h.chat("what did lena access?")
    # lena's top_secret request/response are invisible to the standard tier
    lena_rows = [e for e in out["entries"] if e.get("user_id") == "lena"]
    assert not lena_rows
    assert all(e.get("answer_text") is None for e in out["entries"])


def test_top_secret_resolves_answer_text():
    h = _harness("top_secret", [(_q(user_id="lena"), "done")])
    out = h.chat("what did lena receive?")
    e = next(x for x in out["entries"] if x.get("answer_text"))
    assert "3400 accounts compromised" in e["answer_text"]


def test_standard_sees_reduced_violations_even_with_tier_filter():
    # tier=confidential: the secret-tier violation must STILL appear —
    # reduced (no file_ref/detail) — because violations are always
    # returned to the extent the tier can see
    h = _harness("standard", [(_q(tier="confidential"), "done")])
    out = h.chat("show confidential events")
    viol = [e for e in out["entries"] if e.get("event") == "rejection"]
    assert viol, "reduced violation missing from tier-filtered results"
    v = viol[0]
    assert v.get("redacted") is True
    assert not v.get("file_ref")
    assert v.get("code") == "OVERCLEARANCE"


def test_top_secret_tier_filter_includes_higher_violation():
    # a top_secret auditor filtering tier=secret: the secret-tier violation
    # is fully visible at this tier
    h = _harness("top_secret", [(_q(tier="secret"), "done")])
    out = h.chat("show secret events")
    viol = [e for e in out["entries"] if e.get("event") == "rejection"]
    assert viol
    assert viol[0].get("file_ref"), "full-access violation should keep detail"


# --- tier validation / clamping ------------------------------------------------------


def test_standard_requesting_top_secret_is_clamped():
    h = _harness("standard", [(_q(tier="top_secret"), "done")])
    out = h.chat("give me top secret events")
    # clamped to confidential: no top_secret-tier full entries leak
    assert all(e.get("tier") != "top_secret" or e.get("redacted")
               for e in out["entries"])


def test_invalid_tier_is_a_tool_error():
    # an invalid filter never executes (queries stays 0); the model receives
    # the error and the user sees only the model's summary
    calls_seen = []

    def brain(messages, system):
        n_results = sum(1 for m in messages if m["role"] == "user"
                        and isinstance(m.get("content"), list))
        if n_results == 0:
            resp = types.SimpleNamespace(stop_reason="tool_use")
            resp.content = [types.SimpleNamespace(
                type="tool_use", id="c0", name="query_audit_log",
                input={"tier": "ultra"})]
            return resp
        # inspect the tool result fed back to the model
        last = messages[-1]["content"][0]["content"]
        calls_seen.append(last)
        resp = types.SimpleNamespace(stop_reason="end_turn")
        resp.content = [types.SimpleNamespace(type="text", text="ok")]
        return resp

    h = AuditChatHarness(level="standard", brain=brain)
    out = h.chat("bad tier query")
    assert out["queries"] == 0, "an invalid filter must not count as a query"
    assert any("Invalid filter" in c for c in calls_seen)


# --- filters -----------------------------------------------------------------------


def test_seq_exact_filter():
    h = _harness("top_secret", [(_q(seq=1), "done")])
    out = h.chat("show event 1")
    assert len(out["entries"]) == 1
    assert out["entries"][0]["seq"] == 1


def test_decision_filter_denied():
    h = _harness("standard", [(_q(decision="denied"), "done")])
    out = h.chat("show denials")
    assert out["entries"]
    assert all(e.get("event") in ("rejection", "abuse_block",
                                 "policy_mismatch") for e in out["entries"])


# --- invariants ----------------------------------------------------------------------


def test_read_only_log_never_changes():
    before = _count()
    h = _harness("top_secret", [(_q(user_id="bob"), "done"),
                                (_q(user_id="jo"), "done")])
    h.chat("q1")
    h.chat("q2")
    assert _count() == before, "audit log was modified by the audit chat"


def _count():
    conn = db.central()
    try:
        return conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    finally:
        conn.close()


def test_query_budget_per_turn():
    tool_results = []

    def counting_brain(messages, system):
        n_results = sum(1 for m in messages if m["role"] == "user"
                        and isinstance(m.get("content"), list))
        if n_results < MAX_QUERIES_PER_TURN + 2:
            i = n_results
            resp = types.SimpleNamespace(stop_reason="tool_use")
            resp.content = [types.SimpleNamespace(
                type="tool_use", id=f"c{i}", name="query_audit_log",
                input={"user_id": f"u{i}"})]
            return resp
        for m in messages:
            if m["role"] == "user" and isinstance(m.get("content"), list):
                for b in m["content"]:
                    if isinstance(b, dict) and b.get("type") == "tool_result":
                        tool_results.append(b.get("content", ""))
        resp = types.SimpleNamespace(stop_reason="end_turn")
        resp.content = [types.SimpleNamespace(type="text", text="Summarised.")]
        return resp

    calls = [(_q(user_id=f"u{i}"), "ok") for i in range(MAX_QUERIES_PER_TURN + 2)]
    h = _harness("standard", calls)
    h.brain = counting_brain
    out = h.chat("many queries")
    # only EXECUTED queries count; the rejected ones carry the budget error
    assert out["queries"] == MAX_QUERIES_PER_TURN
    budget_errors = [t for t in tool_results
                     if f"At most {MAX_QUERIES_PER_TURN} log queries" in t]
    assert len(budget_errors) == 2, "expected the 2 over-budget calls rejected"
