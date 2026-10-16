"""Section-1 tests: auth matrix, discovery, extraction, chains, nonces.

LEGACY — exercises the pre-connectors path (the legacy `list_files` gateway
branch and the alice/bob/carol/dave cast). Retained until that branch is
removed; it is still load-bearing (upload-page listing, reset-demo audit
history), so it goes only when a replacement exists.

Runs fully offline (gatekeeper in test mode) against a fresh temp data dir.
"""

import os
import sys
import tempfile
from pathlib import Path

# config reads env at import time — set the sandbox BEFORE importing fileguard
_TMP = tempfile.mkdtemp(prefix="fileguard-test-")
os.environ["FILEGUARD_DATA_DIR"] = _TMP
os.environ["FILEGUARD_GATEKEEPER_MODE"] = "test"

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from fileguard import db, security, session_service  # noqa: E402
from fileguard.gateway import app  # noqa: E402

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def seeded():
    from harness import local_log
    from scripts import ingest_demo, seed

    seed.main()
    ingest_demo.main()
    local_log.log_outgoing({"event_label": "harness-online", "reason_label": "agent-asserted"})


def session_for(user: str) -> str:
    r = client.post("/session", json={"token": f"token-{user}"})
    assert r.status_code == 200
    return r.json()["grant"]


def request_as(grant: str, **payload):
    return client.post(
        "/v1/request",
        json={"credentials": {"grant": grant}, "payload": payload},
    )


# --- sessions / grants -------------------------------------------------------


def test_bad_token_rejected():
    assert client.post("/session", json={"token": "nope"}).status_code == 401


def test_tampered_grant_rejected():
    grant = session_for("bob")
    body, sig = grant.split(".")
    r = request_as(f"{body[:-4]}AAAA.{sig}", tool="list_files", reason="x",
                   desired_clearance="open")
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "NO_GRANT"


def test_expired_grant_rejected():
    grant = session_for("bob")
    payload_part, sig = grant.split(".")
    import base64, json as j

    grant_dict = j.loads(security._unb64(payload_part))
    grant_dict["exp"] = 1
    forged = security.sign_grant(grant_dict)  # signed but expired
    r = request_as(forged, tool="list_files", reason="x", desired_clearance="open")
    assert r.status_code == 403


# --- Flow A: discovery + AND-gating + hidden counts --------------------------


def test_alice_sees_everything_at_max():
    r = request_as(session_for("alice"), tool="list_files", reason="all docs",
                   desired_clearance="top_secret")
    names = {f["name"] for f in r.json()["result"]["files"]}
    assert names == {"employee_handbook.pdf", "q3_financials.xlsx", "hr_policy.pdf",
                     "hr_incident_report.docx", "product_roadmap.docx",
                     "board_compensation.xlsx"}
    assert r.json()["result"]["hidden_counts"] == {}


def test_alice_lowered_request_hidden_counts():
    r = request_as(session_for("alice"), tool="list_files", reason="lowered view",
                   desired_clearance="confidential")
    names = {f["name"] for f in r.json()["result"]["files"]}
    assert names == {"employee_handbook.pdf", "q3_financials.xlsx"}
    assert r.json()["result"]["hidden_counts"] == {"secret": 2, "top_secret": 2}


def test_bob_group_and_clearance_gating():
    r = request_as(session_for("bob"), tool="list_files", reason="finance",
                   desired_clearance="confidential")
    names = {f["name"] for f in r.json()["result"]["files"]}
    assert names == {"employee_handbook.pdf", "q3_financials.xlsx"}
    # roadmap is secret, no groups: bob entitled at his max? no — secret > confidential max
    assert r.json()["result"]["hidden_counts"] == {}


def test_bob_cannot_filter_by_group_he_lacks():
    r = request_as(session_for("bob"), tool="list_files", reason="hr docs",
                   desired_clearance="confidential", desired_group="HR")
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "INVALID_GROUP"


def test_overclearance_request_is_warning_rejection():
    r = request_as(session_for("dave"), tool="list_files", reason="everything",
                   desired_clearance="top_secret")
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "OVERCLEARANCE"
    # warning flag persisted in the central log
    conn = db.central()
    rows = conn.execute("SELECT payload FROM audit_log WHERE payload LIKE '%OVERCLEARANCE%'").fetchall()
    assert any('"warning":true' in row[0] for row in rows)


# --- Flow B: content access --------------------------------------------------


def test_get_content_returns_verbatim_spans():
    r = request_as(session_for("bob"), tool="get_content", reason="Q3 profit drivers",
                   desired_clearance="confidential", file_ref="q3_financials.xlsx")
    assert r.status_code == 200
    spans = r.json()["result"]["spans"]
    assert spans and all(s["verified"] for s in spans)
    # heuristic selector matches "profit" -> the Summary block; in live mode
    # the LLM picks whichever spans are relevant. Assert verbatim financials.
    assert any("470,000" in s["text"] for s in spans)
    assert r.json()["result"]["gatekeeper_mode"] == "test-heuristic"


def test_group_gate_blocks_content():
    # carol: secret clearance (passes hr_policy's base) but no groups -> group gate
    r = request_as(session_for("carol"), tool="get_content", reason="grievance policy",
                   desired_clearance="secret", file_ref="hr_policy.pdf")
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "NO_GROUP_ACCESS"


def test_clearance_gate_precedes_group_gate():
    # bob lacks both clearance AND group for the incident report; clearance fires first
    r = request_as(session_for("bob"), tool="get_content", reason="incident",
                   desired_clearance="confidential", file_ref="hr_incident_report.docx")
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "OVERCLEARANCE"


def test_unknown_file_rejected():
    r = request_as(session_for("alice"), tool="get_content", reason="x",
                   desired_clearance="top_secret", file_ref="ghost.pdf")
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "NO_FILE"


# --- span extractor: hash pin + redundancy -----------------------------------


def test_hash_pin_rejects_changed_file():
    from fileguard import parsers, span_extractor, store

    plaintext = b"stub"  # kind won't matter: hash fails first
    file_id = store.save_plaintext(plaintext)
    with pytest.raises(span_extractor.SpanExtractError, match="hash mismatch"):
        span_extractor.extract_spans(
            b"tampered!", "docx", file_id, file_id,
            [{"doc_id": file_id, "content_hash": file_id, "kind": "docx",
              "start": 0, "end": 0}],
        )
    assert parsers.detect_kind("a.docx") == "docx"


# --- audit chains -------------------------------------------------------------


def test_both_chains_verify():
    ok_c, n_c = db.verify_chain(db.central())
    ok_l, n_l = db.verify_chain(db.local())
    assert ok_c and n_c > 0
    assert ok_l and n_l > 0  # fixture writes one local entry via the harness log


def test_append_only_triggers_block_mutation():
    conn = db.central()
    try:
        with pytest.raises(Exception):
            conn.execute("DELETE FROM audit_log")
        conn.rollback()  # release the failed statement's transaction
    finally:
        conn.close()


# --- confirmation nonces -------------------------------------------------------


def test_nonce_single_use_and_duplicate_idempotent():
    conn = db.central()
    nonce = session_service.register_pending(conn, "sess-1", "req-1")
    ok, decision = session_service.consume_nonce(conn, nonce, "sess-1")
    assert ok and decision == "approved"
    ok2, decision2 = session_service.consume_nonce(conn, nonce, "sess-1")
    assert not ok2 and decision2 == "duplicate"
    ok3, decision3 = session_service.consume_nonce(conn, "bogus", "sess-1")
    assert not ok3 and decision3 == "invalid"


# --- gatekeeper empty selection + non-JSON gateway errors (regressions) --------


def test_empty_gatekeeper_selection_is_clean_no_match(monkeypatch):
    """The gatekeeper finding nothing relevant must be a 200 with spans=[]
    plus its desensitized selection_reason — never a crash (was a raw 500
    whose plain-text body exploded into a JSONDecodeError in the harness)."""
    from fileguard import gatekeeper as gk

    def empty_select(*a, **kw):
        return [], "test-heuristic", "No spans match the access reason."

    monkeypatch.setattr(gk, "select_spans", empty_select)
    r = request_as(session_for("bob"), tool="get_content", reason="board remuneration",
                   desired_clearance="confidential", file_ref="q3_financials.xlsx")
    assert r.status_code == 200
    body = r.json()["result"]
    assert body["spans"] == []
    assert body["gatekeeper_reason"] == "No spans match the access reason."
    # the reason lands in the response audit entry too
    conn = db.central()
    import json as _json
    row = conn.execute(
        "SELECT payload FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
    conn.close()
    assert _json.loads(row[0])["gatekeeper_reason"] == "No spans match the access reason."


def test_gateway_reason_present_on_normal_selection():
    """Every selection carries a short desensitized reason, empty or not."""
    r = request_as(session_for("bob"), tool="get_content", reason="Q3 profit drivers",
                   desired_clearance="confidential", file_ref="q3_financials.xlsx")
    assert r.status_code == 200
    reason = r.json()["result"]["gatekeeper_reason"]
    assert reason and len(reason) <= 200


def test_harness_tolerates_non_json_gateway_error():
    """A plain-text/empty 5xx body must become a clean policy denial inside
    the tool result, not a JSONDecodeError surfacing in the chat."""
    from types import SimpleNamespace

    class BoomResp:
        status_code = 500

        def json(self):
            raise ValueError("no JSON body")

    from harness.agent_loop import AssistantHarness
    out = AssistantHarness._gateway_to_tool_result(
        SimpleNamespace(), BoomResp(), "tool-1")
    assert out["tool_use_id"] == "tool-1"
    assert "policy" in out["content"].lower()
