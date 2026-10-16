"""FileGuard web UI — FastAPI + htmx.

Run: uvicorn ui.web:app --port 8000   (then http://localhost:8000)

  /        chat — chat tokens only (Company A personas: token-maya,
           token-lena, …; closed-network corpus: token-alice, token-bob, …)
  /upload  upload into the uploads connector (the original file store)
  /audit   audit console — audit tokens only (audit-priya, audit-lena,
           audit-token-standard, audit-token-topsecret). Chat and audit
           tokens are not interchangeable.

All logic lives in harness/agent_loop.py and fileguard/audit_view.py; this
module is presentation only. Sessions are HMAC-signed cookies; the chat
harness (with its parked-confirmation state) lives in an in-process store
keyed by session id — single-worker uvicorn for the demo.
"""

import html as html_mod
import json
import queue
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import markdown
import nh3
from fastapi import Depends, FastAPI, File, Form, Request, Response, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from harness.audit_chat import AuditChatError, AuditChatHarness
from fileguard import (
    CLEARANCE_ORDER,
    checkpoint,
    config,
    audit_query,
    audit_view,
    file_index,
    db,
    freshness,
    parsers,
    security,
    session_service,
    store,
    sync_engine,
)
from fileguard.connectors import factory
from harness.agent_loop import AssistantHarness

# Built once per process; connectors are lazy (no network until sync).
try:
    CONNECTORS = factory.build_connectors()
except Exception:  # demo keeps serving even if wiring is broken
    CONNECTORS = []

UI_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(UI_DIR / "templates"))

app = FastAPI(title="FileGuard UI")
app.mount("/static", StaticFiles(directory=UI_DIR / "static"), name="static")


@app.middleware("http")
async def csp_header(request, call_next):
    """Strict CSP: no inline script (base.html's toggle lives in ui.js),
    no remote anything. 'unsafe-inline' styles only — SVG icons use style
    attributes; styles cannot execute script."""
    resp = await call_next(request)
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; base-uri 'none'; "
        "form-action 'self'; frame-ancestors 'none'")
    return resp

_SGT = timezone(timedelta(hours=8))  # timestamps displayed in SGT
templates.env.filters["sgt"] = lambda ts: datetime.fromtimestamp(
    ts, _SGT).strftime("%Y-%m-%d %H:%M:%S")


USER_COOKIE = "fg_user"
AUDIT_COOKIE = "fg_audit"
SESSION_TTL = 8 * 3600

# in-process session store: sid -> {harness, messages, profile, pending}
WEB_SESSIONS: dict = {}

_md = markdown.Markdown(extensions=["sane_lists", "fenced_code", "tables"])

# no <img>, no <a>: injected text cannot exfiltrate span content to a
# remote URL via image loads or clicked links
_ANSWER_TAGS = {"p", "br", "strong", "em", "code", "pre", "ul", "ol", "li",
                "blockquote", "h1", "h2", "h3", "h4", "h5", "h6",
                "table", "thead", "tbody", "tr", "th", "td", "hr"}


def md_html(text: str) -> str:
    """Escape first, then render markdown, then nh3-strip the final HTML —
    model output is untrusted, and the sanitizer sees the rendered result,
    not raw chunks."""
    return nh3.clean(_md.reset().convert(html_mod.escape(text or "")),
                     tags=_ANSWER_TAGS)


# --- session helpers ----------------------------------------------------------


def _make_cookie(kind: str, sid: str = "", level: str = "") -> str:
    return security.sign_grant({
        "kind": kind, "sid": sid, "level": level,
        "exp": int(time.time()) + SESSION_TTL,
    })


def _read_cookie(request: Request, cookie: str, kind: str) -> dict | None:
    raw = request.cookies.get(cookie)
    if not raw:
        return None
    data = security.verify_grant(raw)
    return data if data and data.get("kind") == kind and data.get("exp", 0) > time.time() else None


def current_user(request: Request) -> dict | None:
    """Chat sessions ride their own cookie — signing into the audit console
    no longer ends the chat session (and vice versa)."""
    data = _read_cookie(request, USER_COOKIE, "user")
    if not data:
        return None
    return WEB_SESSIONS.get(data.get("sid"))


def current_audit_level(request: Request) -> str | None:
    data = _read_cookie(request, AUDIT_COOKIE, "audit")
    return data.get("level") if data else None


def ensure_fresh_grant(s: dict) -> None:
    """Sliding session: every chat refreshes the grant, so active use never
    expires; an idle session still dies with the grant TTL. A refresh failure
    must never stall a chat — the grant simply stays until it expires."""
    harness: AssistantHarness = s["harness"]
    try:
        grant = security.verify_grant(harness.st.grant)
        if grant and grant["exp"] - time.time() < config.GRANT_TTL_SECONDS // 2:
            r = harness.client.post("/session/refresh",
                                    json={"grant": harness.st.grant})
            if r.status_code == 200:
                harness.st.grant = r.json()["grant"]
    except Exception:
        pass


# --- rendering -----------------------------------------------------------------


# DECISION 2026-10-15: the live answering model is scrapped — the status quo
# stands (the pipeline's stitched draft + verbatim excerpts are what the user
# Chip vocabulary is the DELIVERY SHAPE (user decision 2026-10-16):
#   excerpt  — the delivered pieces read continuously in the source
#   stitched — there is at least one gap; "(...)" marks it in the box
#   no content — nothing was delivered for this source
# (The live answering model remains scrapped; boxes show verbatim
# delivered content only, never composed text.)
_DELIVERY_LABEL = {
    "excerpt": "excerpt",
    "stitched": "stitched",
    "none": "no content",
}

# hover explanations for the delivery chips (plain title tooltips)
_DELIVERY_HELP = {
    "excerpt": 'Click to view the delivered content — it reads continuously '
               'in the source, exactly as shown.',
    "stitched": 'Click to view the delivered verbatim excerpts — gaps in the '
                'source are marked with "(...)".',
    "none": 'The assistant found no relevant content in this source — '
            'nothing was delivered.',
}


def _message_html(message: dict) -> str:
    role, text = message["role"], message["text"]
    if role == "user":
        return f'<div class="msg user">{html_mod.escape(text)}</div>'
    # need-to-know line: items the search found but withheld above clearance.
    # Reconciled across the turn's searches: a later search at a higher
    # ceiling invalidates earlier chips' labels at or below that ceiling
    # (those items were surfaced or retired by the elevated re-query).
    hidden = ""
    reconciled: dict = {}
    for s in message.get("searches") or []:
        c = s.get("clearance")
        if c in CLEARANCE_ORDER:
            for label in [l for l in reconciled
                          if CLEARANCE_ORDER[l] <= CLEARANCE_ORDER[c]]:
                del reconciled[label]
        for label, n in (s.get("hidden_counts") or {}).items():
            reconciled[label] = n  # latest search wins per label
    if reconciled:
        parts = ", ".join(f"{n} {label.replace('_', ' ')}"
                          for label, n in reconciled.items())
        hidden = (f'<div class="src"><span class="hidden-note">'
                  f'{html_mod.escape(parts + " exist above the searched clearance")}'
                  f'</span></div>')
    chips, metas = "", message.get("source_metas") or []
    n = len(metas) or message.get("sources") or 0
    if n:
        if metas:
            chips = "".join(
                f'<span><b>{html_mod.escape(m["name"])}</b>'
                f'{" · " + html_mod.escape(m["platform"]) if m.get("platform") else ""}'
                f'</span>' for m in metas)
        else:
            chips = "".join(
                f'<span><b>{html_mod.escape(f)}</b></span>'
                for f in message.get("source_files") or [])
        n_receipts = sum(1 for m in metas if m.get("receipt"))
        chips += (f'<span class="verified" title="Each delivered excerpt has a '
                  f'cryptographic receipt bound to the tamper-evident audit log."'
                  f'>{n_receipts} signed '
                  f'receipt{"s" if n_receipts != 1 else ""}</span>')
        chips = f'<div class="src">{chips}</div>'
    badges = ""
    boxes = ""
    for i, m in enumerate(metas):
        d = m.get("delivery") or "none"
        label = _DELIVERY_LABEL.get(d, d.replace("_", " "))
        help = _DELIVERY_HELP.get(d, "")
        empty = d == "none" or not m.get("body")
        chip_cls = "empty" if empty else "cite-chip"
        badges += (f'<span class="badge b-grounding cite-chip {chip_cls} g-{d}"'
                   f' data-src="{i}" role="button" tabindex="0"'
                   f'{" title=\"" + html_mod.escape(help) + "\"" if help else ""}'
                   f'>{html_mod.escape(label)}</span>')
        # hidden citation box: header (source), plain-text verbatim body —
        # rendered for EVERY attempt; empty delivery = blank body
        boxes += (
            f'<div class="cite-box" data-src="{i}" hidden>'
            f'<div class="cite-head"><b>{html_mod.escape(m["name"])}</b>'
            f' &middot; {html_mod.escape(m.get("platform") or "")}'
            f'{"/" + html_mod.escape(m.get("container")) if m.get("container") else ""}'
            f'<button class="cite-close" type="button" aria-label="Close">&times;</button></div>'
            f'<pre class="cite-body">{html_mod.escape(m.get("body") or "")}</pre>'
            f'</div>')
        if m.get("verified_current_at"):
            when = datetime.fromtimestamp(m["verified_current_at"], _SGT).strftime("%H:%M")
            badges += (f'<span class="badge{" b-stale" if m.get("stale") else ""}">'
                       f'{"stale — " if m.get("stale") else ""}verified current {when}</span>')
    if badges:
        badges = f'<div class="src">{badges}</div>'
    return (f'<div class="msg agent"><div class="glyph">{_GLYPH}</div>'
            f'<div><div class="text">{md_html(text)}</div>{hidden}{chips}{badges}{boxes}'
            f'</div></div>')


_GLYPH = ('<svg width="18" height="18" viewBox="0 0 24 24" fill="none" '
          'stroke="currentColor" stroke-width="2" stroke-linecap="round" '
          'stroke-linejoin="round" aria-hidden="true">'
          '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/>'
          '<path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/></svg>')
_SHIELD = ('<svg width="22" height="22" viewBox="0 0 24 24" fill="none" '
           'stroke="currentColor" stroke-width="2" stroke-linecap="round" '
           'stroke-linejoin="round" aria-hidden="true">'
           '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/>'
           '<path d="M9 12l2 2 4-4"/></svg>')


def _confirm_card_html(pending_out: dict) -> str:
    name = pending_out.get("file_name") or "the requested document"
    tier = pending_out.get("tier", "").replace("_", " ")
    once = "One verified span is shared with the assistant. Your prompt and " \
        "this access are recorded in the audit log." \
        if pending_out.get("tier") == "top_secret" else "Once per session."
    return f"""
    <div class="msg agent"><div class="glyph">{_GLYPH}</div><div>
    <div class="confirm">{_SHIELD}<div>
      <b>Confirm {tier} access</b>
      <p>Access to <code>{html_mod.escape(name)}</code>. {once}</p>
      <div class="acts" hx-indicator="#confirm-progress">
        <button class="btn pri" data-approved="true" hx-post="/confirm" hx-vals='{{"approved": "true"}}'
                hx-target="#messages" hx-swap="innerHTML" hx-disabled-elt="this">Confirm access</button>
        <button class="btn" data-approved="false" hx-post="/confirm" hx-vals='{{"approved": "false"}}'
                hx-target="#messages" hx-swap="innerHTML" hx-disabled-elt="this">Cancel</button>
      </div>
      <div class="confirm-progress" id="confirm-progress"><span class="spinner"></span>
        Working — retrieving, verifying and logging the content…</div>
    </div></div></div></div>"""


def render_messages(s: dict) -> str:
    parts = [_message_html(m) for m in s["messages"]]
    if s.get("pending"):
        parts.append(_confirm_card_html(s["pending"]))
    return "\n".join(parts)


def _assistant_message(out: dict) -> dict:
    """Assistant turn from a harness done-result, with source/grounding
    metadata pulled out of the signed receipts."""
    sources = out.get("sources") or []
    metas = [{
        "name": src.get("name", ""),
        "platform": "",
        "container": src.get("container", ""),
        "delivery": src.get("delivery", "none"),
        "body": src.get("body", ""),
        "stale": src.get("stale", False),
        "verified_current_at": src.get("verified_current_at", 0),
        "receipt": src.get("receipt", False),
    } for src in sources]
    n_receipts = sum(1 for m in metas if m.get("receipt"))
    return {
        "role": "assistant", "text": out.get("answer", ""),
        "sources": metas,
        "source_files": [m["name"] for m in metas],
        "source_metas": metas,
        "searches": out.get("searches") or [],
    }


# --- chat page ------------------------------------------------------------------


@app.get("/")
def chat_page(request: Request):
    user = current_user(request)
    allowed, held_index = [], 0
    if user:
        mx = user["profile"]["max_clearance"]
        allowed = [c for c in ("open", "confidential", "secret", "top_secret")
                   if CLEARANCE_ORDER[c] <= CLEARANCE_ORDER[mx]]
        held_index = CLEARANCE_ORDER[mx]
    # least-privilege default: confidential where held, else the user's max
    default_sel = "confidential" if "confidential" in allowed \
        else (allowed[-1] if allowed else "open")
    return templates.TemplateResponse(
        request, "chat.html",
        {"session": user, "messages_html": render_messages(user) if user else "",
         "allowed_clearances": allowed, "held_index": held_index,
         "default_sel": default_sel})


@app.post("/login")
def login(request: Request, token: str = Form("")):
    grant = session_service.issue_grant(token)
    if not grant:
        return HTMLResponse(
            '<div class="form-error">Incorrect token. '
            "(Audit tokens do not work here.)</div>", status_code=401)
    profile = session_service.user_profile(token)
    sid = uuid.uuid4().hex
    WEB_SESSIONS[sid] = {
        "harness": AssistantHarness(grant=grant),
        "messages": [],
        "profile": profile,
        "pending": None,
    }
    resp = HTMLResponse("", headers={"HX-Redirect": "/"})
    resp.set_cookie(USER_COOKIE, _make_cookie("user", sid=sid),
                    max_age=SESSION_TTL, httponly=True, samesite="lax")
    return resp


@app.post("/logout")
def logout(request: Request):
    data = _read_cookie(request, USER_COOKIE, "user")
    if data:
        WEB_SESSIONS.pop(data.get("sid"), None)
    resp = HTMLResponse("", headers={"HX-Redirect": "/"})
    resp.delete_cookie(USER_COOKIE)
    return resp


@app.post("/chat")
async def chat(request: Request, message: str = Form(""),
               default_clearance: str = Form("")):
    user = current_user(request)
    if not user:
        return Response(status_code=401)
    message = message.strip()
    if not message:
        return Response(status_code=400)
    # the sidebar preference is clamped to the user's own ceiling
    mx = user["profile"]["max_clearance"]
    pref = (default_clearance if default_clearance in CLEARANCE_ORDER
            and CLEARANCE_ORDER[default_clearance] <= CLEARANCE_ORDER[mx]
            else mx)

    def sse(event: str, data: str) -> str:
        return f"event: {event}\ndata: {data}\n\n"

    def generate():
        user["messages"].append({"role": "user", "text": message})
        yield sse("user", json.dumps({
            "html": _message_html({"role": "user", "text": message})}))
        if user.get("pending"):
            user["messages"].append({
                "role": "assistant",
                "text": "Please approve or deny the pending confirmation first."})
            yield sse("messages", json.dumps({"html": render_messages(user)}))
            yield sse("end", "{}")
            return
        q: queue.Queue = queue.Queue()
        result = {}

        def run():
            try:
                ensure_fresh_grant(user)
                result["out"] = user["harness"].chat(
                    message, on_stage=lambda l: q.put(("stage", l)),
                    default_clearance=pref)
            except PermissionError:
                result["out"] = {"status": "error", "answer":
                                 "Your session grant has expired — please sign in again."}
            except Exception as e:  # never leave the stream hanging
                result["out"] = {"status": "error", "answer":
                                 f"Assistant error: {type(e).__name__}: {e}"}
            q.put(("done", None))

        threading.Thread(target=run, daemon=True).start()
        while True:
            try:
                kind, payload = q.get(timeout=180)
            except queue.Empty:
                yield sse("stage", json.dumps({"label": "Timed out waiting for the assistant."}))
                break
            if kind == "done":
                break
            yield sse("stage", json.dumps({"label": payload}))

        out = result.get("out", {"status": "error", "answer": "Assistant failed."})
        if out["status"] == "pending_confirmation":
            user["pending"] = out
            user["messages"].append({
                "role": "assistant",
                "text": f"Waiting for your approval to access "
                        f"`{out.get('file_name') or 'the requested document'}` "
                        f"({out.get('tier', '').replace('_', ' ')})."})
        elif out["status"] == "error":
            user["messages"].append({"role": "assistant", "text": out["answer"]})
        else:
            user["messages"].append(_assistant_message(out))
        yield sse("messages", json.dumps({"html": render_messages(user)}))
        yield sse("end", "{}")

    return StreamingResponse(generate(), media_type="text/event-stream")


@app.post("/confirm")
async def confirm(request: Request):
    user = current_user(request)
    if not user or not user.get("pending"):
        return Response(status_code=400)
    form = await request.form()
    values = form.getlist("approved")
    # first value wins — robust even if a client ever sends duplicates
    approved = bool(values) and str(values[0]) == "true"
    try:
        out = user["harness"].resume(approved)
    except PermissionError as e:
        out = {"status": "error", "answer": str(e)}
    user["pending"] = None
    if out["status"] == "pending_confirmation":  # a further park (rare)
        user["pending"] = out
        user["messages"].append({
            "role": "assistant",
            "text": f"Waiting for your approval to access "
                    f"`{out.get('file_name') or 'the requested document'}` "
                    f"({out.get('tier', '').replace('_', ' ')})."})
    elif out["status"] == "error":
        user["messages"].append({"role": "assistant", "text": out["answer"]})
    else:
        user["messages"].append(_assistant_message(out))
    return HTMLResponse(render_messages(user))


# --- file upload -----------------------------------------------------------------
# Future-work item, implemented: authenticated users upload documents and set
# clearance + group labels; files are encrypted at rest and content-hashed
# exactly like seeded files. dev_demo_files never receives uploads.

MAX_UPLOAD_BYTES = 20 * 1024 * 1024


def _sanitize_name(name: str) -> str:
    name = name.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].strip()
    name = "".join(c for c in name if c.isalnum() or c in " ._-,()").strip()
    return name or "uploaded.pdf"


def _unique_name(conn, name: str) -> str:
    if not conn.execute("SELECT 1 FROM files WHERE name = ?", (name,)).fetchone():
        return name
    stem, dot, ext = name.rpartition(".")
    base = stem if dot else name
    ext = f".{ext}" if dot else ""
    i = 2
    while conn.execute("SELECT 1 FROM files WHERE name = ?",
                       (candidate := f"{base}_{i}{ext}",)).fetchone():
        i += 1
    return candidate


def _upload_card(ok: bool, title: str, body: str = "") -> str:
    cls = "upload-ok" if ok else "upload-error"
    return (f'<div class="card upload-result {cls}"><b>{title}</b>{body}</div>')


@app.get("/upload")
def upload_page(request: Request):
    user = current_user(request)
    if not user:
        return RedirectResponse("/", status_code=302)
    profile = user["profile"]
    allowed = [c for c in ("open", "confidential", "secret", "top_secret")
               if CLEARANCE_ORDER[c] <= CLEARANCE_ORDER[profile["max_clearance"]]]
    default_sel = "confidential" if "confidential" in allowed \
        else (allowed[-1] if allowed else "open")
    visible_files, held_index = [], CLEARANCE_ORDER[profile["max_clearance"]]
    try:
        grant = security.verify_grant(user["harness"].st.grant) or {}
        conn = db.central()
        try:
            res = file_index.list_files(
                conn, grant.get("user_id", ""), grant.get("max_clearance", "open"),
                set(grant.get("groups", [])), grant.get("max_clearance", "open"),
                "default")
            visible_files = res["files"]
        finally:
            conn.close()
    except Exception:
        pass
    return templates.TemplateResponse(
        request, "upload.html",
        {"profile": profile, "allowed_clearances": allowed,
         "visible_files": visible_files, "held_index": held_index,
         "default_sel": default_sel})


@app.post("/upload")
async def upload(
    request: Request,
    file: UploadFile = File(...),
    clearance: str = Form(...),
    groups: list[str] = Form([]),
    display_name: str = Form(""),
):
    """Authenticated upload: encrypt + hash at rest, register metadata.
    Uploader may not classify above their own clearance, nor label groups
    they are not a member of. dev_demo_files is never touched."""
    user = current_user(request)
    if not user:
        return Response(status_code=401)
    profile = user["profile"]

    def result(ok, title, body=""):
        return HTMLResponse(_upload_card(ok, title, body))

    if clearance not in CLEARANCE_ORDER:
        return result(False, "Unknown clearance level.")
    if CLEARANCE_ORDER[clearance] > CLEARANCE_ORDER[profile["max_clearance"]]:
        return result(False, f"You cannot classify a document above your own "
                             f"clearance ({profile['max_clearance']}).")
    group_list = [g for g in groups if g]
    foreign = [g for g in group_list if g not in profile["groups"]]
    if foreign:
        return result(False, f"You cannot assign groups you are not a member of: "
                             f"{', '.join(foreign)}.")

    data = await file.read()
    if not data:
        return result(False, "Empty file.")
    if len(data) > MAX_UPLOAD_BYTES:
        return result(False, "File exceeds the 20 MB limit.")
    try:
        kind = parsers.detect_kind(file.filename or "")
    except ValueError:
        return result(False, "Unsupported file type — PDF, XLSX or DOCX only.")
    try:
        spans = parsers.parse_to_spans(data, kind)
    except Exception:
        return result(False, f"File could not be parsed as a valid "
                             f"{kind.upper()} document.")
    if not spans:
        return result(False, "Document contains no extractable text.")

    name = _sanitize_name(display_name or file.filename or "uploaded.pdf")
    if not name.lower().endswith(f".{kind}"):
        name = f"{name}.{kind}"
    conn = db.central()
    try:
        name = _unique_name(conn, name)
        file_id = store.save_plaintext(data)  # encrypt + content-address (sha256)
        conn.execute(
            "INSERT INTO files (file_id, name, kind, base_clearance, groups, "
            "label_date, uploaded_by) VALUES (?,?,?,?,?,date('now'),?)",
            (file_id, name, kind, clearance, json.dumps(group_list),
             profile["user_id"]),
        )
        db.append_log(conn, {
            "event": "upload",
            "user_id": profile["user_id"],
            "session_id": None,
            "tool": "upload",
            "file_ref": file_id,
            "file_name": name,
            "entry_clearance": clearance,
            "groups": group_list,
            "spans": len(spans),
            "bytes": len(data),
        })
        conn.commit()
    finally:
        conn.close()

    body = (
        f"<div class='muted small' style='margin-top:8px;'>"
        f"Registered as <code>{html_mod.escape(name)}</code> · clearance "
        f"{clearance} · groups {group_list or ['— (clearance-only)']} · "
        f"{len(spans)} extractable spans<br>"
        f"Encrypted at rest (AES-256-GCM) · SHA-256 hash "
        f"<code>{file_id[:16]}…</code> · plaintext NOT copied to dev_demo_files."
        f"</div>")
    return result(True, f"📤 Uploaded “{html_mod.escape(name)}” and secured.", body)


# --- audit console --------------------------------------------------------------


def _checkpoint_state() -> dict:
    """Last signed checkpoint + how many user entries await signature."""
    conn = db.central()
    try:
        total = last_cp = 0
        cp = None
        for (seq, pl) in conn.execute(
                "SELECT seq, payload FROM audit_log ORDER BY seq"):
            p = json.loads(pl)
            total += 1
            if p.get("event") == "checkpoint":
                last_cp = seq
                cp = p
        awaiting = sum(1 for (seq, pl) in conn.execute(
            "SELECT seq, payload FROM audit_log WHERE seq > ?",
            (last_cp,))
            if json.loads(pl).get("event") != "checkpoint") if last_cp else total
        return {"cp": cp, "last_cp_seq": last_cp, "awaiting": awaiting,
                "total": total}
    finally:
        conn.close()


def _fmt_sgt(ts: int) -> str:
    return datetime.fromtimestamp(ts, _SGT).strftime("%H:%M:%S")


PLATFORMS = ("confluence", "jira", "slack", "drive", "uploads")
EVENT_TYPES = ("request", "response", "rejection", "abuse_block", "upload",
               "error", "checkpoint")


def _audit_filters(user: str = "", platform: str = "", container: str = "",
                   event_type: str = "", date_from: str = "",
                   date_to: str = "") -> audit_query.AuditQuery:
    """GET params -> AuditQuery (server-rendered filters, like the old sel param)."""
    def day_ts(s: str, end: bool = False) -> float | None:
        try:
            base = datetime.strptime(s, "%Y-%m-%d")
            return (base + timedelta(days=1, seconds=-1)).timestamp() if end \
                else base.timestamp()
        except ValueError:
            return None

    return audit_query.AuditQuery(
        user_id=user or None,
        platform=platform or None,
        container=container or None,
        event_type=event_type or None,
        date_from=day_ts(date_from) if date_from else None,
        date_to=day_ts(date_to, end=True) if date_to else None,
        sort_by="seq",  # the rail is a chain — seq order, newest first
        limit=1000,
    )


def _sources_context() -> dict:
    """Per-connector rows from the sync engine + index totals (Layer 2)."""
    conn = sync_engine._connect()
    try:
        state = {r["platform"]: dict(r) for r in
                 conn.execute("SELECT * FROM sync_state")}
        totals = sync_engine.get_index_stats()
        rows = []
        for platform in PLATFORMS:
            s = state.get(platform, {})
            lag = freshness.get_sync_lag(conn, platform)
            rows.append({
                "platform": platform,
                "total_synced": s.get("total_synced", 0),
                "total_deleted": s.get("total_deleted", 0),
                "last_sync_ts": s.get("last_sync_ts"),
                "last_error": s.get("last_error"),
                "last_error_ts": s.get("last_error_ts"),
                "lag_s": lag,
                "items": totals["by_platform"].get(platform, 0),
            })
        return {"rows": rows, "total_items": totals["total_items"],
                "total_units": totals["total_units"]}
    finally:
        conn.close()


def _console_context(level: str, view: str = "log", sel: int | None = None,
                     stamp: str = "", just_from: int | None = None,
                     q: audit_query.AuditQuery | None = None,
                     raw: dict | None = None) -> dict:
    """Data for the audit console: nav counts, filtered view, checkpoint
    coverage, selected entry. Entries arrive pre-redacted by audit_query."""
    view = view if view in ("log", "violations", "sources") else "log"
    q = q or _audit_filters()
    conn = db.central()
    try:
        # nav counts come from the unfiltered, redacted view
        counts = {"all": audit_query.query_audit(
            conn, audit_query.AuditQuery(limit=1000), level).entries}
        counts["viol"] = [e for e in counts["all"]
                          if e["event"] in audit_query.VIOLATION_EVENTS]
        result = audit_query.query_audit(conn, q, level)
        shown = result.entries
        hashes = dict(conn.execute("SELECT seq, entry_hash FROM audit_log"))
        prevs = dict(conn.execute("SELECT seq, prev_hash FROM audit_log"))
    finally:
        conn.close()

    counts["all"] = len(counts["all"])
    counts["viol"] = len(counts["viol"])
    if view == "violations":
        shown = [e for e in shown if e["event"] in audit_query.VIOLATION_EVENTS]

    sources = _sources_context() if view == "sources" else None

    cps = _checkpoint_state()
    cp = cps["cp"]
    sel_entry = next((e for e in shown if e["seq"] == sel), None)
    sel_session = sel_entry.get("session_id") if sel_entry else None
    if sel_entry and not sel_entry.get("redacted"):
        hashes_sel = (hashes.get(sel_entry["seq"], ""),
                      prevs.get(sel_entry["seq"], ""))
    else:
        hashes_sel = ("", "")

    return {
        "level": level, "view": view, "entries": shown, "sel": sel,
        "sel_entry": sel_entry, "sel_session": sel_session,
        "hashes": hashes_sel, "stamp": stamp,
        "sources": sources, "counts": counts,
        "total": result.total,
        "filters": raw or {"user": "", "platform": "", "container": "",
                           "event_type": "", "date_from": "", "date_to": ""},
        "event_types": EVENT_TYPES, "platforms": PLATFORMS,
        "cp": dict(cp or {}, seq=cps["last_cp_seq"]),
        "just_from": just_from,
        "awaiting": cps["awaiting"],
        "awaiting_label": (f'{cps["awaiting"]} entries awaiting signature'
                           if cps["awaiting"] else "all entries signed"),
        "cp_time": _fmt_sgt(cp["ts"]) if cp else None,
    }


def _query_params(user: str = "", platform: str = "", container: str = "",
                  event_type: str = "", date_from: str = "",
                  date_to: str = ""):
    raw = {"user": user.strip(), "platform": platform.strip(),
           "container": container.strip(),
           "event_type": event_type.strip(),
           "date_from": date_from.strip(), "date_to": date_to.strip()}
    return _audit_filters(**raw), raw


@app.get("/audit")
def audit_page(request: Request, view: str = "log", sel: int | None = None,
               user: str = "", platform: str = "", container: str = "",
               event_type: str = "", date_from: str = "", date_to: str = ""):
    level = current_audit_level(request)
    if not level:
        return templates.TemplateResponse(request, "audit.html", {"level": None})
    q, raw = _query_params(user, platform, container, event_type, date_from, date_to)
    return templates.TemplateResponse(
        request, "audit.html", _console_context(level, view, sel, q=q, raw=raw))


@app.get("/audit/panel")
def audit_panel(request: Request, view: str = "log", sel: int | None = None,
                user: str = "", platform: str = "", container: str = "",
                event_type: str = "", date_from: str = "", date_to: str = ""):
    level = current_audit_level(request)
    if not level:
        return Response(status_code=401)
    q, raw = _query_params(user, platform, container, event_type, date_from, date_to)
    return templates.TemplateResponse(
        request, "_amain.html", _console_context(level, view, sel, q=q, raw=raw))


@app.post("/audit/sync")
def audit_sync(request: Request):
    """Sync-now: pull every connector into the unified index, then re-show
    the Sources view (errors land per-connector in sync_state)."""
    level = current_audit_level(request)
    if not level:
        return Response(status_code=401)
    results = sync_engine.sync_now(CONNECTORS)
    ok = sum(r.synced for r in results)
    errs = [r.platform for r in results if r.errors]
    stamp = f"sync complete — {ok} new/updated items"
    if errs:
        stamp += f" · errors on: {', '.join(errs)}"
    return templates.TemplateResponse(
        request, "_amain.html",
        _console_context(level, "sources", stamp=stamp))


@app.get("/audit/export")
def audit_export(request: Request, fmt: str = "csv", user: str = "",
                 platform: str = "", container: str = "", event_type: str = "",
                 date_from: str = "", date_to: str = ""):
    """Download the current (filtered, redacted) view as CSV or JSON."""
    level = current_audit_level(request)
    if not level:
        return Response(status_code=401)
    q, _ = _query_params(user, platform, container, event_type, date_from, date_to)
    conn = db.central()
    try:
        entries = audit_query.query_audit(conn, q, level).entries
    finally:
        conn.close()
    body = audit_query.export_json(entries) if fmt == "json" \
        else audit_query.export_csv(entries)
    return Response(
        content=body, media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition":
                 f'attachment; filename="audit-export.{fmt}"'})


@app.get("/audit/detail/{seq}")
def audit_detail(request: Request, seq: int):
    """Right-panel record for one entry — arrives pre-redacted by audit_view,
    so the standard auditor only ever receives fields their tier may see."""
    level = current_audit_level(request)
    if not level:
        return Response(status_code=401)
    conn = db.central()
    try:
        entries = audit_view.view_entries(conn, level)
        entry = next((e for e in entries if e["seq"] == seq), None)
        if entry is not None and level == "top_secret":
            # resolve restricted-field commitments (side table) when present;
            # plaintext-in-chain entries pass through unchanged
            entry = audit_query.resolve_restricted_fields(conn, entry)
        hashes = dict(conn.execute("SELECT seq, entry_hash FROM audit_log"))
        prevs = dict(conn.execute("SELECT seq, prev_hash FROM audit_log"))
        # the checkpoint that covers THIS entry (payloads carry no seq —
        # that lives on the row only)
        cp = next((dict(json.loads(pl), seq=cseq)
                   for cseq, pl in conn.execute(
                       "SELECT seq, payload FROM audit_log ORDER BY seq")
                   if json.loads(pl).get("event") == "checkpoint"
                   and json.loads(pl).get("last_seq", 0) >= seq), None)
    finally:
        conn.close()
    if entry is None:
        return HTMLResponse('<p class="meta">This entry is not visible at '
                            'your audit tier.</p>')
    covered = cp is not None
    return templates.TemplateResponse(request, "_entry_detail.html", {
        "level": level, "e": entry,
        "entry_hash": hashes.get(seq, ""), "prev_hash": prevs.get(seq, ""),
        "covered": covered, "cp": cp,
        "cp_time": _fmt_sgt(cp["ts"]) if cp else ""})


@app.post("/audit/checkpoint")
def audit_checkpoint(request: Request):
    """Top-secret auditor only: sign + anchor a checkpoint of the chain."""
    if current_audit_level(request) != "top_secret":
        return HTMLResponse(
            '<span class="form-error">top-secret clearance required'
            '</span>', status_code=403)
    # coverage before signing; -1 when no prior checkpoint exists so the
    # very first checkpoint still sweeps the whole rail
    _st = _checkpoint_state()
    just_from = _st["last_cp_seq"] if _st["cp"] else -1
    record = checkpoint.make_checkpoint()
    if record is None:
        return templates.TemplateResponse(
            request, "_amain.html",
            _console_context("top_secret", "log",
                             stamp="no new entries since the last checkpoint "
                                   "— nothing to do"))
    ok, detail = checkpoint.verify_checkpoint(record)
    # detail names the failing leg (signature / chain / anchor) on failure
    stamp = f'checkpoint #{record["seq"]} signed — ' + (
        detail if ok else f'FAILED: {detail}')
    if not ok:
        return HTMLResponse(stamp, status_code=502)
    return templates.TemplateResponse(
        request, "_amain.html",
        _console_context("top_secret", "log",
                         stamp=stamp, just_from=just_from))


# --- audit chat (read-only LLM assistant over the audit log) ----------------

_AUDIT_CHATS: dict[str, dict] = {}   # sid -> {"harness", "messages"} (in-process)


def _audit_chat(request: Request) -> dict:
    sid = request.cookies.get(AUDIT_COOKIE) or ""
    level = current_audit_level(request)
    if not sid or not level:
        return {}
    sess = _AUDIT_CHATS.get(sid)
    if sess is None or sess["level"] != level:
        sess = {"level": level,
                "harness": AuditChatHarness(level=level),
                "messages": []}
        _AUDIT_CHATS[sid] = sess
    return sess


@app.get("/audit/chat")
def audit_chat_page(request: Request):
    if not current_audit_level(request):
        return RedirectResponse("/audit", status_code=303)
    sess = _audit_chat(request)
    msgs = sess.get("messages", []) if sess else []
    # audit-native message rows (audit theme; md_html escapes + sanitises
    # the model output, so markdown tables render and scripts never do)
    parts = []
    for m in msgs:
        if m["role"] == "user":
            parts.append(f'<div class="achat-msg user">'
                         f'{html_mod.escape(m["text"])}</div>')
        else:
            parts.append(f'<div class="achat-msg assistant">'
                         f'{md_html(m["text"])}</div>')
    return templates.TemplateResponse(request, "audit_chat.html", {
        "level": current_audit_level(request),
        "messages_html": "".join(parts),
        "has_messages": bool(msgs),
    })


@app.post("/audit/chat/send")
async def audit_chat_send(request: Request, message: str = Form("")):
    if not current_audit_level(request):
        return Response(status_code=401)
    sess = _audit_chat(request)
    if not sess:
        return Response(status_code=401)
    message = message.strip()
    if not message:
        return RedirectResponse("/audit/chat", status_code=303)
    sess["messages"].append({"role": "user", "text": message})
    try:
        out = sess["harness"].chat(message)
        answer = out.get("answer", "")
    except AuditChatError as e:
        answer = str(e)
    except Exception as e:  # fail closed: never half-answer
        answer = f"The audit assistant could not complete this query. ({type(e).__name__})"
    sess["messages"].append({"role": "assistant", "text": answer})
    # unique redirect target: a same-URL redirect makes browsers restore
    # the textarea's saved form state, which would resurrect the sent text
    return RedirectResponse(
        f"/audit/chat?turn={len(sess['messages'])}", status_code=303)


@app.post("/audit/chat/clear")
async def audit_chat_clear(request: Request):
    if not current_audit_level(request):
        return Response(status_code=401)
    sess = _audit_chat(request)
    if sess:
        sess["harness"] = AuditChatHarness(level=sess["level"])
        sess["messages"] = []
    return RedirectResponse("/audit/chat", status_code=303)


@app.post("/audit/login")
def audit_login(request: Request, token: str = Form("")):
    level = session_service.issue_audit_level(token)
    if not level:
        return HTMLResponse(
            '<div class="form-error">Incorrect token. '
            "(Chat tokens do not work here.)</div>", status_code=401)
    resp = HTMLResponse("", headers={"HX-Redirect": "/audit"})
    resp.set_cookie(AUDIT_COOKIE, _make_cookie("audit", level=level),
                    max_age=SESSION_TTL, httponly=True, samesite="lax")
    return resp


@app.post("/audit/logout")
def audit_logout():
    resp = HTMLResponse("", headers={"HX-Redirect": "/audit"})
    resp.delete_cookie(AUDIT_COOKIE)
    return resp


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
