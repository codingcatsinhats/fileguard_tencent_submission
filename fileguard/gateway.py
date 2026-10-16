"""Audit Gateway — the central interceptor. No path to file data bypasses it.

/v1/request:  log request -> Auth Checker -> Abuse Guard -> route -> log response.
Rejections and abuse blocks are logged and flagged. Everything crossing this
boundary is a validated RequestObject (Pydantic).
"""

import json
import time

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from . import (
    CLEARANCE_ORDER,
    abuse_guard,
    checkpoint,
    config,
    auth_checker,
    audit_restricted,
    db,
    file_index,
    gatekeeper,
    models,
    parsers,
    security,
    session_service,
    store,
)

app = FastAPI(title="FileGuard Audit Gateway")

# Demo-note: the guard holds per-session state in this process. Production:
# shared store (Redis) behind the gateway service.
abuse = abuse_guard.AbuseGuard()


class SessionRequest(BaseModel):
    token: str


class RefreshRequest(BaseModel):
    grant: str


class ConfirmRegisterRequest(BaseModel):
    grant: str
    summary: str = ""


class ConfirmRequest(BaseModel):
    nonce: str
    session_id: str


def _grant_for_log(grant_str: str) -> dict:
    """Best-effort identity for the request log; verification happens in the
    Auth Checker. An unverifiable grant logs as user_id 'unknown'."""
    grant = security.verify_grant(grant_str)
    if grant is None:
        return {"user_id": "unknown", "session_id": None, "max_clearance": None, "groups": []}
    return grant


def _entry_clearance(conn, payload: models.RequestPayload) -> str:
    """Handling tier = the highest clearance involved in this request."""
    tier = payload.desired_clearance
    if payload.tool == "get_content" and payload.file_ref:
        platform_ref = auth_checker._platform_ref(payload.file_ref)
        if platform_ref is not None:
            # platform item: tier = the container's overlay label
            from . import search, identity
            item = search.lookup_item(*platform_ref)
            if item:
                policy = identity.get_container_policy(
                    identity.load_container_policies(),
                    item["platform"], item["container"])
                if CLEARANCE_ORDER[policy.label] > CLEARANCE_ORDER[tier]:
                    tier = policy.label
            return tier
        row = conn.execute(
            "SELECT base_clearance FROM files WHERE file_id = ? OR name = ?",
            (payload.file_ref, payload.file_ref),
        ).fetchone()
        if row and CLEARANCE_ORDER[row[0]] > CLEARANCE_ORDER[tier]:
            tier = row[0]
    return tier


def _raise_label(label: str, other: str) -> str:
    """Bell-LaPadula-style label join: the higher of two clearances."""
    return other if CLEARANCE_ORDER[other] > CLEARANCE_ORDER[label] else label


def _session_label(conn, session_id: str | None) -> str:
    """Session high-water mark: the highest clearance ever DELIVERED in
    this session (no-reading-down / *-property). Only get_content
    responses with non-empty delivered spans raise the mark — attempts,
    rejections and empty selections never do. Every later entry in the
    session inherits at least this label, so agent-written reasons cannot
    carry delivered top-secret text into entries a lower tier can read.
    Derived from the central log itself: restart-safe, and evaluated on
    the same connection (transaction) as the entry inserts that follow.
    """
    label = "open"
    if not session_id:
        return label
    for (payload_json,) in conn.execute(
        "SELECT payload FROM audit_log "
        "WHERE json_extract(payload, '$.session_id') = ?", (session_id,)
    ):
        p = json.loads(payload_json)
        if (p.get("event") == "response" and p.get("tool") == "get_content"
                and p.get("returned")):
            label = _raise_label(label, p.get("entry_clearance") or "open")
    return label


MAX_REASON_CHARS = 500


def _reason_valid(reason: str | None) -> bool:
    """Bandwidth cap only (the high-water mark is the real fix): reject
    over-long reasons and control characters — rejected outright, never
    truncated (a truncated reason is still a channel)."""
    if not reason:
        return True  # absent/empty reasons are handled by the Abuse Guard
    if len(reason) > MAX_REASON_CHARS:
        return False
    return not any(ord(c) < 32 or ord(c) == 127 for c in reason)


@app.post("/session")
def session(body: SessionRequest):
    grant = session_service.issue_grant(body.token)
    if grant is None:
        raise HTTPException(status_code=401, detail="invalid token")
    return {"grant": grant}


@app.post("/session/refresh")
def session_refresh(body: RefreshRequest):
    """Mint-on-confirm: re-mint the session's grant with an extended TTL."""
    grant = security.verify_grant(body.grant)
    if grant is None:
        raise HTTPException(status_code=401, detail="invalid or expired grant")
    grant["exp"] = int(time.time()) + config.GRANT_TTL_SECONDS
    return {"grant": security.sign_grant(grant)}


@app.post("/confirm/register")
def confirm_register(body: ConfirmRegisterRequest):
    """Issue a single-use nonce for one pending top-secret/secret request."""
    grant = security.verify_grant(body.grant)
    if grant is None:
        raise HTTPException(status_code=401, detail="invalid or expired grant")
    conn = db.central()
    try:
        nonce = session_service.register_pending(conn, grant["session_id"], body.summary)
        return {"nonce": nonce, "session_id": grant["session_id"]}
    finally:
        conn.close()


@app.post("/confirm")
def confirm(body: ConfirmRequest):
    """Consume a confirmation nonce. Duplicate = idempotent no-op."""
    conn = db.central()
    try:
        approved, decision = session_service.consume_nonce(conn, body.nonce, body.session_id)
        return {"approved": approved, "decision": decision}
    finally:
        conn.close()


@app.get("/audit/verify")
def audit_verify():
    conn = db.central()
    try:
        ok, n = db.verify_chain(conn)
        return {"ok": ok, "entries": n}
    finally:
        conn.close()


@app.post("/v1/request")
def handle(req: models.RequestObject):
    conn = db.central()
    try:
        p = req.payload
        if p.tool == "get_content" and (p.file_ref or "").startswith("uploads:"):
            # uploads are the 5th connector but run the legacy store path;
            # their item_id IS the file name — strip the search prefix
            p = p.model_copy(update={"file_ref": p.file_ref.split("uploads:", 1)[1]})
        grant = _grant_for_log(req.credentials.grant)
        # session high-water mark (Bell-LaPadula *-property): every entry
        # written in this request inherits at least the highest clearance
        # ever delivered in this session. Computed on the same connection —
        # i.e. the same transaction — as the inserts below, so a delivered
        # response and its raised descendants can never be observed apart.
        hwm = _session_label(conn, grant["session_id"])

        # 1. log request BEFORE anything proceeds (labeled agent-asserted reason).
        # secret+ requests carry the harness-constructed trace. Restricted
        # fields (raw_user_input — all tiers; search_terms) NEVER enter the
        # chain as plaintext: only sha256(salt||text) commitments do (D7).
        # The harness generates the salts so the harness-local log computes
        # identical commitments and reconciliation compares commitments only.
        restricted_texts: dict[str, str] = {}
        if req.raw_user_input:
            restricted_texts["raw_user_input"] = req.raw_user_input
        if p.tool == "search" and p.query:
            restricted_texts["search_terms"] = p.query
        restricted_commits: dict[str, str] = {}
        for field, text in restricted_texts.items():
            salt = (req.restricted_salts or {}).get(field) or audit_restricted.generate_salt()
            restricted_commits[field] = audit_restricted.compute_commitment(salt, text)
        entry = {
            "event": "request",
            "user_id": grant["user_id"],
            "session_id": grant["session_id"],
            "tool": p.tool,
            "file_ref": p.file_ref,
            "desired_clearance": p.desired_clearance,
            "desired_group": p.desired_group,
            # the agent-written reason is THE downgrade vector — the request
            # entry inherits the session high-water mark like every entry
            "entry_clearance": _raise_label(_entry_clearance(conn, p), hwm),
            "reason": p.reason,
            "reason_label": "agent-asserted",
        }
        if req.trace is not None:
            entry["trace"] = req.trace
        entry.update(restricted_commits)  # commitments, never plaintext
        logged_request = db.append_log(conn, entry)
        if restricted_texts:
            # plaintext + salt into the purge-able side table, keyed by seq
            audit_restricted.store_all_restricted(
                conn, logged_request["seq"], restricted_texts,
                salts={f: (req.restricted_salts or {}).get(f)
                       for f in restricted_texts})

        # 1b. reason hardening: over-long reasons or control characters are
        # REJECTED, never truncated (bandwidth cap; the high-water mark is
        # the real downgrade fix). Not a warning-level rejection: this does
        # not feed the over-clearance escalation.
        if not _reason_valid(p.reason):
            db.append_log(conn, {
                "event": "rejection",
                "user_id": grant["user_id"],
                "session_id": grant["session_id"],
                "tool": p.tool,
                "file_ref": p.file_ref,
                "entry_clearance": _raise_label(
                    _entry_clearance(conn, p), hwm),
                "code": "REASON_INVALID",
                "warning": False,
                "detail": "reason exceeds the length cap or contains "
                          "control characters",
            })
            raise HTTPException(status_code=403, detail={
                "ok": False, "code": "REASON_INVALID",
                "detail": "invalid access reason",
            })

        # 2. backend verification
        verdict = auth_checker.validate(req, conn)
        if not verdict.ok:
            db.append_log(conn, {
                "event": "rejection",
                "user_id": grant["user_id"],
                "session_id": grant["session_id"],
                "tool": p.tool,
                "file_ref": p.file_ref,
                "entry_clearance": _raise_label(
                    _entry_clearance(conn, p), hwm),
                "code": verdict.code,
                "warning": verdict.warning,
                "detail": verdict.detail,
            })
            raise HTTPException(status_code=403, detail={
                "ok": False, "code": verdict.code, "detail": verdict.detail,
            })

        # 3. abuse prevention
        abuse_verdict = abuse.check_request(
            grant["session_id"], grant["user_id"], p.model_dump(), conn
        )
        if not abuse_verdict.ok:
            db.append_log(conn, {
                "event": "abuse_block",
                "user_id": grant["user_id"],
                "session_id": grant["session_id"],
                "tool": p.tool,
                "file_ref": p.file_ref,
                "entry_clearance": _raise_label(
                    _entry_clearance(conn, p), hwm),
                "code": abuse_verdict.code,
                "detail": abuse_verdict.detail,
            })
            raise HTTPException(status_code=403, detail={
                "ok": False, "code": "ABUSE_BLOCKED",
                "detail": f"blocked by usage policy: {abuse_verdict.detail}",
            })

        # 4. route
        full_doc = False
        total = None          # full span count of the requested document
        receipt_fields = None  # get_content only: everything a verifier recomputes

        # 3. route
        if p.tool == "search":
            return _handle_search(req, conn, grant, p, hwm)

        platform_ref = None
        if p.tool == "get_content":
            platform_ref = auth_checker._platform_ref(p.file_ref or "")
        if platform_ref is not None:
            return _handle_pipeline(req, conn, grant, p, hwm, platform_ref)

        if p.tool == "list_files":
            result = file_index.list_files(
                conn, grant["user_id"], grant["max_clearance"],
                set(grant["groups"]), verdict.effective_clearance, p.desired_group,
            )
            returned = result["files"]
        else:  # get_content
            row = conn.execute(
                "SELECT file_id, name, kind, base_clearance, groups FROM files "
                "WHERE file_id = ? OR name = ?",
                (p.file_ref, p.file_ref),
            ).fetchone()
            file_id, name, kind, base_clearance = row[0], row[1], row[2], row[3]
            try:
                plaintext = store.load_plaintext(file_id)
                content_hash = security.sha256_hex(plaintext)
                refs, mode, gk_reason = gatekeeper.select_spans(
                    plaintext, kind, file_id, content_hash, p.reason,
                    {"max_clearance": grant["max_clearance"], "groups": grant["groups"],
                     "conn": conn, "file_ref": p.file_ref},
                )
                # an empty selection means "nothing relevant" — a valid answer,
                # not a failure; the agent is told so via spans: []
                spans = _extract_verified(plaintext, kind, file_id, content_hash, refs) \
                    if refs else []
            except gatekeeper.GatekeeperError as e:
                db.append_log(conn, {
                    "event": "error", "stage": "gatekeeper",
                    "user_id": grant["user_id"], "session_id": grant["session_id"],
                    "file_ref": p.file_ref,
                    "entry_clearance": _raise_label(
                        _entry_clearance(conn, p), hwm),
                    "detail": str(e),
                })
                raise HTTPException(status_code=502, detail={
                    "ok": False, "code": "GATEKEEPER_UNAVAILABLE",
                    "detail": "content selection is temporarily unavailable; try again",
                })
            result = {
                "file": {"file_id": file_id, "name": name, "kind": kind},
                "gatekeeper_mode": mode,
                "gatekeeper_reason": gk_reason,
                "spans": spans,
            }
            returned = [{k: s[k] for k in ("kind", "start", "end")} for s in spans]
            span_hashes = [security.sha256_hex(s["text"].encode("utf-8"))
                           for s in spans]
            receipt_fields = {
                "content_hash": content_hash,   # the hash pinned at selection
                "span_hashes": span_hashes,
                "delivered_clearance": base_clearance,
            }
            # abuse accounting: did the gatekeeper return the whole document?
            total = len(parsers.parse_to_spans(plaintext, kind))
            full_doc = len(spans) >= total and total > 0

        # 5. log what was returned, then feed abuse accounting. The response
        # inherits the request's clearance so the log pair (requested/approved)
        # is tiered — and hidden/redacted — identically.
        response_clearance = _raise_label(_entry_clearance(conn, p), hwm)
        # a real delivery raises the mark BEFORE the response entry is
        # written, so the entry, its session_label, and the receipt agree
        if p.tool == "get_content" and returned:
            hwm = _raise_label(hwm, response_clearance)
        # captured so the receipt can bind to the exact entry ts+hash
        response_ts = int(time.time())
        logged_response = db.append_log(conn, {
            "event": "response",
            "user_id": grant["user_id"],
            "session_id": grant["session_id"],
            "tool": p.tool,
            "file_ref": p.file_ref,
            "entry_clearance": response_clearance,
            "gatekeeper_reason": gk_reason if p.tool == "get_content" else None,
            "returned": returned,
            "span_count_total": total,
            "full_doc": full_doc,
            "policy_version": config.POLICY_VERSION,
            "session_label": hwm,
            **(receipt_fields or {}),
        }, ts=response_ts)
        # receipt: signed attestation of what was DELIVERED (not what the
        # answer says), bound to the audit entry via its chained hash. The
        # session_label is the high-water mark including this delivery.
        if receipt_fields is not None:
            receipt_payload = {
                **receipt_fields,
                "session_label": hwm,
                "policy_version": config.POLICY_VERSION,
                "log_entry_hash": logged_response["entry_hash"],
                "log_seq": logged_response["seq"],
                "user_id": grant["user_id"],
                "session_id": grant["session_id"],
                "file_name": name,
                "ts": response_ts,
            }
            result["receipt"] = {
                "payload": receipt_payload,
                "signature": security.receipt_sign(receipt_payload),
            }
        # abuse accounting post-routing: a block armed here is never silent —
        # it is logged with its code, and future requests in this session are
        # refused with the same code in their pre-flight echo.
        armed = abuse.note_response(grant["session_id"], p.tool, returned,
                                    full_doc=full_doc, total_spans=total)
        if armed:
            db.append_log(conn, {
                "event": "abuse_block",
                "user_id": grant["user_id"],
                "session_id": grant["session_id"],
                "tool": p.tool,
                "file_ref": p.file_ref,
                "entry_clearance": _raise_label(
                    _entry_clearance(conn, p), hwm),
                "code": armed.code,
                "detail": armed.detail,
            })
        # signed checkpoint cadence: bounded effort, make_checkpoint's
        # no-op rule guards duplicates
        checkpoint.maybe_checkpoint()
        return {"ok": True, "result": result}
    finally:
        conn.close()


def _extract_verified(plaintext, kind, file_id, content_hash, refs):
    from . import span_extractor

    return span_extractor.extract_spans(plaintext, kind, file_id, content_hash, refs)


# --- unified-index routes (D1 two-stage model) --------------------------------
# Both run AFTER auth_checker + abuse pre-flight in handle(), and share its
# audit entry shape. platform/container fields on the entries power the
# audit console's platform filters.

def _handle_search(req, conn, grant, p, hwm) -> dict:
    """Stage 1: permission-filtered discovery. References only — no text."""
    from . import search as search_mod

    res = search_mod.search(
        query=p.query or "", reason=p.reason, user_id=grant["user_id"],
        user_clearance=grant["max_clearance"], user_groups=grant["groups"],
        effective_clearance=p.desired_clearance, limit=30,
        desired_group=p.desired_group,
    )
    returned = [{
        "platform": r.platform, "container": r.container,
        "item_id": r.item_id, "title": r.title,
        "clearance_label": r.clearance_label, "unit_count": r.unit_count,
    } for r in res.results]

    response_clearance = _raise_label(_entry_clearance(conn, p), hwm)
    # search terms are restricted (D7): the request entry carries the
    # commitment + side-table plaintext; repeat the same commitment here
    # rather than plaintext query text
    st_commit = None
    if p.query:
        salt = (req.restricted_salts or {}).get("search_terms")
        st_commit = audit_restricted.compute_commitment(salt, p.query) if salt \
            else None
    db.append_log(conn, {
        "event": "response", "tool": "search",
        "user_id": grant["user_id"], "session_id": grant["session_id"],
        "file_ref": None, "query": st_commit,
        "platform": "*", "entry_clearance": response_clearance,
        "returned": returned, "hidden_counts": res.hidden_counts,
        "policy_version": config.POLICY_VERSION, "session_label": hwm,
    })
    # abuse accounting post-routing (D9): broad-search strikes, empty-result
    # flood (with the forced-first exemption via search_seq), volume cap. A
    # block armed here is never silent — logged with its code.
    armed = abuse.note_search_response(
        grant["session_id"], p.query or "", returned,
        total=res.total, search_seq=p.search_seq)
    if armed:
        db.append_log(conn, {
            "event": "abuse_block",
            "user_id": grant["user_id"],
            "session_id": grant["session_id"],
            "tool": "search",
            "entry_clearance": response_clearance,
            "code": armed.code,
            "warning": False,
            "detail": armed.detail,
        })
    checkpoint.maybe_checkpoint()
    return {"ok": True, "result": {
        "search_id": res.search_id, "query": p.query, "results": returned,
        "hidden_counts": res.hidden_counts, "total": res.total,
        # the ceiling this search ran at — the UI reconciles hidden_counts
        # across searches: an elevated re-query invalidates earlier chips
        "clearance": p.desired_clearance,
    }}



def _render_delivery(citations) -> tuple[str, str]:
    """Classify the delivered spans and render the verbatim body.

    excerpt  — the delivered pieces read continuously in the source
               (consecutive unit orders), shown whole in document order.
    stitched — there is at least one gap between delivered pieces; the
               pieces are shown in document order with "(...)" at each gap.
    Uncertain cases count as stitched.
    Returns (delivery, body); body is plain text.
    """
    if not citations:
        return "none", ""
    ordered = sorted(citations, key=lambda c: c.order)
    # group into continuous runs of consecutive unit orders
    runs: list[list] = [[ordered[0]]]
    for c in ordered[1:]:
        if c.order == runs[-1][-1].order + 1:
            runs[-1].append(c)
        else:
            runs.append([c])
    run_bodies = ["\n\n".join(c.text for c in run) for run in runs]
    if len(runs) == 1:
        return "excerpt", run_bodies[0]
    return "stitched", "\n\n(...)\n\n".join(run_bodies)


def _handle_pipeline(req, conn, grant, p, hwm, platform_ref) -> dict:
    """Stage 2: get_content over a unified-index item via run_pipeline."""
    from . import pipeline as pipeline_mod, search as search_mod, identity
    from .connectors import factory

    platform, item_id = platform_ref
    item = search_mod.lookup_item(platform, item_id)
    connector = factory.get_connector(platform)
    preq = pipeline_mod.PipelineRequest(
        user_id=grant["user_id"],
        employee_id=factory.bridge_employee(grant["user_id"]),
        max_clearance=grant["max_clearance"], groups=grant["groups"],
        session_id=grant["session_id"], reason=p.reason,
        platform=platform, item_id=item_id,
        effective_clearance=p.desired_clearance,
    )
    pr = pipeline_mod.run_pipeline(preq, conn, connector=connector)

    container = (item or {}).get("container", "")
    label = identity.get_container_policy(
        identity.load_container_policies(), platform, container).label

    # delivered units = the pipeline's citations (verbatim, grounded)
    returned = [{"unit_id": c.unit_id, "kind": c.kind, "order": c.order}
                for c in pr.citations]
    total = 0  # items rows carry no unit_count; count units in the index
    from .sync_engine import _connect as _idx
    ic = _idx()
    try:
        total = ic.execute(
            "SELECT COUNT(*) FROM units WHERE item_key = ?",
            (f"{platform}:{item_id}",)).fetchone()[0]
    finally:
        ic.close()
    full_doc = bool(returned) and len(returned) >= total

    response_clearance = _raise_label(_entry_clearance(conn, p), hwm)
    delivered = pr.level != "no_evidence" and bool(returned)
    # delivery term + verbatim body, classified by document-order
    # continuity of the delivered spans (excerpt = reads continuously in
    # the source; stitched = gaps, shown with "(...)"). The grounding
    # ladder's internal verified/pruned/excerpts_only states stay
    # mechanical — they gate the audit fields, not the user-facing term.
    delivery, body = _render_delivery(pr.citations)
    if not delivered:
        delivery = "none"
    if delivered:
        hwm = _raise_label(hwm, response_clearance)
    response_ts = int(time.time())

    entry = {
        "event": "response", "tool": "get_content",
        "user_id": grant["user_id"], "session_id": grant["session_id"],
        "file_ref": p.file_ref,
        "platform": platform, "container": container, "item_id": item_id,
        "item_title": pr.item_title,
        "entry_clearance": response_clearance,
        "gatekeeper_reason": pr.gatekeeper_reason,
        "returned": returned, "span_count_total": total, "full_doc": full_doc,
        "policy_version": config.POLICY_VERSION, "session_label": hwm,
        "grounding_level": pr.level, "pruned_count": pr.pruned_count,
        "delivery": delivery,
        "stale": pr.stale, "verified_current_at": pr.verified_current_at,
    }
    if pr.answer_text:
        answer_salt = audit_restricted.generate_salt()
        entry["answer_text"] = audit_restricted.compute_commitment(
            answer_salt, pr.answer_text)
    receipt_fields = None
    if delivered:
        receipt_fields = {
            "content_hash": pr.content_hash,
            "span_hashes": [security.sha256_hex(c.text.encode("utf-8"))
                            for c in pr.citations],
            "delivered_clearance": label,
            # demo UI chips (extra fields — receipt verification only pins REQUIRED)
            "platform": platform,
            "grounding_level": pr.level,
            "delivery": delivery,
            "verified_current_at": pr.verified_current_at,
            "stale": pr.stale,
        }
        entry.update(receipt_fields)

    logged_response = db.append_log(conn, entry, ts=response_ts)

    # answer_text is a restricted field (D7): plaintext into the side table
    # keyed by this response entry's seq, commitment already in the chain.
    # Server-side salt — the harness never sees the answer before delivery,
    # so reconciliation (request-side only) is unaffected.
    if pr.answer_text:
        audit_restricted.store_all_restricted(
            conn, logged_response["seq"], {"answer_text": pr.answer_text},
            salts={"answer_text": answer_salt})

    # citations here carry the delivered text (receipt-bound delivery to
    # the session user); the AUDIT entry's `returned` above stays
    # metadata-only by design
    result = {
        "platform": platform, "item_id": item_id,
        "container": container, "title": pr.item_title, "url": pr.item_url,
        "grounding_level": pr.level, "answer": pr.answer_text,
        "gatekeeper_reason": pr.gatekeeper_reason,
        "delivery": delivery, "body": body,
        "stale": pr.stale,
        "verified_current_at": pr.verified_current_at,
        "last_synced_at": pr.last_synced_at,
        "citations": [
            {"unit_id": c.unit_id, "kind": c.kind, "order": c.order,
             "text": c.text}
            for c in pr.citations
        ],
    }
    if receipt_fields is not None:
        receipt_payload = {
            **receipt_fields,
            "session_label": hwm,
            "policy_version": config.POLICY_VERSION,
            "log_entry_hash": logged_response["entry_hash"],
            "log_seq": logged_response["seq"],
            "user_id": grant["user_id"], "session_id": grant["session_id"],
            "file_name": pr.item_title or item_id,
            "ts": response_ts,
        }
        result["receipt"] = {
            "payload": receipt_payload,
            "signature": security.receipt_sign(receipt_payload),
        }

    armed = abuse.note_response(grant["session_id"], "get_content", returned,
                                full_doc=full_doc, total_spans=total)
    if armed:
        db.append_log(conn, {
            "event": "abuse_block", "tool": "get_content",
            "user_id": grant["user_id"], "session_id": grant["session_id"],
            "file_ref": p.file_ref,
            "entry_clearance": _raise_label(_entry_clearance(conn, p), hwm),
            "code": armed.code, "detail": armed.detail,
        })
    checkpoint.maybe_checkpoint()
    return {"ok": True, "result": result}
