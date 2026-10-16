"""Gatekeeper Agent — selects relevant spans, never composes content.

Output is structurally bounded: the model must call the `submit_spans` tool
(strict schema, span references only). Every returned reference is validated
against the actual parsed span index — invalid references are dropped, and a
zero-span selection is returned as a legitimate "nothing relevant" outcome
with its desensitized selection_reason. The LLM's judgment can only
narrow what is returned, never widen it.
"""

import json
import logging
import re
from dataclasses import dataclass

from . import config, parsers, security

logger = logging.getLogger(__name__)

SUBMIT_SPANS_TOOL = {
    "name": "submit_spans",
    "description": (
        "Submit the spans of the document that are relevant to the access "
        "request. Reference spans EXACTLY as they appear in the document "
        "index. Never invent span identifiers. Never summarize or quote "
        "content — references only."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "spans": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "kind": {"type": "string",
                                 "enum": ["page", "cell_range", "paragraph",
                                          "message", "section", "field",
                                          "comment"]},
                        "start": {"type": ["integer", "string"]},
                        "end": {"type": ["integer", "string"]},
                    },
                    "required": ["kind", "start", "end"],
                    "additionalProperties": False,
                },
            },
            "selection_reason": {
                "type": "string",
                "description": (
                    "One short sentence stating why the submitted spans match the "
                    "access reason, or why none do. Never quote or copy document "
                    "content, names, or figures."
                ),
            },
        },
        "required": ["spans", "selection_reason"],
        "additionalProperties": False,
    },
    "strict": True,
}

SYSTEM_PROMPT = """You are a document gatekeeper. You receive a document index \
(every span, with its identifier) and an access request reason. Select ONLY the \
spans strictly relevant to the reason. Prefer fewer spans. Output references via \
the submit_spans tool and nothing else. Never invent identifiers; copy them \
exactly from the index. You do not summarize, conclude, or compose content. \
Always include selection_reason: exactly one desensitized sentence, with no \
document content. If nothing in the document matches, submit an empty span list \
and say so in selection_reason.

The document index may include a <span_relations> block showing entities that \
appear in multiple spans. Use these relationships to select more complete span \
sets: if a relevant entity appears in multiple spans, consider including all \
spans where it appears. These relationships are context for your selection only — \
never mention them in selection_reason."""


def _extract_span_relationships(spans) -> list[dict]:
    """Detect intra-document entity co-occurrence: capitalized multi-word
    phrases (proper nouns, project names, contract names) that appear in
    more than one span. Returns a list of {entity, span_refs: [...]} where
    each span_ref is {kind, start, end}.

    This intelligence is visible ONLY to the gatekeeper LLM — it never
    surfaces to the agent. The agent sees only the selected spans via the
    submit_spans tool.
    """
    # extract capitalized multi-word phrases from each span
    # e.g. "Board of Directors", "Q3 Revenue", "Meridian Contract"
    entity_pattern = re.compile(
        r"\b(?:[A-Z][a-z]+(?:\s+(?:of|the|and|for)?\s*)?){2,}\b"
    )
    span_entities: list[set[str]] = []
    for s in spans:
        found = set()
        for m in entity_pattern.finditer(s.text):
            phrase = m.group().strip()
            # filter out sentence-start artifacts: a phrase at the very
            # start of a sentence is often just a capitalized common word
            if len(phrase) >= 4 and not phrase.isupper():
                found.add(phrase)
        span_entities.append(found)

    # build entity -> span refs map, keep only entities in 2+ spans
    entity_map: dict[str, list[dict]] = {}
    for i, s in enumerate(spans):
        for entity in span_entities[i]:
            ref = {"kind": s.kind, "start": s.start, "end": s.end}
            entity_map.setdefault(entity, []).append(ref)

    return [
        {"entity": entity, "span_refs": refs}
        for entity, refs in sorted(entity_map.items())
        if len(refs) >= 2
    ]


def _render_index(spans) -> str:
    parts = [f"<document_index doc_id_kind={spans and spans[0].kind!r}>"]
    for s in spans:
        parts.append(f'<span kind="{s.kind}" start={json.dumps(s.start)} end={json.dumps(s.end)}>')
        parts.append(s.text)
        parts.append("</span>")

    # intra-document relationships (visible to gatekeeper only)
    relations = _extract_span_relationships(spans)
    if relations:
        parts.append("<span_relations>")
        for r in relations:
            refs_str = ", ".join(
                f'{ref["kind"]}[{json.dumps(ref["start"])}..{json.dumps(ref["end"])}]'
                for ref in r["span_refs"]
            )
            parts.append(f'<relation entity="{r["entity"]}" spans="{refs_str}" />')
        parts.append("</span_relations>")

    parts.append("</document_index>")
    return "\n".join(parts)


def _validate_refs(raw_refs, spans, doc_id: str, content_hash: str) -> list[dict]:
    valid = {(s.kind, _key(s.start), _key(s.end)) for s in spans}
    refs = []
    for r in raw_refs:
        try:
            key = (r["kind"], _key(r["start"]), _key(r["end"]))
        except (KeyError, TypeError):
            continue
        if key in valid:
            refs.append({
                "doc_id": doc_id, "content_hash": content_hash,
                "kind": key[0], "start": r["start"], "end": r["end"],
            })
    return refs


def _key(v):
    return str(v)


@dataclass
class _PseudoSpan:
    """Adapter: a unified-index Unit rendered as a span for the LLM index.
    Order doubles as start/end — units have no intra-item offsets."""
    kind: str
    start: int
    end: int
    text: str
    unit_index: int


def select_units(
    units,
    reason: str,
    user_context: dict,
    platform: str = "",
    container: str = "",
    item_id: str = "",
) -> tuple[list[int], str, str]:
    """Live Gatekeeper selection over unified-index Units (the platform
    pipeline path — the uploads path uses select_spans).

    Units ARE the spans: no parser, order doubles as start/end. Returns
    (selected unit indexes, mode, selection_reason). An empty selection is
    a legitimate outcome ("nothing matches the reason"), never an error.
    Fail-closed: LLM failures raise GatekeeperError for the caller to
    convert into a no-evidence answer, never a fallback to unfiltered
    content.
    """
    if not units:
        return [], "live-llm", "item has no units"
    pseudo = [_PseudoSpan(kind=u.kind, start=u.order, end=u.order,
                          text=u.text, unit_index=i)
              for i, u in enumerate(units)]
    try:
        raw_refs, sel_reason = _llm_select(pseudo, reason, user_context)
    except GatekeeperError:
        raise
    except Exception as e:  # API/network/auth failures — never leak raw
        raise GatekeeperError(f"gatekeeper LLM unavailable: {type(e).__name__}: {e}") from e

    # validate: refs may only point at spans that exist (can only narrow)
    valid = {(s.kind, _key(s.start), _key(s.end)): s.unit_index for s in pseudo}
    indexes = []
    dropped = 0
    for r in raw_refs:
        try:
            key = (r["kind"], _key(r["start"]), _key(r["end"]))
        except (KeyError, TypeError):
            dropped += 1
            continue
        if key in valid and valid[key] not in indexes:
            indexes.append(valid[key])
        elif key not in valid:
            dropped += 1
    if dropped:
        logger.warning("gatekeeper cited %d non-existent span(s) — dropped "
                       "(can only narrow)", dropped)
    return indexes, "live-llm", (sel_reason or "").strip()[:200]


class GatekeeperError(Exception):
    """The gatekeeper could not complete selection (e.g. LLM unavailable)."""


def select_spans(
    plaintext: bytes,
    kind: str,
    doc_id: str,
    content_hash: str,
    reason: str,
    user_context: dict,
) -> tuple[list[dict], str, str]:
    """Returns (validated span refs, selection_mode, selection_reason).

    An empty selection is a legitimate outcome ("nothing in this document
    matches"), never an error — the caller receives ([], mode, reason).

    In test mode, the heuristic selector consults the audit log (via
    user_context['conn'] and user_context['file_ref'], when available)
    for past span selections on this file for similar reasons. This is
    purely intra-document intelligence — no file names or metadata from
    other files are ever surfaced."""
    spans = parsers.parse_to_spans(plaintext, kind)
    if not spans:
        raise ValueError("document has no extractable spans")

    if config.GATEKEEPER_MODE == "test":
        boost = _span_relevance_from_audit(
            user_context.get("conn"),
            user_context.get("file_ref", ""),
            reason,
        )
        refs, sel_reason = _heuristic_select(spans, reason, boost)
        mode = "test-heuristic"
    else:
        try:
            refs, sel_reason = _llm_select(spans, reason, user_context)
        except Exception as e:  # API/network/auth failures — never leak raw
            raise GatekeeperError(f"gatekeeper LLM unavailable: {type(e).__name__}: {e}") from e
        mode = "live-llm"

    validated = _validate_refs(refs, spans, doc_id, content_hash)
    sel_reason = (sel_reason or "").strip()[:200]
    return validated, mode, sel_reason


# --- live selection (Claude) -------------------------------------------------


def _llm_select(spans, reason: str, user_context: dict) -> list[dict]:
    import anthropic

    client = anthropic.Anthropic()
    prompt = (
        f"Access request reason (agent-asserted): {reason}\n"
        f"User context: clearance={user_context.get('max_clearance')}, "
        f"groups={user_context.get('groups')}\n\n"
        f"{_render_index(spans)}\n\n"
        "Submit the spans relevant to the reason."
    )
    response = client.messages.create(
        model=config.GATEKEEPER_MODEL,
        max_tokens=4096,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
        tools=[SUBMIT_SPANS_TOOL],
        tool_choice={"type": "tool", "name": "submit_spans"},
    )
    for block in response.content:
        if block.type == "tool_use" and block.name == "submit_spans":
            return block.input.get("spans", []), block.input.get("selection_reason", "")
    return [], ""


# --- offline heuristic (dev/test only; never used when mode=live) -------------


def _span_relevance_from_audit(conn, file_ref: str, reason: str) -> dict:
    """Query the audit log for past get_content responses on this file and
    build a span-frequency map: {(kind, start, end): count} for spans that
    were previously returned for reasons sharing keywords with the current
    reason.

    Purely intra-document: only queries responses for *this* file_ref, never
    surfaces names or metadata from other files. Ephemeral — rebuilt per
    selection call, no separate persistence.

    For the hackathon demo data volume (~50 entries) this LIKE scan is
    negligible. For production, a json_extract index or a denormalized
    response_spans table would be needed.
    """
    if conn is None or not file_ref:
        return {}

    reason_words = set(w for w in re.split(r"\W+", reason.lower()) if len(w) > 2)
    if not reason_words:
        return {}

    boost: dict[tuple, int] = {}
    try:
        for (payload_json,) in conn.execute(
            "SELECT payload FROM audit_log "
            "WHERE json_extract(payload, '$.event') = 'response' "
            "AND json_extract(payload, '$.file_ref') = ?",
            (file_ref,),
        ):
            import json as _json
            p = _json.loads(payload_json)
            returned = p.get("returned") or []
            if not returned:
                continue
            # find the corresponding request entry's reason — the response
            # itself stores gatekeeper_reason, but the request reason is in
            # the request entry with the same session_id/tool/file_ref
            # For the boost, we use the gatekeeper_reason as a proxy since
            # it is already desensitized and present in the response entry
            gk_reason = (p.get("gatekeeper_reason") or "").lower()
            gk_words = set(w for w in re.split(r"\W+", gk_reason) if len(w) > 2)
            # overlap: does this past selection relate to the current reason?
            overlap = reason_words & gk_words
            if not overlap:
                continue
            weight = len(overlap) / max(1, len(reason_words))
            for ref in returned:
                key = (ref.get("kind"), _key(ref.get("start")), _key(ref.get("end")))
                boost[key] = boost.get(key, 0) + weight
    except Exception:
        # audit query is best-effort; never break selection on audit failure
        return {}
    return boost


def _heuristic_select(
    spans,
    reason: str,
    audit_boost: dict | None = None,
) -> tuple[list[dict], str]:
    """TF-IDF span selector for offline/test mode.

    Scores each span by the sum of tf(t) * log(N / df(t)) for every reason
    term t that appears in the span. This down-weights common words that
    appear in many spans and up-weights distinctive terms.

    If audit_boost is provided (from past access patterns), spans that were
    previously selected for similar reasons receive a multiplicative boost.
    This is intra-document intelligence only — no cross-file discovery.

    When no span scores above zero, returns an empty selection — the gateway
    treats this as a legitimate "nothing relevant" 200 response with spans=[].
    This is the security-critical fix: the old fallback returned the first
    span regardless of relevance, potentially leaking sensitive content.
    """
    import math
    from collections import Counter

    audit_boost = audit_boost or {}
    N = len(spans)
    reason_terms = set(w for w in re.split(r"\W+", reason.lower()) if len(w) > 2)

    # document frequency: how many spans contain each term
    df: Counter[str] = Counter()
    span_term_counts: list[Counter[str]] = []
    for s in spans:
        terms = Counter(w for w in re.split(r"\W+", s.text.lower()) if len(w) > 2)
        span_term_counts.append(terms)
        df.update(terms.keys())

    scored = []
    for i, s in enumerate(spans):
        tc = span_term_counts[i]
        tfidf = sum(
            tc[t] * math.log(N / max(1, df[t]))
            for t in reason_terms if t in tc
        )
        # apply audit boost: spans previously selected for similar reasons
        # get a multiplicative uplift, so a span with moderate TF-IDF but
        # strong historical relevance can still be selected
        boost_key = (s.kind, _key(s.start), _key(s.end))
        boost_val = audit_boost.get(boost_key, 0)
        score = tfidf * (1 + boost_val) if boost_val else tfidf
        scored.append((score, i, s))

    scored.sort(key=lambda t: -t[0])
    top_k = min(3, max(1, len(scored) // 3))
    picked = [
        {"kind": s.kind, "start": s.start, "end": s.end}
        for score, _, s in scored[:top_k]
        if score > 0
    ]
    if not picked:
        return [], "No spans in this document match the access reason."
    return picked, f"Selected {len(picked)} span(s) by term relevance to the access reason."
