"""Audit chat harness — a read-only LLM assistant over the audit log.

The auditor chats; the model answers by making ONE structured tool call
(`query_audit_log`) whose parameters are validated and executed by this
harness against `audit_query.query_audit`. Security invariants:

- REDACT-THEN-LLM: the query runs with the AUDITOR's tier, so entries are
  redacted/resolved server-side before the model ever sees them. The model
  cannot leak above-tier content because it never receives any.
- TIER IS A FILTER, NOT A GRANT: the model may pass `tier` to narrow by
  entry clearance ("show me confidential events only"). The harness
  validates the value and CLAMPS it to the auditor's capability
  (standard → confidential). Violations at higher tiers are always
  included in the form the auditor may see (reduced for standard).
- READ-ONLY: the only execution path is a SELECT via query_audit. The
  model cannot modify, purge or delete anything, and free-form queries
  never reach the log — only this schema.
- DETERMINISTIC IN TESTS: tests inject a scripted brain (see
  test_audit_chat.py); the live brain is Claude with the same tool schema.
"""

import json
import time
from dataclasses import dataclass, field
from typing import Any

from fileguard import CLEARANCE_ORDER, config

# the standard auditor's full-entry capability: everything at or below
# confidential (higher-tier events reach standard auditors only as reduced
# violations, applied by audit_query redaction)
_AUDITOR_CAP = {"standard": "confidential", "top_secret": "top_secret"}

KNOWN_EVENTS = ("request", "response", "rejection", "abuse_block",
                "policy_mismatch", "upload", "checkpoint",
                "purge_restricted", "reconciliation_flag")

MAX_QUERIES_PER_TURN = 5
MAX_ITERATIONS = 12

AUDIT_TOOLS_SPEC = [
    {
        "name": "query_audit_log",
        "description": "Query the central audit log. All parameters are "
                       "optional filters; omit what the question doesn't "
                       "need. Read-only.",
        "input_schema": {
            "type": "object",
            "properties": {
                "user_id": {"type": "string",
                            "description": "Filter by user, e.g. 'jdoe'"},
                "session_id": {"type": "string",
                               "description": "Filter by session id"},
                "event_type": {"type": "string",
                               "enum": list(KNOWN_EVENTS),
                               "description": "request | response | "
                               "rejection | abuse_block | policy_mismatch "
                               "| upload | purge_restricted | ..."},
                "platform": {"type": "string",
                             "description": "confluence | jira | slack | "
                             "drive | uploads | *"},
                "container": {"type": "string",
                              "description": "space / project / channel / "
                              "folder, e.g. 'PAYGW'"},
                "item_id": {"type": "string"},
                "decision": {"type": "string",
                             "enum": ["allowed", "denied"],
                             "description": "allowed = successful response; "
                             "denied = rejection or abuse_block"},
                "tier": {"type": "string",
                         "enum": ["open", "confidential", "secret",
                                  "top_secret"],
                         "description": "Show only entries whose clearance "
                         "tier is at most this level. Violations at higher "
                         "tiers are still included in the form you may see. "
                         "Omit for everything you are allowed to see."},
                "start_time": {"type": "string",
                               "description": "ISO 8601, e.g. "
                               "'2026-10-14T00:00:00+08:00'. Omit for the "
                               "earliest."},
                "end_time": {"type": "string",
                             "description": "ISO 8601. Omit for the latest."},
                "seq": {"type": "integer",
                        "description": "Exact central-log event number"},
                "limit": {"type": "integer",
                          "description": "Max entries to return "
                          "(default 50, max 200)"},
            },
            "additionalProperties": False,
        },
    },
]

SYSTEM_PROMPT = (
    "You are FileGuard's audit assistant for compliance officers. You "
    "answer questions about the central audit log by calling "
    "query_audit_log with structured filters, then summarising the "
    "entries you receive.\n"
    "Rules:\n"
    "- Cite every entry you mention by its seq (the central-log event "
    "number) — auditors will look it up.\n"
    "- You are read-only: there is no way to modify or delete log entries.\n"
    "- Only summarise what the query returned. If it returns nothing, say "
    "no matching entries were found — do not invent events.\n"
    "- Respecting the auditor's tier is automatic: entries you are not "
    "permitted to see are already filtered before you receive them, and "
    "higher-tier violations appear in reduced form. Never speculate about "
    "hidden content.\n"
    "- Be concise: answer the question, cite seqs, offer the obvious "
    "follow-up filter.\n"
    "- When listing multiple entries, format them as a markdown table with "
    "columns for seq, time, user and what happened."
)


def _parse_time(value: str) -> float | None:
    """ISO 8601 (or unix seconds) → epoch; None for 'earliest'/'latest'/blank."""
    v = (value or "").strip()
    if not v or v.lower() in ("earliest", "latest"):
        return None
    try:
        return float(v)  # raw unix seconds
    except ValueError:
        pass
    from datetime import datetime
    try:
        return datetime.fromisoformat(v).timestamp()
    except ValueError:
        raise ValueError(f"unparseable time: {v!r} (use ISO 8601)")


@dataclass
class AuditChatState:
    level: str                      # "standard" | "top_secret"
    messages: list = field(default_factory=list)
    queries_this_turn: int = 0


class AuditChatError(RuntimeError):
    """The audit brain cannot run (e.g. missing/bad API key)."""

    HELP = (
        "The audit assistant needs an Anthropic API key:\n"
        "```\nexport ANTHROPIC_API_KEY=sk-ant-...\n```"
    )


class AuditChatHarness:
    """Read-only LLM assistant over the central audit log."""

    def __init__(self, level: str, brain=None, client=None):
        from fileguard import db
        self.st = AuditChatState(level=level)
        self.brain = brain or self._live_brain
        self._db_mod = db
        self.st.messages.append({"role": "system", "content": SYSTEM_PROMPT})

    # --- public API ---------------------------------------------------------

    def chat(self, user_input: str) -> dict:
        """One auditor turn: returns {"answer", "queries", "entries"}."""
        self.st.queries_this_turn = 0
        self.st.messages.append({"role": "user", "content": user_input})
        last_entries: list = []
        queries = 0
        for _ in range(MAX_ITERATIONS):
            response = self.brain(
                [dict(m) for m in self.st.messages if m["role"] != "system"],
                "\n\n".join(m["content"] for m in self.st.messages
                            if m["role"] == "system"))
            self.st.messages.append({"role": "assistant",
                                     "content": response.content})
            if response.stop_reason != "tool_use":
                text = "".join(b.text for b in response.content
                               if b.type == "text")
                return {"answer": text, "queries": queries,
                        "entries": last_entries}
            tool_results = []
            for block in response.content:
                if block.type != "tool_use":
                    continue
                outcome, entries, executed = self._execute(block)
                if executed:
                    queries += 1
                    self.st.queries_this_turn += 1
                    if entries:
                        last_entries = entries
                tool_results.append(outcome)
            self.st.messages.append({"role": "user",
                                     "content": tool_results})
        return {"answer": "Query budget exhausted for this turn.",
                "queries": queries, "entries": last_entries}

    # --- tool execution (the rigid part) -------------------------------------

    def _execute(self, block) -> tuple[dict, list, bool]:
        """Returns (tool_result, compact_entries, executed)."""
        name, args = block.name, dict(block.input or {})
        if name != "query_audit_log":
            return ({"type": "tool_result", "tool_use_id": block.id,
                     "is_error": True,
                     "content": "Unknown tool — only query_audit_log exists."},
                    [], False)
        if self.st.queries_this_turn >= MAX_QUERIES_PER_TURN:
            return ({"type": "tool_result", "tool_use_id": block.id,
                     "is_error": True,
                     "content": f"At most {MAX_QUERIES_PER_TURN} log queries "
                                "per turn. Summarise what you have."},
                    [], False)
        try:
            payload, compact = self._run_query(args)
        except ValueError as e:
            return ({"type": "tool_result", "tool_use_id": block.id,
                     "is_error": True,
                     "content": f"Invalid filter: {e}"}, [], False)
        content = json.dumps(payload)
        return ({"type": "tool_result", "tool_use_id": block.id,
                 "content": content}, compact, True)

    def _run_query(self, args: dict) -> tuple[dict, list]:
        """Returns (payload-for-LLM, compact-entries)."""
        from fileguard import audit_query

        # tier: validated, clamped to the auditor's capability
        tier = args.get("tier")
        if tier is not None:
            if tier not in CLEARANCE_ORDER:
                raise ValueError(f"unknown tier {tier!r}")
            cap = _AUDITOR_CAP[self.st.level]
            if CLEARANCE_ORDER[tier] > CLEARANCE_ORDER[cap]:
                tier = cap  # clamp: standard cannot widen to top_secret

        def _time(v):
            return _parse_time(v) if v else None

        q = audit_query.AuditQuery(
            user_id=(args.get("user_id") or "").strip() or None,
            session_id=(args.get("session_id") or "").strip() or None,
            event_type=(args.get("event_type") or "").strip() or None,
            platform=(args.get("platform") or "").strip() or None,
            container=(args.get("container") or "").strip() or None,
            item_id=(args.get("item_id") or "").strip() or None,
            decision=(args.get("decision") or "").strip() or None,
            date_from=_time(args.get("start_time")),
            date_to=_time(args.get("end_time")),
            seq=args.get("seq"),
            limit=min(max(int(args.get("limit") or 50), 1), 200),
        )
        conn = self._db_mod.central()
        try:
            # redact-then-LLM: tier redaction + restricted-field resolution
            # happen HERE, with the auditor's level — the model only ever
            # receives what its tier permits
            result = audit_query.query_audit(conn, q, self.st.level)
        finally:
            conn.close()

        entries = result.entries

        # tier filter (narrowing): keep full entries whose clearance is at
        # most the requested tier; violations always survive in the form
        # the auditor may see (already reduced for standard)
        if tier is not None:
            from fileguard.audit_query import VIOLATION_EVENTS
            entries = [e for e in entries
                       if e.get("event") in VIOLATION_EVENTS
                       or CLEARANCE_ORDER.get(e.get("entry_clearance"), 3)
                       <= CLEARANCE_ORDER.get(tier, 3)]

        compact = [self._compact(e) for e in entries]
        payload = {
            "total_matching": result.total,
            "returned": len(compact),
            "note": "citations: use each entry's seq",
            "entries": compact,
        }
        return payload, compact

    @staticmethod
    def _compact(e: dict) -> dict:
        out = {
            "seq": e.get("seq"),
            "ts": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e.get("ts", 0))),
            "event": e.get("event"),
            "user_id": e.get("user_id"),
            "tool": e.get("tool"),
            "tier": e.get("entry_clearance"),
            "redacted": e.get("redacted", False),
        }
        for k in ("file_ref", "item_id", "container", "platform", "code",
                  "warning", "gatekeeper_reason", "delivery",
                  "grounding_level", "detail", "reason", "answer_text"):
            if e.get(k) not in (None, "", [], {}):
                out[k] = e[k] if not isinstance(e[k], str) or len(e[k]) <= 300 \
                    else e[k][:300] + "…"
        if isinstance(e.get("returned"), list) and e["returned"]:
            out["returned_count"] = len(e["returned"])
        return out

    # --- brains ---------------------------------------------------------------

    @staticmethod
    def _live_brain(messages, system):
        import anthropic
        try:
            client = anthropic.Anthropic()
        except Exception as e:
            raise AuditChatError(AuditChatError.HELP) from e
        try:
            return client.messages.create(
                model=config.GATEKEEPER_MODEL,
                max_tokens=2048,
                system=system,
                messages=messages,
                tools=AUDIT_TOOLS_SPEC,
            )
        except anthropic.AuthenticationError as e:
            raise AuditChatError(AuditChatError.HELP) from e
