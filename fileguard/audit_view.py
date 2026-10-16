"""Audit viewer access rules — the audit log is itself sensitive.

Two audit-console levels (from audit tokens — never chat tokens):

  standard   -> routine entries in full
             + VIOLATIONS (rejections / abuse blocks) at ANY tier, reduced to
               employee, violation type, time — no file name or specifics
             - normal accesses rated secret/top secret are NOT SHOWN AT ALL
  top_secret -> everything, fully unredacted, including traces and raw input
                (no blind spots for the people allowed to look)
"""

import json

from . import CLEARANCE_ORDER

VIOLATION_EVENTS = ("rejection", "abuse_block", "policy_mismatch")

# fields stripped from violations shown to the standard auditor
VIOLATION_SENSITIVE_FIELDS = ("file_ref", "session_id", "reason", "trace",
                              "raw_user_input", "detail", "returned")


def view_entries(conn, audit_level: str | None) -> list[dict]:
    """Render the central audit log for an audit-console sign-in.
    audit_level None = not signed in: routine entries only, no violations detail."""
    viewer = {"standard": "confidential", "top_secret": "top_secret"}.get(audit_level)
    file_names = {row[0]: row[1] for row in conn.execute("SELECT file_id, name FROM files")}
    out = []
    for seq, ts, payload_json in conn.execute(
        "SELECT seq, ts, payload FROM audit_log ORDER BY seq"
    ):
        entry = json.loads(payload_json)
        entry_clearance = entry.get("entry_clearance", "open")
        sensitive = entry_clearance in ("secret", "top_secret")
        violation = entry.get("event") in VIOLATION_EVENTS
        full_access = viewer is not None and (
            not sensitive or CLEARANCE_ORDER[viewer] >= CLEARANCE_ORDER[entry_clearance]
        )

        if full_access:
            resolved = {"seq": seq, **entry, "redacted": False}
            # Restricted fields (D7): the chain stores commitments only.
            #   top_secret viewer -> resolve to plaintext where not purged
            #   standard viewer   -> answer_text resolved (routine entries
            #                        only reach here anyway); raw_user_input /
            #                        search_terms commitments dropped entirely
            from .audit_query import resolve_restricted_fields
            from .audit_restricted import retrieve_restricted
            if viewer == "top_secret":
                resolved = resolve_restricted_fields(conn, resolved)
            else:
                for f in ("raw_user_input", "search_terms"):
                    resolved.pop(f, None)
                if "answer_text" in resolved:
                    if retrieve_restricted(conn, seq, "answer_text") is None:
                        resolved["answer_text"] = "[purged]"
                    else:
                        resolved = resolve_restricted_fields(conn, resolved)
            # show the human-readable file name alongside any file reference
            ref = resolved.get("file_ref")
            if ref:
                resolved["file_name"] = file_names.get(ref, ref)
            out.append(resolved)
        elif violation and audit_level:
            # standard auditor: violations are always recorded — but only
            # who/what-type/when, never the specifics (incl. the file name)
            redacted = {
                "seq": seq,
                "ts": ts,
                "event": entry.get("event"),
                "user_id": entry.get("user_id"),
                "tool": entry.get("tool"),
                "code": entry.get("code"),
                "warning": entry.get("warning"),
                "entry_clearance": entry_clearance,
                "redacted": True,
                "redacted_fields": [f for f in VIOLATION_SENSITIVE_FIELDS
                                    if f in entry],
            }
            out.append(redacted)
        # else: normal secret+ access below the viewer's level — omitted entirely
    return out
