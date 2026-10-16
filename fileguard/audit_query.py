"""Audit query API — structured filters over the audit log.

Filters: user, platform, container, item_id, decision (allowed/denied),
event_type, date range. Sorted and paginated. Export to CSV or JSON.

Supports:
- "Who retrieved this document?" (filter by item_id + decision=allowed)
- "What did this user access?" (filter by user_id)

Keeps the two auditor tiers and the existing redaction rules:
- standard: routine entries in full, violations reduced to who/type/when,
  secret/top_secret accesses omitted
- top_secret: everything, including restricted fields (retrieved from
  the side table)

Restricted fields (raw_user_input, search_terms, answer_text) are
resolved from the side table only for top_secret auditors.
"""

from __future__ import annotations

import json
import sqlite3
import time
import csv
import io
import logging
from dataclasses import dataclass, field
from typing import Any

from fileguard import CLEARANCE_ORDER
from fileguard.audit_restricted import (
    retrieve_restricted,
)

logger = logging.getLogger(__name__)

VIOLATION_EVENTS = ("rejection", "abuse_block", "policy_mismatch")
VIOLATION_SENSITIVE_FIELDS = (
    "file_ref", "session_id", "reason", "trace",
    "raw_user_input", "search_terms", "detail", "returned",
)


@dataclass
class AuditQuery:
    """Filter parameters for the audit log query."""
    user_id: str | None = None
    platform: str | None = None
    container: str | None = None
    item_id: str | None = None
    decision: str | None = None  # "allowed" | "denied"
    event_type: str | None = None
    date_from: float | None = None  # unix timestamp
    date_to: float | None = None
    session_id: str | None = None
    seq: int | None = None  # exact central-log event number
    sort_by: str = "ts"  # ts | seq | user_id
    sort_desc: bool = True
    limit: int = 100
    offset: int = 0


@dataclass
class AuditQueryResult:
    """Result of an audit log query."""
    entries: list[dict]
    total: int
    limit: int
    offset: int


def query_audit(
    conn: sqlite3.Connection,
    q: AuditQuery,
    audit_level: str | None = None,
) -> AuditQueryResult:
    """Query the audit log with structured filters.

    Args:
        conn: Connection to the central DB.
        q: Query parameters.
        audit_level: "standard" | "top_secret" | None.
            None = not signed in (routine only, no violations detail).
            standard = routine in full, violations reduced.
            top_secret = everything including restricted fields.

    Returns:
        AuditQueryResult with paginated entries and total count.
    """
    # Build WHERE clause from JSON-extracted fields in the payload
    conditions = []
    params = []

    if q.user_id:
        conditions.append("json_extract(payload, '$.user_id') = ?")
        params.append(q.user_id)

    if q.platform:
        conditions.append("json_extract(payload, '$.platform') = ?")
        params.append(q.platform)

    if q.container:
        conditions.append("json_extract(payload, '$.container') = ?")
        params.append(q.container)

    if q.item_id:
        conditions.append("json_extract(payload, '$.item_id') = ?")
        params.append(q.item_id)

    if q.event_type:
        conditions.append("json_extract(payload, '$.event') = ?")
        params.append(q.event_type)

    if q.decision:
        if q.decision == "allowed":
            conditions.append("json_extract(payload, '$.event') = 'response'")
        elif q.decision == "denied":
            conditions.append("json_extract(payload, '$.event') IN ('rejection', 'abuse_block')")

    if q.date_from:
        conditions.append("ts >= ?")
        params.append(int(q.date_from))

    if q.date_to:
        conditions.append("ts <= ?")
        params.append(int(q.date_to))

    if q.session_id:
        conditions.append("json_extract(payload, '$.session_id') = ?")
        params.append(q.session_id)

    if q.seq is not None:
        conditions.append("seq = ?")
        params.append(int(q.seq))

    where_clause = " AND ".join(conditions) if conditions else "1=1"

    # Sort
    sort_col = "ts" if q.sort_by == "ts" else ("seq" if q.sort_by == "seq" else "ts")
    sort_dir = "DESC" if q.sort_desc else "ASC"

    # Count total matching entries (before pagination)
    count_sql = f"SELECT COUNT(*) FROM audit_log WHERE {where_clause}"
    total = conn.execute(count_sql, params).fetchone()[0]

    # Fetch entries with pagination
    query_sql = f"""
        SELECT seq, ts, payload FROM audit_log
        WHERE {where_clause}
        ORDER BY {sort_col} {sort_dir}
        LIMIT ? OFFSET ?
    """
    rows = conn.execute(query_sql, params + [q.limit, q.offset]).fetchall()

    # Determine viewer clearance
    viewer = {"standard": "confidential", "top_secret": "top_secret"}.get(audit_level)

    entries = []
    for seq, ts, payload_json in rows:
        entry = json.loads(payload_json)
        entry["seq"] = seq
        entry = _apply_redaction(entry, audit_level, viewer, conn)
        if entry is not None:
            entries.append(entry)

    return AuditQueryResult(
        entries=entries,
        total=total,
        limit=q.limit,
        offset=q.offset,
    )


def _apply_redaction(
    entry: dict,
    audit_level: str | None,
    viewer: str | None,
    conn: sqlite3.Connection | None = None,
) -> dict | None:
    """Apply redaction rules based on the auditor's tier.

    Returns the (possibly redacted) entry, or None if the entry should
    be omitted entirely.

    Restricted fields (D7): the chain stores sha256(salt||text) commitments
    only; plaintext lives in the purge-able side table. Resolution here:
      top_secret viewer -> commitments resolved to plaintext where the
                           side-table row still exists, "[purged]" otherwise
      standard viewer   -> raw_user_input / search_terms dropped entirely
                           (never visible at this tier); answer_text
                           resolved (only routine entries reach here at
                           this tier, per the entry-tier omission below)
    Without a conn (legacy callers), commitments are left as-is.
    """
    entry_clearance = entry.get("entry_clearance", "open")
    sensitive = entry_clearance in ("secret", "top_secret")
    violation = entry.get("event") in VIOLATION_EVENTS

    full_access = viewer is not None and (
        not sensitive or CLEARANCE_ORDER[viewer] >= CLEARANCE_ORDER[entry_clearance]
    )

    if full_access:
        result = {**entry, "redacted": False}
        if conn is not None:
            from .audit_restricted import retrieve_restricted
            seq = result.get("seq")
            if viewer == "top_secret":
                for field in ("raw_user_input", "search_terms", "answer_text"):
                    if field in result:
                        text = retrieve_restricted(conn, seq, field)
                        result[field] = text if text is not None else "[purged]"
            else:
                for field in ("raw_user_input", "search_terms"):
                    result.pop(field, None)
                if "answer_text" in result:
                    text = retrieve_restricted(conn, seq, "answer_text")
                    result["answer_text"] = text if text is not None else "[purged]"
        return result

    elif violation and audit_level:
        # Standard auditor: violations are recorded but reduced
        redacted = {
            "seq": entry.get("seq"),
            "ts": entry.get("ts"),
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
        return redacted
    else:
        # Normal secret+ access below the viewer's level — omitted entirely
        return None


def query_who_accessed(
    conn: sqlite3.Connection,
    platform: str,
    item_id: str,
    audit_level: str | None = None,
    date_from: float | None = None,
    date_to: float | None = None,
) -> list[dict]:
    """Who retrieved/accessed this document?

    Returns a list of entries where this item was accessed (allowed only).
    """
    q = AuditQuery(
        platform=platform,
        item_id=item_id,
        decision="allowed",
        date_from=date_from,
        date_to=date_to,
        sort_by="ts",
        sort_desc=False,
        limit=1000,
    )
    result = query_audit(conn, q, audit_level)
    return result.entries


def query_user_access(
    conn: sqlite3.Connection,
    user_id: str,
    audit_level: str | None = None,
    date_from: float | None = None,
    date_to: float | None = None,
    platform: str | None = None,
    container: str | None = None,
) -> list[dict]:
    """What did this user access?

    Returns a list of entries for this user's accesses.
    """
    q = AuditQuery(
        user_id=user_id,
        platform=platform,
        container=container,
        date_from=date_from,
        date_to=date_to,
        sort_by="ts",
        sort_desc=False,
        limit=1000,
    )
    result = query_audit(conn, q, audit_level)
    return result.entries


def export_csv(entries: list[dict]) -> str:
    """Export audit entries to CSV format.

    Returns the CSV as a string.
    """
    if not entries:
        return ""

    # Collect all column names across entries
    columns = set()
    for e in entries:
        columns.update(e.keys())
    columns = sorted(columns)

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for e in entries:
        # Flatten nested values
        flat = {}
        for k, v in e.items():
            if isinstance(v, (dict, list)):
                flat[k] = json.dumps(v)
            else:
                flat[k] = v
        writer.writerow(flat)

    return output.getvalue()


def export_json(entries: list[dict]) -> str:
    """Export audit entries to JSON format.

    Returns the JSON as a string.
    """
    return json.dumps(entries, indent=2, ensure_ascii=False, default=str)


def resolve_restricted_fields(
    conn: sqlite3.Connection,
    entry: dict,
) -> dict:
    """Resolve restricted field commitments from the side table.

    For top-secret auditors, replaces commitment values with the actual
    plaintext from the side table (if not purged).

    Args:
        conn: Connection to the central DB.
        entry: The audit entry (must have 'seq').

    Returns:
        The entry with restricted fields resolved (if available).
    """
    entry_id = entry.get("seq")
    if entry_id is None:
        return entry

    result = dict(entry)
    for field in ("raw_user_input", "search_terms", "answer_text"):
        if field in result:
            plaintext = retrieve_restricted(conn, entry_id, field)
            if plaintext is not None:
                result[field] = plaintext
            # If purged, keep the commitment as-is

    return result
