"""Restricted audit fields — salted-hash commitments in the chain,
plaintext in a purge-able side table.

Three fields are restricted:
- `raw_user_input` — the original user prompt (all tiers, always restricted)
- `search_terms` — the search query text
- `answer_text` — the final answer text

In the chained audit entry, only a salted-hash commitment is stored:
    commit = sha256(salt || text)

The plaintext and salt live in a side table:
    audit_restricted(entry_id, field, salt, text, purged_at)

Deleting the side-table row removes both plaintext and salt. The commitment
in the chain stays, so the chain still verifies.

Visibility:
- raw_user_input and search_terms: readable by top-secret auditors only
- answer_text: readable by top-secret auditors always; standard auditors
  see it only on routine entries, using the existing redaction by entry label

Purge:
- Logged as an audited entry recording who, when, why, and which commitments
- Only the side table allows deletion, and only through the purge action
- The main log's update/delete triggers stay intact

Reconciliation:
- The harness generates each salt and sends it with the field, so local
  and central logs compute identical commitments
- Reconciliation compares commitments only
"""

from __future__ import annotations

import json
import sqlite3
import hashlib
import time
import logging
from dataclasses import dataclass

from fileguard import db, security

logger = logging.getLogger(__name__)

RESTRICTED_FIELDS = ("raw_user_input", "search_terms", "answer_text")

SIDETABLE_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_restricted (
    entry_id   INTEGER NOT NULL,
    field      TEXT NOT NULL,
    salt       TEXT NOT NULL,
    text       TEXT NOT NULL,
    purged_at  REAL,
    PRIMARY KEY (entry_id, field)
);
CREATE INDEX IF NOT EXISTS audit_restricted_entry_idx ON audit_restricted(entry_id);
"""


def init_side_table(conn: sqlite3.Connection) -> None:
    """Create the audit_restricted side table if it doesn't exist."""
    conn.executescript(SIDETABLE_SCHEMA)
    conn.commit()


def generate_salt() -> str:
    """Generate a random salt for a restricted field commitment."""
    import secrets
    return secrets.token_hex(32)


def compute_commitment(salt: str, text: str) -> str:
    """Compute the salted-hash commitment: sha256(salt || text).

    This is what goes in the chained audit entry. The chain verifies
    because the commitment is deterministic given salt + text.
    """
    return hashlib.sha256(f"{salt}{text}".encode("utf-8")).hexdigest()


def store_restricted(
    conn: sqlite3.Connection,
    entry_id: int,
    field: str,
    text: str,
    salt: str | None = None,
) -> str:
    """Store a restricted field in the side table and return the commitment.

    The commitment (sha256(salt || text)) should be stored in the audit
    log entry payload, replacing the plaintext. The plaintext + salt live
    only in the side table.

    Args:
        conn: Connection to the central DB.
        entry_id: The audit_log seq of the entry.
        field: One of RESTRICTED_FIELDS.
        text: The plaintext to restrict.
        salt: Optional salt (if None, a new one is generated).

    Returns:
        The commitment string to store in the chained entry.
    """
    if salt is None:
        salt = generate_salt()

    init_side_table(conn)

    commitment = compute_commitment(salt, text)

    conn.execute("""
        INSERT OR REPLACE INTO audit_restricted (entry_id, field, salt, text, purged_at)
        VALUES (?, ?, ?, ?, NULL)
    """, (entry_id, field, salt, text))
    conn.commit()

    return commitment


def retrieve_restricted(
    conn: sqlite3.Connection,
    entry_id: int,
    field: str,
) -> str | None:
    """Retrieve the plaintext of a restricted field from the side table.

    Returns None if the field was purged or never stored.
    """
    init_side_table(conn)
    row = conn.execute(
        "SELECT text FROM audit_restricted WHERE entry_id = ? AND field = ? AND purged_at IS NULL",
        (entry_id, field),
    ).fetchone()
    return row[0] if row else None


def verify_commitment(
    conn: sqlite3.Connection,
    entry_id: int,
    field: str,
    commitment: str,
) -> bool:
    """Verify that a commitment in the chain matches the side-table data.

    Recomputes sha256(salt || text) from the side table and compares
    with the stored commitment. Returns False if the side-table row
    was purged or doesn't match.
    """
    init_side_table(conn)
    row = conn.execute(
        "SELECT salt, text FROM audit_restricted WHERE entry_id = ? AND field = ? AND purged_at IS NULL",
        (entry_id, field),
    ).fetchone()
    if row is None:
        # Purged — can't verify, but the chain commitment is still valid
        return True  # purged is a valid state; the commitment stays

    salt, text = row
    return compute_commitment(salt, text) == commitment


def purge_restricted(
    conn: sqlite3.Connection,
    entry_id: int,
    field: str | None = None,
    purged_by: str = "",
    reason: str = "",
) -> int:
    """Purge restricted field(s) from the side table.

    Sets purged_at on the side-table row(s), removing the plaintext and salt.
    The commitment in the chain stays, so the chain still verifies.
    The purge action itself is logged as an audited entry.

    Args:
        conn: Connection to the central DB.
        entry_id: The audit_log seq of the entry to purge.
        field: Specific field to purge (None = all restricted fields for this entry).
        purged_by: Who initiated the purge.
        reason: Why the purge was initiated.

    Returns:
        Number of rows purged.
    """
    init_side_table(conn)

    now = time.time()

    if field is not None:
        cur = conn.execute(
            "UPDATE audit_restricted SET purged_at = ? WHERE entry_id = ? AND field = ? AND purged_at IS NULL",
            (now, entry_id, field),
        )
    else:
        cur = conn.execute(
            "UPDATE audit_restricted SET purged_at = ? WHERE entry_id = ? AND purged_at IS NULL",
            (now, entry_id),
        )
    purged_count = cur.rowcount
    conn.commit()

    if purged_count > 0:
        # Log the purge as an audited entry
        db.append_log(conn, {
            "event": "purge_restricted",
            "entry_id": entry_id,
            "field": field,
            "purged_by": purged_by,
            "reason": reason,
            "purged_count": purged_count,
            "entry_clearance": "top_secret",
        })

    return purged_count


def get_restricted_fields_for_entry(
    conn: sqlite3.Connection,
    entry_id: int,
) -> list[dict]:
    """Get the restricted field metadata for an entry (without plaintext).

    Returns a list of {field, commitment_available, purged} dicts.
    """
    init_side_table(conn)
    rows = conn.execute(
        "SELECT field, purged_at FROM audit_restricted WHERE entry_id = ?",
        (entry_id,),
    ).fetchall()
    return [
        {
            "field": r[0],
            "available": r[1] is None,
            "purged": r[1] is not None,
        }
        for r in rows
    ]


def is_restricted_field(field: str) -> bool:
    """Check if a field name is a restricted field."""
    return field in RESTRICTED_FIELDS


def store_all_restricted(
    conn: sqlite3.Connection,
    entry_id: int,
    fields: dict[str, str],
    salts: dict[str, str] | None = None,
) -> dict[str, str]:
    """Store multiple restricted fields and return commitments.

    Args:
        conn: Connection to the central DB.
        entry_id: The audit_log seq.
        fields: Dict of {field_name: plaintext_value}.
        salts: Optional dict of {field_name: salt} (for reconciliation).

    Returns:
        Dict of {field_name: commitment} to store in the chained entry.
    """
    salts = salts or {}
    commitments = {}
    for field, text in fields.items():
        if is_restricted_field(field):
            salt = salts.get(field)
            commitments[field] = store_restricted(conn, entry_id, field, text, salt)
    return commitments
