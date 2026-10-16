"""Session Service: user token -> HMAC-signed ScopedGrant.

Folds into the Gateway process for the hackathon. The grant travels in the
RequestObject credentials; it never enters model context.
"""

import hashlib
import json
import sqlite3
import time
import uuid

from . import config, db, security


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def issue_grant(token: str, conn: sqlite3.Connection | None = None) -> str | None:
    """Validate the user token and return a signed grant string, or None.

    The grant embeds the current permission epoch. The gateway rejects
    grants with a stale epoch (hard gate — see identity.check_epoch).
    """
    own = conn is None
    conn = conn or db.central()
    try:
        row = conn.execute(
            "SELECT user_id, max_clearance, groups FROM users WHERE token_hash = ?",
            (_hash_token(token),),
        ).fetchone()
        if row is None:
            return None
        user_id, max_clearance, groups = row

        # Get the current epoch from the directory table if it exists
        epoch = _get_epoch(conn, user_id)

        grant = {
            "user_id": user_id,
            "max_clearance": max_clearance,
            "groups": json.loads(groups),
            "session_id": uuid.uuid4().hex,
            "exp": int(time.time()) + config.GRANT_TTL_SECONDS,
            "epoch": epoch,
        }
        return security.sign_grant(grant)
    finally:
        if own:
            conn.close()


def _get_epoch(conn: sqlite3.Connection, user_id: str) -> int:
    """Get the permission epoch for a user. Falls back to 0 if the
    directory table doesn't exist yet (backward compat with old grants)."""
    try:
        from . import identity
        identity.init_directory(conn)
        emp = identity.lookup_employee(conn, user_id)
        if emp:
            return emp["epoch"]
        # Fall back to global epoch
        return identity.get_global_epoch(conn)
    except Exception:
        return 0


def user_profile(token: str) -> dict | None:
    """Display profile for the signed-in user (sidebar, etc.)."""
    conn = db.central()
    try:
        row = conn.execute(
            "SELECT user_id, name, position, max_clearance, groups "
            "FROM users WHERE token_hash = ?",
            (_hash_token(token),),
        ).fetchone()
        if row is None:
            return None
        return {
            "user_id": row[0], "name": row[1], "position": row[2],
            "max_clearance": row[3], "groups": json.loads(row[4]),
        }
    finally:
        conn.close()


def issue_audit_level(token: str) -> str | None:
    """Validate an audit-console token. Returns 'standard' | 'top_secret'.

    Deliberately separate from issue_grant: audit tokens and chat tokens are
    not interchangeable in either direction.
    """
    conn = db.central()
    try:
        row = conn.execute(
            "SELECT level FROM audit_tokens WHERE token_hash = ?",
            (_hash_token(token),),
        ).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


# --- confirmation nonces (replay-proof one-click) ----------------------------

_NONCE_SCHEMA = """
CREATE TABLE IF NOT EXISTS confirm_nonces (
    nonce      TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0,
    decision   TEXT
);
"""


def init_nonce_table(conn: sqlite3.Connection) -> None:
    conn.executescript(_NONCE_SCHEMA)
    conn.commit()


def register_pending(conn: sqlite3.Connection, session_id: str, request_id: str) -> str:
    """Issue a single-use nonce for one pending top-secret request."""
    init_nonce_table(conn)
    nonce = security.new_nonce()
    conn.execute(
        "INSERT INTO confirm_nonces (nonce, session_id, request_id, expires_at) VALUES (?,?,?,?)",
        (nonce, session_id, request_id, int(time.time()) + config.CONFIRM_NONCE_TTL),
    )
    conn.commit()
    return nonce


def consume_nonce(
    conn: sqlite3.Connection, nonce: str, session_id: str
) -> tuple[bool, str]:
    """Atomically consume a nonce.

    Returns (approved, decision):
      first use, valid      -> (True, "approved")
      reuse (any reason)    -> (False, "duplicate")   # idempotent no-op
      expired / unknown     -> (False, "invalid")
    """
    init_nonce_table(conn)
    row = conn.execute(
        "SELECT used, decision, expires_at, request_id FROM confirm_nonces WHERE nonce = ?",
        (nonce,),
    ).fetchone()
    if row is None:
        return False, "invalid"
    used, decision, expires_at, _ = row
    if used:
        return False, "duplicate"
    if expires_at < int(time.time()):
        return False, "invalid"
    # Atomic consume: UNIQUE on nonce means a racing duplicate hits IntegrityError.
    cur = conn.execute(
        "UPDATE confirm_nonces SET used = 1, decision = 'approved' "
        "WHERE nonce = ? AND session_id = ? AND used = 0",
        (nonce, session_id),
    )
    conn.commit()
    if cur.rowcount != 1:
        return False, "duplicate"
    return True, "approved"
