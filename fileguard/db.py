"""SQLite storage: metadata DB and append-only hash-chained audit logs."""

import json
import sqlite3
import time

from . import config, security

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    user_id     TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    position    TEXT NOT NULL DEFAULT '',
    max_clearance TEXT NOT NULL,
    groups      TEXT NOT NULL,          -- JSON array of flat labels
    token_hash  TEXT NOT NULL
);

-- Audit-console tokens. Separate from user tokens by design: the two are
-- never interchangeable. level: 'standard' (redacted view) | 'top_secret'
-- (full view, including sensitive content).
CREATE TABLE IF NOT EXISTS audit_tokens (
    token_hash  TEXT PRIMARY KEY,
    level       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS files (
    name          TEXT PRIMARY KEY,     -- unique display name
    file_id       TEXT NOT NULL,        -- sha256 of plaintext (content-addressed);
                                        -- NOT unique: identical bytes may be
                                        -- registered under different names/metadata
    kind          TEXT NOT NULL,        -- pdf | xlsx | docx
    base_clearance TEXT NOT NULL,
    groups        TEXT NOT NULL,        -- JSON array; empty = clearance-only
    label_date    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS files_file_id_idx ON files(file_id);

-- Append-only audit log. Triggers below make UPDATE/DELETE impossible.
CREATE TABLE IF NOT EXISTS audit_log (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         INTEGER NOT NULL,
    prev_hash  TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    payload    TEXT NOT NULL           -- canonical JSON
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
"""


def connect(path) -> sqlite3.Connection:
    path = str(path)
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(SCHEMA)
    try:  # dev migration for DBs created before the position column
        conn.execute("ALTER TABLE users ADD COLUMN position TEXT NOT NULL DEFAULT ''")
        conn.commit()
    except sqlite3.OperationalError:
        pass
    _migrate_files_pk(conn)
    try:  # dev migration: uploader attribution on files
        conn.execute("ALTER TABLE files ADD COLUMN uploaded_by TEXT")
        conn.commit()
    except sqlite3.OperationalError:
        pass
    return conn


def _migrate_files_pk(conn: sqlite3.Connection) -> None:
    """Dev migration: files PK moved from file_id to name, so identical
    content can be registered multiple times with different metadata."""
    cols = conn.execute("PRAGMA table_info(files)").fetchall()
    if not cols:
        return
    pk_cols = [c[1] for c in cols if c[5]]
    if pk_cols != ["file_id"]:
        return
    conn.executescript("""
        CREATE TABLE files_new (
            name TEXT PRIMARY KEY,
            file_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            base_clearance TEXT NOT NULL,
            groups TEXT NOT NULL,
            label_date TEXT NOT NULL);
        INSERT INTO files_new (name, file_id, kind, base_clearance, groups, label_date)
            SELECT name, file_id, kind, base_clearance, groups, label_date FROM files;
        DROP TABLE files;
        ALTER TABLE files_new RENAME TO files;
        CREATE INDEX IF NOT EXISTS files_file_id_idx ON files(file_id);
    """)
    conn.commit()


def central() -> sqlite3.Connection:
    config.CENTRAL_DB.parent.mkdir(parents=True, exist_ok=True)
    return connect(config.CENTRAL_DB)


def local() -> sqlite3.Connection:
    config.LOCAL_DB.parent.mkdir(parents=True, exist_ok=True)
    return connect(config.LOCAL_DB)


def append_log(conn: sqlite3.Connection, payload: dict, ts: int | None = None) -> dict:
    """Append one hash-chained entry. Returns {seq, entry_hash}.
    `ts` overrides the wall clock — used only by demo-seed to backdate the
    curated demo history; live code never passes it."""
    row = conn.execute(
        "SELECT entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
    ).fetchone()
    prev_hash = row[0] if row else security.GENESIS
    payload = dict(payload, ts=int(ts if ts is not None else time.time()))
    eh = security.entry_hash(prev_hash, payload)
    cur = conn.execute(
        "INSERT INTO audit_log (ts, prev_hash, entry_hash, payload) VALUES (?,?,?,?)",
        (payload["ts"], prev_hash, eh, security.canonical_json(payload).decode()),
    )
    conn.commit()
    return {"seq": cur.lastrowid, "entry_hash": eh}


def verify_chain(conn: sqlite3.Connection) -> tuple[bool, int]:
    """Recompute the chain; return (ok, entries_checked)."""
    prev = security.GENESIS
    n = 0
    for seq, ts, ph, eh, payload_json in conn.execute(
        "SELECT seq, ts, prev_hash, entry_hash, payload FROM audit_log ORDER BY seq"
    ):
        payload = json.loads(payload_json)
        if ph != prev:
            return False, n
        if security.entry_hash(prev, payload) != eh or payload.get("ts") != ts:
            return False, n
        prev = eh
        n += 1
    return True, n
