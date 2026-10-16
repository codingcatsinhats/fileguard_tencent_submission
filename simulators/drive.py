"""Google Drive simulator: stateful HTTP server backed by SQLite.

Implements:
- files list + get with parents
- permissions list per file
- changes feed with page token

Permission semantics: user reads if in file permissions, or parent folder's,
or domain/link-sharing; removed shares and trashed files grant nothing.
"""

from __future__ import annotations

import json
import sqlite3
import sys
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, Header, Query

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import parse_bearer, validate_token, mount_scenario_endpoints, is_sync_admin  # noqa: E402
from evaluators import drive_can_read  # noqa: E402

SCHEMA = """
CREATE TABLE IF NOT EXISTS folders (
    path TEXT PRIMARY KEY,
    permissions TEXT NOT NULL,    -- JSON: [{type, target}]
    label TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS files (
    key TEXT PRIMARY KEY,
    folder TEXT NOT NULL REFERENCES folders(path),
    title TEXT NOT NULL,
    permissions TEXT NOT NULL,    -- JSON: [{type, target}] or 'inherit'
    link_sharing TEXT,            -- NULL or 'anyone_with_link'
    content TEXT NOT NULL,
    is_trashed INTEGER DEFAULT 0,
    updated_ts REAL NOT NULL,
    version INTEGER DEFAULT 1
);
CREATE INDEX IF NOT EXISTS files_folder_idx ON files(folder);
CREATE INDEX IF NOT EXISTS files_updated_idx ON files(updated_ts);

CREATE TABLE IF NOT EXISTS changes_log (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    file_key TEXT NOT NULL,
    change_type TEXT NOT NULL,    -- created | updated | trashed | permission_removed
    ts REAL NOT NULL,
    details TEXT NOT NULL DEFAULT '{}'
);
"""

app = FastAPI(title="Drive Simulator")
_db_path: str | None = None


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def _parse_permissions(perm_str: str) -> list[dict]:
    """Parse 'group:eng:viewer' or 'user:tom:viewer,user:vendor@...' format."""
    if perm_str == "anyone_with_link":
        return [{"type": "anyone", "target": "*"}]

    perms = []
    for part in perm_str.split(","):
        part = part.strip()
        if part.startswith("user:"):
            pieces = part.split(":")
            perms.append({"type": "user", "target": pieces[1]})
        elif part.startswith("group:"):
            pieces = part.split(":")
            perms.append({"type": "group", "target": pieces[1]})
        elif part.startswith("domain:"):
            pieces = part.split(":")
            perms.append({"type": "domain", "target": pieces[1]})
    return perms


def seed(data: dict, db_path: str):
    global _db_path
    _db_path = db_path

    conn = _conn()
    conn.executescript(SCHEMA)

    # Folders
    for path, sharing, label in data["drive_folders"]:
        perms = _parse_permissions(sharing)
        conn.execute(
            "INSERT OR REPLACE INTO folders (path, permissions, label) VALUES (?,?,?)",
            (path, json.dumps(perms), label),
        )

    # Files
    for item in data["drive_files"]:
        key, folder, title, sharing, label, content, updated_rel = item
        from company_a.story import _resolve_ts
        updated_ts = _resolve_ts(updated_rel, data["now_ts"])
        file_perms = _parse_permissions(sharing) if sharing != "inherit" else "inherit"
        link_sharing = "anyone_with_link" if sharing == "anyone_with_link" else None
        conn.execute(
            "INSERT OR REPLACE INTO files (key, folder, title, permissions, link_sharing, content, is_trashed, updated_ts, version) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (key, folder, title,
             json.dumps(file_perms) if isinstance(file_perms, list) else file_perms,
             link_sharing, content, 0, updated_ts, 1),
        )

    # Filler files
    for ff in data["filler"]["drive"]:
        conn.execute(
            "INSERT OR REPLACE INTO files (key, folder, title, permissions, link_sharing, content, is_trashed, updated_ts, version) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (ff["key"], ff["folder"], ff["title"], json.dumps([]), None,
             ff["text"], 0, ff["updated_ts"], 1),
        )

    conn.commit()
    conn.close()


def _get_file_permissions(conn, file_row) -> list[dict]:
    """Get effective file permissions (inherit means use folder's)."""
    raw = file_row["permissions"]
    if raw == "inherit":
        folder = conn.execute("SELECT * FROM folders WHERE path = ?", (file_row["folder"],)).fetchone()
        return json.loads(folder["permissions"]) if folder else []
    return json.loads(raw)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/files")
def list_files(updated_since: float = Query(None), authorization: str = Header(None)):
    conn = _conn()
    try:
        token = parse_bearer(authorization)
        person = validate_token(token, conn) if token else None

        query = "SELECT * FROM files"
        params: list = []
        if updated_since:
            query += " WHERE updated_ts > ?"
            params.append(updated_since)
        query += " ORDER BY updated_ts DESC"

        files = conn.execute(query, params).fetchall()
        result = []
        for f in files:
            file_perms = _get_file_permissions(conn, f)
            can = person and drive_can_read(
                person["email"], file_perms,
            ) if person else False
            result.append({
                "key": f["key"],
                "folder": f["folder"],
                "title": f["title"],
                "updated_ts": f["updated_ts"],
                "version": f["version"],
                "accessible": can,
            })
        return {"files": result}
    finally:
        conn.close()


@app.get("/files/{file_key}")
def get_file(file_key: str, authorization: str = Header(None),
             as_user: str = Query(None)):
    conn = _conn()
    try:
        token = parse_bearer(authorization)
        person = validate_token(token, conn) if token else None
        if as_user and person:
            person = conn.execute("SELECT * FROM directory WHERE employee_id = ? OR email = ?",
                                    (as_user, as_user)).fetchone()
            if person:
                person = dict(person)

        f = conn.execute("SELECT * FROM files WHERE key = ?", (file_key,)).fetchone()
        if f is None:
            raise HTTPException(404, "file not found")

        file_perms = _get_file_permissions(conn, f)
        can = is_sync_admin(person) or (person and drive_can_read(
            person["email"], file_perms,
            link_sharing=f["link_sharing"] if f["link_sharing"] else None,
            is_trashed=bool(f["is_trashed"]),
        )) if person else False

        if not can:
            raise HTTPException(403, "access denied")

        return {
            "key": f["key"],
            "folder": f["folder"],
            "title": f["title"],
            "content": f["content"],
            "version": f["version"],
            "updated_ts": f["updated_ts"],
            "permissions": file_perms,
            "link_sharing": f["link_sharing"],
            "is_trashed": bool(f["is_trashed"]),
            "url": f"/files/{file_key}",
        }
    finally:
        conn.close()


@app.get("/files/{file_key}/permissions")
def get_file_permissions(file_key: str, authorization: str = Header(None)):
    conn = _conn()
    try:
        token = parse_bearer(authorization)
        person = validate_token(token, conn) if token else None
        if not person:
            raise HTTPException(401, "invalid token")
        f = conn.execute("SELECT * FROM files WHERE key = ?", (file_key,)).fetchone()
        if f is None:
            raise HTTPException(404, "file not found")
        perms = _get_file_permissions(conn, f)
        return {"permissions": perms, "link_sharing": f["link_sharing"]}
    finally:
        conn.close()


@app.get("/changes")
def get_changes(page_token: float = Query(0), authorization: str = Header(None)):
    """Changes feed: events since page_token."""
    conn = _conn()
    try:
        token = parse_bearer(authorization)
        person = validate_token(token, conn) if token else None
        if not person:
            raise HTTPException(401, "invalid token")

        changes = conn.execute(
            "SELECT * FROM changes_log WHERE ts > ? ORDER BY ts", (page_token,)
        ).fetchall()
        result = [{
            "file_key": c["file_key"],
            "change_type": c["change_type"],
            "ts": c["ts"],
            "details": json.loads(c["details"]),
        } for c in changes]
        return {"changes": result, "next_page_token": time.time()}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Scenario events
# ---------------------------------------------------------------------------

def apply_event(event_name: str, extra: dict | None = None):
    conn = _conn()
    try:
        if event_name == "reset":
            return {"reset": True}

        if event_name == "remove_tom_share":
            # R3: remove tom's share on DR-VENDOR-SPEC
            f = conn.execute("SELECT * FROM files WHERE key = 'DR-VENDOR-SPEC'").fetchone()
            if f:
                perms = _get_file_permissions(conn, f)
                tom_email = "tom.becker@acme-pay.example"
                new_perms = [p for p in perms if p.get("target") != tom_email]
                conn.execute(
                    "UPDATE files SET permissions = ? WHERE key = 'DR-VENDOR-SPEC'",
                    (json.dumps(new_perms),),
                )
                conn.execute(
                    "INSERT INTO changes_log (file_key, change_type, ts, details) VALUES (?,?,?,?)",
                    ("DR-VENDOR-SPEC", "permission_removed", time.time(),
                     json.dumps({"removed": tom_email})),
                )
                conn.commit()
            return {"file": "DR-VENDOR-SPEC", "removed": "tom"}

        return {"unknown_event": event_name}
    finally:
        conn.close()


mount_scenario_endpoints(app, "drive", apply_event)
