"""Confluence simulator: stateful HTTP server backed by SQLite.

Implements the subset of Confluence API endpoints the connector calls:
- spaces list
- pages list with version
- page detail (ancestors, restrictions, body)
- modified-since query
- space permissions
- page restrictions

Permission semantics: a user can view a page if they hold view permission
on the space AND satisfy view restrictions on the page AND on every ancestor.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, Header, Query

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import parse_bearer, validate_token, mount_scenario_endpoints, viewer_response, is_sync_admin  # noqa: E402
from evaluators import confluence_can_view  # noqa: E402

SCHEMA = """
CREATE TABLE IF NOT EXISTS spaces (
    key TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    view_permission TEXT NOT NULL,   -- JSON: [{type, target}]
    label TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pages (
    key TEXT PRIMARY KEY,
    space_key TEXT NOT NULL REFERENCES spaces(key),
    title TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    body TEXT NOT NULL,
    restrictions TEXT NOT NULL DEFAULT '[]',  -- JSON: [{type, target}]
    updated_ts REAL NOT NULL,
    ancestors TEXT NOT NULL DEFAULT '[]'      -- JSON: [page_key, ...]
);
CREATE INDEX IF NOT EXISTS pages_space_idx ON pages(space_key);
CREATE INDEX IF NOT EXISTS pages_updated_idx ON pages(updated_ts);

CREATE TABLE IF NOT EXISTS page_restrictions_history (
    page_key TEXT NOT NULL,
    restrictions TEXT NOT NULL,
    ts REAL NOT NULL
);
"""

app = FastAPI(title="Confluence Simulator")
_db_path: str | None = None


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def seed(data: dict, db_path: str):
    """Seed the Confluence simulator store from the Company A data."""
    global _db_path
    _db_path = db_path

    conn = _conn()
    conn.executescript(SCHEMA)

    # Spaces
    for space_key, name, view_perm, label in data["confluence_spaces"]:
        perms = _parse_space_permission(view_perm)
        conn.execute(
            "INSERT OR REPLACE INTO spaces (key, name, view_permission, label) VALUES (?,?,?,?)",
            (space_key, name, json.dumps(perms), label),
        )

    # Pages (key items)
    for item in data["confluence_pages"]:
        key, space, title, version, body, updated_rel, restrictions = item
        from company_a.story import _resolve_ts
        updated_ts = _resolve_ts(updated_rel, data["now_ts"])
        restr = _parse_page_restrictions(restrictions)
        conn.execute(
            "INSERT OR REPLACE INTO pages (key, space_key, title, version, body, restrictions, updated_ts, ancestors) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (key, space, title, version, body, json.dumps(restr), updated_ts, json.dumps([])),
        )

    # Filler pages
    for fp in data["filler"]["confluence"]:
        conn.execute(
            "INSERT OR REPLACE INTO pages (key, space_key, title, version, body, restrictions, updated_ts, ancestors) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (fp["key"], fp["space"], fp["title"], fp["version"], fp["text"],
             json.dumps([]), fp["updated_ts"], json.dumps([])),
        )

    conn.commit()
    conn.close()


def _parse_space_permission(perm_str: str) -> list[dict]:
    """Convert permission strings like 'all_employees_not_tom' or 'group:eng' or 'user:sam'."""
    if perm_str == "all_employees":
        return [{"type": "group", "target": "all_employees"}]
    if perm_str == "all_employees_not_tom":
        return [{"type": "group", "target": "all_employees_not_tom"}]
    if perm_str.startswith("group:"):
        return [{"type": "group", "target": perm_str[6:]}]
    if perm_str.startswith("user:"):
        return [{"type": "user", "target": perm_str[5:]}]
    return []


def _parse_page_restrictions(restr_str: str | None) -> list[dict]:
    if not restr_str:
        return []
    if restr_str.startswith("user:"):
        return [{"type": "user", "target": restr_str[5:]}]
    if restr_str.startswith("group:"):
        return [{"type": "group", "target": restr_str[6:]}]
    return []


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/spaces")
def list_spaces(authorization: str = Header(None)):
    conn = _conn()
    try:
        token = parse_bearer(authorization)
        person = validate_token(token, conn) if token else None
        spaces = conn.execute("SELECT * FROM spaces ORDER BY key").fetchall()
        result = []
        for s in spaces:
            result.append({
                "key": s["key"],
                "name": s["name"],
                "label": s["label"],
            })
        return {"spaces": result}
    finally:
        conn.close()


@app.get("/content")
def list_content(space_key: str = Query(None), updated_since: float = Query(None),
                 authorization: str = Header(None)):
    """List pages, optionally filtered by space and updated-since."""
    conn = _conn()
    try:
        token = parse_bearer(authorization)
        person = validate_token(token, conn) if token else None

        query = "SELECT * FROM pages"
        params: list = []
        conditions = []
        if space_key:
            conditions.append("space_key = ?")
            params.append(space_key)
        if updated_since:
            conditions.append("updated_ts > ?")
            params.append(updated_since)
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY updated_ts DESC"

        pages = conn.execute(query, params).fetchall()
        result = []
        for p in pages:
            space = conn.execute("SELECT * FROM spaces WHERE key = ?", (p["space_key"],)).fetchone()
            can = person and confluence_can_view(
                person["email"], p["space_key"],
                json.loads(space["view_permission"]),
                json.loads(p["restrictions"]),
            ) if person else False
            result.append({
                "key": p["key"],
                "space_key": p["space_key"],
                "title": p["title"],
                "version": p["version"],
                "updated_ts": p["updated_ts"],
                "accessible": can,
            })
        return {"pages": result}
    finally:
        conn.close()


@app.get("/content/{page_key}")
def get_content(page_key: str, authorization: str = Header(None),
                as_user: str = Query(None)):
    """Get page detail: body, version, restrictions, ancestors."""
    conn = _conn()
    try:
        token = parse_bearer(authorization)
        person = validate_token(token, conn) if token else None
        if as_user and person:
            # Viewer page: ?as=<user_id> (admin/service token can impersonate)
            person = conn.execute("SELECT * FROM directory WHERE employee_id = ? OR email = ?",
                                    (as_user, as_user)).fetchone()
            if person:
                person = dict(person)

        page = conn.execute("SELECT * FROM pages WHERE key = ?", (page_key,)).fetchone()
        if page is None:
            raise HTTPException(404, "page not found")
        space = conn.execute("SELECT * FROM spaces WHERE key = ?", (page["space_key"],)).fetchone()

        can = False
        if person:
            can = is_sync_admin(person) or confluence_can_view(
                person["email"], page["space_key"],
                json.loads(space["view_permission"]),
                json.loads(page["restrictions"]),
            )

        if not can:
            raise HTTPException(403, "access denied")

        return {
            "key": page["key"],
            "space_key": page["space_key"],
            "title": page["title"],
            "version": page["version"],
            "body": page["body"],
            "restrictions": json.loads(page["restrictions"]),
            "ancestors": json.loads(page["ancestors"]),
            "updated_ts": page["updated_ts"],
            "url": f"/content/{page_key}",
            "links": [],
        }
    finally:
        conn.close()


@app.get("/spaces/{space_key}/permissions")
def get_space_permissions(space_key: str, authorization: str = Header(None)):
    conn = _conn()
    try:
        token = parse_bearer(authorization)
        person = validate_token(token, conn) if token else None
        if not person:
            raise HTTPException(401, "invalid token")
        space = conn.execute("SELECT * FROM spaces WHERE key = ?", (space_key,)).fetchone()
        if space is None:
            raise HTTPException(404, "space not found")
        return {"permissions": json.loads(space["view_permission"])}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Scenario events
# ---------------------------------------------------------------------------

def apply_event(event_name: str, extra: dict | None = None):
    """Apply a named scenario event to the Confluence store."""
    conn = _conn()
    try:
        if event_name == "reset":
            return {"reset": True}

        if event_name == "runbook_v8":
            # Update CF-RUNBOOK to v8 with step 6
            from company_a.story import demo_now_ts
            now_ts = demo_now_ts()
            v8_body = ("Steps 1-5: check alerts, verify pool size, restart service, "
                       "notify on-call, escalate to DBA if pool < 10. "
                       "Step 6: promote the replica using the --force-failover flag.")
            conn.execute(
                "UPDATE pages SET version = 8, body = ?, updated_ts = ? WHERE key = 'CF-RUNBOOK'",
                (v8_body, now_ts - 65 * 60),  # 13:00 when DEMO_NOW is 14:05
            )
            conn.commit()
            return {"page": "CF-RUNBOOK", "version": 8}

        if event_name == "restrict_vendor_pricing":
            # R2: CF-VENDOR-PRICING restricted to sam only
            page = conn.execute("SELECT * FROM pages WHERE key = 'CF-VENDOR-PRICING'").fetchone()
            if page:
                conn.execute(
                    "UPDATE pages SET restrictions = ? WHERE key = 'CF-VENDOR-PRICING'",
                    (json.dumps([{"type": "user", "target": "sam.alvarez@halcyon.example"}]),),
                )
                conn.execute(
                    "INSERT INTO page_restrictions_history (page_key, restrictions, ts) VALUES (?,?,?)",
                    ("CF-VENDOR-PRICING", json.dumps([{"type": "user", "target": "sam.alvarez@halcyon.example"}]),
                     time.time()),
                )
                conn.commit()
            return {"page": "CF-VENDOR-PRICING", "restricted_to": "sam"}

        return {"unknown_event": event_name}
    finally:
        conn.close()


mount_scenario_endpoints(app, "confluence", apply_event)
