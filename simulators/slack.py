"""Slack simulator: stateful HTTP server backed by SQLite.

Implements:
- conversation list
- history + replies (cursor pagination, ts ids)
- channel members
- users
- event poll endpoint (messages + membership changes)

Permission semantics: public = full members; private/shared = members only;
DM = participants; guests only explicitly-added channels; replies inherit channel.
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
from evaluators import slack_can_read  # noqa: E402

SCHEMA = """
CREATE TABLE IF NOT EXISTS channels (
    name TEXT PRIMARY KEY,
    type TEXT NOT NULL,         -- public | private | shared | direct
    members TEXT NOT NULL,      -- JSON: [emails]
    label TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS messages (
    key TEXT PRIMARY KEY,
    channel TEXT NOT NULL REFERENCES channels(name),
    author TEXT NOT NULL,      -- email
    text TEXT NOT NULL,
    ts TEXT NOT NULL,          -- Slack-style ts (string, float)
    thread_ts TEXT,            -- NULL = not a reply; parent ts if reply
    is_guest_visible INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS messages_channel_idx ON messages(channel);
CREATE INDEX IF NOT EXISTS messages_ts_idx ON messages(ts);

CREATE TABLE IF NOT EXISTS membership_events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    channel TEXT NOT NULL,
    person TEXT NOT NULL,
    action TEXT NOT NULL,      -- join | leave
    ts REAL NOT NULL
);
"""

app = FastAPI(title="Slack Simulator")
_db_path: str | None = None


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def seed(data: dict, db_path: str):
    global _db_path
    _db_path = db_path

    conn = _conn()
    conn.executescript(SCHEMA)

    for ch_name, ch_type, members, label in data["slack_channels"]:
        member_emails = [next(p[5] for p in data["people"] if p[0] == m) for m in members]
        conn.execute(
            "INSERT OR REPLACE INTO channels (name, type, members, label) VALUES (?,?,?,?)",
            (ch_name, ch_type, json.dumps(member_emails), label),
        )

    for msg in data["slack_messages"]:
        key, channel, author_id, ts_rel, text, thread_ts = msg
        from company_a.story import _resolve_ts
        msg_ts = _resolve_ts(ts_rel, data["now_ts"])
        author_email = next(p[5] for p in data["people"] if p[0] == author_id)
        # guest-visible: public channels
        ch_type = next(c[1] for c in data["slack_channels"] if c[0] == channel)
        guest_visible = 1 if ch_type == "public" else 0
        conn.execute(
            "INSERT OR REPLACE INTO messages (key, channel, author, text, ts, thread_ts, is_guest_visible) "
            "VALUES (?,?,?,?,?,?,?)",
            (key, channel, author_email, text, str(msg_ts),
             str(_resolve_ts(thread_ts, data["now_ts"])) if thread_ts else None,
             guest_visible),
        )

    # Filler messages
    for fm in data["filler"]["slack"]:
        member_emails = json.loads(conn.execute("SELECT members FROM channels WHERE name = ?", (fm["channel"],)).fetchone()["members"])
        author_email = next(p[5] for p in data["people"] if p[0] == fm["author"])
        conn.execute(
            "INSERT OR REPLACE INTO messages (key, channel, author, text, ts, thread_ts, is_guest_visible) "
            "VALUES (?,?,?,?,?,?,?)",
            (fm["key"], fm["channel"], author_email, fm["text"],
             str(fm["ts_ts"]), None, 1),
        )

    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/conversations")
def list_conversations(authorization: str = Header(None)):
    conn = _conn()
    try:
        token = parse_bearer(authorization)
        person = validate_token(token, conn) if token else None
        channels = conn.execute("SELECT * FROM channels ORDER BY name").fetchall()
        result = []
        for ch in channels:
            members = json.loads(ch["members"])
            is_guest = person and person.get("employee_id") == "tom"
            can = person and slack_can_read(
                person["email"], ch["type"], members, is_guest
            ) if person else False
            result.append({
                "name": ch["name"],
                "type": ch["type"],
                "label": ch["label"],
                "accessible": can,
                "member_count": len(members),
            })
        return {"channels": result}
    finally:
        conn.close()


@app.get("/conversations/{channel}/history")
def get_history(channel: str, cursor: str = Query(None), limit: int = Query(100),
                authorization: str = Header(None)):
    conn = _conn()
    try:
        token = parse_bearer(authorization)
        person = validate_token(token, conn) if token else None
        ch = conn.execute("SELECT * FROM channels WHERE name = ?", (channel,)).fetchone()
        if ch is None:
            raise HTTPException(404, "channel not found")

        members = json.loads(ch["members"])
        is_guest = person and person.get("employee_id") == "tom"
        can = is_sync_admin(person) or (person and slack_can_read(
            person["email"], ch["type"], members, is_guest
        )) if person else False

        if not can:
            raise HTTPException(403, "access denied")

        # Cursor: ts-based (messages before cursor ts)
        query = "SELECT * FROM messages WHERE channel = ?"
        params: list = [channel]
        if cursor:
            query += " AND ts < ?"
            params.append(cursor)
        query += " ORDER BY ts DESC LIMIT ?"
        params.append(limit)

        msgs = conn.execute(query, params).fetchall()
        result = []
        for m in msgs:
            result.append({
                "key": m["key"],
                "channel": m["channel"],
                "author": m["author"],
                "text": m["text"],
                "ts": m["ts"],
                "thread_ts": m["thread_ts"],
            })

        # Next cursor
        next_cursor = None
        if len(result) == limit:
            next_cursor = result[-1]["ts"]

        return {"messages": result, "next_cursor": next_cursor}
    finally:
        conn.close()


@app.get("/conversations/{channel}/replies")
def get_replies(channel: str, thread_ts: str = Query(...),
                authorization: str = Header(None)):
    conn = _conn()
    try:
        token = parse_bearer(authorization)
        person = validate_token(token, conn) if token else None
        ch = conn.execute("SELECT * FROM channels WHERE name = ?", (channel,)).fetchone()
        if ch is None:
            raise HTTPException(404, "channel not found")

        members = json.loads(ch["members"])
        is_guest = person and person.get("employee_id") == "tom"
        can = is_sync_admin(person) or (person and slack_can_read(
            person["email"], ch["type"], members, is_guest
        )) if person else False

        if not can:
            raise HTTPException(403, "access denied")

        msgs = conn.execute(
            "SELECT * FROM messages WHERE channel = ? AND (ts = ? OR thread_ts = ?) ORDER BY ts",
            (channel, thread_ts, thread_ts),
        ).fetchall()
        result = [{
            "key": m["key"],
            "channel": m["channel"],
            "author": m["author"],
            "text": m["text"],
            "ts": m["ts"],
            "thread_ts": m["thread_ts"],
        } for m in msgs]
        return {"messages": result}
    finally:
        conn.close()


@app.get("/conversations/{channel}/members")
def get_members(channel: str, authorization: str = Header(None)):
    conn = _conn()
    try:
        token = parse_bearer(authorization)
        person = validate_token(token, conn) if token else None
        if not person:
            raise HTTPException(401, "invalid token")
        ch = conn.execute("SELECT * FROM channels WHERE name = ?", (channel,)).fetchone()
        if ch is None:
            raise HTTPException(404, "channel not found")
        return {"members": json.loads(ch["members"])}
    finally:
        conn.close()


@app.get("/users")
def get_users(authorization: str = Header(None)):
    conn = _conn()
    try:
        token = parse_bearer(authorization)
        person = validate_token(token, conn) if token else None
        if not person:
            raise HTTPException(401, "invalid token")
        rows = conn.execute("SELECT email, name, employee_id FROM directory").fetchall()
        return {"users": [{"email": r["email"], "name": r["name"], "id": r["employee_id"]} for r in rows]}
    finally:
        conn.close()


@app.get("/events/poll")
def poll_events(cursor: float = Query(0), authorization: str = Header(None)):
    """Event poll: emits message and membership-change events since cursor."""
    conn = _conn()
    try:
        token = parse_bearer(authorization)
        person = validate_token(token, conn) if token else None
        if not person:
            raise HTTPException(401, "invalid token")

        # Membership events
        membership = conn.execute(
            "SELECT * FROM membership_events WHERE ts > ? ORDER BY ts", (cursor,)
        ).fetchall()
        events = []
        for ev in membership:
            events.append({
                "type": "membership_change",
                "channel": ev["channel"],
                "person": ev["person"],
                "action": ev["action"],
                "ts": ev["ts"],
            })

        return {"events": events, "next_cursor": time.time()}
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

        if event_name == "remove_raj_from_sre_oncall":
            # R1: remove raj from #sre-oncall-private
            ch = conn.execute("SELECT * FROM channels WHERE name = '#sre-oncall-private'").fetchone()
            if ch:
                members = json.loads(ch["members"])
                raj_email = "raj.patel@halcyon.example"
                if raj_email in members:
                    members.remove(raj_email)
                    conn.execute(
                        "UPDATE channels SET members = ? WHERE name = '#sre-oncall-private'",
                        (json.dumps(members),),
                    )
                    conn.execute(
                        "INSERT INTO membership_events (channel, person, action, ts) VALUES (?,?,?,?)",
                        ("#sre-oncall-private", raj_email, "leave", time.time()),
                    )
                    conn.commit()
            return {"channel": "#sre-oncall-private", "removed": "raj"}

        return {"unknown_event": event_name}
    finally:
        conn.close()


mount_scenario_endpoints(app, "slack", apply_event)
