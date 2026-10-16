"""Shared utilities for platform simulators: bearer auth, scenario control,
viewer pages, and a common FastAPI base.

Each simulator is a small stateful HTTP server backed by its own SQLite
store seeded by the Company A data generator. They are not canned responses —
they evaluate permissions on every request and change over time.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Header, Query
from pydantic import BaseModel


# ---------------------------------------------------------------------------
# SQLite helpers
# ---------------------------------------------------------------------------

def connect_sim_db(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# ---------------------------------------------------------------------------
# Bearer token authentication
# ---------------------------------------------------------------------------

def parse_bearer(authorization: str | None) -> str | None:
    """Extract the token from an Authorization: Bearer <token> header."""
    if not authorization:
        return None
    if not authorization.startswith("Bearer "):
        return None
    return authorization[7:]


def validate_token(token: str, conn: sqlite3.Connection) -> dict | None:
    """Look up a bearer token in the directory table and return the
    employee record, or None if invalid."""
    row = conn.execute(
        "SELECT * FROM directory WHERE token_hash = ?",
        (hash_token(token),),
    ).fetchone()
    if row is None:
        return None
    return dict(row)


def hash_token(token: str) -> str:
    import hashlib
    return hashlib.sha256(token.encode()).hexdigest()


# The sync connector's service account (directory row "sync-service"). Like a
# real Confluence/Drive integration account it must be able to read everything
# to index it — permission enforcement happens at query time in fileguard.
SYNC_ADMIN_ID = "sync-service"


def is_sync_admin(person) -> bool:
    return bool(person) and person["employee_id"] == SYNC_ADMIN_ID


# ---------------------------------------------------------------------------
# Scenario control endpoints
# ---------------------------------------------------------------------------

def mount_scenario_endpoints(app: FastAPI, platform: str, apply_event_fn):
    """Mount /sim/ endpoints for scenario control. apply_event_fn(name) applies
    a named scenario event to the simulator's store."""

    @app.post("/sim/reset")
    def sim_reset():
        """Reset the simulator to the seeded state."""
        apply_event_fn("reset")
        return {"ok": True, "platform": platform}

    @app.post("/sim/event/{event_name}")
    def sim_event(event_name: str):
        """Apply a named scenario event."""
        supported = {
            "runbook_v8", "remove_raj_from_sre_oncall",
            "restrict_vendor_pricing", "remove_tom_share",
        }
        if event_name not in supported:
            raise HTTPException(404, f"Unknown event: {event_name}")
        result = apply_event_fn(event_name)
        return {"ok": True, "platform": platform, "event": event_name, "result": result}

    @app.post("/sim/clock")
    def sim_clock(body: dict | None = None):
        """Set or advance the demo clock."""
        if body is None:
            body = {}
        new_ts = apply_event_fn("set_clock", body)
        return {"ok": True, "platform": platform, "clock": new_ts}


# ---------------------------------------------------------------------------
# Viewer page helper
# ---------------------------------------------------------------------------

def viewer_response(item: dict, user_email: str | None, can_access: bool) -> dict:
    """Build a viewer response for an item. If the user cannot access,
    return a 403-style response (simulated, not an HTTP error)."""
    if not can_access:
        return {"ok": False, "error": "access_denied"}
    return {"ok": True, "item": item}
