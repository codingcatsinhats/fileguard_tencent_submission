"""Identity, directory, and permission layer.

Provides:
- A directory table mapping employees to platform user ids (emails),
  clearance, and groups.
- A permission epoch counter (per-employee and global), bumped on
  membership or permission-change events.
- A clearance overlay policy loaded from containers.yaml.
- A combined access decision: native_permission AND label check AND
  group check.

The permission epoch is a HARD GATE on grants: a stale epoch = reject,
no live check override. The live ACL check stays authoritative for
items and is a defense-in-depth fallback.
"""

from __future__ import annotations

import json
import sqlite3
import time
import logging
from pathlib import Path
from typing import Any
from dataclasses import dataclass

from fileguard import config, db, security
from fileguard.connector import Decision

logger = logging.getLogger(__name__)

CLEARANCE_ORDER = {"open": 0, "confidential": 1, "secret": 2, "top_secret": 3}

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

DIRECTORY_SCHEMA = """
CREATE TABLE IF NOT EXISTS directory (
    employee_id     TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    email           TEXT NOT NULL,
    clearance       TEXT NOT NULL DEFAULT 'open',
    groups          TEXT NOT NULL DEFAULT '[]',   -- JSON array
    token_hash      TEXT NOT NULL,
    platform_ids    TEXT NOT NULL DEFAULT '{}',   -- JSON: {platform: email}
    epoch           INTEGER NOT NULL DEFAULT 1   -- per-employee epoch
);

CREATE TABLE IF NOT EXISTS global_epoch (
    key     TEXT PRIMARY KEY DEFAULT 'global',
    epoch   INTEGER NOT NULL DEFAULT 1
);
"""

# ---------------------------------------------------------------------------
# Directory operations
# ---------------------------------------------------------------------------

def init_directory(conn: sqlite3.Connection) -> None:
    """Create directory tables if they don't exist."""
    conn.row_factory = sqlite3.Row
    conn.executescript(DIRECTORY_SCHEMA)
    # Ensure global epoch row exists
    conn.execute("""
        INSERT OR IGNORE INTO global_epoch (key, epoch) VALUES ('global', 1)
    """)
    conn.commit()


def register_employee(
    conn: sqlite3.Connection,
    employee_id: str,
    name: str,
    email: str,
    clearance: str,
    groups: list[str],
    token_hash: str,
    platform_ids: dict[str, str] | None = None,
) -> None:
    """Register or update an employee in the directory."""
    init_directory(conn)
    conn.execute("""
        INSERT INTO directory (employee_id, name, email, clearance, groups,
                               token_hash, platform_ids, epoch)
        VALUES (?,?,?,?,?,?,?,1)
        ON CONFLICT(employee_id) DO UPDATE SET
            name=excluded.name,
            email=excluded.email,
            clearance=excluded.clearance,
            groups=excluded.groups,
            token_hash=excluded.token_hash,
            platform_ids=excluded.platform_ids
    """, (
        employee_id, name, email, clearance,
        json.dumps(groups), token_hash,
        json.dumps(platform_ids or {"email": email}),
    ))
    conn.commit()


def lookup_employee(conn: sqlite3.Connection, employee_id: str) -> dict | None:
    """Look up an employee by ID. Returns dict or None."""
    init_directory(conn)
    row = conn.execute(
        "SELECT * FROM directory WHERE employee_id = ?", (employee_id,)
    ).fetchone()
    if row is None:
        return None
    return {
        "employee_id": row["employee_id"],
        "name": row["name"],
        "email": row["email"],
        "clearance": row["clearance"],
        "groups": json.loads(row["groups"]),
        "token_hash": row["token_hash"],
        "platform_ids": json.loads(row["platform_ids"]),
        "epoch": row["epoch"],
    }


def lookup_by_token(conn: sqlite3.Connection, token_hash: str) -> dict | None:
    """Look up an employee by token hash. Returns dict or None."""
    init_directory(conn)
    row = conn.execute(
        "SELECT * FROM directory WHERE token_hash = ?", (token_hash,)
    ).fetchone()
    if row is None:
        return None
    return {
        "employee_id": row["employee_id"],
        "name": row["name"],
        "email": row["email"],
        "clearance": row["clearance"],
        "groups": json.loads(row["groups"]),
        "token_hash": row["token_hash"],
        "platform_ids": json.loads(row["platform_ids"]),
        "epoch": row["epoch"],
    }


# ---------------------------------------------------------------------------
# Permission epoch
# ---------------------------------------------------------------------------

def get_global_epoch(conn: sqlite3.Connection) -> int:
    """Get the current global permission epoch."""
    init_directory(conn)
    row = conn.execute(
        "SELECT epoch FROM global_epoch WHERE key = 'global'"
    ).fetchone()
    return row[0] if row else 1


def get_employee_epoch(conn: sqlite3.Connection, employee_id: str) -> int:
    """Get the current epoch for a specific employee."""
    init_directory(conn)
    row = conn.execute(
        "SELECT epoch FROM directory WHERE employee_id = ?", (employee_id,)
    ).fetchone()
    return row[0] if row else 0


def bump_epoch(conn: sqlite3.Connection, employee_id: str | None = None) -> int:
    """Bump the global epoch and optionally a specific employee's epoch.

    Called when a membership or permission-change event occurs.
    Returns the new global epoch value.
    """
    init_directory(conn)

    # Bump global epoch
    conn.execute("""
        INSERT INTO global_epoch (key, epoch) VALUES ('global', 2)
        ON CONFLICT(key) DO UPDATE SET epoch = epoch + 1
    """)
    global_row = conn.execute(
        "SELECT epoch FROM global_epoch WHERE key = 'global'"
    ).fetchone()
    new_global = global_row[0]

    # Bump employee-specific epoch if requested
    if employee_id:
        conn.execute(
            "UPDATE directory SET epoch = epoch + 1 WHERE employee_id = ?",
            (employee_id,),
        )

    conn.commit()
    return new_global


def check_epoch(conn: sqlite3.Connection, employee_id: str, grant_epoch: int) -> bool:
    """Check if a grant's epoch is still valid.

    The epoch is a HARD GATE: if the grant epoch is less than the
    current employee epoch OR the current global epoch, the grant
    is stale and must be rejected.
    """
    current_employee = get_employee_epoch(conn, employee_id)
    current_global = get_global_epoch(conn)
    return grant_epoch >= current_employee and grant_epoch >= current_global


# ---------------------------------------------------------------------------
# Clearance overlay
# ---------------------------------------------------------------------------

@dataclass
class ContainerPolicy:
    """Clearance overlay policy for a single container."""
    label: str  # required clearance level
    groups: list[str]  # required groups (empty = no group requirement)


def load_container_policies() -> dict[str, dict[str, ContainerPolicy]]:
    """Load containers.yaml and return a nested dict:
    {platform: {container_name: ContainerPolicy}}"""
    import yaml

    yaml_path = Path(__file__).resolve().parent.parent / "demo-seed" / "company_a" / "containers.yaml"
    if not yaml_path.exists():
        return {}

    with open(yaml_path) as f:
        data = yaml.safe_load(f)

    result: dict[str, dict[str, ContainerPolicy]] = {}
    for platform, containers in data.items():
        result[platform] = {}
        for container_name, policy in containers.items():
            result[platform][container_name] = ContainerPolicy(
                label=policy.get("label", "open"),
                groups=policy.get("groups", []),
            )
    return result


def get_container_policy(
    policies: dict[str, dict[str, ContainerPolicy]],
    platform: str,
    container: str,
) -> ContainerPolicy:
    """Get the overlay policy for a specific container.
    Falls back to 'default' or open/confidential if not found."""
    platform_policies = policies.get(platform, {})
    if container in platform_policies:
        return platform_policies[container]
    if "default" in platform_policies:
        return platform_policies["default"]
    return ContainerPolicy(label="confidential", groups=[])


def overlay_check(
    user_clearance: str,
    user_groups: list[str],
    policy: ContainerPolicy,
) -> Decision:
    """Check the clearance overlay: user clearance >= label AND
    group overlap (if groups specified). The overlay only narrows."""
    # Clearance check
    if CLEARANCE_ORDER.get(user_clearance, 0) < CLEARANCE_ORDER.get(policy.label, 3):
        return Decision(
            allowed=False,
            reason=f"clearance {user_clearance} below required {policy.label}",
        )
    # Group check (empty groups = no requirement)
    if policy.groups:
        user_set = set(user_groups)
        if not (set(policy.groups) & user_set):
            return Decision(
                allowed=False,
                reason=f"requires one of {policy.groups}",
            )
    return Decision(allowed=True)


# ---------------------------------------------------------------------------
# Combined decision
# ---------------------------------------------------------------------------

def combined_decision(
    native_allowed: bool,
    user_clearance: str,
    user_groups: list[str],
    platform: str,
    container: str,
    policies: dict[str, dict[str, ContainerPolicy]] | None = None,
) -> Decision:
    """Combine native permission with the clearance overlay.

    Effective access = native_permission AND label check AND group check.
    The overlay only narrows.
    """
    if not native_allowed:
        return Decision(allowed=False, reason="native permission denied")

    if policies is None:
        policies = load_container_policies()

    policy = get_container_policy(policies, platform, container)
    return overlay_check(user_clearance, user_groups, policy)
