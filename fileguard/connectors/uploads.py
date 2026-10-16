"""Uploads connector adapter.

Wraps the existing file store (store.py + parsers.py + files table in the
central DB) to implement the Connector protocol. This is the only connector
that reads from the local DB instead of making HTTP calls to a simulator.

Uploaded files are permission-gated by clearance level and groups, not by
platform ACLs. The can_access() check uses the same clearance AND-group
logic as file_index.py.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from fileguard.connector import (  # noqa: E402
    Connector, Item, ItemRef, Unit, ACLSnapshot, Decision,
)
from fileguard import config  # noqa: E402
from fileguard.db import connect  # noqa: E402
from fileguard.parsers import detect_kind, parse_to_spans  # noqa: E402
from fileguard.store import load_plaintext  # noqa: E402

CLEARANCE_ORDER = {"open": 0, "confidential": 1, "secret": 2, "top_secret": 3}


class UploadsConnector(Connector):
    platform = "uploads"

    def __init__(self, directory: dict[str, str] | None = None):
        """directory: {employee_id: email} for identity resolution.
        For uploads, identity is the user_id in the central DB."""
        self._directory = directory or {}

    def _db(self) -> sqlite3.Connection:
        return connect(config.CENTRAL_DB)

    def changes(self, cursor: float | None) -> tuple[list[ItemRef], float]:
        """Return all uploaded files (or those since cursor timestamp).
        The uploads platform has no change feed — we scan the files table."""
        conn = self._db()
        try:
            query = "SELECT name, file_id, base_clearance, label_date FROM files"
            params: list = []
            if cursor:
                # label_date is a TEXT field like "2026-01-15"; compare as string
                query += " WHERE label_date > ?"
                params.append(str(cursor))
            rows = conn.execute(query, params).fetchall()
            refs = [
                ItemRef(platform="uploads", container="uploads",
                        item_id=row[0], version=row[1])
                for row in rows
            ]
            new_cursor = time.time()
            return refs, new_cursor
        finally:
            conn.close()

    def fetch(self, item_ref: ItemRef) -> Item:
        conn = self._db()
        try:
            row = conn.execute(
                "SELECT name, file_id, kind, base_clearance, groups, label_date, uploaded_by "
                "FROM files WHERE name = ?",
                (item_ref.item_id,),
            ).fetchone()
            if row is None:
                raise FileNotFoundError(f"upload not found: {item_ref.item_id}")

            name, file_id, kind, base_clearance, groups_json, label_date, uploaded_by = row
            plaintext = load_plaintext(file_id)
            spans = parse_to_spans(plaintext, kind)

            units = []
            for idx, span in enumerate(spans):
                units.append(Unit(
                    unit_id=f"uploads:{name}@{file_id}#{span.kind}_{span.start}_{span.end}",
                    kind=span.kind,
                    text=span.text,
                    order=idx,
                    metadata={"start": span.start, "end": span.end},
                ))

            groups = json.loads(groups_json)

            return Item(
                platform="uploads",
                container="uploads",
                item_id=name,
                version=file_id,
                url=f"/files/{name}",
                title=name,
                author=uploaded_by or "",
                created_at=float(label_date.rsplit("-", 1)[0].replace("-", "")) if label_date else 0.0,
                updated_at=float(label_date.rsplit("-", 1)[0].replace("-", "")) if label_date else 0.0,
                units=units,
                links=[],
                acl={
                    "base_clearance": base_clearance,
                    "groups": groups,
                },
                deleted=False,
            )
        finally:
            conn.close()

    def current_version(self, item_ref: ItemRef) -> str:
        """Content-addressed: file_id IS the version and never changes."""
        conn = self._db()
        try:
            row = conn.execute(
                "SELECT file_id FROM files WHERE name = ?", (item_ref.item_id,)
            ).fetchone()
            return row[0] if row else ""
        finally:
            conn.close()

    def fetch_acl(self, item_ref: ItemRef) -> ACLSnapshot:
        conn = self._db()
        try:
            row = conn.execute(
                "SELECT file_id, base_clearance, groups FROM files WHERE name = ?",
                (item_ref.item_id,),
            ).fetchone()
            if row is None:
                return ACLSnapshot(
                    item_key=f"uploads:{item_ref.item_id}",
                    version="",
                    acl_json="{}",
                    fetched_at="",
                )
            file_id, base_clearance, groups_json = row
            return ACLSnapshot(
                item_key=f"uploads:{item_ref.item_id}",
                version=file_id,
                acl_json=json.dumps({
                    "base_clearance": base_clearance,
                    "groups": json.loads(groups_json),
                }),
                fetched_at="",
            )
        finally:
            conn.close()

    def can_access(self, person_email: str, item: Item | ItemRef) -> Decision:
        """Uploads are gated by clearance AND group, not platform ACL.
        person_email maps to a user_id in the central DB.

        For the uploads connector, the 'person' is identified by their
        user_id (which may be their email). We check:
        - base_clearance <= user's max_clearance
        - group filter passes (same logic as file_index.py)
        """
        conn = self._db()
        try:
            # Look up user by email or user_id
            user = conn.execute(
                "SELECT user_id, max_clearance, groups FROM users WHERE user_id = ? OR user_id = ?",
                (person_email, person_email),
            ).fetchone()
            if user is None:
                # Try matching by email in the directory
                # In the existing system, user_id IS the identifier
                return Decision(allowed=False, reason="user not found")

            user_id, user_max, user_groups_json = user
            user_groups = set(json.loads(user_groups_json))

            if isinstance(item, Item):
                base_clearance = item.acl.get("base_clearance", "top_secret")
                file_groups = set(item.acl.get("groups", []))
            else:
                acl_snapshot = self.fetch_acl(item)
                acl_data = json.loads(acl_snapshot.acl_json)
                base_clearance = acl_data.get("base_clearance", "top_secret")
                file_groups = set(acl_data.get("groups", []))

            # Clearance check
            if CLEARANCE_ORDER.get(base_clearance, 3) > CLEARANCE_ORDER.get(user_max, 0):
                return Decision(allowed=False, reason="insufficient clearance")

            # Group filter: empty file groups = clearance-only (open to all with clearance)
            if file_groups and not (file_groups & user_groups):
                return Decision(allowed=False, reason="no group access")

            return Decision(allowed=True)
        finally:
            conn.close()

    def resolve_identity(self, employee_id: str) -> str:
        return self._directory.get(employee_id, employee_id)
