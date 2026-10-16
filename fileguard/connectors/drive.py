"""Google Drive connector adapter.

Talks to the Drive simulator (or a real Google Drive instance) via HTTP.
Depends only on the adapter interface, not on simulator internals.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import httpx

# Make simulator evaluators importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "simulators"))
from evaluators import drive_can_read  # noqa: E402

from fileguard.connector import (  # noqa: E402
    Connector, Item, ItemRef, Unit, ACLSnapshot, Decision,
)


class DriveConnector(Connector):
    platform = "drive"

    def __init__(self, base_url: str, admin_token: str, directory: dict[str, str]):
        """base_url: simulator or real API URL. admin_token: bearer for sync.
        directory: {employee_id: email} for identity resolution."""
        self._client = httpx.Client(base_url=base_url, headers={"Authorization": f"Bearer {admin_token}"})
        self._directory = directory

    def changes(self, cursor: float | None) -> tuple[list[ItemRef], float]:
        """Drive change feed: poll changes endpoint."""
        params = {}
        if cursor:
            params["page_token"] = cursor
        resp = self._client.get("/changes", params=params)
        resp.raise_for_status()
        data = resp.json()

        refs = [
            ItemRef(platform="drive", container="drive",
                    item_id=c["file_key"], version=str(c["ts"]))
            for c in data.get("changes", [])
        ]
        new_cursor = data.get("next_page_token", time.time())
        return refs, new_cursor

    def fetch(self, item_ref: ItemRef) -> Item:
        resp = self._client.get(f"/files/{item_ref.item_id}")
        resp.raise_for_status()
        f = resp.json()

        # Build units: one section for the whole file content
        units = [Unit(
            unit_id=f"drive:{item_ref.item_id}@{f['version']}#body",
            kind="section",
            text=f["content"],
            order=0,
            metadata={"title": f["title"], "folder": f["folder"]},
        )]

        return Item(
            platform="drive",
            container=f["folder"],
            item_id=f["key"],
            version=str(f["version"]),
            url=f.get("url", f"/files/{f['key']}"),
            title=f["title"],
            author="",
            created_at=f["updated_ts"],
            updated_at=f["updated_ts"],
            units=units,
            links=[],
            acl={
                "permissions": f.get("permissions", []),
                "link_sharing": f.get("link_sharing"),
                "is_trashed": f.get("is_trashed", False),
            },
            deleted=f.get("is_trashed", False),
        )

    def current_version(self, item_ref: ItemRef) -> str:
        resp = self._client.get("/files")
        resp.raise_for_status()
        for f in resp.json().get("files", []):
            if f["key"] == item_ref.item_id:
                return str(f["version"])
        return ""

    def fetch_acl(self, item_ref: ItemRef) -> ACLSnapshot:
        resp = self._client.get(f"/files/{item_ref.item_id}/permissions")
        resp.raise_for_status()
        data = resp.json()

        return ACLSnapshot(
            item_key=f"drive:{item_ref.item_id}",
            version=item_ref.version,
            acl_json=json.dumps({
                "permissions": data.get("permissions", []),
                "link_sharing": data.get("link_sharing"),
            }),
            fetched_at=resp.headers.get("date", ""),
        )

    def can_access(self, person_email: str, item: Item | ItemRef) -> Decision:
        if isinstance(item, Item):
            permissions = item.acl.get("permissions", [])
            link_sharing = item.acl.get("link_sharing")
            is_trashed = item.acl.get("is_trashed", False)
        else:
            acl_snapshot = self.fetch_acl(item)
            acl_data = json.loads(acl_snapshot.acl_json)
            permissions = acl_data.get("permissions", [])
            link_sharing = acl_data.get("link_sharing")
            is_trashed = False  # trashed files don't appear in change feeds normally

        # share targets use employee ids ("user:lena") while this check
        # evaluates by email — normalize id targets through the directory
        # (found live: DR-FORENSICS-Q3, shared to lena, denied her)
        if self._directory and permissions:
            permissions = [
                {**perm, "target": self._directory.get(perm.get("target"),
                                                       perm["target"])}
                if perm.get("type") == "user" else perm
                for perm in permissions
            ]

        allowed = drive_can_read(
            person_email, permissions,
            link_sharing=link_sharing,
            is_trashed=is_trashed,
        )
        return Decision(allowed=allowed, reason="" if allowed else "access denied")

    def resolve_identity(self, employee_id: str) -> str:
        return self._directory.get(employee_id, employee_id)
