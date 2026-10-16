"""Confluence connector adapter.

Talks to the Confluence simulator (or a real Confluence instance) via HTTP.
Depends only on the adapter interface, not on simulator internals.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import httpx

# Make simulator evaluators importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "simulators"))
from evaluators import confluence_can_view  # noqa: E402

from fileguard.connector import (  # noqa: E402
    Connector, Item, ItemRef, Unit, ACLSnapshot, Decision,
)


class ConfluenceConnector(Connector):
    platform = "confluence"

    def __init__(self, base_url: str, admin_token: str, directory: dict[str, str]):
        """base_url: simulator or real API URL. admin_token: bearer for sync.
        directory: {employee_id: email} for identity resolution."""
        self._client = httpx.Client(base_url=base_url, headers={"Authorization": f"Bearer {admin_token}"})
        self._directory = directory

    def changes(self, cursor: float | None) -> tuple[list[ItemRef], float]:
        params = {}
        if cursor:
            params["updated_since"] = cursor
        resp = self._client.get("/content", params=params)
        resp.raise_for_status()
        data = resp.json()
        refs = [
            ItemRef(platform="confluence", container=p["space_key"],
                    item_id=p["key"], version=str(p["version"]))
            for p in data.get("pages", [])
        ]
        new_cursor = data.get("next_cursor", 0)
        return refs, new_cursor

    def fetch(self, item_ref: ItemRef) -> Item:
        resp = self._client.get(f"/content/{item_ref.item_id}")
        resp.raise_for_status()
        p = resp.json()

        # Build units: one section per page (simplified — real Confluence
        # would split by headings)
        units = [Unit(
            unit_id=f"confluence:{item_ref.item_id}@{p['version']}#body",
            kind="section",
            text=p["body"],
            order=0,
            metadata={"title": p["title"]},
        )]

        return Item(
            platform="confluence",
            container=p["space_key"],
            item_id=p["key"],
            version=str(p["version"]),
            url=p.get("url", f"/content/{p['key']}"),
            title=p["title"],
            author="",
            created_at=p["updated_ts"],
            updated_at=p["updated_ts"],
            units=units,
            links=p.get("links", []),
            acl={"restrictions": p.get("restrictions", []), "space_key": p["space_key"]},
            deleted=False,
        )

    def current_version(self, item_ref: ItemRef) -> str:
        resp = self._client.get("/content", params={"space_key": item_ref.container})
        resp.raise_for_status()
        for p in resp.json().get("pages", []):
            if p["key"] == item_ref.item_id:
                return str(p["version"])
        return ""

    def fetch_acl(self, item_ref: ItemRef) -> ACLSnapshot:
        resp = self._client.get(f"/content/{item_ref.item_id}")
        resp.raise_for_status()
        p = resp.json()
        return ACLSnapshot(
            item_key=f"confluence:{item_ref.item_id}",
            version=str(p["version"]),
            acl_json=json.dumps({"restrictions": p.get("restrictions", []),
                                 "space_key": p["space_key"]}),
            fetched_at=resp.headers.get("date", ""),
        )

    def can_access(self, person_email: str, item: Item | ItemRef) -> Decision:
        # Fetch space permissions + page restrictions
        if isinstance(item, Item):
            space_key = item.container
            restrictions = item.acl.get("restrictions", [])
        else:
            space_key = item.container
            # Need to fetch the item to check
            full = self.fetch(item)
            restrictions = full.acl.get("restrictions", [])

        # Restrictions may target employee ids ("user:lena") while this
        # check evaluates by email — normalize id targets through the
        # directory (found live: lena denied on CF-SEC-Q3, restricted TO her)
        if self._directory and restrictions:
            restrictions = [
                {**r, "target": self._directory.get(r.get("target"), r["target"])}
                if r.get("type") == "user" else r
                for r in restrictions
            ]

        # Get space permissions
        resp = self._client.get(f"/spaces/{space_key}/permissions")
        if resp.status_code != 200:
            return Decision(allowed=False, reason="space not found")
        space_perms = resp.json().get("permissions", [])

        allowed = confluence_can_view(person_email, space_key, space_perms, restrictions)
        return Decision(allowed=allowed, reason="" if allowed else "access denied")

    def resolve_identity(self, employee_id: str) -> str:
        return self._directory.get(employee_id, employee_id)
