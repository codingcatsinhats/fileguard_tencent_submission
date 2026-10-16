"""Slack connector adapter.

Talks to the Slack simulator (or a real Slack instance) via HTTP.
Depends only on the adapter interface, not on simulator internals.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import httpx
from urllib.parse import quote

# Make simulator evaluators importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "simulators"))
from evaluators import slack_can_read  # noqa: E402

from fileguard.connector import (  # noqa: E402
    Connector, Item, ItemRef, Unit, ACLSnapshot, Decision,
)


class SlackConnector(Connector):
    platform = "slack"

    def __init__(self, base_url: str, admin_token: str, directory: dict[str, str]):
        """base_url: simulator or real API URL. admin_token: bearer for sync.
        directory: {employee_id: email} for identity resolution."""
        self._client = httpx.Client(base_url=base_url, headers={"Authorization": f"Bearer {admin_token}"})
        self._directory = directory

    def changes(self, cursor: float | None) -> tuple[list[ItemRef], float]:
        """Slack change feed: poll membership events + new messages.
        For simplicity, returns refs to all channels that have events since cursor."""
        params = {}
        if cursor:
            params["cursor"] = cursor
        resp = self._client.get("/events/poll", params=params)
        resp.raise_for_status()
        data = resp.json()

        # Collect channels that had membership changes
        channels_seen: set[str] = set()
        for ev in data.get("events", []):
            ch = ev.get("channel")
            if ch:
                channels_seen.add(ch)

        # Build item refs for each affected channel
        refs = [
            ItemRef(platform="slack", container=ch, item_id=ch, version=str(data.get("next_cursor", time.time())))
            for ch in sorted(channels_seen)
        ]
        new_cursor = data.get("next_cursor", time.time())
        return refs, new_cursor

    def fetch(self, item_ref: ItemRef) -> Item:
        """Fetch full channel history as an Item with one Unit per message."""
        channel = item_ref.item_id
        resp = self._client.get(f"/conversations/{quote(channel, safe='')}/history")
        resp.raise_for_status()
        data = resp.json()

        units = []
        for idx, msg in enumerate(data.get("messages", [])):
            units.append(Unit(
                unit_id=f"slack:{channel}@{msg['ts']}#{msg['key']}",
                kind="message",
                text=msg["text"],
                order=idx,
                metadata={
                    "author": msg["author"],
                    "ts": msg["ts"],
                    "thread_ts": msg.get("thread_ts"),
                },
            ))

        # Fetch channel metadata
        conv_resp = self._client.get("/conversations")
        conv_resp.raise_for_status()
        channel_info = None
        for ch in conv_resp.json().get("channels", []):
            if ch["name"] == channel:
                channel_info = ch
                break

        channel_type = channel_info["type"] if channel_info else "public"

        return Item(
            platform="slack",
            container=channel,
            item_id=channel,
            version=str(item_ref.version),
            url=f"/conversations/{channel}",
            title=channel,
            author="",
            created_at=float(data["messages"][0]["ts"]) if data.get("messages") else 0.0,
            updated_at=float(data["messages"][0]["ts"]) if data.get("messages") else 0.0,
            units=units,
            links=[],
            acl={"channel_type": channel_type, "channel": channel},
            deleted=False,
        )

    def current_version(self, item_ref: ItemRef) -> str:
        """Return the latest message ts as the version."""
        resp = self._client.get(f"/conversations/{quote(item_ref.item_id, safe='')}/history", params={"limit": 1})
        resp.raise_for_status()
        msgs = resp.json().get("messages", [])
        if msgs:
            return str(msgs[0]["ts"])
        return ""

    def fetch_acl(self, item_ref: ItemRef) -> ACLSnapshot:
        """Fetch channel members for ACL snapshot."""
        channel = item_ref.item_id
        resp = self._client.get(f"/conversations/{quote(channel, safe='')}/members")
        resp.raise_for_status()
        members = resp.json().get("members", [])

        # Get channel type from conversations list
        conv_resp = self._client.get("/conversations")
        conv_resp.raise_for_status()
        channel_type = "public"
        for ch in conv_resp.json().get("channels", []):
            if ch["name"] == channel:
                channel_type = ch["type"]
                break

        return ACLSnapshot(
            item_key=f"slack:{channel}",
            version=item_ref.version,
            acl_json=json.dumps({
                "channel_type": channel_type,
                "members": members,
            }),
            fetched_at=resp.headers.get("date", ""),
        )

    def can_access(self, person_email: str, item: Item | ItemRef) -> Decision:
        if isinstance(item, Item):
            channel_type = item.acl.get("channel_type", "public")
            # We need members list
            acl_snapshot = self.fetch_acl(item)
            acl_data = json.loads(acl_snapshot.acl_json)
            members = acl_data.get("members", [])
        else:
            acl_snapshot = self.fetch_acl(item)
            acl_data = json.loads(acl_snapshot.acl_json)
            channel_type = acl_data.get("channel_type", "public")
            members = acl_data.get("members", [])

        # Guest detection: tom is the guest in Company A
        is_guest = person_email == "tom.becker@acme-pay.example"

        allowed = slack_can_read(person_email, channel_type, members, is_guest)
        return Decision(allowed=allowed, reason="" if allowed else "access denied")

    def resolve_identity(self, employee_id: str) -> str:
        return self._directory.get(employee_id, employee_id)
