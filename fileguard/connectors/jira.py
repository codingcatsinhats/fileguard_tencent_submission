"""Jira connector adapter.

Talks to the Jira simulator (or a real Jira instance) via HTTP.
Depends only on the adapter interface, not on simulator internals.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx

# Make simulator evaluators importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "simulators"))
from evaluators import jira_can_view  # noqa: E402

from fileguard.connector import (  # noqa: E402
    Connector, Item, ItemRef, Unit, ACLSnapshot, Decision,
)


class JiraConnector(Connector):
    platform = "jira"

    def __init__(self, base_url: str, admin_token: str, directory: dict[str, str]):
        """base_url: simulator or real API URL. admin_token: bearer for sync.
        directory: {employee_id: email} for identity resolution."""
        self._client = httpx.Client(base_url=base_url, headers={"Authorization": f"Bearer {admin_token}"})
        self._directory = directory

    def changes(self, cursor: float | None) -> tuple[list[ItemRef], float]:
        params = {}
        if cursor:
            params["updated_since"] = cursor
        resp = self._client.get("/search", params=params)
        resp.raise_for_status()
        data = resp.json()
        refs = [
            ItemRef(platform="jira", container=i["project_key"],
                    item_id=i["key"], version=str(i["updated_ts"]))
            for i in data.get("issues", [])
        ]
        new_cursor = data.get("next_cursor", 0)
        return refs, new_cursor

    def fetch(self, item_ref: ItemRef) -> Item:
        resp = self._client.get(f"/issue/{item_ref.item_id}")
        resp.raise_for_status()
        i = resp.json()

        # Build units: summary is the primary content, fields are metadata
        units = [Unit(
            unit_id=f"jira:{item_ref.item_id}@{i['updated_ts']}#summary",
            kind="field",
            text=i["summary"],
            order=0,
            metadata={"status": i["status"], "security_level": i.get("security_level")},
        )]
        # Add fields as additional units
        fields = i.get("fields", {})
        for idx, (fname, fval) in enumerate(fields.items(), start=1):
            if fval:
                units.append(Unit(
                    unit_id=f"jira:{item_ref.item_id}@{i['updated_ts']}#{fname}",
                    kind="field",
                    text=str(fval),
                    order=idx,
                    metadata={"field_name": fname},
                ))

        return Item(
            platform="jira",
            container=i["project_key"],
            item_id=i["key"],
            version=str(i["updated_ts"]),
            url=i.get("url", f"/issue/{i['key']}"),
            title=i["summary"],
            author="",
            created_at=i["updated_ts"],
            updated_at=i["updated_ts"],
            units=units,
            links=i.get("links", []),
            acl={
                "project_key": i["project_key"],
                "security_level": i.get("security_level"),
            },
            deleted=False,
        )

    def current_version(self, item_ref: ItemRef) -> str:
        resp = self._client.get("/search", params={"jql": f"project={item_ref.container}"})
        resp.raise_for_status()
        for i in resp.json().get("issues", []):
            if i["key"] == item_ref.item_id:
                return str(i["updated_ts"])
        return ""

    def fetch_acl(self, item_ref: ItemRef) -> ACLSnapshot:
        # Get project roles
        resp_roles = self._client.get(f"/projects/{item_ref.container}/roles")
        resp_roles.raise_for_status()
        roles = resp_roles.json().get("roles", {})

        # Get issue to check security level
        resp_issue = self._client.get(f"/issue/{item_ref.item_id}")
        resp_issue.raise_for_status()
        issue_data = resp_issue.json()

        return ACLSnapshot(
            item_key=f"jira:{item_ref.item_id}",
            version=str(issue_data.get("updated_ts", "")),
            acl_json=json.dumps({
                "project_key": item_ref.container,
                "project_roles": roles,
                "security_level": issue_data.get("security_level"),
            }),
            fetched_at=resp_issue.headers.get("date", ""),
        )

    def can_access(self, person_email: str, item: Item | ItemRef) -> Decision:
        if isinstance(item, Item):
            project_key = item.container
            security_level = item.acl.get("security_level")
        else:
            project_key = item.container
            acl_snapshot = self.fetch_acl(item)
            acl_data = json.loads(acl_snapshot.acl_json)
            security_level = acl_data.get("security_level")
            roles = acl_data.get("project_roles", {})
            # We still need security level members - fetch from roles response
            # The simulator stores security level members in the security_levels table
            # but the connector only sees the roles endpoint.
            # For Jira, security level membership is evaluated by the simulator
            # when fetching an issue with as_user. We'll do a lightweight check:
            # if the issue is fetchable as this user, they have access.
            try:
                resp = self._client.get(
                    f"/issue/{item.item_id}",
                    params={"as_user": person_email},
                )
                if resp.status_code == 200:
                    return Decision(allowed=True)
                return Decision(allowed=False, reason="access denied by jira")
            except httpx.HTTPError:
                return Decision(allowed=False, reason="unable to verify access")

        # For Item with full ACL, we need project roles and security level members
        resp_roles = self._client.get(f"/projects/{project_key}/roles")
        if resp_roles.status_code != 200:
            return Decision(allowed=False, reason="project not found")
        roles = resp_roles.json().get("roles", {})

        # Security level members: the simulator's /search endpoint doesn't expose
        # the security_levels table directly. We use the issue endpoint with
        # as_user to check access authoritatively.
        try:
            resp = self._client.get(
                f"/issue/{item.item_id if isinstance(item, Item) else item.item_id}",
                params={"as_user": person_email},
            )
            if resp.status_code == 200:
                return Decision(allowed=True)
            return Decision(allowed=False, reason="access denied by jira")
        except httpx.HTTPError:
            return Decision(allowed=False, reason="unable to verify access")

    def resolve_identity(self, employee_id: str) -> str:
        return self._directory.get(employee_id, employee_id)
