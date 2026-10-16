"""Connector interface and normalised data model.

Defines the contract that all platform connectors (simulated and real)
must implement, plus the normalised Item/Unit/ACLSnapshot/Decision types.

The connector is the only abstraction the sync engine and query pipeline
depend on. It never touches simulator internals.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Protocol, Any


# ---------------------------------------------------------------------------
# Normalised data model
# ---------------------------------------------------------------------------

@dataclass
class Unit:
    """A single span of content within an Item."""
    unit_id: str          # format: platform:item_id@version#unit_id
    kind: str              # message | section | field | comment | page | range | cell_range | paragraph
    text: str
    order: int
    metadata: dict = field(default_factory=dict)

    @property
    def text_sha256(self) -> str:
        import hashlib
        return hashlib.sha256(self.text.encode("utf-8")).hexdigest()


@dataclass
class ItemRef:
    """A lightweight reference to an item (used in change feeds)."""
    platform: str
    container: str
    item_id: str
    version: str


@dataclass
class ACLSnapshot:
    """A snapshot of an item's permissions at a point in time."""
    item_key: str
    version: str
    acl_json: str          # platform-native permission structure
    fetched_at: float


@dataclass
class Item:
    """A fully fetched item with units, links, and ACL."""
    platform: str
    container: str
    item_id: str
    version: str
    url: str
    title: str
    author: str
    created_at: float
    updated_at: float
    units: list[Unit]
    links: list[str]       # item keys this item links to
    acl: dict              # platform-native permission structure
    deleted: bool = False


@dataclass
class Decision:
    """An access decision for a person on an item."""
    allowed: bool
    reason: str = ""


# ---------------------------------------------------------------------------
# Connector protocol
# ---------------------------------------------------------------------------

class Connector(Protocol):
    """The contract every platform connector implements.

    The connector never exposes simulator internals. The sync engine
    and query pipeline depend only on this interface.
    """

    platform: str

    def changes(self, cursor: float | None) -> tuple[list[ItemRef], float]:
        """Incremental change feed. Returns (item_refs, new_cursor)."""
        ...

    def fetch(self, item_ref: ItemRef) -> Item:
        """Fetch full item: body units, version, url, links, ACL."""
        ...

    def current_version(self, item_ref: ItemRef) -> str:
        """Cheap metadata call for the freshness gate."""
        ...

    def fetch_acl(self, item_ref: ItemRef) -> ACLSnapshot:
        """Current permissions (live check input)."""
        ...

    def can_access(self, person_email: str, item: Item | ItemRef) -> Decision:
        """Uses the shared evaluator with a fresh ACL."""
        ...

    def resolve_identity(self, employee_id: str) -> str:
        """Map an employee ID to a platform user ID (email)."""
        ...
