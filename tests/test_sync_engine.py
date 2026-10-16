"""Sync engine tests: incremental sync, deletions, connector failure isolation,
cursor persistence, sync_now trigger, and sync status reporting."""

import os
import sys
import json
import time
import sqlite3
import tempfile
from pathlib import Path
from dataclasses import dataclass, field
from typing import Callable

import pytest

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))
sys.path.insert(0, str(_REPO / "simulators"))
sys.path.insert(0, str(_REPO / "demo-seed"))

from fileguard.connector import (  # noqa: E402
    Connector, Item, ItemRef, Unit, ACLSnapshot, Decision,
)
from fileguard import sync_engine  # noqa: E402


# ---------------------------------------------------------------------------
# Mock connectors for deterministic testing
# ---------------------------------------------------------------------------

class MockConnector:
    """Minimal connector for testing the sync engine."""
    platform = "mock"

    def __init__(self, items: list[Item], fail_on_changes: bool = False):
        self._items = {item.item_id: item for item in items}
        self._fail_on_changes = fail_on_changes
        self.changes_call_count = 0

    def changes(self, cursor: float | None) -> tuple[list[ItemRef], float]:
        self.changes_call_count += 1
        if self._fail_on_changes:
            raise ConnectionError("simulated connector failure")
        refs = [
            ItemRef(platform="mock", container=item.container,
                    item_id=item.item_id, version=item.version)
            for item in self._items.values()
            if cursor is None or item.updated_at > cursor
        ]
        return refs, time.time()

    def fetch(self, item_ref: ItemRef) -> Item:
        return self._items[item_ref.item_id]

    def current_version(self, item_ref: ItemRef) -> str:
        return self._items[item_ref.item_id].version

    def fetch_acl(self, item_ref: ItemRef) -> ACLSnapshot:
        item = self._items[item_ref.item_id]
        return ACLSnapshot(
            item_key=f"mock:{item_ref.item_id}",
            version=item.version,
            acl_json=json.dumps(item.acl),
            fetched_at="",
        )

    def can_access(self, person_email: str, item: Item | ItemRef) -> Decision:
        return Decision(allowed=True)

    def resolve_identity(self, employee_id: str) -> str:
        return employee_id


def _make_item(item_id: str, version: str, text: str = "hello world",
               platform: str = "mock", container: str = "test") -> Item:
    return Item(
        platform=platform,
        container=container,
        item_id=item_id,
        version=version,
        url=f"/items/{item_id}",
        title=f"Item {item_id}",
        author="test",
        created_at=float(int(time.time())),
        updated_at=float(int(time.time())),
        units=[Unit(
            unit_id=f"{platform}:{item_id}@{version}#0",
            kind="section",
            text=text,
            order=0,
            metadata={},
        )],
        links=[],
        acl={"restrictions": []},
    )


class FailingConnector:
    """Connector that always fails on changes()."""
    platform = "failing"

    def changes(self, cursor):
        raise ConnectionError("always fails")

    def fetch(self, item_ref):
        raise ConnectionError("always fails")

    def current_version(self, item_ref):
        return ""

    def fetch_acl(self, item_ref):
        raise ConnectionError("always fails")

    def can_access(self, person_email, item):
        return Decision(allowed=False)

    def resolve_identity(self, employee_id):
        return employee_id


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def isolated_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("FILEGUARD_DATA_DIR", str(tmp_path))
    yield


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_sync_connector_inserts_items():
    items = [_make_item("I1", "v1"), _make_item("I2", "v1")]
    connector = MockConnector(items)
    result = sync_engine.sync_connector(connector)
    assert result.synced == 2
    assert result.deleted == 0
    assert not result.errors

    stats = sync_engine.get_index_stats()
    assert stats["total_items"] == 2
    assert stats["total_units"] == 2

def test_sync_connector_updates_existing_item():
    # First sync
    items = [_make_item("I1", "v1", text="old text")]
    connector = MockConnector(items)
    sync_engine.sync_connector(connector)

    # Second sync with updated version — the mock returns ALL items
    # when cursor is None, but only newer ones when cursor is passed.
    # To simulate an update, we bump updated_at and version.
    updated_item = _make_item("I1", "v2", text="new text")
    updated_item.updated_at = time.time() + 1  # newer than cursor
    connector2 = MockConnector([updated_item])
    result = sync_engine.sync_connector(connector2)
    assert result.synced == 1

    # Verify the item was updated
    conn = sync_engine._connect()
    row = conn.execute("SELECT version, title FROM items WHERE item_id = 'I1'").fetchone()
    conn.close()
    assert row["version"] == "v2"

def test_sync_connector_handles_tombstones():
    # First sync with one item
    items = [_make_item("I1", "v1")]
    connector = MockConnector(items)
    sync_engine.sync_connector(connector)

    # Second sync with a deletion (empty version = tombstone)
    connector2 = MockConnector([])
    # Manually create a ref with empty version to simulate deletion
    original_changes = connector2.changes
    def mock_changes(cursor):
        return ([ItemRef(platform="mock", container="test",
                         item_id="I1", version="")], time.time())
    connector2.changes = mock_changes

    result = sync_engine.sync_connector(connector2)
    assert result.deleted == 1

    conn = sync_engine._connect()
    row = conn.execute("SELECT deleted FROM items WHERE item_id = 'I1'").fetchone()
    conn.close()
    assert row["deleted"] == 1

def test_failed_connector_does_not_block_others():
    good_connector = MockConnector([_make_item("I1", "v1")])
    bad_connector = FailingConnector()

    results = sync_engine.sync_all([good_connector, bad_connector])

    # Good connector should have succeeded
    good_result = next(r for r in results if r.platform == "mock")
    assert good_result.synced == 1
    assert not good_result.errors

    # Bad connector should have failed
    bad_result = next(r for r in results if r.platform == "failing")
    assert bad_result.synced == 0
    assert len(bad_result.errors) > 0

    # The good connector's items should be in the index
    stats = sync_engine.get_index_stats()
    assert stats["total_items"] == 1

def test_cursor_persists_across_syncs():
    connector = MockConnector([_make_item("I1", "v1")])
    sync_engine.sync_connector(connector)

    # Check that the cursor was persisted
    conn = sync_engine._connect()
    cursor = conn.execute("SELECT cursor FROM sync_state WHERE platform = 'mock'").fetchone()
    conn.close()
    assert cursor[0] > 0

def test_sync_status_reporting():
    connector = MockConnector([_make_item("I1", "v1")])
    sync_engine.sync_connector(connector)

    status = sync_engine.get_sync_status()
    assert len(status["connectors"]) == 1
    assert status["connectors"][0]["platform"] == "mock"
    assert status["connectors"][0]["total_synced"] == 1
    assert status["connectors"][0]["last_error"] is None

def test_sync_now_triggers_immediate_sync():
    connector = MockConnector([_make_item("I1", "v1")])
    results = sync_engine.sync_now([connector])
    assert len(results) == 1
    assert results[0].synced == 1

def test_force_full_sync_ignores_cursor():
    # First sync
    connector = MockConnector([_make_item("I1", "v1")])
    sync_engine.sync_connector(connector)

    # Second sync with force_full should re-sync everything
    result = sync_engine.sync_connector(connector, force_full=True)
    assert result.synced == 1

def test_sync_records_error_state():
    connector = FailingConnector()
    result = sync_engine.sync_connector(connector)
    assert len(result.errors) > 0

    status = sync_engine.get_sync_status()
    failing = next(c for c in status["connectors"] if c["platform"] == "failing")
    assert failing["last_error"] is not None
    assert failing["last_error_ts"] is not None

def test_index_stats_by_platform():
    items1 = [_make_item("I1", "v1", platform="mock")]
    items2 = [_make_item("I2", "v1", platform="mock2")]
    c1 = MockConnector(items1)
    c1.platform = "mock"
    c2 = MockConnector(items2)
    c2.platform = "mock2"

    sync_engine.sync_all([c1, c2])

    stats = sync_engine.get_index_stats()
    assert stats["total_items"] == 2
    assert "mock" in stats["by_platform"]
    assert "mock2" in stats["by_platform"]
    assert stats["by_platform"]["mock"] == 1
    assert stats["by_platform"]["mock2"] == 1

def test_units_are_replaced_on_update():
    # First sync with 1 unit
    items = [_make_item("I1", "v1", text="original")]
    connector = MockConnector(items)
    sync_engine.sync_connector(connector)

    conn = sync_engine._connect()
    item_key = "mock:I1"
    units = conn.execute("SELECT * FROM units WHERE item_key = ?", (item_key,)).fetchall()
    conn.close()
    assert len(units) == 1
    assert units[0]["text"] == "original"

    # Update with different text
    updated_item = _make_item("I1", "v2", text="updated")
    updated_item.updated_at = time.time() + 1  # newer than cursor
    connector = MockConnector([updated_item])
    sync_engine.sync_connector(connector)

    conn = sync_engine._connect()
    units = conn.execute("SELECT * FROM units WHERE item_key = ?", (item_key,)).fetchall()
    conn.close()
    assert len(units) == 1  # old unit deleted, new one inserted
    assert units[0]["text"] == "updated"
