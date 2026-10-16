"""Freshness gate tests: version match, version mismatch (re-fetch),
source unreachable (serve stale), freshness stamps in pipeline, sync lag."""

import json
import os
import sys
import sqlite3
import time
import hashlib
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))
sys.path.insert(0, str(_REPO / "simulators"))
sys.path.insert(0, str(_REPO / "demo-seed"))

from fileguard import config, db, identity, sync_engine, pipeline, freshness  # noqa: E402
from fileguard.connector import Item, ItemRef, Unit, Decision, ACLSnapshot  # noqa: E402
from fileguard.freshness import FreshnessResult, check_freshness, get_sync_lag  # noqa: E402
from fileguard.pipeline import PipelineRequest, PipelineResult, run_pipeline  # noqa: E402


# ---------------------------------------------------------------------------
# Mock connector with version control
# ---------------------------------------------------------------------------

class FreshnessMockConnector:
    """Mock connector that can change its version on demand."""
    platform = "confluence"

    def __init__(self, items: list[Item]):
        self._items = {item.item_id: item for item in items}
        self._version_overrides: dict[str, str] = {}
        self._unreachable: bool = False
        self._fetch_count: int = 0

    def set_live_version(self, item_id: str, version: str):
        """Override the live version returned by current_version."""
        self._version_overrides[item_id] = version

    def set_unreachable(self, unreachable: bool = True):
        """Simulate the source being unreachable."""
        self._unreachable = unreachable

    @property
    def fetch_count(self):
        return self._fetch_count

    def changes(self, cursor):
        refs = [ItemRef(platform="confluence", container=item.container,
                        item_id=item.item_id, version=item.version)
                for item in self._items.values()]
        return refs, time.time()

    def fetch(self, item_ref):
        self._fetch_count += 1
        item = self._items[item_ref.item_id]
        # If a version override exists, return the item with that version
        override = self._version_overrides.get(item_ref.item_id)
        if override and override != item.version:
            return Item(
                platform=item.platform, container=item.container,
                item_id=item.item_id, version=override,
                url=item.url, title=item.title + " (v8 update)",
                author=item.author, created_at=item.created_at,
                updated_at=time.time(),
                units=item.units + [
                    Unit(unit_id=f"confluence:{item.item_id}@{override}#extra",
                         kind="section", text="Step 6: promote the replica using the --force-failover flag",
                         order=len(item.units), metadata={})
                ],
                links=item.links, acl=item.acl,
            )
        return item

    def current_version(self, item_ref):
        if self._unreachable:
            raise ConnectionError("source is unreachable")
        override = self._version_overrides.get(item_ref.item_id)
        if override:
            return override
        return self._items[item_ref.item_id].version

    def fetch_acl(self, item_ref):
        item = self._items[item_ref.item_id]
        return ACLSnapshot(item_key=f"confluence:{item_ref.item_id}",
                           version=item.version, acl_json="{}", fetched_at=time.time())

    def can_access(self, person_email, item):
        return Decision(allowed=True)

    def resolve_identity(self, employee_id):
        return f"{employee_id}@halcyon.example"


def _make_item(item_id, version, title, units_text, container="PAY-DOCS",
               platform="confluence"):
    units = [
        Unit(unit_id=f"{platform}:{item_id}@{version}#{i}",
             kind="section", text=text, order=i, metadata={})
        for i, text in enumerate(units_text)
    ]
    return Item(
        platform=platform, container=container, item_id=item_id,
        version=version, url=f"/items/{item_id}", title=title,
        author="test", created_at=float(int(time.time())),
        updated_at=float(int(time.time())),
        units=units, links=[], acl={},
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def isolated_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("FILEGUARD_DATA_DIR", str(tmp_path))
    yield


@pytest.fixture
def conn():
    c = db.central()
    identity.init_directory(c)
    yield c
    c.close()


@pytest.fixture
def seeded_index():
    """Seed the unified index with a known runbook item."""
    items = [
        _make_item("CF-RUNBOOK", "v7",
                   "Runbook: payment-service incident response",
                   ["Steps 1-5: check alerts, verify pool size, restart service",
                    "If pool size is below 50, escalate to oncall immediately"]),
    ]
    connector = FreshnessMockConnector(items)
    sync_engine.sync_connector(connector)
    return items, connector


@pytest.fixture
def registered_employees(conn):
    def _hash(token):
        return hashlib.sha256(token.encode()).hexdigest()

    identity.register_employee(
        conn, "raj", "Raj Patel", "raj@halcyon.example",
        "confidential", ["eng", "sre", "payments"], _hash("tok-raj"),
    )
    return conn


# ---------------------------------------------------------------------------
# Freshness gate unit tests
# ---------------------------------------------------------------------------

def test_freshness_version_match(seeded_index):
    """Live version == indexed version → fresh=True."""
    items, connector = seeded_index
    idx_conn = sync_engine._connect()
    try:
        result = check_freshness(
            idx_conn=idx_conn,
            connector=connector,
            platform="confluence",
            item_id="CF-RUNBOOK",
            indexed_version="v7",
            container="PAY-DOCS",
        )
        assert result.fresh
        assert not result.stale
        assert result.indexed_version == "v7"
        assert result.live_version == "v7"
        assert result.verified_current_at > 0
        assert result.last_synced_at > 0
        assert not result.re_fetched
    finally:
        idx_conn.close()


def test_freshness_version_mismatch_triggers_refetch(seeded_index):
    """Live version != indexed version → re-fetch and re-index."""
    items, connector = seeded_index
    # Simulate v8 published at the source
    connector.set_live_version("CF-RUNBOOK", "v8")

    idx_conn = sync_engine._connect()
    try:
        # Record fetch count before freshness check (initial sync already did 1 fetch)
        fetches_before = connector.fetch_count
        result = check_freshness(
            idx_conn=idx_conn,
            connector=connector,
            platform="confluence",
            item_id="CF-RUNBOOK",
            indexed_version="v7",
            container="PAY-DOCS",
        )
        assert result.re_fetched
        assert result.fresh  # after re-fetch, it's fresh
        assert not result.stale
        assert result.live_version == "v8"
        assert connector.fetch_count == fetches_before + 1  # one re-fetch

        # Verify the index was updated
        row = idx_conn.execute(
            "SELECT version, title FROM items WHERE platform='confluence' AND item_id='CF-RUNBOOK'"
        ).fetchone()
        assert row[0] == "v8"
        assert "v8 update" in row[1]
    finally:
        idx_conn.close()


def test_freshness_source_unreachable_serves_stale(seeded_index):
    """Source unreachable → serve indexed copy marked stale."""
    items, connector = seeded_index
    connector.set_unreachable(True)

    idx_conn = sync_engine._connect()
    try:
        result = check_freshness(
            idx_conn=idx_conn,
            connector=connector,
            platform="confluence",
            item_id="CF-RUNBOOK",
            indexed_version="v7",
            container="PAY-DOCS",
        )
        assert result.stale
        assert not result.fresh
        assert result.live_version is None
        assert "unreachable" in result.error.lower()
        assert result.verified_current_at > 0
    finally:
        idx_conn.close()


def test_freshness_no_connector_assumes_fresh(seeded_index):
    """No connector → can't check, assume fresh."""
    items, _ = seeded_index
    idx_conn = sync_engine._connect()
    try:
        result = check_freshness(
            idx_conn=idx_conn,
            connector=None,
            platform="confluence",
            item_id="CF-RUNBOOK",
            indexed_version="v7",
            container="PAY-DOCS",
        )
        assert result.fresh
        assert not result.stale
        assert result.live_version == "v7"
    finally:
        idx_conn.close()


def test_freshness_last_synced_at(seeded_index):
    """last_synced_at is populated from the items table."""
    items, connector = seeded_index
    idx_conn = sync_engine._connect()
    try:
        result = check_freshness(
            idx_conn=idx_conn,
            connector=connector,
            platform="confluence",
            item_id="CF-RUNBOOK",
            indexed_version="v7",
            container="PAY-DOCS",
        )
        assert result.last_synced_at > 0
    finally:
        idx_conn.close()


def test_get_sync_lag(seeded_index):
    """get_sync_lag returns seconds since last sync."""
    items, _ = seeded_index
    idx_conn = sync_engine._connect()
    try:
        lag = get_sync_lag(idx_conn, "confluence")
        assert lag is not None
        assert lag >= 0
    finally:
        idx_conn.close()


def test_get_sync_lag_no_sync(tmp_path):
    """get_sync_lag returns None if no sync has been recorded."""
    monkeypatch_path = tmp_path / "fresh"
    monkeypatch_path.mkdir()
    os.environ["FILEGUARD_DATA_DIR"] = str(monkeypatch_path)
    idx_conn = sync_engine._connect()
    try:
        lag = get_sync_lag(idx_conn, "nonexistent")
        assert lag is None
    finally:
        idx_conn.close()


# ---------------------------------------------------------------------------
# Pipeline integration tests with freshness
# ---------------------------------------------------------------------------

def test_pipeline_freshness_stamps(seeded_index, registered_employees):
    """Pipeline result includes freshness stamps."""
    items, connector = seeded_index
    req = PipelineRequest(
        user_id="raj", employee_id="raj",
        max_clearance="confidential", groups=["eng", "sre", "payments"],
        session_id="sess-f1",
        reason="payment service runbook steps",
        platform="confluence", item_id="CF-RUNBOOK",
    )
    conn = db.central()
    try:
        result = run_pipeline(req, conn, connector=connector)
        assert result.ok
        assert result.verified_current_at > 0
        assert result.last_synced_at > 0
        assert not result.stale
        assert not result.re_fetched
    finally:
        conn.close()


def test_pipeline_fresh_version_mismatch_refetch(seeded_index, registered_employees):
    """Pipeline detects version mismatch and re-fetches the item."""
    items, connector = seeded_index
    # Simulate v8 published
    connector.set_live_version("CF-RUNBOOK", "v8")

    req = PipelineRequest(
        user_id="raj", employee_id="raj",
        max_clearance="confidential", groups=["eng", "sre", "payments"],
        session_id="sess-f2",
        reason="payment service runbook failover",
        platform="confluence", item_id="CF-RUNBOOK",
    )
    conn = db.central()
    try:
        result = run_pipeline(req, conn, connector=connector)
        assert result.ok
        assert result.re_fetched
        assert not result.stale
        # The item title should reflect the re-fetched version
        assert "v8" in result.item_title or "update" in result.item_title.lower()
    finally:
        conn.close()


def test_pipeline_source_unreachable_serves_stale(seeded_index, registered_employees):
    """Pipeline serves stale content when source is unreachable."""
    items, connector = seeded_index
    connector.set_unreachable(True)

    req = PipelineRequest(
        user_id="raj", employee_id="raj",
        max_clearance="confidential", groups=["eng", "sre", "payments"],
        session_id="sess-f3",
        reason="payment service runbook steps",
        platform="confluence", item_id="CF-RUNBOOK",
    )
    conn = db.central()
    try:
        result = run_pipeline(req, conn, connector=connector)
        assert result.ok
        assert result.stale
        assert not result.re_fetched
        # Still serves content (the indexed copy)
        assert result.level in ("verified", "pruned", "excerpts_only")
    finally:
        conn.close()


def test_pipeline_no_connector_no_freshness_check(seeded_index, registered_employees):
    """Without a connector, freshness is assumed fresh (no live check)."""
    items, _ = seeded_index
    req = PipelineRequest(
        user_id="raj", employee_id="raj",
        max_clearance="confidential", groups=["eng", "sre", "payments"],
        session_id="sess-f4",
        reason="payment service runbook steps",
        platform="confluence", item_id="CF-RUNBOOK",
    )
    conn = db.central()
    try:
        result = run_pipeline(req, conn, connector=None)
        assert result.ok
        assert not result.stale
        assert not result.re_fetched
    finally:
        conn.close()


def test_pipeline_refetch_updates_content_hash(seeded_index, registered_employees):
    """After re-fetch, content hash reflects the new version."""
    items, connector = seeded_index
    connector.set_live_version("CF-RUNBOOK", "v8")

    req = PipelineRequest(
        user_id="raj", employee_id="raj",
        max_clearance="confidential", groups=["eng", "sre", "payments"],
        session_id="sess-f5",
        reason="payment service runbook failover",
        platform="confluence", item_id="CF-RUNBOOK",
    )
    conn = db.central()
    try:
        # First request: re-fetches to v8
        r1 = run_pipeline(req, conn, connector=connector)
        assert r1.re_fetched
        hash_after_refetch = r1.content_hash

        # Second request: v8 is now indexed, no re-fetch
        connector.set_live_version("CF-RUNBOOK", "v8")  # still v8
        r2 = run_pipeline(req, conn, connector=connector)
        assert not r2.re_fetched  # no re-fetch needed
        assert r2.content_hash == hash_after_refetch  # same hash
    finally:
        conn.close()


def test_pipeline_freshness_g4_scenario(seeded_index, registered_employees):
    """G4 scenario: runbook v7 in the morning, v8 at 13:00, queried at 14:05.

    The pipeline must return v8 with step 6 and show it was verified current.
    """
    items, connector = seeded_index
    # Simulate v8 published (step 6 added)
    connector.set_live_version("CF-RUNBOOK", "v8")

    req = PipelineRequest(
        user_id="raj", employee_id="raj",
        max_clearance="confidential", groups=["eng", "sre", "payments"],
        session_id="sess-g4",
        reason="payment service incident runbook failover step",
        platform="confluence", item_id="CF-RUNBOOK",
    )
    conn = db.central()
    try:
        result = run_pipeline(req, conn, connector=connector)
        assert result.ok
        assert result.re_fetched
        assert not result.stale
        assert result.verified_current_at > 0
        # Answer should include step 6 content
        assert "force-failover" in result.answer_text.lower() or "replica" in result.answer_text.lower()
    finally:
        conn.close()


def test_pipeline_freshness_g5_scenario(seeded_index, registered_employees):
    """G5 scenario: same question at 12:50 (before the edit) → v7, no step 6."""
    items, connector = seeded_index
    # v7 is still the live version (no edit yet)
    req = PipelineRequest(
        user_id="raj", employee_id="raj",
        max_clearance="confidential", groups=["eng", "sre", "payments"],
        session_id="sess-g5",
        reason="payment service incident runbook steps",
        platform="confluence", item_id="CF-RUNBOOK",
    )
    conn = db.central()
    try:
        result = run_pipeline(req, conn, connector=connector)
        assert result.ok
        assert not result.re_fetched  # no re-fetch needed (versions match)
        assert not result.stale
        # Should NOT contain step 6
        assert "force-failover" not in result.answer_text.lower()
    finally:
        conn.close()
