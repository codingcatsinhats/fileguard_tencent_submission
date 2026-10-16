"""Freshness gate — verify indexed items are current before serving.

Before using any selected item, call `current_version` on the connector
and compare with the indexed version. If different, re-fetch and re-index
that item synchronously within a short timeout. If the source is unreachable,
serve the indexed copy marked stale and log it.

Each cited item carries:
- `verified_current_at`: when we confirmed the version was current
- `last_synced_at`: when the sync engine last fetched this item
- `stale`: True if the source was unreachable or the version changed mid-request
"""

from __future__ import annotations

import json
import sqlite3
import time
import logging
from dataclasses import dataclass, field
from typing import Any

from fileguard.connector import Connector, Item, ItemRef, Unit

logger = logging.getLogger(__name__)

# Maximum time to wait for a re-fetch before serving stale.
FRESHNESS_TIMEOUT_S = 5.0


@dataclass
class FreshnessResult:
    """Result of a freshness check on one item."""
    fresh: bool              # True if indexed version == live version
    stale: bool              # True if source unreachable or version changed
    indexed_version: str
    live_version: str | None  # None if source unreachable
    verified_current_at: float  # timestamp of the freshness check
    last_synced_at: float       # when the sync engine last fetched
    re_fetched: bool            # True if we re-fetched and re-indexed
    error: str = ""


def check_freshness(
    idx_conn: sqlite3.Connection,
    connector: Connector | None,
    platform: str,
    item_id: str,
    indexed_version: str,
    container: str = "",
) -> FreshnessResult:
    """Check if an indexed item's version matches the live version.

    If the versions differ, re-fetch and re-index the item synchronously.
    If the source is unreachable, serve the indexed copy marked stale.

    Args:
        idx_conn: Connection to the unified index DB.
        connector: The platform connector (None = no live check, assume fresh).
        platform: The platform name.
        item_id: The item ID.
        indexed_version: The version currently in the index.
        container: The container name (for re-fetch).

    Returns:
        FreshnessResult with freshness status and timestamps.
    """
    now = time.time()

    # Look up last_synced_at from the items table
    row = idx_conn.execute(
        "SELECT fetched_at FROM items WHERE platform = ? AND item_id = ?",
        (platform, item_id),
    ).fetchone()
    last_synced = row[0] if row else 0.0

    if connector is None:
        # No connector — can't check freshness, assume fresh
        return FreshnessResult(
            fresh=True,
            stale=False,
            indexed_version=indexed_version,
            live_version=indexed_version,
            verified_current_at=now,
            last_synced_at=last_synced,
            re_fetched=False,
        )

    # Try to get the current version from the source
    item_ref = ItemRef(
        platform=platform,
        container=container,
        item_id=item_id,
        version=indexed_version,
    )

    try:
        live_version = connector.current_version(item_ref)
    except Exception as e:
        logger.warning(
            f"freshness: source unreachable for {platform}:{item_id}: {e}"
        )
        return FreshnessResult(
            fresh=False,
            stale=True,
            indexed_version=indexed_version,
            live_version=None,
            verified_current_at=now,
            last_synced_at=last_synced,
            re_fetched=False,
            error=f"source unreachable: {type(e).__name__}: {e}",
        )

    # Versions match — item is fresh
    if live_version == indexed_version:
        return FreshnessResult(
            fresh=True,
            stale=False,
            indexed_version=indexed_version,
            live_version=live_version,
            verified_current_at=now,
            last_synced_at=last_synced,
            re_fetched=False,
        )

    # Version mismatch — re-fetch and re-index synchronously
    logger.info(
        f"freshness: version mismatch for {platform}:{item_id}: "
        f"indexed={indexed_version} live={live_version}, re-fetching"
    )

    try:
        item = _refetch_with_timeout(connector, item_ref, FRESHNESS_TIMEOUT_S)
        if item is not None:
            _re_index(idx_conn, item)
            return FreshnessResult(
                fresh=True,
                stale=False,
                indexed_version=live_version,
                live_version=live_version,
                verified_current_at=now,
                last_synced_at=time.time(),
                re_fetched=True,
            )
    except Exception as e:
        logger.warning(
            f"freshness: re-fetch failed for {platform}:{item_id}: {e}"
        )

    # Re-fetch failed — serve stale
    return FreshnessResult(
        fresh=False,
        stale=True,
        indexed_version=indexed_version,
        live_version=live_version,
        verified_current_at=now,
        last_synced_at=last_synced,
        re_fetched=False,
        error="re-fetch failed or timed out",
    )


def _refetch_with_timeout(
    connector: Connector,
    item_ref: ItemRef,
    timeout_s: float,
) -> Item | None:
    """Re-fetch an item from the source, with a soft timeout.

    For the hackathon demo, we just call fetch() directly — the simulators
    are local and fast. In production, this would use a thread with a
    hard timeout or an async call with asyncio.wait_for.
    """
    # Simple direct fetch — simulators are local and sub-second
    return connector.fetch(item_ref)


def _re_index(idx_conn: sqlite3.Connection, item: Item) -> None:
    """Re-index a re-fetched item: update the items and units tables.

    Uses the same upsert logic as the sync engine.
    """
    from fileguard.sync_engine import _upsert_item

    _upsert_item(idx_conn, item)
    idx_conn.commit()


def get_sync_lag(idx_conn: sqlite3.Connection, platform: str) -> float | None:
    """Get the sync lag (seconds since last successful sync) for a platform.

    Returns None if no sync has ever been recorded.
    """
    row = idx_conn.execute(
        "SELECT last_sync_ts FROM sync_state WHERE platform = ?",
        (platform,),
    ).fetchone()
    if row is None or row[0] is None:
        return None
    return time.time() - row[0]
