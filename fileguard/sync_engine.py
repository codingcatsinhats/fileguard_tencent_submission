"""Sync engine: incremental sync per connector.

Polls each connector's change feed, fetches new/updated items, and writes
them to the unified index DB. Handles edits, deletions (tombstones), and
permission changes. Failed connectors are isolated — one failure does not
block others.

The unified index is a SQLite DB with:
- items: platform, container, item_id, version, url, title, author,
  created_at, updated_at, deleted (tombstone), acl_json
- units: unit_id, item_key, kind, text, order_idx, text_sha256
- sync_state: per-connector cursor, last_sync_ts, last_error, lag

Phase 6 will add an FTS5 virtual table on units.text for search.
"""

from __future__ import annotations

import json
import sqlite3
import time
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from fileguard.connector import Connector, ItemRef, Item
from fileguard import config

logger = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS items (
    platform    TEXT NOT NULL,
    container   TEXT NOT NULL,
    item_id     TEXT NOT NULL,
    version     TEXT NOT NULL,
    url         TEXT NOT NULL DEFAULT '',
    title       TEXT NOT NULL DEFAULT '',
    author      TEXT NOT NULL DEFAULT '',
    created_at  REAL NOT NULL DEFAULT 0,
    updated_at  REAL NOT NULL DEFAULT 0,
    deleted     INTEGER NOT NULL DEFAULT 0,
    acl_json    TEXT NOT NULL DEFAULT '{}',
    links_json  TEXT NOT NULL DEFAULT '[]',
    fetched_at  REAL NOT NULL DEFAULT 0,
    PRIMARY KEY (platform, item_id)
);

CREATE INDEX IF NOT EXISTS items_container_idx ON items(platform, container);
CREATE INDEX IF NOT EXISTS items_deleted_idx ON items(deleted);

CREATE TABLE IF NOT EXISTS units (
    unit_id     TEXT NOT NULL,
    item_key    TEXT NOT NULL,   -- "platform:item_id"
    kind        TEXT NOT NULL,
    text        TEXT NOT NULL,
    order_idx   INTEGER NOT NULL,
    text_sha256 TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (unit_id)
);
CREATE INDEX IF NOT EXISTS units_item_key_idx ON units(item_key);

CREATE TABLE IF NOT EXISTS sync_state (
    platform       TEXT PRIMARY KEY,
    cursor         REAL NOT NULL DEFAULT 0,
    last_sync_ts   REAL,
    last_error     TEXT,
    last_error_ts  REAL,
    total_synced   INTEGER NOT NULL DEFAULT 0,
    total_deleted  INTEGER NOT NULL DEFAULT 0
);
"""


@dataclass
class SyncResult:
    """Result of syncing one connector."""
    platform: str
    synced: int = 0
    deleted: int = 0
    errors: list[str] = field(default_factory=list)
    duration_s: float = 0.0


def _db_path() -> Path:
    return config.DATA_DIR / "index.db"


def _connect() -> sqlite3.Connection:
    path = _db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    return conn


def _item_key(platform: str, item_id: str) -> str:
    return f"{platform}:{item_id}"


def _upsert_item(conn: sqlite3.Connection, item: Item) -> None:
    """Insert or update an item and its units."""
    item_key = _item_key(item.platform, item.item_id)

    # Upsert item
    conn.execute("""
        INSERT INTO items (platform, container, item_id, version, url, title,
                           author, created_at, updated_at, deleted, acl_json,
                           links_json, fetched_at)
        VALUES (?,?,?,?,?,?,?,?,?,0,?,?,?)
        ON CONFLICT(platform, item_id) DO UPDATE SET
            container=excluded.container,
            version=excluded.version,
            url=excluded.url,
            title=excluded.title,
            author=excluded.author,
            created_at=excluded.created_at,
            updated_at=excluded.updated_at,
            deleted=0,
            acl_json=excluded.acl_json,
            links_json=excluded.links_json,
            fetched_at=excluded.fetched_at
    """, (
        item.platform, item.container, item.item_id, item.version,
        item.url, item.title, item.author,
        item.created_at, item.updated_at,
        json.dumps(item.acl), json.dumps(item.links), time.time(),
    ))

    # Delete old units and insert new ones
    conn.execute("DELETE FROM units WHERE item_key = ?", (item_key,))

    for unit in item.units:
        conn.execute("""
            INSERT INTO units (unit_id, item_key, kind, text, order_idx,
                               text_sha256, metadata_json)
            VALUES (?,?,?,?,?,?,?)
            ON CONFLICT(unit_id) DO UPDATE SET
                item_key=excluded.item_key,
                kind=excluded.kind,
                text=excluded.text,
                order_idx=excluded.order_idx,
                text_sha256=excluded.text_sha256,
                metadata_json=excluded.metadata_json
        """, (
            unit.unit_id, item_key, unit.kind, unit.text,
            unit.order, unit.text_sha256,
            json.dumps(unit.metadata),
        ))


def _tombstone_item(conn: sqlite3.Connection, platform: str, item_id: str) -> None:
    """Mark an item as deleted (tombstone)."""
    conn.execute("""
        UPDATE items SET deleted = 1, fetched_at = ?
        WHERE platform = ? AND item_id = ?
    """, (time.time(), platform, item_id))
    # Also remove units for tombstoned items
    item_key = _item_key(platform, item_id)
    conn.execute("DELETE FROM units WHERE item_key = ?", (item_key,))


def _get_cursor(conn: sqlite3.Connection, platform: str) -> float:
    row = conn.execute(
        "SELECT cursor FROM sync_state WHERE platform = ?", (platform,)
    ).fetchone()
    return row[0] if row else 0.0


def _update_sync_state(
    conn: sqlite3.Connection,
    platform: str,
    cursor: float,
    synced: int,
    deleted: int,
    error: str | None = None,
) -> None:
    now = time.time()
    if error:
        conn.execute("""
            INSERT INTO sync_state (platform, cursor, last_sync_ts, last_error,
                                   last_error_ts, total_synced, total_deleted)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(platform) DO UPDATE SET
                cursor=excluded.cursor,
                last_sync_ts=excluded.last_sync_ts,
                last_error=excluded.last_error,
                last_error_ts=excluded.last_error_ts,
                total_synced=sync_state.total_synced + ?,
                total_deleted=sync_state.total_deleted + ?
        """, (platform, cursor, now, error, now, synced, deleted, synced, deleted))
    else:
        conn.execute("""
            INSERT INTO sync_state (platform, cursor, last_sync_ts, last_error,
                                   last_error_ts, total_synced, total_deleted)
            VALUES (?, ?, ?, NULL, NULL, ?, ?)
            ON CONFLICT(platform) DO UPDATE SET
                cursor=excluded.cursor,
                last_sync_ts=excluded.last_sync_ts,
                last_error=NULL,
                last_error_ts=NULL,
                total_synced=sync_state.total_synced + ?,
                total_deleted=sync_state.total_deleted + ?
        """, (platform, cursor, now, synced, deleted, synced, deleted))


def sync_connector(connector: Connector, force_full: bool = False) -> SyncResult:
    """Sync a single connector. Returns SyncResult.

    If force_full is True, ignores the persisted cursor and syncs from zero.
    """
    start = time.time()
    platform = connector.platform
    result = SyncResult(platform=platform)

    conn = _connect()
    try:
        cursor = 0.0 if force_full else _get_cursor(conn, platform)

        # 1. Get changes from the connector
        try:
            refs, new_cursor = connector.changes(cursor if cursor > 0 else None)
        except Exception as e:
            result.errors.append(f"changes() failed: {e}")
            _update_sync_state(conn, platform, cursor, 0, 0, str(e))
            conn.commit()
            result.duration_s = time.time() - start
            return result

        # 2. Fetch and upsert each changed item
        for ref in refs:
            try:
                # Check if this is a deletion (version is empty or item is deleted)
                if not ref.version:
                    _tombstone_item(conn, ref.platform, ref.item_id)
                    result.deleted += 1
                    continue

                item = connector.fetch(ref)
                _upsert_item(conn, item)
                result.synced += 1
            except Exception as e:
                result.errors.append(f"fetch({ref.item_id}): {e}")
                logger.warning(f"[{platform}] fetch failed for {ref.item_id}: {e}")

        # 3. Update cursor and sync state
        error_msg = "; ".join(result.errors) if result.errors else None
        _update_sync_state(conn, platform, new_cursor, result.synced,
                           result.deleted, error_msg)
        conn.commit()

    except Exception as e:
        result.errors.append(f"unexpected: {e}")
        logger.error(f"[{platform}] sync failed: {e}")
        try:
            _update_sync_state(conn, platform, 0, 0, 0, str(e))
            conn.commit()
        except Exception:
            pass
    finally:
        conn.close()

    result.duration_s = time.time() - start
    return result


def sync_all(connectors: list[Connector]) -> list[SyncResult]:
    """Sync all connectors. A failure in one does not block others."""
    results = []
    for connector in connectors:
        result = sync_connector(connector)
        results.append(result)
        if result.errors:
            logger.warning(f"[{result.platform}] synced with errors: {result.errors}")
        else:
            logger.info(f"[{result.platform}] synced {result.synced} items, "
                        f"{result.deleted} deleted in {result.duration_s:.2f}s")
    return results


def sync_now(connectors: list[Connector]) -> list[SyncResult]:
    """Trigger an immediate sync of all connectors (for the demo)."""
    return sync_all(connectors)


def get_sync_status() -> dict:
    """Return per-connector sync status."""
    conn = _connect()
    try:
        rows = conn.execute("SELECT * FROM sync_state ORDER BY platform").fetchall()
        now = time.time()
        return {
            "connectors": [
                {
                    "platform": r["platform"],
                    "cursor": r["cursor"],
                    "last_sync_ts": r["last_sync_ts"],
                    "last_error": r["last_error"],
                    "last_error_ts": r["last_error_ts"],
                    "total_synced": r["total_synced"],
                    "total_deleted": r["total_deleted"],
                    "lag_s": now - r["last_sync_ts"] if r["last_sync_ts"] else None,
                }
                for r in rows
            ]
        }
    finally:
        conn.close()


def get_index_stats() -> dict:
    """Return index statistics."""
    conn = _connect()
    try:
        total_items = conn.execute(
            "SELECT COUNT(*) FROM items WHERE deleted = 0"
        ).fetchone()[0]
        total_units = conn.execute("SELECT COUNT(*) FROM units").fetchone()[0]
        by_platform = {}
        for row in conn.execute(
            "SELECT platform, COUNT(*) as cnt FROM items WHERE deleted = 0 "
            "GROUP BY platform"
        ):
            by_platform[row["platform"]] = row["cnt"]
        return {
            "total_items": total_items,
            "total_units": total_units,
            "by_platform": by_platform,
        }
    finally:
        conn.close()
