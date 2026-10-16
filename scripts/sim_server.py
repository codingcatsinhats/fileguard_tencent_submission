"""Run one platform simulator as a service, seeded with Company A data.

    python3 scripts/sim_server.py confluence   # ports: see factory.SIM_PORTS

Reseeds the simulator's SQLite store on every start (fresh demo state each
restart), including the directory table the simulators use for bearer-token
auth. The admin token is the demo credential hardcoded in
fileguard/connectors/factory.py — demo on purpose, not a mistake.
"""

import hashlib
import json
import os
import sqlite3
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "simulators"))
sys.path.insert(0, str(ROOT / "demo-seed"))

from fileguard.connectors import factory  # noqa: E402
from common import SYNC_ADMIN_ID  # noqa: E402
from company_a.story import generate_all, PEOPLE  # noqa: E402


def seed_directory(db_path: str) -> None:
    """The directory table simulators validate bearer tokens against."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS directory (
            employee_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            token_hash TEXT,
            clearance TEXT NOT NULL DEFAULT 'open',
            groups TEXT NOT NULL DEFAULT '[]'
        );
    """)
    admin_hash = hashlib.sha256(factory.ADMIN_TOKEN.encode()).hexdigest()
    conn.execute("DELETE FROM directory")
    # sync-service first: every row shares the admin token hash, and
    # validate_token returns the first match — the connector's bearer must
    # resolve to the service account the sims exempt from native ACL checks.
    conn.execute(
        "INSERT OR REPLACE INTO directory "
        "(employee_id, name, email, token_hash, clearance, groups) "
        "VALUES (?,?,?,?,?,?)",
        (SYNC_ADMIN_ID, "Sync service account", "sync@halcyon.example",
         admin_hash, "top_secret", "[]"),
    )
    for eid, name, _role, groups_str, clearance, email, _notes in PEOPLE:
        conn.execute(
            "INSERT OR REPLACE INTO directory "
            "(employee_id, name, email, token_hash, clearance, groups) "
            "VALUES (?,?,?,?,?,?)",
            (eid, name, email, admin_hash, clearance,
             json.dumps(groups_str.split(","))),
        )
    conn.commit()
    conn.close()


def bootstrap_change_feeds(platform: str, db_path: str) -> None:
    """Seed one change-feed event per item so the connectors' changes() finds
    everything on a fresh demo seed (slack polls membership_events, drive
    polls changes_log — neither is populated by the story generator).
    Real now, not the story's DEMO_NOW: a reseed must land AFTER any sync
    cursor a previous demo run persisted, or the feed looks empty."""
    conn = sqlite3.connect(db_path)
    ts = time.time() + 1
    if platform == "slack":
        channels = [r[0] for r in conn.execute("SELECT name FROM channels")]
        for ch in channels:
            conn.execute(
                "INSERT INTO membership_events (channel, person, action, ts) "
                "VALUES (?, 'sync-service', 'bootstrap', ?)", (ch, ts))
    elif platform == "drive":
        for (key,) in conn.execute("SELECT key FROM files"):
            conn.execute(
                "INSERT INTO changes_log (file_key, change_type, ts, details) "
                "VALUES (?, 'bootstrap', ?, '{}')", (key, ts))
    conn.commit()
    conn.close()


def main() -> None:
    platform = sys.argv[1] if len(sys.argv) > 1 else ""
    if platform not in factory.SIM_PORTS:
        raise SystemExit(f"usage: sim_server.py [{'|'.join(factory.SIM_PORTS)}]")
    import importlib
    mod = importlib.import_module(platform)

    db_path = str(ROOT / "data" / "sim" / f"{platform}.db")
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    data = generate_all()
    # the Windows mount throws transient "readonly database" WAL errors right
    # after reset-demo deletes data/sim — retry until the fs settles
    import time
    for attempt in range(10):
        try:
            mod.seed(data, db_path)
            seed_directory(db_path)
            bootstrap_change_feeds(platform, db_path)
            break
        except sqlite3.OperationalError as e:
            if attempt == 9:
                raise
            print(f"seed retry {attempt + 1} ({e})", flush=True)
            time.sleep(1)
    # pidfile: sync_demo restarts stale sims after reset-demo wipes data/sim
    # (lives in data/ itself — reset-demo deletes data/sim but not this)
    (ROOT / "data" / f"sim_{platform}.pid").write_text(str(os.getpid()))

    import uvicorn
    print(f"{platform} simulator on :{factory.SIM_PORTS[platform]} (db: {db_path})")
    uvicorn.run(mod.app, host="127.0.0.1", port=factory.SIM_PORTS[platform],
                log_level="warning")


if __name__ == "__main__":
    main()
