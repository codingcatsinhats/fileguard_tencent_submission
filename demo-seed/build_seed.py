"""One-off builder for demo-seed/seed/ — the static demo assets.

Creates a clean central.db (users, audit tokens, file registry — zero audit
entries) plus the encrypted object store, using the same seed/ingest logic
as development. Run only when the document set or user list changes:

    python3 demo-seed/build_seed.py

The audit *history* is NOT baked in: reset-demo.py generates it at reset
time (seed_story.py) so timestamps are always relative to the reset.
"""

import os
import shutil
import sys
from pathlib import Path

SEED_DIR = Path(__file__).resolve().parent
SEED_DATA = SEED_DIR / "seed"
REPO_ROOT = SEED_DIR.parent

_STALE = ("central.db", "central.db-wal", "central.db-shm",
          "harness_local.db", "harness_local.db-wal", "harness_local.db-shm")


def main() -> None:
    os.environ["FILEGUARD_DATA_DIR"] = str(SEED_DATA)
    sys.path.insert(0, str(REPO_ROOT))

    for name in _STALE:
        (SEED_DATA / name).unlink(missing_ok=True)
    shutil.rmtree(SEED_DATA / "store", ignore_errors=True)

    from fileguard import db
    from scripts import ingest_demo, seed

    seed.main()
    ingest_demo.main()

    conn = db.central()
    try:
        n_files = conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]
        n_logs = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    finally:
        conn.close()
    assert n_logs == 0, "seed registry must ship with an empty audit log"
    print(f"demo-seed/seed built: {n_files} files registered, "
          f"objects in demo-seed/seed/store/, audit log empty.")


if __name__ == "__main__":
    main()
