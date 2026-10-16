"""Populate the unified index from the demo simulators (Layer 0 wiring).

    python3 scripts/sync_demo.py

Restarts any stale simulator (reset-demo deletes their DBs — a sim whose db
file is gone is restarted via its pidfile), starts the missing ones, then
runs sync_all() over the five connectors and prints the index state.
Explicit by design: reset-demo does NOT sync.
"""

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import httpx  # noqa: E402

from fileguard.connectors import factory  # noqa: E402
from fileguard import sync_engine  # noqa: E402

SIM_DIR = ROOT / "data" / "sim"


def sim_up(platform: str) -> bool:
    try:
        httpx.get(
            f"http://127.0.0.1:{factory.SIM_PORTS[platform]}/spaces",
            headers={"Authorization": f"Bearer {factory.ADMIN_TOKEN}"},
            timeout=2,
        )
        return True
    except Exception:
        return False


def _pidfile(platform: str) -> Path:
    # outside data/sim: reset-demo deletes that dir, pidfiles must survive it
    return ROOT / "data" / f"sim_{platform}.pid"


def _kill_stale(platform: str) -> int | None:
    """SIGTERM the managed sim (pidfile). Returns its pid, or None.
    A sim left alive across a reset-demo serves a stale/deleted DB, so
    sync_demo always restarts the sims it manages — reseeding is <1s."""
    pid_file = _pidfile(platform)
    if not pid_file.exists():
        return None
    pid = None
    try:
        pid = int(pid_file.read_text().strip())
        os.kill(pid, signal.SIGTERM)
    except (ValueError, ProcessLookupError, PermissionError, OSError):
        # OSError: foreign/garbage pid (e.g. pidfile copied across machines —
        # Windows raises WinError 87; the pid can't be ours, so ignore)
        pass
    pid_file.unlink(missing_ok=True)
    return pid


def _spawn(platform: str) -> None:
    subprocess.Popen(
        [sys.executable, str(ROOT / "scripts" / "sim_server.py"), platform],
        cwd=str(ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def ensure_sims() -> list[str]:
    SIM_DIR.mkdir(parents=True, exist_ok=True)
    started = []
    for platform in factory.SIM_PORTS:
        pid = _kill_stale(platform)
        if pid is not None:
            # wait for the port to free up before respawning; a sim stuck on
            # a deleted WAL file can ignore SIGTERM — escalate to SIGKILL
            for i in range(30):
                if not sim_up(platform):
                    break
                if i == 19:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                time.sleep(0.5)
        elif sim_up(platform):
            continue  # foreign sim (no pidfile): leave it alone
        _spawn(platform)
        started.append(platform)
    deadline = time.time() + 60
    pending = list(started)
    while pending and time.time() < deadline:
        pending = [p for p in pending if not sim_up(p)]
        if pending:
            time.sleep(0.5)
    if pending:
        raise SystemExit(f"simulators failed to start: {pending}")
    return started


def main() -> None:
    started = ensure_sims()
    if started:
        print(f"started simulators: {', '.join(started)}")
    else:
        print("simulators already running")

    connectors = factory.build_connectors()
    results = sync_engine.sync_now(connectors)

    print()
    for r in results:
        status = f"{r.synced} synced, {r.deleted} deleted in {r.duration_s:.1f}s"
        if r.errors:
            status += f" — ERRORS: {'; '.join(r.errors[:3])}"
        print(f"  {r.platform:<11} {status}")

    stats = sync_engine.get_index_stats()
    print(f"\nindex: {stats['total_items']} items, {stats['total_units']} units "
          f"({stats['by_platform']})")
    print("Restart uvicorn (ui.web) is NOT required — the index is on disk.")


if __name__ == "__main__":
    main()
