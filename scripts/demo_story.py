"""Storyline event orchestration for the Company A demo (S2/S6).

    python3 scripts/demo_story.py runbook-v8      # S2: CF-RUNBOOK v7 -> v8
    python3 scripts/demo_story.py revoke-raj      # R1: raj out of #sre-oncall-private
    python3 scripts/demo_story.py restrict-vendor # R2: CF-VENDOR-PRICING -> sam only
    python3 scripts/demo_story.py unshare-tom     # R3: DR-VENDOR-SPEC share removed
    python3 scripts/demo_story.py clock 13:00     # set the sims' demo clock
    python3 scripts/demo_story.py reset           # back to the seeded state

Each mutation re-syncs the affected platform's connector so the unified index
picks up the new version/ACL immediately (between the event and the resync a
search could still list the old state — run the two back-to-back).
"""

import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import httpx  # noqa: E402

from fileguard.connectors import factory  # noqa: E402
from fileguard import sync_engine  # noqa: E402

# event -> (simulator platform hosting it, index platforms to re-sync)
EVENTS = {
    "runbook_v8": ("confluence", ["confluence"]),
    "restrict_vendor_pricing": ("confluence", ["confluence"]),
    "remove_raj_from_sre_oncall": ("slack", ["slack"]),
    "remove_tom_share": ("drive", ["drive"]),
}

ALIASES = {
    "runbook-v8": "runbook_v8",
    "revoke-raj": "remove_raj_from_sre_oncall",
    "restrict-vendor": "restrict_vendor_pricing",
    "unshare-tom": "remove_tom_share",
}


def post(platform: str, path: str, body: dict | None = None) -> dict:
    r = httpx.post(
        f"http://127.0.0.1:{factory.SIM_PORTS[platform]}{path}",
        headers={"Authorization": f"Bearer {factory.ADMIN_TOKEN}"},
        json=body, timeout=10,
    )
    r.raise_for_status()
    return r.json()


def do_event(event: str) -> None:
    platform, resync = EVENTS[event]
    out = post(platform, f"/sim/event/{event}")
    print(f"{event} applied on {platform}: {out.get('result', out)}")
    connectors = [c for c in factory.build_connectors() if c.platform in resync]
    for r in sync_engine.sync_now(connectors):
        print(f"  resync {r.platform}: {r.synced} updated, "
              f"{r.deleted} deleted{', ERRORS: ' + str(r.errors[:2]) if r.errors else ''}")


def do_clock(hhmm: str) -> None:
    # today at hhmm local, as an epoch the sims treat as their demo clock
    import datetime
    h, m = map(int, hhmm.split(":"))
    today = datetime.datetime.now().replace(hour=h, minute=m, second=0,
                                            microsecond=0)
    body = {"ts": today.timestamp()}
    for platform in factory.SIM_PORTS:
        out = post(platform, "/sim/clock", body)
        print(f"clock on {platform}: {out.get('clock')}")


def do_reset() -> None:
    for platform in factory.SIM_PORTS:
        out = post(platform, "/sim/reset")
        print(f"reset {platform}: ok={out.get('ok')}")
    connectors = [c for c in factory.build_connectors()
                  if c.platform in factory.SIM_PORTS]
    for r in sync_engine.sync_now(connectors):
        print(f"  resync {r.platform}: {r.synced} updated, {r.deleted} deleted")


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        raise SystemExit(2)
    cmd = sys.argv[1]
    if cmd == "clock":
        if len(sys.argv) < 3:
            raise SystemExit("usage: demo_story.py clock HH:MM")
        do_clock(sys.argv[2])
    elif cmd == "reset":
        do_reset()
    elif cmd in ALIASES:
        do_event(ALIASES[cmd])
    elif cmd in EVENTS:
        do_event(cmd)
    else:
        print(f"unknown command: {cmd}")
        print(__doc__)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
