"""Demo wiring: build the five connectors against the local simulators.

This module is DEMO GLUE, not fileguard logic — it only constructs the
existing, tested connector adapters and bridges chat users to Company A
platform identities.

  simulators run on localhost:8101-8104 (scripts/sim_server.py <platform>),
  seeded from demo-seed/company_a. Start them, then sync_all(build_connectors()).

DEMO_IDENTITY_BRIDGE: chat tokens (alice/bob/carol/dave) and Company A
platform identities (maya/raj/lena/...) are disjoint populations. The bridge
maps each chat user to a Company A employee with the same clearance ceiling
so the platform-native permission check has a real person to evaluate. The clearance/group overlay still runs
against the CHAT USER's real grant, and only ever narrows, so the bridge can
grant nothing the grant doesn't already allow. Production: join the identity
directory instead.
"""

from __future__ import annotations

from fileguard.connectors.confluence import ConfluenceConnector
from fileguard.connectors.drive import DriveConnector
from fileguard.connectors.jira import JiraConnector
from fileguard.connectors.slack import SlackConnector
from fileguard.connectors.uploads import UploadsConnector

# DEMO CREDENTIAL, hardcoded on purpose — this is a demo, not a mistake.
# Production: secret manager / per-connector service accounts.
ADMIN_TOKEN = "admin-connector-demo"

SIM_PORTS = {
    "confluence": 8101,
    "jira": 8102,
    "slack": 8103,
    "drive": 8104,
}

# chat user_id -> Company A employee_id (same clearance; see module docstring).
# Company A personas (maya/lena/sam, added to the seed) map to themselves:
# their clearance, groups AND platform identity are the real ones, so the
# native check and the overlay agree.
DEMO_IDENTITY_BRIDGE = {
    "alice": "lena",   # top_secret
    "bob": "maya",     # confidential
    "carol": "priya",  # secret
    "dave": "tom",     # open
    "maya": "maya",
    "lena": "lena",
    "sam": "sam",
    "raj": "raj",
    "tom": "tom",
    "jo": "jo",
    "jdoe": "jdoe",
}

PLATFORM_CLASSES = {
    "confluence": ConfluenceConnector,
    "jira": JiraConnector,
    "slack": SlackConnector,
    "drive": DriveConnector,
}


def _directory() -> dict[str, str]:
    """{employee_id: email} for identity resolution, from the Company A cast."""
    import sys
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent.parent
    for p in (str(root), str(root / "demo-seed")):
        if p not in sys.path:
            sys.path.insert(0, p)
    from company_a.story import PEOPLE
    return {p[0]: p[5] for p in PEOPLE}


def build_connectors() -> list:
    """One connector per platform, pointed at the local simulators
    (uploads reads the central DB directly and needs no network)."""
    directory = _directory()
    connectors = []
    for platform, cls in PLATFORM_CLASSES.items():
        connectors.append(cls(
            base_url=f"http://127.0.0.1:{SIM_PORTS[platform]}",
            admin_token=ADMIN_TOKEN,
            directory=directory,
        ))
    connectors.append(UploadsConnector(directory=directory))
    return connectors


def get_connector(platform: str):
    """The connector for one platform, or None for non-platform tools
    (uploads has no simulator — it reads the central DB directly and is
    its own connector)."""
    if platform not in PLATFORM_CLASSES:
        return None
    directory = _directory()
    cls = PLATFORM_CLASSES[platform]
    return cls(base_url=f"http://127.0.0.1:{SIM_PORTS[platform]}",
               admin_token=ADMIN_TOKEN, directory=directory)


def bridge_employee(user_id: str) -> str:
    """Chat user -> Company A employee id for the live platform check."""
    return DEMO_IDENTITY_BRIDGE.get(user_id, user_id)
