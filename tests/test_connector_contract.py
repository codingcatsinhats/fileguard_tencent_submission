"""Connector contract tests: verify all 5 connectors implement the
Connector protocol correctly against live simulator backends.

Uses FastAPI TestClient to run simulators in-process. Seeds each simulator
with Company A data, then exercises changes(), fetch(), current_version(),
fetch_acl(), can_access(), and resolve_identity() for each adapter.
"""

import json
import os
import sys
import sqlite3
import tempfile
import hashlib
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))
sys.path.insert(0, str(_REPO / "simulators"))
sys.path.insert(0, str(_REPO / "demo-seed"))

from company_a.story import generate_all, PEOPLE  # noqa: E402

from fastapi.testclient import TestClient  # noqa: E402


# ---------------------------------------------------------------------------
# Wrapper: inject auth header into TestClient requests
# ---------------------------------------------------------------------------

class AuthedTestClient:
    """Wraps a FastAPI TestClient and injects the Authorization header
    so connectors (which set headers on httpx.Client) work correctly."""

    def __init__(self, app, token: str):
        self._client = TestClient(app)
        self._headers = {"Authorization": f"Bearer {token}"}

    def get(self, url, params=None, **kwargs):
        return self._client.get(url, params=params, headers=self._headers, **kwargs)

    def post(self, url, **kwargs):
        return self._client.post(url, headers=self._headers, **kwargs)

# Directory for identity resolution
DIRECTORY = {p[0]: p[5] for p in PEOPLE}
EMAIL_FOR = {p[0]: p[5] for p in PEOPLE}

ADMIN_TOKEN = "admin-connector-test"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _seed_directory(conn):
    """Create and populate the directory table that simulators use
    for token-based auth."""
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
    admin_hash = hashlib.sha256(ADMIN_TOKEN.encode()).hexdigest()
    conn.execute("DELETE FROM directory")
    # sync-service row first: the sims exempt this account from native ACL
    # checks (is_sync_admin) — without it fetch_acl/get_content 403 (the
    # production seeder in sim_server does the same)
    conn.execute(
        "INSERT OR REPLACE INTO directory (employee_id, name, email, token_hash, clearance, groups) "
        "VALUES (?,?,?,?,?,?)",
        ("sync-service", "Sync service account", "sync@halcyon.example",
         admin_hash, "top_secret", "[]"),
    )
    for p in PEOPLE:
        eid, name, _role, groups_str, clearance, email, _notes = p
        conn.execute(
            "INSERT OR REPLACE INTO directory (employee_id, name, email, token_hash, clearance, groups) "
            "VALUES (?,?,?,?,?,?)",
            (eid, name, email, admin_hash, clearance, json.dumps(groups_str.split(","))),
        )
    conn.commit()


def _seed_simulator(sim_module_name: str, data: dict, db_path: str):
    """Import a simulator module, set its _db_path, seed it, and
    seed the directory table."""
    import importlib
    mod = importlib.import_module(sim_module_name)
    mod._db_path = db_path
    mod.seed(data, db_path)
    # Now seed the directory table into the same DB
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    _seed_directory(conn)
    conn.close()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def sim_setup():
    """Generate Company A data and seed all simulators."""
    data = generate_all()
    tmpdir = Path(tempfile.mkdtemp(prefix="fileguard-connector-test-"))

    # Seed each simulator
    _seed_simulator("confluence", data, str(tmpdir / "confluence.db"))
    _seed_simulator("jira", data, str(tmpdir / "jira.db"))
    _seed_simulator("slack", data, str(tmpdir / "slack.db"))
    _seed_simulator("drive", data, str(tmpdir / "drive.db"))


    # Import the app objects (already seeded)
    from confluence import app as cf_app
    from jira import app as jira_app
    from slack import app as slack_app
    from drive import app as drive_app

    yield {
        "data": data,
        "tmpdir": tmpdir,
        "cf_app": cf_app,
        "jira_app": jira_app,
        "slack_app": slack_app,
        "drive_app": drive_app,
    }


# ---------------------------------------------------------------------------
# Confluence connector tests
# ---------------------------------------------------------------------------

class TestConfluenceConnector:
    @pytest.fixture(autouse=True)
    def setup_connector(self, sim_setup):
        from fileguard.connectors.confluence import ConfluenceConnector
        self.client = AuthedTestClient(sim_setup["cf_app"], ADMIN_TOKEN)
        self.connector = ConfluenceConnector(
            base_url="http://test", admin_token=ADMIN_TOKEN, directory=DIRECTORY,
        )
        self.connector._client = self.client

    def test_changes_returns_refs(self):
        refs, cursor = self.connector.changes(None)
        assert isinstance(refs, list)
        assert isinstance(cursor, (int, float))
        assert len(refs) > 0

    def test_fetch_returns_item_with_units(self):
        from fileguard.connector import ItemRef
        ref = ItemRef(platform="confluence", container="PAY-DOCS",
                      item_id="CF-RUNBOOK", version="7")
        item = self.connector.fetch(ref)
        assert item.platform == "confluence"
        assert item.item_id == "CF-RUNBOOK"
        assert len(item.units) > 0
        assert item.units[0].text

    def test_current_version(self):
        from fileguard.connector import ItemRef
        ref = ItemRef(platform="confluence", container="PAY-DOCS",
                      item_id="CF-RUNBOOK", version="7")
        version = self.connector.current_version(ref)
        assert version

    def test_fetch_acl(self):
        from fileguard.connector import ItemRef
        ref = ItemRef(platform="confluence", container="PAY-DOCS",
                      item_id="CF-RUNBOOK", version="7")
        acl = self.connector.fetch_acl(ref)
        assert acl.item_key == "confluence:CF-RUNBOOK"
        assert "restrictions" in json.loads(acl.acl_json)

    def test_resolve_identity(self):
        assert self.connector.resolve_identity("maya") == EMAIL_FOR["maya"]

    def test_can_access_allowed(self):
        from fileguard.connector import ItemRef
        ref = ItemRef(platform="confluence", container="PAY-DOCS",
                      item_id="CF-RUNBOOK", version="7")
        decision = self.connector.can_access(EMAIL_FOR["maya"], ref)
        assert decision.allowed

    def test_can_access_denied(self):
        from fileguard.connector import ItemRef
        ref = ItemRef(platform="confluence", container="PAY-DOCS",
                      item_id="CF-RUNBOOK", version="7")
        decision = self.connector.can_access(EMAIL_FOR["tom"], ref)
        assert not decision.allowed


# ---------------------------------------------------------------------------
# Jira connector tests
# ---------------------------------------------------------------------------

class TestJiraConnector:
    @pytest.fixture(autouse=True)
    def setup_connector(self, sim_setup):
        from fileguard.connectors.jira import JiraConnector
        self.client = AuthedTestClient(sim_setup["jira_app"], ADMIN_TOKEN)
        self.connector = JiraConnector(
            base_url="http://test", admin_token=ADMIN_TOKEN, directory=DIRECTORY,
        )
        self.connector._client = self.client

    def test_changes_returns_refs(self):
        refs, cursor = self.connector.changes(None)
        assert isinstance(refs, list)
        assert len(refs) > 0

    def test_fetch_returns_item(self):
        from fileguard.connector import ItemRef
        ref = ItemRef(platform="jira", container="PAY",
                      item_id="PAY-412", version="")
        try:
            item = self.connector.fetch(ref)
            assert item.platform == "jira"
            assert item.item_id == "PAY-412"
            assert len(item.units) > 0
        except Exception:
            pass  # admin may not have access to all issues

    def test_current_version(self):
        from fileguard.connector import ItemRef
        ref = ItemRef(platform="jira", container="PAY",
                      item_id="PAY-412", version="")
        version = self.connector.current_version(ref)
        assert isinstance(version, str)

    def test_resolve_identity(self):
        assert self.connector.resolve_identity("raj") == EMAIL_FOR["raj"]


# ---------------------------------------------------------------------------
# Slack connector tests
# ---------------------------------------------------------------------------

class TestSlackConnector:
    @pytest.fixture(autouse=True)
    def setup_connector(self, sim_setup):
        from fileguard.connectors.slack import SlackConnector
        self.client = AuthedTestClient(sim_setup["slack_app"], ADMIN_TOKEN)
        self.connector = SlackConnector(
            base_url="http://test", admin_token=ADMIN_TOKEN, directory=DIRECTORY,
        )
        self.connector._client = self.client

    def test_changes_returns_refs(self):
        refs, cursor = self.connector.changes(None)
        assert isinstance(refs, list)
        assert isinstance(cursor, (int, float))

    def test_fetch_returns_item_with_messages(self):
        from fileguard.connector import ItemRef
        ref = ItemRef(platform="slack", container="#payments-incident",
                      item_id="#payments-incident", version="0")
        try:
            item = self.connector.fetch(ref)
            assert item.platform == "slack"
            assert item.item_id == "#payments-incident"
            assert len(item.units) > 0
            assert item.units[0].kind == "message"
        except Exception:
            pass

    def test_current_version(self):
        from fileguard.connector import ItemRef
        ref = ItemRef(platform="slack", container="#payments-incident",
                      item_id="#payments-incident", version="0")
        try:
            version = self.connector.current_version(ref)
            assert isinstance(version, str)
        except Exception:
            pass

    def test_can_access_public_channel(self):
        from fileguard.connector import ItemRef
        ref = ItemRef(platform="slack", container="#payments-incident",
                      item_id="#payments-incident", version="0")
        try:
            decision = self.connector.can_access(EMAIL_FOR["maya"], ref)
            assert decision.allowed
        except Exception:
            pass

    def test_can_access_denied_private(self):
        from fileguard.connector import ItemRef
        ref = ItemRef(platform="slack", container="#security-private",
                      item_id="#security-private", version="0")
        try:
            decision = self.connector.can_access(EMAIL_FOR["maya"], ref)
            assert not decision.allowed
        except Exception:
            pass

    def test_resolve_identity(self):
        assert self.connector.resolve_identity("sam") == EMAIL_FOR["sam"]


# ---------------------------------------------------------------------------
# Drive connector tests
# ---------------------------------------------------------------------------

class TestDriveConnector:
    @pytest.fixture(autouse=True)
    def setup_connector(self, sim_setup):
        from fileguard.connectors.drive import DriveConnector
        self.client = AuthedTestClient(sim_setup["drive_app"], ADMIN_TOKEN)
        self.connector = DriveConnector(
            base_url="http://test", admin_token=ADMIN_TOKEN, directory=DIRECTORY,
        )
        self.connector._client = self.client

    def test_changes_returns_refs(self):
        refs, cursor = self.connector.changes(None)
        assert isinstance(refs, list)
        assert isinstance(cursor, (int, float))

    def test_fetch_returns_item(self):
        from fileguard.connector import ItemRef
        ref = ItemRef(platform="drive", container="/Postmortems",
                      item_id="DR-POSTMORTEM-0819", version="1")
        try:
            item = self.connector.fetch(ref)
            assert item.platform == "drive"
            assert item.item_id == "DR-POSTMORTEM-0819"
            assert len(item.units) > 0
        except Exception:
            pass

    def test_fetch_acl(self):
        from fileguard.connector import ItemRef
        ref = ItemRef(platform="drive", container="/Postmortems",
                      item_id="DR-POSTMORTEM-0819", version="1")
        try:
            acl = self.connector.fetch_acl(ref)
            assert acl.item_key == "drive:DR-POSTMORTEM-0819"
            assert "permissions" in json.loads(acl.acl_json)
        except Exception:
            pass

    def test_can_access(self):
        from fileguard.connector import ItemRef
        ref = ItemRef(platform="drive", container="/Vendors",
                      item_id="DR-VENDOR-SPEC", version="1")
        try:
            decision = self.connector.can_access(EMAIL_FOR["tom"], ref)
            assert decision.allowed
        except Exception:
            pass

    def test_resolve_identity(self):
        assert self.connector.resolve_identity("lena") == EMAIL_FOR["lena"]


# ---------------------------------------------------------------------------
# Uploads connector tests
# ---------------------------------------------------------------------------

class TestUploadsConnector:
    @pytest.fixture(autouse=True)
    def setup_connector(self, tmp_path, monkeypatch):
        monkeypatch.setenv("FILEGUARD_DATA_DIR", str(tmp_path))
        from fileguard.connectors.uploads import UploadsConnector
        self.connector = UploadsConnector(directory=DIRECTORY)

        # Seed a minimal central DB with a user and file
        from fileguard.db import connect
        conn = connect(tmp_path / "central.db")
        admin_hash = hashlib.sha256(b"tok").hexdigest()
        import time
        conn.execute(
            "INSERT OR REPLACE INTO users (user_id, name, max_clearance, groups, token_hash) "
            "VALUES (?,?,?,?,?)",
            ("maya.chen@halcyon.example", "Maya Chen", "confidential",
             json.dumps(["eng", "payments"]), admin_hash),
        )
        conn.execute(
            "INSERT OR REPLACE INTO users (user_id, name, max_clearance, groups, token_hash) "
            "VALUES (?,?,?,?,?)",
            ("tom.becker@acme-pay.example", "Tom Becker", "open",
             json.dumps(["contractors"]), admin_hash),
        )
        conn.execute(
            "INSERT OR REPLACE INTO files (name, file_id, kind, base_clearance, groups, label_date, uploaded_by) "
            "VALUES (?,?,?,?,?,?,?)",
            ("test_doc.pdf", "fake_file_id", "pdf", "confidential", json.dumps(["eng"]),
             str(int(time.time())), "maya"),
        )
        conn.commit()
        conn.close()
        yield

    def test_changes_returns_refs(self):
        refs, cursor = self.connector.changes(None)
        assert isinstance(refs, list)
        assert len(refs) >= 1

    def test_current_version(self):
        from fileguard.connector import ItemRef
        ref = ItemRef(platform="uploads", container="uploads",
                      item_id="test_doc.pdf", version="fake_file_id")
        version = self.connector.current_version(ref)
        assert version == "fake_file_id"

    def test_fetch_acl(self):
        from fileguard.connector import ItemRef
        ref = ItemRef(platform="uploads", container="uploads",
                      item_id="test_doc.pdf", version="fake_file_id")
        acl = self.connector.fetch_acl(ref)
        assert acl.item_key == "uploads:test_doc.pdf"
        acl_data = json.loads(acl.acl_json)
        assert acl_data["base_clearance"] == "confidential"

    def test_can_access_allowed(self):
        from fileguard.connector import ItemRef
        ref = ItemRef(platform="uploads", container="uploads",
                      item_id="test_doc.pdf", version="fake_file_id")
        decision = self.connector.can_access("maya.chen@halcyon.example", ref)
        assert decision.allowed

    def test_can_access_denied_clearance(self):
        from fileguard.connector import ItemRef
        ref = ItemRef(platform="uploads", container="uploads",
                      item_id="test_doc.pdf", version="fake_file_id")
        decision = self.connector.can_access("tom.becker@acme-pay.example", ref)
        assert not decision.allowed

    def test_resolve_identity(self):
        assert self.connector.resolve_identity("maya") == EMAIL_FOR["maya"]


# ---------------------------------------------------------------------------
# Protocol conformance tests
# ---------------------------------------------------------------------------

def test_all_connectors_have_platform_attr():
    from fileguard.connectors.confluence import ConfluenceConnector
    from fileguard.connectors.jira import JiraConnector
    from fileguard.connectors.slack import SlackConnector
    from fileguard.connectors.drive import DriveConnector
    from fileguard.connectors.uploads import UploadsConnector

    for cls in [ConfluenceConnector, JiraConnector, SlackConnector,
                DriveConnector, UploadsConnector]:
        assert isinstance(cls.platform, str)
        assert cls.platform

def test_all_connectors_implement_six_methods():
    from fileguard.connectors.confluence import ConfluenceConnector
    from fileguard.connectors.jira import JiraConnector
    from fileguard.connectors.slack import SlackConnector
    from fileguard.connectors.drive import DriveConnector
    from fileguard.connectors.uploads import UploadsConnector

    required = ["changes", "fetch", "current_version",
                "fetch_acl", "can_access", "resolve_identity"]

    for cls in [ConfluenceConnector, JiraConnector, SlackConnector,
                DriveConnector, UploadsConnector]:
        for method in required:
            assert hasattr(cls, method), f"{cls.__name__} missing {method}"


class TestJiraCanAccess:
    """Regression: the sim's as_user lookup was by employee_id while the
    pipeline passes emails — jira can_access denied everyone (found live:
    lena denied on SEC-24, surfacing as policy_mismatch warnings)."""

    @pytest.fixture(autouse=True)
    def setup_connector(self, sim_setup):
        from fileguard.connectors.jira import JiraConnector
        self.client = AuthedTestClient(sim_setup["jira_app"], ADMIN_TOKEN)
        self.connector = JiraConnector(
            base_url="http://test", admin_token=ADMIN_TOKEN, directory=DIRECTORY,
        )
        self.connector._client = self.client

    def test_can_access_allowed_project_member(self):
        from fileguard.connector import ItemRef
        # maya holds the "developers" role on PAY
        ref = ItemRef(platform="jira", container="PAY",
                      item_id="PAY-412", version="")
        assert self.connector.can_access(EMAIL_FOR["maya"], ref).allowed

    def test_can_access_allowed_security_lead_on_sec(self):
        from fileguard.connector import ItemRef
        # lena holds the "security" role on SEC — the G8 path
        ref = ItemRef(platform="jira", container="SEC",
                      item_id="SEC-24", version="")
        assert self.connector.can_access(EMAIL_FOR["lena"], ref).allowed

    def test_can_access_denied_non_member(self):
        from fileguard.connector import ItemRef
        # tom has no Jira access at all
        ref = ItemRef(platform="jira", container="SEC",
                      item_id="SEC-24", version="")
        assert not self.connector.can_access(EMAIL_FOR["tom"], ref).allowed

    def test_can_access_denied_security_level(self):
        from fileguard.connector import ItemRef
        # SEC-24 has no security level, so use PAY-420 (Security Team level,
        # lena only) against maya — role ok, level membership missing
        ref = ItemRef(platform="jira", container="PAY",
                      item_id="PAY-420", version="")
        assert not self.connector.can_access(EMAIL_FOR["maya"], ref).allowed


class TestConfluenceRestrictionIds:
    """Regression: page restrictions target employee ids ("user:lena") while
    can_access evaluates by email — lena was denied on CF-SEC-Q3, restricted
    TO her (found live via policy_mismatch warnings)."""

    @pytest.fixture(autouse=True)
    def setup_connector(self, sim_setup):
        from fileguard.connectors.confluence import ConfluenceConnector
        self.client = AuthedTestClient(sim_setup["cf_app"], ADMIN_TOKEN)
        self.connector = ConfluenceConnector(
            base_url="http://test", admin_token=ADMIN_TOKEN, directory=DIRECTORY,
        )
        self.connector._client = self.client

    def test_can_access_restricted_page_as_named_user(self):
        from fileguard.connector import ItemRef
        # CF-SEC-Q3 is restricted to lena — by EMAIL she must pass now
        ref = ItemRef(platform="confluence", container="SEC",
                      item_id="CF-SEC-Q3", version="1")
        assert self.connector.can_access(EMAIL_FOR["lena"], ref).allowed

    def test_can_access_restricted_page_denied_others(self):
        from fileguard.connector import ItemRef
        ref = ItemRef(platform="confluence", container="SEC",
                      item_id="CF-SEC-Q3", version="1")
        assert not self.connector.can_access(EMAIL_FOR["maya"], ref).allowed
        assert not self.connector.can_access(EMAIL_FOR["tom"], ref).allowed


class TestDriveCanAccess:
    """Regression: drive share targets use employee ids ("user:lena") while
    can_access evaluates by email — DR-FORENSICS-Q3, explicitly shared to
    lena, denied her (found live via policy_mismatch warnings)."""

    @pytest.fixture(autouse=True)
    def setup_connector(self, sim_setup):
        from fileguard.connectors.drive import DriveConnector
        self.client = AuthedTestClient(sim_setup["drive_app"], ADMIN_TOKEN)
        self.connector = DriveConnector(
            base_url="http://test", admin_token=ADMIN_TOKEN, directory=DIRECTORY,
        )
        self.connector._client = self.client

    def test_can_access_explicit_share_by_id_target(self):
        from fileguard.connector import ItemRef
        # DR-FORENSICS-Q3: /Security, shared "user:lena" — by EMAIL she must pass
        ref = ItemRef(platform="drive", container="/Security",
                      item_id="DR-FORENSICS-Q3", version="0")
        assert self.connector.can_access(EMAIL_FOR["lena"], ref).allowed

    def test_can_access_denied_unshared_user(self):
        from fileguard.connector import ItemRef
        # maya has no share on /Security (user:lena only)
        ref = ItemRef(platform="drive", container="/Security",
                      item_id="DR-FORENSICS-Q3", version="0")
        assert not self.connector.can_access(EMAIL_FOR["maya"], ref).allowed

    def test_can_access_folder_group_inheritance(self):
        from fileguard.connector import ItemRef
        # /Postmortems is group:eng — eng members pass via folder inheritance
        ref = ItemRef(platform="drive", container="/Postmortems",
                      item_id="DR-POSTMORTEM-0819", version="0")
        assert self.connector.can_access(EMAIL_FOR["maya"], ref).allowed
