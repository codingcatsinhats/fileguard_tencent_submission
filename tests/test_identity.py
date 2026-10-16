"""Identity, directory, permission epoch, and clearance overlay tests."""

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

from fileguard import identity, db, session_service, security, models, auth_checker, config  # noqa: E402


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


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Directory tests
# ---------------------------------------------------------------------------

def test_register_and_lookup_employee(conn):
    identity.register_employee(
        conn, "maya", "Maya Chen", "maya@halcyon.example",
        "confidential", ["eng", "payments"], _hash("tok-maya"),
    )
    emp = identity.lookup_employee(conn, "maya")
    assert emp is not None
    assert emp["name"] == "Maya Chen"
    assert emp["clearance"] == "confidential"
    assert "eng" in emp["groups"]
    assert emp["epoch"] == 1


def test_lookup_by_token(conn):
    identity.register_employee(
        conn, "raj", "Raj Patel", "raj@halcyon.example",
        "confidential", ["eng", "sre"], _hash("tok-raj"),
    )
    emp = identity.lookup_by_token(conn, _hash("tok-raj"))
    assert emp is not None
    assert emp["employee_id"] == "raj"


def test_lookup_nonexistent_employee(conn):
    assert identity.lookup_employee(conn, "nobody") is None


# ---------------------------------------------------------------------------
# Permission epoch tests
# ---------------------------------------------------------------------------

def test_global_epoch_starts_at_1(conn):
    assert identity.get_global_epoch(conn) == 1


def test_employee_epoch_starts_at_1(conn):
    identity.register_employee(
        conn, "maya", "Maya", "maya@x.example",
        "confidential", ["eng"], _hash("tok"),
    )
    assert identity.get_employee_epoch(conn, "maya") == 1


def test_bump_global_epoch(conn):
    new_epoch = identity.bump_epoch(conn)
    assert new_epoch == 2
    assert identity.get_global_epoch(conn) == 2


def test_bump_employee_epoch(conn):
    identity.register_employee(
        conn, "maya", "Maya", "maya@x.example",
        "confidential", ["eng"], _hash("tok"),
    )
    identity.bump_epoch(conn, employee_id="maya")
    assert identity.get_employee_epoch(conn, "maya") == 2
    # Global should also be bumped
    assert identity.get_global_epoch(conn) == 2


def test_check_epoch_valid(conn):
    identity.register_employee(
        conn, "maya", "Maya", "maya@x.example",
        "confidential", ["eng"], _hash("tok"),
    )
    # Epoch is 1, grant epoch is 1 → valid
    assert identity.check_epoch(conn, "maya", 1)


def test_check_epoch_stale_after_bump(conn):
    identity.register_employee(
        conn, "maya", "Maya", "maya@x.example",
        "confidential", ["eng"], _hash("tok"),
    )
    # Grant minted at epoch 1
    identity.bump_epoch(conn, employee_id="maya")
    # Now epoch is 2, grant epoch 1 is stale
    assert not identity.check_epoch(conn, "maya", 1)
    # Grant epoch 2 is valid
    assert identity.check_epoch(conn, "maya", 2)


def test_check_epoch_stale_after_global_bump(conn):
    identity.register_employee(
        conn, "maya", "Maya", "maya@x.example",
        "confidential", ["eng"], _hash("tok"),
    )
    # Global bump (e.g., a different user's permissions changed)
    identity.bump_epoch(conn)
    # Maya's grant is now stale even though her epoch didn't change
    assert not identity.check_epoch(conn, "maya", 1)


# ---------------------------------------------------------------------------
# Clearance overlay tests
# ---------------------------------------------------------------------------

def test_load_container_policies():
    policies = identity.load_container_policies()
    assert "confluence" in policies
    assert "PAY-DOCS" in policies["confluence"]
    assert policies["confluence"]["PAY-DOCS"].label == "confidential"
    assert policies["confluence"]["SEC"].label == "secret"
    assert "security" in policies["confluence"]["SEC"].groups


def test_overlay_check_passes():
    policy = identity.ContainerPolicy(label="confidential", groups=[])
    decision = identity.overlay_check("confidential", ["eng"], policy)
    assert decision.allowed


def test_overlay_check_fails_clearance():
    policy = identity.ContainerPolicy(label="secret", groups=[])
    decision = identity.overlay_check("confidential", ["eng"], policy)
    assert not decision.allowed
    assert "clearance" in decision.reason


def test_overlay_check_fails_group():
    policy = identity.ContainerPolicy(label="confidential", groups=["security"])
    decision = identity.overlay_check("top_secret", ["eng"], policy)
    assert not decision.allowed
    assert "security" in decision.reason


def test_overlay_check_higher_clearance_passes_group_req():
    # User has higher clearance but not the required group → denied
    policy = identity.ContainerPolicy(label="confidential", groups=["leads"])
    decision = identity.overlay_check("top_secret", ["eng"], policy)
    assert not decision.allowed


def test_overlay_check_no_groups_required():
    policy = identity.ContainerPolicy(label="open", groups=[])
    decision = identity.overlay_check("open", [], policy)
    assert decision.allowed


# ---------------------------------------------------------------------------
# Combined decision tests
# ---------------------------------------------------------------------------

def test_combined_decision_native_allowed_overlay_passes():
    policies = identity.load_container_policies()
    decision = identity.combined_decision(
        native_allowed=True,
        user_clearance="confidential",
        user_groups=["eng"],
        platform="confluence",
        container="PAY-DOCS",
        policies=policies,
    )
    assert decision.allowed


def test_combined_decision_native_denied():
    policies = identity.load_container_policies()
    decision = identity.combined_decision(
        native_allowed=False,
        user_clearance="top_secret",
        user_groups=["security"],
        platform="confluence",
        container="PAY-DOCS",
        policies=policies,
    )
    assert not decision.allowed
    assert "native" in decision.reason


def test_combined_decision_overlay_denies_clearance():
    policies = identity.load_container_policies()
    # Tom has "open" clearance, PAY-DOCS requires "confidential"
    decision = identity.combined_decision(
        native_allowed=True,
        user_clearance="open",
        user_groups=["contractors"],
        platform="confluence",
        container="PAY-DOCS",
        policies=policies,
    )
    assert not decision.allowed


def test_combined_decision_overlay_denies_group():
    policies = identity.load_container_policies()
    # SEC requires "security" group; maya is in "eng" but not "security"
    decision = identity.combined_decision(
        native_allowed=True,
        user_clearance="top_secret",
        user_groups=["eng"],
        platform="confluence",
        container="SEC",
        policies=policies,
    )
    assert not decision.allowed


# ---------------------------------------------------------------------------
# Grant + epoch integration tests
# ---------------------------------------------------------------------------

def test_grant_carries_epoch(conn):
    # Register a user in both users table and directory
    conn2 = db.central()
    conn2.execute(
        "INSERT OR REPLACE INTO users (user_id, name, max_clearance, groups, token_hash) "
        "VALUES (?,?,?,?,?)",
        ("maya", "Maya Chen", "confidential", json.dumps(["eng"]), _hash("tok-maya")),
    )
    conn2.commit()
    identity.register_employee(
        conn2, "maya", "Maya Chen", "maya@halcyon.example",
        "confidential", ["eng"], _hash("tok-maya"),
    )
    conn2.close()

    grant_str = session_service.issue_grant("tok-maya")
    assert grant_str is not None
    grant = security.verify_grant(grant_str)
    assert grant is not None
    assert "epoch" in grant
    assert grant["epoch"] == 1


def test_stale_grant_rejected_by_auth_checker(conn):
    # Register user
    conn2 = db.central()
    conn2.execute(
        "INSERT OR REPLACE INTO users (user_id, name, max_clearance, groups, token_hash) "
        "VALUES (?,?,?,?,?)",
        ("maya", "Maya Chen", "confidential", json.dumps(["eng"]), _hash("tok-maya")),
    )
    conn2.commit()
    identity.register_employee(
        conn2, "maya", "Maya Chen", "maya@halcyon.example",
        "confidential", ["eng"], _hash("tok-maya"),
    )
    conn2.close()

    # Issue grant (epoch 1)
    grant_str = session_service.issue_grant("tok-maya")
    assert grant_str is not None

    # Bump epoch (simulates permission change)
    conn3 = db.central()
    identity.bump_epoch(conn3, employee_id="maya")
    conn3.close()

    # Now the old grant should be rejected by auth_checker
    req = models.RequestObject(
        credentials=models.Credentials(grant=grant_str),
        payload=models.RequestPayload(
            tool="list_files",
            reason="test",
            desired_clearance="confidential",
        ),
    )
    verdict = auth_checker.validate(req)
    assert not verdict.ok
    assert verdict.code == "STALE_EPOCH"


def test_fresh_grant_passes_auth_checker(conn):
    # Register user
    conn2 = db.central()
    conn2.execute(
        "INSERT OR REPLACE INTO users (user_id, name, max_clearance, groups, token_hash) "
        "VALUES (?,?,?,?,?)",
        ("maya", "Maya Chen", "confidential", json.dumps(["eng"]), _hash("tok-maya")),
    )
    conn2.commit()
    identity.register_employee(
        conn2, "maya", "Maya Chen", "maya@halcyon.example",
        "confidential", ["eng"], _hash("tok-maya"),
    )
    conn2.close()

    # Issue grant (epoch 1)
    grant_str = session_service.issue_grant("tok-maya")

    # Bump epoch
    conn3 = db.central()
    identity.bump_epoch(conn3, employee_id="maya")
    conn3.close()

    # Issue fresh grant (epoch 2)
    grant_str_fresh = session_service.issue_grant("tok-maya")

    req = models.RequestObject(
        credentials=models.Credentials(grant=grant_str_fresh),
        payload=models.RequestPayload(
            tool="list_files",
            reason="test",
            desired_clearance="confidential",
        ),
    )
    verdict = auth_checker.validate(req)
    assert verdict.ok
