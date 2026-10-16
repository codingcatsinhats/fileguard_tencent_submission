"""LEGACY — demo-seed reset for the old-cast audit story (seed_story.py).

reset() now also seeds the Company A audit history (covered in
test_company_a_seed.py); this module checks the alice-cast story still
produces a valid, verifiable demo state.

Runs the real reset() into its own temp data dir, restoring the previous
FILEGUARD_DATA_DIR afterwards so other test modules are unaffected."""

import importlib.util
import json
import os
import sys
import tempfile
import time
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

_TMP = Path(tempfile.mkdtemp(prefix="fileguard-demoseed-"))
os.environ.setdefault("FILEGUARD_GATEKEEPER_MODE", "test")

import pytest  # noqa: E402

from fileguard import db, session_service  # noqa: E402


def _load(name: str):
    spec = importlib.util.spec_from_file_location(
        name, _REPO / "demo-seed" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module", autouse=True)
def reset_state():
    # capture at FIXTURE time (not import): every test module re-points
    # FILEGUARD_DATA_DIR at import, and the last one imported wins — restore
    # that exact value so later modules see the environment they set up.
    env_before = os.environ.get("FILEGUARD_DATA_DIR")
    reset_demo = _load("reset-demo")
    summary = reset_demo.reset(data_dir=_TMP, now_ts=int(time.time()))
    yield summary
    if env_before is None:
        os.environ.pop("FILEGUARD_DATA_DIR", None)
    else:
        os.environ["FILEGUARD_DATA_DIR"] = env_before


def test_reset_verifies_chains_and_counts(reset_state):
    assert reset_state["chain_ok"]
    assert reset_state["users"] == 11  # 4 legacy + 7 Company A personas
    assert reset_state["files"] == 6
    assert reset_state["central_len"] > 50


def test_seeded_chain_verifies_and_timestamps_are_backdated(reset_state):
    ok, n = db.verify_chain(db.central())
    assert ok and n == reset_state["central_len"]
    conn = db.central()
    oldest = conn.execute("SELECT MIN(ts) FROM audit_log").fetchone()[0]
    conn.close()
    assert oldest < int(time.time()) - 7 * 86400  # history spans over a week


def test_seeded_state_supports_login_and_registry():
    assert session_service.issue_grant("token-alice")
    assert session_service.issue_grant("token-bob")
    conn = db.central()
    row = conn.execute(
        "SELECT base_clearance, groups FROM files WHERE name = ?",
        ("board_compensation.xlsx",)).fetchone()
    conn.close()
    assert row == ("top_secret", '["finance"]')


def test_seed_story_contains_incidents():
    """The curated history must include the planted incidents: an
    over-clearance rejection and an abuse-guard block."""
    conn = db.central()
    kinds = {json.loads(p)["event"] for (p,) in
             conn.execute("SELECT payload FROM audit_log")}
    conn.close()
    assert "rejection" in kinds and "abuse_block" in kinds
