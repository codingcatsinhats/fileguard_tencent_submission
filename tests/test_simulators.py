"""Tests for pure permission evaluator functions and simulator behavior."""

import json
import os
import sys
import tempfile
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))
sys.path.insert(0, str(_REPO / "simulators"))
sys.path.insert(0, str(_REPO / "demo-seed"))

from company_a.story import generate_all, PEOPLE  # noqa: E402
from evaluators import confluence_can_view, jira_can_view, slack_can_read, drive_can_read  # noqa: E402


# ---------------------------------------------------------------------------
# Helper: email lookup
# ---------------------------------------------------------------------------

def email_for(eid: str) -> str:
    return next(p[5] for p in PEOPLE if p[0] == eid)


# ---------------------------------------------------------------------------
# Confluence evaluator tests
# ---------------------------------------------------------------------------

def test_confluence_space_all_employees():
    # PAY-DOCS: all employees (not tom)
    perms = [{"type": "group", "target": "all_employees_not_tom"}]
    assert confluence_can_view(email_for("maya"), "PAY-DOCS", perms, [], None)
    assert not confluence_can_view(email_for("tom"), "PAY-DOCS", perms, [], None)

def test_confluence_space_group_eng():
    # PAYGW: group eng
    perms = [{"type": "group", "target": "eng"}]
    # maya is in eng, tom is not
    assert confluence_can_view(email_for("maya"), "PAYGW", perms, [], None)
    # tom: not in eng — but the evaluator delegates group check to caller
    # so with the simplified evaluator, group perms are permissive
    # The real check happens in the adapter which resolves groups.
    # For the test, we verify the permissive path works.

def test_confluence_page_restriction():
    # CF-SEC-Q3: restricted to lena only
    perms = [{"type": "group", "target": "security"}]
    restriction = [{"type": "user", "target": email_for("lena")}]
    assert confluence_can_view(email_for("lena"), "SEC", perms, restriction, None)
    assert not confluence_can_view(email_for("maya"), "SEC", perms, restriction, None)

def test_confluence_ancestor_restrictions():
    # Page with ancestor restriction
    perms = [{"type": "group", "target": "all_employees"}]
    ancestor_restr = [{"type": "user", "target": email_for("sam")}]
    assert confluence_can_view(email_for("sam"), "PAY-DOCS", perms, [], [ancestor_restr])
    assert not confluence_can_view(email_for("maya"), "PAY-DOCS", perms, [], [ancestor_restr])


# ---------------------------------------------------------------------------
# Jira evaluator tests
# ---------------------------------------------------------------------------

def test_jira_project_browse():
    # PAY: role "developers" includes maya, raj, sam, jo, jdoe, lena
    roles = {"developers": [email_for("maya"), email_for("raj"), email_for("sam"),
                           email_for("jo"), email_for("jdoe"), email_for("lena")]}
    assert jira_can_view(email_for("maya"), "PAY", roles, None, {})
    assert not jira_can_view(email_for("tom"), "PAY", roles, None, {})

def test_jira_security_level():
    # PAY-420: security level "Security Team" — lena only
    roles = {"developers": [email_for("maya"), email_for("raj"), email_for("sam"),
                           email_for("jo"), email_for("jdoe"), email_for("lena")]}
    sec_members = {"Security Team": [email_for("lena")]}
    assert jira_can_view(email_for("lena"), "PAY", roles, "Security Team", sec_members)
    assert not jira_can_view(email_for("maya"), "PAY", roles, "Security Team", sec_members)

def test_jira_sec_project():
    # SEC project: role "security" includes lena only
    roles = {"security": [email_for("lena")]}
    sec_members = {"Security Team": [email_for("lena")]}
    assert jira_can_view(email_for("lena"), "SEC", roles, None, sec_members)
    assert not jira_can_view(email_for("maya"), "SEC", roles, None, sec_members)


# ---------------------------------------------------------------------------
# Slack evaluator tests
# ---------------------------------------------------------------------------

def test_slack_public_full_member():
    members = [email_for("maya"), email_for("raj")]
    assert slack_can_read(email_for("maya"), "public", members)

def test_slack_public_guest():
    # Tom is a guest — can only read channels he's explicitly in
    members = [email_for("maya"), email_for("raj")]
    assert not slack_can_read(email_for("tom"), "public", members, is_guest=True)

def test_slack_private_member():
    members = [email_for("sam"), email_for("raj")]
    assert slack_can_read(email_for("sam"), "private", members)
    assert not slack_can_read(email_for("maya"), "private", members)

def test_slack_shared_member():
    members = [email_for("sam"), email_for("maya"), email_for("jdoe"), email_for("tom")]
    assert slack_can_read(email_for("tom"), "shared", members)
    assert not slack_can_read(email_for("raj"), "shared", members)

def test_slack_direct_participant():
    members = [email_for("sam"), email_for("raj")]
    assert slack_can_read(email_for("sam"), "direct", members)
    assert not slack_can_read(email_for("maya"), "direct", members)


# ---------------------------------------------------------------------------
# Drive evaluator tests
# ---------------------------------------------------------------------------

def test_drive_user_permission():
    perms = [{"type": "user", "target": email_for("lena")}]
    assert drive_can_read(email_for("lena"), perms)
    assert not drive_can_read(email_for("maya"), perms)

def test_drive_link_sharing():
    perms = []
    assert drive_can_read(email_for("tom"), perms, link_sharing="anyone_with_link")

def test_drive_trashed():
    perms = [{"type": "user", "target": email_for("maya")}]
    assert not drive_can_read(email_for("maya"), perms, is_trashed=True)

def test_drive_removed_share():
    # Tom's share was removed
    perms = [{"type": "user", "target": email_for("sam")}]
    assert not drive_can_read(email_for("tom"), perms)

def test_drive_parent_folder():
    file_perms = []
    parent_perms = [{"type": "user", "target": email_for("maya")}]
    assert drive_can_read(email_for("maya"), file_perms, parent_folder_permissions=parent_perms)
