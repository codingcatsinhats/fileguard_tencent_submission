"""Company A seed generator tests: determinism, key facts, permissions."""

import os
import sys
import tempfile
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO / "demo-seed"))

from company_a.story import generate_all, verify_data, PEOPLE, CONFLUENCE_PAGES, JIRA_ISSUES, SLACK_CHANNELS, DRIVE_FILES  # noqa: E402


def test_generator_is_deterministic():
    data1 = generate_all()
    data2 = generate_all()
    assert data1 == data2


def test_all_people_present():
    data = generate_all()
    pids = {p[0] for p in data["people"]}
    assert pids == {"maya", "raj", "lena", "tom", "priya", "sam", "jo", "jdoe"}


def test_clearances():
    data = generate_all()
    clearance_map = {p[0]: p[4] for p in data["people"]}
    assert clearance_map["maya"] == "confidential"
    assert clearance_map["raj"] == "confidential"
    assert clearance_map["lena"] == "top_secret"
    assert clearance_map["tom"] == "open"
    assert clearance_map["priya"] == "secret"
    assert clearance_map["sam"] == "secret"
    assert clearance_map["jo"] == "confidential"
    assert clearance_map["jdoe"] == "confidential"


def test_confluence_pages():
    data = generate_all()
    keys = {p[0] for p in data["confluence_pages"]}
    assert "CF-RUNBOOK" in keys
    assert "CF-POSTMORTEM-0819" in keys
    assert "CF-POSTMORTEM-0311" in keys
    assert "CF-SECURE-CODING" in keys
    assert "CF-ADR-014" in keys
    assert "CF-PAYGW-ARCH" in keys
    assert "CF-PAYGW-API" in keys
    assert "CF-VENDOR-PRICING" in keys
    assert "CF-SEC-Q3" in keys
    assert "CF-LEADS-BUDGET" in keys


def test_cf_sec_q3_restricted_to_lena():
    data = generate_all()
    sec_q3 = next(p for p in data["confluence_pages"] if p[0] == "CF-SEC-Q3")
    assert sec_q3[6] == "user:lena"


def test_jira_issues():
    data = generate_all()
    keys = {i[0] for i in data["jira_issues"]}
    for expected in ["PAY-412", "PAY-413", "PAY-414", "PAY-390", "PAY-420",
                     "DBM-101", "DBM-107", "DBM-108", "DBM-110", "SEC-21", "SEC-24"]:
        assert expected in keys, f"Missing {expected}"


def test_pay420_security_level():
    data = generate_all()
    pay420 = next(i for i in data["jira_issues"] if i[0] == "PAY-420")
    assert pay420[4] == "Security Team"


def test_slack_channels():
    data = generate_all()
    names = {c[0] for c in data["slack_channels"]}
    for expected in ["#payments-incident", "#db-migration", "#db-migration-leads",
                     "#auth-design", "#sre-oncall-private", "#security-private",
                     "#vendor-integration", "DM-sam-raj"]:
        assert expected in names


def test_tom_only_in_vendor_integration_private():
    data = generate_all()
    tom_private = [c for c in data["slack_channels"]
                   if "tom" in c[2] and c[1] in ("private", "shared")]
    assert len(tom_private) == 1
    assert tom_private[0][0] == "#vendor-integration"


def test_drive_files():
    data = generate_all()
    keys = {f[0] for f in data["drive_files"]}
    for expected in ["DR-POSTMORTEM-0819", "DR-POSTMORTEM-0819-DRAFT",
                     "DR-FORENSICS-Q3", "DR-VENDOR-SPEC", "DR-BUDGET", "DR-ONBOARDING"]:
        assert expected in keys


def test_filler_count():
    data = generate_all()
    assert len(data["filler"]["confluence"]) == 40
    assert len(data["filler"]["jira"]) == 61
    assert len(data["filler"]["slack"]) == 20
    assert len(data["filler"]["drive"]) == 25


def test_filler_has_no_golden_strings():
    data = generate_all()
    golden = ["4.12.1", "connection pool from 200 to 20", "--force-failover",
              "74s", "JWT with short TTL", "credential-stuffing",
              "0.15% per transaction"]
    for item in data["filler"]["confluence"]:
        for sub in golden:
            assert sub.lower() not in item["text"].lower(), \
                f"Filler {item['key']} contains golden substring: {sub}"
    for item in data["filler"]["jira"]:
        for sub in golden:
            assert sub.lower() not in item["summary"].lower(), \
                f"Filler {item['key']} contains golden substring: {sub}"


def test_audit_seed_has_jdoe_paygw_7_accesses():
    data = generate_all()
    paygw_accesses = [e for e in data["audit_entries"]
                      if e.get("user_id") == "jdoe"
                      and e.get("file_ref") in ("CF-PAYGW-ARCH", "CF-ADR-014", "CF-PAYGW-API")
                      and e.get("event") == "request"
                      and e.get("allowed", False)]
    # Within 30 days
    now_ts = data["now_ts"]
    recent = [e for e in paygw_accesses if (now_ts - e["ts"]) <= 30 * 86400]
    assert len(recent) == 7, f"Expected 7 PAYGW accesses in 30d, got {len(recent)}"


def test_audit_seed_has_violations():
    data = generate_all()
    overclearance = [e for e in data["audit_entries"]
                     if e.get("code") == "OVERCLEARANCE"]
    assert len(overclearance) >= 1
    abuse = [e for e in data["audit_entries"]
             if e.get("code") == "ABUSE_RATE"]
    assert len(abuse) >= 1


def test_audit_seed_has_35_day_old_access():
    data = generate_all()
    now_ts = data["now_ts"]
    old = [e for e in data["audit_entries"]
           if e.get("user_id") == "jdoe"
           and e.get("file_ref") == "CF-PAYGW-ARCH"
           and e.get("event") == "request"
           and (now_ts - e["ts"]) > 30 * 86400]
    assert len(old) == 1, f"Expected 1 old access, got {len(old)}"


def test_verify_data_passes():
    data = generate_all()
    errors = verify_data(data)
    assert errors == [], f"Verification errors: {errors}"


def test_scenario_events_defined():
    from company_a.story import SCENARIO_EVENTS
    for event in ["runbook_v8", "remove_raj_from_sre_oncall",
                  "restrict_vendor_pricing", "remove_tom_share"]:
        assert event in SCENARIO_EVENTS


def test_jira_issues_have_descriptions():
    """No title-only content: every key issue and filler issue carries at
    least a short-paragraph description (get_content delivers nothing from
    summary-only items)."""
    data = generate_all()
    assert verify_data(data) == []
    for issue in data["jira_issues"]:
        desc = issue[7]
        assert isinstance(desc, str) and len(desc) >= 80, f"{issue[0]}: thin/missing description"
    for fi in data["filler"]["jira"]:
        desc = fi.get("fields", {}).get("description", "")
        assert len(desc) >= 40, f"{fi['key']}: thin/missing filler description"
    # the security fixtures G8 depends on are substantive
    sec24 = next(i for i in data["jira_issues"] if i[0] == "SEC-24")
    assert "deserialization" in sec24[7]
    sec21 = next(i for i in data["jira_issues"] if i[0] == "SEC-21")
    assert "3400" in sec21[7]


def test_audit_seed_entries_have_session_ids():
    """Every seeded audit entry carries a stable, realistic session id —
    request/response pairs of one access share it."""
    import re
    data = generate_all()
    assert verify_data(data) == []
    for e in data["audit_entries"]:
        sid = e.get("session_id")
        assert sid and re.fullmatch(r"[0-9a-f]{16}", sid), \
            f"{e.get('event')}/{e.get('file_ref')}: missing or fake session id"
    # request/response pairs of one access share the session
    resp = [e for e in data["audit_entries"] if e["event"] == "response"]
    reqs = {e["session_id"] for e in data["audit_entries"] if e["event"] == "request"}
    for r in resp:
        assert r["session_id"] in reqs
