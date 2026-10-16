"""Unified search tests: FTS5 search, ACL pre-filter, references only,
no existence leak, search_id, result caps, access reason."""

import json
import os
import sys
import sqlite3
import time
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))
sys.path.insert(0, str(_REPO / "simulators"))
sys.path.insert(0, str(_REPO / "demo-seed"))

from fileguard import search, sync_engine, config  # noqa: E402
from fileguard.connector import Item, ItemRef, Unit, Connector, Decision, ACLSnapshot  # noqa: E402


# ---------------------------------------------------------------------------
# Mock connector with searchable items
# ---------------------------------------------------------------------------

class MockSearchConnector:
    platform = "mock"

    def __init__(self, items: list[Item]):
        self._items = {item.item_id: item for item in items}

    def changes(self, cursor):
        refs = [ItemRef(platform="mock", container=item.container,
                        item_id=item.item_id, version=item.version)
                for item in self._items.values()]
        return refs, time.time()

    def fetch(self, item_ref):
        return self._items[item_ref.item_id]

    def current_version(self, item_ref):
        return self._items[item_ref.item_id].version

    def fetch_acl(self, item_ref):
        item = self._items[item_ref.item_id]
        return ACLSnapshot(item_key=f"mock:{item_ref.item_id}",
                           version=item.version, acl_json="{}", fetched_at="")

    def can_access(self, person_email, item):
        return Decision(allowed=True)

    def resolve_identity(self, employee_id):
        return employee_id


def _make_item(item_id, version, title, text, container="PAY-DOCS",
               platform="confluence", updated_at=None, acl=None):
    ts = updated_at if updated_at is not None else float(int(time.time()))
    return Item(
        platform=platform, container=container, item_id=item_id,
        version=version, url=f"/items/{item_id}", title=title,
        author="test", created_at=ts,
        updated_at=ts,
        acl=acl or {},
        units=[Unit(unit_id=f"{platform}:{item_id}@{version}#0",
                    kind="section", text=text, order=0, metadata={})],
        links=[],
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def isolated_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("FILEGUARD_DATA_DIR", str(tmp_path))
    yield


@pytest.fixture
def seeded_index():
    """Seed the index with known items for search tests."""
    items = [
        _make_item("CF-RUNBOOK", "v7", "Runbook: payment incident response",
                   "Steps 1-5: check alerts, verify pool size, restart service"),
        _make_item("CF-POSTMORTEM", "v1", "Postmortem: payment outage",
                   "Root cause: connection pool cut from 200 to 20"),
        _make_item("CF-SEC-CHECKLIST", "v1", "Secure coding checklist",
                   "Input validation, output encoding, parameterised queries"),
        _make_item("CF-ADR-014", "v1", "ADR-014: auth token format",
                   "JWT with short TTL and key rotation every 30 days"),
        # recall fixtures: singular "vulnerability", only ONE of the
        # tokens a "failover breach" query would use
        _make_item("CF-SEC-VULN", "v1", "Dependency vulnerability scan findings",
                   "Dependency vulnerability scan found two issues in the auth flow"),
        # ranking fixtures: the AND-match is OLDER than the OR-only filler —
        # under recency ordering the filler outranked the real content
        _make_item("CF-SEC-REPORT", "v1", "Security vulnerability report",
                   "Security vulnerability report: critical findings in the login flow",
                   updated_at=time.time() - 86400),
        _make_item("FILLER-SEC-NEW", "v1", "Security audit checklist",
                   "Filler document: generated content, no key facts here."),
        # stopword-noise fixture: matches "all"* prefixes only ("Allocation")
        _make_item("CF-ALLOC-DOC", "v1", "Allocation overview",
                   "Allocation and installation overview for the platform"),
        # uploads leak regression: top_secret/HR file inside the
        # confidential `uploads` container — its acl_json rating must rule
        _make_item("hr_incident_report.docx", "abc123",
                   "hr_incident_report.docx",
                   "HR incident report investigating a security vulnerability "
                   "report from the finance team", container="uploads",
                   platform="uploads",
                   acl={"base_clearance": "top_secret", "groups": ["HR"]}),
    ]
    connector = MockSearchConnector(items)
    sync_engine.sync_connector(connector)
    return items


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_search_returns_results(seeded_index):
    result = search.search(
        query="payment outage",
        reason="investigating incident",
        user_id="maya",
        user_clearance="confidential",
        user_groups=["eng"],
    )
    assert result.total > 0
    assert result.search_id  # non-empty

def test_search_returns_references_only(seeded_index):
    result = search.search(
        query="payment",
        reason="test",
        user_id="maya",
        user_clearance="confidential",
        user_groups=["eng"],
    )
    assert result.total > 0
    ref = result.results[0]
    # References only: no body text or snippets
    assert hasattr(ref, "title")
    assert hasattr(ref, "platform")
    assert hasattr(ref, "item_id")
    assert hasattr(ref, "clearance_label")
    assert hasattr(ref, "modified_ts")
    assert hasattr(ref, "unit_count")
    # No text/snippet field
    assert not hasattr(ref, "text")
    assert not hasattr(ref, "snippet")
    assert not hasattr(ref, "body")

def test_search_requires_reason(seeded_index):
    result = search.search(
        query="payment",
        reason="",
        user_id="maya",
        user_clearance="confidential",
        user_groups=["eng"],
    )
    assert result.total == 0
    assert result.search_id == ""

def test_search_fts_matches(seeded_index):
    result = search.search(
        query="connection pool",
        reason="test",
        user_id="maya",
        user_clearance="confidential",
        user_groups=["eng"],
    )
    assert result.total > 0
    # Should match the postmortem about connection pool
    titles = [r.title for r in result.results]
    assert any("Postmortem" in t for t in titles)

def test_search_no_results_returns_empty(seeded_index):
    result = search.search(
        query="zzznonexistentzzz",
        reason="test",
        user_id="maya",
        user_clearance="confidential",
        user_groups=["eng"],
    )
    assert result.total == 0
    assert result.results == []
    # search_id should still be generated (same response shape as forbidden)
    assert result.search_id

def test_search_respects_clearance_ceiling(seeded_index):
    # User with open clearance searching for confidential items
    result = search.search(
        query="payment",
        reason="test",
        user_id="tom",
        user_clearance="open",
        user_groups=["contractors"],
        effective_clearance="open",
    )
    # PAY-DOCS is confidential, so tom shouldn't see any results
    # (either filtered by overlay or counted as hidden)
    visible = [r for r in result.results if r.clearance_label == "open"]
    assert len(visible) == 0

def test_search_search_id_persists_results(seeded_index):
    result = search.search(
        query="payment",
        reason="test",
        user_id="maya",
        user_clearance="confidential",
        user_groups=["eng"],
    )
    # Retrieve saved results
    saved = search.get_search_results(result.search_id)
    assert saved is not None
    assert len(saved) == result.total
    if saved:
        assert saved[0]["title"] == result.results[0].title

def test_search_result_limit(seeded_index):
    result = search.search(
        query="payment",
        reason="test",
        user_id="maya",
        user_clearance="confidential",
        user_groups=["eng"],
        limit=1,
    )
    assert result.total <= 1

def test_search_lookup_item(seeded_index):
    item = search.lookup_item("confluence", "CF-RUNBOOK")
    assert item is not None
    assert item["title"] == "Runbook: payment incident response"

def test_search_lookup_nonexistent_item(seeded_index):
    item = search.lookup_item("confluence", "NONEXISTENT")
    assert item is None

def test_no_existence_leak_forbidden_vs_nonexistent(seeded_index):
    """A forbidden item and a non-existent item must produce the same
    response shape. Both return empty results with a search_id."""
    # Search for something that exists but user can't access
    forbidden = search.search(
        query="payment outage",
        reason="test",
        user_id="tom",
        user_clearance="open",
        user_groups=["contractors"],
        effective_clearance="open",
    )
    # Search for something that doesn't exist
    nonexistent = search.search(
        query="zzznonexistentzzz",
        reason="test",
        user_id="tom",
        user_clearance="open",
        user_groups=["contractors"],
    )
    # Both should have the same shape: empty results, non-empty search_id
    assert forbidden.total == 0
    assert nonexistent.total == 0
    assert forbidden.results == nonexistent.results
    assert forbidden.search_id
    assert nonexistent.search_id
    assert forbidden.hidden_counts.keys() == nonexistent.hidden_counts.keys()

def test_search_hidden_counts(seeded_index):
    """hidden_counts should report items the user is entitled to
    (passes overlay) but withheld by the clearance ceiling."""
    result = search.search(
        query="payment",
        reason="test",
        user_id="maya",
        user_clearance="confidential",
        user_groups=["eng"],
        effective_clearance="open",  # lower ceiling → items hidden
    )
    # Maya has confidential clearance but requested open ceiling
    # PAY-DOCS is confidential → should be in hidden_counts
    assert "confidential" in result.hidden_counts
    assert result.hidden_counts["confidential"] > 0


# --- recall: prefix matching + OR fallback (found live in the demo) --------------


def test_prefix_matching_reaches_morphological_variants(seeded_index):
    # "vulnerabilities" (plural) must reach "vulnerability" (singular)
    result = search.search(
        query="security vulnerabilities",
        reason="security review",
        user_id="maya",
        user_clearance="confidential",
        user_groups=["eng"],
    )
    ids = {r.item_id for r in result.results}
    assert "CF-SEC-VULN" in ids, "prefix match failed to reach singular form"


def test_or_fallback_supplements_starved_and_query(seeded_index):
    # the doc body has only ONE of the two query tokens ("vulnerability"
    # yes, "failover" no) — the AND query starves, the OR fallback must
    # still surface it
    result = search.search(
        query="failover vulnerability",
        reason="incident review",
        user_id="maya",
        user_clearance="confidential",
        user_groups=["eng"],
    )
    ids = {r.item_id for r in result.results}
    assert "CF-SEC-VULN" in ids, "OR fallback failed to supplement starved AND"


# --- relevance ranking: match strength over recency (found live) -----------------


def test_and_match_ranks_above_newer_or_only_filler(seeded_index):
    result = search.search(
        query="security vulnerabilities",
        reason="security review",
        user_id="maya",
        user_clearance="confidential",
        user_groups=["eng"],
    )
    ids = [r.item_id for r in result.results]
    assert "CF-SEC-REPORT" in ids and "FILLER-SEC-NEW" in ids
    # the full AND-match (older) must rank above the newer OR-only filler
    assert ids.index("CF-SEC-REPORT") < ids.index("FILLER-SEC-NEW"), \
        f"recency still outranking relevance: {ids}"


def test_all_results_still_within_entitlement(seeded_index):
    # ranking must not change the security envelope: same set either order
    r1 = search.search(query="security vulnerabilities", reason="r1 review",
                       user_id="maya", user_clearance="confidential",
                       user_groups=["eng"])
    r2 = search.search(query="security vulnerabilities", reason="r2 review",
                       user_id="maya", user_clearance="confidential",
                       user_groups=["eng"])
    assert {x.item_id for x in r1.results} == {x.item_id for x in r2.results}


# --- query-side stopword filter (found live: "what are all ..." noise) ----------


def test_stopword_noise_filtered_from_fallback(seeded_index):
    # "all"* prefixes would match the Allocation doc under the unfiltered
    # fallback; with the stopword filter it must stay out
    result = search.search(
        query="what are all security vulnerabilities",
        reason="security review",
        user_id="maya",
        user_clearance="confidential",
        user_groups=["eng"],
    )
    ids = {r.item_id for r in result.results}
    assert "CF-ALLOC-DOC" not in ids, "stopword-prefix noise leaked into results"
    assert "CF-SEC-VULN" in ids, "real match lost by the filter"


def test_all_stopword_query_returns_empty(seeded_index):
    # a query with no distinctive terms has no honest results
    result = search.search(
        query="show me everything",
        reason="browsing",
        user_id="maya",
        user_clearance="confidential",
        user_groups=["eng"],
    )
    assert result.results == []
    assert result.total == 0


# --- uploads native ACL in search (name-leak regression) -------------------------


def test_uploads_acl_hidden_from_non_hr_user(seeded_index):
    # lena-like: top_secret clearance but NOT in HR — the file must be
    # invisible in every form (no reference, no hidden_counts entry)
    result = search.search(
        query="incident vulnerability report",
        reason="security review",
        user_id="maya", user_clearance="confidential", user_groups=["eng"],
    )
    ids = {r.item_id for r in result.results}
    assert "hr_incident_report.docx" not in ids
    assert sum(result.hidden_counts.values()) == 0, (
        "a natively-forbidden file must not even be counted as hidden")


def test_uploads_acl_visible_to_hr_at_full_clearance(seeded_index):
    result = search.search(
        query="incident vulnerability report",
        reason="HR investigation",
        user_id="alice", user_clearance="top_secret", user_groups=["HR"],
    )
    hit = next((r for r in result.results if r.item_id == "hr_incident_report.docx"), None)
    assert hit is not None, "HR-entitled user must see the file"
    assert hit.clearance_label == "top_secret", "label must be the file's true rating"


def test_uploads_acl_counts_hidden_at_low_ceiling(seeded_index):
    # mirrors the gateway: user_clearance = the user's MAX (top_secret,
    # passes the native check), effective_clearance = the requested
    # ceiling (confidential — withholds the file into hidden_counts)
    result = search.search(
        query="incident vulnerability report",
        reason="HR investigation",
        user_id="alice", user_clearance="top_secret", user_groups=["HR"],
        effective_clearance="confidential",
    )
    ids = {r.item_id for r in result.results}
    assert "hr_incident_report.docx" not in ids
    assert result.hidden_counts.get("top_secret", 0) >= 1
