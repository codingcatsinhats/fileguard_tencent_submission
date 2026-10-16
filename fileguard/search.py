"""Unified search: FTS5 full-text search over the sync engine's index.

Search flow:
1. Parse the query (simple tokenisation + FTS5 MATCH).
2. FTS5 search on unit text → item keys → join to items table.
3. ACL pre-filter on indexed snapshots (cheap check).
4. Rank per connector, merge with reciprocal rank fusion.
5. Return top K candidates as references only (no body text/snippets).
6. Generate a server-side search_id for get_content.

No existence leak: forbidden and non-existent items produce identical
responses (empty results with the same shape).
"""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fileguard import config

logger = logging.getLogger(__name__)

CLEARANCE_ORDER = {"open": 0, "confidential": 1, "secret": 2, "top_secret": 3}

FTS_SCHEMA = """
CREATE VIRTUAL TABLE IF NOT EXISTS units_fts USING fts5(
    unit_id,
    item_key,
    text,
    content='units',
    content_rowid='rowid'
);
"""

# Trigger to keep FTS in sync with units table
FTS_TRIGGERS = """
CREATE TRIGGER IF NOT EXISTS units_ai AFTER INSERT ON units BEGIN
    INSERT INTO units_fts(unit_id, item_key, text)
    VALUES (new.unit_id, new.item_key, new.text);
END;
CREATE TRIGGER IF NOT EXISTS units_ad AFTER DELETE ON units BEGIN
    DELETE FROM units_fts WHERE unit_id = old.unit_id;
END;
CREATE TRIGGER IF NOT EXISTS units_au AFTER UPDATE ON units BEGIN
    DELETE FROM units_fts WHERE unit_id = old.unit_id;
    INSERT INTO units_fts(unit_id, item_key, text)
    VALUES (new.unit_id, new.item_key, new.text);
END;
"""

# Search metadata table (search_id → results)
SEARCH_META_SCHEMA = """
CREATE TABLE IF NOT EXISTS search_meta (
    search_id   TEXT PRIMARY KEY,
    query       TEXT NOT NULL,
    reason      TEXT NOT NULL,
    user_id     TEXT NOT NULL,
    created_at  REAL NOT NULL,
    results_json TEXT NOT NULL DEFAULT '[]'
);
"""


@dataclass
class SearchRef:
    """A search result reference — no body text or snippets."""
    platform: str
    container: str
    item_id: str
    title: str
    clearance_label: str
    modified_ts: float
    unit_count: int


@dataclass
class SearchResult:
    """Complete search response."""
    search_id: str
    results: list[SearchRef]
    hidden_counts: dict[str, int]
    total: int


def _db_path() -> Path:
    return config.DATA_DIR / "index.db"


def _connect() -> sqlite3.Connection:
    path = _db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    # Create FTS and search_meta tables
    conn.executescript(FTS_SCHEMA)
    conn.executescript(FTS_TRIGGERS)
    conn.executescript(SEARCH_META_SCHEMA)
    # Rebuild FTS to ensure it's in sync (cheap for demo-scale data)
    conn.execute("INSERT INTO units_fts(units_fts) VALUES('rebuild')")
    return conn


def _token_variants(token: str) -> list[str]:
    """FTS5 prefix variants for one query token. A prefix only widens
    rightward ("vulnerabilities"* can never match "vulnerability"), so
    crude inflection needs a truncated stem too: query the full token AND
    a stem (last two chars dropped when long enough), OR'd together.
    Covers plural/singular ("-ies"/"-y" aside — crude by design; the live
    Gatekeeper, not the retriever, owns semantics)."""
    t = token.replace('"', "")
    if not t:
        return []
    variants = [f'"{t}"*']
    if len(t) > 6:
        variants.append(f'"{t[:-3]}"*')
    elif len(t) > 3:
        variants.append(f'"{t[:-1]}"*')
    return variants


def _sanitize_fts_query(query: str) -> str:
    """Sanitize a query for FTS5 MATCH: per-token OR'd variant groups
    (full prefix + stem prefix), ANDed across tokens. The default
    tokenizer has no stemming — exact-token AND silently missed
    plural/singular variants (found live: "security vulnerabilities" could
    not reach "Dependency vulnerability scan findings")."""
    tokens = query.strip().split()
    if not tokens:
        return ""
    groups = ["(" + " OR ".join(_token_variants(t)) + ")" for t in tokens]
    return " AND ".join(groups)


def _fts_or_query(query: str) -> str:
    """OR-of-all-variants — the recall fallback for when the AND query
    starves (doc contains only SOME of the query's tokens). Ranked by
    bm25 so multi-token matches surface first."""
    tokens = query.strip().split()
    if not tokens:
        return ""
    variants: list[str] = []
    for t in tokens:
        variants.extend(_token_variants(t))
    return " OR ".join(variants)


# When the AND query yields fewer than this many items, supplement with the
# OR fallback (bm25-ranked). Recall-first; precision is bounded by the
# result cap, the ACL pre-filter and the abuse-guard volume cap.
_OR_FALLBACK_MIN_ITEMS = 5

# Query-side hygiene: natural-language filler words explode the OR fallback
# through prefix matching ("all"* matches "Allocations", "me"* matches
# "metrics"), drowning real matches and wasting the agent's retrieval
# budget (found live: "what are all security vulnerabilities" surfaced
# documents sharing only grammar with the question). Applied to the search
# tokens only — raw text still reaches the audit log and the Gatekeeper.
QUERY_STOPWORDS = {
    "what", "when", "where", "who", "whom", "which", "why", "how",
    "is", "are", "was", "were", "be", "been", "being", "do", "does",
    "did", "the", "a", "an", "and", "or", "of", "to", "in", "on",
    "for", "with", "about", "show", "tell", "give", "list", "find",
    "all", "any", "some", "me", "my", "our", "us", "please",
    "everything", "there", "that", "this", "these", "those", "from",
}
MIN_QUERY_TOKEN_LEN = 4


def _filter_tokens(query: str) -> list[str]:
    """Drop stopwords and very short tokens from a search query."""
    out = []
    for tok in query.strip().split():
        if len(tok.lower()) < MIN_QUERY_TOKEN_LEN or tok.lower() in QUERY_STOPWORDS:
            continue
        out.append(tok)
    return out


def _get_container_label(platform: str, container: str) -> str:
    """Get the clearance label for a container from containers.yaml."""
    try:
        from fileguard.identity import load_container_policies, get_container_policy
        policies = load_container_policies()
        policy = get_container_policy(policies, platform, container)
        return policy.label
    except Exception:
        return "confidential"


def _acl_prefilter(
    conn: sqlite3.Connection,
    item_rows: list[dict],
    user_clearance: str,
    user_groups: list[str],
) -> tuple[list[dict], list[dict]]:
    """Cheap ACL pre-filter on indexed ACL snapshots.

    Returns (visible_items, hidden_items). Visible items pass both
    native permission (approximated by ACL snapshot) and the clearance
    overlay. Hidden items pass natively but are withheld by the
    clearance ceiling.

    For the pre-filter, we use the stored acl_json and the container
    overlay policy. The authoritative live check happens in get_content.
    """
    try:
        from fileguard.identity import load_container_policies, get_container_policy, overlay_check
        policies = load_container_policies()
    except Exception:
        policies = {}

    visible = []
    hidden = []

    for row in item_rows:
        platform = row["platform"]
        container = row["container"]

        # Native check from the item's own ACL snapshot. The container
        # overlay alone under-filters per-file ACLs: uploads files carry
        # base_clearance + groups in acl_json (the files table is the
        # source of truth), and a top_secret/HR file in the `uploads`
        # container leaked its NAME to non-HR users at a confidential
        # ceiling (found live). A user failing the native check is skipped
        # entirely — not even hidden_counts, which are for natively-allowed
        # items withheld by the ceiling only.
        if platform == "uploads":
            try:
                acl = json.loads(row.get("acl_json") or "{}")
            except (TypeError, ValueError):
                acl = {}
            base = acl.get("base_clearance")
            if base and CLEARANCE_ORDER.get(user_clearance, 0) < CLEARANCE_ORDER.get(base, 3):
                continue
            acl_groups = set(acl.get("groups") or [])
            if acl_groups and not (acl_groups & set(user_groups)):
                continue

        # Clearance overlay check (container label + groups)
        if policies:
            policy = get_container_policy(policies, platform, container)
        else:
            from fileguard.identity import ContainerPolicy
            policy = ContainerPolicy(label="confidential", groups=[])

        # Check clearance
        if CLEARANCE_ORDER.get(user_clearance, 0) < CLEARANCE_ORDER.get(policy.label, 3):
            # User clearance too low — hidden (if natively they could see it)
            # For the pre-filter, we skip items the user can't access
            continue

        # Check groups
        if policy.groups:
            user_set = set(user_groups)
            if not (set(policy.groups) & user_set):
                continue

        # This item passes the pre-filter
        visible.append(row)

    return visible, hidden


def search(
    query: str,
    reason: str,
    user_id: str,
    user_clearance: str,
    user_groups: list[str],
    effective_clearance: str | None = None,
    limit: int = 30,
    desired_group: str = "default",
) -> SearchResult:
    """Search the unified index. Returns references only — no body text.

    Args:
        query: natural-language search query
        reason: access reason (required, audited)
        user_id: the user's identifier
        user_clearance: the user's max clearance level
        user_groups: the user's group memberships
        effective_clearance: the ceiling for this request (defaults to user_clearance)
        limit: max results to return (default 30, max 60)
        desired_group: group filter (default = all user's groups)
    """
    if not reason or not reason.strip():
        return SearchResult(search_id="", results=[], hidden_counts={}, total=0)

    # Clamp limit
    limit = min(max(limit, 1), 60)

    # Effective clearance ceiling
    ceiling = effective_clearance or user_clearance

    conn = _connect()
    try:
        query_tokens = _filter_tokens(query)
        fts_query = _sanitize_fts_query(" ".join(query_tokens))
        if not fts_query:
            return SearchResult(
                search_id=str(uuid.uuid4().hex),
                results=[],
                hidden_counts={},
                total=0,
            )

        # FTS5 search — get item keys, then join to items table.
        # Search both unit text and item titles. We do two FTS queries:
        # one on units_fts for body text, one on a title FTS for titles.
        fts_rows = conn.execute("""
            SELECT DISTINCT u.item_key, bm25(units_fts) as rank
            FROM units_fts
            JOIN units u ON units_fts.unit_id = u.unit_id
            WHERE units_fts MATCH ?
            ORDER BY rank
            LIMIT 100
        """, (fts_query,)).fetchall()

        # Recall fallback: when the AND query starves (fewer than
        # _OR_FALLBACK_MIN_ITEMS items), retry with OR-of-prefix-tokens so
        # documents containing only ONE of the query's terms still surface.
        and_keys = {r["item_key"] for r in fts_rows}
        if len(and_keys) < _OR_FALLBACK_MIN_ITEMS:
            or_query = _fts_or_query(" ".join(query_tokens))
            if or_query:
                extra = conn.execute("""
                    SELECT DISTINCT u.item_key, bm25(units_fts) as rank
                    FROM units_fts
                    JOIN units u ON units_fts.unit_id = u.unit_id
                    WHERE units_fts MATCH ?
                    ORDER BY rank
                    LIMIT 100
                """, (or_query,)).fetchall()
                seen = set(and_keys)
                for r in extra:
                    if r["item_key"] not in seen:
                        seen.add(r["item_key"])
                        fts_rows.append(r)

        # Also search item titles via LIKE (simpler than FTS for titles).
        # Any-token match: bodies often lack the exact query terms while the
        # title carries them ("Runbook: payment-service incident response").
        # References only — a title match leaks nothing beyond existence.
        raw_tokens = query_tokens
        token_clauses = " OR ".join("LOWER(title) LIKE LOWER(?)" for _ in raw_tokens)
        title_rows = conn.execute(f"""
            SELECT platform || ':' || item_id as item_key
            FROM items
            WHERE deleted = 0
              AND ({token_clauses})
            LIMIT 100
        """, [f"%{t}%" for t in raw_tokens]).fetchall()

        # Merge: combine item_keys from both, deduplicate
        all_keys = set()
        for r in fts_rows:
            all_keys.add(r["item_key"])
        for r in title_rows:
            all_keys.add(r["item_key"])

        if not all_keys:
            # No results — return empty (same shape as forbidden)
            search_id = str(uuid.uuid4().hex)
            _save_search_meta(conn, search_id, query, reason, user_id, [])
            return SearchResult(search_id=search_id, results=[], hidden_counts={}, total=0)

        # Get item details
        item_keys = list(all_keys)
        placeholders = ",".join("?" * len(item_keys))
        item_rows = conn.execute(f"""
            SELECT i.*, COUNT(u.unit_id) as unit_count
            FROM items i
            LEFT JOIN units u ON u.item_key = i.platform || ':' || i.item_id
            WHERE i.deleted = 0
              AND (i.platform || ':' || i.item_id) IN ({placeholders})
            GROUP BY i.platform, i.item_id
        """, item_keys).fetchall()

        # Convert to dicts for pre-filter
        item_dicts = [dict(r) for r in item_rows]

        # ACL pre-filter
        visible, hidden = _acl_prefilter(conn, item_dicts, user_clearance, user_groups)

        # Build references and hidden_counts
        refs = []
        hidden_counts: dict[str, int] = {}

        for item in visible:
            # Effective label: the stronger of the container overlay and
            # the item's own ACL rating (uploads files carry
            # base_clearance — a top_secret file in a confidential
            # container must show its true rating, not the container's)
            label = _get_container_label(item["platform"], item["container"])
            if item["platform"] == "uploads":
                try:
                    acl = json.loads(item.get("acl_json") or "{}")
                except (TypeError, ValueError):
                    acl = {}
                base = acl.get("base_clearance")
                if base and CLEARANCE_ORDER.get(base, 3) > CLEARANCE_ORDER.get(label, 3):
                    label = base
            # Check clearance ceiling
            if CLEARANCE_ORDER.get(label, 3) <= CLEARANCE_ORDER.get(ceiling, 0):
                refs.append(SearchRef(
                    platform=item["platform"],
                    container=item["container"],
                    item_id=item["item_id"],
                    title=item["title"],
                    clearance_label=label,
                    modified_ts=item["updated_at"],
                    unit_count=item["unit_count"],
                ))
            else:
                # Withheld by ceiling — count it
                hidden_counts[label] = hidden_counts.get(label, 0) + 1

        # Rank by match strength, not recency: full AND-matches first
        # (bm25 ascending — lower is better), then OR-fallback / title-only
        # matches, recency as the final tiebreaker. The agent's per-turn
        # retrieval budget is spent top-down, so filler with fresh
        # timestamps must not outrank real multi-token matches (found live:
        # 3-get budget burned on filler before the breach content).
        rank_by_key: dict[str, float] = {}
        for r in fts_rows:
            if r["item_key"] not in rank_by_key:
                rank_by_key[r["item_key"]] = r["rank"]  # AND rows come first

        def _relevance_key(ref):
            key = f"{ref.platform}:{ref.item_id}"
            is_and = key in and_keys
            return (0 if is_and else 1,
                    rank_by_key.get(key, float("inf")),
                    -ref.modified_ts)

        refs.sort(key=_relevance_key)
        refs = refs[:limit]

        # Generate search_id and save metadata
        search_id = str(uuid.uuid4().hex)
        results_json = json.dumps([{
            "platform": r.platform,
            "container": r.container,
            "item_id": r.item_id,
            "title": r.title,
            "clearance_label": r.clearance_label,
            "modified_ts": r.modified_ts,
            "unit_count": r.unit_count,
        } for r in refs])

        _save_search_meta(conn, search_id, query, reason, user_id, results_json)

        return SearchResult(
            search_id=search_id,
            results=refs,
            hidden_counts=hidden_counts,
            total=len(refs),
        )

    finally:
        conn.close()


def _save_search_meta(
    conn: sqlite3.Connection,
    search_id: str,
    query: str,
    reason: str,
    user_id: str,
    results_json: str | list,
):
    """Save search metadata for later retrieval by get_content."""
    if isinstance(results_json, list):
        results_json = json.dumps(results_json)
    conn.execute("""
        INSERT OR REPLACE INTO search_meta (search_id, query, reason, user_id, created_at, results_json)
        VALUES (?,?,?,?,?,?)
    """, (search_id, query, reason, user_id, time.time(), results_json))
    conn.commit()


def get_search_results(search_id: str) -> list[dict] | None:
    """Retrieve saved search results by search_id."""
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT results_json FROM search_meta WHERE search_id = ?",
            (search_id,),
        ).fetchone()
        if row is None:
            return None
        return json.loads(row["results_json"])
    finally:
        conn.close()


def lookup_item(platform: str, item_id: str) -> dict | None:
    """Look up a single item by platform + item_id.
    Returns None if not found or deleted.
    Used by get_content for direct-by-id lookups."""
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT * FROM items WHERE platform = ? AND item_id = ? AND deleted = 0",
            (platform, item_id),
        ).fetchone()
        if row is None:
            return None
        return dict(row)
    finally:
        conn.close()
