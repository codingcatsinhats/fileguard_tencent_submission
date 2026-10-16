"""Query pipeline — the get_content flow for the Internal Brain.

Pipeline stages:
1. Candidate assembly: resolve the item from the unified index.
2. Live access check: re-verify the user's permission on the item
   via the connector's can_access (authoritative) + identity overlay.
3. (Freshness gate — Phase 8, stubbed for now)
4. Gatekeeper selection: select relevant units from the item.
5. Extraction: extract verbatim span text (already in units — no
   re-fetch needed; the text is pinned at sync time).
6. Grounding check: run the graceful grounding ladder.
7. Answer generation: the answering model composes an answer with
   citations, then grounding verifies it.

The pipeline never calls an LLM in test mode — it uses the deterministic
stub implementations. Live-mode runs are optional smoke tests.
"""

from __future__ import annotations

import json
import sqlite3
import time
import logging
from dataclasses import dataclass, field
from typing import Any

from fileguard import config, security, db
from fileguard.connector import Unit, Item, ItemRef, Decision
from fileguard.grounding import GroundingResult, grounding_check, GENERIC_NO_EVIDENCE
from fileguard.stub_models import (
    UnitSpanRef,
    GatekeeperResult,
    AnswerResult,
    stub_select_spans,
    stub_generate_answer,
)

logger = logging.getLogger(__name__)


@dataclass
class PipelineRequest:
    """Inputs to the get_content pipeline."""
    user_id: str
    employee_id: str
    max_clearance: str
    groups: list[str]
    session_id: str
    reason: str
    platform: str
    item_id: str
    effective_clearance: str | None = None


@dataclass
class PipelineResult:
    """Output of the get_content pipeline."""
    ok: bool
    level: str = "verified"  # verified | pruned | excerpts_only | no_evidence
    answer_text: str = ""
    citations: list[UnitSpanRef] = field(default_factory=list)
    gatekeeper_reason: str = ""
    gatekeeper_mode: str = "stub-keyword"
    answer_mode: str = "stub-keyword"
    item_title: str = ""
    item_url: str = ""
    pruned_count: int = 0
    grounding_reason: str = ""
    error: str = ""
    content_hash: str = ""  # hash of the item version, for audit binding
    # Freshness stamps
    verified_current_at: float = 0.0  # when we confirmed the version was current
    last_synced_at: float = 0.0       # when the sync engine last fetched
    stale: bool = False               # True if source unreachable or version changed
    re_fetched: bool = False          # True if we re-fetched during the pipeline


def _load_item_units(conn: sqlite3.Connection, platform: str, item_id: str) -> tuple[dict, list[Unit]]:
    """Load an item and its units from the unified index.

    Returns (item_dict, units_list). Raises ValueError if not found.
    """
    item_row = conn.execute(
        "SELECT * FROM items WHERE platform = ? AND item_id = ? AND deleted = 0",
        (platform, item_id),
    ).fetchone()
    if item_row is None:
        raise ValueError(f"item not found: {platform}:{item_id}")

    item_dict = dict(item_row)
    item_key = f"{platform}:{item_id}"

    unit_rows = conn.execute(
        "SELECT * FROM units WHERE item_key = ? ORDER BY order_idx",
        (item_key,),
    ).fetchall()

    units = [
        Unit(
            unit_id=r["unit_id"],
            kind=r["kind"],
            text=r["text"],
            order=r["order_idx"],
            metadata=json.loads(r["metadata_json"]) if r["metadata_json"] else {},
        )
        for r in unit_rows
    ]

    return item_dict, units


def _compute_content_hash(item_dict: dict, units: list[Unit]) -> str:
    """Compute a content hash for the item (version + unit texts).

    This pins the item at the point of selection — if the item changes
    (new sync with different version), the hash won't match and the
    pipeline can detect the drift.
    """
    import hashlib
    parts = [item_dict.get("version", "")]
    for u in units:
        parts.append(u.text_sha256)
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def run_pipeline(
    req: PipelineRequest,
    conn: sqlite3.Connection,
    connector=None,
) -> PipelineResult:
    """Execute the get_content pipeline.

    Args:
        req: The pipeline request (user, reason, item reference).
        conn: A connection to the central DB (for directory/identity checks).
        connector: Optional platform connector for live access checks.
                   If None, uses the stored ACL + identity overlay only.

    Returns:
        PipelineResult with the grounded answer or a no-evidence response.
    """
    from fileguard.sync_engine import _connect as _index_connect
    from fileguard.identity import (
        load_container_policies,
        get_container_policy,
        overlay_check,
        combined_decision,
    )

    # 1. Candidate assembly: load the item from the unified index
    idx_conn = _index_connect()
    try:
        try:
            item_dict, units = _load_item_units(idx_conn, req.platform, req.item_id)
        except ValueError:
            # Item not found — return no-evidence (identical to "nothing may be seen")
            return PipelineResult(
                ok=True,
                level="no_evidence",
                answer_text=GENERIC_NO_EVIDENCE,
                grounding_reason="item not found in index",
            )

        container = item_dict.get("container", "")
        item_title = item_dict.get("title", "")
        item_url = item_dict.get("url", "")

        # Compute content hash for audit binding
        content_hash = _compute_content_hash(item_dict, units)

        # 2. Live access check
        # a. Connector native permission (if connector available)
        native_allowed = True
        if connector is not None:
            try:
                # Resolve identity
                platform_email = connector.resolve_identity(req.employee_id)
                item_ref = ItemRef(
                    platform=req.platform,
                    container=container,
                    item_id=req.item_id,
                    version=item_dict.get("version", ""),
                )
                decision = connector.can_access(platform_email, item_ref)
                native_allowed = decision.allowed
            except Exception as e:
                logger.warning(f"connector access check failed: {e}")
                native_allowed = False

        # b. Identity overlay (clearance + groups)
        try:
            policies = load_container_policies()
        except Exception:
            policies = {}

        # Overlay evaluated INDEPENDENTLY of the native check: when the
        # overlay would permit but the platform denies, that mismatch is a
        # drift signal (stale containers.yaml or platform misconfiguration)
        # — audited as a warning, never overriding the terminal native deny.
        # The reverse (platform-allow / overlay-deny) is the overlay
        # narrowing by design and is never flagged.
        overlay_only = overlay_check(
            user_clearance=req.effective_clearance or req.max_clearance,
            user_groups=req.groups,
            policy=get_container_policy(policies, req.platform, container),
        )
        overlay_decision = combined_decision(
            native_allowed=native_allowed,
            user_clearance=req.effective_clearance or req.max_clearance,
            user_groups=req.groups,
            platform=req.platform,
            container=container,
            policies=policies,
        )
        if not native_allowed and overlay_only.allowed:
            try:
                db.append_log(conn, {
                    "event": "policy_mismatch",
                    "warning": True,
                    "user_id": req.user_id,
                    "session_id": req.session_id,
                    "tool": "get_content",
                    "file_ref": f"{req.platform}:{req.item_id}",
                    "platform": req.platform,
                    "container": container,
                    "item_id": req.item_id,
                    "entry_clearance": get_container_policy(
                        policies, req.platform, container).label,
                    "detail": "overlay permits but native platform denies — "
                              "stale containers.yaml or platform "
                              "misconfiguration",
                    "policy_version": config.POLICY_VERSION,
                })
            except Exception as e:  # auditing must not break the deny path
                logger.warning(f"policy_mismatch audit failed: {e}")

        if not overlay_decision.allowed:
            # Access denied — return no-evidence (identical to "nothing exists")
            return PipelineResult(
                ok=True,
                level="no_evidence",
                answer_text=GENERIC_NO_EVIDENCE,
                content_hash=content_hash,
                grounding_reason=f"access denied: {overlay_decision.reason}",
            )

        # 3. Freshness gate: check if indexed version is current
        from fileguard.freshness import check_freshness

        freshness = check_freshness(
            idx_conn=idx_conn,
            connector=connector,
            platform=req.platform,
            item_id=req.item_id,
            indexed_version=item_dict.get("version", ""),
            container=container,
        )

        # If stale (re-fetch failed or source unreachable), serve the indexed
        # copy but mark it stale. If re-fetched, reload the item + units
        # to get the fresh content.
        if freshness.re_fetched:
            # Reload the re-fetched item + units from the index
            item_dict, units = _load_item_units(idx_conn, req.platform, req.item_id)
            # Recompute content hash for the new version
            content_hash = _compute_content_hash(item_dict, units)
            item_title = item_dict.get("title", "")
            item_url = item_dict.get("url", "")

        # 4. Gatekeeper selection — mode dispatch (Phase 7). "test" uses the
        # deterministic TF-IDF stub (CI, fully offline); "live" invokes the
        # real Gatekeeper LLM over the item's units (fail-closed: LLM
        # failures become no-evidence, never unfiltered content).
        if config.GATEKEEPER_MODE == "test":
            gk_result = stub_select_spans(
                units=units,
                reason=req.reason,
                platform=req.platform,
                container=container,
                item_id=req.item_id,
            )
        else:
            from . import gatekeeper
            try:
                unit_refs, gk_mode, gk_reason = gatekeeper.select_units(
                    units=units, reason=req.reason,
                    user_context={"max_clearance": req.max_clearance,
                                  "groups": req.groups},
                    platform=req.platform, container=container,
                    item_id=req.item_id,
                )
            except gatekeeper.GatekeeperError as e:
                return PipelineResult(
                    ok=False,
                    level="no_evidence",
                    answer_text=GENERIC_NO_EVIDENCE,
                    gatekeeper_reason=str(e)[:200],
                    gatekeeper_mode="live-llm",
                    item_title=item_title, item_url=item_url,
                    content_hash=content_hash,
                    grounding_reason="gatekeeper unavailable (fail-closed)",
                )
            gk_result = GatekeeperResult(
                spans=[UnitSpanRef(
                    platform=req.platform, container=container,
                    item_id=req.item_id, unit_id=units[i].unit_id,
                    kind=units[i].kind, text=units[i].text, order=units[i].order,
                ) for i in unit_refs],
                selection_reason=gk_reason, mode=gk_mode,
            )

        # If Gatekeeper selected nothing, return no-evidence
        if not gk_result.spans:
            return PipelineResult(
                ok=True,
                level="no_evidence",
                answer_text=GENERIC_NO_EVIDENCE,
                gatekeeper_reason=gk_result.selection_reason,
                gatekeeper_mode=gk_result.mode,
                item_title=item_title,
                item_url=item_url,
                content_hash=content_hash,
                grounding_reason="gatekeeper selected no spans",
            )

        # 5. Extraction: spans already have text (units are stored with text)
        # No re-fetch needed — the text is pinned at sync time and verified
        # by the content hash.

        # 6+7. Answer generation + grounding check.
        # DECISION 2026-10-15: the answering model is SCRAPPED — no live
        # third LLM. The deterministic stub draft (grounded/pruned below)
        # is what the UI's "stitched"/"excerpts" chips display; the agent
        # LLM writes the final reply around it.
        answer_result = stub_generate_answer(gk_result.spans, req.reason)

        # Run the grounding ladder
        grounding = grounding_check(answer_result, gk_result.spans)

        return PipelineResult(
            ok=True,
            level=grounding.level,
            answer_text=grounding.answer_text,
            citations=grounding.citations,
            gatekeeper_reason=gk_result.selection_reason,
            gatekeeper_mode=gk_result.mode,
            answer_mode=answer_result.mode,
            item_title=item_title,
            item_url=item_url,
            pruned_count=grounding.pruned_count,
            grounding_reason=grounding.reason,
            content_hash=content_hash,
            verified_current_at=freshness.verified_current_at,
            last_synced_at=freshness.last_synced_at,
            stale=freshness.stale,
            re_fetched=freshness.re_fetched,
        )

    finally:
        idx_conn.close()


def get_item_by_search_id(
    search_id: str,
    item_index: int = 0,
) -> tuple[str, str] | None:
    """Look up an item by search_id and result index.

    Returns (platform, item_id) or None if not found.
    """
    from fileguard.search import get_search_results
    results = get_search_results(search_id)
    if not results or item_index >= len(results):
        return None
    r = results[item_index]
    return r["platform"], r["item_id"]
