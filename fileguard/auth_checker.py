"""Auth Checker — backend verification of the full RequestObject.

Pure function: validate(credentials, payload, db) -> AuthVerdict.
Invalid -> the gateway logs the rejection (warning flag when the agent
attempted to overstep) and returns 403. Valid -> pipeline continues.
"""

import json
import sqlite3

from . import CLEARANCE_ORDER, db, models, security


def _user_for_grant(conn: sqlite3.Connection, grant: dict) -> tuple | None:
    return conn.execute(
        "SELECT user_id, max_clearance, groups FROM users WHERE user_id = ?",
        (grant["user_id"],),
    ).fetchone()


def _file_ref(conn: sqlite3.Connection, file_ref: str) -> tuple | None:
    """file_ref may be the content-addressed id or the display name."""
    row = conn.execute(
        "SELECT file_id, name, base_clearance, groups FROM files WHERE file_id = ?",
        (file_ref,),
    ).fetchone()
    if row is None:
        row = conn.execute(
            "SELECT file_id, name, base_clearance, groups FROM files WHERE name = ?",
            (file_ref,),
        ).fetchone()
    return row


PLATFORM_NAMES = ("confluence", "jira", "slack", "drive")


def _platform_ref(file_ref: str) -> tuple[str, str] | None:
    """'confluence:CF-RUNBOOK' -> ('confluence', 'CF-RUNBOOK'), else None.
    Upload file names can never contain ':' (sanitizer strips it)."""
    platform, sep, item_id = file_ref.partition(":")
    if sep and platform in PLATFORM_NAMES and item_id:
        return platform, item_id
    return None


def validate(req: models.RequestObject, conn: sqlite3.Connection | None = None) -> models.AuthVerdict:
    own = conn is None
    conn = conn or db.central()
    try:
        p = req.payload
        if p.tool == "get_content" and (p.file_ref or "").startswith("uploads:"):
            # uploads run the legacy files-table path; strip the search prefix
            p = p.model_copy(update={"file_ref": p.file_ref.split("uploads:", 1)[1]})

        # 1. grant: signature, expiry, live user
        grant = security.verify_grant(req.credentials.grant)
        if grant is None:
            return models.AuthVerdict(ok=False, code="NO_GRANT", detail="missing, expired, or tampered grant")
        user = _user_for_grant(conn, grant)
        if user is None:
            return models.AuthVerdict(ok=False, code="NO_GRANT", detail="unknown user")
        user_id, user_max, user_groups_json = user
        user_groups = set(json.loads(user_groups_json))

        # 1b. permission epoch: hard gate — stale epoch = reject
        grant_epoch = grant.get("epoch", 0)
        if grant_epoch > 0:
            from . import identity
            try:
                if not identity.check_epoch(conn, user_id, grant_epoch):
                    return models.AuthVerdict(
                        ok=False, code="STALE_EPOCH",
                        detail="permission epoch has changed — grant invalidated",
                    )
            except Exception:
                pass  # directory table may not exist yet (backward compat)

        # 2. clearance ceiling: requesting above the user's max is an overstep
        if CLEARANCE_ORDER[p.desired_clearance] > CLEARANCE_ORDER[user_max]:
            return models.AuthVerdict(
                ok=False, code="OVERCLEARANCE", warning=True,
                detail=f"requested {p.desired_clearance} above user max {user_max}",
            )

        # 3. group filter: an explicitly requested group must be the user's
        if p.desired_group != "default" and p.desired_group not in user_groups:
            return models.AuthVerdict(
                ok=False, code="INVALID_GROUP",
                detail=f"user not in requested group '{p.desired_group}'",
            )

        effective = p.desired_clearance
        if p.tool == "get_content":
            if not p.file_ref:
                return models.AuthVerdict(ok=False, code="NO_FILE", detail="get_content requires file_ref")
            platform_ref = _platform_ref(p.file_ref)
            if platform_ref is not None:
                # Unified-index item ("platform:item_id"): the files table
                # doesn't apply. Cheap existence check only — the pipeline's
                # live connector check + clearance overlay are authoritative,
                # and they deny identically to "not found" (no existence leak).
                from . import search
                if search.lookup_item(*platform_ref) is None:
                    return models.AuthVerdict(ok=False, code="NO_FILE", detail="unknown file")
                return models.AuthVerdict(ok=True, effective_clearance=effective)
            f = _file_ref(conn, p.file_ref)
            if f is None:
                return models.AuthVerdict(ok=False, code="NO_FILE", detail="unknown file")
            file_id, name, base, file_groups_json = f
            # AND-gating: clearance AND group must both pass. Group membership
            # restricts; it never elevates above the file's base clearance.
            if CLEARANCE_ORDER[base] > CLEARANCE_ORDER[user_max]:
                return models.AuthVerdict(
                    ok=False, code="OVERCLEARANCE", warning=True,
                    detail=f"file '{name}' rated {base}, above user max {user_max}",
                )
            file_groups = set(json.loads(file_groups_json))
            if file_groups and not (file_groups & user_groups):
                return models.AuthVerdict(
                    ok=False, code="NO_GROUP_ACCESS",
                    detail=f"file '{name}' requires one of {sorted(file_groups)}",
                )
            if p.desired_group != "default" and p.desired_group not in file_groups:
                return models.AuthVerdict(
                    ok=False, code="INVALID_GROUP",
                    detail=f"file '{name}' is not labeled '{p.desired_group}'",
                )

        return models.AuthVerdict(ok=True, effective_clearance=effective)
    finally:
        if own:
            conn.close()
