"""File Index Service — discovery. Pure SQL filtering, names + metadata only.

Access rule (AND-gated): base_clearance <= effective clearance AND the group
filter passes. Groups restrict; they never elevate above base clearance.

hidden_counts: files the user is *entitled* to (base <= user's max, group
filter passes) but withheld because the agent requested a lower ceiling —
counted per level, only for levels the user actually holds.
"""

import json
import sqlite3

from . import CLEARANCE_ORDER, CLEARANCE_NAME


def _group_filter_ok(file_groups: set[str], user_groups: set[str], desired_group: str) -> bool:
    if desired_group != "default":
        return desired_group in file_groups and desired_group in user_groups
    return not file_groups or bool(file_groups & user_groups)


def list_files(
    conn: sqlite3.Connection,
    user_id: str,
    user_max: str,
    user_groups: set[str],
    effective_clearance: str,
    desired_group: str,
) -> dict:
    user = conn.execute("SELECT groups FROM users WHERE user_id = ?", (user_id,)).fetchone()
    if user:
        user_groups = set(json.loads(user[0]))

    listed, hidden = [], {}
    for file_id, name, kind, base, groups_json, uploaded_by in conn.execute(
        "SELECT file_id, name, kind, base_clearance, groups, uploaded_by "
        "FROM files"
    ):
        file_groups = set(json.loads(groups_json))
        if not _group_filter_ok(file_groups, user_groups, desired_group):
            continue
        entry = {
            "file_id": file_id,
            "name": name,
            "kind": kind,
            "base_clearance": base,
            "groups": sorted(file_groups),
            "uploaded_by": uploaded_by,
        }
        if CLEARANCE_ORDER[base] <= CLEARANCE_ORDER[effective_clearance]:
            listed.append(entry)
        elif CLEARANCE_ORDER[base] <= CLEARANCE_ORDER[user_max]:
            # entitled but withheld by the requested ceiling — count it
            hidden[base] = hidden.get(base, 0) + 1

    # order hidden counts by level, ascending
    hidden_counts = {
        level: hidden[level]
        for level in sorted(hidden, key=lambda lv: CLEARANCE_ORDER[lv])
    }
    return {"files": listed, "hidden_counts": hidden_counts}
