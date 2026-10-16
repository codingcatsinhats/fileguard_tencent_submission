"""Monthly reconciliation: harness-local log vs central audit log.

For every local `outgoing_request` entry there must be a matching central
`request` entry (same session, tool, file, reason — canonical-JSON compare,
timestamps within tolerance). Both chains must independently verify.

  equivalent -> local log is CLEARED by archiving the DB file (append-only
                tables are never deleted; a fresh file takes its place)
  mismatch   -> a reconciliation_flag entry is appended to the central log
                and the local log is PRESERVED for investigation

Run: python3 scripts/reconcile.py [--apply]
    without --apply: report only (dry run)
"""

import json
import shutil
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fileguard import db, security  # noqa: E402

TS_TOLERANCE_SECONDS = 120
MATCH_FIELDS = ("user_id", "session_id", "tool", "file_ref", "desired_clearance",
                "desired_group", "reason")


def _projection(payload: dict) -> dict | None:
    """Normalized form used for the equivalence compare. Handles both log
    shapes: local entries nest the request under 'payload', the central log
    stores the fields flat."""
    if payload.get("event") not in ("outgoing_request", "request"):
        return None
    if not payload.get("user_id"):
        return None  # not an access record (e.g. harness lifecycle entries)
    p = payload.get("payload") or {}

    def pick(key, default=None):
        return p.get(key, payload.get(key, default))

    return {
        "user_id": pick("user_id"),
        "session_id": pick("session_id"),
        "tool": pick("tool"),
        "file_ref": pick("file_ref"),
        "desired_clearance": pick("desired_clearance"),
        "desired_group": pick("desired_group", "default"),
        "reason": pick("reason"),
        # restricted fields (D7): commitments only — the plaintext lives in
        # the side table and never enters either chain. Entries predating
        # the scheme have plaintext under these keys on both sides or no
        # key at all, so the compare stays meaningful either way.
        "raw_user_input": pick("raw_user_input"),
        "search_terms": pick("search_terms"),
    }


def _load(conn, event: str) -> list[tuple[dict, int]]:
    out = []
    for (payload_json,) in conn.execute("SELECT payload FROM audit_log ORDER BY seq"):
        payload = json.loads(payload_json)
        if payload.get("event") == event:
            out.append((payload, payload.get("ts", 0)))
    return out


def _equivalent(a: dict, b: dict) -> bool:
    """Projection equality with restricted-field wildcarding (D7): entries
    predating the commitment scheme may carry plaintext on one side and
    nothing on the other. A restricted key absent (None) on EITHER side is
    dropped from the compare; when both sides have it, commitments must be
    identical (the plaintext never enters either chain)."""
    a2, b2 = dict(a), dict(b)
    for k in ("raw_user_input", "search_terms"):
        if a2.get(k) is None or b2.get(k) is None:
            a2.pop(k, None)
            b2.pop(k, None)
    return a2 == b2


def reconcile(apply: bool = False) -> dict:
    report = {"local_chain_ok": None, "central_chain_ok": None,
              "local_entries": 0, "matched": 0, "missing": [], "equivalent": None,
              "action": "none"}

    ok_c, _ = db.verify_chain(db.central())
    ok_l, _ = db.verify_chain(db.local())
    report["central_chain_ok"], report["local_chain_ok"] = ok_c, ok_l

    conn = db.local()
    local_rows = _load(conn, "outgoing_request")
    conn.close()
    central_conn = db.central()
    try:
        central_rows = _load(central_conn, "request")
        central_projs = [_projection(p) for p, _ in central_rows]

        for payload, ts in local_rows:
            proj = _projection(payload)
            if proj is None:
                continue
            report["local_entries"] += 1
            match = any(
                cp is not None
                and _equivalent(cp, proj) and abs(cts - ts) <= TS_TOLERANCE_SECONDS
                for cp, cts in zip(central_projs, [t for _, t in central_rows])
            )
            if match:
                report["matched"] += 1
            else:
                report["missing"].append(security.canonical_json(proj).decode())

        equivalent = (
            ok_c and ok_l
            and report["local_entries"] > 0
            and not report["missing"]
        )
        report["equivalent"] = equivalent

        if not apply:
            report["action"] = "dry-run (pass --apply to act)"
            return report

        if equivalent:
            stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            archive = _archive_path(stamp)
            shutil.move(str(db.config.LOCAL_DB), str(archive))
            db.local().close()  # fresh file takes the old one's place
            report["action"] = f"local log archived to {archive.name}; fresh log started"
        else:
            db.append_log(central_conn, {
                "event": "reconciliation_flag",
                "detail": "harness-local log failed equivalence check",
                "missing_count": len(report["missing"]),
                "samples": report["missing"][:5],
                "local_chain_ok": ok_l,
                "central_chain_ok": ok_c,
            })
            report["action"] = "FLAG raised; local log preserved for investigation"
        return report
    finally:
        central_conn.close()


def _archive_path(stamp: str) -> Path:
    return db.config.LOCAL_DB.parent / f"harness_local_archive_{stamp}.db"


if __name__ == "__main__":
    result = reconcile(apply="--apply" in sys.argv)
    print(json.dumps(result, indent=2, default=str))
