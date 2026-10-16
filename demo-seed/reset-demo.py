"""Reset the development data directory to the curated demo state.

    python3 demo-seed/reset-demo.py

Wipes data/ (central.db, harness_local.db, encrypted store), copies in the
static seed assets from demo-seed/seed/ (users, tokens, file registry,
encrypted objects — all built once by build_seed.py), then generates the
demo audit history with timestamps relative to NOW (the last ~12 business
days) via seed_story.py. Finally self-verifies both hash chains and prints
a demo checklist. Idempotent — safe to re-run mid-demo.

NOTE: restart uvicorn after resetting; running sessions live in process.
"""

import os
import shutil
import sys
import time
from pathlib import Path

SEED_DIR = Path(__file__).resolve().parent
SEED_DATA = SEED_DIR / "seed"
REPO_ROOT = SEED_DIR.parent

_DATA_FILES = ("central.db", "central.db-wal", "central.db-shm",
               "harness_local.db", "harness_local.db-wal",
               "harness_local.db-shm",
               "index.db", "index.db-wal", "index.db-shm")

_STORY_DAYS = 12  # business days of curated history, ending today


def _populate_company_a_audit(conn_c, now_ts: int) -> int:
    """Append the Company A audit history (S7 jdoe pattern, planted
    violations, routine history) to the central chain.

    audit_seed_entries produces the payloads; the adapter adds the fields the
    live log and the audit console expect (session_id, platform/container for
    the platform filter, policy_version) and appends through db.append_log so
    the hash chain stays verifiable."""
    import sys
    sys.path.insert(0, str(REPO_ROOT))
    sys.path.insert(0, str(SEED_DIR / "company_a"))
    from fileguard import db
    from company_a.story import audit_seed_entries

    # confluence container by key prefix (all seeded audit items are pages)
    def container_for(key: str) -> str:
        if key.startswith("CF-PAYGW") or key.startswith("CF-ADR"):
            return "PAYGW"  # ADR-014 lives in the PAYGW space (storyline §3)
        if key.startswith("CF-SEC"):
            return "SEC"
        if key.startswith("CF-LEADS"):
            return "LEADS"
        return "PAY-DOCS"

    entries = audit_seed_entries(now_ts)
    entries.sort(key=lambda e: e["ts"])
    for e in entries:
        e = dict(e)
        ts = e.pop("ts")
        e.pop("allowed", None)  # story-internal flag, not part of log schema
        e.setdefault("session_id", None)
        e.setdefault("policy_version", "1")
        if e.get("file_ref", "").startswith("CF-"):
            e.setdefault("platform", "confluence")
            e.setdefault("container", container_for(e["file_ref"]))
            e.setdefault("item_id", e["file_ref"])
        db.append_log(conn_c, e, ts=int(ts))
    return len(entries)


def reset(data_dir: Path | None = None, now_ts: int | None = None) -> dict:
    """Reset to demo state. Returns a summary dict (also printed by main)."""
    data_dir = Path(data_dir) if data_dir else REPO_ROOT / "data"
    os.environ["FILEGUARD_DATA_DIR"] = str(data_dir)
    sys.path.insert(0, str(REPO_ROOT))

    from fileguard import db

    sys.path.insert(0, str(SEED_DIR))
    import seed_story

    now_ts = int(now_ts if now_ts is not None else time.time())

    # 1. wipe
    for name in _DATA_FILES:
        (data_dir / name).unlink(missing_ok=True)
    shutil.rmtree(data_dir / "store", ignore_errors=True)
    # simulator stores: reseeded by scripts/sim_server.py on next start
    shutil.rmtree(data_dir / "sim", ignore_errors=True)
    data_dir.mkdir(parents=True, exist_ok=True)

    # 2. copy static seed assets (registry, users, tokens, encrypted objects)
    shutil.copy2(SEED_DATA / "central.db", data_dir / "central.db")
    shutil.copytree(SEED_DATA / "store", data_dir / "store")

    # 3. generate the relative-time audit story
    conn_c = db.central()
    conn_l = db.local()
    try:
        n = seed_story.populate(conn_c, conn_l, now_ts - _STORY_DAYS * 86400)
        n_company_a = _populate_company_a_audit(conn_c, now_ts)
        ok_c, len_c = db.verify_chain(conn_c)
        ok_l, len_l = db.verify_chain(conn_l)
        n_files = conn_c.execute("SELECT COUNT(*) FROM files").fetchone()[0]
        n_users = conn_c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    finally:
        conn_c.close()
        conn_l.close()

    if not (ok_c and ok_l):
        raise SystemExit("FATAL: seeded audit chain failed verification")

    return {"entries": n, "central_len": len_c, "local_len": len_l,
            "files": n_files, "users": n_users, "chain_ok": ok_c and ok_l}


def main() -> None:
    summary = reset()
    print("Demo state reset.")
    print(f"  files registered : {summary['files']}")
    print(f"  users            : {summary['users']}")
    print(f"  audit entries    : {summary['central_len']} central, "
          f"{summary['local_len']} harness-local (story events: {summary['entries']})")
    print(f"  hash chains      : VERIFIED (both logs)")
    print()
    print("Chat tokens : token-alice (top_secret) · token-bob (confidential) ·")
    print("              token-carol (secret) · token-dave (open)")
    print("              Company A: token-maya (confidential, eng) ·")
    print("              token-lena (top_secret, security) · token-sam (secret, leads) ·")
    print("              token-raj (confidential, sre) · token-tom (open, contractor) ·")
    print("              token-jo (confidential, junior) · token-jdoe (confidential, payments)")
    print("Audit tokens: audit-priya (standard) · audit-lena (top secret) ·")
    print("              audit-token-standard · audit-token-topsecret")
    print()
    print("Discovery is reason-driven: the agent calls search with a reason")
    print("(RBAC-gated, audit-logged, references only), then get_content with")
    print("a specific reason. The gatekeeper selects relevant spans — the")
    print("agent never sees raw content. Need-to-know applied to AI retrieval.")
    print()
    print("Next: python3 scripts/sync_demo.py  (starts sims, syncs the index)")
    print("Demo question for maya: \"What was the root cause of the payment")
    print("outage last quarter, and what follow-up tickets were created?\"")
    print("Upload-store question for alice (closed-network corpus): \"what is the board of")
    print("director's average salary?\"")
    print()
    print("Restart uvicorn (ui.web) so in-process sessions pick up the new state.")


if __name__ == "__main__":
    main()
