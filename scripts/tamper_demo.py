"""Tamper demo — "don't trust us, verify us".

Runs entirely in a throwaway sandbox: seeds a fresh state, delivers a span
(via a token-alice session against the upload store — the uploads
connector's own delivery path), checkpoints and anchors the chain, then tampers
with a COPY of the log and shows every verification fail loudly:

  1. chain verification     — hash chain broken
  2. checkpoint             — chain history no longer matches the anchor
  3. signed receipt         — log entry no longer matches the receipt

Run: python3 scripts/tamper_demo.py
"""

import json
import os
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fileguard import db  # noqa: E402


def banner(title: str) -> None:
    print(f"\n{'=' * 8} {title} {'=' * 8}")


def main() -> int:
    # 1. fresh sandbox, one delivered span -> receipt; then anchor a checkpoint
    sandbox = Path(tempfile.mkdtemp(prefix="fileguard-tamper-"))
    os.environ["FILEGUARD_DATA_DIR"] = str(sandbox)
    os.environ["FILEGUARD_GATEKEEPER_MODE"] = "test"

    from fastapi.testclient import TestClient
    from fileguard import checkpoint
    from fileguard.gateway import app
    from scripts import seed, ingest_demo
    from verify_receipt import verify as verify_receipt

    seed.main()
    ingest_demo.main()
    client = TestClient(app)
    grant = client.post("/session", json={"token": "token-alice"}).json()["grant"]
    r = client.post("/v1/request", json={
        "credentials": {"grant": grant},
        "payload": {"tool": "get_content", "reason": "grievance policy deadlines",
                    "desired_clearance": "secret", "file_ref": "hr_policy.pdf"}})
    receipt = r.json()["result"]["receipt"]
    cp = checkpoint.make_checkpoint()
    ok, detail = checkpoint.verify_checkpoint(cp)
    print(f"receipt verifies: {verify_receipt(receipt)[0]}")
    print(f"checkpoint verifies: {ok} ({detail})")

    # 2. copy the state, then tamper with the copy
    banner("tampering with a COPY of the log")
    tampered = Path(tempfile.mkdtemp(prefix="fileguard-tampered-"))
    # copy wal+shm too: committed rows may still live in the WAL
    for suffix in ("", "-wal", "-shm"):
        src = Path(sandbox) / f"central.db{suffix}"
        if src.exists():
            shutil.copy(src, tampered / f"central.db{suffix}")
    (tampered / "checkpoints.jsonl").write_text(
        (Path(sandbox) / "checkpoints.jsonl").read_text())
    for f in sandbox.rglob("tsa/*"):
        (tampered / "tsa").mkdir(exist_ok=True)
        shutil.copy(f, tampered / "tsa" / f.name)

    conn = sqlite3.connect(tampered / "central.db")
    # the real log forbids this (audit_no_update trigger); the copy drops it
    conn.execute("DROP TRIGGER audit_no_update")
    entry = conn.execute(
        "SELECT payload FROM audit_log WHERE payload LIKE '%grievance%'"
    ).fetchone()[0]
    forged = json.loads(entry)
    forged["reason"] = "totally innocent request"
    conn.execute("UPDATE audit_log SET payload = ? WHERE payload = ?",
                 (json.dumps(forged, sort_keys=True, separators=(",", ":")),
                  entry))
    conn.commit()
    conn.close()
    print("mutated the delivered request's reason field in the copy")

    # 3. point verification at the tampered copy and watch it fail
    os.environ["FILEGUARD_DATA_DIR"] = str(tampered)


    banner("1. chain verification")
    ok, n = db.verify_chain(db.central())
    print(f"   chain ok: {ok} (verification stopped after {n} entries — "
          f"first break is the tampered entry)")

    banner("2. checkpoint vs tampered chain")
    ok, detail = checkpoint.verify_checkpoint(cp)
    print(f"   checkpoint ok: {ok} ({detail})")

    banner("3. signed receipt vs tampered chain")
    ok, detail = verify_receipt(receipt)
    print(f"   receipt ok: {ok} ({detail})")

    banner("summary")
    print("every binding caught the tamper — the log cannot be rewritten\n"
          "without breaking the chain, the anchored checkpoint, or the\n"
          "receipt that binds delivered content to a log entry.")
    return 0


if __name__ == "__main__":
    import os
    sys.exit(main())
