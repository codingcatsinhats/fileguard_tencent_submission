"""Verify a signed delivery receipt against the central audit log.

A receipt attests to what was DELIVERED (spans), not what the answer says.
Verification recomputes everything the receipt claims from the log itself:

  1. required fields present          (a receipt missing them can't bind)
  2. Ed25519 signature valid          (security.receipt_verify)
  3. central hash chain intact        (db.verify_chain)
  4. the bound log entry exists and matches every field the receipt claims
     (content_hash, span_hashes, policy_version, delivered_clearance,
      session_label, user_id, session_id)

Run: python3 scripts/verify_receipt.py '<receipt-json>'   # or a .json file
Exit 0 = verified, 1 = failed.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fileguard import db, security  # noqa: E402

REQUIRED = ("content_hash", "span_hashes", "policy_version",
            "delivered_clearance", "session_label", "log_entry_hash",
            "user_id", "session_id")


def verify(receipt: dict) -> tuple[bool, str]:
    payload = receipt.get("payload") or {}
    missing = [f for f in REQUIRED if payload.get(f) is None]
    if missing:
        return False, f"receipt is missing required fields: {missing}"
    if not security.receipt_verify(payload, receipt.get("signature") or ""):
        return False, "signature invalid"

    conn = db.central()
    try:
        ok, _ = db.verify_chain(conn)
        if not ok:
            return False, "central hash chain FAILED verification"
        row = conn.execute(
            "SELECT payload FROM audit_log WHERE entry_hash = ?",
            (payload["log_entry_hash"],)).fetchone()
        if row is None:
            return False, "bound log entry not found in the central chain"
        entry = json.loads(row[0])
    finally:
        conn.close()

    if entry.get("event") != "response":
        return False, "bound entry is not a response entry"
    mismatches = [f for f in REQUIRED
                  if f != "log_entry_hash" and entry.get(f) != payload[f]]
    if mismatches:
        return False, f"receipt does not match the log entry: {mismatches}"
    return True, f"verified against log seq {payload.get('log_seq')}"


def main() -> int:
    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    raw = Path(arg).read_text() if Path(arg).is_file() else arg
    receipt = json.loads(raw)
    ok, detail = verify(receipt)
    print(("VERIFIED: " if ok else "FAILED: ") + detail)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
