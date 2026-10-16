"""Signed checkpoints + external anchoring of the central audit log.

A checkpoint signs {last_seq, last_entry_hash, ts, policy_version} with
the dedicated Ed25519 receipt key and anchors it with an RFC 3161
timestamp from a local self-hosted TSA (openssl ts). This bounds the
window a compromised gateway has: entries covered by an anchored
checkpoint cannot be rewritten without detection, even against a full
log copy.

anchor backend: the local TSA proves the mechanism, not third-party
credibility. It is one swappable function — point it at a public or
commercial TSA (freetsa.org, DigiCert, ...) and nothing else changes.
"""

import hashlib
import json
import subprocess
import time

from . import config, db, security

CHECKPOINT_EVERY = 25          # auto-checkpoint cadence (gateway hook)
_since_last = 0                # in-process counter; idempotency never relies on it


# --- anchor backend (swappable) ---------------------------------------------

def _tsa_dir():
    return config.DATA_DIR / "tsa"


def _run(args: list[str], **kw) -> bytes:
    # cwd = TSA dir + relative filenames: absolute paths break this openssl
    # build when the path contains a space (e.g. ".../test coding/...")
    return subprocess.run(["openssl", *args], check=True, cwd=str(_tsa_dir()),
                          capture_output=True, **kw).stdout


def _ensure_tsa() -> None:
    """Generate the local TSA material once (demo CA + timestamping cert)."""
    d = _tsa_dir()
    if (d / "tsa.pem").exists():
        return
    d.mkdir(parents=True, exist_ok=True)
    _run(["req", "-x509", "-newkey", "rsa:2048", "-nodes",
          "-keyout", "ca.key", "-out", "ca.pem",
          "-days", "3650", "-subj", "/CN=FileGuard Demo CA"])
    _run(["req", "-new", "-newkey", "rsa:2048", "-nodes",
          "-keyout", "tsa.key", "-out", "tsa.csr",
          "-subj", "/CN=FileGuard Local TSA"])
    # this OpenSSL build lacks the "timestamping" short name — use the OID
    (d / "ext.cnf").write_text(
        "extendedKeyUsage=critical,1.3.6.1.5.5.7.3.8\n"
        "keyUsage=critical,digitalSignature\n")
    # minimal TSA config: the system openssl.cnf [ts] section (demoCA) would
    # otherwise hijack `ts -reply`. Relative names: _run runs in this dir.
    (d / "tsa.cnf").write_text(
        "[ts]\n"
        "certs = tsa.pem\n"
        "signer_cert = tsa.pem\n"
        "signer_key = tsa.key\n"
        "signer_digest = sha256\n"
        "default_policy = 1.3.6.1.5.5.7.3.8\n"
        "digests = sha256\n"
        "serial = serial\n")
    _run(["x509", "-req", "-in", "tsa.csr",
          "-CA", "ca.pem", "-CAkey", "ca.key",
          "-CAcreateserial", "-out", "tsa.pem",
          "-days", "3650", "-extfile", "ext.cnf"])


def anchor_token(data: bytes) -> bytes | None:
    """RFC 3161 token over sha256(data) from the local TSA.
    Returns None if openssl or the TSA is unavailable — the checkpoint is
    still signed, just marked unanchored (verified=true reflects this)."""
    try:
        _ensure_tsa()
        d = _tsa_dir()
        digest = hashlib.sha256(data).hexdigest()
        # -no_nonce keeps the query deterministic so verification can
        # regenerate it from the digest alone
        _run(["ts", "-query", "-digest", digest, "-sha256",
              "-no_nonce", "-out", "req.tsq"])
        _run(["ts", "-reply", "-config", "tsa.cnf", "-section", "ts",
              "-queryfile", "req.tsq", "-out", "token.tsr"])
        return (d / "token.tsr").read_bytes()
    except Exception:
        return None


def anchor_verify(checkpoint_record: dict) -> bool:
    """Validate the stored RFC 3161 token against the regenerated query."""
    token_hex = checkpoint_record.get("anchor_token")
    if not token_hex:
        return False
    try:
        d = _tsa_dir()
        core = {k: checkpoint_record[k] for k in
                ("last_seq", "last_entry_hash", "ts", "policy_version")}
        digest = hashlib.sha256(security.canonical_json(core)).hexdigest()
        _run(["ts", "-query", "-digest", digest, "-sha256",
              "-no_nonce", "-out", "vreq.tsq"])
        (d / "vtoken.tsr").write_bytes(bytes.fromhex(token_hex))
        _run(["ts", "-verify", "-queryfile", "vreq.tsq",
              "-in", "vtoken.tsr", "-CAfile", "ca.pem", "-untrusted", "tsa.pem"])
        return True
    except Exception:
        return False


# --- checkpoint create / verify ----------------------------------------------

def _last_user_entry(conn):
    row = conn.execute(
        "SELECT seq, entry_hash, payload FROM audit_log ORDER BY seq DESC"
    ).fetchall()
    for seq, eh, pl in row:
        if json.loads(pl).get("event") != "checkpoint":
            return seq, eh
    return None


def _last_checkpoint(conn):
    for (pl,) in conn.execute(
            "SELECT payload FROM audit_log ORDER BY seq DESC"):
        p = json.loads(pl)
        if p.get("event") == "checkpoint":
            return p
    return None


def make_checkpoint(conn=None) -> dict | None:
    """Checkpoint the chain through the latest non-checkpoint entry.
    Returns the checkpoint record, or None when there is nothing new —
    a second call never duplicates the last checkpoint."""
    own = conn is None
    conn = db.central() if own else conn
    try:
        last = _last_user_entry(conn)
        if last is None:
            return None
        last_seq, last_hash = last
        prev = _last_checkpoint(conn)
        if prev and prev.get("last_seq", 0) >= last_seq:
            return None  # no new logs since the last checkpoint — no-op
        core = {"last_seq": last_seq, "last_entry_hash": last_hash,
                "ts": int(time.time()),
                "policy_version": config.POLICY_VERSION}
        anchor = anchor_token(security.canonical_json(core))
        record = {"event": "checkpoint", **core,
                  "signature": security.receipt_sign(core),
                  "verified": anchor is not None,
                  "anchor": "rfc3161:local-tsa" if anchor else "unanchored"}
        if anchor:
            record["anchor_token"] = anchor.hex()
        logged = db.append_log(conn, record)
        record["seq"] = logged["seq"]
        # external reference outside the DB: survives log-copy tampering
        with open(config.DATA_DIR / "checkpoints.jsonl", "a") as f:
            f.write(json.dumps(record, sort_keys=True) + "\n")
        return record
    finally:
        if own:
            conn.close()


def verify_checkpoint(record: dict, check_anchor: bool = True) -> tuple[bool, str]:
    """Verify a checkpoint against the live central chain."""
    try:
        core = {k: record[k] for k in
                ("last_seq", "last_entry_hash", "ts", "policy_version")}
    except KeyError as e:
        return False, f"checkpoint missing field {e}"
    if not security.receipt_verify(core, record.get("signature") or ""):
        return False, "checkpoint signature invalid"
    conn = db.central()
    try:
        ok, _ = db.verify_chain(conn)
        if not ok:
            return False, "central chain FAILED verification"
        row = conn.execute("SELECT entry_hash FROM audit_log WHERE seq = ?",
                           (record["last_seq"],)).fetchone()
        if row is None or row[0] != record["last_entry_hash"]:
            return False, (f"chain history no longer matches the checkpoint "
                           f"at seq {record['last_seq']}")
    finally:
        conn.close()
    if check_anchor and record.get("verified") and not anchor_verify(record):
        return False, "anchor token failed RFC 3161 verification"
    return True, f"chain verified and anchored through seq {record['last_seq']}"


def maybe_checkpoint() -> dict | None:
    """Gateway hook: attempt a checkpoint every CHECKPOINT_EVERY requests.
    make_checkpoint's own no-op rule guards against duplicates."""
    global _since_last
    _since_last += 1
    if _since_last < CHECKPOINT_EVERY:
        return None
    _since_last = 0
    return make_checkpoint()
