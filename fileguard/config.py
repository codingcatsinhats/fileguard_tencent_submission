"""Environment-driven configuration. Dev defaults are for the hackathon only.

Paths and keys are properties evaluated at ACCESS time, so tests can
re-point FILEGUARD_DATA_DIR at import time (each test module gets a fresh
sandbox). The properties live on the module itself (module __class__ swap),
so `config.CENTRAL_DB` keeps working everywhere.
"""

import hashlib
import os
import sys
from pathlib import Path
from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parent.parent


class _Cfg(ModuleType):
    @property
    def DATA_DIR(self) -> Path:
        return Path(os.environ.get("FILEGUARD_DATA_DIR", REPO_ROOT / "data"))

    @property
    def CENTRAL_DB(self) -> Path:  # gateway-side: metadata + central audit log
        return self.DATA_DIR / "central.db"

    @property
    def LOCAL_DB(self) -> Path:  # harness-side: local audit log
        return self.DATA_DIR / "harness_local.db"

    @property
    def STORE_DIR(self) -> Path:  # encrypted, content-addressed files
        return self.DATA_DIR / "store"

    @property
    def SECRET_KEY(self) -> bytes:
        # HMAC secret for scoped grants. Production: KMS-managed, rotated.
        return os.environ.get("FILEGUARD_SECRET_KEY", "dev-only-secret-key").encode()

    @property
    def STORE_KEY(self) -> bytes:
        # AES-256 key for the content store (hex in env). Production: KMS/HSM.
        # Dev default is a fixed non-zero key so the store survives restarts.
        #
        # Production gaps (not implemented for hackathon demo):
        # - Key rotation (point 14): a migration script would re-encrypt every
        #   .bin in STORE_DIR with a new key, requiring key-versioning in the
        #   blob header and dual-key support during the migration window.
        #   Not worth it for a demo — key compromise doesn't happen in 10 min.
        # - Envelope encryption (point 15): per-file DEK wrapped by this master
        #   KEK would isolate per-file key leakage, but changes the blob format
        #   (nonce + wrapped_dek + ciphertext) and requires backward-compat.
        #   The current single-key design is sufficient for the demo threat
        #   model; STORE_KEY is already separate from SECRET_KEY and RECEIPT_KEY.
        return bytes.fromhex(os.environ.get("FILEGUARD_STORE_KEY", "1f2e3d4c5b6a7988" * 4))

    @property
    def RECEIPT_KEY(self) -> bytes:
        # Ed25519 seed for signed delivery receipts. Deliberately separate
        # from SECRET_KEY (session HMAC) and STORE_KEY (AES-GCM): one key
        # per job, so a leaked session secret cannot forge provenance.
        return hashlib.sha256(os.environ.get(
            "FILEGUARD_RECEIPT_KEY", "dev-only-receipt-key").encode()).digest()

    # Bumped when log/receipt semantics change; receipts pin the version
    # they were issued under.
    POLICY_VERSION = os.environ.get("FILEGUARD_POLICY_VERSION", "1")

    # 60 min, sliding: every chat refreshes it, so only idle sessions expire
    GRANT_TTL_SECONDS = int(os.environ.get("FILEGUARD_GRANT_TTL", "3600"))
    CONFIRM_NONCE_TTL = int(os.environ.get("FILEGUARD_NONCE_TTL", "300"))

    # Gatekeeper: "live" calls Claude; "test" uses an offline heuristic selector
    # (clearly labeled in responses; for development without API access).
    # Properties so tests can set the env var at runtime and have it take effect.
    @property
    def GATEKEEPER_MODE(self) -> str:
        return os.environ.get("FILEGUARD_GATEKEEPER_MODE", "live")

    @property
    def GATEKEEPER_MODEL(self) -> str:
        return os.environ.get("FILEGUARD_GATEKEEPER_MODEL", "claude-sonnet-5-5")


sys.modules[__name__].__class__ = _Cfg
