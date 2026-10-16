"""Signing, hashing, and encryption primitives.

Hash chain, HMAC grant tokens, AES-256-GCM content encryption.
"""

import base64
import hashlib
import hmac
import json
import secrets
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import config

GENESIS = "0" * 64


def canonical_json(obj) -> bytes:
    """Deterministic serialization — the only form ever hashed or compared."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def entry_hash(prev_hash: str, payload: dict) -> str:
    return sha256_hex(prev_hash.encode() + canonical_json(payload))


# --- scoped grants (HMAC-signed, TTL) ---------------------------------------
# Manual HMAC-SHA256 over canonical JSON: signed, expiring, tamper-evident.
# Drop-in production swap: PyJWT / itsdangerous if SSO demands a standard.


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def sign_grant(grant: dict) -> str:
    body = _b64(canonical_json(grant))
    sig = _b64(hmac.new(config.SECRET_KEY, body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}"


def verify_grant(token: str) -> dict | None:
    """Return the grant dict if signature valid and unexpired, else None."""
    try:
        body, sig = token.split(".")
        expected = hmac.new(config.SECRET_KEY, body.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _unb64(sig)):
            return None
        grant = json.loads(_unb64(body))
        if grant.get("exp", 0) < int(time.time()):
            return None
        return grant
    except Exception:
        return None


def mint_nonce_ttl() -> int:
    return int(time.time()) + config.GRANT_TTL_SECONDS


def new_nonce() -> str:
    return secrets.token_hex(32)


# --- content store (AES-256-GCM) --------------------------------------------


def encrypt_bytes(plaintext: bytes) -> bytes:
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(config.STORE_KEY).encrypt(nonce, plaintext, None)


def decrypt_bytes(blob: bytes) -> bytes:
    return AESGCM(config.STORE_KEY).decrypt(blob[:12], blob[12:], None)


# --- signed delivery receipts (Ed25519 over canonical JSON) -----------------

_RECEIPT_PUB_KEY: Ed25519PublicKey | None = None


def _receipt_public_key() -> Ed25519PublicKey:
    """Derive and cache the Ed25519 public key from the configured seed.

    The private key seed is used ONCE to derive the public key; after that,
    verification never touches private key material.
    """
    global _RECEIPT_PUB_KEY
    if _RECEIPT_PUB_KEY is None:
        priv = Ed25519PrivateKey.from_private_bytes(config.RECEIPT_KEY)
        _RECEIPT_PUB_KEY = priv.public_key()
    return _RECEIPT_PUB_KEY


def receipt_sign(payload: dict) -> str:
    key = Ed25519PrivateKey.from_private_bytes(config.RECEIPT_KEY)
    return key.sign(canonical_json(payload)).hex()


def receipt_verify(payload: dict, signature: str) -> bool:
    """True iff `signature` is a valid receipt signature over `payload`.

    Uses the public key only — private key material is never accessed
    during verification.
    """
    try:
        _receipt_public_key().verify(bytes.fromhex(signature), canonical_json(payload))
        return True
    except Exception:
        return False
