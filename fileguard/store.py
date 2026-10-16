"""Content Store — encrypted, content-addressed file storage."""

from . import config, security


def save_plaintext(plaintext: bytes) -> str:
    """Encrypt and store; returns the content-addressed file id (sha256)."""
    file_id = security.sha256_hex(plaintext)
    config.STORE_DIR.mkdir(parents=True, exist_ok=True)
    path = config.STORE_DIR / f"{file_id}.bin"
    if not path.exists():  # content-addressed: identical bytes stored once
        path.write_bytes(security.encrypt_bytes(plaintext))
    return file_id


def load_plaintext(file_id: str) -> bytes:
    path = config.STORE_DIR / f"{file_id}.bin"
    if not path.exists():
        raise FileNotFoundError(f"no content stored for {file_id}")
    return security.decrypt_bytes(path.read_bytes())
