"""Demo decryption tool — locate an encrypted file by name (regex), decrypt it.

Usage (from the repo root or this folder):
    python3 dev_demo_files/decrypt.py <regex>        # exactly one match -> decrypt
    python3 dev_demo_files/decrypt.py <regex> --all  # decrypt every match

Output is written to this folder as the original filename (a duplicate is
suffixed with a counter). Dev/demo only — see README.md in this folder.
"""

import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from fileguard import db, store  # noqa: E402


def find_matches(pattern: str) -> list[tuple[str, str, str, str]]:
    """Return (file_id, name, kind, base_clearance) for name-regex matches."""
    rx = re.compile(pattern)
    conn = db.central()
    try:
        rows = conn.execute(
            "SELECT file_id, name, kind, base_clearance FROM files"
        ).fetchall()
    finally:
        conn.close()
    return [row for row in rows if rx.search(row[1])]


def decrypt_one(file_id: str, name: str) -> Path:
    plaintext = store.load_plaintext(file_id)
    out = HERE / name
    counter = 1
    while out.exists():
        out = HERE / f"{out.stem}_decrypted_{counter}{out.suffix}"
        counter += 1
    out.write_bytes(plaintext)
    return out


def main() -> None:
    args = [a for a in sys.argv[1:] if a != "--all"]
    if not args:
        print(__doc__)
        sys.exit(1)
    pattern = args[0]
    decrypt_all = "--all" in sys.argv

    matches = find_matches(pattern)
    if not matches:
        print(f"no encrypted files match /{pattern}/")
        sys.exit(1)

    if len(matches) > 1 and not decrypt_all:
        print(f"{len(matches)} files match /{pattern}/ — refine the pattern or pass --all:")
        for file_id, name, kind, clearance in matches:
            print(f"  {name:28} clearance={clearance:12} file_id={file_id[:12]}…")
        sys.exit(1)

    for file_id, name, kind, clearance in matches:
        out = decrypt_one(file_id, name)
        print(f"decrypted {name} (clearance={clearance}, file_id={file_id[:12]}…)")
        print(f"  -> {out.relative_to(HERE.parent)}")


if __name__ == "__main__":
    main()
