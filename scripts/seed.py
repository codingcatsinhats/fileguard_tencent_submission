"""Seed sample users + audit-console tokens. Tokens are dev-only, stored hashed.

Seeds BOTH casts: the Company A personas (primary demo) and the
closed-network-corpus cast (alice/bob/carol/dave — upload-store demo;
bridged to Company A identities in fileguard/connectors/factory.py). Audit tokens: generic
audit-token-standard/topsecret plus the D10 persona tokens
audit-priya / audit-lena.
"""

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fileguard import db  # noqa: E402

USERS = [
    # user_id, name, position, max_clearance, groups, token
    ("alice", "Alice", "HR Lead", "top_secret", ["HR", "finance"], "token-alice"),
    ("bob", "Bob", "Finance Analyst", "confidential", ["finance"], "token-bob"),
    ("carol", "Carol", "Manager", "secret", ["R&D"], "token-carol"),
    ("dave", "Dave", "Intern", "open", [], "token-dave"),
    # Company A personas (demo-seed/company_a): same ids/clearances/groups as
    # the platform directory, so connector content is reachable natively —
    # maya sees payments engineering (Jira PAY, PAYGW, /Postmortems), lena
    # sees SEC spaces and #security-private, sam sees LEADS/leadership.
    ("maya", "Maya Chen", "Backend Engineer, Payments", "confidential",
     ["eng", "payments"], "token-maya"),
    ("lena", "Lena Okafor", "Security Lead", "top_secret",
     ["eng", "security"], "token-lena"),
    ("sam", "Sam Alvarez", "Engineering Manager", "secret",
     ["eng", "payments", "leads"], "token-sam"),
    ("raj", "Raj Patel", "SRE, On-call", "confidential",
     ["eng", "sre", "payments"], "token-raj"),
    ("tom", "Tom Becker", "External Contractor", "open",
     ["contractors"], "token-tom"),
    ("jo", "Jo Park", "Junior Engineer", "confidential",
     ["eng"], "token-jo"),
    ("jdoe", "John Doe", "Senior Payments Engineer", "confidential",
     ["eng", "payments"], "token-jdoe"),
]

AUDIT_TOKENS = [
    # token, level
    ("audit-token-standard", "standard"),     # redacted view of secret+ entries
    ("audit-token-topsecret", "top_secret"),  # full view incl. sensitive content
    # D10 persona tokens (Company A cast): one person, one tier, never both
    ("audit-priya", "standard"),   # Priya Nair, compliance officer
    ("audit-lena", "top_secret"),  # Lena Okafor, security lead (also a chat user)
]


def main() -> None:
    conn = db.central()
    try:
        for user_id, name, position, clearance, groups, token in USERS:
            conn.execute(
                "INSERT OR REPLACE INTO users "
                "(user_id, name, position, max_clearance, groups, token_hash) "
                "VALUES (?,?,?,?,?,?)",
                (user_id, name, position, clearance, json.dumps(groups),
                 hashlib.sha256(token.encode()).hexdigest()),
            )
        for token, level in AUDIT_TOKENS:
            conn.execute(
                "INSERT OR REPLACE INTO audit_tokens (token_hash, level) VALUES (?,?)",
                (hashlib.sha256(token.encode()).hexdigest(), level),
            )
        conn.commit()
        print("Seeded users. Dev tokens:")
        for user_id, _, position, clearance, groups, token in USERS:
            print(f"  {user_id:6} {position:16} clearance={clearance:12} "
                  f"groups={groups}  token={token}")
        print("Audit-console tokens (separate URL path; NOT valid for chat):")
        for token, level in AUDIT_TOKENS:
            print(f"  level={level:10} token={token}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
