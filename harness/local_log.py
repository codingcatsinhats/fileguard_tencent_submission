"""Harness-local audit log — independently records every outgoing request.

Same append-only hash-chained schema as the central log, in a separate DB
owned by the harness. Monthly reconciliation (Section 2) compares chains:
equivalent -> local cleared; mismatch -> flag + preserve.
"""

from fileguard import db


def log_outgoing(request_body: dict) -> dict:
    conn = db.local()
    try:
        return db.append_log(conn, {
            "event": "outgoing_request",
            **request_body,
        })
    finally:
        conn.close()


def verify() -> tuple[bool, int]:
    conn = db.local()
    try:
        return db.verify_chain(conn)
    finally:
        conn.close()
