"""LEGACY — curated demo audit history for the alice/bob/carol/dave cast.

Generated at reset time, never baked in. Still run by demo-seed/reset-demo.py
alongside the Company A audit seed (demo-seed/company_a/story.py), so the
audit console has history for both token families.

Writes a plausible ~2-week story of FileGuard usage into a FRESH central.db
and harness_local.db: routine cross-tier accesses by the seeded users plus a
few deliberate incidents (an over-clearance attempt, a request flood) so the
audit console's colour coding, redaction and abuse story are visible.

Every entry goes through db.append_log itself — the hash chain is genuine.
Payload shapes mirror exactly what gateway.py / harness.local_log write.
"""

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fileguard import db  # noqa: E402

DAY = 86400
# working hours in SGT expressed as UTC hours (SGT = UTC+8)
SPAN_KIND = {"pdf": "page", "xlsx": "cell_range", "docx": "paragraph"}
_SPAN_REF = {  # a realistic first-span reference per document
    "employee_handbook.pdf": ("page", 1, 2),
    "q3_financials.xlsx": ("cell_range", "Summary!A1", "Summary!C4"),
    "product_roadmap.docx": ("paragraph", 0, 2),
    "hr_policy.pdf": ("page", 1, 1),
    "hr_incident_report.docx": ("paragraph", 0, 3),
    "board_compensation.xlsx": ("cell_range", "Remuneration!A1", "Remuneration!D6"),
}


# --- document facts (must match scripts/ingest_demo.py SAMPLES) ---------------

FILES = {
    # name: (base_clearance, groups, kind)
    "employee_handbook.pdf": ("open", [], "pdf"),
    "q3_financials.xlsx": ("confidential", ["finance"], "xlsx"),
    "product_roadmap.docx": ("secret", [], "docx"),
    "hr_policy.pdf": ("secret", ["HR"], "pdf"),
    "hr_incident_report.docx": ("top_secret", ["HR"], "docx"),
    "board_compensation.xlsx": ("top_secret", ["finance"], "xlsx"),
}

USERS = {  # user_id: (max_clearance, groups)
    "alice": ("top_secret", ["HR", "finance"]),
    "bob": ("confidential", ["finance"]),
    "carol": ("secret", ["R&D"]),
    "dave": ("open", []),
}

_REASONS = {
    "employee_handbook.pdf": "Locate leave and expense policy basics for an employee question",
    "q3_financials.xlsx": "Find quarterly revenue and profit figures for the finance review",
    "product_roadmap.docx": "Summarise the upcoming product milestones for planning",
    "hr_policy.pdf": "Retrieve the grievance handling procedure for an HR query",
    "hr_incident_report.docx": "Check investigation status for the scheduled hearing",
    "board_compensation.xlsx": "Retrieve board remuneration totals for the compensation review",
}

_GK_REASONS = {
    "employee_handbook.pdf": "Selected the leave and expense policy paragraphs.",
    "q3_financials.xlsx": "Selected the quarterly metrics table.",
    "product_roadmap.docx": "Selected the milestone paragraphs.",
    "hr_policy.pdf": "Selected the grievance procedure and escalation paragraphs.",
    "hr_incident_report.docx": "Selected the status paragraph of the investigation report.",
    "board_compensation.xlsx": "Selected the remuneration table.",
}


def _session(user: str, day_idx: int) -> str:
    """Stable pseudo session id — one session per user per demo day."""
    h = hashlib.sha256(f"{user}-{day_idx}".encode()).hexdigest()
    return h[:16]


def _tier(user: str, name: str) -> str:
    """Handling tier = max(desired, file base); desired defaults to user max."""
    base = FILES[name][0]
    order = ["open", "confidential", "secret", "top_secret"]
    return base if order.index(base) > order.index(USERS[user][0]) else USERS[user][0]


def _file_ids(conn) -> dict:
    return {name: fid for fid, name in
            conn.execute("SELECT file_id, name FROM files")}


def _trace(tool: str, args: dict, ts: int, raw_input: str | None) -> list:
    return [
        {"role": "user", "content": raw_input or "find the relevant document"},
        {"role": "assistant",
         "content": "I'll retrieve the relevant excerpts from the document index."},
        {"role": "harness", "tool_call": {"tool": tool, "args": args}, "ts": ts},
    ]


class Story:
    def __init__(self, conn_c, conn_l, file_ids):
        self.c = conn_c
        self.l = conn_l
        self.fids = file_ids

    # one get_content access = local mirror + central request + central response
    def access(self, ts, user, name, *, raw_input=None, day_idx=0):
        tier = _tier(user, name)
        desired = USERS[user][0]
        sid = _session(user, day_idx)
        reason = _REASONS[name]
        args = {"file_ref": name, "desired_clearance": desired, "reason": reason}
        db.append_log(self.l, {
            "event": "outgoing_request", "user_id": user, "session_id": sid,
            "payload": {"tool": "get_content", "reason": reason,
                        "desired_clearance": desired, "file_ref": name},
            "reason_label": "agent-asserted",
        }, ts=ts)
        entry = {
            "event": "request", "user_id": user, "session_id": sid,
            "tool": "get_content", "file_ref": name,
            "desired_clearance": desired, "desired_group": "default",
            "entry_clearance": tier, "reason": reason,
            "reason_label": "agent-asserted",
        }
        order = ["open", "confidential", "secret", "top_secret"]
        if order.index(tier) >= order.index("secret"):
            entry["trace"] = _trace("get_content", args, ts, raw_input)
        raw_text = None
        raw_salt = None
        if tier == "top_secret":
            # restricted field (D7): commitment in the chain, plaintext +
            # salt in the side table — same shape the live gateway writes
            from fileguard.audit_restricted import (
                compute_commitment, generate_salt, store_all_restricted)
            raw_text = raw_input or "show me the document"
            raw_salt = generate_salt()
            entry["raw_user_input"] = compute_commitment(raw_salt, raw_text)
        logged_request = db.append_log(self.c, entry, ts=ts)
        if raw_text is not None:
            store_all_restricted(
                self.c, logged_request["seq"], {"raw_user_input": raw_text},
                salts={"raw_user_input": raw_salt})
        kind, start, end = _SPAN_REF[name]
        db.append_log(self.c, {
            "event": "response", "user_id": user, "session_id": sid,
            "tool": "get_content", "file_ref": name,
            "entry_clearance": tier, "gatekeeper_reason": _GK_REASONS[name],
            "returned": [{"kind": kind, "start": start, "end": end}],
        }, ts=ts + 2)

    def discovery(self, ts, user, ceiling, listed, day_idx=0):
        sid = _session(user, day_idx)
        reason = "List documents available for the current research task"
        db.append_log(self.l, {
            "event": "outgoing_request", "user_id": user, "session_id": sid,
            "payload": {"tool": "list_files", "reason": reason,
                        "desired_clearance": ceiling},
            "reason_label": "agent-asserted",
        }, ts=ts)
        db.append_log(self.c, {
            "event": "request", "user_id": user, "session_id": sid,
            "tool": "list_files", "desired_clearance": ceiling,
            "desired_group": "default", "entry_clearance": ceiling,
            "reason": reason, "reason_label": "agent-asserted",
        }, ts=ts)
        db.append_log(self.c, {
            "event": "response", "user_id": user, "session_id": sid,
            "tool": "list_files", "entry_clearance": ceiling,
            "returned": listed,
        }, ts=ts + 2)

    # --- incidents ------------------------------------------------------------

    def overclearance(self, ts, user, name, day_idx=0):
        """User asks for a document above their clearance; the gateway
        rejects (code OVERCLEARANCE, warning flag) — visible redacted to the
        standard auditor."""
        sid = _session(user, day_idx)
        reason = "Follow up on an executive expense claim"
        db.append_log(self.l, {
            "event": "outgoing_request", "user_id": user, "session_id": sid,
            "payload": {"tool": "get_content", "reason": reason,
                        "desired_clearance": "top_secret", "file_ref": name},
            "reason_label": "agent-asserted",
        }, ts=ts)
        db.append_log(self.c, {
            "event": "request", "user_id": user, "session_id": sid,
            "tool": "get_content", "file_ref": name,
            "desired_clearance": "top_secret", "desired_group": "default",
            "entry_clearance": FILES[name][0], "reason": reason,
            "reason_label": "agent-asserted",
        }, ts=ts)
        db.append_log(self.c, {
            "event": "rejection", "user_id": user, "session_id": sid,
            "tool": "get_content", "file_ref": name,
            "entry_clearance": FILES[name][0],
            "code": "OVERCLEARANCE", "warning": True,
            "detail": f"file '{name}' rated {FILES[name][0]}, "
                      f"above user max {USERS[user][0]}",
        }, ts=ts + 1)

    def flood(self, ts, user, day_idx=0):
        """Burst of rapid requests tripping the Abuse Guard rate limit."""
        sid = _session(user, day_idx)
        for i in range(4):
            db.append_log(self.c, {
                "event": "request", "user_id": user, "session_id": sid,
                "tool": "list_files", "desired_clearance": USERS[user][0],
                "desired_group": "default",
                "entry_clearance": USERS[user][0],
                "reason": "List all documents",
                "reason_label": "agent-asserted",
            }, ts=ts + i)
            if i < 3:
                db.append_log(self.c, {
                    "event": "abuse_block", "user_id": user,
                    "session_id": sid, "tool": "list_files",
                    "entry_clearance": USERS[user][0],
                    "code": "ABUSE_RATE", "detail": "request rate limit exceeded",
                }, ts=ts + i)


def _business_days(start_ts: int, count: int) -> list:
    """Epoch midnights (UTC) of `count` consecutive weekdays ending today."""
    import datetime as dt
    days, cur = [], dt.datetime.fromtimestamp(start_ts, dt.timezone.utc)
    while len(days) < count:
        if cur.weekday() < 5:
            days.append(int(cur.replace(hour=0, minute=0, second=0,
                                        microsecond=0).timestamp()))
        cur -= dt.timedelta(days=1)
    return list(reversed(days))


def populate(conn_c, conn_l, start_ts: int) -> int:
    """Fill a fresh central + local log with the demo story. Returns count."""
    fids = _file_ids(conn_c)
    s = Story(conn_c, conn_l, fids)
    days = _business_days(start_ts, 12)
    T = lambda d, h, m=0: days[d] + h * 3600 + m * 60  # noqa: E731
    n = 0

    def logged(fn, *a, **kw):
        nonlocal n
        before = conn_c.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] + \
            conn_l.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        fn(*a, **kw)
        after = conn_c.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] + \
            conn_l.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        n += after - before

    def listed_subset(names, ceiling):
        order = ["open", "confidential", "secret", "top_secret"]
        out = []
        for name in names:
            base, groups, kind = FILES[name]
            if order.index(base) <= order.index(ceiling):
                out.append({"file_id": fids[name], "name": name, "kind": kind,
                            "base_clearance": base, "groups": sorted(groups)})
        return out

    all_names = list(FILES)

    # week 1 — routine mixed-tier usage
    logged(s.discovery, T(0, 1, 41), "alice", "top_secret",
           listed_subset(all_names, "top_secret"), day_idx=0)
    logged(s.access, T(0, 1, 43), "alice", "employee_handbook.pdf", day_idx=0)
    logged(s.access, T(0, 2, 5), "alice", "q3_financials.xlsx", day_idx=0)
    logged(s.access, T(0, 2, 9), "alice", "board_compensation.xlsx",
           raw_input="what is the board of director's average salary?", day_idx=0)
    logged(s.discovery, T(0, 3, 12), "bob", "confidential",
           listed_subset(all_names, "confidential"), day_idx=0)
    logged(s.access, T(0, 3, 14), "bob", "employee_handbook.pdf", day_idx=0)
    logged(s.access, T(1, 6, 22), "carol", "product_roadmap.docx", day_idx=1)
    logged(s.access, T(1, 6, 26), "carol", "employee_handbook.pdf", day_idx=1)
    logged(s.access, T(2, 1, 18), "alice", "hr_policy.pdf", day_idx=2)
    logged(s.access, T(2, 1, 24), "alice", "hr_incident_report.docx",
           raw_input="any update on the finance investigation?", day_idx=2)
    logged(s.access, T(2, 4, 47), "bob", "q3_financials.xlsx", day_idx=2)
    logged(s.discovery, T(3, 2, 3), "dave", "open",
           listed_subset(all_names, "open"), day_idx=3)
    logged(s.access, T(3, 2, 6), "dave", "employee_handbook.pdf", day_idx=3)
    logged(s.access, T(4, 7, 31), "carol", "product_roadmap.docx", day_idx=4)
    logged(s.access, T(4, 7, 35), "carol", "employee_handbook.pdf", day_idx=4)

    # week 2 — routine plus incidents
    logged(s.access, T(5, 1, 12), "alice", "q3_financials.xlsx", day_idx=5)
    logged(s.access, T(5, 1, 16), "alice", "board_compensation.xlsx",
           raw_input="prepare the compensation summary for the board meeting",
           day_idx=5)
    logged(s.overclearance, T(5, 4, 41), "bob", "hr_incident_report.docx",
           day_idx=5)
    logged(s.access, T(6, 2, 50), "bob", "q3_financials.xlsx", day_idx=6)
    logged(s.access, T(6, 2, 55), "bob", "employee_handbook.pdf", day_idx=6)
    logged(s.access, T(7, 5, 8), "alice", "hr_policy.pdf", day_idx=7)
    logged(s.flood, T(8, 3, 17), "bob", day_idx=8)
    logged(s.access, T(8, 5, 44), "carol", "employee_handbook.pdf", day_idx=8)
    logged(s.access, T(9, 1, 29), "alice", "hr_incident_report.docx",
           raw_input="what is the hearing schedule for IR-2041?", day_idx=9)
    logged(s.overclearance, T(9, 6, 2), "bob", "board_compensation.xlsx",
           day_idx=9)
    logged(s.access, T(10, 2, 14), "dave", "employee_handbook.pdf", day_idx=10)
    logged(s.access, T(11, 1, 37), "alice", "board_compensation.xlsx",
           raw_input="refresh the board remuneration numbers before the meeting",
           day_idx=11)
    logged(s.access, T(11, 3, 3), "bob", "q3_financials.xlsx", day_idx=11)
    return n
