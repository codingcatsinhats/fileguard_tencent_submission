"""Abuse Guard — backend abuse prevention, deterministic caps only.

Runs after the Auth Checker on every request. Explicit thresholds a security
team can reason about; no ML in the enforcement path.

Caps:
  rate      token bucket per session (burst + sustained refill)
  volume    spans per get_content response, files per session
  patterns  full-document pulls, thin/generic reasons, over-clearance
            rejections escalating to an automatic block

A block is a session-level time-out: the request is denied with a plain
policy reply, logged (event=abuse_block), and flagged.
"""

import json
import re
import time

from . import db

DEFAULTS = {
    "burst": 10,                # max requests in an instantaneous burst
    "refill_per_min": 30,       # sustained request rate
    "block_seconds": 300,       # how long a tripped session stays blocked
    "max_spans_per_response": 10,
    # discovery-breadth cap. Post-revamp calibration: one search returns up
    # to 30 references and a turn allows 3 searches (worst case 90), so the
    # cap must exceed one turn's budget. The count is a DECAYING WINDOW
    # (volume_window_seconds) that resets at each new user turn — a fixed
    # session counter made every broad-but-legitimate query permanently
    # brick the session (found in the demo: ABUSE_VOLUME on the outage
    # question, then ABUSE_BLOCKED mid-turn, unrecoverable until re-login).
    "max_files_per_session": 120,
    "volume_window_seconds": 600,
    "full_doc_pulls_before_block": 3,
    "full_doc_min_total": 5,    # docs with fewer spans than this are exempt:
                                # fully returning a tiny doc is not abuse
    "thin_reasons_before_block": 4,
    "overclearance_before_block": 3,
    "pattern_window_seconds": 600,
    "min_reason_chars": 8,
    # --- D9 extensions (broad search / empty flood / denied flood) ---
    # A search is "broad" only when BOTH signals fire: permitted-match
    # volume above the threshold AND low term specificity. Never count
    # matches the user cannot access — that would leak existence.
    "broad_search_min_matches": 15,
    "broad_min_distinctive_tokens": 1,  # fewer than this = low specificity
    "broad_searches_before_block": 3,   # strikes decay over the window
    "empty_searches_before_block": 6,   # rolling window, per session
    "denied_items_before_block": 4,     # distinct denied items, rolling window
}

# tokens that carry no specificity on their own
GENERIC_TOKENS = {
    "the", "and", "for", "with", "what", "how", "why", "when", "who",
    "show", "find", "list", "give", "tell", "about", "from", "into",
    "data", "docs", "document", "documents", "file", "files", "info",
    "information", "please", "latest", "recent", "any", "all", "some",
    "need", "want", "look", "search", "query", "content",
}

# the forced-first search of a turn is exempt from empty counting unless a
# refinement in the same turn also comes back empty — the harness marks
# each search with its 0-based position (payload.search_seq) so this
# stateless guard can apply the exemption
FORCED_FIRST_SEQ = 0

GENERIC_REASONS = {"data", "find files", "documents", "read file", "info", "everything"}


def _low_specificity(query: str) -> bool:
    """Very short, mostly generic words, no distinctive token (D9 3b)."""
    tokens = re.findall(r"[a-z0-9]+", (query or "").lower())
    distinctive = [t for t in tokens
                   if len(t) >= 4 and t not in GENERIC_TOKENS]
    return len(distinctive) == 0


class AbuseVerdict:
    def __init__(self, ok: bool, code: str = "OK", detail: str = ""):
        self.ok, self.code, self.detail = ok, code, detail


class AbuseGuard:
    """In-memory per-session state, window queries over the central log."""

    def __init__(self, **overrides):
        self.cfg = dict(DEFAULTS)
        self.cfg.update(overrides)
        self._buckets: dict[str, dict] = {}      # session -> tokens
        self._session: dict[str, dict] = {}      # session -> counters
        self._blocks: dict[str, dict] = {}       # session -> {until, code, detail}

    # --- request-time check (pre-routing) -----------------------------------

    def check_request(self, session_id: str, user_id: str, payload: dict, conn) -> AbuseVerdict:
        now = time.time()
        blk = self._blocks.get(session_id)
        if blk and blk["until"] > now:
            return AbuseVerdict(
                False, "ABUSE_BLOCKED",
                f"session temporarily blocked by usage policy "
                f"({blk['code']}: {blk['detail']})")

        if not self._take_token(session_id, now):
            self._arm(session_id, "ABUSE_RATE", "request rate limit exceeded")
            return AbuseVerdict(False, "ABUSE_RATE", "request rate limit exceeded")

        st = self._state(session_id)

        # over-clearance escalation (from central-log rejections + this session)
        rejections = self._recent_rejections(conn, user_id, now)
        if rejections >= self.cfg["overclearance_before_block"]:
            self._arm(session_id, "ABUSE_OVERCLEARANCE",
                      "repeated attempts to exceed clearance")
            return AbuseVerdict(False, "ABUSE_OVERCLEARANCE",
                                "repeated attempts to exceed clearance")

        # denied-item flood: distinct get_content denials in the window (D9)
        denied = self._recent_denied_items(conn, user_id, now)
        if denied >= self.cfg["denied_items_before_block"]:
            self._arm(session_id, "ABUSE_DENIED_FLOOD",
                      f"{denied} distinct items denied in the window")
            return AbuseVerdict(False, "ABUSE_DENIED_FLOOD",
                                "repeated denied content requests")

        # thin / generic reasons
        reason = (payload.get("reason") or "").strip().lower()
        if len(reason) < self.cfg["min_reason_chars"] or reason in GENERIC_REASONS:
            st["thin_reasons"] = st.get("thin_reasons", 0) + 1
            if st["thin_reasons"] >= self.cfg["thin_reasons_before_block"]:
                self._arm(session_id, "ABUSE_PATTERN",
                          "repeated low-information access requests")
                return AbuseVerdict(False, "ABUSE_PATTERN",
                                    "repeated low-information access requests")

        # discovery-breadth pre-flight: refuse while the decaying window is
        # saturated (e.g. the block expired but the strikes haven't decayed)
        volume_strikes = [t for t in st.get("volume_strikes", [])
                          if t > now - self.cfg["volume_window_seconds"]]
        st["volume_strikes"] = volume_strikes
        if len(volume_strikes) >= self.cfg["max_files_per_session"]:
            self._arm(session_id, "ABUSE_VOLUME",
                      "session discovery volume cap reached")
            return AbuseVerdict(False, "ABUSE_VOLUME",
                                "session discovery volume cap reached")

        return AbuseVerdict(True)

    # --- response-time accounting (post-routing) ----------------------------

    def note_search_response(self, session_id: str, query: str,
                             returned: list | None, total: int | None = None,
                             search_seq: int | None = None) -> AbuseVerdict | None:
        """Post-routing accounting for `search` (D9). Arms a block with an
        explicit code and returns the verdict the caller must log
        (None = nothing armed).

        - broad search: permitted-match volume above threshold AND low
          specificity (both required); strikes decay over the pattern
          window and persist across turns in the session
        - empty-result flood: counted in the same rolling window; the
          forced first search of a turn is exempt unless a refinement in
          that turn also comes back empty
        - a successful retrieval never resets counters (window decay only)
        """
        armed = None
        st = self._state(session_id)
        now = time.time()
        window = self.cfg["pattern_window_seconds"]
        matches = total if total is not None else len(returned or [])
        empty = not returned

        # discovery-breadth cap: decaying window of returned-reference
        # strikes, reset at each new user turn (search_seq == 0)
        if search_seq == FORCED_FIRST_SEQ:
            st["volume_strikes"] = []
        if returned:
            strikes = st.setdefault("volume_strikes", [])
            strikes.extend([now] * len(returned))
            window = self.cfg["volume_window_seconds"]
            strikes = [t for t in strikes if t > now - window]
            st["volume_strikes"] = strikes
            if len(strikes) >= self.cfg["max_files_per_session"]:
                self._arm(session_id, "ABUSE_VOLUME",
                          "session discovery volume cap reached")
                return AbuseVerdict(False, "ABUSE_VOLUME",
                                    "session discovery volume cap reached")

        # empty-result accounting with the forced-first exemption
        if search_seq == FORCED_FIRST_SEQ:
            st["turn_first_empty"] = False  # new turn begins with this search
        if empty:
            if search_seq == FORCED_FIRST_SEQ:
                st["turn_first_empty"] = True  # pending, not counted yet
            else:
                strikes = st.setdefault("empty_strikes", [])
                strikes.append(now)
                if st.get("turn_first_empty"):
                    strikes.append(now)  # the forced first retroactively counts
                    st["turn_first_empty"] = False
        else:
            st["turn_first_empty"] = False

        empties = [t for t in st.get("empty_strikes", [])
                   if t > now - window]
        st["empty_strikes"] = empties
        if len(empties) >= self.cfg["empty_searches_before_block"]:
            armed = AbuseVerdict(False, "ABUSE_EMPTY_FLOOD",
                                 "repeated empty searches")
            self._arm(session_id, armed.code, armed.detail)
            return armed

        # broad-search strike: volume AND low specificity (D9 3b)
        if not empty and matches >= self.cfg["broad_search_min_matches"] \
                and _low_specificity(query):
            strikes = st.setdefault("broad_strikes", [])
            strikes.append(now)
            strikes = [t for t in strikes if t > now - window]
            st["broad_strikes"] = strikes
            if len(strikes) >= self.cfg["broad_searches_before_block"]:
                armed = AbuseVerdict(False, "ABUSE_BROAD_SEARCH",
                                     "repeated broad, low-specificity searches")
                self._arm(session_id, armed.code, armed.detail)
        return armed

    def note_response(self, session_id: str, tool: str, returned: list | None,
                      full_doc: bool = False,
                      total_spans: int | None = None) -> AbuseVerdict | None:
        """Post-routing accounting. Arms a block with an explicit code and
        returns the AbuseVerdict the caller must log (None = nothing armed).

        total_spans is the document's full span count: full-document pulls
        only count toward a block when the document is at least
        full_doc_min_total spans — fully returning a tiny document is not
        abuse. A None total counts conservatively (old behaviour).
        """
        armed = None
        st = self._state(session_id)
        now = time.time()
        if tool in ("list_files", "search") and returned:
            # LEGACY discovery path (list_files): same decaying-window
            # volume cap as note_search_response, no per-turn reset marker
            strikes = st.setdefault("volume_strikes", [])
            strikes.extend([now] * len(returned))
            window = self.cfg["volume_window_seconds"]
            st["volume_strikes"] = [t for t in strikes if t > now - window]
            if len(st["volume_strikes"]) >= self.cfg["max_files_per_session"]:
                armed = AbuseVerdict(False, "ABUSE_VOLUME",
                                     "session discovery volume cap reached")
                self._arm(session_id, armed.code, armed.detail)
        if tool == "get_content" and returned is not None:
            if len(returned) > self.cfg["max_spans_per_response"]:
                armed = AbuseVerdict(False, "ABUSE_SPAN_VOLUME",
                                     "response exceeded the span cap")
                self._arm(session_id, armed.code, armed.detail)
            elif full_doc and (total_spans is None
                               or total_spans >= self.cfg["full_doc_min_total"]):
                st["full_doc_pulls"] = st.get("full_doc_pulls", 0) + 1
                if st["full_doc_pulls"] >= self.cfg["full_doc_pulls_before_block"]:
                    armed = AbuseVerdict(False, "ABUSE_FULL_DOC",
                                         "repeated full-document pulls")
                    self._arm(session_id, armed.code, armed.detail)
            else:
                st["full_doc_pulls"] = 0
        return armed

    # --- internals -----------------------------------------------------------

    def _state(self, session_id: str) -> dict:
        return self._session.setdefault(session_id, {})

    def _take_token(self, session_id: str, now: float) -> bool:
        bucket = self._buckets.setdefault(
            session_id, {"tokens": float(self.cfg["burst"]), "ts": now}
        )
        refill = (now - bucket["ts"]) / 60.0 * self.cfg["refill_per_min"]
        bucket["tokens"] = min(float(self.cfg["burst"]), bucket["tokens"] + refill)
        bucket["ts"] = now
        if bucket["tokens"] < 1:
            return False
        bucket["tokens"] -= 1
        return True

    def _arm(self, session_id: str, code: str, detail: str) -> None:
        """Arm a block. Every arming path names its reason; the caller logs
        the code/detail (check_request returns it, note_response returns it).
        """
        self._blocks[session_id] = {
            "until": time.time() + self.cfg["block_seconds"],
            "code": code, "detail": detail,
        }

    def _recent_rejections(self, conn, user_id: str, now: float) -> int:
        cutoff = now - self.cfg["pattern_window_seconds"]
        n = 0
        for (payload_json,) in conn.execute(
            "SELECT payload FROM audit_log WHERE ts > ?", (cutoff,)
        ):
            payload = json.loads(payload_json)
            if (payload.get("event") == "rejection"
                    and payload.get("warning")
                    and payload.get("user_id") == user_id):
                n += 1
        return n

    def _recent_denied_items(self, conn, user_id: str, now: float) -> int:
        """Distinct items denied to this user in the window (any get_content
        rejection: over-clearance, group, live-check denial, not-found is
        indistinguishable by design — counting it is fine, it says no)."""
        cutoff = now - self.cfg["pattern_window_seconds"]
        refs = set()
        for (payload_json,) in conn.execute(
            "SELECT payload FROM audit_log WHERE ts > ?", (cutoff,)
        ):
            payload = json.loads(payload_json)
            if (payload.get("event") == "rejection"
                    and payload.get("tool") == "get_content"
                    and payload.get("user_id") == user_id):
                refs.add(payload.get("file_ref"))
        refs.discard(None)
        return len(refs)
