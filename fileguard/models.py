"""Pydantic models: everything that crosses the Audit Gateway is validated here."""

from typing import Literal

from pydantic import BaseModel, Field

Clearance = Literal["open", "confidential", "secret", "top_secret"]
ToolName = Literal["list_files", "get_content", "search"]
SpanKind = Literal["page", "cell_range", "paragraph", "message", "section", "field", "comment"]


class ScopedGrant(BaseModel):
    user_id: str
    max_clearance: Clearance
    groups: list[str]
    session_id: str
    exp: int


class RequestPayload(BaseModel):
    tool: ToolName
    reason: str = Field(min_length=1)  # agent-asserted; labeled as such in logs
    desired_clearance: Clearance
    desired_group: str = "default"  # "default" = all the user's groups
    file_ref: str | None = None  # get_content only: file_id, file name, or "platform:item_id"
    query: str | None = None  # search only: the search terms
    search_seq: int | None = None  # search only: 0-based index within the user turn
                                   # (harness-supplied; abuse guard exempting forced first)


class Credentials(BaseModel):
    grant: str  # HMAC-signed grant string; Auth Checker verifies signature + expiry


class RequestObject(BaseModel):
    credentials: Credentials
    payload: RequestPayload
    raw_user_input: str | None = None  # all tiers; stored restricted (D7)
    trace: list | None = None  # secret+: harness-constructed
    restricted_salts: dict[str, str] | None = None  # harness-generated salts for
    # restricted fields (raw_user_input, search_terms) — central and local logs
    # compute identical commitments so reconciliation compares commitments only


class SpanRef(BaseModel):
    doc_id: str
    content_hash: str
    kind: SpanKind
    start: int | str  # page no / "Sheet1!A1" / paragraph idx
    end: int | str


class AuthVerdict(BaseModel):
    ok: bool
    code: str = "OK"  # OK | OVERCLEARANCE | INVALID_GROUP | NO_GRANT | NO_FILE | NO_GROUP_ACCESS | STALE_EPOCH
    detail: str = ""
    effective_clearance: Clearance | None = None
    warning: bool = False  # agent attempted to overstep — flag in audit
