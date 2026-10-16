"""FileGuard — extractive, audited agentic access to enterprise knowledge."""

CLEARANCE_ORDER = {"open": 0, "confidential": 1, "secret": 2, "top_secret": 3}
CLEARANCE_NAME = {v: k for k, v in CLEARANCE_ORDER.items()}
