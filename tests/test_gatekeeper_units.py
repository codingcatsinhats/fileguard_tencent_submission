"""Gatekeeper select_units tests — pipeline-path span selection.

Regression: the submit_spans tool enum only allowed uploads-era kinds
(page/cell_range/paragraph), so Jira "field" spans could never be
referenced — the model's selections were silently dropped and entitled
users got empty answers (found live: SEC-24 / SEC-21).
"""

import os
import sys
import tempfile
import types
from pathlib import Path

os.environ["FILEGUARD_DATA_DIR"] = tempfile.mkdtemp()
os.environ["FILEGUARD_GATEKEEPER_MODE"] = "test"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fileguard.connector import Unit  # noqa: E402
from fileguard import gatekeeper  # noqa: E402


def _units(*kinds):
    return [Unit(unit_id=f"jira:SEC-24@1#{i}", kind=k, text=f"unit {i}",
                 order=i, metadata={}) for i, k in enumerate(kinds)]


def _fake_llm(refs):
    def _llm(spans, reason, user_context):
        return refs, "fake selection reason"
    return _llm


def test_tool_schema_covers_all_unit_kinds():
    enum = gatekeeper.SUBMIT_SPANS_TOOL["input_schema"]["properties"]["spans"]["items"]["properties"]["kind"]["enum"]
    for kind in ("page", "cell_range", "paragraph", "message", "section",
                 "field", "comment"):
        assert kind in enum, f"span kind {kind} missing from submit_spans enum"


def test_select_units_accepts_field_kind_refs():
    units = _units("field", "field")
    monkey_refs = [{"kind": "field", "start": 0, "end": 0},
                   {"kind": "field", "start": 1, "end": 1}]
    gatekeeper._llm_select, orig = _fake_llm(monkey_refs), gatekeeper._llm_select
    try:
        refs, mode, reason = gatekeeper.select_units(
            units, "dependency scan findings", {}, platform="jira",
            container="SEC", item_id="SEC-24")
    finally:
        gatekeeper._llm_select = orig
    assert refs == [0, 1]
    assert mode == "live-llm"
    assert "fake selection reason" in reason


def test_select_units_drops_nonexistent_refs():
    units = _units("field", "field")
    # model cites a kind that matches no unit (e.g. coerced to the old enum)
    monkey_refs = [{"kind": "paragraph", "start": 0, "end": 0}]
    gatekeeper._llm_select, orig = _fake_llm(monkey_refs), gatekeeper._llm_select
    try:
        refs, _, _ = gatekeeper.select_units(
            units, "reason", {}, platform="jira", container="SEC",
            item_id="SEC-24")
    finally:
        gatekeeper._llm_select = orig
    assert refs == []


def test_select_units_dedupes_and_preserves_order():
    units = _units("field", "field")
    gatekeeper._llm_select, orig = _fake_llm([
        {"kind": "field", "start": 1, "end": 1},
        {"kind": "field", "start": 1, "end": 1},
        {"kind": "field", "start": 0, "end": 0},
    ]), gatekeeper._llm_select
    try:
        refs, _, _ = gatekeeper.select_units(
            units, "reason", {}, platform="jira", container="SEC",
            item_id="SEC-24")
    finally:
        gatekeeper._llm_select = orig
    assert refs == [1, 0]


def test_select_units_empty_units_is_legitimate():
    refs, mode, _ = gatekeeper.select_units(
        [], "reason", {}, platform="jira", container="SEC", item_id="X")
    assert refs == [] and mode == "live-llm"
