"""Token/cost accounting: pull usage out of each phase's result event and
aggregate it across the run.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from apt.runner import aggregate_usage, usage_from_result  # noqa: E402


def _result_event():
    return {
        "type": "result",
        "num_turns": 27,
        "total_cost_usd": 2.307451,
        "usage": {
            "input_tokens": 54,
            "output_tokens": 33201,
            "cache_creation_input_tokens": 71566,
            "cache_read_input_tokens": 1522992,
            "output_tokens_details": {"thinking_tokens": 13630},
        },
    }


def test_usage_from_result_extracts_and_totals_tokens():
    u = usage_from_result(_result_event())

    assert u["input_tokens"] == 54
    assert u["output_tokens"] == 33201
    assert u["cache_creation_input_tokens"] == 71566
    assert u["cache_read_input_tokens"] == 1522992
    assert u["thinking_tokens"] == 13630
    assert u["cost_usd"] == 2.307451
    assert u["num_turns"] == 27
    # total = input + output + cache_creation + cache_read
    assert u["total_tokens"] == 54 + 33201 + 71566 + 1522992


def test_usage_from_result_handles_missing_usage():
    u = usage_from_result({"type": "result"})

    assert u["total_tokens"] == 0
    assert u["cost_usd"] == 0.0
    assert u["num_turns"] == 0


def test_aggregate_usage_sums_across_phases():
    a = usage_from_result(_result_event())
    b = usage_from_result(_result_event())

    total = aggregate_usage([a, b])

    assert total["total_tokens"] == a["total_tokens"] * 2
    assert total["output_tokens"] == 33201 * 2
    assert total["cost_usd"] == round(2.307451 * 2, 6)
    assert total["num_turns"] == 54
