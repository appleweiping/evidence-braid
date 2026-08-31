from __future__ import annotations

import json
from pathlib import Path

from evidence_braid.engine import evaluate
from evidence_braid.io import canonical_json, load_events, load_policy
from evidence_braid.models import parse_timestamp
from evidence_braid.replay import replay
from evidence_braid.report import render_html, render_svg

EXAMPLES = Path(__file__).parents[1] / "examples"
AS_OF = parse_timestamp("2026-08-31T12:00:00Z", "test")


def _example_result():
    return evaluate(
        load_policy(EXAMPLES / "policy.json"), load_events(EXAMPLES / "events.jsonl"), AS_OF
    )


def test_checked_in_machine_example_is_current() -> None:
    expected = (EXAMPLES / "decision.json").read_text(encoding="utf-8")
    assert canonical_json(_example_result().to_dict()) == expected


def test_checked_in_human_reports_are_current() -> None:
    result = _example_result()
    assert render_html(result) == (EXAMPLES / "decision.html").read_text(encoding="utf-8")
    assert render_svg(result) == (EXAMPLES / "decision.svg").read_text(encoding="utf-8")


def test_checked_in_replay_is_current() -> None:
    policy = load_policy(EXAMPLES / "policy.json")
    events = load_events(EXAMPLES / "events.jsonl")
    actual = [result.to_dict() for result in replay(policy, events)]
    expected = [
        json.loads(line)
        for line in (EXAMPLES / "replay.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert actual == expected
