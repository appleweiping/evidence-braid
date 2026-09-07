from __future__ import annotations

import json
import subprocess
import sys
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


def test_durable_ledger_example_reopens_and_preserves_evaluation() -> None:
    result = subprocess.run(
        [sys.executable, str(EXAMPLES / "durable_ledger.py")],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    report = json.loads(result.stdout)
    assert report["entry_count"] == len(load_events(EXAMPLES / "events.jsonl"))
    assert report["reopened"] is True
    assert report["evaluation_unchanged"] is True


def test_authority_workflow_example_replays_persisted_receipts() -> None:
    result = subprocess.run(
        [sys.executable, str(EXAMPLES / "authority_workflow.py")],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    report = json.loads(result.stdout)
    assert report["status"] == "approved"
    assert report["approval_count"] == 2
    assert report["record_count"] == 6
    assert report["offline_replay_equal"] is True
    assert report["artifact_content_verified"] is True
    assert report["actor_authentication_provided"] is False
