from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from conftest import event_dict, policy_dict

from evidence_braid import Adjudication, Verdict
from evidence_braid.cli import run
from evidence_braid.engine import ReliabilityUpdateTrace, evaluate
from evidence_braid.errors import InputFormatError, ValidationError
from evidence_braid.io import canonical_json, load_adjudications
from evidence_braid.models import (
    EvidenceEvent,
    Policy,
    ReliabilityUpdatePolicy,
    parse_timestamp,
)
from evidence_braid.reliability import (
    ReliabilityAdjustment,
    adjust_reliabilities,
    validate_adjudication_set,
)
from evidence_braid.replay import replay
from evidence_braid.report import render_html

AS_OF = parse_timestamp("2026-08-31T12:00:00Z", "test")


def updating_policy_dict(
    *, prior_weight: Any = 4, max_adjustment: Any = None, **claim_overrides: Any
) -> dict[str, Any]:
    raw = policy_dict(**claim_overrides)
    updates: dict[str, Any] = {"prior_weight": prior_weight}
    if max_adjustment is not None:
        updates["max_adjustment"] = max_adjustment
    raw["reliability_updates"] = updates
    return raw


def updating_policy(**overrides: Any) -> Policy:
    return Policy.from_dict(updating_policy_dict(**overrides))


def adjudication_dict(
    event_id: str,
    *,
    source: str = "microphone-a",
    verdict: str = "incorrect",
    adjudicated_at: str = "2026-08-31T11:59:40Z",
) -> dict[str, Any]:
    return {
        "event_id": event_id,
        "source": source,
        "verdict": verdict,
        "adjudicated_at": adjudicated_at,
    }


def adjudication(event_id: str, **overrides: Any) -> Adjudication:
    return Adjudication.from_dict(adjudication_dict(event_id, **overrides))


def microphone_history() -> list[Adjudication]:
    """One correct and three incorrect judgements about a 0.9 source."""
    return [
        adjudication("m1"),
        adjudication("m2"),
        adjudication("m3"),
        adjudication("m4", verdict="correct"),
    ]


def two_source_events() -> list[EvidenceEvent]:
    return [
        EvidenceEvent.from_dict(event_dict("e-cam", source="camera-a", modality="vision")),
        EvidenceEvent.from_dict(event_dict("e-mic", source="microphone-a", modality="audio")),
    ]


def trace_for(result: Any, event_id: str) -> Any:
    return next(item for item in result.decisions[0].trace if item.event_id == event_id)


# --- the rule itself -------------------------------------------------------


def test_rule_matches_the_documented_closed_form() -> None:
    # declared 0.9, prior_weight 4, one correct of four adjudications:
    #   posterior = (4 * 0.9 + 1) / (4 + 4) = 4.6 / 8 = 0.575
    (adjustment,) = adjust_reliabilities(updating_policy(), microphone_history())
    assert adjustment.source == "microphone-a"
    assert adjustment.declared_reliability == 0.9
    assert adjustment.posterior_reliability == 0.575
    assert adjustment.applied_reliability == 0.575
    assert adjustment.correct_event_ids == ("m4",)
    assert adjustment.incorrect_event_ids == ("m1", "m2", "m3")


def test_prior_weight_is_denominated_in_adjudications() -> None:
    # With as many adjudications as the prior weight, the applied value sits
    # exactly halfway between the declared reliability and the observed rate:
    #   (4 * 0.9 + 4) / (4 + 4) = 7.6 / 8 = 0.95, halfway from 0.9 to 1.0.
    history = [adjudication(f"m{index}", verdict="correct") for index in range(4)]
    (adjustment,) = adjust_reliabilities(updating_policy(), history)
    assert adjustment.applied_reliability == 0.95


def test_a_source_without_adjudications_does_not_move() -> None:
    policy = updating_policy()
    result = evaluate(policy, two_source_events(), AS_OF, adjudications=microphone_history())

    # camera-a is adjudicated by nothing, so it keeps the declared 1.0 exactly
    # and is absent from the audit trail entirely.
    assert [item.source for item in result.reliability_updates] == ["microphone-a"]
    assert trace_for(result, "e-cam").source_reliability == 1.0
    assert policy.reliability_for("camera-a") == 1.0


def test_a_source_with_adjudications_moves_and_is_used_for_weighting() -> None:
    result = evaluate(
        updating_policy(), two_source_events(), AS_OF, adjudications=microphone_history()
    )
    trace = trace_for(result, "e-mic")
    assert trace.source_reliability == 0.575
    # 0.9 raw confidence, 30s of a 60s audio half-life, and the applied weight:
    #   0.9 * 0.575 * 2 ** -0.5 = 0.365927759264
    assert trace.effective_confidence == 0.365927759264


def test_max_adjustment_bounds_how_far_one_weight_may_move() -> None:
    (adjustment,) = adjust_reliabilities(updating_policy(max_adjustment=0.2), microphone_history())
    # The unbounded closed form still reaches 0.575; the policy refuses to
    # apply more than 0.2 of it, and the audit trail shows both numbers.
    assert adjustment.posterior_reliability == 0.575
    assert adjustment.applied_reliability == 0.7


def test_ground_truth_applies_only_once_it_is_knowable() -> None:
    late = [
        replace(item, adjudicated_at=parse_timestamp("2026-08-31T12:00:01Z", "test"))
        for item in microphone_history()
    ]
    result = evaluate(updating_policy(), two_source_events(), AS_OF, adjudications=late)
    assert result.reliability_updates == ()
    assert trace_for(result, "e-mic").source_reliability == 0.9


# --- opt-in ----------------------------------------------------------------


def test_a_policy_without_the_block_behaves_exactly_as_before() -> None:
    plain = Policy.from_dict(policy_dict())
    result = evaluate(plain, two_source_events(), AS_OF)
    assert plain.reliability_updates is None
    assert result.reliability_updates is None
    assert "reliability_updates" not in result.to_dict()
    assert trace_for(result, "e-mic").source_reliability == 0.9


def test_enabling_the_block_without_ground_truth_changes_no_weight() -> None:
    plain = evaluate(Policy.from_dict(policy_dict()), two_source_events(), AS_OF)
    enabled = evaluate(updating_policy(), two_source_events(), AS_OF)

    # The key appears so an operator can tell "updating is on and nothing moved"
    # from "updating is off", but every decision number is untouched.
    assert enabled.reliability_updates == ()
    assert enabled.to_dict()["reliability_updates"] == []
    assert [item.to_dict() for item in enabled.decisions] == [
        item.to_dict() for item in plain.decisions
    ]


def test_an_explicit_null_block_is_the_same_as_omitting_it() -> None:
    raw = policy_dict()
    raw["reliability_updates"] = None
    assert Policy.from_dict(raw).reliability_updates is None


# --- determinism -----------------------------------------------------------


def test_two_identical_runs_are_byte_identical() -> None:
    first = evaluate(
        updating_policy(), two_source_events(), AS_OF, adjudications=microphone_history()
    )
    second = evaluate(
        updating_policy(), two_source_events(), AS_OF, adjudications=microphone_history()
    )
    assert canonical_json(first.to_dict()).encode("utf-8") == canonical_json(
        second.to_dict()
    ).encode("utf-8")
    assert first.digest == second.digest


def test_adjudication_order_cannot_change_a_result() -> None:
    # Only counts enter the rule, so a reordered ground-truth file must produce
    # the same weights, the same audit trail, and the same digest.
    forward = evaluate(
        updating_policy(), two_source_events(), AS_OF, adjudications=microphone_history()
    )
    reversed_input = evaluate(
        updating_policy(),
        list(reversed(two_source_events())),
        AS_OF,
        adjudications=list(reversed(microphone_history())),
    )
    assert forward.to_dict() == reversed_input.to_dict()
    assert forward.digest == reversed_input.digest


def test_replay_adds_a_snapshot_when_ground_truth_arrives() -> None:
    events = two_source_events()
    snapshots = replay(updating_policy(), events, adjudications=microphone_history())

    # One boundary at the shared ingestion time, one at the adjudication time.
    assert len(snapshots) == 2
    assert [item.reliability_updates == () for item in snapshots] == [True, False]
    assert trace_for(snapshots[0], "e-mic").source_reliability == 0.9
    assert trace_for(snapshots[1], "e-mic").source_reliability == 0.575


def test_replay_snapshots_stay_prefix_stable_when_ground_truth_is_appended() -> None:
    events = two_source_events()
    history = microphone_history()
    later = adjudication("m5", adjudicated_at="2026-08-31T11:59:50Z")

    prefix = replay(updating_policy(), events, adjudications=history)
    extended = replay(updating_policy(), events, adjudications=[*history, later])

    assert [item.to_dict() for item in prefix] == [item.to_dict() for item in extended[:2]]
    assert [item.digest for item in prefix] == [item.digest for item in extended[:2]]
    # (4 * 0.9 + 1) / (4 + 5) = 4.6 / 9 = 0.511111111111
    assert extended[2].reliability_updates[0].applied_reliability == 0.511111111111


def test_replay_without_ground_truth_keeps_its_ingestion_boundaries() -> None:
    events = two_source_events()
    assert len(replay(updating_policy(), events)) == 1
    assert replay(updating_policy(), events)[0].reliability_updates == ()


# --- the audit trail -------------------------------------------------------


def test_audit_trail_names_every_adjudication_that_moved_the_weight() -> None:
    result = evaluate(
        updating_policy(), two_source_events(), AS_OF, adjudications=microphone_history()
    )
    (update,) = result.to_dict()["reliability_updates"]
    assert update == {
        "source": "microphone-a",
        "declared_reliability": 0.9,
        "posterior_reliability": 0.575,
        "applied_reliability": 0.575,
        "adjustment": -0.325,
        "correct_count": 1,
        "incorrect_count": 3,
        "correct_event_ids": ["m4"],
        "incorrect_event_ids": ["m1", "m2", "m3"],
    }


def test_audit_trail_reports_the_bounded_and_unbounded_values_separately() -> None:
    result = evaluate(
        updating_policy(max_adjustment=0.2),
        two_source_events(),
        AS_OF,
        adjudications=microphone_history(),
    )
    (update,) = result.to_dict()["reliability_updates"]
    assert update["posterior_reliability"] == 0.575
    assert update["applied_reliability"] == 0.7
    assert update["adjustment"] == -0.2


def test_a_moved_weight_changes_the_digest() -> None:
    unmoved = evaluate(updating_policy(), two_source_events(), AS_OF)
    moved = evaluate(
        updating_policy(), two_source_events(), AS_OF, adjudications=microphone_history()
    )
    assert unmoved.digest != moved.digest


def test_html_report_shows_a_moved_reliability() -> None:
    moved = evaluate(
        updating_policy(), two_source_events(), AS_OF, adjudications=microphone_history()
    )
    report = render_html(moved)
    assert "Reliability updates" in report
    assert "-0.325" in report

    # A run that moved nothing must not grow an empty section.
    assert "Reliability updates" not in render_html(
        evaluate(updating_policy(), two_source_events(), AS_OF)
    )


# --- refused configurations and inputs -------------------------------------


def test_adjudications_without_a_configured_policy_are_refused() -> None:
    # Silently ignoring ground truth would make an operator believe a weight was
    # being maintained when nothing was reading it.
    with pytest.raises(ValidationError, match="does not configure reliability_updates"):
        evaluate(
            Policy.from_dict(policy_dict()),
            two_source_events(),
            AS_OF,
            adjudications=microphone_history(),
        )


@pytest.mark.parametrize(
    ("block", "message"),
    [
        ({"prior_weight": 0}, r"prior_weight must be finite"),
        ({"prior_weight": -1}, r"prior_weight must be finite"),
        ({"prior_weight": "4"}, r"prior_weight must be a number"),
        ({}, r"prior_weight must be a number"),
        ({"prior_weight": 4, "max_adjustment": 1.5}, r"max_adjustment must be finite"),
        ({"prior_weight": 4, "max_adjustment": -0.1}, r"max_adjustment must be finite"),
        ({"prior_weight": 4, "half_life": 2}, r"unknown field\(s\): 'half_life'"),
    ],
)
def test_an_invalid_update_block_is_refused(block: dict[str, Any], message: str) -> None:
    raw = policy_dict()
    raw["reliability_updates"] = block
    with pytest.raises(ValidationError, match=message):
        Policy.from_dict(raw)


def test_a_non_object_update_block_is_refused() -> None:
    raw = policy_dict()
    raw["reliability_updates"] = 4
    with pytest.raises(ValidationError, match="must be an object"):
        Policy.from_dict(raw)


def test_direct_construction_validates_the_update_block() -> None:
    with pytest.raises(ValidationError, match="prior_weight"):
        ReliabilityUpdatePolicy(0)
    with pytest.raises(ValidationError, match="max_adjustment"):
        ReliabilityUpdatePolicy(4, 2.0)
    with pytest.raises(ValidationError, match="ReliabilityUpdatePolicy instance or null"):
        replace(Policy.from_dict(policy_dict()), reliability_updates={"prior_weight": 4})


def test_duplicate_adjudicated_event_ids_are_refused() -> None:
    with pytest.raises(ValidationError, match=r"duplicate adjudicated event_id\(s\): m1"):
        evaluate(
            updating_policy(),
            two_source_events(),
            AS_OF,
            adjudications=[adjudication("m1"), adjudication("m1", verdict="correct")],
        )


def test_an_undeclared_adjudicated_source_is_refused() -> None:
    with pytest.raises(ValidationError, match=r"missing from policy\.sources: microphone-b"):
        evaluate(
            updating_policy(),
            two_source_events(),
            AS_OF,
            adjudications=[adjudication("m1", source="microphone-b")],
        )


def test_an_adjudication_naming_the_wrong_source_is_refused() -> None:
    with pytest.raises(ValidationError, match="did not come from: e-mic"):
        evaluate(
            updating_policy(),
            two_source_events(),
            AS_OF,
            adjudications=[adjudication("e-mic", source="camera-a")],
        )


def test_an_adjudication_predating_its_own_evidence_is_refused() -> None:
    with pytest.raises(ValidationError, match="dated before the observation"):
        evaluate(
            updating_policy(),
            two_source_events(),
            AS_OF,
            adjudications=[adjudication("e-mic", adjudicated_at="2026-08-31T11:59:00Z")],
        )


def test_an_adjudication_for_an_event_outside_the_window_is_accepted() -> None:
    # Ground truth outlives the evidence retention window, so an adjudication
    # whose event is no longer in the stream still counts.
    result = evaluate(updating_policy(), [], AS_OF, adjudications=[adjudication("m1")])
    assert result.reliability_updates[0].incorrect_event_ids == ("m1",)


def test_an_event_in_the_current_window_can_be_adjudicated() -> None:
    # The judged observation is still in the stream, its source agrees with the
    # policy, and the judgement is dated after ingestion, so it simply counts:
    #   (4 * 0.9 + 0) / (4 + 1) = 3.6 / 5 = 0.72
    result = evaluate(
        updating_policy(),
        two_source_events(),
        AS_OF,
        adjudications=[adjudication("e-mic", adjudicated_at="2026-08-31T11:59:45Z")],
    )
    assert result.reliability_updates[0].applied_reliability == 0.72
    assert trace_for(result, "e-mic").source_reliability == 0.72


@pytest.mark.parametrize("value", [None, "m1", {"event_id": "m1"}])
def test_a_non_adjudication_input_is_refused(value: Any) -> None:
    with pytest.raises(ValidationError, match=r"adjudications\[0\] must be an Adjudication"):
        evaluate(updating_policy(), two_source_events(), AS_OF, adjudications=[value])


def test_validating_adjudications_requires_a_policy() -> None:
    with pytest.raises(ValidationError, match="policy must be a Policy instance"):
        validate_adjudication_set(policy_dict(), [], [])


# --- the adjudication model ------------------------------------------------


def test_adjudication_round_trips_through_json() -> None:
    raw = adjudication_dict("m1", verdict="correct")
    assert Adjudication.from_dict(raw).to_dict() == raw


def test_adjudication_normalizes_its_timestamp() -> None:
    item = adjudication("m1", adjudicated_at="2026-08-31T13:59:40+02:00")
    assert item.to_dict()["adjudicated_at"] == "2026-08-31T11:59:40Z"


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("event_id", "", "event_id must be a non-empty string"),
        ("source", " ", "source must be a non-empty string"),
        ("verdict", "maybe", "verdict must be one of: correct, incorrect"),
        ("adjudicated_at", "yesterday", "adjudicated_at is not a valid ISO-8601"),
    ],
)
def test_a_malformed_adjudication_is_refused(field: str, value: Any, message: str) -> None:
    raw = adjudication_dict("m1")
    raw[field] = value
    with pytest.raises(ValidationError, match=message):
        Adjudication.from_dict(raw)


def test_an_adjudication_with_an_unknown_field_is_refused() -> None:
    raw = adjudication_dict("m1")
    raw["confidence"] = 0.5
    with pytest.raises(ValidationError, match=r"unknown field\(s\): 'confidence'"):
        Adjudication.from_dict(raw)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("verdict", "correct", "verdict must be one of"),
        ("adjudicated_at", "2026-08-31T11:59:40Z", "adjudicated_at must be a timezone-aware"),
    ],
)
def test_direct_adjudication_construction_validates_typed_fields(
    field: str, value: Any, message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        replace(adjudication("m1"), **{field: value})


def test_verdict_values_are_stable() -> None:
    assert [member.value for member in Verdict] == ["correct", "incorrect"]


# --- output-model invariants -----------------------------------------------


def valid_update_fields() -> dict[str, Any]:
    return {
        "source": "microphone-a",
        "declared_reliability": 0.9,
        "posterior_reliability": 0.575,
        "applied_reliability": 0.575,
        "adjustment": -0.325,
        "correct_count": 1,
        "incorrect_count": 3,
        "correct_event_ids": ("m4",),
        "incorrect_event_ids": ("m1", "m2", "m3"),
    }


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"correct_count": 2}, "counts do not match their event IDs"),
        ({"incorrect_count": 0}, "counts do not match their event IDs"),
        ({"correct_event_ids": ("m1",)}, "both correct and incorrect"),
        ({"adjustment": -0.3}, "must equal applied minus declared"),
        (
            {
                "correct_count": 0,
                "incorrect_count": 0,
                "correct_event_ids": (),
                "incorrect_event_ids": (),
                "declared_reliability": 0.575,
                "adjustment": 0.0,
            },
            "at least one adjudication",
        ),
    ],
)
def test_a_reliability_update_trace_cannot_misreport_itself(
    overrides: dict[str, Any], message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        ReliabilityUpdateTrace(**{**valid_update_fields(), **overrides})


def test_a_result_cannot_report_one_source_twice() -> None:
    result = evaluate(
        updating_policy(), two_source_events(), AS_OF, adjudications=microphone_history()
    )
    duplicate = result.reliability_updates[0]
    with pytest.raises(ValidationError, match="duplicate sources"):
        replace(result, reliability_updates=(duplicate, duplicate))


def test_a_result_rejects_a_foreign_reliability_record() -> None:
    result = evaluate(updating_policy(), two_source_events(), AS_OF)
    with pytest.raises(ValidationError, match="ReliabilityUpdateTrace instance"):
        replace(result, reliability_updates=({"source": "microphone-a"},))


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"correct_event_ids": ("m1",)}, "both correct and incorrect"),
        ({"correct_event_ids": (), "incorrect_event_ids": ()}, "at least one adjudication"),
    ],
)
def test_an_internal_adjustment_validates_its_own_identities(
    overrides: dict[str, Any], message: str
) -> None:
    fields: dict[str, Any] = {
        "source": "microphone-a",
        "declared_reliability": 0.9,
        "posterior_reliability": 0.575,
        "applied_reliability": 0.575,
        "correct_event_ids": ("m4",),
        "incorrect_event_ids": ("m1", "m2", "m3"),
    }
    with pytest.raises(ValidationError, match=message):
        ReliabilityAdjustment(**{**fields, **overrides})


# --- adapters and the command line -----------------------------------------


def test_load_adjudications_reads_jsonl(tmp_path: Path) -> None:
    path = tmp_path / "truth.jsonl"
    path.write_text(
        "\n".join(json.dumps(adjudication_dict(f"m{index}")) for index in range(3)) + "\n",
        encoding="utf-8",
    )
    assert [item.event_id for item in load_adjudications(path)] == ["m0", "m1", "m2"]


def test_load_adjudications_reports_the_offending_line(tmp_path: Path) -> None:
    path = tmp_path / "truth.jsonl"
    raw = adjudication_dict("m1")
    raw["verdict"] = "maybe"
    path.write_text(json.dumps(adjudication_dict("m0")) + "\n" + json.dumps(raw) + "\n", "utf-8")
    with pytest.raises(ValidationError, match=r"adjudications\[2\]\.verdict"):
        load_adjudications(path)


def test_load_adjudications_wraps_a_malformed_line(tmp_path: Path) -> None:
    path = tmp_path / "truth.jsonl"
    path.write_text("{oops}\n", encoding="utf-8")
    with pytest.raises(InputFormatError, match="line 1"):
        load_adjudications(path)


def _cli_inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    policy_path = tmp_path / "policy.json"
    event_path = tmp_path / "events.jsonl"
    truth_path = tmp_path / "truth.jsonl"
    policy_path.write_text(json.dumps(updating_policy_dict()), encoding="utf-8")
    event_path.write_text(
        "\n".join(
            json.dumps(item)
            for item in (
                event_dict("e-cam", source="camera-a", modality="vision"),
                event_dict("e-mic", source="microphone-a", modality="audio"),
            )
        )
        + "\n",
        encoding="utf-8",
    )
    truth_path.write_text(
        "\n".join(
            json.dumps(adjudication_dict(item.event_id, verdict=item.verdict.value))
            for item in microphone_history()
        )
        + "\n",
        encoding="utf-8",
    )
    return policy_path, event_path, truth_path


def test_cli_evaluate_applies_supplied_ground_truth(tmp_path: Path) -> None:
    policy_path, event_path, truth_path = _cli_inputs(tmp_path)
    output = tmp_path / "decision.json"
    code = run(
        [
            "evaluate",
            str(policy_path),
            str(event_path),
            "--as-of",
            "2026-08-31T12:00:00Z",
            "--output",
            str(output),
            "--adjudications",
            str(truth_path),
        ]
    )
    assert code == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["reliability_updates"] == [
        {
            "source": "microphone-a",
            "declared_reliability": 0.9,
            "posterior_reliability": 0.575,
            "applied_reliability": 0.575,
            "adjustment": -0.325,
            "correct_count": 1,
            "incorrect_count": 3,
            "correct_event_ids": ["m4"],
            "incorrect_event_ids": ["m1", "m2", "m3"],
        }
    ]


def test_cli_replay_applies_supplied_ground_truth(tmp_path: Path) -> None:
    policy_path, event_path, truth_path = _cli_inputs(tmp_path)
    output = tmp_path / "replay.jsonl"
    code = run(
        [
            "replay",
            str(policy_path),
            str(event_path),
            "--output",
            str(output),
            "--adjudications",
            str(truth_path),
        ]
    )
    assert code == 0
    snapshots = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert [len(item["reliability_updates"]) for item in snapshots] == [0, 1]


def test_cli_reports_ground_truth_a_policy_never_asked_for(tmp_path: Path, capsys: Any) -> None:
    policy_path, event_path, truth_path = _cli_inputs(tmp_path)
    policy_path.write_text(json.dumps(policy_dict()), encoding="utf-8")
    code = run(
        [
            "evaluate",
            str(policy_path),
            str(event_path),
            "--as-of",
            "2026-08-31T12:00:00Z",
            "--adjudications",
            str(truth_path),
        ]
    )
    assert code == 2
    assert "does not configure reliability_updates" in capsys.readouterr().err
