from __future__ import annotations

from dataclasses import replace
from datetime import datetime

import pytest

from evidence_braid.baselines import BaselineDecision, majority_vote, reliability_weighted_vote
from evidence_braid.errors import ValidationError
from evidence_braid.io import canonical_json
from evidence_braid.models import Outcome

AS_OF = datetime.fromisoformat("2026-08-31T12:00:00+00:00")


def test_majority_vote_is_count_based_and_explainable(policy, make_event) -> None:
    events = [
        make_event("support-a", confidence=0.1),
        make_event("support-b", confidence=0.1, source="unknown"),
        make_event("against", signal="contradict", confidence=1.0),
    ]

    decision = majority_vote(policy, events, AS_OF)[0]

    assert decision.outcome is Outcome.ESCALATE
    assert decision.support_mass == 2
    assert decision.contradict_mass == 1
    assert decision.support_probability == pytest.approx(2 / 3)
    assert decision.event_count == 3
    assert decision.to_dict()["method"] == "majority_vote"


def test_reliability_weighted_vote_can_disagree_with_majority(policy, make_event) -> None:
    events = [
        make_event("support-a", confidence=0.1),
        make_event("support-b", confidence=0.1, source="unknown"),
        make_event("against", signal="contradict", confidence=1.0),
    ]

    first = reliability_weighted_vote(policy, events, AS_OF)[0]
    shuffled = reliability_weighted_vote(policy, list(reversed(events)), AS_OF)[0]

    assert first == shuffled
    assert first.outcome is Outcome.REJECT
    assert first.support_mass == 0.18
    assert first.contradict_mass == 1.0
    assert first.support_probability == pytest.approx(0.18 / 1.18)


@pytest.mark.parametrize("method", [majority_vote, reliability_weighted_vote])
def test_baseline_abstains_without_visible_evidence(policy, make_event, method) -> None:
    future = make_event("future", ingested_at="2026-08-31T12:00:01Z")

    decision = method(policy, [future], AS_OF)[0]

    assert decision.outcome is Outcome.REVIEW
    assert decision.support_probability == 0.5
    assert decision.event_count == 0


def test_baselines_validate_the_same_stream_invariants(policy, make_event) -> None:
    event = make_event()
    with pytest.raises(ValidationError, match="duplicate"):
        majority_vote(policy, [event, event], AS_OF)
    with pytest.raises(ValidationError, match="UTC offset"):
        reliability_weighted_vote(policy, [event], datetime(2026, 8, 31))


def test_baseline_accepts_an_event_generator(policy, make_event) -> None:
    decision = majority_vote(policy, (make_event(str(index)) for index in range(2)), AS_OF)[0]
    assert decision.event_count == 2


def test_baseline_direct_model_stabilizes_floats_and_serializes_strictly() -> None:
    decision = BaselineDecision(
        "incident",
        "reliability_weighted_vote",
        Outcome.REJECT,
        -0.0,
        0.1234567890129,
        -0.0,
        1,
    )

    assert decision.support_mass == 0.0
    assert decision.contradict_mass == 0.123456789013
    assert decision.support_probability == 0.0
    assert "-0.0" not in canonical_json(decision.to_dict())


def test_weighted_zero_mass_event_has_review_and_neutral_probability(policy, make_event) -> None:
    decision = reliability_weighted_vote(policy, [make_event(confidence=0.0)], AS_OF)[0]

    assert decision.event_count == 1
    assert decision.support_mass == 0.0
    assert decision.contradict_mass == 0.0
    assert decision.outcome is Outcome.REVIEW
    assert decision.support_probability == 0.5


def test_weighted_direct_mass_accepts_physical_boundary() -> None:
    decision = BaselineDecision(
        "incident",
        "reliability_weighted_vote",
        Outcome.REJECT,
        0.4,
        0.6,
        0.4,
        1,
    )

    assert decision.support_mass + decision.contradict_mass == 1.0


def test_weighted_direct_mass_rejects_value_beyond_event_count() -> None:
    with pytest.raises(ValidationError, match="cannot exceed event_count"):
        BaselineDecision(
            "incident",
            "reliability_weighted_vote",
            Outcome.ESCALATE,
            1.000000000002,
            0,
            1,
            1,
        )


def test_weighted_direct_mass_allows_one_stabilized_unit_of_rounding() -> None:
    decision = BaselineDecision(
        "incident",
        "reliability_weighted_vote",
        Outcome.ESCALATE,
        0.5000000000006,
        0.4999999999996,
        0.5,
        1,
    )

    assert decision.support_mass == 0.500000000001
    assert decision.contradict_mass == 0.5
    assert decision.support_mass + decision.contradict_mass == 1.000000000001


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("claim", " bad "),
        ("method", "unknown"),
        ("method", []),
        ("outcome", "escalate"),
        ("support_mass", -1),
        ("support_mass", float("inf")),
        ("contradict_mass", True),
        ("support_probability", -0.1),
        ("support_probability", float("nan")),
        ("event_count", -1),
        ("event_count", True),
        ("event_count", 10**641),
        pytest.param("support_mass", 10**10000, id="huge-support-mass"),
        ("claim", "bad\ud800"),
    ],
)
def test_baseline_decision_rejects_invalid_direct_state(field: str, value: object) -> None:
    decision = BaselineDecision("incident", "majority_vote", Outcome.REVIEW, 0, 0, 0.5, 0)
    with pytest.raises(ValidationError):
        replace(decision, **{field: value})


@pytest.mark.parametrize(
    "decision",
    [
        BaselineDecision("incident", "majority_vote", Outcome.REVIEW, 0, 0, 0.5, 0),
    ],
)
def test_baseline_valid_direct_reference(decision: BaselineDecision) -> None:
    assert decision.to_dict()["outcome"] == "review"


@pytest.mark.parametrize(
    "changes",
    [
        {"outcome": Outcome.ESCALATE},
        {"support_probability": 0.4},
        {"support_mass": 0.5, "event_count": 1},
        {"support_mass": 1, "event_count": 0},
        {"support_mass": 1, "event_count": 2},
    ],
)
def test_baseline_decision_rejects_cross_field_inconsistency(changes: dict[str, object]) -> None:
    decision = BaselineDecision("incident", "majority_vote", Outcome.REVIEW, 0, 0, 0.5, 0)
    with pytest.raises(ValidationError, match=r"inconsistent|whole|sum|zero"):
        replace(decision, **changes)


def test_baseline_decision_rejects_overflowed_total_mass() -> None:
    with pytest.raises(ValidationError, match="sum must be finite"):
        BaselineDecision(
            "incident",
            "reliability_weighted_vote",
            Outcome.REVIEW,
            1e308,
            1e308,
            0.5,
            1,
        )
