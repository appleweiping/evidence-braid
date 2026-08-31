from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta, timezone

import pytest
from conftest import policy_dict

from evidence_braid.decay import weight_event
from evidence_braid.engine import CorrelationTrace, EvaluationResult, EventTrace, evaluate
from evidence_braid.errors import ValidationError
from evidence_braid.grouping import collapse_correlated
from evidence_braid.models import Outcome, Policy, Signal

AS_OF = datetime(2026, 8, 31, 12, 0, tzinfo=UTC)


def test_half_life_halves_confidence(policy, make_event) -> None:
    weighted = weight_event(
        make_event(confidence=1.0, observed_at="2026-08-31T11:59:00Z"), policy, AS_OF
    )
    assert weighted.decay_factor == pytest.approx(0.5)
    assert weighted.effective_confidence == pytest.approx(0.5)


def test_modality_specific_half_life(policy, make_event) -> None:
    event = make_event(modality="sensor", confidence=1.0, observed_at="2026-08-31T11:58:00Z")
    assert weight_event(event, policy, AS_OF).effective_confidence == pytest.approx(0.5)


def test_source_reliability_scales_confidence(policy, make_event) -> None:
    event = make_event(
        source="unknown",
        confidence=1.0,
        observed_at="2026-08-31T12:00:00Z",
        ingested_at="2026-08-31T12:00:00Z",
    )
    assert weight_event(event, policy, AS_OF).effective_confidence == pytest.approx(0.8)


def test_small_allowed_future_skew_does_not_amplify(policy, make_event) -> None:
    event = make_event(observed_at="2026-08-31T12:00:01Z", ingested_at="2026-08-31T11:59:59Z")
    assert weight_event(event, policy, AS_OF).decay_factor == 1.0
    assert evaluate(policy, [event], AS_OF).considered_event_count == 1


def test_future_event_beyond_skew_rejected(policy, make_event) -> None:
    event = make_event(observed_at="2026-08-31T12:00:03Z", ingested_at="2026-08-31T11:59:59Z")
    with pytest.raises(ValidationError, match="future"):
        evaluate(policy, [event], AS_OF)


def test_weighting_defensively_rejects_future_evaluation_skew(policy, make_event) -> None:
    event = make_event(
        observed_at="2026-08-31T12:00:03Z",
        ingested_at="2026-08-31T12:00:03Z",
    )
    with pytest.raises(ValidationError, match="future"):
        weight_event(event, policy, AS_OF)


def test_clock_skew_is_rejected_even_when_evaluated_later(policy, make_event) -> None:
    event = make_event(
        observed_at="2026-08-31T12:00:04Z",
        ingested_at="2026-08-31T12:00:00Z",
    )
    later = datetime(2026, 8, 31, 12, 5, tzinfo=UTC)
    with pytest.raises(ValidationError, match="future of ingestion"):
        evaluate(policy, [event], later)


def test_correlated_events_collapse_to_strongest(policy, make_event) -> None:
    weak = weight_event(
        make_event("weak", confidence=0.5, correlation_group="frame-a"), policy, AS_OF
    )
    strong = weight_event(
        make_event("strong", confidence=0.9, correlation_group="frame-a"), policy, AS_OF
    )
    selection = collapse_correlated([weak, strong])[0]
    assert selection.representative.event.event_id == "strong"
    assert [item.event.event_id for item in selection.suppressed] == ["weak"]


def test_correlation_tie_break_is_input_order_independent(policy, make_event) -> None:
    a = weight_event(make_event("a", correlation_group="same"), policy, AS_OF)
    b = weight_event(make_event("b", correlation_group="same"), policy, AS_OF)
    assert collapse_correlated([b, a]) == collapse_correlated([a, b])
    assert collapse_correlated([b, a])[0].representative.event.event_id == "a"


def test_correlation_comparison_uses_public_stable_precision(policy, make_event) -> None:
    a = weight_event(
        make_event(
            "a",
            confidence=0.90000000000003,
            correlation_group="same",
            observed_at="2026-08-31T12:00:00Z",
            ingested_at="2026-08-31T12:00:00Z",
        ),
        policy,
        AS_OF,
    )
    b = weight_event(
        make_event(
            "b",
            confidence=0.90000000000004,
            correlation_group="same",
            observed_at="2026-08-31T12:00:00Z",
            ingested_at="2026-08-31T12:00:00Z",
        ),
        policy,
        AS_OF,
    )
    assert a.effective_confidence != b.effective_confidence
    assert round(a.effective_confidence, 12) == round(b.effective_confidence, 12)

    forward = collapse_correlated([a, b])[0]
    reverse = collapse_correlated([b, a])[0]
    assert forward == reverse
    assert forward.representative.event.event_id == "a"


def test_internal_weight_and_selection_models_reject_mutable_or_invalid_state(
    policy, make_event
) -> None:
    representative = weight_event(
        make_event("representative", correlation_group="same"),
        policy,
        AS_OF,
    )
    suppressed = weight_event(
        make_event("suppressed", confidence=0.5, correlation_group="same"),
        policy,
        AS_OF,
    )
    selection = collapse_correlated([suppressed, representative])[0]
    supplied = list(selection.suppressed)
    copied = replace(selection, suppressed=supplied)
    supplied.clear()
    assert [item.event.event_id for item in copied.suppressed] == ["suppressed"]

    with pytest.raises(ValidationError, match="effective_confidence"):
        replace(representative, effective_confidence=float("inf"))
    with pytest.raises(ValidationError, match="EvidenceEvent"):
        replace(representative, event="bad")
    with pytest.raises(ValidationError, match="representative"):
        replace(selection, representative="bad")
    with pytest.raises(ValidationError, match=r"suppressed\[0\]"):
        replace(selection, suppressed=["bad"])
    with pytest.raises(ValidationError, match="selection signal"):
        replace(selection, signal=Signal.CONTRADICT)
    with pytest.raises(ValidationError, match="correlation group"):
        replace(selection, suppressed=[weight_event(make_event("other"), policy, AS_OF)])
    with pytest.raises(ValidationError, match="duplicate event IDs"):
        replace(selection, suppressed=[selection.representative])
    with pytest.raises(ValidationError, match="sequence"):
        replace(selection, suppressed="bad")


def test_two_independent_modalities_escalate(make_event) -> None:
    policy = Policy.from_dict(policy_dict(support_threshold=0.7))
    events = [
        make_event("vision", confidence=0.9),
        make_event("audio", modality="audio", source="microphone-a", confidence=0.9),
    ]
    decision = evaluate(policy, events, AS_OF).decisions[0]
    assert decision.outcome is Outcome.ESCALATE
    assert decision.support.qualifying_groups == 2


def test_high_score_without_modality_diversity_reviews(make_event) -> None:
    policy = Policy.from_dict(policy_dict(support_threshold=0.7))
    events = [make_event("a", confidence=0.95), make_event("b", source="camera-b", confidence=0.95)]
    decision = evaluate(policy, events, AS_OF).decisions[0]
    assert decision.outcome is Outcome.REVIEW
    assert decision.reason == "support_score_met_but_independence_gate_failed"


def test_high_score_without_source_diversity_reviews(make_event) -> None:
    events = [make_event("a", confidence=0.95), make_event("b", modality="audio", confidence=0.95)]
    decision = evaluate(Policy.from_dict(policy_dict()), events, AS_OF).decisions[0]
    assert decision.outcome is Outcome.REVIEW
    assert decision.support.qualifying_sources == ("camera-a",)


def test_high_contradiction_score_without_diversity_reviews(make_event) -> None:
    policy = Policy.from_dict(policy_dict(contradiction_threshold=0.7))
    events = [
        make_event("a", signal="contradict", confidence=0.95),
        make_event("b", signal="contradict", source="camera-b", confidence=0.95),
    ]
    decision = evaluate(policy, events, AS_OF).decisions[0]
    assert decision.outcome is Outcome.REVIEW
    assert decision.reason == "contradiction_score_met_but_independence_gate_failed"


def test_copies_in_one_group_do_not_satisfy_quorum(make_event) -> None:
    events = [
        make_event("a", confidence=0.99, correlation_group="shared"),
        make_event(
            "b",
            modality="audio",
            source="microphone-a",
            confidence=0.99,
            correlation_group="shared",
        ),
    ]
    decision = evaluate(Policy.from_dict(policy_dict()), events, AS_OF).decisions[0]
    assert decision.support.qualifying_groups == 1
    assert decision.outcome is Outcome.REVIEW


def test_strong_independent_contradictions_reject(make_event) -> None:
    events = [
        make_event("vision", signal="contradict", confidence=0.95),
        make_event(
            "operator", modality="text", source="operator-a", signal="contradict", confidence=0.95
        ),
    ]
    decision = evaluate(Policy.from_dict(policy_dict()), events, AS_OF).decisions[0]
    assert decision.outcome is Outcome.REJECT


def test_conflicting_support_and_contradiction_review(make_event) -> None:
    policy = Policy.from_dict(policy_dict(min_margin=0.2))
    events = [
        make_event("s1", confidence=1.0),
        make_event("s2", modality="audio", source="microphone-a", confidence=1.0),
        make_event("c1", signal="contradict", confidence=1.0),
        make_event("c2", modality="text", source="operator-a", signal="contradict", confidence=1.0),
    ]
    decision = evaluate(policy, events, AS_OF).decisions[0]
    assert decision.outcome is Outcome.REVIEW
    assert decision.reason == "evidence_margin_too_small"


def test_exactly_balanced_zero_margin_thresholds_report_conflict(make_event) -> None:
    policy = Policy.from_dict(
        policy_dict(
            support_threshold=0.5,
            contradiction_threshold=0.5,
            min_margin=0,
            quorum=1,
            min_sources=1,
            min_modalities=1,
        )
    )
    events = [make_event("s", confidence=1.0), make_event("c", signal="contradict", confidence=1.0)]
    decision = evaluate(policy, events, AS_OF).decisions[0]
    assert decision.outcome is Outcome.REVIEW
    assert decision.reason == "conflicting_thresholds"


def test_below_threshold_with_clear_margin_reports_threshold(make_event) -> None:
    policy = Policy.from_dict(
        policy_dict(
            support_threshold=0.9,
            min_margin=0.1,
            quorum=1,
            min_sources=1,
            min_modalities=1,
        )
    )
    event = make_event(
        confidence=0.2, observed_at="2026-08-31T12:00:00Z", ingested_at="2026-08-31T12:00:00Z"
    )
    decision = evaluate(policy, [event], AS_OF).decisions[0]
    assert decision.reason == "decision_threshold_not_met"


def test_threshold_boundary_is_inclusive(make_event) -> None:
    policy = Policy.from_dict(
        policy_dict(support_threshold=0.75, quorum=1, min_sources=1, min_modalities=1, min_margin=0)
    )
    event = make_event(
        confidence=0.75, observed_at="2026-08-31T12:00:00Z", ingested_at="2026-08-31T12:00:00Z"
    )
    assert evaluate(policy, [event], AS_OF).decisions[0].outcome is Outcome.ESCALATE


def test_comparisons_use_the_same_stable_precision_as_output(make_event) -> None:
    raw = policy_dict(
        support_threshold=0.78,
        min_evidence_confidence=0.78,
        quorum=1,
        min_sources=1,
        min_modalities=1,
        min_margin=0,
    )
    raw["decay"]["default_half_life_seconds"] = 10_000_000_000_000
    policy = Policy.from_dict(raw)
    event = make_event(
        confidence=0.78,
        observed_at="2026-08-31T11:59:59Z",
        ingested_at="2026-08-31T11:59:59Z",
    )

    decision = evaluate(policy, [event], AS_OF).decisions[0]

    assert decision.support.score == 0.78
    assert decision.support.qualifying_groups == 1
    assert decision.outcome is Outcome.ESCALATE


def test_minimum_evidence_boundary_is_inclusive(make_event) -> None:
    policy = Policy.from_dict(
        policy_dict(
            support_threshold=0.2,
            min_evidence_confidence=0.2,
            quorum=1,
            min_sources=1,
            min_modalities=1,
            min_margin=0,
        )
    )
    event = make_event(confidence=0.4, observed_at="2026-08-31T11:59:00Z")
    assert evaluate(policy, [event], AS_OF).decisions[0].support.qualifying_groups == 1


def test_event_not_ingested_yet_is_pending(policy, make_event) -> None:
    event = make_event(observed_at="2026-08-31T12:01:00Z", ingested_at="2026-08-31T12:02:00Z")
    result = evaluate(policy, [event], AS_OF)
    assert result.considered_event_count == 0
    assert result.pending_event_ids == ("e1",)


def test_evaluate_rejects_naive_as_of_as_domain_error(policy, make_event) -> None:
    with pytest.raises(ValidationError, match="UTC offset"):
        evaluate(policy, [make_event()], datetime(2026, 8, 31, 12, 0))


def test_evaluate_rejects_non_datetime_as_of_as_domain_error(policy) -> None:
    with pytest.raises(ValidationError, match="timezone-aware datetime"):
        evaluate(policy, [], "2026-08-31T12:00:00Z")  # type: ignore[arg-type]


def test_evaluate_rejects_unparsed_event_as_domain_error(policy) -> None:
    with pytest.raises(ValidationError, match=r"events\[0\]"):
        evaluate(policy, [{"event_id": "raw"}], AS_OF)  # type: ignore[list-item]


def test_evaluate_rejects_unparsed_policy_as_domain_error(make_event) -> None:
    with pytest.raises(ValidationError, match="Policy instance"):
        evaluate({}, [make_event()], AS_OF)  # type: ignore[arg-type]


def test_unknown_claim_rejected(policy, make_event) -> None:
    with pytest.raises(ValidationError, match="missing from policy"):
        evaluate(policy, [make_event(claim="other")], AS_OF)


def test_duplicate_event_id_rejected(policy, make_event) -> None:
    with pytest.raises(ValidationError, match="duplicate event_id"):
        evaluate(policy, [make_event(), make_event()], AS_OF)


def test_evaluation_is_deterministic_across_input_order(policy, make_event) -> None:
    events = [make_event("z"), make_event("a", modality="audio", source="microphone-a")]
    first = evaluate(policy, events, AS_OF)
    second = evaluate(policy, reversed(events), AS_OF)
    assert first.to_dict() == second.to_dict()
    assert first.digest == second.digest


def test_negative_zero_has_one_output_and_digest_representation(policy, make_event) -> None:
    positive = evaluate(policy, [make_event(confidence=0.0)], AS_OF)
    negative = evaluate(policy, [make_event(confidence=-0.0)], AS_OF)

    assert negative.to_dict() == positive.to_dict()
    assert negative.digest == positive.digest
    assert "-0.0" not in str(negative.to_dict())

    decision = negative.decisions[0]
    trace = replace(
        decision.trace[0],
        raw_confidence=-0.0,
        source_reliability=-0.0,
        age_seconds=-0.0,
        decay_factor=-0.0,
        effective_confidence=-0.0,
    )
    correlation = replace(decision.correlations[0], effective_confidence=-0.0)
    copied = replace(
        negative,
        decisions=(
            replace(
                decision,
                support=replace(decision.support, score=-0.0),
                contradict=replace(decision.contradict, score=-0.0),
                margin=-0.0,
                trace=(trace,),
                correlations=(correlation,),
            ),
        ),
    )
    assert "-0.0" not in str(copied.to_dict())


def test_decision_trace_is_deeply_immutable_and_serialization_is_detached(
    policy, make_event
) -> None:
    events = [
        make_event("strong", confidence=0.9, correlation_group="same"),
        make_event("weak", confidence=0.5, correlation_group="same"),
    ]
    result = evaluate(policy, events, AS_OF)
    decision = result.decisions[0]
    original_digest = result.digest

    with pytest.raises(FrozenInstanceError):
        decision.trace[0].effective_confidence = 0.0  # type: ignore[misc]
    with pytest.raises(TypeError):
        decision.correlations[0].suppressed_event_ids[0] = "changed"  # type: ignore[index]

    public = decision.to_dict()
    public["trace"][0]["effective_confidence"] = 0.0
    public["correlations"][0]["suppressed_event_ids"][0] = "changed"
    assert result.digest == original_digest
    assert result.decisions[0].trace[0].effective_confidence != 0.0
    assert result.decisions[0].correlations[0].suppressed_event_ids == ("weak",)


def test_no_evidence_produces_review(policy) -> None:
    decision = evaluate(policy, [], AS_OF).decisions[0]
    assert decision.outcome is Outcome.REVIEW
    assert decision.reason == "evidence_margin_too_small"


def test_output_models_snapshot_replace_collections(policy, make_event) -> None:
    first = make_event("first", correlation_group="same")
    second = make_event("second", confidence=0.5, correlation_group="same")
    result = evaluate(policy, [first, second], AS_OF)
    decision = result.decisions[0]

    sources = list(decision.support.qualifying_sources)
    summary = replace(decision.support, qualifying_sources=sources)
    sources.append("late-mutation")
    assert "late-mutation" not in summary.qualifying_sources

    trace = list(decision.trace)
    correlations = list(decision.correlations)
    copied_decision = replace(decision, trace=trace, correlations=correlations)
    trace.clear()
    correlations.clear()
    assert len(copied_decision.trace) == 2
    assert len(copied_decision.correlations) == 1

    pending = ["pending"]
    decisions = list(result.decisions)
    copied_result = replace(
        result,
        input_event_count=3,
        pending_event_ids=pending,
        decisions=decisions,
    )
    pending.clear()
    decisions.clear()
    assert copied_result.pending_event_ids == ("pending",)
    assert len(copied_result.decisions) == 1


def test_nested_output_models_snapshot_and_canonicalize_sequences(policy, make_event) -> None:
    result = evaluate(
        policy,
        [
            make_event("z", correlation_group="same"),
            make_event("a", confidence=0.5, correlation_group="same"),
        ],
        AS_OF,
    )
    decision = result.decisions[0]
    correlation = decision.correlations[0]

    suppressed = list(reversed(correlation.suppressed_event_ids))
    copied_correlation = replace(correlation, suppressed_event_ids=suppressed)
    suppressed.append("later")
    assert copied_correlation.suppressed_event_ids == ("a",)

    unsorted_trace = list(reversed(decision.trace))
    copied_decision = replace(decision, trace=unsorted_trace)
    assert [event.event_id for event in copied_decision.trace] == ["a", "z"]


@pytest.mark.parametrize(
    "mutation",
    [
        lambda result: replace(result.decisions[0].support, gate_passed=1),
        lambda result: replace(result.decisions[0].support, qualifying_groups=99),
        lambda result: replace(
            result.decisions[0].support,
            qualifying_modalities=["thermal"],
        ),
        lambda result: replace(result.decisions[0].support, group_ids=[" bad "]),
        lambda result: replace(result.decisions[0].trace[0], source_reliability=float("nan")),
        lambda result: replace(result.decisions[0].trace[0], modality="thermal"),
        lambda result: replace(result.decisions[0].correlations[0], signal="maybe"),
        lambda result: replace(
            result.decisions[0].correlations[0],
            suppressed_event_ids=[result.decisions[0].correlations[0].representative_event_id],
        ),
        lambda result: replace(result.decisions[0], support=result.decisions[0].contradict),
        lambda result: replace(result.decisions[0], contradict=result.decisions[0].support),
        lambda result: replace(
            result.decisions[0],
            trace=[replace(result.decisions[0].trace[0], claim="another")],
        ),
        lambda result: replace(
            result.decisions[0],
            trace=[result.decisions[0].trace[0], result.decisions[0].trace[0]],
        ),
        lambda result: replace(
            result.decisions[0],
            correlations=[
                result.decisions[0].correlations[0],
                result.decisions[0].correlations[0],
            ],
        ),
        lambda result: replace(result, considered_event_count=2),
        lambda result: replace(result, input_event_count=2),
        lambda result: replace(
            result,
            input_event_count=3,
            pending_event_ids=["pending", "pending"],
        ),
        lambda result: replace(result, input_event_count=0, considered_event_count=0),
        lambda result: replace(result, input_event_count=-1),
        lambda result: replace(result, decisions=[*result.decisions, *result.decisions]),
    ],
)
def test_output_models_reject_invalid_direct_state(policy, make_event, mutation) -> None:
    result = evaluate(policy, [make_event(correlation_group="same")], AS_OF)
    with pytest.raises(ValidationError):
        mutation(result)


def test_direct_trace_and_result_type_validation(policy, make_event) -> None:
    result = evaluate(policy, [make_event()], AS_OF)
    trace = result.decisions[0].trace[0]
    with pytest.raises(ValidationError, match="signal"):
        replace(trace, signal="maybe")
    with pytest.raises(ValidationError, match="sequence"):
        replace(result.decisions[0], trace="not-a-sequence")
    with pytest.raises(ValidationError, match=r"decisions\[0\]"):
        replace(result, decisions=["not-a-decision"])
    with pytest.raises(ValidationError, match="schema_version"):
        replace(result, schema_version=True)


def test_direct_output_constructor_normalizes_timezone_and_rejects_wrong_types(
    policy, make_event
) -> None:
    result = evaluate(policy, [make_event()], AS_OF)
    shifted = replace(result, evaluated_at=AS_OF.astimezone(timezone(timedelta(hours=3))))
    assert shifted.evaluated_at == AS_OF

    trace = result.decisions[0].trace[0]
    with pytest.raises(ValidationError):
        EventTrace(
            event_id=trace.event_id,
            claim=trace.claim,
            signal=trace.signal,
            modality=trace.modality,
            source=trace.source,
            correlation_group=None,
            raw_confidence=0.5,
            source_reliability=0.5,
            age_seconds=-1,
            decay_factor=0.5,
            effective_confidence=0.25,
        )
    with pytest.raises(ValidationError):
        CorrelationTrace("group:x", "support", "e", 0.5, "not-a-sequence")
    with pytest.raises(ValidationError):
        EvaluationResult(1, "p", AS_OF, 0, 0, (), ("not-a-decision",))  # type: ignore[arg-type]
