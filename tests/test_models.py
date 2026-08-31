from __future__ import annotations

import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from math import copysign
from types import MappingProxyType

import pytest
from conftest import event_dict, policy_dict

from evidence_braid.errors import InputFormatError, ValidationError
from evidence_braid.io import canonical_json
from evidence_braid.models import (
    MAX_ATTRIBUTE_DEPTH,
    MAX_ATTRIBUTE_INTEGER_DIGITS,
    ClaimRule,
    DecayPolicy,
    EvidenceEvent,
    Modality,
    Policy,
    Signal,
    SourcePolicy,
    format_timestamp,
    parse_timestamp,
)


def test_event_parses_and_normalizes_timestamp() -> None:
    event = EvidenceEvent.from_dict(event_dict(observed_at="2026-08-31T13:59:30+02:00"))
    assert event.observed_at == datetime(2026, 8, 31, 11, 59, 30, tzinfo=UTC)
    assert event.modality is Modality.VISION
    assert event.signal is Signal.SUPPORT


def test_event_round_trip_preserves_public_data() -> None:
    raw = event_dict(
        correlation_group="cam-frame-7",
        attributes={"region": "north", "bounds": [1, {"confidence": 0.5}]},
    )
    assert EvidenceEvent.from_dict(raw).to_dict() == raw


@pytest.mark.parametrize("confidence", [-0.01, 1.01, float("inf"), "0.5", True])
def test_event_rejects_invalid_confidence(confidence: object) -> None:
    with pytest.raises(ValidationError, match="confidence"):
        EvidenceEvent.from_dict(event_dict(confidence=confidence))


@pytest.mark.parametrize("field", ["event_id", "claim", "source"])
def test_event_rejects_empty_required_string(field: str) -> None:
    with pytest.raises(ValidationError, match=field):
        EvidenceEvent.from_dict(event_dict(**{field: " "}))


def test_event_rejects_non_string_identifier() -> None:
    with pytest.raises(ValidationError, match="event_id"):
        EvidenceEvent.from_dict(event_dict(event_id=None))


@pytest.mark.parametrize("text", ["bad\x00id", "bad\ud800id", "bad\ufffeid"])
def test_event_rejects_text_that_cannot_be_rendered_safely(text: str) -> None:
    with pytest.raises(ValidationError, match=r"XML 1\.0"):
        EvidenceEvent.from_dict(event_dict(event_id=text))


def test_event_rejects_invalid_correlation_group_text() -> None:
    with pytest.raises(ValidationError, match="correlation_group"):
        EvidenceEvent.from_dict(event_dict(correlation_group="group\x01"))


def test_event_rejects_naive_timestamp() -> None:
    with pytest.raises(ValidationError, match="UTC offset"):
        EvidenceEvent.from_dict(event_dict(observed_at="2026-08-31T12:00:00"))


def test_timestamp_rejects_non_string() -> None:
    with pytest.raises(ValidationError, match="ISO-8601 string"):
        parse_timestamp(None, "test")


def test_event_allows_independent_source_clock_ahead() -> None:
    event = EvidenceEvent.from_dict(
        event_dict(
            observed_at="2026-08-31T12:00:01Z",
            ingested_at="2026-08-31T11:59:59Z",
        )
    )
    assert event.observed_at > event.ingested_at


def test_event_rejects_unknown_field() -> None:
    with pytest.raises(ValidationError, match=r"unknown field.*typo"):
        EvidenceEvent.from_dict(event_dict(typo=1))


def test_event_rejects_invalid_modality() -> None:
    with pytest.raises(ValidationError, match="modality"):
        EvidenceEvent.from_dict(event_dict(modality="thermal"))


def test_event_rejects_invalid_signal() -> None:
    with pytest.raises(ValidationError, match="signal"):
        EvidenceEvent.from_dict(event_dict(signal="maybe"))


def test_policy_rejects_unknown_schema_version() -> None:
    raw = policy_dict()
    raw["schema_version"] = 2
    with pytest.raises(ValidationError, match="schema_version"):
        Policy.from_dict(raw)


@pytest.mark.parametrize("version", [True, 1.0, "1", None])
def test_policy_schema_version_requires_exact_integer(version: object) -> None:
    raw = policy_dict()
    raw["schema_version"] = version
    with pytest.raises(ValidationError, match="schema_version"):
        Policy.from_dict(raw)


def test_policy_rejects_noncanonical_mapping_name() -> None:
    raw = policy_dict()
    raw["sources"][" camera-b "] = {"reliability": 1.0}
    with pytest.raises(ValidationError, match="leading or trailing"):
        Policy.from_dict(raw)


def test_policy_rejects_unrenderable_identifier() -> None:
    raw = policy_dict()
    raw["policy_id"] = "bad\ud800policy"
    with pytest.raises(ValidationError, match=r"XML 1\.0"):
        Policy.from_dict(raw)


def test_policy_requires_claim() -> None:
    raw = policy_dict()
    raw["claims"] = {}
    with pytest.raises(ValidationError, match="at least one"):
        Policy.from_dict(raw)


def test_policy_requires_object() -> None:
    with pytest.raises(ValidationError, match="must be an object"):
        Policy.from_dict([])


def test_python_mapping_keys_must_be_strings() -> None:
    raw = policy_dict()
    raw["sources"] = {1: {"reliability": 1.0}}
    with pytest.raises(ValidationError, match="keys must be strings"):
        Policy.from_dict(raw)


def test_policy_rejects_invalid_half_life() -> None:
    raw = policy_dict()
    raw["decay"]["default_half_life_seconds"] = 0
    with pytest.raises(ValidationError, match="half_life"):
        Policy.from_dict(raw)


def test_policy_rejects_threshold_above_one() -> None:
    with pytest.raises(ValidationError, match="support_threshold"):
        Policy.from_dict(policy_dict(support_threshold=1.01))


def test_policy_rejects_boolean_quorum() -> None:
    with pytest.raises(ValidationError, match="quorum"):
        Policy.from_dict(policy_dict(quorum=True))


def test_numeric_overflow_is_reported_as_validation_error() -> None:
    raw = policy_dict()
    raw["decay"]["default_half_life_seconds"] = 10**10_000
    with pytest.raises(ValidationError, match="finite number"):
        Policy.from_dict(raw)


def test_policy_rejects_unknown_modality_override() -> None:
    raw = policy_dict()
    raw["decay"]["modality_half_life_seconds"]["radar"] = 10
    with pytest.raises(ValidationError, match="unknown modality"):
        Policy.from_dict(raw)


def test_source_reliability_uses_configured_then_default() -> None:
    policy = Policy.from_dict(policy_dict())
    assert policy.reliability_for("camera-a") == 1.0
    assert policy.reliability_for("unknown") == 0.8


def test_format_timestamp_is_canonical_utc() -> None:
    value = parse_timestamp("2026-08-31T14:00:00+02:00", "test")
    assert format_timestamp(value) == "2026-08-31T12:00:00Z"


def test_format_timestamp_rejects_naive_datetime() -> None:
    with pytest.raises(ValidationError, match="UTC offset"):
        format_timestamp(datetime(2026, 8, 31, 12, 0))


def test_datetime_wraps_timezone_failures_as_validation_errors() -> None:
    class BrokenOffset(tzinfo):
        def utcoffset(self, value):
            raise ValueError("broken offset")

        def dst(self, value):
            return None

    class FlakyOffset(tzinfo):
        def __init__(self) -> None:
            self.calls = 0

        def utcoffset(self, value):
            self.calls += 1
            if self.calls > 1:
                raise ValueError("broken conversion")
            return timedelta(0)

        def dst(self, value):
            return timedelta(0)

    with pytest.raises(ValidationError, match="valid timezone-aware"):
        format_timestamp(datetime(2026, 8, 31, tzinfo=BrokenOffset()))
    with pytest.raises(ValidationError, match="valid timezone-aware"):
        format_timestamp(datetime(2026, 8, 31, tzinfo=FlakyOffset()))


def test_direct_event_and_replace_reject_datetime_subclasses(make_event) -> None:
    class MutableDateTime(datetime):
        def astimezone(self, timezone=None):
            return "not-a-datetime"

    supplied = MutableDateTime(2026, 8, 31, 12, tzinfo=UTC)
    supplied.mutable_state = []

    with pytest.raises(ValidationError, match="timezone-aware datetime"):
        EvidenceEvent(
            event_id="e",
            claim="incident",
            modality=Modality.VISION,
            source="camera-a",
            signal=Signal.SUPPORT,
            confidence=0.5,
            observed_at=supplied,
            ingested_at=datetime(2026, 8, 31, 12, tzinfo=UTC),
        )
    with pytest.raises(ValidationError, match="timezone-aware datetime"):
        replace(make_event(), observed_at=supplied)


@pytest.mark.parametrize(
    "attributes",
    [
        {"score": float("inf")},
        {"nested": [float("nan")]},
        {"not_json": (1, 2)},
        {"bad\x00key": "value"},
        {"value": "bad\x00text"},
    ],
)
def test_event_attributes_must_be_finite_strict_json(attributes: object) -> None:
    with pytest.raises(ValidationError, match=r"JSON|XML"):
        EvidenceEvent.from_dict(event_dict(attributes=attributes))


def test_event_attributes_are_recursively_immutable_and_detached() -> None:
    raw_attributes = {"nested": [{"score": 0.5}]}
    event = EvidenceEvent.from_dict(event_dict(attributes=raw_attributes))
    raw_attributes["nested"][0]["score"] = 0.1

    assert isinstance(event.attributes, MappingProxyType)
    assert event.to_dict()["attributes"] == {"nested": [{"score": 0.5}]}
    with pytest.raises(TypeError):
        event.attributes["new"] = "value"  # type: ignore[index]

    detached = event.to_dict()
    detached["attributes"]["nested"][0]["score"] = 0.2
    assert event.to_dict()["attributes"]["nested"][0]["score"] == 0.5


def test_event_attributes_reject_reference_cycle() -> None:
    attributes: dict[str, object] = {}
    attributes["self"] = attributes
    with pytest.raises(ValidationError, match="reference cycle"):
        EvidenceEvent.from_dict(event_dict(attributes=attributes))


def test_event_attributes_reject_nested_non_string_key() -> None:
    with pytest.raises(ValidationError, match="keys must be strings"):
        EvidenceEvent.from_dict(event_dict(attributes={"nested": {1: "value"}}))


def test_event_attributes_reject_list_reference_cycle() -> None:
    values: list[object] = []
    values.append(values)
    with pytest.raises(ValidationError, match="reference cycle"):
        EvidenceEvent.from_dict(event_dict(attributes={"values": values}))


def test_direct_event_construction_and_replace_snapshot_nested_state() -> None:
    attributes = {"nested": [{"score": 0.5}]}
    event = EvidenceEvent(
        event_id=" e1 ",
        claim=" incident ",
        modality=Modality.VISION,
        source=" camera-a ",
        signal=Signal.SUPPORT,
        confidence=1,
        observed_at=datetime(2026, 8, 31, 14, tzinfo=timezone(timedelta(hours=2))),
        ingested_at=datetime(2026, 8, 31, 12, tzinfo=UTC),
        attributes=attributes,
    )
    attributes["nested"][0]["score"] = 0.1

    assert event.event_id == "e1"
    assert event.claim == "incident"
    assert event.source == "camera-a"
    assert event.observed_at == datetime(2026, 8, 31, 12, tzinfo=UTC)
    assert event.to_dict()["attributes"] == {"nested": [{"score": 0.5}]}

    replacement_list = [1, {"value": 2}]
    replaced = replace(
        event,
        attributes=MappingProxyType({"nested": replacement_list}),
    )
    replacement_list.append(3)
    assert replaced.to_dict()["attributes"] == {"nested": [1, {"value": 2}]}


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("modality", "vision", "modality"),
        ("signal", "support", "signal"),
        ("confidence", float("inf"), "confidence"),
        ("observed_at", datetime(2026, 8, 31), "UTC offset"),
        ("correlation_group", "bad\x00group", "XML"),
        ("attributes", {"tuple": (1, 2)}, "JSON"),
    ],
)
def test_direct_event_construction_rejects_invalid_state(
    make_event, field: str, value: object, message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        replace(make_event(), **{field: value})


def test_direct_policy_construction_and_replace_snapshot_mappings() -> None:
    parsed = Policy.from_dict(policy_dict())
    sources = dict(parsed.sources)
    claims = dict(parsed.claims)
    policy = Policy(
        schema_version=1,
        policy_id=" p ",
        default_source_reliability=1,
        sources=sources,
        decay=parsed.decay,
        claims=claims,
    )
    sources.clear()
    claims.clear()
    assert policy.policy_id == "p"
    assert set(policy.sources) == set(parsed.sources)
    assert set(policy.claims) == set(parsed.claims)

    replacement_sources = dict(parsed.sources)
    replaced = replace(parsed, sources=replacement_sources)
    replacement_sources.clear()
    assert set(replaced.sources) == set(parsed.sources)


@pytest.mark.parametrize(
    "factory",
    [
        lambda: SourcePolicy(True),
        lambda: DecayPolicy(60, [], 0),
        lambda: DecayPolicy(60, {"vision": 60}, 0),
        lambda: DecayPolicy(60, {Modality.VISION: 60}, True),
        lambda: ClaimRule(0.5, 0.5, 0.1, True, 1, 1, 0.2),
    ],
)
def test_direct_policy_parts_reject_invalid_state(factory) -> None:
    with pytest.raises(ValidationError):
        factory()


@pytest.mark.parametrize(
    "changes",
    [
        {"schema_version": True},
        {"decay": {}},
        {"sources": {"camera": {"reliability": 1}}},
        {"claims": {"incident": {"support_threshold": 1}}},
        {"claims": {}},
    ],
)
def test_direct_policy_rejects_invalid_state(changes: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        replace(Policy.from_dict(policy_dict()), **changes)


def test_attribute_depth_limit_returns_validation_error() -> None:
    attributes: object = "leaf"
    for _ in range(MAX_ATTRIBUTE_DEPTH + 2):
        attributes = {"nested": attributes}

    with pytest.raises(ValidationError, match=rf"nesting depth of {MAX_ATTRIBUTE_DEPTH}"):
        EvidenceEvent.from_dict(event_dict(attributes=attributes))


def test_attribute_integer_limit_keeps_accepted_values_serializable() -> None:
    maximum = 10**MAX_ATTRIBUTE_INTEGER_DIGITS - 1
    event = EvidenceEvent.from_dict(
        event_dict(attributes={"positive": maximum, "negative": -maximum, "zero": 0, "flag": True})
    )

    serialized = canonical_json(event.to_dict())

    assert str(maximum) in serialized
    assert str(-maximum) in serialized
    assert '"zero": 0' in serialized
    assert '"flag": true' in serialized


def test_negative_zero_is_canonical_in_events_and_policy_numbers() -> None:
    negative_event = EvidenceEvent.from_dict(event_dict(confidence=-0.0))
    positive_event = EvidenceEvent.from_dict(event_dict(confidence=0.0))
    assert negative_event.to_dict() == positive_event.to_dict()
    assert copysign(1.0, negative_event.confidence) == 1.0

    raw = policy_dict(
        support_threshold=-0.0,
        contradiction_threshold=-0.0,
        min_margin=-0.0,
        min_evidence_confidence=-0.0,
    )
    raw["default_source_reliability"] = -0.0
    raw["sources"]["camera-a"]["reliability"] = -0.0
    raw["decay"]["max_future_skew_seconds"] = -0.0
    policy = Policy.from_dict(raw)

    normalized = (
        policy.default_source_reliability,
        policy.sources["camera-a"].reliability,
        policy.decay.max_future_skew_seconds,
        policy.claims["incident"].support_threshold,
        policy.claims["incident"].contradiction_threshold,
        policy.claims["incident"].min_margin,
        policy.claims["incident"].min_evidence_confidence,
    )
    assert all(value == 0.0 and copysign(1.0, value) == 1.0 for value in normalized)
    assert copysign(1.0, replace(negative_event, confidence=-0.0).confidence) == 1.0


def test_integer_limit_uses_cross_process_runtime_safe_threshold() -> None:
    assert (
        getattr(
            sys.int_info,
            "str_digits_check_threshold",
            640,
        )
        == MAX_ATTRIBUTE_INTEGER_DIGITS
    )


@pytest.mark.parametrize(
    "integer",
    [
        10**MAX_ATTRIBUTE_INTEGER_DIGITS,
        -(10**MAX_ATTRIBUTE_INTEGER_DIGITS),
        10**10_000,
    ],
    ids=["positive-boundary", "negative-boundary", "very-large"],
)
def test_attribute_integer_limit_rejects_large_python_values(integer: int) -> None:
    with pytest.raises(
        ValidationError,
        match=rf"at most {MAX_ATTRIBUTE_INTEGER_DIGITS} digits",
    ):
        EvidenceEvent.from_dict(event_dict(attributes={"integer": integer}))


def test_policy_and_output_counts_reject_unserializable_integers(make_event) -> None:
    huge = 10**MAX_ATTRIBUTE_INTEGER_DIGITS
    with pytest.raises(ValidationError, match="at most"):
        ClaimRule(0.5, 0.5, 0, huge, 1, 1, 0)

    from evidence_braid.engine import EvaluationResult, SignalSummary

    with pytest.raises(ValidationError, match="at most"):
        SignalSummary(Signal.SUPPORT, 0, huge, (), (), False, ())
    with pytest.raises(ValidationError, match="at most"):
        EvaluationResult(1, "p", make_event().observed_at, huge, 0, (), ())


def test_attribute_rejects_nonstandard_scalar_subclasses() -> None:
    class IntegerSubclass(int):
        pass

    class StringSubclass(str):
        pass

    for value in (IntegerSubclass(1), StringSubclass("text")):
        with pytest.raises(ValidationError, match="JSON values"):
            EvidenceEvent.from_dict(event_dict(attributes={"value": value}))
    with pytest.raises(ValidationError, match="confidence"):
        EvidenceEvent.from_dict(event_dict(confidence=IntegerSubclass(1)))
    raw_policy = policy_dict()
    raw_policy["schema_version"] = IntegerSubclass(1)
    with pytest.raises(ValidationError, match="schema_version"):
        Policy.from_dict(raw_policy)


def test_canonical_json_wraps_python_integer_string_limit() -> None:
    with pytest.raises(InputFormatError, match="strict JSON"):
        canonical_json({"integer": 10**10_000})
