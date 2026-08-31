"""Deterministic evidence evaluation and decision tracing."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from math import prod
from typing import Any

from .decay import WeightedEvent, weight_event
from .errors import ValidationError
from .grouping import CorrelationSelection, collapse_correlated
from .models import (
    ClaimRule,
    EvidenceEvent,
    Modality,
    Outcome,
    Policy,
    Signal,
    _enum,
    _immutable_text_tuple,
    _nonnegative_int,
    _number,
    _stable_float,
    _text,
    format_timestamp,
    normalize_datetime,
)


def _combined_confidence(values: Iterable[float]) -> float:
    """Combine independent confidence without allowing a score above one."""
    return 1.0 - prod(1.0 - _stable_float(value) for value in values)


def _model_tuple(value: Any, model_type: type, path: str) -> tuple:
    """Validate and snapshot a typed output sequence."""
    if isinstance(value, str | bytes) or not isinstance(value, Sequence):
        raise ValidationError(f"{path} must be a sequence of {model_type.__name__} objects")
    result = tuple(value)
    for index, item in enumerate(result):
        if not isinstance(item, model_type):
            raise ValidationError(f"{path}[{index}] must be a {model_type.__name__} instance")
    return result


def _canonical_text_tuple(value: Any, path: str) -> tuple[str, ...]:
    items = _immutable_text_tuple(value, path)
    if len(set(items)) != len(items):
        raise ValidationError(f"{path} must not contain duplicates")
    return tuple(sorted(items))


@dataclass(frozen=True, slots=True)
class SignalSummary:
    signal: Signal
    score: float
    qualifying_groups: int
    qualifying_sources: tuple[str, ...]
    qualifying_modalities: tuple[str, ...]
    gate_passed: bool
    group_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "signal", _enum(self.signal, Signal, "summary.signal"))
        object.__setattr__(self, "score", _number(self.score, "summary.score", 0.0, 1.0))
        groups = _nonnegative_int(self.qualifying_groups, "summary.qualifying_groups")
        object.__setattr__(self, "qualifying_groups", groups)
        sources = _canonical_text_tuple(self.qualifying_sources, "summary.qualifying_sources")
        modalities = _canonical_text_tuple(
            self.qualifying_modalities,
            "summary.qualifying_modalities",
        )
        for index, modality in enumerate(modalities):
            try:
                Modality(modality)
            except ValueError as exc:
                raise ValidationError(
                    f"summary.qualifying_modalities[{index}] is not a supported modality"
                ) from exc
        group_ids = _canonical_text_tuple(self.group_ids, "summary.group_ids")
        if groups > len(group_ids):
            raise ValidationError("summary.qualifying_groups cannot exceed its group count")
        if not isinstance(self.gate_passed, bool):
            raise ValidationError("summary.gate_passed must be a boolean")
        object.__setattr__(self, "qualifying_sources", sources)
        object.__setattr__(self, "qualifying_modalities", modalities)
        object.__setattr__(self, "group_ids", group_ids)

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": _stable_float(self.score),
            "qualifying_groups": self.qualifying_groups,
            "qualifying_sources": list(self.qualifying_sources),
            "qualifying_modalities": list(self.qualifying_modalities),
            "gate_passed": self.gate_passed,
            "group_ids": list(self.group_ids),
        }


@dataclass(frozen=True, slots=True)
class EventTrace:
    """Deeply immutable audit record for one weighted observation."""

    event_id: str
    claim: str
    signal: str
    modality: str
    source: str
    correlation_group: str | None
    raw_confidence: float
    source_reliability: float
    age_seconds: float
    decay_factor: float
    effective_confidence: float

    def __post_init__(self) -> None:
        object.__setattr__(self, "event_id", _text(self.event_id, "trace.event_id"))
        object.__setattr__(self, "claim", _text(self.claim, "trace.claim"))
        try:
            signal = Signal(self.signal)
        except (TypeError, ValueError) as exc:
            raise ValidationError("trace.signal must be support or contradict") from exc
        try:
            modality = Modality(self.modality)
        except (TypeError, ValueError) as exc:
            raise ValidationError("trace.modality is not supported") from exc
        object.__setattr__(self, "signal", signal.value)
        object.__setattr__(self, "modality", modality.value)
        object.__setattr__(self, "source", _text(self.source, "trace.source"))
        if self.correlation_group is not None:
            object.__setattr__(
                self,
                "correlation_group",
                _text(self.correlation_group, "trace.correlation_group"),
            )
        for field_name in (
            "raw_confidence",
            "source_reliability",
            "decay_factor",
            "effective_confidence",
        ):
            object.__setattr__(
                self,
                field_name,
                _number(getattr(self, field_name), f"trace.{field_name}", 0.0, 1.0),
            )
        object.__setattr__(
            self,
            "age_seconds",
            _number(self.age_seconds, "trace.age_seconds", 0.0),
        )

    @classmethod
    def from_weighted(cls, weighted: WeightedEvent) -> EventTrace:
        event = weighted.event
        return cls(
            event_id=event.event_id,
            claim=event.claim,
            signal=event.signal.value,
            modality=event.modality.value,
            source=event.source,
            correlation_group=event.correlation_group,
            raw_confidence=event.confidence,
            source_reliability=_stable_float(weighted.source_reliability),
            age_seconds=_stable_float(weighted.age_seconds),
            decay_factor=_stable_float(weighted.decay_factor),
            effective_confidence=_stable_float(weighted.effective_confidence),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "claim": self.claim,
            "signal": self.signal,
            "modality": self.modality,
            "source": self.source,
            "correlation_group": self.correlation_group,
            "raw_confidence": self.raw_confidence,
            "source_reliability": self.source_reliability,
            "age_seconds": self.age_seconds,
            "decay_factor": self.decay_factor,
            "effective_confidence": self.effective_confidence,
        }


@dataclass(frozen=True, slots=True)
class CorrelationTrace:
    """Deeply immutable record of one correlation collapse decision."""

    group_id: str
    signal: str
    representative_event_id: str
    effective_confidence: float
    suppressed_event_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "group_id", _text(self.group_id, "correlation.group_id"))
        try:
            signal = Signal(self.signal)
        except (TypeError, ValueError) as exc:
            raise ValidationError("correlation.signal must be support or contradict") from exc
        object.__setattr__(self, "signal", signal.value)
        object.__setattr__(
            self,
            "representative_event_id",
            _text(self.representative_event_id, "correlation.representative_event_id"),
        )
        object.__setattr__(
            self,
            "effective_confidence",
            _number(
                self.effective_confidence,
                "correlation.effective_confidence",
                0.0,
                1.0,
            ),
        )
        suppressed = _canonical_text_tuple(
            self.suppressed_event_ids,
            "correlation.suppressed_event_ids",
        )
        if self.representative_event_id in suppressed:
            raise ValidationError("a correlation representative cannot suppress itself")
        object.__setattr__(self, "suppressed_event_ids", suppressed)

    @classmethod
    def from_selection(cls, selection: CorrelationSelection) -> CorrelationTrace:
        return cls(
            group_id=selection.group_id,
            signal=selection.signal.value,
            representative_event_id=selection.representative.event.event_id,
            effective_confidence=_stable_float(selection.representative.effective_confidence),
            suppressed_event_ids=tuple(item.event.event_id for item in selection.suppressed),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "group_id": self.group_id,
            "signal": self.signal,
            "representative_event_id": self.representative_event_id,
            "effective_confidence": self.effective_confidence,
            "suppressed_event_ids": list(self.suppressed_event_ids),
        }


@dataclass(frozen=True, slots=True)
class ClaimDecision:
    claim: str
    outcome: Outcome
    reason: str
    support: SignalSummary
    contradict: SignalSummary
    margin: float
    trace: tuple[EventTrace, ...]
    correlations: tuple[CorrelationTrace, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "claim", _text(self.claim, "decision.claim"))
        object.__setattr__(self, "outcome", _enum(self.outcome, Outcome, "decision.outcome"))
        object.__setattr__(self, "reason", _text(self.reason, "decision.reason"))
        if not isinstance(self.support, SignalSummary) or self.support.signal is not Signal.SUPPORT:
            raise ValidationError("decision.support must be a support SignalSummary")
        if (
            not isinstance(self.contradict, SignalSummary)
            or self.contradict.signal is not Signal.CONTRADICT
        ):
            raise ValidationError("decision.contradict must be a contradict SignalSummary")
        object.__setattr__(self, "margin", _number(self.margin, "decision.margin", -1.0, 1.0))
        trace = _model_tuple(self.trace, EventTrace, "decision.trace")
        trace = tuple(sorted(trace, key=lambda event: event.event_id))
        if len({event.event_id for event in trace}) != len(trace):
            raise ValidationError("decision.trace contains duplicate event IDs")
        if any(event.claim != self.claim for event in trace):
            raise ValidationError("decision.trace contains an event for another claim")
        correlations = _model_tuple(
            self.correlations,
            CorrelationTrace,
            "decision.correlations",
        )
        correlations = tuple(sorted(correlations, key=lambda item: (item.group_id, item.signal)))
        keys = {(item.group_id, item.signal) for item in correlations}
        if len(keys) != len(correlations):
            raise ValidationError("decision.correlations contains duplicate group/signal entries")
        object.__setattr__(self, "trace", trace)
        object.__setattr__(self, "correlations", correlations)

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim": self.claim,
            "outcome": self.outcome.value,
            "reason": self.reason,
            "support": self.support.to_dict(),
            "contradict": self.contradict.to_dict(),
            "margin": _stable_float(self.margin),
            "trace": [event.to_dict() for event in self.trace],
            "correlations": [selection.to_dict() for selection in self.correlations],
        }


@dataclass(frozen=True, slots=True)
class EvaluationResult:
    schema_version: int
    policy_id: str
    evaluated_at: datetime
    input_event_count: int
    considered_event_count: int
    pending_event_ids: tuple[str, ...]
    decisions: tuple[ClaimDecision, ...]

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise ValidationError("result.schema_version must be 1")
        object.__setattr__(self, "policy_id", _text(self.policy_id, "result.policy_id"))
        object.__setattr__(
            self,
            "evaluated_at",
            normalize_datetime(self.evaluated_at, "result.evaluated_at"),
        )
        input_count = _nonnegative_int(self.input_event_count, "result.input_event_count")
        considered_count = _nonnegative_int(
            self.considered_event_count,
            "result.considered_event_count",
        )
        if considered_count > input_count:
            raise ValidationError("result.considered_event_count cannot exceed input_event_count")
        pending = _canonical_text_tuple(self.pending_event_ids, "result.pending_event_ids")
        if considered_count + len(pending) != input_count:
            raise ValidationError("result counts do not match pending_event_ids")
        decisions = _model_tuple(self.decisions, ClaimDecision, "result.decisions")
        decisions = tuple(sorted(decisions, key=lambda decision: decision.claim))
        if len({decision.claim for decision in decisions}) != len(decisions):
            raise ValidationError("result.decisions contains duplicate claims")
        if sum(len(decision.trace) for decision in decisions) != considered_count:
            raise ValidationError("result considered count does not match decision traces")
        object.__setattr__(self, "input_event_count", input_count)
        object.__setattr__(self, "considered_event_count", considered_count)
        object.__setattr__(self, "pending_event_ids", pending)
        object.__setattr__(self, "decisions", decisions)

    def _payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "policy_id": self.policy_id,
            "evaluated_at": format_timestamp(self.evaluated_at),
            "input_event_count": self.input_event_count,
            "considered_event_count": self.considered_event_count,
            "pending_event_ids": list(self.pending_event_ids),
            "decisions": [decision.to_dict() for decision in self.decisions],
        }

    @property
    def digest(self) -> str:
        encoded = json.dumps(
            self._payload(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        return f"sha256:{hashlib.sha256(encoded).hexdigest()}"

    def to_dict(self) -> dict[str, Any]:
        payload = self._payload()
        payload["digest"] = self.digest
        return payload


def _summarize_signal(
    signal: Signal,
    selections: tuple[CorrelationSelection, ...],
    rule: ClaimRule,
) -> SignalSummary:
    matching = [item for item in selections if item.signal is signal]
    score = _stable_float(
        _combined_confidence(item.representative.effective_confidence for item in matching)
    )
    minimum_confidence = _stable_float(rule.min_evidence_confidence)
    qualifying = [
        item
        for item in matching
        if _stable_float(item.representative.effective_confidence) >= minimum_confidence
    ]
    sources = tuple(sorted({item.representative.event.source for item in qualifying}))
    modalities = tuple(sorted({item.representative.event.modality.value for item in qualifying}))
    gate_passed = (
        len(qualifying) >= rule.quorum
        and len(sources) >= rule.min_sources
        and len(modalities) >= rule.min_modalities
    )
    return SignalSummary(
        signal=signal,
        score=score,
        qualifying_groups=len(qualifying),
        qualifying_sources=sources,
        qualifying_modalities=modalities,
        gate_passed=gate_passed,
        group_ids=tuple(item.group_id for item in matching),
    )


def _choose_outcome(
    support: SignalSummary,
    contradict: SignalSummary,
    rule: ClaimRule,
) -> tuple[Outcome, str]:
    support_score = _stable_float(support.score)
    contradict_score = _stable_float(contradict.score)
    support_threshold = _stable_float(rule.support_threshold)
    contradiction_threshold = _stable_float(rule.contradiction_threshold)
    minimum_margin = _stable_float(rule.min_margin)
    margin = _stable_float(support_score - contradict_score)
    supports_escalation = (
        support.gate_passed and support_score >= support_threshold and margin >= minimum_margin
    )
    supports_rejection = (
        contradict.gate_passed
        and contradict_score >= contradiction_threshold
        and -margin >= minimum_margin
    )
    if supports_escalation and supports_rejection:
        return Outcome.REVIEW, "conflicting_thresholds"
    if supports_escalation:
        return Outcome.ESCALATE, "support_threshold_and_independence_gates_met"
    if supports_rejection:
        return Outcome.REJECT, "contradiction_threshold_and_independence_gates_met"
    if support_score >= support_threshold and not support.gate_passed:
        return Outcome.REVIEW, "support_score_met_but_independence_gate_failed"
    if contradict_score >= contradiction_threshold and not contradict.gate_passed:
        return Outcome.REVIEW, "contradiction_score_met_but_independence_gate_failed"
    if abs(margin) < minimum_margin:
        return Outcome.REVIEW, "evidence_margin_too_small"
    return Outcome.REVIEW, "decision_threshold_not_met"


def _evaluate_claim(
    claim: str,
    rule: ClaimRule,
    events: list[EvidenceEvent],
    policy: Policy,
    as_of: datetime,
) -> ClaimDecision:
    weighted: list[WeightedEvent] = [weight_event(event, policy, as_of) for event in events]
    weighted.sort(key=lambda item: item.event.event_id)
    selections = collapse_correlated(weighted)
    support = _summarize_signal(Signal.SUPPORT, selections, rule)
    contradict = _summarize_signal(Signal.CONTRADICT, selections, rule)
    outcome, reason = _choose_outcome(support, contradict, rule)
    trace = tuple(EventTrace.from_weighted(item) for item in weighted)
    correlations = tuple(CorrelationTrace.from_selection(item) for item in selections)
    return ClaimDecision(
        claim=claim,
        outcome=outcome,
        reason=reason,
        support=support,
        contradict=contradict,
        margin=_stable_float(support.score - contradict.score),
        trace=trace,
        correlations=correlations,
    )


def validate_event_set(policy: Policy, events: Iterable[EvidenceEvent]) -> list[EvidenceEvent]:
    """Validate stream-wide invariants shared by fixed evaluation and replay."""
    if not isinstance(policy, Policy):
        raise ValidationError("policy must be a Policy instance")
    event_list = list(events)
    for index, event in enumerate(event_list):
        if not isinstance(event, EvidenceEvent):
            raise ValidationError(f"events[{index}] must be an EvidenceEvent instance")
    id_counts = Counter(event.event_id for event in event_list)
    duplicate_ids = sorted(event_id for event_id, count in id_counts.items() if count > 1)
    if duplicate_ids:
        raise ValidationError(f"duplicate event_id(s): {', '.join(duplicate_ids)}")
    unknown_claims = sorted({event.claim for event in event_list} - set(policy.claims))
    if unknown_claims:
        raise ValidationError(f"event claim(s) missing from policy: {', '.join(unknown_claims)}")
    for event in event_list:
        future_skew = (event.observed_at - event.ingested_at).total_seconds()
        if future_skew > policy.decay.max_future_skew_seconds:
            raise ValidationError(
                f"event {event.event_id} was observed {future_skew:.3f}s in the future of "
                "ingestion, beyond allowed source-clock skew"
            )
    return event_list


def evaluate(policy: Policy, events: Iterable[EvidenceEvent], as_of: datetime) -> EvaluationResult:
    """Evaluate every configured claim using evidence known at ``as_of``.

    Duplicate IDs are rejected even if one copy is not yet ingested. Unknown
    claims are rejected so policy drift cannot silently discard observations.
    """
    normalized_as_of = normalize_datetime(as_of, "as_of")
    event_list = validate_event_set(policy, events)
    considered = [event for event in event_list if event.ingested_at <= normalized_as_of]
    pending = tuple(
        sorted(event.event_id for event in event_list if event.ingested_at > normalized_as_of)
    )
    by_claim: dict[str, list[EvidenceEvent]] = {claim: [] for claim in policy.claims}
    for event in considered:
        by_claim[event.claim].append(event)
    decisions = tuple(
        _evaluate_claim(claim, policy.claims[claim], by_claim[claim], policy, normalized_as_of)
        for claim in sorted(policy.claims)
    )
    return EvaluationResult(
        schema_version=1,
        policy_id=policy.policy_id,
        evaluated_at=normalized_as_of,
        input_event_count=len(event_list),
        considered_event_count=len(considered),
        pending_event_ids=pending,
        decisions=decisions,
    )
