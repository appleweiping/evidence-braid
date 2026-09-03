"""Transparent comparison baselines for controlled evaluations.

These deliberately simple methods are not substitutes for the policy engine.
They make ablation and regression studies explicit by showing what happens
when correlation, decay, confidence, or independence gates are omitted.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from math import fsum, isfinite

from .engine import validate_event_set
from .errors import ValidationError
from .models import (
    MAX_ATTRIBUTE_INTEGER_DIGITS,
    EvidenceEvent,
    Outcome,
    Policy,
    Signal,
    _number,
    _stable_float,
    _text,
    normalize_datetime,
)

_METHODS = {"majority_vote", "reliability_weighted_vote"}
_MAX_EVENT_COUNT = 10**MAX_ATTRIBUTE_INTEGER_DIGITS - 1
_MASS_TOLERANCE = 1e-12


@dataclass(frozen=True, slots=True)
class BaselineDecision:
    """One inspectable baseline prediction and its support probability."""

    claim: str
    method: str
    outcome: Outcome
    support_mass: float
    contradict_mass: float
    support_probability: float
    event_count: int

    def __post_init__(self) -> None:
        claim = _text(self.claim, "baseline.claim")
        if claim != self.claim:
            raise ValidationError("baseline.claim must be canonical non-empty text")
        object.__setattr__(self, "claim", claim)
        if type(self.method) is not str or self.method not in _METHODS:
            raise ValidationError("baseline.method is not a supported baseline")
        if not isinstance(self.outcome, Outcome):
            raise ValidationError("baseline.outcome must be an Outcome")
        for name in ("support_mass", "contradict_mass"):
            value = _number(getattr(self, name), f"baseline.{name}", 0.0)
            object.__setattr__(self, name, _stable_float(value))
        probability = _number(
            self.support_probability,
            "baseline.support_probability",
            0.0,
            1.0,
        )
        object.__setattr__(self, "support_probability", _stable_float(probability))
        if (
            type(self.event_count) is not int
            or self.event_count < 0
            or self.event_count > _MAX_EVENT_COUNT
        ):
            raise ValidationError(
                "baseline.event_count must be an integer >= 0 with at most "
                f"{MAX_ATTRIBUTE_INTEGER_DIGITS} digits"
            )
        total = self.support_mass + self.contradict_mass
        if not isfinite(total):
            raise ValidationError("baseline support and contradiction mass sum must be finite")
        if self.event_count == 0 and total != 0.0:
            raise ValidationError("baseline mass must be zero when event_count is zero")
        if self.method == "majority_vote":
            if not self.support_mass.is_integer() or not self.contradict_mass.is_integer():
                raise ValidationError("majority_vote masses must be whole event counts")
            if int(total) != self.event_count:
                raise ValidationError("majority_vote masses must sum to event_count")
        elif total > self.event_count and _stable_float(total - self.event_count) > _MASS_TOLERANCE:
            raise ValidationError("reliability_weighted_vote masses cannot exceed event_count")
        expected_outcome = _outcome(self.support_mass, self.contradict_mass)
        if self.outcome is not expected_outcome:
            raise ValidationError(
                "baseline.outcome is inconsistent with support and contradiction mass"
            )
        expected_probability = _stable_float(self.support_mass / total) if total else 0.5
        if self.support_probability != expected_probability:
            raise ValidationError(
                "baseline.support_probability is inconsistent with support and contradiction mass"
            )

    def to_dict(self) -> dict[str, str | float | int]:
        return {
            "claim": self.claim,
            "method": self.method,
            "outcome": self.outcome.value,
            "support_mass": self.support_mass,
            "contradict_mass": self.contradict_mass,
            "support_probability": self.support_probability,
            "event_count": self.event_count,
        }


def _outcome(support: float, contradict: float) -> Outcome:
    if support > contradict:
        return Outcome.ESCALATE
    if contradict > support:
        return Outcome.REJECT
    return Outcome.REVIEW


def _visible_events(
    policy: Policy,
    events: Iterable[EvidenceEvent],
    as_of: datetime,
) -> list[EvidenceEvent]:
    normalized = normalize_datetime(as_of, "as_of")
    validated = validate_event_set(policy, events)
    return [event for event in validated if event.ingested_at <= normalized]


def majority_vote(
    policy: Policy,
    events: Iterable[EvidenceEvent],
    as_of: datetime,
) -> tuple[BaselineDecision, ...]:
    """Count each visible event equally, ignoring confidence and correlation."""

    visible = _visible_events(policy, events, as_of)
    decisions: list[BaselineDecision] = []
    for claim in sorted(policy.claims):
        matching = [event for event in visible if event.claim == claim]
        support = sum(event.signal is Signal.SUPPORT for event in matching)
        contradict = sum(event.signal is Signal.CONTRADICT for event in matching)
        total = support + contradict
        decisions.append(
            BaselineDecision(
                claim=claim,
                method="majority_vote",
                outcome=_outcome(support, contradict),
                support_mass=support,
                contradict_mass=contradict,
                support_probability=support / total if total else 0.5,
                event_count=total,
            )
        )
    return tuple(decisions)


def reliability_weighted_vote(
    policy: Policy,
    events: Iterable[EvidenceEvent],
    as_of: datetime,
) -> tuple[BaselineDecision, ...]:
    """Vote with confidence times source reliability and no decay/correlation gates."""

    visible = _visible_events(policy, events, as_of)
    decisions: list[BaselineDecision] = []
    for claim in sorted(policy.claims):
        matching = sorted(
            (event for event in visible if event.claim == claim),
            key=lambda event: event.event_id,
        )
        support = fsum(
            event.confidence * policy.reliability_for(event.source)
            for event in matching
            if event.signal is Signal.SUPPORT
        )
        contradict = fsum(
            event.confidence * policy.reliability_for(event.source)
            for event in matching
            if event.signal is Signal.CONTRADICT
        )
        support = round(support, 12)
        contradict = round(contradict, 12)
        total = support + contradict
        decisions.append(
            BaselineDecision(
                claim=claim,
                method="reliability_weighted_vote",
                outcome=_outcome(support, contradict),
                support_mass=support,
                contradict_mass=contradict,
                support_probability=round(support / total, 12) if total else 0.5,
                event_count=len(matching),
            )
        )
    return tuple(decisions)
