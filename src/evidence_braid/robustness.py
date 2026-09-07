"""Deterministic leave-one-out robustness diagnostics.

Robustness is deliberately a diagnostic, not a confidence claim.  The
analysis removes one visible evidence event at a time, re-evaluates the same
policy at the same instant, and records claims whose outcome changes.  This
makes threshold fragility and single-source dependence inspectable without
introducing a random sampler or an unreviewable statistical assumption.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from itertools import islice
from typing import Any

from .engine import evaluate, validate_event_set
from .errors import ValidationError
from .models import (
    Adjudication,
    EvidenceEvent,
    Outcome,
    Policy,
    _nonnegative_int,
    _number,
    _stable_float,
    _text,
    normalize_datetime,
)
from .reliability import validate_adjudication_set

_RESULT_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_PERTURBATIONS = 10_000


@dataclass(frozen=True, slots=True)
class RobustnessImpact:
    """The effect of removing one visible event for one claim."""

    event_id: str
    claim: str
    baseline_outcome: Outcome
    without_event_outcome: Outcome
    baseline_reason: str
    without_event_reason: str
    baseline_margin: float
    without_event_margin: float

    def __post_init__(self) -> None:
        object.__setattr__(self, "event_id", _text(self.event_id, "impact.event_id"))
        object.__setattr__(self, "claim", _text(self.claim, "impact.claim"))
        for name in ("baseline_outcome", "without_event_outcome"):
            value = getattr(self, name)
            if not isinstance(value, Outcome):
                raise ValidationError(f"impact.{name} must be an Outcome")
        if self.baseline_outcome is self.without_event_outcome:
            raise ValidationError("a robustness impact must change the outcome")
        for name in ("baseline_reason", "without_event_reason"):
            object.__setattr__(self, name, _text(getattr(self, name), f"impact.{name}"))
        for name in ("baseline_margin", "without_event_margin"):
            object.__setattr__(
                self,
                name,
                _number(getattr(self, name), f"impact.{name}", -1.0, 1.0),
            )

    @property
    def margin_delta(self) -> float:
        """Margin after removal minus the baseline margin."""

        return _stable_float(self.without_event_margin - self.baseline_margin)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "claim": self.claim,
            "baseline_outcome": self.baseline_outcome.value,
            "without_event_outcome": self.without_event_outcome.value,
            "baseline_reason": self.baseline_reason,
            "without_event_reason": self.without_event_reason,
            "baseline_margin": _stable_float(self.baseline_margin),
            "without_event_margin": _stable_float(self.without_event_margin),
            "margin_delta": self.margin_delta,
        }


@dataclass(frozen=True, slots=True)
class ClaimRobustness:
    """Leave-one-out stability for a single configured claim."""

    claim: str
    baseline_outcome: Outcome
    baseline_margin: float
    tested_event_count: int
    changed_event_count: int
    impacts: tuple[RobustnessImpact, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "claim", _text(self.claim, "claim_robustness.claim"))
        if not isinstance(self.baseline_outcome, Outcome):
            raise ValidationError("claim_robustness.baseline_outcome must be an Outcome")
        object.__setattr__(
            self,
            "baseline_margin",
            _number(self.baseline_margin, "claim_robustness.baseline_margin", -1.0, 1.0),
        )
        tested = _nonnegative_int(self.tested_event_count, "claim_robustness.tested_event_count")
        changed = _nonnegative_int(self.changed_event_count, "claim_robustness.changed_event_count")
        if changed > tested:
            raise ValidationError(
                "claim_robustness.changed_event_count cannot exceed tested events"
            )
        impacts = tuple(islice(iter(self.impacts), _MAX_PERTURBATIONS + 1))
        if len(impacts) > _MAX_PERTURBATIONS:
            raise ValidationError("claim_robustness.impacts exceeds the compiled limit")
        if any(not isinstance(item, RobustnessImpact) for item in impacts):
            raise ValidationError("claim_robustness.impacts must contain RobustnessImpact objects")
        if any(item.claim != self.claim for item in impacts):
            raise ValidationError("claim_robustness.impacts contains another claim")
        if len({item.event_id for item in impacts}) != len(impacts):
            raise ValidationError("claim_robustness.impacts contains duplicate event IDs")
        if len(impacts) != changed:
            raise ValidationError("claim_robustness.changed_event_count does not match impacts")
        object.__setattr__(self, "tested_event_count", tested)
        object.__setattr__(self, "changed_event_count", changed)
        object.__setattr__(self, "impacts", tuple(sorted(impacts, key=lambda item: item.event_id)))

    @property
    def stability(self) -> float:
        """Fraction of tested removals that kept the baseline outcome."""

        if self.tested_event_count == 0:
            return 1.0
        return _stable_float(
            (self.tested_event_count - self.changed_event_count) / self.tested_event_count
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim": self.claim,
            "baseline_outcome": self.baseline_outcome.value,
            "baseline_margin": _stable_float(self.baseline_margin),
            "tested_event_count": self.tested_event_count,
            "changed_event_count": self.changed_event_count,
            "stability": self.stability,
            "impacts": [item.to_dict() for item in self.impacts],
        }


@dataclass(frozen=True, slots=True)
class RobustnessReport:
    """Complete deterministic robustness result for one evaluation instant."""

    schema_version: int
    policy_id: str
    evaluated_at: datetime
    input_event_count: int
    considered_event_count: int
    baseline_digest: str
    claims: tuple[ClaimRobustness, ...]

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise ValidationError("robustness.schema_version must be 1")
        object.__setattr__(self, "policy_id", _text(self.policy_id, "robustness.policy_id"))
        object.__setattr__(
            self,
            "evaluated_at",
            normalize_datetime(self.evaluated_at, "robustness.evaluated_at"),
        )
        inputs = _nonnegative_int(self.input_event_count, "robustness.input_event_count")
        considered = _nonnegative_int(
            self.considered_event_count, "robustness.considered_event_count"
        )
        if considered > inputs:
            raise ValidationError("robustness.considered_event_count cannot exceed input events")
        if (
            type(self.baseline_digest) is not str
            or _RESULT_DIGEST.fullmatch(self.baseline_digest) is None
        ):
            raise ValidationError("robustness.baseline_digest must be a lowercase SHA-256 digest")
        claims = tuple(islice(iter(self.claims), _MAX_PERTURBATIONS + 1))
        if len(claims) > _MAX_PERTURBATIONS:
            raise ValidationError("robustness.claims exceeds the compiled limit")
        if any(not isinstance(item, ClaimRobustness) for item in claims):
            raise ValidationError("robustness.claims must contain ClaimRobustness objects")
        if any(item.tested_event_count != considered for item in claims):
            raise ValidationError("every claim must test the report's considered event count")
        if len({item.claim for item in claims}) != len(claims):
            raise ValidationError("robustness.claims contains duplicate claims")
        object.__setattr__(self, "input_event_count", inputs)
        object.__setattr__(self, "considered_event_count", considered)
        object.__setattr__(self, "claims", tuple(sorted(claims, key=lambda item: item.claim)))

    @property
    def fragile_claims(self) -> tuple[str, ...]:
        """Claims whose outcome changed under at least one removal."""

        return tuple(item.claim for item in self.claims if item.changed_event_count)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "policy_id": self.policy_id,
            "evaluated_at": self.evaluated_at.isoformat().replace("+00:00", "Z"),
            "input_event_count": self.input_event_count,
            "considered_event_count": self.considered_event_count,
            "baseline_digest": self.baseline_digest,
            "fragile_claims": list(self.fragile_claims),
            "claims": [item.to_dict() for item in self.claims],
        }


def robustness(
    policy: Policy,
    events: Iterable[EvidenceEvent],
    as_of: datetime,
    *,
    adjudications: Iterable[Adjudication] = (),
    max_events: int = 256,
) -> RobustnessReport:
    """Measure single-event outcome dependence at a fixed evaluation instant.

    Only events already ingested at ``as_of`` are perturbed.  If an event has
    an adjudication, its judgement is removed in the same perturbation so the
    diagnostic does not retain ground truth for evidence it just removed.
    ``max_events`` is an explicit cost guard because the calculation is
    quadratic in the number of visible events.
    """

    if type(max_events) is not int or not 1 <= max_events <= _MAX_PERTURBATIONS:
        raise ValidationError(f"max_events must be an integer in [1, {_MAX_PERTURBATIONS}]")
    if not isinstance(policy, Policy):
        raise ValidationError("policy must be a Policy instance")
    normalized_as_of = normalize_datetime(as_of, "as_of")
    event_list = validate_event_set(policy, events)
    adjudication_list = validate_adjudication_set(policy, event_list, adjudications)
    baseline = evaluate(policy, event_list, normalized_as_of, adjudications=adjudication_list)
    visible = tuple(
        sorted(
            (event for event in event_list if event.ingested_at <= normalized_as_of),
            key=lambda event: event.event_id,
        )
    )
    if len(visible) > max_events:
        raise ValidationError(
            f"robustness would require {len(visible)} leave-one-out evaluations; "
            f"max_events is {max_events}"
        )
    baseline_by_claim = {item.claim: item for item in baseline.decisions}
    impacts: dict[str, list[RobustnessImpact]] = {claim: [] for claim in baseline_by_claim}
    for event in visible:
        reduced_events = tuple(item for item in event_list if item.event_id != event.event_id)
        reduced_adjudications = tuple(
            item for item in adjudication_list if item.event_id != event.event_id
        )
        without = evaluate(
            policy,
            reduced_events,
            normalized_as_of,
            adjudications=reduced_adjudications,
        )
        without_by_claim = {item.claim: item for item in without.decisions}
        for claim, original in baseline_by_claim.items():
            changed = without_by_claim[claim].outcome is not original.outcome
            if changed:
                replacement = without_by_claim[claim]
                impacts[claim].append(
                    RobustnessImpact(
                        event_id=event.event_id,
                        claim=claim,
                        baseline_outcome=original.outcome,
                        without_event_outcome=replacement.outcome,
                        baseline_reason=original.reason,
                        without_event_reason=replacement.reason,
                        baseline_margin=original.margin,
                        without_event_margin=replacement.margin,
                    )
                )
    claims = tuple(
        ClaimRobustness(
            claim=claim,
            baseline_outcome=decision.outcome,
            baseline_margin=decision.margin,
            tested_event_count=len(visible),
            changed_event_count=len(impacts[claim]),
            impacts=tuple(impacts[claim]),
        )
        for claim, decision in sorted(baseline_by_claim.items())
    )
    return RobustnessReport(
        schema_version=1,
        policy_id=baseline.policy_id,
        evaluated_at=baseline.evaluated_at,
        input_event_count=baseline.input_event_count,
        considered_event_count=baseline.considered_event_count,
        baseline_digest=baseline.digest,
        claims=claims,
    )


analyze_robustness = robustness

__all__ = [
    "ClaimRobustness",
    "RobustnessImpact",
    "RobustnessReport",
    "analyze_robustness",
    "robustness",
]
