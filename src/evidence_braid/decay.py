"""Pure confidence-weighting functions."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from .errors import ValidationError
from .models import EvidenceEvent, Policy, _number


@dataclass(frozen=True, slots=True)
class WeightedEvent:
    event: EvidenceEvent
    age_seconds: float
    source_reliability: float
    decay_factor: float
    effective_confidence: float

    def __post_init__(self) -> None:
        if not isinstance(self.event, EvidenceEvent):
            raise ValidationError("weighted.event must be an EvidenceEvent instance")
        object.__setattr__(
            self,
            "age_seconds",
            _number(self.age_seconds, "weighted.age_seconds", 0.0),
        )
        for field_name in ("source_reliability", "decay_factor", "effective_confidence"):
            object.__setattr__(
                self,
                field_name,
                _number(getattr(self, field_name), f"weighted.{field_name}", 0.0, 1.0),
            )


def weight_event(
    event: EvidenceEvent,
    policy: Policy,
    as_of: datetime,
    *,
    reliability: float | None = None,
) -> WeightedEvent:
    """Apply source reliability and exponential half-life decay.

    ``reliability`` overrides the policy's declared value for this source. The
    engine passes one only when an opt-in reliability update applies, so the
    function stays a pure function of its arguments either way.
    """
    age_seconds = (as_of - event.observed_at).total_seconds()
    if age_seconds < -policy.decay.max_future_skew_seconds:
        raise ValidationError(
            f"event {event.event_id} is {-age_seconds:.3f}s in the future, beyond allowed skew"
        )
    age_seconds = max(age_seconds, 0.0)
    half_life = policy.decay.half_life_for(event.modality)
    decay_factor = 2.0 ** (-age_seconds / half_life)
    applied = policy.reliability_for(event.source) if reliability is None else reliability
    effective = event.confidence * applied * decay_factor
    return WeightedEvent(event, age_seconds, applied, decay_factor, effective)
