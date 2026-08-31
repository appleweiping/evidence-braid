"""Historical replay over ingestion-time boundaries."""

from __future__ import annotations

from collections.abc import Iterable

from .engine import EvaluationResult, evaluate, validate_event_set
from .models import EvidenceEvent, Policy


def replay(policy: Policy, events: Iterable[EvidenceEvent]) -> tuple[EvaluationResult, ...]:
    """Evaluate each ingestion-time prefix without revealing later events."""
    ordered = sorted(
        validate_event_set(policy, events),
        key=lambda event: (event.ingested_at, event.event_id),
    )
    timestamps = sorted({event.ingested_at for event in ordered})
    return tuple(
        evaluate(policy, [event for event in ordered if event.ingested_at <= as_of], as_of)
        for as_of in timestamps
    )
