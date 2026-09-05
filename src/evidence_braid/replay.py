"""Historical replay over ingestion-time boundaries."""

from __future__ import annotations

from collections.abc import Iterable

from .engine import EvaluationResult, evaluate, validate_event_set
from .models import Adjudication, EvidenceEvent, Policy
from .reliability import validate_adjudication_set


def replay(
    policy: Policy,
    events: Iterable[EvidenceEvent],
    *,
    adjudications: Iterable[Adjudication] = (),
) -> tuple[EvaluationResult, ...]:
    """Evaluate each ingestion-time prefix without revealing later events.

    Ground truth is knowable on its own clock, so an adjudication time is a
    snapshot boundary exactly as an ingestion time is. Without adjudications the
    boundaries, and therefore the snapshots, are the ones replay always
    produced.
    """
    ordered = sorted(
        validate_event_set(policy, events),
        key=lambda event: (event.ingested_at, event.event_id),
    )
    adjudged = sorted(
        validate_adjudication_set(policy, ordered, adjudications),
        key=lambda item: (item.adjudicated_at, item.event_id),
    )
    timestamps = sorted(
        {event.ingested_at for event in ordered} | {item.adjudicated_at for item in adjudged}
    )
    return tuple(
        evaluate(
            policy,
            [event for event in ordered if event.ingested_at <= as_of],
            as_of,
            adjudications=[item for item in adjudged if item.adjudicated_at <= as_of],
        )
        for as_of in timestamps
    )
