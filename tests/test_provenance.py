from __future__ import annotations

from datetime import UTC, datetime

import pytest

from evidence_braid import EvidenceEvent, Modality, Signal, build_provenance
from evidence_braid.errors import ValidationError


def _event(event_id: str, claim: str, signal: Signal, group: str | None = None) -> EvidenceEvent:
    instant = datetime(2026, 1, 1, tzinfo=UTC)
    return EvidenceEvent(
        event_id=event_id,
        claim=claim,
        modality=Modality.TEXT,
        source="source-a",
        signal=signal,
        confidence=0.8,
        observed_at=instant,
        ingested_at=instant,
        correlation_group=group,
    )


def test_provenance_graph_is_stable_and_traceable() -> None:
    graph = build_provenance(
        [_event("b", "claim", Signal.CONTRADICT), _event("a", "claim", Signal.SUPPORT, "g")]
    )
    assert graph.to_dict()["kind"] == "evidence-braid-provenance"
    assert {node.id for node in graph.trace_claim("claim")} >= {"claim:claim", "event:a", "event:b"}
    assert graph == build_provenance(
        list(
            reversed(
                [_event("b", "claim", Signal.CONTRADICT), _event("a", "claim", Signal.SUPPORT, "g")]
            )
        )
    )


def test_provenance_rejects_non_events_and_duplicate_ids() -> None:
    event = _event("a", "claim", Signal.SUPPORT)
    with pytest.raises(ValidationError):
        build_provenance([object()])  # type: ignore[list-item]
    with pytest.raises(ValidationError):
        build_provenance([event, event])
