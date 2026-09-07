from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from evidence_braid import (
    EvidenceEvent,
    EvidenceLedger,
    LedgerEntry,
    Modality,
    Signal,
    build_ledger,
)
from evidence_braid.errors import ValidationError


def _event(event_id: str, seconds: int) -> EvidenceEvent:
    observed = datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=seconds)
    return EvidenceEvent(
        event_id=event_id,
        claim="claim",
        modality=Modality.TEXT,
        source="source",
        signal=Signal.SUPPORT,
        confidence=0.8,
        observed_at=observed,
        ingested_at=observed,
    )


def test_ledger_orders_and_verifies_events() -> None:
    ledger = build_ledger([_event("b", 2), _event("a", 1)])
    assert [entry.event_id for entry in ledger.entries] == ["a", "b"]
    assert ledger.verify() is True
    assert ledger.head_digest == ledger.entries[-1].digest
    assert ledger.to_dict()["verified"] is True


def test_ledger_detects_tampering_without_claiming_truth() -> None:
    ledger = build_ledger([_event("a", 1)])
    entry = ledger.entries[0]
    tampered = type(entry)(
        sequence=entry.sequence,
        event_id=entry.event_id,
        event={**entry.event, "confidence": 0.1},
        previous_digest=entry.previous_digest,
        digest=entry.digest,
    )
    altered = type(ledger)((tampered,), ledger.genesis)
    assert altered.verify() is False
    assert "verified" in altered.to_dict()


def test_ledger_verification_fails_closed_for_each_broken_link() -> None:
    ledger = build_ledger([_event("a", 1)])
    entry = ledger.entries[0]
    assert not EvidenceLedger(ledger.entries, "0" * 64).verify()
    assert not EvidenceLedger(
        (LedgerEntry(1, entry.event_id, entry.event, entry.previous_digest, entry.digest),),
        ledger.genesis,
    ).verify()
    assert not EvidenceLedger(
        (LedgerEntry(entry.sequence, entry.event_id, entry.event, "1" * 64, entry.digest),),
        ledger.genesis,
    ).verify()
    assert not EvidenceLedger(
        (
            LedgerEntry(
                entry.sequence,
                entry.event_id,
                {"event_id": "wrong"},
                entry.previous_digest,
                entry.digest,
            ),
        ),
        ledger.genesis,
    ).verify()
    with pytest.raises(ValidationError):
        build_ledger([_event("a", 1), _event("a", 2)])
    with pytest.raises(ValidationError):
        build_ledger([object()])  # type: ignore[list-item]
