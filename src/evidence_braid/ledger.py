"""Hash-chained evidence receipts for offline integrity verification.

The chain proves that a serialized sequence was not reordered or edited after
it was produced.  It does *not* prove that an observation is true; truth still
comes from caller-supplied adjudication.  Keeping this distinction explicit is
important for provenance systems and makes the receipt safe to verify without
network access or private keys.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .errors import ValidationError
from .io import canonical_json
from .models import EvidenceEvent

_GENESIS = hashlib.sha256(b"evidence-braid-ledger:v1").hexdigest()


def _digest(previous: str, event: EvidenceEvent) -> str:
    payload = f"{previous}\n{canonical_json(event.to_dict(), pretty=False)}".encode()
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True, slots=True)
class LedgerEntry:
    """One event and the hash linking it to its predecessor."""

    sequence: int
    event_id: str
    event: Mapping[str, Any]
    previous_digest: str
    digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "event_id": self.event_id,
            "event": dict(self.event),
            "previous_digest": self.previous_digest,
            "digest": self.digest,
        }


@dataclass(frozen=True, slots=True)
class EvidenceLedger:
    """An immutable, deterministically ordered hash chain."""

    entries: tuple[LedgerEntry, ...]
    genesis: str = _GENESIS

    def verify(self) -> bool:
        """Return true only when sequence numbers and every link are intact."""

        if self.genesis != _GENESIS:
            return False
        previous = self.genesis
        for expected_sequence, entry in enumerate(self.entries):
            if entry.sequence != expected_sequence or entry.event_id != entry.event.get("event_id"):
                return False
            if entry.previous_digest != previous:
                return False
            try:
                event = EvidenceEvent.from_dict(entry.event, f"ledger[{expected_sequence}].event")
                expected = _digest(previous, event)
            except ValidationError:
                return False
            if entry.digest != expected:
                return False
            previous = entry.digest
        return True

    @property
    def head_digest(self) -> str:
        return self.entries[-1].digest if self.entries else self.genesis

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "kind": "evidence-braid-ledger",
            "genesis": self.genesis,
            "head_digest": self.head_digest,
            "entry_count": len(self.entries),
            "entries": [entry.to_dict() for entry in self.entries],
            "verified": self.verify(),
        }


def build_ledger(events: Iterable[EvidenceEvent]) -> EvidenceLedger:
    """Build a stable chain ordered by ingestion time and event identity."""

    supplied = list(events)
    if any(not isinstance(event, EvidenceEvent) for event in supplied):
        raise ValidationError("ledger events must be EvidenceEvent instances")
    ordered = sorted(supplied, key=lambda event: (event.ingested_at, event.event_id))
    if len({event.event_id for event in ordered}) != len(ordered):
        raise ValidationError("ledger event IDs must be unique")
    entries: list[LedgerEntry] = []
    previous = _GENESIS
    for sequence, event in enumerate(ordered):
        document = event.to_dict()
        digest = _digest(previous, event)
        entries.append(
            LedgerEntry(
                sequence=sequence,
                event_id=event.event_id,
                event=document,
                previous_digest=previous,
                digest=digest,
            )
        )
        previous = digest
    ledger = EvidenceLedger(tuple(entries))
    if not ledger.verify():  # pragma: no cover - defensive invariant guard
        raise AssertionError("newly built evidence ledger did not verify")
    return ledger


__all__ = ["EvidenceLedger", "LedgerEntry", "build_ledger"]
