"""Versioned, immutable evidence chains with strict offline verification.

A digest detects changes relative to a retained trusted head. An attacker who
can replace the entire chain can compute a replacement head; hashes alone do
not authenticate actors, establish truth, or prevent rollback.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .errors import ValidationError
from .io import canonical_json
from .models import EvidenceEvent, _freeze_json, _thaw_json

MAX_LEDGER_ENTRIES = 100_000
_GENESIS = hashlib.sha256(b"evidence-braid-ledger:v1").hexdigest()
_GENESIS_V2 = hashlib.sha256(b"evidence-braid-ledger:v2").hexdigest()
_VERSIONS = {"1.0": _GENESIS, "2.0": _GENESIS_V2}


def _digest(previous: str, event: EvidenceEvent, sequence: int, version: str) -> str:
    if version == "1.0":
        payload = f"{previous}\n{canonical_json(event.to_dict(), pretty=False)}"
    else:
        payload = canonical_json(
            {
                "schema_version": version,
                "sequence": sequence,
                "previous_digest": previous,
                "event": event.to_dict(),
            },
            pretty=False,
        )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _fields(value: Any, names: set[str], path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != names:
        raise ValidationError(f"{path} must contain exactly: {', '.join(sorted(names))}")
    return value


def _hash(value: Any, path: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(c not in "0123456789abcdef" for c in value)
    ):
        raise ValidationError(f"{path} must be a lowercase SHA-256 digest")
    return value


@dataclass(frozen=True, slots=True)
class LedgerEntry:
    """One event and its predecessor; event data is recursively snapshotted."""

    sequence: int
    event_id: str
    event: Mapping[str, Any]
    previous_digest: str
    digest: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "event", _freeze_json(self.event, "ledger.event", allow_frozen_sequences=True)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "event_id": self.event_id,
            "event": _thaw_json(self.event),
            "previous_digest": self.previous_digest,
            "digest": self.digest,
        }

    @classmethod
    def from_dict(cls, value: Any) -> LedgerEntry:
        data = _fields(
            value, {"sequence", "event_id", "event", "previous_digest", "digest"}, "entry"
        )
        if type(data["sequence"]) is not int or not 0 <= data["sequence"] < MAX_LEDGER_ENTRIES:
            raise ValidationError("entry.sequence must be an integer within ledger limits")
        event = EvidenceEvent.from_dict(data["event"], "entry.event")
        # Reject normalization changes that could hide edits before hashing.
        if canonical_json(data["event"]) != canonical_json(event.to_dict()):
            raise ValidationError("entry.event must use the canonical event representation")
        if type(data["event_id"]) is not str or data["event_id"] != event.event_id:
            raise ValidationError("entry.event_id must match its event")
        return cls(
            data["sequence"],
            event.event_id,
            event.to_dict(),
            _hash(data["previous_digest"], "entry.previous_digest"),
            _hash(data["digest"], "entry.digest"),
        )


@dataclass(frozen=True, slots=True)
class EvidenceLedger:
    """An immutable chain; v1 receipts remain readable, new chains use v2."""

    entries: tuple[LedgerEntry, ...]
    genesis: str = _GENESIS
    schema_version: str = "1.0"

    def __post_init__(self) -> None:
        object.__setattr__(self, "entries", tuple(self.entries))

    def verify(self, *, expected_head: str | None = None) -> bool:
        """Verify every link and optionally compare an independently retained head."""
        if (
            type(self.schema_version) is not str
            or self.schema_version not in _VERSIONS
            or self.genesis != _VERSIONS[self.schema_version]
        ):
            return False
        if len(self.entries) > MAX_LEDGER_ENTRIES:
            return False
        previous = self.genesis
        identifiers: set[str] = set()
        for sequence, entry in enumerate(self.entries):
            if not isinstance(entry, LedgerEntry):
                return False
            try:
                parsed = LedgerEntry.from_dict(entry.to_dict())
                event = EvidenceEvent.from_dict(parsed.to_dict()["event"])
            except ValidationError:
                return False
            if parsed.sequence != sequence or parsed.event_id in identifiers:
                return False
            if parsed.previous_digest != previous or parsed.digest != _digest(
                previous, event, sequence, self.schema_version
            ):
                return False
            identifiers.add(parsed.event_id)
            previous = parsed.digest
        return expected_head is None or previous == expected_head

    @property
    def head_digest(self) -> str:
        return self.entries[-1].digest if self.entries else self.genesis

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "kind": "evidence-braid-ledger",
            "genesis": self.genesis,
            "head_digest": self.head_digest,
            "entry_count": len(self.entries),
            "entries": [entry.to_dict() for entry in self.entries],
            "verified": self.verify(),
        }

    @classmethod
    def from_dict(cls, value: Any, *, expected_head: str | None = None) -> EvidenceLedger:
        data = _fields(
            value,
            {
                "schema_version",
                "kind",
                "genesis",
                "head_digest",
                "entry_count",
                "entries",
                "verified",
            },
            "ledger",
        )
        version = data["schema_version"]
        if (
            type(version) is not str
            or version not in _VERSIONS
            or data["kind"] != "evidence-braid-ledger"
        ):
            raise ValidationError("unsupported ledger kind or schema_version")
        entries = data["entries"]
        if not isinstance(entries, list) or len(entries) > MAX_LEDGER_ENTRIES:
            raise ValidationError("ledger.entries must be an array within ledger limits")
        if type(data["entry_count"]) is not int or data["entry_count"] != len(entries):
            raise ValidationError("ledger.entry_count does not match entries")
        ledger = cls(
            tuple(LedgerEntry.from_dict(entry) for entry in entries), data["genesis"], version
        )
        if (
            data["verified"] is not True
            or data["head_digest"] != ledger.head_digest
            or not ledger.verify(expected_head=expected_head)
        ):
            raise ValidationError("ledger integrity verification failed")
        return ledger


def build_ledger(events: Iterable[EvidenceEvent]) -> EvidenceLedger:
    """Build a v2 chain ordered by ingestion time and event identity."""
    supplied: list[EvidenceEvent] = []
    for event in events:
        if not isinstance(event, EvidenceEvent):
            raise ValidationError("ledger events must be EvidenceEvent instances")
        if len(supplied) == MAX_LEDGER_ENTRIES:
            raise ValidationError("ledger exceeds maximum entry count")
        supplied.append(event)
    ordered = sorted(supplied, key=lambda event: (event.ingested_at, event.event_id))
    if len({event.event_id for event in ordered}) != len(ordered):
        raise ValidationError("ledger event IDs must be unique")
    entries: list[LedgerEntry] = []
    previous = _GENESIS_V2
    for sequence, event in enumerate(ordered):
        digest = _digest(previous, event, sequence, "2.0")
        entries.append(LedgerEntry(sequence, event.event_id, event.to_dict(), previous, digest))
        previous = digest
    return EvidenceLedger(tuple(entries), _GENESIS_V2, "2.0")


__all__ = ["EvidenceLedger", "LedgerEntry", "build_ledger"]
