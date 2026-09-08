"""Verified immutable ledger indexes and head/query-bound continuation tokens.

Filtering is not adjudication. Tokens carry no authentication and must not be
used as tenant authorization or proof that an untrusted client read every page.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from bisect import bisect_left
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType
from typing import Any

from .errors import ValidationError
from .io import _loads, canonical_json
from .ledger import MAX_LEDGER_ENTRIES, EvidenceLedger, LedgerEntry, _hash
from .models import EvidenceEvent, Modality, Signal, _text, format_timestamp, normalize_datetime

_FIELDS = ("event_id", "claim", "source", "modality", "signal", "correlation_group")
_MAX_INDEX_BYTES = 64 * 1024 * 1024
_MAX_PAGE_BYTES = 16 * 1024 * 1024
_MAX_TOKEN = 2048


def _count(value: Any, name: str, maximum: int, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValidationError(f"{name} must be an integer in {minimum}..{maximum}")
    return value


def _bytes(value: Any) -> bytes:
    return canonical_json(value, pretty=False).encode("utf-8")


@dataclass(frozen=True, slots=True)
class LedgerQuery:
    """AND across fields, OR within each nonempty exact-match tuple.

    Empty tuples mean no restriction. Time ranges are [start, end) in UTC.
    Returned order is ledger sequence, never reordered by event timestamps.
    """

    event_ids: tuple[str, ...] = ()
    claims: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()
    modalities: tuple[Modality, ...] = ()
    signals: tuple[Signal, ...] = ()
    correlation_groups: tuple[str, ...] = ()
    observed_start: datetime | None = None
    observed_end: datetime | None = None
    ingested_start: datetime | None = None
    ingested_end: datetime | None = None

    def __post_init__(self) -> None:
        total_bytes = 0
        for name in ("event_ids", "claims", "sources", "correlation_groups"):
            values = getattr(self, name)
            if type(values) is not tuple or len(values) > 128:
                raise ValidationError(f"{name} must be an immutable tuple of at most 128 values")
            for value in values:
                if type(value) is not str or len(value) > 4096:
                    raise ValidationError(f"{name} values must be bounded text")
                if _text(value, name) != value:
                    raise ValidationError(f"{name} values must already be normalized")
                size = len(value.encode("utf-8"))
                if size > 4096:
                    raise ValidationError(f"{name} value exceeds 4096 UTF-8 bytes")
                total_bytes += size
            if len(set(values)) != len(values):
                raise ValidationError(f"{name} values must be unique")
            object.__setattr__(self, name, tuple(sorted(values)))
        if total_bytes > 64 * 1024:
            raise ValidationError("query exact-match text exceeds 64 KiB")
        for name, kind in (("modalities", Modality), ("signals", Signal)):
            values = getattr(self, name)
            if (
                type(values) is not tuple
                or len(values) > len(kind)
                or any(type(value) is not kind for value in values)
                or len(set(values)) != len(values)
            ):
                raise ValidationError(f"{name} must be a tuple of unique typed enum values")
            object.__setattr__(self, name, tuple(sorted(values)))
        for clock in ("observed", "ingested"):
            for bound in ("start", "end"):
                name = f"{clock}_{bound}"
                value = getattr(self, name)
                if value is not None:
                    object.__setattr__(self, name, normalize_datetime(value, name))
            start, end = getattr(self, f"{clock}_start"), getattr(self, f"{clock}_end")
            if start is not None and end is not None and start >= end:
                raise ValidationError(f"{clock} range must have start before end")

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_ids": list(self.event_ids),
            "claims": list(self.claims),
            "sources": list(self.sources),
            "modalities": [value.value for value in self.modalities],
            "signals": [value.value for value in self.signals],
            "correlation_groups": list(self.correlation_groups),
            **{
                f"{clock}_{bound}": (
                    format_timestamp(value)
                    if (value := getattr(self, f"{clock}_{bound}")) is not None
                    else None
                )
                for clock in ("observed", "ingested")
                for bound in ("start", "end")
            },
        }

    @property
    def identity(self) -> str:
        return hashlib.sha256(_bytes({"query_version": "1.0", **self.to_dict()})).hexdigest()


@dataclass(frozen=True, slots=True, init=False)
class LedgerIndex:
    """Verify once and detach a head-anchored prefix; later appends cannot move it.

    The required head must be independently trusted when authenticity matters.
    prefix_count permits reopening an old retained prefix from an extended chain.
    The complete supplied chain is verified before accepting that prefix.
    """

    ledger: EvidenceLedger
    _events: tuple[EvidenceEvent, ...] = field(repr=False)
    _sizes: tuple[int, ...] = field(repr=False)
    _postings: Mapping[str, Mapping[str, tuple[int, ...]]] = field(repr=False)

    def __init__(
        self, ledger: EvidenceLedger, *, expected_head: str, prefix_count: int | None = None
    ) -> None:
        _hash(expected_head, "expected_head")
        if type(ledger) is not EvidenceLedger or len(ledger.entries) > MAX_LEDGER_ENTRIES:
            raise ValidationError("query index requires a verified ledger")
        sizes: list[int] = []
        total = 0
        for entry in ledger.entries:
            if type(entry) is not LedgerEntry:
                raise ValidationError("query index contains an invalid receipt")
            size = len(_bytes(entry.to_dict()))
            total += size
            if total > _MAX_INDEX_BYTES:
                raise ValidationError("indexed receipt bytes exceed 64 MiB")
            sizes.append(size)
        if not ledger.verify():
            raise ValidationError("query index requires a verified ledger")
        count = (
            len(ledger.entries)
            if prefix_count is None
            else _count(prefix_count, "prefix_count", len(ledger.entries))
        )
        snapshot = EvidenceLedger(ledger.entries[:count], ledger.genesis, ledger.schema_version)
        if snapshot.head_digest != expected_head:
            raise ValidationError("query prefix does not match the expected head")
        events: list[EvidenceEvent] = []
        postings: dict[str, dict[str, list[int]]] = {name: {} for name in _FIELDS}
        for entry in snapshot.entries:
            event = EvidenceEvent.from_dict(entry.to_dict()["event"])
            events.append(event)
            for name in _FIELDS:
                value = getattr(event, name)
                if value is not None:
                    postings[name].setdefault(str(value), []).append(entry.sequence)
        object.__setattr__(self, "ledger", snapshot)
        object.__setattr__(self, "_events", tuple(events))
        object.__setattr__(self, "_sizes", tuple(sizes[:count]))
        object.__setattr__(
            self,
            "_postings",
            MappingProxyType(
                {
                    name: MappingProxyType({key: tuple(rows) for key, rows in values.items()})
                    for name, values in postings.items()
                }
            ),
        )

    def select(self, query: LedgerQuery | None = None) -> LedgerSelection:
        return LedgerSelection(self, LedgerQuery() if query is None else query)


@dataclass(frozen=True, slots=True)
class LedgerPage:
    """Detached receipts and continuation metadata, not standalone chain proof."""

    entries: tuple[LedgerEntry, ...]
    head_digest: str
    snapshot_entries: int
    total_matches: int
    entry_bytes: int
    next_cursor: str | None
    query_identity: str

    def __post_init__(self) -> None:
        _hash(self.head_digest, "head_digest")
        _hash(self.query_identity, "query_identity")
        _count(self.snapshot_entries, "snapshot_entries", MAX_LEDGER_ENTRIES)
        _count(self.total_matches, "total_matches", self.snapshot_entries)
        _count(self.entry_bytes, "entry_bytes", _MAX_PAGE_BYTES)
        if type(self.entries) is not tuple or len(self.entries) > min(1000, self.total_matches):
            raise ValidationError("page entries must be a bounded immutable tuple")
        previous = -1
        size = 0
        for entry in self.entries:
            if type(entry) is not LedgerEntry:
                raise ValidationError("page contains an invalid receipt")
            LedgerEntry.from_dict(entry.to_dict())
            if not previous < entry.sequence < self.snapshot_entries:
                raise ValidationError("page receipt sequences must increase within the snapshot")
            previous = entry.sequence
            size += len(_bytes(entry.to_dict()))
        if size != self.entry_bytes:
            raise ValidationError("page entry byte accounting disagrees with receipts")
        if self.next_cursor is not None and (
            type(self.next_cursor) is not str
            or not self.next_cursor
            or len(self.next_cursor) > _MAX_TOKEN
        ):
            raise ValidationError("page cursor must be bounded text or None")

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": "evidence-braid-ledger-page",
            "schema_version": "1.0",
            "entries": [entry.to_dict() for entry in self.entries],
            "head_digest": self.head_digest,
            "snapshot_entries": self.snapshot_entries,
            "total_matches": self.total_matches,
            "entry_bytes": self.entry_bytes,
            "next_cursor": self.next_cursor,
            "query_identity": self.query_identity,
        }


@dataclass(frozen=True, slots=True, init=False)
class LedgerSelection:
    """A reusable indexed selection; pagination does not rerun the full query."""

    index: LedgerIndex = field(repr=False)
    query: LedgerQuery
    positions: tuple[int, ...]

    def __init__(self, index: LedgerIndex, query: LedgerQuery) -> None:
        if type(index) is not LedgerIndex or type(query) is not LedgerQuery:
            raise ValidationError("selection requires LedgerIndex and LedgerQuery")
        candidates: set[int] | None = None
        for name, values in zip(
            _FIELDS,
            (
                query.event_ids,
                query.claims,
                query.sources,
                query.modalities,
                query.signals,
                query.correlation_groups,
            ),
            strict=True,
        ):
            if values:
                union = {
                    row for value in values for row in index._postings[name].get(str(value), ())
                }
                candidates = union if candidates is None else candidates & union
        rows = range(len(index.ledger.entries)) if candidates is None else sorted(candidates)
        positions = []
        for position in rows:
            event = index._events[position]
            if all(
                (start is None or instant >= start) and (end is None or instant < end)
                for instant, start, end in (
                    (event.observed_at, query.observed_start, query.observed_end),
                    (event.ingested_at, query.ingested_start, query.ingested_end),
                )
            ):
                positions.append(position)
        object.__setattr__(self, "index", index)
        object.__setattr__(self, "query", query)
        object.__setattr__(self, "positions", tuple(positions))

    def _cursor(self, next_sequence: int) -> str:
        payload = {
            "kind": "evidence-braid-ledger-cursor",
            "schema_version": "1.0",
            "ledger_version": self.index.ledger.schema_version,
            "head": self.index.ledger.head_digest,
            "entries": len(self.index.ledger.entries),
            "query": self.query.identity,
            "next_sequence": next_sequence,
        }
        return base64.urlsafe_b64encode(_bytes(payload)).decode("ascii").rstrip("=")

    def _resume(self, cursor: str) -> int:
        if type(cursor) is not str or not 1 <= len(cursor) <= _MAX_TOKEN or not cursor.isascii():
            raise ValidationError("cursor must be bounded ASCII text")
        try:
            raw = base64.b64decode(cursor + "=" * (-len(cursor) % 4), altchars=b"-_", validate=True)
            data = _loads(raw.decode("utf-8"))
            if type(data) is not dict:
                raise ValueError("not an object")
            sequence = _count(
                data.get("next_sequence"), "next_sequence", len(self.index.ledger.entries)
            )
            if self._cursor(sequence) != cursor:
                raise ValueError("cursor identity or canonical encoding differs")
        except (ValueError, UnicodeError, binascii.Error, RecursionError) as exc:
            raise ValidationError("cursor does not match this snapshot and query") from exc
        return sequence

    def page(
        self,
        *,
        limit: int = 100,
        max_entry_bytes: int = 4 * 1024 * 1024,
        cursor: str | None = None,
    ) -> LedgerPage:
        _count(limit, "limit", 1000, 1)
        _count(max_entry_bytes, "max_entry_bytes", _MAX_PAGE_BYTES, 1)
        start = 0 if cursor is None else self._resume(cursor)
        offset = bisect_left(self.positions, start)
        entries: list[LedgerEntry] = []
        size = 0
        while offset < len(self.positions) and len(entries) < limit:
            position = self.positions[offset]
            proposed = size + self.index._sizes[position]
            if proposed > max_entry_bytes:
                if not entries:
                    raise ValidationError("next receipt exceeds the page byte budget")
                break
            entries.append(self.index.ledger.entries[position])
            size = proposed
            offset += 1
        continuation = (
            self._cursor(self.positions[offset]) if offset < len(self.positions) else None
        )
        return LedgerPage(
            tuple(entries),
            self.index.ledger.head_digest,
            len(self.index.ledger.entries),
            len(self.positions),
            size,
            continuation,
            self.query.identity,
        )


__all__ = ["LedgerIndex", "LedgerPage", "LedgerQuery", "LedgerSelection"]
