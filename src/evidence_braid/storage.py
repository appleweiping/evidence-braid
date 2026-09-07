"""SQLite-backed atomic append and bounded portable ledger interchange.

Connections are scoped to operations, so separate threads/processes can share
one store. SQLite serializes writers using BEGIN IMMEDIATE. Every append first
verifies the complete existing chain under that lock; no unchecked head cache
is trusted. This favors auditability over high-volume ingestion throughput.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path

from .errors import InputFormatError, ValidationError
from .io import _decode, _loads, _read_bounded, canonical_json, write_text
from .ledger import _GENESIS_V2, MAX_LEDGER_ENTRIES, EvidenceLedger, LedgerEntry, _digest, _hash
from .models import EvidenceEvent

MAX_LEDGER_BYTES = 64 * 1024 * 1024
MAX_ENTRY_BYTES = 1024 * 1024
MAX_APPEND_ENTRIES = 10_000
_APPLICATION_ID = 0x45425244


def load_ledger(path: str | Path, *, expected_head: str | None = None) -> EvidenceLedger:
    """Read a strict UTF-8 JSON snapshot, at most 64 MiB, and verify its chain."""
    source = Path(path)
    raw = _read_bounded(source, MAX_LEDGER_BYTES, "ledger")
    try:
        data = _loads(_decode(raw, source))
    except (ValueError, RecursionError) as exc:
        raise InputFormatError(f"invalid ledger JSON in {source}: {exc}") from exc
    return EvidenceLedger.from_dict(data, expected_head=expected_head)


def write_ledger(path: str | Path, ledger: EvidenceLedger) -> None:
    """Verify and write one portable snapshot under import bounds.

    This legacy export writes directly, so interruption may leave a partial
    destination. It does not share the workflow bundle's atomic publisher.
    """
    if not isinstance(ledger, EvidenceLedger) or not ledger.verify():
        raise ValidationError("cannot export an invalid ledger")
    content = canonical_json(ledger.to_dict(), pretty=False) + "\n"
    if len(content.encode("utf-8")) > MAX_LEDGER_BYTES:
        raise ValidationError("ledger export exceeds the 64 MiB limit")
    write_text(path, content)


class SQLiteLedger:
    """A local v2 evidence store with no public update/delete operations.

    ``create=False`` refuses missing stores. The default creates an empty
    database when absent, but refuses an unrelated SQLite database. Events are
    appended in supplied order, even if their ingestion timestamps are older.
    The returned snapshot is the exact state committed by that transaction.
    """

    def __init__(self, path: str | Path, *, create: bool = True, timeout: float = 10.0):
        if type(create) is not bool:
            raise ValidationError("create must be a boolean")
        if type(timeout) not in (int, float) or not 0 <= timeout <= 60:
            raise ValidationError("timeout must be finite and between 0 and 60 seconds")
        self.path = Path(path).absolute()
        self.timeout = float(timeout)
        with self._connection(create=create) as connection:
            connection.execute("BEGIN IMMEDIATE")
            marker = connection.execute("PRAGMA application_id").fetchone()[0]
            objects = connection.execute(
                "SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
            ).fetchall()
            if marker == 0 and not objects and create:
                connection.execute(f"PRAGMA application_id={_APPLICATION_ID}")
                connection.execute(
                    "CREATE TABLE ledger_meta (singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
                    "version TEXT NOT NULL, head TEXT NOT NULL, entries INTEGER NOT NULL)"
                )
                connection.execute(
                    "CREATE TABLE ledger_entries (sequence INTEGER PRIMARY KEY CHECK(sequence>=0), "
                    "event_id TEXT UNIQUE NOT NULL, event TEXT NOT NULL, "
                    "previous_digest TEXT NOT NULL, "
                    "digest TEXT NOT NULL)"
                )
                connection.execute(
                    "INSERT INTO ledger_meta VALUES (1, '2.0', ?, 0)", (_GENESIS_V2,)
                )
                connection.execute(
                    "CREATE TRIGGER ledger_no_update BEFORE UPDATE ON ledger_entries "
                    "BEGIN SELECT RAISE(ABORT, 'ledger entries are append-only'); END"
                )
                connection.execute(
                    "CREATE TRIGGER ledger_no_delete BEFORE DELETE ON ledger_entries "
                    "BEGIN SELECT RAISE(ABORT, 'ledger entries are append-only'); END"
                )
            elif marker != _APPLICATION_ID:
                raise ValidationError("database is not an Evidence Braid ledger")
            self._read(connection)

    @contextmanager
    def _connection(self, *, create: bool = False) -> Iterator[sqlite3.Connection]:
        connection: sqlite3.Connection | None = None
        try:
            mode = "rwc" if create else "rw"
            connection = sqlite3.connect(
                self.path.as_uri() + f"?mode={mode}", uri=True, timeout=self.timeout
            )
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA synchronous=FULL")
            with connection:
                yield connection
        except sqlite3.Error as exc:
            raise InputFormatError(f"ledger database operation failed: {exc}") from exc
        finally:
            if connection is not None:
                connection.close()

    @staticmethod
    def _read(connection: sqlite3.Connection) -> EvidenceLedger:
        meta = connection.execute(
            "SELECT singleton, version, head, entries FROM ledger_meta"
        ).fetchall()
        if len(meta) != 1 or meta[0][0] != 1 or meta[0][1] != "2.0":
            raise ValidationError("invalid ledger database metadata")
        count, total, largest = connection.execute(
            "SELECT count(*), coalesce(sum(length(cast(event AS BLOB))),0), "
            "coalesce(max(length(cast(event AS BLOB))),0) FROM ledger_entries"
        ).fetchone()
        if count > MAX_LEDGER_ENTRIES or total > MAX_LEDGER_BYTES or largest > MAX_ENTRY_BYTES:
            raise ValidationError("ledger database exceeds entry or byte limits")
        if type(meta[0][3]) is not int or meta[0][3] != count:
            raise ValidationError("ledger database entry count does not match metadata")
        entries: list[LedgerEntry] = []
        for sequence, identifier, raw, previous, digest in connection.execute(
            "SELECT sequence, event_id, event, previous_digest, digest "
            "FROM ledger_entries ORDER BY sequence"
        ):
            try:
                event = _loads(raw)
            except (TypeError, ValueError, RecursionError) as exc:
                raise InputFormatError("invalid stored ledger event JSON") from exc
            entries.append(
                LedgerEntry.from_dict(
                    {
                        "sequence": sequence,
                        "event_id": identifier,
                        "event": event,
                        "previous_digest": previous,
                        "digest": digest,
                    }
                )
            )
        ledger = EvidenceLedger(tuple(entries), _GENESIS_V2, "2.0")
        if not ledger.verify(expected_head=meta[0][2]):
            raise ValidationError("ledger database integrity verification failed")
        return ledger

    def snapshot(self, *, expected_head: str | None = None) -> EvidenceLedger:
        """Read and verify one consistent database snapshot."""
        if expected_head is not None:
            _hash(expected_head, "expected_head")
        with self._connection() as connection:
            connection.execute("BEGIN")
            ledger = self._read(connection)
            if not ledger.verify(expected_head=expected_head):
                raise ValidationError("ledger does not match the expected head")
            return ledger

    def append(
        self, events: Iterable[EvidenceEvent], *, expected_head: str | None = None
    ) -> EvidenceLedger:
        """Commit every supplied event or none; duplicate identities are errors."""
        if expected_head is not None:
            _hash(expected_head, "expected_head")
        supplied: list[EvidenceEvent] = []
        batch_bytes = 0
        for event in events:
            if not isinstance(event, EvidenceEvent):
                raise ValidationError("append requires EvidenceEvent instances")
            size = len(canonical_json(event.to_dict(), pretty=False).encode("utf-8"))
            batch_bytes += size
            if (
                size > MAX_ENTRY_BYTES
                or batch_bytes > MAX_LEDGER_BYTES
                or len(supplied) == MAX_APPEND_ENTRIES
            ):
                raise ValidationError("append exceeds entry or byte limits")
            supplied.append(event)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = self._read(connection)
            if expected_head is not None and existing.head_digest != expected_head:
                raise ValidationError("append conflict: expected head is stale")
            if len(existing.entries) + len(supplied) > MAX_LEDGER_ENTRIES:
                raise ValidationError("append exceeds ledger entry limit")
            existing_bytes = connection.execute(
                "SELECT coalesce(sum(length(cast(event AS BLOB))),0) FROM ledger_entries"
            ).fetchone()[0]
            if existing_bytes + batch_bytes > MAX_LEDGER_BYTES:
                raise ValidationError("append exceeds ledger byte limit")
            entries = list(existing.entries)
            previous = existing.head_digest
            for event in supplied:
                sequence = len(entries)
                digest = _digest(previous, event, sequence, "2.0")
                entry = LedgerEntry(sequence, event.event_id, event.to_dict(), previous, digest)
                self._insert(connection, entry)
                entries.append(entry)
                previous = digest
            connection.execute(
                "UPDATE ledger_meta SET head=?, entries=? WHERE singleton=1",
                (previous, len(entries)),
            )
            return EvidenceLedger(tuple(entries), _GENESIS_V2, "2.0")

    @staticmethod
    def _insert(connection: sqlite3.Connection, entry: LedgerEntry) -> None:
        connection.execute(
            "INSERT INTO ledger_entries VALUES (?, ?, ?, ?, ?)",
            (
                entry.sequence,
                entry.event_id,
                canonical_json(entry.to_dict()["event"], pretty=False),
                entry.previous_digest,
                entry.digest,
            ),
        )

    def import_snapshot(self, ledger: EvidenceLedger) -> EvidenceLedger:
        """Atomically import an intact v2 chain into an empty store only."""
        if (
            not isinstance(ledger, EvidenceLedger)
            or ledger.schema_version != "2.0"
            or not ledger.verify()
        ):
            raise ValidationError("import requires a verified v2 ledger")
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if self._read(connection).entries:
                raise ValidationError("import requires an empty ledger database")
            for entry in ledger.entries:
                self._insert(connection, entry)
            connection.execute(
                "UPDATE ledger_meta SET head=?, entries=? WHERE singleton=1",
                (ledger.head_digest, len(ledger.entries)),
            )
            return self._read(connection)


__all__ = ["SQLiteLedger", "load_ledger", "write_ledger"]
