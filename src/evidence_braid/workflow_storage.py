"""Original local CAS/idempotency journal around the existing workflow replay engine.

One consistent transaction verifies the current workflow and a disjoint-range
operation journal. Authority declarations are independently supplied, not signed
actor authentication. A context alone is not a rollback/fork trust anchor.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
from collections.abc import Callable
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, Literal, TypeVar

from .authority import ArtifactReference, AuthorityPolicy, WorkflowTransition, _identifier, _integer
from .errors import InputFormatError, ValidationError
from .io import _loads
from .ledger import EvidenceLedger, _fields, _hash
from .workflow import WorkflowBundle, WorkflowReceipt, replay_workflow

_T = TypeVar("_T")
_Outcome = Literal["none", "unknown", "complete"]
_APPLICATION_ID = 0x45425746
_SCHEMA = (
    (
        "table",
        "workflow_context",
        "CREATE TABLE workflow_context (singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
        "document BLOB NOT NULL)",
    ),
    (
        "table",
        "workflow_receipts",
        "CREATE TABLE workflow_receipts (sequence INTEGER PRIMARY KEY CHECK(sequence>=0), "
        "document BLOB NOT NULL)",
    ),
    (
        "table",
        "workflow_operations",
        "CREATE TABLE workflow_operations (sequence INTEGER PRIMARY KEY CHECK(sequence>=0), "
        "request_id TEXT UNIQUE NOT NULL, document BLOB NOT NULL)",
    ),
    (
        "table",
        "workflow_meta",
        "CREATE TABLE workflow_meta (singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
        "document BLOB NOT NULL)",
    ),
    *(
        (
            "trigger",
            f"{table}_no_{action.lower()}",
            f"CREATE TRIGGER {table}_no_{action.lower()} BEFORE {action} ON {table} "
            "BEGIN SELECT RAISE(ABORT, 'workflow history is append-only'); END",
        )
        for table in ("workflow_context", "workflow_receipts", "workflow_operations")
        for action in ("UPDATE", "DELETE")
    ),
)


@dataclass(frozen=True, slots=True)
class WorkflowStoreLimits:
    max_bundle_bytes: int = 64 * 1024 * 1024
    max_records: int = 10_000
    max_receipt_bytes: int = 256 * 1024
    max_append_records: int = 1_000
    max_request_bytes: int = 8 * 1024 * 1024
    max_operations: int = 10_000
    max_operation_bytes: int = 8 * 1024
    max_operations_bytes: int = 16 * 1024 * 1024

    def __post_init__(self) -> None:
        for name, maximum in (
            ("max_bundle_bytes", 64 * 1024 * 1024),
            ("max_records", 10_000),
            ("max_receipt_bytes", 256 * 1024),
            ("max_append_records", 1_000),
            ("max_request_bytes", 8 * 1024 * 1024),
            ("max_operations", 10_000),
            ("max_operation_bytes", 8 * 1024),
            ("max_operations_bytes", 16 * 1024 * 1024),
        ):
            _integer(getattr(self, name), name, maximum, 1)


class WorkflowConflictError(ValidationError):
    """A stale exact checkpoint or conflicting use of a retained request ID."""


class WorkflowStorageError(InputFormatError):
    """An I/O/SQLite failure with an explicit mutation-acknowledgement outcome."""

    def __init__(
        self, outcome: _Outcome, request_id: str | None = None, request_digest: str | None = None
    ):
        if outcome not in ("none", "unknown", "complete"):
            raise ValueError("invalid workflow storage outcome")
        self.outcome = outcome
        self.request_id = request_id
        self.request_digest = request_digest
        super().__init__(
            f"workflow storage operation failed; commit outcome={outcome}; "
            "inspect or look up the operation before retrying"
        )


@dataclass(frozen=True, slots=True)
class WorkflowCheckpoint:
    context_digest: str
    record_count: int
    workflow_head: str
    operation_count: int
    operation_head: str

    def __post_init__(self) -> None:
        for name in ("context_digest", "workflow_head", "operation_head"):
            _hash(getattr(self, name), name)
        _integer(self.record_count, "record_count", 10_000)
        _integer(self.operation_count, "operation_count", self.record_count)
        if self.record_count == 0 and self.workflow_head != self.context_digest:
            raise ValidationError("empty workflow checkpoint must use its context head")

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": "1.0", **asdict(self)}

    @classmethod
    def from_dict(cls, value: Any) -> WorkflowCheckpoint:
        node = _fields(value, {"schema_version", *cls.__dataclass_fields__}, "checkpoint")
        if node["schema_version"] != "1.0":
            raise ValidationError("unsupported workflow checkpoint version")
        return cls(*(node[name] for name in cls.__dataclass_fields__))


@dataclass(frozen=True, slots=True)
class StoredWorkflow:
    bundle: WorkflowBundle
    checkpoint: WorkflowCheckpoint

    def __post_init__(self) -> None:
        if (
            type(self.bundle) is not WorkflowBundle
            or type(self.checkpoint) is not WorkflowCheckpoint
        ):
            raise ValidationError("stored workflow requires exact bundle and checkpoint types")
        if (self.bundle.context_digest, len(self.bundle.records), self.bundle.head_digest) != (
            self.checkpoint.context_digest,
            self.checkpoint.record_count,
            self.checkpoint.workflow_head,
        ):
            raise ValidationError("stored workflow does not match its checkpoint")

    def to_dict(self) -> dict[str, Any]:
        return {"bundle": self.bundle.to_dict(), "checkpoint": self.checkpoint.to_dict()}


@dataclass(frozen=True, slots=True)
class WorkflowCommit:
    request_id: str
    request_digest: str
    previous: WorkflowCheckpoint
    result: StoredWorkflow

    def __post_init__(self) -> None:
        _identifier(self.request_id, "request_id")
        _hash(self.request_digest, "request_digest")
        if type(self.previous) is not WorkflowCheckpoint or type(self.result) is not StoredWorkflow:
            raise ValidationError("commit requires exact checkpoint and snapshot types")
        after = self.result.checkpoint
        if (
            self.previous.context_digest != after.context_digest
            or after.operation_count != self.previous.operation_count + 1
            or not self.previous.record_count
            < after.record_count
            <= self.previous.record_count + 1_000
            or _head(self.result.bundle, self.previous.record_count) != self.previous.workflow_head
        ):
            raise ValidationError("commit checkpoints do not describe a nonempty append")
        transitions = tuple(
            r.transition for r in self.result.bundle.records[self.previous.record_count :]
        )
        if (
            _request_digest(self.request_id, self.previous, transitions, WorkflowStoreLimits())
            != self.request_digest
        ):
            raise ValidationError("commit request digest does not match its receipt range")
        _, expected = _operation(
            self.request_id, self.request_digest, self.previous, self.result.bundle
        )
        if expected != after:
            raise ValidationError("commit operation head does not bind its result")

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "request_digest": self.request_digest,
            "previous": self.previous.to_dict(),
            "result": self.result.to_dict(),
        }


def _bytes(value: Any, maximum: int) -> bytes:
    result = bytearray()
    encoder = json.JSONEncoder(
        ensure_ascii=False, sort_keys=True, allow_nan=False, separators=(",", ":")
    )
    for chunk in encoder.iterencode(value):
        encoded = chunk.encode("utf-8")
        if len(result) + len(encoded) > maximum:
            raise ValidationError("workflow store canonical byte limit exceeded")
        result.extend(encoded)
    return bytes(result)


def _parse(raw: bytes) -> dict[str, Any]:
    try:
        result = _loads(raw.decode("utf-8"))
        if type(result) is not dict or _bytes(result, len(raw)) != raw:
            raise ValidationError("stored workflow JSON must be a canonical object")
        return result
    except (UnicodeError, ValueError, RecursionError) as error:
        raise ValidationError("invalid stored workflow canonical JSON") from error


def _digest(value: Any, maximum: int = 8192) -> str:
    return hashlib.sha256(_bytes(value, maximum)).hexdigest()


def _checkpoint(value: WorkflowCheckpoint) -> WorkflowCheckpoint:
    if type(value) is not WorkflowCheckpoint:
        raise ValidationError("expected must be an exact WorkflowCheckpoint")
    return WorkflowCheckpoint.from_dict(value.to_dict())


def _head(bundle: WorkflowBundle, count: int) -> str:
    return bundle.records[count - 1].digest if count else bundle.context_digest


def _genesis(bundle: WorkflowBundle, initial_count: int) -> WorkflowCheckpoint:
    head = _head(bundle, initial_count)
    return WorkflowCheckpoint(
        bundle.context_digest,
        initial_count,
        head,
        0,
        _digest(
            {
                "kind": "evidence-braid-workflow-operation-genesis",
                "schema_version": "1.0",
                "context_digest": bundle.context_digest,
                "initial_record_count": initial_count,
                "initial_workflow_head": head,
            }
        ),
    )


def _context(bundle: WorkflowBundle, initial_count: int) -> dict[str, Any]:
    return {
        "kind": "evidence-braid-workflow-store-context",
        "schema_version": "1.0",
        "workflow_id": bundle.workflow_id,
        "authority_digest": bundle.authority_digest,
        "evidence": bundle.evidence.to_dict(),
        "artifacts": [a.to_dict() for a in bundle.artifacts],
        "context_digest": bundle.context_digest,
        "initial_record_count": initial_count,
        "initial_workflow_head": _head(bundle, initial_count),
    }


def _request_digest(
    request_id: str,
    expected: WorkflowCheckpoint,
    transitions: tuple[WorkflowTransition, ...],
    limits: WorkflowStoreLimits,
) -> str:
    return _digest(
        {
            "kind": "evidence-braid-workflow-request",
            "schema_version": "1.0",
            "request_id": request_id,
            "expected_checkpoint": expected.to_dict(),
            "transitions": [t.to_dict() for t in transitions],
        },
        limits.max_request_bytes,
    )


def _operation(
    request_id: str, request_digest: str, previous: WorkflowCheckpoint, bundle: WorkflowBundle
) -> tuple[dict[str, Any], WorkflowCheckpoint]:
    content = {
        "kind": "evidence-braid-workflow-operation",
        "schema_version": "1.0",
        "sequence": previous.operation_count,
        "request_id": request_id,
        "request_digest": request_digest,
        "expected_checkpoint": previous.to_dict(),
        "result_record_count": len(bundle.records),
        "result_workflow_head": bundle.head_digest,
        "previous_digest": previous.operation_head,
    }
    digest = _digest(content)
    return {**content, "digest": digest}, WorkflowCheckpoint(
        bundle.context_digest,
        len(bundle.records),
        bundle.head_digest,
        previous.operation_count + 1,
        digest,
    )


@dataclass(frozen=True, slots=True)
class _Operation:
    request_id: str
    request_digest: str
    previous: WorkflowCheckpoint
    result: WorkflowCheckpoint


@dataclass(slots=True)
class _Transaction:
    outcome: _Outcome = "none"
    dirty: bool = False
    # Only an acknowledged close grants cleanup ownership. Setup may acquire a
    # connection and fail before returning it to _run; that state is not closed.
    closed: bool = False


@dataclass(frozen=True, slots=True)
class _Read:
    snapshot: StoredWorkflow
    operations: tuple[_Operation, ...]
    operation_bytes: int
    stored_payload_bytes: int


def _file_identity(info: os.stat_result) -> tuple[int, int]:
    if not stat.S_ISREG(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ValidationError("workflow database must be a regular nonsymlink/nonreparse file")
    device, inode = info.st_dev, info.st_ino
    # Windows may expose a 128-bit file identifier. Zero/absent identifiers are
    # not evidence of sameness: two unrelated files could otherwise compare equal.
    if (
        type(device) is not int
        or type(inode) is not int
        or not 0 <= device < 1 << 128
        or not 0 < inode < 1 << 128
    ):
        raise ValidationError("workflow database requires an available stable file identity")
    return device, inode


def _regular(path: Path) -> tuple[int, int]:
    return _file_identity(path.lstat())


def _path(value: str | Path) -> Path:
    if not isinstance(value, (str, Path)):
        raise ValidationError("workflow database must be a local path")
    text = str(value)
    remainder = text[2:] if re.match(r"^[A-Za-z]:[\\/]", text) else text
    if (
        not text
        or any(ord(c) < 32 for c in text)
        or ":" in remainder
        or text.startswith(("//", "\\\\"))
    ):
        raise ValidationError("workflow database must be a local path without protocols")
    supplied = Path(value).absolute()
    return supplied.parent.resolve(strict=True) / supplied.name


def _schema(connection: sqlite3.Connection) -> None:
    if (
        connection.execute("PRAGMA application_id").fetchone()[0] != _APPLICATION_ID
        or connection.execute("PRAGMA user_version").fetchone()[0] != 1
    ):
        raise ValidationError("database is not the supported workflow store format")
    expected: set[tuple[str, str, str | None]] = {(kind, name, sql) for kind, name, sql in _SCHEMA}
    expected.add(("index", "sqlite_autoindex_workflow_operations_1", None))
    count, name_bytes, sql_bytes = connection.execute(
        "SELECT count(*), coalesce(max(length(cast(name AS BLOB))),0), "
        "coalesce(max(length(cast(sql AS BLOB))),0) FROM sqlite_schema"
    ).fetchone()
    if count != len(expected) or name_bytes > 128 or sql_bytes > 1024:
        raise ValidationError("workflow database schema exceeds its closed metadata bounds")
    actual = connection.execute(
        "SELECT type, name, sql FROM sqlite_schema LIMIT ?", (len(expected) + 1,)
    ).fetchall()
    if len(actual) != len(expected) or set(actual) != expected:
        raise ValidationError("workflow database schema differs from its closed format")


def _admit_table(
    connection: sqlite3.Connection,
    table: str,
    *,
    count_limit: int,
    item_limit: int,
    total_limit: int,
) -> tuple[int, int]:
    # Complete literal queries keep admission closed even for an internal caller.
    query = {
        "workflow_context": "SELECT count(*), coalesce(sum(length(document)),0), "
        "coalesce(max(length(document)),0), coalesce(sum(typeof(document) != 'blob'),0) "
        "FROM workflow_context",
        "workflow_meta": "SELECT count(*), coalesce(sum(length(document)),0), "
        "coalesce(max(length(document)),0), coalesce(sum(typeof(document) != 'blob'),0) "
        "FROM workflow_meta",
        "workflow_receipts": "SELECT count(*), coalesce(sum(length(document)),0), "
        "coalesce(max(length(document)),0), coalesce(sum(typeof(document) != 'blob'),0) "
        "FROM workflow_receipts",
        "workflow_operations": "SELECT count(*), coalesce(sum(length(document)),0), "
        "coalesce(max(length(document)),0), coalesce(sum(typeof(document) != 'blob'),0) "
        "FROM workflow_operations",
    }[table]
    rows = connection.execute(query).fetchone()
    count, total, largest, wrong = rows
    if count > count_limit or total > total_limit or largest > item_limit or wrong:
        raise ValidationError("workflow database exceeds canonical BLOB type/count/byte limits")
    return count, total


class SQLiteWorkflowStore:
    """Existing-only local store with fixed externally trusted authority/context.

    Supplied read checkpoints are exact-current anchors, not prefix selectors.
    Context-only opening verifies internal consistency, not rollback resistance.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        authority: AuthorityPolicy,
        expected_context: str,
        expected: WorkflowCheckpoint | None = None,
        timeout: float = 10.0,
        limits: WorkflowStoreLimits | None = None,
    ):
        self._configure(path, authority, expected_context, timeout, limits)
        self._identity: tuple[int, int] | None = None
        self.snapshot(expected=expected)

    def _configure(
        self,
        path: str | Path,
        authority: AuthorityPolicy,
        expected_context: str,
        timeout: float,
        limits: WorkflowStoreLimits | None,
    ) -> None:
        if type(authority) is not AuthorityPolicy:
            raise ValidationError(
                "workflow store requires an independently trusted AuthorityPolicy"
            )
        _hash(expected_context, "expected_context")
        if type(timeout) not in (int, float) or not 0 <= timeout <= 60:
            raise ValidationError("timeout must be finite and between 0 and 60 seconds")
        if limits is not None and type(limits) is not WorkflowStoreLimits:
            raise ValidationError("limits must be WorkflowStoreLimits or None")
        self._authority = AuthorityPolicy.from_dict(authority.to_dict())
        self._context_digest = expected_context
        self._limits = WorkflowStoreLimits() if limits is None else replace(limits)
        self._timeout = float(timeout)
        try:
            self._path = _path(path)
        except OSError as error:
            raise WorkflowStorageError("none") from error

    @property
    def path(self) -> Path:
        return self._path

    def _connect(self, writable: bool) -> sqlite3.Connection:
        before = _regular(self._path)
        if self._identity is not None and before != self._identity:
            raise ValidationError("workflow database file was replaced")
        connection = sqlite3.connect(
            self._path.as_uri() + ("?mode=rw" if writable else "?mode=ro"),
            uri=True,
            timeout=self._timeout,
            isolation_level=None,
        )
        try:
            if _regular(self._path) != before:
                raise ValidationError("workflow database changed while opening")
            connection.execute("PRAGMA trusted_schema=OFF")
            if writable:
                connection.execute("PRAGMA synchronous=FULL")
            self._identity = before
            return connection
        except BaseException as primary:
            try:
                connection.close()
            except BaseException as cleanup:
                if isinstance(primary, Exception) and not isinstance(cleanup, Exception):
                    raise cleanup from primary
                primary.add_note("workflow connection setup close failed")
            raise

    @staticmethod
    def _commit(connection: sqlite3.Connection) -> None:
        connection.commit()

    @staticmethod
    def _close(connection: sqlite3.Connection) -> None:
        connection.close()

    def _run(
        self,
        action: Callable[[sqlite3.Connection, _Transaction], _T],
        *,
        writable: bool,
        request_id: str | None = None,
        request_digest: str | None = None,
        transaction: _Transaction | None = None,
    ) -> _T:
        state = _Transaction() if transaction is None else transaction
        connection: sqlite3.Connection | None = None
        primary: BaseException | None = None
        try:
            state.closed = False
            connection = self._connect(writable)
            connection.execute("BEGIN IMMEDIATE" if writable else "BEGIN")
            result = action(connection, state)
            if state.dirty:
                state.outcome = "unknown"
                self._commit(connection)
                state.outcome = "complete"
            else:
                connection.rollback()
        except BaseException as error:
            primary = error
        if connection is not None:
            cleanups: tuple[tuple[str, Callable[[], None]], ...] = (
                ("rollback", lambda: connection.rollback()),
                ("close", lambda: self._close(connection)),
            )
            for label, cleanup in cleanups:
                try:
                    cleanup()
                    if label == "close":
                        state.closed = True
                except BaseException as error:
                    if primary is None or (
                        isinstance(primary, Exception) and not isinstance(error, Exception)
                    ):
                        if primary is not None:
                            error.add_note(f"prior workflow failure: {type(primary).__name__}")
                        primary = error
                    else:
                        primary.add_note(f"workflow {label} also failed")
        if primary is not None:
            primary.add_note(f"workflow commit outcome={state.outcome}; request_id={request_id}")
            if not isinstance(primary, Exception) or (
                isinstance(primary, ValidationError) and state.outcome == "none"
            ):
                raise primary
            raise WorkflowStorageError(state.outcome, request_id, request_digest) from primary
        return result

    def _read(self, connection: sqlite3.Connection) -> _Read:
        _schema(connection)
        limits = self._limits
        context_count, context_bytes = _admit_table(
            connection,
            "workflow_context",
            count_limit=1,
            item_limit=limits.max_bundle_bytes,
            total_limit=limits.max_bundle_bytes,
        )
        meta_count, _ = _admit_table(
            connection, "workflow_meta", count_limit=1, item_limit=8192, total_limit=8192
        )
        record_count, receipt_bytes = _admit_table(
            connection,
            "workflow_receipts",
            count_limit=limits.max_records,
            item_limit=limits.max_receipt_bytes,
            total_limit=limits.max_bundle_bytes,
        )
        operation_count, operation_bytes = _admit_table(
            connection,
            "workflow_operations",
            count_limit=limits.max_operations,
            item_limit=limits.max_operation_bytes,
            total_limit=limits.max_operations_bytes,
        )
        wrong_identifiers = connection.execute(
            "SELECT count(*) FROM workflow_operations WHERE typeof(request_id) != 'text' "
            "OR length(cast(request_id AS BLOB)) NOT BETWEEN 1 AND 128"
        ).fetchone()[0]
        if wrong_identifiers:
            raise ValidationError("stored workflow request IDs exceed type/byte limits")
        if (
            context_count != 1
            or meta_count != 1
            or context_bytes + receipt_bytes > limits.max_bundle_bytes
        ):
            raise ValidationError(
                "workflow database context/meta or aggregate byte limits disagree"
            )
        if (
            connection.execute("SELECT singleton FROM workflow_context").fetchone()[0] != 1
            or connection.execute("SELECT singleton FROM workflow_meta").fetchone()[0] != 1
        ):
            raise ValidationError("invalid workflow database singleton")
        # No BLOB is selected before all four tables have passed the admission pass.
        context_raw = connection.execute("SELECT document FROM workflow_context").fetchone()[0]
        context = _fields(
            _parse(context_raw),
            {
                "kind",
                "schema_version",
                "workflow_id",
                "authority_digest",
                "evidence",
                "artifacts",
                "context_digest",
                "initial_record_count",
                "initial_workflow_head",
            },
            "store context",
        )
        if (
            context["kind"] != "evidence-braid-workflow-store-context"
            or context["schema_version"] != "1.0"
            or context["context_digest"] != self._context_digest
            or context["authority_digest"] != self._authority.digest
        ):
            raise ValidationError("workflow store context or independent authority does not match")
        _integer(context["initial_record_count"], "initial_record_count", record_count)
        records: list[WorkflowReceipt] = []
        for sequence, raw in connection.execute(
            "SELECT sequence, document FROM workflow_receipts ORDER BY sequence"
        ):
            if type(sequence) is not int or sequence != len(records):
                raise ValidationError("stored workflow receipt sequence is not contiguous")
            records.append(WorkflowReceipt.from_dict(_parse(raw)))
        if type(context["artifacts"]) is not list:
            raise ValidationError("stored workflow artifacts must be an array")
        bundle = WorkflowBundle(
            context["workflow_id"],
            context["authority_digest"],
            EvidenceLedger.from_dict(context["evidence"]),
            tuple(ArtifactReference.from_dict(a) for a in context["artifacts"]),
            tuple(records),
        )
        _bytes(bundle.to_dict(), limits.max_bundle_bytes)
        replay_workflow(bundle, authority=self._authority)
        if (
            _bytes(_context(bundle, context["initial_record_count"]), limits.max_bundle_bytes)
            != context_raw
        ):
            raise ValidationError("stored workflow context is not its exact derived representation")
        checkpoint = _genesis(bundle, context["initial_record_count"])
        operations: list[_Operation] = []
        for sequence, identifier, raw in connection.execute(
            "SELECT sequence, request_id, document FROM workflow_operations ORDER BY sequence"
        ):
            node = _fields(
                _parse(raw),
                {
                    "kind",
                    "schema_version",
                    "sequence",
                    "request_id",
                    "request_digest",
                    "expected_checkpoint",
                    "result_record_count",
                    "result_workflow_head",
                    "previous_digest",
                    "digest",
                },
                "operation",
            )
            if (
                type(sequence) is not int
                or sequence != len(operations)
                or type(node["sequence"]) is not int
                or node["sequence"] != sequence
            ):
                raise ValidationError("stored workflow operation sequence is not contiguous")
            _identifier(identifier, "stored request_id")
            _integer(
                node["result_record_count"],
                "operation result count",
                record_count,
                checkpoint.record_count + 1,
            )
            end = node["result_record_count"]
            if end - checkpoint.record_count > limits.max_append_records:
                raise ValidationError("stored workflow operation exceeds append count limit")
            request_digest = _request_digest(
                identifier,
                checkpoint,
                tuple(r.transition for r in bundle.records[checkpoint.record_count : end]),
                limits,
            )
            content = {
                "kind": "evidence-braid-workflow-operation",
                "schema_version": "1.0",
                "sequence": sequence,
                "request_id": identifier,
                "request_digest": request_digest,
                "expected_checkpoint": checkpoint.to_dict(),
                "result_record_count": end,
                "result_workflow_head": _head(bundle, end),
                "previous_digest": checkpoint.operation_head,
            }
            digest = _digest(content)
            if _bytes({**content, "digest": digest}, limits.max_operation_bytes) != raw:
                raise ValidationError(
                    "stored operation does not bind its exact workflow receipt range"
                )
            after = WorkflowCheckpoint(
                checkpoint.context_digest, end, _head(bundle, end), sequence + 1, digest
            )
            operations.append(_Operation(identifier, request_digest, checkpoint, after))
            checkpoint = after
        stored_checkpoint = WorkflowCheckpoint.from_dict(
            _parse(connection.execute("SELECT document FROM workflow_meta").fetchone()[0])
        )
        if (
            checkpoint != stored_checkpoint
            or checkpoint.record_count != record_count
            or checkpoint.operation_count != operation_count
        ):
            raise ValidationError(
                "stored workflow checkpoint or operation partition disagrees with history"
            )
        return _Read(
            StoredWorkflow(bundle, checkpoint),
            tuple(operations),
            operation_bytes,
            context_bytes + receipt_bytes,
        )

    def snapshot(self, *, expected: WorkflowCheckpoint | None = None) -> StoredWorkflow:
        anchor = None if expected is None else _checkpoint(expected)

        def read(connection: sqlite3.Connection, state: _Transaction) -> StoredWorkflow:
            result = self._read(connection).snapshot
            if anchor is not None and result.checkpoint != anchor:
                raise WorkflowConflictError(
                    "workflow current checkpoint does not match the external anchor"
                )
            return result

        return self._run(read, writable=False)

    def _historical(self, current: WorkflowBundle, operation: _Operation) -> WorkflowCommit:
        bundle = replace(current, records=current.records[: operation.result.record_count])
        replay_workflow(bundle, authority=self._authority)
        return WorkflowCommit(
            operation.request_id,
            operation.request_digest,
            operation.previous,
            StoredWorkflow(bundle, operation.result),
        )

    def lookup(self, request_id: str, *, expected_request_digest: str) -> WorkflowCommit | None:
        _identifier(request_id, "request_id")
        _hash(expected_request_digest, "expected_request_digest")

        def read(connection: sqlite3.Connection, state: _Transaction) -> WorkflowCommit | None:
            current = self._read(connection)
            for operation in current.operations:
                if operation.request_id == request_id:
                    if operation.request_digest != expected_request_digest:
                        raise WorkflowConflictError(
                            "request ID is bound to different canonical input"
                        )
                    result = self._historical(current.snapshot.bundle, operation)
                    state.outcome = "complete"
                    return result
            return None

        return self._run(
            read, writable=False, request_id=request_id, request_digest=expected_request_digest
        )

    def _prepare(
        self,
        transitions: tuple[WorkflowTransition, ...] | list[WorkflowTransition],
        *,
        request_id: str,
        expected: WorkflowCheckpoint,
    ) -> tuple[WorkflowCheckpoint, tuple[WorkflowTransition, ...], str]:
        _identifier(request_id, "request_id")
        before = _checkpoint(expected)
        if before.context_digest != self._context_digest:
            raise WorkflowConflictError("expected checkpoint belongs to another context")
        limits = self._limits
        if (
            type(transitions) not in (tuple, list)
            or not 1 <= len(transitions) <= limits.max_append_records
        ):
            raise ValidationError("append requires a bounded nonempty exact tuple/list")
        commands: list[WorkflowTransition] = []
        for item in transitions:
            if type(item) is not WorkflowTransition or len(commands) >= limits.max_append_records:
                raise ValidationError("append requires bounded exact WorkflowTransition values")
            commands.append(WorkflowTransition.from_dict(item.to_dict()))
        if not commands:
            raise ValidationError("append requires at least one transition")
        supplied = tuple(commands)
        request_digest = _request_digest(request_id, before, supplied, limits)
        return before, supplied, request_digest

    def request_digest(
        self,
        transitions: tuple[WorkflowTransition, ...] | list[WorkflowTransition],
        *,
        request_id: str,
        expected: WorkflowCheckpoint,
    ) -> str:
        """Admit/own the exact request and compute identity without accessing storage."""
        return self._prepare(transitions, request_id=request_id, expected=expected)[2]

    def append(
        self,
        transitions: tuple[WorkflowTransition, ...] | list[WorkflowTransition],
        *,
        request_id: str,
        expected: WorkflowCheckpoint,
    ) -> WorkflowCommit:
        before, supplied, request_digest = self._prepare(
            transitions, request_id=request_id, expected=expected
        )
        limits = self._limits

        def append(connection: sqlite3.Connection, state: _Transaction) -> WorkflowCommit:
            current = self._read(connection)
            for operation in current.operations:
                if operation.request_id == request_id:
                    if operation.request_digest != request_digest:
                        raise WorkflowConflictError(
                            "request ID is bound to different canonical input"
                        )
                    result = self._historical(current.snapshot.bundle, operation)
                    state.outcome = "complete"
                    return result
            if current.snapshot.checkpoint != before:
                raise WorkflowConflictError("append checkpoint is stale")
            if (
                before.record_count + len(supplied) > limits.max_records
                or before.operation_count >= limits.max_operations
            ):
                raise ValidationError("workflow append exceeds record or operation limits")
            # This single existing engine authorizes the WHOLE batch before any INSERT.
            candidate = current.snapshot.bundle.append(supplied, authority=self._authority)
            _bytes(candidate.to_dict(), limits.max_bundle_bytes)
            rows = tuple(
                _bytes(r.to_dict(), limits.max_receipt_bytes)
                for r in candidate.records[before.record_count :]
            )
            if current.stored_payload_bytes + sum(map(len, rows)) > limits.max_bundle_bytes:
                raise ValidationError("workflow append exceeds stored aggregate byte limit")
            operation_document, after = _operation(request_id, request_digest, before, candidate)
            raw = _bytes(operation_document, limits.max_operation_bytes)
            if current.operation_bytes + len(raw) > limits.max_operations_bytes:
                raise ValidationError("workflow append exceeds aggregate operation byte limit")
            result = WorkflowCommit(
                request_id, request_digest, before, StoredWorkflow(candidate, after)
            )
            metadata = _bytes(after.to_dict(), 8192)
            for offset, row in enumerate(rows, before.record_count):
                connection.execute("INSERT INTO workflow_receipts VALUES (?, ?)", (offset, row))
            connection.execute(
                "INSERT INTO workflow_operations VALUES (?, ?, ?)",
                (before.operation_count, request_id, raw),
            )
            connection.execute("UPDATE workflow_meta SET document=? WHERE singleton=1", (metadata,))
            state.dirty = True
            return result

        return self._run(
            append, writable=True, request_id=request_id, request_digest=request_digest
        )


def create_workflow_store(
    path: str | Path,
    initial: WorkflowBundle,
    *,
    authority: AuthorityPolicy,
    expected_context: str,
    expected_head: str,
    timeout: float = 10.0,
    limits: WorkflowStoreLimits | None = None,
) -> SQLiteWorkflowStore:
    """Explicit exclusive creation; never remove a possibly committed database."""
    if type(initial) is not WorkflowBundle:
        raise ValidationError("initial must be an exact WorkflowBundle")
    _hash(expected_head, "expected_head")
    store = object.__new__(SQLiteWorkflowStore)
    store._configure(path, authority, expected_context, timeout, limits)
    active = store._limits
    raw_initial = _bytes(initial.to_dict(), active.max_bundle_bytes)
    bundle = WorkflowBundle.from_dict(
        _parse(raw_initial), authority=store._authority, expected_head=expected_head
    )
    if bundle.context_digest != expected_context or len(bundle.records) > active.max_records:
        raise ValidationError("initial workflow context or record limit does not match")
    checkpoint = _genesis(bundle, len(bundle.records))
    context = _bytes(_context(bundle, len(bundle.records)), active.max_bundle_bytes)
    receipts = tuple(_bytes(r.to_dict(), active.max_receipt_bytes) for r in bundle.records)
    if len(context) + sum(map(len, receipts)) > active.max_bundle_bytes:
        raise ValidationError("initial workflow exceeds stored aggregate byte limit")
    metadata = _bytes(checkpoint.to_dict(), 8192)
    state = _Transaction()
    store._identity = None
    try:
        # Reserve without following/replacing any existing destination.
        # Explicit close preserves an original control exception if the body and
        # close both fail; a context-manager __exit__ could replace that control.
        handle = store.path.open("xb")
        try:
            info = os.fstat(handle.fileno())
            store._identity = _file_identity(info)
        except BaseException as primary:
            try:
                handle.close()
                state.closed = True
            except BaseException as cleanup:
                if isinstance(primary, Exception) and not isinstance(cleanup, Exception):
                    raise cleanup from primary
                primary.add_note("workflow reservation close also failed")
            raise
        else:
            handle.close()
            state.closed = True

        def create(connection: sqlite3.Connection, transaction: _Transaction) -> None:
            connection.execute(f"PRAGMA application_id={_APPLICATION_ID}")
            connection.execute("PRAGMA user_version=1")
            for _, _, statement in _SCHEMA:
                connection.execute(statement)
            connection.execute("INSERT INTO workflow_context VALUES (1, ?)", (context,))
            connection.execute("INSERT INTO workflow_meta VALUES (1, ?)", (metadata,))
            for index, receipt in enumerate(receipts):
                connection.execute("INSERT INTO workflow_receipts VALUES (?, ?)", (index, receipt))
            transaction.dirty = True

        store._run(create, writable=True, transaction=state)
        return store
    except BaseException as primary:
        primary.add_note(f"workflow creation outcome={state.outcome}")
        if store._identity is not None and state.outcome == "none" and state.closed:
            try:
                if _regular(store.path) != store._identity:
                    raise OSError("reserved database identity changed")
                if any(
                    Path(str(store.path) + suffix).exists()
                    for suffix in ("-journal", "-wal", "-shm")
                ):
                    raise OSError("database sidecar remains; preserve for inspection")
                store.path.unlink()
            except FileNotFoundError:
                pass
            except BaseException as cleanup:
                if isinstance(primary, Exception) and not isinstance(cleanup, Exception):
                    cleanup.add_note(
                        f"workflow creation outcome={state.outcome}; inspect {store.path}"
                    )
                    raise cleanup from primary
                primary.add_note(f"workflow creation cleanup incomplete; inspect {store.path}")
        else:
            primary.add_note(f"workflow destination was not removed; inspect {store.path}")
        if isinstance(primary, (ValidationError, WorkflowStorageError)) or not isinstance(
            primary, Exception
        ):
            raise
        raise WorkflowStorageError(state.outcome) from primary


__all__ = [
    "SQLiteWorkflowStore",
    "StoredWorkflow",
    "WorkflowCheckpoint",
    "WorkflowCommit",
    "WorkflowConflictError",
    "WorkflowStorageError",
    "WorkflowStoreLimits",
    "create_workflow_store",
]
