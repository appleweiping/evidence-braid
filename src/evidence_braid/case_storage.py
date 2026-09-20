"""One-case SQLite CAS with a durable execution claim and retained output bytes.

The claim is committed before a trusted callback is entered. A stranded claim
is deliberately not retried after restart: local SQLite cannot transact with
arbitrary callback effects. Actor names remain declarations, not authentication.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Any, Literal, TypeVar, cast

from .authority import _identifier
from .case_observation import (
    ObservationLimits,
    ObservationRegistry,
    ObservationUnavailable,
    _output,
    prepare_observation,
)
from .epistemic_case import (
    CaseActorKind,
    CaseAuthority,
    CaseJournal,
    CaseObservation,
    CaseObservationStatus,
    CasePlan,
    CaseRole,
    CaseVerdict,
    CaseVerdictOutcome,
    replay_case,
)
from .errors import InputFormatError, ValidationError
from .io import canonical_json
from .workflow_storage import _path, _regular

_T = TypeVar("_T")
_DOMAIN = b"evidence-braid:case-store:v1\x00"
_APP_ID = 0x45424353
_MAX_JOURNAL = 2 * 1024 * 1024
_MAX_RECEIPT = 20 * 1024
_MAX_OPERATIONS = 3
_MAX_OPERATION_BYTES = 8192
_MAX_TOTAL_OPERATIONS = _MAX_OPERATIONS * _MAX_OPERATION_BYTES
_MAX_ASSERTION = 64 * 1024
_MAX_INPUT = 256 * 1024
_MAX_OUTPUT = 4096
_MAX_TOTAL_PAYLOAD = 512 * 1024
_MAX_CONTEXT = 8192
_MAX_META = 8192
_MAX_METADATA_NAME = 128
_MAX_SCHEMA_SQL = 1024
_MAX_ROLE = 16
_MAX_ID = 128
_MAX_DIGEST_TEXT = 64
_OBSERVATION_LIMITS = ObservationLimits()
_SCHEMA = (
    "CREATE TABLE case_context (singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
    "document BLOB NOT NULL)",
    "CREATE TABLE case_receipts (sequence INTEGER PRIMARY KEY CHECK(sequence>=0), "
    "document BLOB NOT NULL)",
    "CREATE TABLE case_payloads (role TEXT PRIMARY KEY, artifact_id TEXT NOT NULL, "
    "digest TEXT NOT NULL, content BLOB NOT NULL)",
    "CREATE TABLE case_operations (sequence INTEGER PRIMARY KEY CHECK(sequence>=0), "
    "operation_id TEXT UNIQUE NOT NULL, document BLOB NOT NULL)",
    "CREATE TABLE case_meta (singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
    "document BLOB NOT NULL)",
    *(
        f"CREATE TRIGGER {table}_no_{action.lower()} BEFORE {action} ON {table} "
        "BEGIN SELECT RAISE(ABORT, 'case history is append-only'); END"
        for table in ("case_context", "case_receipts", "case_payloads", "case_operations")
        for action in ("UPDATE", "DELETE")
    ),
)


def _raw(value: Any) -> bytes:
    return canonical_json(value, pretty=False).encode("utf-8")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest(tag: bytes, value: Any) -> str:
    return _sha(_DOMAIN + tag + _raw(value))


def _parse(raw: bytes, maximum: int) -> dict[str, Any]:
    if type(raw) is not bytes or len(raw) > maximum:
        raise ValidationError("case store document exceeds its BLOB bound")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique,
            parse_constant=_reject_constant,
            parse_float=_reject_float,
        )
    except (ValueError, UnicodeError, RecursionError) as error:
        raise InputFormatError("invalid case store document") from error
    if type(value) is not dict or _raw(value) != raw:
        raise ValidationError("case store document is not a canonical object")
    return value


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_constant(_: str) -> None:
    raise ValueError("nonfinite number")


def _reject_float(_: str) -> None:
    raise ValueError("floating-point number")


def _fields(value: Any, expected: set[str]) -> dict[str, Any]:
    if type(value) is not dict or set(value) != expected:
        raise ValidationError("case store document has unsupported fields")
    return value


def _bounded_bytes(value: Any, maximum: int, label: str) -> bytes:
    if type(value) is not bytes or len(value) > maximum:
        raise ValidationError(f"{label} requires bounded built-in bytes")
    return bytes(value)


class CaseStoreConflictError(ValidationError):
    """Stale full checkpoint, reused ID with changed input, or spent claim."""


class CaseStoreError(InputFormatError):
    """Storage failure whose commit acknowledgement may be uncertain."""

    def __init__(
        self,
        outcome: Literal["none", "unknown", "complete"],
        operation_id: str | None = None,
        request_digest: str | None = None,
    ):
        self.outcome = outcome
        self.operation_id = operation_id
        self.request_digest = request_digest
        self.observed_bytes: bytes | None = None
        super().__init__(
            f"case store operation failed; commit outcome={outcome}; "
            "reopen and look up before retrying"
        )


@dataclass(frozen=True, slots=True)
class CaseStoreCheckpoint:
    context_digest: str
    record_count: int
    case_head: str
    operation_count: int
    operation_head: str
    generation: int

    def __post_init__(self) -> None:
        for name in ("context_digest", "case_head", "operation_head"):
            value = getattr(self, name)
            if (
                type(value) is not str
                or len(value) != 64
                or any(c not in "0123456789abcdef" for c in value)
            ):
                raise ValidationError("invalid case store checkpoint hash")
        if (
            type(self.record_count) is not int
            or not 1 <= self.record_count <= 3
            or type(self.operation_count) is not int
            or not 0 <= self.operation_count <= 3
            or type(self.generation) is not int
            or self.generation != self.operation_count
        ):
            raise ValidationError("invalid case store checkpoint count")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "context_digest": self.context_digest,
            "record_count": self.record_count,
            "case_head": self.case_head,
            "operation_count": self.operation_count,
            "operation_head": self.operation_head,
            "generation": self.generation,
        }

    @classmethod
    def from_dict(cls, value: Any) -> CaseStoreCheckpoint:
        data = _fields(value, {"schema_version", *cls.__dataclass_fields__})
        if data["schema_version"] != "1.0":
            raise ValidationError("unsupported case checkpoint version")
        return cls(*(data[name] for name in cls.__dataclass_fields__))


@dataclass(frozen=True, slots=True)
class StoredCase:
    journal: CaseJournal
    checkpoint: CaseStoreCheckpoint
    assertion_bytes: bytes
    input_bytes: bytes
    observed_bytes: bytes | None
    pending_request_id: str | None


@dataclass(frozen=True, slots=True)
class CaseStoreCommit:
    operation_id: str
    request_digest: str
    previous: CaseStoreCheckpoint
    result: StoredCase


@dataclass(frozen=True, slots=True)
class _Read:
    snapshot: StoredCase
    operations: tuple[CaseStoreCommit, ...]
    claimed_adapter_key: tuple[str, str, str, str] | None


def _context(journal: CaseJournal) -> dict[str, Any]:
    # replay_case has verified that the first receipt is a CasePlan.
    plan = cast(CasePlan, journal.receipts[0].record)
    return {
        "kind": "evidence-braid-case-store-context",
        "schema_version": "1.0",
        "authority_digest": journal.authority_digest,
        "case_id": plan.case_id,
        "plan_head": journal.receipts[0].digest,
        "plan_digest": plan.digest,
        "assertion_artifact_id": plan.assertion_artifact_id,
        "input_artifact_id": plan.input_artifact_id,
    }


def _genesis(context: dict[str, Any]) -> CaseStoreCheckpoint:
    context_digest = _digest(b"C", context)
    return CaseStoreCheckpoint(
        context_digest,
        1,
        context["plan_head"],
        0,
        _sha(_DOMAIN + b"G" + bytes.fromhex(context_digest)),
        0,
    )


def _request_content(
    operation_type: str,
    operation_id: str,
    request_id: str,
    expected: CaseStoreCheckpoint,
    adapter_key: list[str] | None,
    payload_digest: str | None,
    status: str | None,
    record_digest: str | None,
    evaluator_id: str | None,
) -> dict[str, Any]:
    return {
        "operation_type": operation_type,
        "operation_id": operation_id,
        "request_id": request_id,
        "expected": expected.to_dict(),
        "adapter_key": adapter_key,
        "payload_digest": payload_digest,
        "status": status,
        "record_digest": record_digest,
        "evaluator_id": evaluator_id,
    }


def _operation(
    content: dict[str, Any], before: CaseStoreCheckpoint, journal: CaseJournal
) -> tuple[bytes, CaseStoreCheckpoint]:
    request_digest = _digest(b"Q", content)
    document = {
        "kind": "evidence-braid-case-store-operation",
        "schema_version": "1.0",
        "sequence": before.operation_count,
        **content,
        "request_digest": request_digest,
        "result_record_count": len(journal.receipts),
        "result_case_head": journal.head_digest,
        "previous_digest": before.operation_head,
    }
    digest = _digest(b"O", document)
    raw = _raw({**document, "digest": digest})
    if len(raw) > _MAX_OPERATION_BYTES:
        raise ValidationError("case operation exceeds byte limit")
    after = CaseStoreCheckpoint(
        before.context_digest,
        len(journal.receipts),
        journal.head_digest,
        before.operation_count + 1,
        digest,
        before.generation + 1,
    )
    return raw, after


def _schema(connection: sqlite3.Connection) -> None:
    if (
        connection.execute("PRAGMA application_id").fetchone()[0] != _APP_ID
        or connection.execute("PRAGMA user_version").fetchone()[0] != 1
    ):
        raise ValidationError("unsupported case store format")
    expected: set[tuple[str, str, str | None]] = {
        (item.split(" ")[1].lower(), item.split(" ")[2], item) for item in _SCHEMA
    }
    # SQLite owns these two indexes for the TEXT primary key and UNIQUE ID.
    expected |= {
        ("index", "sqlite_autoindex_case_payloads_1", None),
        ("index", "sqlite_autoindex_case_operations_1", None),
    }
    # Bound attacker-controlled sqlite_schema TEXT before returning its rows.
    metadata = connection.execute(
        "SELECT count(*), "
        "coalesce(max(length(cast(type AS BLOB))),0), "
        "coalesce(max(length(cast(name AS BLOB))),0), "
        "coalesce(max(length(cast(sql AS BLOB))),0), "
        "coalesce(sum(length(cast(type AS BLOB))),0), "
        "coalesce(sum(length(cast(name AS BLOB))),0), "
        "coalesce(sum(length(cast(sql AS BLOB))),0), "
        "coalesce(sum(typeof(type)!='text'),0), "
        "coalesce(sum(typeof(name)!='text'),0), "
        "coalesce(sum(sql IS NOT NULL AND typeof(sql)!='text'),0) "
        "FROM sqlite_schema"
    ).fetchone()
    (
        count,
        max_type,
        max_name,
        max_sql,
        total_type,
        total_name,
        total_sql,
        bad_type,
        bad_name,
        bad_sql,
    ) = metadata
    if (
        count != len(expected)
        or max_type > 16
        or max_name > _MAX_METADATA_NAME
        or max_sql > _MAX_SCHEMA_SQL
        or total_type > 16 * len(expected)
        or total_name > _MAX_METADATA_NAME * len(expected)
        or total_sql > _MAX_SCHEMA_SQL * len(expected)
        or bad_type
        or bad_name
        or bad_sql
    ):
        raise ValidationError("case store schema metadata bounds differ")
    actual = set(connection.execute("SELECT type,name,sql FROM sqlite_schema").fetchall())
    if actual != expected:
        raise ValidationError("case store schema differs from its closed format")


def _admit(connection: sqlite3.Connection, table: str, count: int, item: int, total: int) -> None:
    queries = {
        "case_context": "SELECT count(*),coalesce(sum(length(document)),0),"
        "coalesce(max(length(document)),0),coalesce(sum(typeof(document)!='blob'),0) "
        "FROM case_context",
        "case_receipts": "SELECT count(*),coalesce(sum(length(document)),0),"
        "coalesce(max(length(document)),0),coalesce(sum(typeof(document)!='blob'),0) "
        "FROM case_receipts",
        "case_payloads": "SELECT count(*),coalesce(sum(length(content)),0),"
        "coalesce(max(length(content)),0),coalesce(sum(typeof(content)!='blob'),0) "
        "FROM case_payloads",
        "case_operations": "SELECT count(*),coalesce(sum(length(document)),0),"
        "coalesce(max(length(document)),0),coalesce(sum(typeof(document)!='blob'),0) "
        "FROM case_operations",
        "case_meta": "SELECT count(*),coalesce(sum(length(document)),0),"
        "coalesce(max(length(document)),0),coalesce(sum(typeof(document)!='blob'),0) "
        "FROM case_meta",
    }
    try:
        query = queries[table]
    except KeyError as error:
        raise AssertionError("internal table name") from error
    row = connection.execute(query).fetchone()
    if row[0] > count or row[1] > total or row[2] > item or row[3]:
        raise ValidationError("case store table exceeds closed BLOB bounds")


def _admit_text_metadata(connection: sqlite3.Connection) -> None:
    """Bound TEXT roles, IDs and digests before selecting any of their values."""
    payload = connection.execute(
        "SELECT count(*), "
        "coalesce(max(length(cast(role AS BLOB))),0), "
        "coalesce(sum(length(cast(role AS BLOB))),0), "
        "coalesce(max(length(cast(artifact_id AS BLOB))),0), "
        "coalesce(sum(length(cast(artifact_id AS BLOB))),0), "
        "coalesce(max(length(cast(digest AS BLOB))),0), "
        "coalesce(sum(length(cast(digest AS BLOB))),0), "
        "coalesce(sum(typeof(role)!='text' OR typeof(artifact_id)!='text' "
        "OR typeof(digest)!='text'),0) FROM case_payloads"
    ).fetchone()
    if (
        payload[0] > 3
        or payload[1] > _MAX_ROLE
        or payload[2] > 3 * _MAX_ROLE
        or payload[3] > _MAX_ID
        or payload[4] > 3 * _MAX_ID
        or payload[5] > _MAX_DIGEST_TEXT
        or payload[6] > 3 * _MAX_DIGEST_TEXT
        or payload[7]
    ):
        raise ValidationError("case store payload metadata bounds differ")
    operations = connection.execute(
        "SELECT count(*), "
        "coalesce(max(length(cast(operation_id AS BLOB))),0), "
        "coalesce(sum(length(cast(operation_id AS BLOB))),0), "
        "coalesce(sum(typeof(operation_id)!='text'),0) FROM case_operations"
    ).fetchone()
    if (
        operations[0] > _MAX_OPERATIONS
        or operations[1] > _MAX_ID
        or operations[2] > _MAX_OPERATIONS * _MAX_ID
        or operations[3]
    ):
        raise ValidationError("case store operation metadata bounds differ")


class SQLiteCaseStore:
    """Existing-only, one-case, independently authorized local CAS store."""

    def __init__(
        self,
        path: str | Path,
        *,
        authority: CaseAuthority,
        expected_plan_head: str,
        expected: CaseStoreCheckpoint | None = None,
        timeout: float = 10.0,
    ):
        self._configure(path, authority, expected_plan_head, timeout)
        self._identity: tuple[int, int] | None = None
        self._bridge_lock = Lock()
        self.snapshot(expected=expected)

    def _configure(
        self, path: str | Path, authority: CaseAuthority, expected_plan_head: str, timeout: float
    ) -> None:
        if type(authority) is not CaseAuthority:
            raise ValidationError("case store needs independently supplied authority")
        if (
            type(expected_plan_head) is not str
            or len(expected_plan_head) != 64
            or any(c not in "0123456789abcdef" for c in expected_plan_head)
        ):
            raise ValidationError("case store needs an exact plan head")
        if type(timeout) not in (int, float) or not 0 <= timeout <= 60:
            raise ValidationError("invalid case store timeout")
        self._path = _path(path)
        self._authority = CaseAuthority.from_bytes(authority.to_bytes())
        self._plan_head = expected_plan_head
        self._timeout = float(timeout)

    @property
    def path(self) -> Path:
        return self._path

    def _connect(self, writable: bool) -> sqlite3.Connection:
        before = _regular(self._path)
        if self._identity is not None and self._identity != before:
            raise ValidationError("case store file identity changed")
        connection = sqlite3.connect(
            self._path.as_uri() + ("?mode=rw" if writable else "?mode=ro"),
            uri=True,
            timeout=self._timeout,
            isolation_level=None,
        )
        try:
            if _regular(self._path) != before:
                raise ValidationError("case store file changed during open")
            connection.execute("PRAGMA trusted_schema=OFF")
            if writable:
                connection.execute("PRAGMA synchronous=FULL")
            self._identity = before
            return connection
        except BaseException:
            connection.close()
            raise

    def _run(
        self,
        action: Callable[[sqlite3.Connection], _T],
        *,
        writable: bool,
        operation_id: str | None = None,
        request_digest: str | None = None,
    ) -> _T:
        outcome: Literal["none", "unknown", "complete"] = "none"
        connection: sqlite3.Connection | None = None
        error: BaseException | None = None
        result: _T
        try:
            connection = self._connect(writable)
            connection.execute("BEGIN IMMEDIATE" if writable else "BEGIN")
            result = action(connection)
            if writable:
                outcome = "unknown"
                self._commit(connection)
                outcome = "complete"
            else:
                connection.rollback()
        except BaseException as exc:
            error = exc
        if connection is not None:
            try:
                connection.rollback()
            except BaseException as exc:
                if error is None:
                    error = exc
                else:
                    error.add_note("case store rollback also failed")
            try:
                self._close(connection)
            except BaseException as exc:
                if error is None:
                    error = exc
                else:
                    error.add_note("case store close also failed")
        if error is not None:
            error.add_note(f"case store commit outcome={outcome}; operation_id={operation_id}")
            if not isinstance(error, Exception) or (
                isinstance(error, ValidationError) and outcome == "none"
            ):
                raise error
            raise CaseStoreError(outcome, operation_id, request_digest) from error
        return result

    @staticmethod
    def _commit(connection: sqlite3.Connection) -> None:
        connection.commit()

    @staticmethod
    def _close(connection: sqlite3.Connection) -> None:
        connection.close()

    def _read(self, connection: sqlite3.Connection) -> _Read:
        _schema(connection)
        _admit(connection, "case_context", 1, _MAX_CONTEXT, _MAX_CONTEXT)
        _admit(connection, "case_receipts", 3, _MAX_RECEIPT, _MAX_JOURNAL)
        _admit(connection, "case_payloads", 3, _MAX_INPUT, _MAX_TOTAL_PAYLOAD)
        _admit(
            connection,
            "case_operations",
            _MAX_OPERATIONS,
            _MAX_OPERATION_BYTES,
            _MAX_TOTAL_OPERATIONS,
        )
        _admit(connection, "case_meta", 1, _MAX_META, _MAX_META)
        _admit_text_metadata(connection)
        context_rows = connection.execute("SELECT document FROM case_context").fetchall()
        meta_rows = connection.execute("SELECT document FROM case_meta").fetchall()
        if len(context_rows) != 1 or len(meta_rows) != 1:
            raise ValidationError("case store singleton missing")
        context = _fields(
            _parse(context_rows[0][0], _MAX_CONTEXT),
            {
                "kind",
                "schema_version",
                "authority_digest",
                "case_id",
                "plan_head",
                "plan_digest",
                "assertion_artifact_id",
                "input_artifact_id",
            },
        )
        if (
            context["kind"] != "evidence-braid-case-store-context"
            or context["schema_version"] != "1.0"
            or context["authority_digest"] != self._authority.digest
            or context["plan_head"] != self._plan_head
        ):
            raise ValidationError("case store context or authority differs")
        receipt_rows = connection.execute(
            "SELECT sequence,document FROM case_receipts ORDER BY sequence"
        ).fetchall()
        if not 1 <= len(receipt_rows) <= 3 or any(
            type(seq) is not int or seq != index for index, (seq, _) in enumerate(receipt_rows)
        ):
            raise ValidationError("case receipt sequence is not contiguous")
        journal_document = {
            "kind": "evidence-braid-case-journal",
            "schema_version": "1.0",
            "authority_digest": self._authority.digest,
            "receipts": [_parse(raw, _MAX_RECEIPT) for _, raw in receipt_rows],
        }
        journal = CaseJournal.from_dict(journal_document, authority=self._authority)
        if _context(CaseJournal(self._authority.digest, (journal.receipts[0],))) != context:
            raise ValidationError("case store context differs from exact plan")
        payload_rows = connection.execute(
            "SELECT role,artifact_id,digest,content FROM case_payloads ORDER BY role"
        ).fetchall()
        payload: dict[str, bytes] = {}
        # CaseJournal.from_dict replays the whole history before this point.
        plan = cast(CasePlan, journal.receipts[0].record)
        expected_payloads = {
            "assertion": (plan.assertion_artifact_id, plan.assertion_sha256, _MAX_ASSERTION),
            "input": (plan.input_artifact_id, plan.input_sha256, _MAX_INPUT),
        }
        if len(payload_rows) not in (2, 3):
            raise ValidationError("case store payload inventory differs")
        for role, identifier, digest, data in payload_rows:
            if (
                type(role) is not str
                or role in payload
                or role not in ("assertion", "input", "output")
            ):
                raise ValidationError("case store payload role differs")
            if role == "output":
                if (
                    len(journal.receipts) < 2
                    or type(journal.receipts[1].record) is not CaseObservation
                ):
                    raise ValidationError("orphan output BLOB")
                obs = journal.receipts[1].record
                if obs.status is not CaseObservationStatus.OBSERVED:
                    raise ValidationError("failed observation has output BLOB")
                # CaseObservation validates both commitments for OBSERVED status.
                expected_payloads["output"] = (
                    cast(str, obs.artifact_id),
                    cast(str, obs.observed_sha256),
                    _MAX_OUTPUT,
                )
            expected = expected_payloads[role]
            source = _bounded_bytes(data, expected[2], f"stored {role}")
            if identifier != expected[0] or digest != expected[1] or _sha(source) != digest:
                raise ValidationError("case store payload commitment differs")
            payload[role] = source
        if (
            "assertion" not in payload
            or "input" not in payload
            or len(payload["assertion"]) + len(payload["input"]) + len(payload.get("output", b""))
            > _MAX_TOTAL_PAYLOAD
        ):
            raise ValidationError("case store retained input inventory differs")
        if len(journal.receipts) >= 2 and type(journal.receipts[1].record) is CaseObservation:
            obs = journal.receipts[1].record
            if (obs.status is CaseObservationStatus.OBSERVED) != ("output" in payload):
                raise ValidationError("observation and stored output differ")
            if "output" in payload:
                _output(
                    payload["output"],
                    _OBSERVATION_LIMITS,
                    len(payload["assertion"]) + len(payload["input"]),
                )
        checkpoint = _genesis(context)
        operations: list[CaseStoreCommit] = []
        pending: str | None = None
        claimed_key: tuple[str, str, str, str] | None = None
        for sequence, identifier, raw in connection.execute(
            "SELECT sequence,operation_id,document FROM case_operations ORDER BY sequence"
        ):
            if type(sequence) is not int or sequence != len(operations):
                raise ValidationError("case operation sequence differs")
            node = _fields(
                _parse(raw, _MAX_OPERATION_BYTES),
                {
                    "kind",
                    "schema_version",
                    "sequence",
                    "operation_id",
                    "request_digest",
                    "operation_type",
                    "request_id",
                    "expected",
                    "adapter_key",
                    "payload_digest",
                    "status",
                    "record_digest",
                    "evaluator_id",
                    "result_record_count",
                    "result_case_head",
                    "previous_digest",
                    "digest",
                },
            )
            if (
                node["kind"] != "evidence-braid-case-store-operation"
                or node["schema_version"] != "1.0"
                or node["sequence"] != sequence
                or node["operation_id"] != identifier
            ):
                raise ValidationError("case operation header differs")
            _identifier(identifier, "case operation ID")
            _identifier(node["request_id"], "case request ID")
            if (
                CaseStoreCheckpoint.from_dict(node["expected"]) != checkpoint
                or node["previous_digest"] != checkpoint.operation_head
            ):
                raise ValidationError("case operation previous checkpoint differs")
            content = _request_content(
                node["operation_type"],
                identifier,
                node["request_id"],
                checkpoint,
                node["adapter_key"],
                node["payload_digest"],
                node["status"],
                node["record_digest"],
                node["evaluator_id"],
            )
            if node["request_digest"] != _digest(b"Q", content):
                raise ValidationError("case request digest differs")
            before = checkpoint
            kind = node["operation_type"]
            if kind == "claim":
                if (
                    sequence != 0
                    or node["request_id"] != identifier
                    or pending is not None
                    or node["result_record_count"] != 1
                    or node["result_case_head"] != self._plan_head
                    or node["payload_digest"] is not None
                    or node["status"] is not None
                    or node["record_digest"] is not None
                    or node["evaluator_id"] is not None
                ):
                    raise ValidationError("case claim structure differs")
                key = node["adapter_key"]
                if (
                    type(key) is not list
                    or len(key) != 4
                    or key[:3] != [plan.test_id, plan.adapter_id, plan.adapter_version]
                ):
                    raise ValidationError("case claimed adapter differs")
                actor = next((a for a in self._authority.actors if a.actor_id == key[3]), None)
                if (
                    actor is None
                    or actor.kind is not CaseActorKind.TOOL
                    or not actor.permits(plan.scope, CaseRole.OBSERVE)
                    or key[3] == plan.proposer_id
                ):
                    raise ValidationError("case claimed observer lacks authority")
                pending = node["request_id"]
                claimed_key = tuple(key)
            elif kind == "finish":
                if len(journal.receipts) < 2:
                    raise ValidationError("case finish receipt missing")
                if (
                    sequence != 1
                    or pending != node["request_id"]
                    or node["adapter_key"] is not None
                    or node["evaluator_id"] is not None
                    or node["result_record_count"] != 2
                ):
                    raise ValidationError("case finish structure differs")
                finished_obs = journal.receipts[1].record
                if (
                    type(finished_obs) is not CaseObservation
                    or finished_obs.request_id != pending
                    or finished_obs.digest != node["record_digest"]
                    or journal.receipts[1].digest != node["result_case_head"]
                    or finished_obs.status.value != node["status"]
                    or finished_obs.observed_sha256 != node["payload_digest"]
                ):
                    raise ValidationError("case finish does not bind observation")
                if finished_obs.status is CaseObservationStatus.OBSERVED:
                    expected_id = "observed-" + _sha(
                        plan.digest.encode("ascii") + pending.encode("ascii") + payload["output"]
                    )
                    if finished_obs.artifact_id != expected_id:
                        raise ValidationError("case observed artifact identity differs")
                pending = None
            elif kind == "verdict":
                if len(journal.receipts) < 3:
                    raise ValidationError("case verdict receipt missing")
                stored_observation = journal.receipts[1].record
                if (
                    sequence != 2
                    or pending is not None
                    or type(stored_observation) is not CaseObservation
                    or node["request_id"] != stored_observation.request_id
                    or node["adapter_key"] is not None
                    or node["payload_digest"] is not None
                    or node["status"] is not None
                    or node["result_record_count"] != 3
                ):
                    raise ValidationError("case verdict structure differs")
                verdict = journal.receipts[2].record
                if (
                    type(verdict) is not CaseVerdict
                    or verdict.digest != node["record_digest"]
                    or verdict.evaluator_id != node["evaluator_id"]
                    or journal.receipts[2].digest != node["result_case_head"]
                ):
                    raise ValidationError("case verdict operation differs")
                # Stage A replay checks the verdict against the observation digest;
                # the payload check above binds those digest bytes to the BLOB.
            else:
                raise ValidationError("unsupported case store operation type")
            expected_journal = CaseJournal(
                self._authority.digest, journal.receipts[: node["result_record_count"]]
            )
            operation_raw, checkpoint = _operation(content, before, expected_journal)
            if raw != operation_raw or node["digest"] != checkpoint.operation_head:
                raise ValidationError("case operation does not bind exact receipt prefix")
            historical = StoredCase(
                expected_journal,
                checkpoint,
                payload["assertion"],
                payload["input"],
                payload.get("output") if kind != "claim" else None,
                pending,
            )
            operations.append(
                CaseStoreCommit(identifier, node["request_digest"], before, historical)
            )
        stored = CaseStoreCheckpoint.from_dict(_parse(meta_rows[0][0], _MAX_META))
        if stored != checkpoint or checkpoint.record_count != len(journal.receipts):
            raise ValidationError("case store checkpoint differs from its history")
        snapshot = StoredCase(
            journal,
            checkpoint,
            payload["assertion"],
            payload["input"],
            payload.get("output"),
            pending,
        )
        return _Read(snapshot, tuple(operations), claimed_key)

    def snapshot(self, *, expected: CaseStoreCheckpoint | None = None) -> StoredCase:
        if expected is not None and type(expected) is not CaseStoreCheckpoint:
            raise ValidationError("expected case checkpoint must be exact")

        def read(connection: sqlite3.Connection) -> StoredCase:
            snapshot = self._read(connection).snapshot
            if expected is not None and snapshot.checkpoint != expected:
                raise CaseStoreConflictError("case store current checkpoint differs")
            return snapshot

        return self._run(read, writable=False)

    def lookup(self, operation_id: str, *, expected_request_digest: str) -> CaseStoreCommit | None:
        _identifier(operation_id, "case operation ID")
        if type(expected_request_digest) is not str or len(expected_request_digest) != 64:
            raise ValidationError("invalid case request digest")

        def read(connection: sqlite3.Connection) -> CaseStoreCommit | None:
            for operation in self._read(connection).operations:
                if operation.operation_id == operation_id:
                    if operation.request_digest != expected_request_digest:
                        raise CaseStoreConflictError("case operation ID bound to different request")
                    return operation
            return None

        return self._run(read, writable=False)

    def _write(
        self,
        operation_type: str,
        operation_id: str,
        request_id: str,
        expected: CaseStoreCheckpoint,
        adapter_key: list[str] | None,
        payload_digest: str | None,
        status: str | None,
        record_digest: str | None,
        evaluator_id: str | None,
        record: CaseObservation | CaseVerdict | None,
        output: bytes | None,
    ) -> CaseStoreCommit:
        _identifier(operation_id, "case operation ID")
        _identifier(request_id, "case request ID")
        if type(expected) is not CaseStoreCheckpoint:
            raise ValidationError("case write requires full expected checkpoint")
        content = _request_content(
            operation_type,
            operation_id,
            request_id,
            expected,
            adapter_key,
            payload_digest,
            status,
            record_digest,
            evaluator_id,
        )
        request_digest = _digest(b"Q", content)

        def write(connection: sqlite3.Connection) -> CaseStoreCommit:
            current = self._read(connection)
            if any(op.operation_id == operation_id for op in current.operations):
                raise CaseStoreConflictError("case operation ID already consumed; use lookup")
            before = current.snapshot.checkpoint
            if before != expected:
                raise CaseStoreConflictError("case write checkpoint is stale")
            if before.operation_count >= _MAX_OPERATIONS:
                raise ValidationError("case operation limit reached")
            if operation_type == "claim":
                if before.operation_count != 0 or current.snapshot.pending_request_id is not None:
                    raise CaseStoreConflictError("case observation already claimed")
                journal = current.snapshot.journal
                pending = request_id
            elif operation_type == "finish":
                if (
                    before.operation_count != 1
                    or current.snapshot.pending_request_id != request_id
                    or type(record) is not CaseObservation
                ):
                    raise CaseStoreConflictError("case observation claim is not current")
                journal = current.snapshot.journal.append(
                    (record,),
                    authority=self._authority,
                    expected=current.snapshot.journal.checkpoint,
                )
                pending = None
            elif operation_type == "verdict":
                if before.operation_count != 2 or type(record) is not CaseVerdict:
                    raise CaseStoreConflictError("case verdict input is not current")
                journal = current.snapshot.journal.append(
                    (record,),
                    authority=self._authority,
                    expected=current.snapshot.journal.checkpoint,
                )
                pending = None
            else:
                raise AssertionError("internal case operation type")
            raw, after = _operation(content, before, journal)
            if output is not None and (
                type(record) is not CaseObservation or record.artifact_id is None
            ):
                raise ValidationError("output requires a committed observation identity")
            result = StoredCase(
                journal,
                after,
                current.snapshot.assertion_bytes,
                current.snapshot.input_bytes,
                output if output is not None else current.snapshot.observed_bytes,
                pending,
            )
            commit = CaseStoreCommit(operation_id, request_digest, before, result)
            if record is not None:
                receipt = _raw(journal.receipts[-1].to_dict())
                connection.execute(
                    "INSERT INTO case_receipts VALUES (?,?)", (len(journal.receipts) - 1, receipt)
                )
            if output is not None:
                if type(record) is not CaseObservation:
                    raise ValidationError("output requires an observation")
                connection.execute(
                    "INSERT INTO case_payloads VALUES (?,?,?,?)",
                    ("output", record.artifact_id, _sha(output), output),
                )
            connection.execute(
                "INSERT INTO case_operations VALUES (?,?,?)",
                (before.operation_count, operation_id, raw),
            )
            connection.execute(
                "UPDATE case_meta SET document=? WHERE singleton=1", (_raw(after.to_dict()),)
            )
            return commit

        return self._run(
            write, writable=True, operation_id=operation_id, request_digest=request_digest
        )

    def _claim_key(
        self, registry: ObservationRegistry, *, request_id: str, expected: CaseStoreCheckpoint
    ) -> list[str]:
        _identifier(request_id, "observation request ID")
        if type(registry) is not ObservationRegistry or registry.limits != _OBSERVATION_LIMITS:
            raise ValidationError("case-store/1 requires the fixed observation byte limits")
        snapshot = self.snapshot(expected=expected)
        prepare_observation(
            snapshot.journal,
            self._authority,
            registry,
            snapshot.assertion_bytes,
            snapshot.input_bytes,
            expected_plan_head=self._plan_head,
            request_id=request_id,
        )
        plan = snapshot.journal.receipts[0].record
        if type(plan) is not CasePlan:
            raise ValidationError("case claim has no plan")
        selected = registry.select(plan, self._authority)
        return list(selected.key)

    def claim_request_digest(
        self, registry: ObservationRegistry, *, request_id: str, expected: CaseStoreCheckpoint
    ) -> str:
        """Compute a claim identity before any mutation for uncertain recovery."""
        key = self._claim_key(registry, request_id=request_id, expected=expected)
        return _digest(
            b"Q",
            _request_content(
                "claim", request_id, request_id, expected, key, None, None, None, None
            ),
        )

    def claim_observation(
        self, registry: ObservationRegistry, *, request_id: str, expected: CaseStoreCheckpoint
    ) -> CaseStoreCommit:
        key = self._claim_key(registry, request_id=request_id, expected=expected)
        return self._write(
            "claim",
            request_id,
            request_id,
            expected,
            key,
            None,
            None,
            None,
            None,
            None,
            None,
        )

    def _prepare_finish(
        self,
        *,
        request_id: str,
        operation_id: str,
        expected: CaseStoreCheckpoint,
        output: bytes | None = None,
        status: CaseObservationStatus = CaseObservationStatus.OBSERVED,
        error_code: str | None = None,
    ) -> tuple[CaseObservation, bytes | None]:
        _identifier(request_id, "observation request ID")
        _identifier(operation_id, "finish operation ID")
        if type(status) is not CaseObservationStatus:
            raise ValidationError("invalid case observation status")
        snapshot = self.snapshot(expected=expected)
        if snapshot.pending_request_id != request_id:
            raise CaseStoreConflictError("case observation claim differs")
        plan = cast(CasePlan, snapshot.journal.receipts[0].record)
        if status is CaseObservationStatus.OBSERVED:
            if error_code is not None:
                raise ValidationError("observed output cannot have error code")
            output = _output(
                output,
                _OBSERVATION_LIMITS,
                len(snapshot.assertion_bytes) + len(snapshot.input_bytes),
            )
        else:
            if output is not None:
                raise ValidationError("non-observed case cannot retain output")
            _identifier(error_code, "case observation error code")
        digest = _sha(output) if output is not None else None
        artifact_id = (
            "observed-" + _sha(plan.digest.encode("ascii") + request_id.encode("ascii") + output)
            if output is not None
            else None
        )
        # The claim's adapter observer is verified on every read; bind it here.
        key = self._run(
            lambda connection: self._read(connection).claimed_adapter_key,
            writable=False,
        )
        # A matching pending request can only arise from a replayed claim.
        key = cast(tuple[str, str, str, str], key)
        observation = CaseObservation(
            plan.digest,
            request_id,
            key[3],
            status,
            plan.input_sha256,
            digest,
            artifact_id,
            error_code,
        )
        return observation, output

    def finish_request_digest(
        self,
        *,
        request_id: str,
        operation_id: str,
        expected: CaseStoreCheckpoint,
        output: bytes | None = None,
        status: CaseObservationStatus = CaseObservationStatus.OBSERVED,
        error_code: str | None = None,
    ) -> str:
        """Precompute the exact finish identity without modifying the store."""
        observation, admitted = self._prepare_finish(
            request_id=request_id,
            operation_id=operation_id,
            expected=expected,
            output=output,
            status=status,
            error_code=error_code,
        )
        return _digest(
            b"Q",
            _request_content(
                "finish",
                operation_id,
                request_id,
                expected,
                None,
                _sha(admitted) if admitted is not None else None,
                status.value,
                observation.digest,
                None,
            ),
        )

    def finish_observation(
        self,
        *,
        request_id: str,
        operation_id: str,
        expected: CaseStoreCheckpoint,
        output: bytes | None = None,
        status: CaseObservationStatus = CaseObservationStatus.OBSERVED,
        error_code: str | None = None,
    ) -> CaseStoreCommit:
        observation, output = self._prepare_finish(
            request_id=request_id,
            operation_id=operation_id,
            expected=expected,
            output=output,
            status=status,
            error_code=error_code,
        )
        return self._write(
            "finish",
            operation_id,
            request_id,
            expected,
            None,
            observation.observed_sha256,
            status.value,
            observation.digest,
            None,
            observation,
            output,
        )

    def append_checked_verdict(
        self, *, operation_id: str, evaluator_id: str, expected: CaseStoreCheckpoint
    ) -> CaseStoreCommit:
        _identifier(operation_id, "verdict operation ID")
        _identifier(evaluator_id, "case evaluator ID")
        snapshot = self.snapshot(expected=expected)
        if len(snapshot.journal.receipts) != 2:
            raise ValidationError("case verdict requires durable observation")
        # Exactly two replayed receipts are necessarily plan then observation.
        plan = cast(CasePlan, snapshot.journal.receipts[0].record)
        observation = cast(CaseObservation, snapshot.journal.receipts[1].record)
        outcome = (
            CaseVerdictOutcome.INCONCLUSIVE
            if snapshot.observed_bytes is None
            else CaseVerdictOutcome.SUPPORTED
            if _sha(snapshot.observed_bytes) == plan.prediction_sha256
            else CaseVerdictOutcome.REFUTED
        )
        verdict = CaseVerdict(plan.digest, observation.digest, evaluator_id, outcome)
        return self._write(
            "verdict",
            operation_id,
            observation.request_id,
            expected,
            None,
            None,
            None,
            verdict.digest,
            evaluator_id,
            verdict,
            None,
        )

    def lookup_operation(self, operation_id: str) -> CaseStoreCommit | None:
        """Discover a verified committed operation after a bridge crash.

        The returned digest must still be compared with a separately retained
        intended digest when one was available; this does not authorize retry.
        """
        _identifier(operation_id, "case operation ID")

        def read(connection: sqlite3.Connection) -> CaseStoreCommit | None:
            return next(
                (op for op in self._read(connection).operations if op.operation_id == operation_id),
                None,
            )

        return self._run(read, writable=False)

    def execute_observation(
        self,
        registry: ObservationRegistry,
        *,
        request_id: str,
        finish_id: str,
        expected: CaseStoreCheckpoint,
    ) -> CaseStoreCommit:
        """Claim durably, then enter one provisioned callback at most once."""
        _identifier(finish_id, "finish operation ID")
        if finish_id == request_id:
            raise ValidationError("claim and finish operation IDs must differ")
        if not self._bridge_lock.acquire(blocking=False):
            raise ValidationError("case observation bridge is already active")
        try:
            claimed = self.claim_observation(registry, request_id=request_id, expected=expected)
            # A successful claim write retains the previously replayed plan.
            plan = cast(CasePlan, claimed.result.journal.receipts[0].record)
            selected = registry.select(plan, self._authority)
            status = CaseObservationStatus.OBSERVED
            error_code: str | None = None
            raw: bytes | None = None
            try:
                raw = selected.callback(claimed.result.input_bytes)
            except ObservationUnavailable:
                status, error_code = CaseObservationStatus.UNAVAILABLE, "adapter_unavailable"
            except Exception:
                status, error_code = CaseObservationStatus.ERROR, "adapter_error"
            if status is CaseObservationStatus.OBSERVED:
                try:
                    raw = _output(
                        raw,
                        registry.limits,
                        len(claimed.result.assertion_bytes) + len(claimed.result.input_bytes),
                    )
                except ValidationError:
                    status, error_code, raw = (
                        CaseObservationStatus.ERROR,
                        "invalid_adapter_output",
                        None,
                    )
            try:
                return self.finish_observation(
                    request_id=request_id,
                    operation_id=finish_id,
                    expected=claimed.result.checkpoint,
                    output=raw,
                    status=status,
                    error_code=error_code,
                )
            except CaseStoreError as error:
                # The callback must not be re-entered to reconstruct these bytes.
                error.observed_bytes = raw
                raise
        finally:
            self._bridge_lock.release()


def create_case_store(
    path: str | Path,
    journal: CaseJournal,
    *,
    authority: CaseAuthority,
    expected_plan_head: str,
    assertion_bytes: bytes,
    input_bytes: bytes,
    timeout: float = 10.0,
) -> SQLiteCaseStore:
    if type(journal) is not CaseJournal or type(authority) is not CaseAuthority:
        raise ValidationError("case store creation requires typed journal and authority")
    replay_case(journal, authority=authority, expected_head=expected_plan_head)
    if len(journal.receipts) != 1 or type(journal.receipts[0].record) is not CasePlan:
        raise ValidationError("case store creation requires exactly one plan")
    plan = journal.receipts[0].record
    assertion = _bounded_bytes(assertion_bytes, _MAX_ASSERTION, "case assertion")
    source = _bounded_bytes(input_bytes, _MAX_INPUT, "case input")
    if (
        len(assertion) + len(source) > _MAX_TOTAL_PAYLOAD
        or _sha(assertion) != plan.assertion_sha256
        or _sha(source) != plan.input_sha256
    ):
        raise ValidationError("case creation input commitment differs")
    instance = object.__new__(SQLiteCaseStore)
    instance._configure(path, authority, expected_plan_head, timeout)
    instance._identity = None
    instance._bridge_lock = Lock()
    context = _context(journal)
    checkpoint = _genesis(context)
    # Exclusive reservation: never replace or follow an existing database.
    try:
        with instance.path.open("xb"):
            pass
    except FileExistsError as error:
        raise ValidationError("case store destination already exists") from error

    def create(connection: sqlite3.Connection) -> None:
        connection.execute(f"PRAGMA application_id={_APP_ID}")
        connection.execute("PRAGMA user_version=1")
        for statement in _SCHEMA:
            connection.execute(statement)
        connection.execute("INSERT INTO case_context VALUES (1,?)", (_raw(context),))
        connection.execute(
            "INSERT INTO case_receipts VALUES (0,?)", (_raw(journal.receipts[0].to_dict()),)
        )
        connection.execute(
            "INSERT INTO case_payloads VALUES (?,?,?,?)",
            ("assertion", plan.assertion_artifact_id, plan.assertion_sha256, assertion),
        )
        connection.execute(
            "INSERT INTO case_payloads VALUES (?,?,?,?)",
            ("input", plan.input_artifact_id, plan.input_sha256, source),
        )
        connection.execute("INSERT INTO case_meta VALUES (1,?)", (_raw(checkpoint.to_dict()),))

    instance._run(create, writable=True)
    instance.snapshot(expected=checkpoint)
    return instance


__all__ = [
    "CaseStoreCheckpoint",
    "CaseStoreCommit",
    "CaseStoreConflictError",
    "CaseStoreError",
    "SQLiteCaseStore",
    "StoredCase",
    "create_case_store",
]
