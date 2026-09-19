"""Explicit authenticated service for one trusted, existing loopback workflow.

This is not a public HTTP server, identity provider or hard CPU isolation boundary.
All credentials grant disclosure of the complete workflow, not a filtered scope.
"""

from __future__ import annotations

import hashlib
import hmac
import socket
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType
from typing import Any

from . import _workflow_service_wire as wire
from ._workflow_service_wire import WorkflowServiceError, WorkflowServiceLimits
from .authority import AuthorityPolicy, WorkflowTransition
from .errors import ValidationError
from .workflow_storage import (
    SQLiteWorkflowStore,
    StoredWorkflow,
    WorkflowCheckpoint,
    WorkflowCommit,
    WorkflowConflictError,
    WorkflowStorageError,
    _bytes,
)


@dataclass(frozen=True, slots=True)
class WorkflowServiceCredential:
    """Operator-provisioned token digest to actor/full-workflow-access binding."""

    credential_id: str
    actor_id: str
    token_sha256: str = field(repr=False)
    access: str

    def __post_init__(self) -> None:
        wire.identifier(self.credential_id)
        wire.identifier(self.actor_id)
        wire.digest(self.token_sha256)
        if type(self.access) is not str or self.access not in ("read", "act"):
            raise ValidationError("service access must be read or act")


@dataclass(slots=True)
class _Operation:
    outcome: wire.Outcome = "none"
    pending: bool = False
    request_id: str | None = None
    request_digest: str | None = None

    def observe(self, error: BaseException) -> None:
        if self.outcome == "complete":
            return
        if isinstance(error, WorkflowStorageError):
            self.outcome = error.outcome
        elif isinstance(error, (ValidationError, WorkflowServiceError)):
            self.outcome = "none"
        elif self.pending:
            self.outcome = "unknown"


@dataclass(slots=True)
class _Connection:
    socket: socket.socket
    operation: _Operation = field(default_factory=_Operation)
    phase: str = "reading"
    closed: bool = False


class _Bucket:
    def __init__(self, rate: int, now: int) -> None:
        self.rate = rate
        self.credit = rate * 1_000_000_000
        self.at = now

    def refill(self, now: int) -> None:
        elapsed = max(0, min(now - self.at, 1_000_000_000))
        self.credit = min(self.rate * 1_000_000_000, self.credit + elapsed * self.rate)
        self.at = max(now, self.at)


class LocalWorkflowService:
    """Single-use, bounded native listener. Start and close are explicit ownership.

    A close timeout retains DRAINING and live handles; it cannot cancel native
    store execution. A credential authenticates a configured actor, not a person.
    """

    def __init__(
        self,
        *,
        database: str | Path,
        authority: AuthorityPolicy,
        expected_workflow_id: str,
        expected_context: str,
        startup_checkpoint: WorkflowCheckpoint,
        service_id: str,
        credentials: tuple[WorkflowServiceCredential, ...],
        limits: WorkflowServiceLimits | None = None,
        port: int = 0,
    ) -> None:
        self._limits = wire.limits_copy(limits)
        self._authority = wire.authority_copy(authority, self._limits)
        self._workflow_id = wire.identifier(expected_workflow_id)
        self._context = wire.digest(expected_context)
        self._checkpoint = wire.checkpoint(startup_checkpoint, self._context)
        self._service_id = wire.identifier(service_id)
        self._port = wire.integer(port, 65535, 0)
        if (
            type(credentials) is not tuple
            or not 1 <= len(credentials) <= self._limits.max_credentials
        ):
            raise ValidationError("invalid credential count or container")
        if any(type(item) is not WorkflowServiceCredential for item in credentials):
            raise ValidationError("credentials require exact native records")
        self._credentials = tuple(
            WorkflowServiceCredential(
                item.credential_id,
                item.actor_id,
                item.token_sha256,
                item.access,
            )
            for item in credentials
        )
        actors = {actor.actor_id for actor in self._authority.actors}
        if (
            len({item.credential_id for item in credentials}) != len(credentials)
            or len({item.token_sha256 for item in credentials}) != len(credentials)
            or any(item.actor_id not in actors for item in credentials)
        ):
            raise ValidationError("credential registry must uniquely bind trusted actors")
        self._digests = tuple(bytes.fromhex(item.token_sha256) for item in self._credentials)
        # Constructor only validates the local path/configuration, without opening the DB.
        self._store = SQLiteWorkflowStore(
            database,
            authority=self._authority,
            expected_context=self._context,
            limits=self._limits.store_limits(),
            timeout=self._limits.sqlite_ms / 1000,
        )
        self._lock = threading.RLock()
        self._close_lock = threading.Lock()
        self._closer: threading.Thread | None = None
        self._core = threading.Lock()
        self._permits = threading.BoundedSemaphore(self._limits.max_workers)
        self._stop = threading.Event()
        self._start_done = threading.Event()
        self._start_done.set()
        self._starter: threading.Thread | None = None
        self._listener: socket.socket | None = None
        self._pending_socket: socket.socket | None = None
        self._acceptor: threading.Thread | None = None
        self._workers: dict[threading.Thread, _Connection] = {}
        self._address: tuple[str, int] | None = None
        self._state = "NEW"
        self._failure: BaseException | None = None
        self._last_error: WorkflowServiceError | None = None
        now = time.monotonic_ns()
        self._global_bucket = _Bucket(16, now)
        self._buckets = {item.actor_id: _Bucket(4, now) for item in credentials}

    @property
    def state(self) -> str:
        with self._lock:
            return self._state

    @property
    def address(self) -> tuple[str, int]:
        with self._lock:
            if self._address is None:
                raise WorkflowServiceError("lifecycle_error")
            return self._address

    @property
    def last_error(self) -> WorkflowServiceError | None:
        """Latest bounded nonfatal request/delivery diagnostic, without payloads."""
        with self._lock:
            return self._last_error

    def check(self) -> None:
        with self._lock:
            failure = self._failure
        if failure is not None:
            raise failure

    def _fatal(self, error: BaseException) -> None:
        with self._lock:
            self._failure = wire.primary_failure(self._failure, error)
            self._state = "DRAINING"
            self._stop.set()

    def start(self) -> LocalWorkflowService:
        with self._lock:
            if self._state != "NEW":
                raise WorkflowServiceError("lifecycle_error")
            self._state = "STARTING"
            self._starter = threading.current_thread()
            self._start_done.clear()
        primary: BaseException | None = None
        try:
            current = self._store.snapshot(expected=self._checkpoint)
            if current.bundle.workflow_id != self._workflow_id:
                raise WorkflowServiceError("conflict")
            # Validate maximum response-model shape before publishing a listening address.
            wire.parse_json(
                _bytes(current.to_dict(), self._limits.response_bytes), self._limits, response=True
            )
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            with self._lock:
                self._listener = listener
            listener.bind(("127.0.0.1", self._port))
            listener.listen(8)
            listener.settimeout(0.05)
            with self._lock:
                if self._stop.is_set():
                    raise WorkflowServiceError("lifecycle_error")
                self._address = ("127.0.0.1", listener.getsockname()[1])
                acceptor = threading.Thread(
                    target=self._accept, name="workflow-local-accept", daemon=False
                )
                self._acceptor = acceptor
                self._state = "RUNNING"
                acceptor.start()
        except BaseException as error:
            primary = error
            self._fatal(error)
        finally:
            self._start_done.set()
        if primary is not None:
            try:
                self.close()
            except BaseException as error:
                if error is not primary:
                    primary = wire.primary_failure(primary, error)
            raise primary
        return self

    def __enter__(self) -> LocalWorkflowService:
        return self.start()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        try:
            self.close()
        except BaseException as cleanup:
            if exc is None or (isinstance(exc, Exception) and not isinstance(cleanup, Exception)):
                raise
            exc.add_note("local workflow service shutdown also failed; inspect ownership")

    def _reap(self) -> None:
        # Permits are released only after thread termination, never just before return.
        with self._lock:
            finished = [
                thread
                for thread, record in self._workers.items()
                if not thread.is_alive() and record.closed
            ]
            for thread in finished:
                del self._workers[thread]
                self._permits.release()

    def _accept(self) -> None:
        try:
            while not self._stop.is_set():
                self._reap()
                listener = self._listener
                if listener is None:
                    break
                try:
                    connection, peer = listener.accept()
                    self._pending_socket = connection
                except TimeoutError:
                    continue
                except OSError:
                    if self._stop.is_set():
                        break
                    raise
                reserved = False
                handed = False
                primary: BaseException | None = None
                try:
                    reserved = self._permits.acquire(blocking=False)
                    if peer[0] != "127.0.0.1" or not reserved or self._stop.is_set():
                        continue
                    record = _Connection(connection)
                    worker = threading.Thread(
                        target=self._worker,
                        args=(record,),
                        name="workflow-local-request",
                        daemon=False,
                    )
                    with self._lock:
                        if self._stop.is_set():
                            continue
                        self._workers[worker] = record
                        try:
                            worker.start()
                        except BaseException:
                            if worker.ident is None:
                                del self._workers[worker]
                            else:
                                handed = True
                                self._pending_socket = None
                            raise
                        handed = True
                        self._pending_socket = None
                except BaseException as error:
                    primary = error
                    raise
                finally:
                    if not handed:
                        try:
                            connection.close()
                            self._pending_socket = None
                        except BaseException as error:
                            primary = wire.primary_failure(primary, error)
                        if reserved:
                            try:
                                self._permits.release()
                            except BaseException as error:
                                primary = wire.primary_failure(primary, error)
                        if primary is not None:
                            raise primary
        except BaseException as error:
            self._fatal(error)

    def _authenticate(self, headers: dict[str, str]) -> WorkflowServiceCredential:
        supplied = headers.get("authorization", "")
        if len(supplied) != 71 or not supplied.startswith("Bearer "):
            raise WorkflowServiceError("unauthorized")
        try:
            token = bytes.fromhex(wire.digest(supplied[7:]))
        except ValidationError:
            raise WorkflowServiceError("unauthorized") from None
        actual = hashlib.sha256(token).digest()
        found: WorkflowServiceCredential | None = None
        for credential, expected in zip(self._credentials, self._digests, strict=True):
            if hmac.compare_digest(actual, expected):
                found = credential
        if found is None:
            raise WorkflowServiceError("unauthorized")
        return found

    def _rate(self, actor: str) -> None:
        with self._lock:
            now = time.monotonic_ns()
            local = self._buckets[actor]
            for bucket in (local, self._global_bucket):
                bucket.refill(now)
            if min(local.credit, self._global_bucket.credit) < 1_000_000_000:
                raise WorkflowServiceError("rate_limited")
            local.credit -= 1_000_000_000
            self._global_bucket.credit -= 1_000_000_000

    def _read(self, record: _Connection) -> tuple[str, WorkflowServiceCredential, Any]:
        line, headers, tail = wire.read_headers(
            record.socket, wire.deadline(self._limits.header_ms), self._limits, stop=self._stop
        )
        parts = line.split(" ")
        if len(parts) != 3 or parts[2] != "HTTP/1.1":
            raise WorkflowServiceError("invalid_request")
        if parts[0] != "POST":
            raise WorkflowServiceError("method_not_allowed")
        target = parts[1]
        if any(char in target for char in ("?", "#", "%", "\\")) or not target.startswith("/"):
            raise WorkflowServiceError("invalid_request")
        if target not in wire._ROUTES:
            raise WorkflowServiceError("not_found")
        required = {"host", "authorization", "content-type", "content-length"}
        if set(headers) - required - {"connection", "accept"}:
            raise WorkflowServiceError("invalid_request")
        if headers.get("host") != f"127.0.0.1:{self.address[1]}":
            raise WorkflowServiceError("invalid_request")
        credential = self._authenticate(headers)
        operation = wire._ROUTES[target]
        if operation == "append" and credential.access != "act":
            raise WorkflowServiceError("forbidden")
        self._rate(credential.actor_id)
        if headers.get("content-type") != "application/json":
            raise WorkflowServiceError("unsupported_media_type")
        if (
            headers.get("connection", "close") != "close"
            or headers.get("accept", "application/json") != "application/json"
        ):
            raise WorkflowServiceError("invalid_request")
        size = wire.content_length(headers, self._limits.max_request_bytes)
        raw = wire.read_body(
            record.socket, tail, size, wire.deadline(self._limits.body_ms), stop=self._stop
        )
        try:
            return operation, credential, wire.parse_json(raw, self._limits)
        except ValidationError:
            raise WorkflowServiceError("invalid_request") from None

    def _success(
        self,
        operation: str,
        credential: WorkflowServiceCredential,
        state: _Operation,
        result: StoredWorkflow | WorkflowCommit | None,
    ) -> bytes:
        return wire.response_frame(
            200,
            _bytes(
                {
                    "schema_version": "1.0",
                    "service_id": self._service_id,
                    "workflow_id": self._workflow_id,
                    "context_digest": self._context,
                    "actor_id": credential.actor_id,
                    "operation": operation,
                    "request_id": state.request_id,
                    "request_digest": state.request_digest,
                    "outcome": state.outcome,
                    "result": None if result is None else result.to_dict(),
                },
                self._limits.response_bytes,
            ),
        )

    def _admit(
        self,
        record: _Connection,
        operation: str,
        credential: WorkflowServiceCredential,
        node: Any,
    ) -> tuple[str | None, WorkflowCheckpoint | None, tuple[WorkflowTransition, ...]]:
        names = {"schema_version"}
        if operation != "snapshot":
            names |= {"request_id", "request_digest"}
        if operation != "lookup":
            names.add("expected_checkpoint")
        if operation == "append":
            names.add("transitions")
        body = wire.object_fields(node, names)
        if body["schema_version"] != "1.0":
            raise ValidationError("unsupported service request version")
        state = record.operation
        core_id: str | None = None
        if operation != "snapshot":
            state.request_id = wire.identifier(body["request_id"], 58)
            state.request_digest = wire.digest(body["request_digest"])
            core_id = wire.namespace_id(
                self._service_id, self._context, credential.actor_id, state.request_id
            )
        before: WorkflowCheckpoint | None = None
        if operation != "lookup" and body["expected_checkpoint"] is not None:
            before = wire.checkpoint(
                WorkflowCheckpoint.from_dict(body["expected_checkpoint"]), self._context
            )
        commands: tuple[WorkflowTransition, ...] = ()
        if operation == "append":
            values = body["transitions"]
            if type(values) is not list or not 1 <= len(values) <= self._limits.max_append_records:
                raise WorkflowServiceError("limit_exceeded")
            commands = wire.transitions_copy(
                tuple(WorkflowTransition.from_dict(item) for item in values),
                credential.actor_id,
                self._limits,
            )
            if before is None:
                raise ValidationError("append requires an exact checkpoint")
        return core_id, before, commands

    def _dispatch(
        self,
        record: _Connection,
        operation: str,
        credential: WorkflowServiceCredential,
        node: Any,
    ) -> bytes:
        try:
            core_id, before, commands = self._admit(record, operation, credential, node)
        except ValidationError:
            raise WorkflowServiceError("invalid_request") from None
        state = record.operation
        if not self._core.acquire(timeout=self._limits.admission_ms / 1000):
            raise WorkflowServiceError("unavailable")
        try:
            with self._lock:
                if self._stop.is_set():
                    raise WorkflowServiceError("unavailable")
                record.phase = "core"
            result: StoredWorkflow | WorkflowCommit | None
            if operation == "snapshot":
                result = self._store.snapshot(expected=before)
            elif operation == "lookup":
                if core_id is None or state.request_digest is None:
                    raise ValidationError("lookup identity is missing")
                state.pending = True
                result = self._store.lookup(core_id, expected_request_digest=state.request_digest)
                if result is not None:
                    state.outcome = "complete"
                state.pending = False
            else:
                if core_id is None or before is None:
                    raise ValidationError("append identity is missing")
                actual = self._store.request_digest(commands, request_id=core_id, expected=before)
                if actual != state.request_digest:
                    raise WorkflowServiceError("conflict")
                state.pending = True
                result = self._store.append(commands, request_id=core_id, expected=before)
                state.outcome = "complete"
                state.pending = False
            return self._success(operation, credential, state, result)
        finally:
            try:
                with self._lock:
                    record.phase = "writing"
            finally:
                self._core.release()

    @staticmethod
    def _diagnostic(error: BaseException, state: _Operation) -> WorkflowServiceError:
        state.observe(error)
        if state.outcome == "complete" and not isinstance(error, WorkflowStorageError):
            code = "internal_error"
        elif isinstance(error, WorkflowServiceError):
            code = error.code
        elif isinstance(error, WorkflowConflictError):
            code = "conflict"
        elif isinstance(error, WorkflowStorageError):
            code = "unavailable"
        elif isinstance(error, ValidationError):
            code = "workflow_rejected"
        elif isinstance(error, (OSError, TimeoutError)):
            code = "unavailable"
        else:
            code = "internal_error"
        return WorkflowServiceError(
            code, state.outcome, request_id=state.request_id, request_digest=state.request_digest
        )

    def _worker(self, record: _Connection) -> None:
        primary: BaseException | None = None
        try:
            try:
                operation, credential, node = self._read(record)
                payload = self._dispatch(record, operation, credential, node)
            except BaseException as error:
                record.operation.observe(error)
                if not isinstance(error, Exception):
                    raise
                diagnostic = self._diagnostic(error, record.operation)
                with self._lock:
                    self._last_error = diagnostic
                try:
                    payload = wire.error_frame(diagnostic)
                except Exception:
                    payload = wire.EMERGENCY[record.operation.outcome]
            wire.send(record.socket, payload, wire.deadline(self._limits.io_ms))
        except BaseException as error:
            primary = error
            record.operation.observe(error)
            if isinstance(error, Exception):
                with self._lock:
                    self._last_error = WorkflowServiceError(
                        "transport_error",
                        record.operation.outcome,
                        request_id=record.operation.request_id,
                        request_digest=record.operation.request_digest,
                    )
            else:
                error.add_note(f"workflow service outcome={record.operation.outcome}")
                self._fatal(error)
        finally:
            try:
                record.socket.close()
                record.closed = True
            except BaseException as error:
                failure = wire.primary_failure(primary, error)
                if isinstance(failure, Exception):
                    failure = WorkflowServiceError(
                        "transport_error",
                        record.operation.outcome,
                        request_id=record.operation.request_id,
                        request_digest=record.operation.request_digest,
                    )
                self._fatal(failure)

    def close(self, *, timeout_ms: int | None = None) -> None:
        milliseconds = (
            self._limits.close_ms if timeout_ms is None else wire.integer(timeout_ms, 30000)
        )
        end = wire.deadline(milliseconds)
        current = threading.current_thread()
        with self._lock:
            if current is self._closer or (
                current is self._acceptor
                or current in self._workers
                or (current is self._starter and not self._start_done.is_set())
            ):
                raise WorkflowServiceError("lifecycle_error")
            self._stop.set()
            if self._state != "CLOSED":
                self._state = "DRAINING"
        try:
            acquired = self._close_lock.acquire(timeout=wire.remaining(end))
        except TimeoutError:
            raise WorkflowServiceError("shutdown_timeout") from None
        if not acquired:
            raise WorkflowServiceError("shutdown_timeout")
        self._closer = current
        with self._lock:
            primary = self._failure
        try:
            if not self._start_done.wait(wire.remaining(end)):
                raise WorkflowServiceError("shutdown_timeout")
            listener = self._listener
            if listener is not None:
                try:
                    listener.close()
                    self._listener = None
                except BaseException as error:
                    primary = wire.primary_failure(primary, error)
            with self._lock:
                workers = list(self._workers.items())
            for _, record in workers:
                if record.phase == "reading" and not record.closed:
                    try:
                        record.socket.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    except BaseException as error:
                        primary = wire.primary_failure(primary, error)
            for thread in [self._acceptor, *(thread for thread, _ in workers)]:
                if thread is not None and thread.ident is not None:
                    thread.join(wire.remaining(end))
            for thread, record in workers:
                if not thread.is_alive() and not record.closed:
                    try:
                        record.socket.close()
                        record.closed = True
                    except BaseException as error:
                        primary = wire.primary_failure(primary, error)
            if self._pending_socket is not None and (
                self._acceptor is None or not self._acceptor.is_alive()
            ):
                try:
                    self._pending_socket.close()
                    self._pending_socket = None
                except BaseException as error:
                    primary = wire.primary_failure(primary, error)
            self._reap()
            with self._lock:
                if (
                    self._listener is not None
                    or self._pending_socket is not None
                    or self._workers
                    or (self._acceptor is not None and self._acceptor.is_alive())
                ):
                    raise WorkflowServiceError("shutdown_timeout")
                self._state = "CLOSED"
        except TimeoutError:
            primary = wire.primary_failure(primary, WorkflowServiceError("shutdown_timeout"))
        except BaseException as error:
            primary = wire.primary_failure(primary, error)
        finally:
            self._closer = None
            self._close_lock.release()
        with self._lock:
            if self._failure is not None and self._failure is not primary:
                primary = wire.primary_failure(primary, self._failure)
        if primary is not None:
            if not isinstance(primary, Exception):
                raise primary
            if isinstance(primary, WorkflowServiceError):
                raise primary
            raise WorkflowServiceError("transport_error") from None
        self.check()
