"""Synchronous, pinned loopback workflow SDK with explicit durable retry intent."""

from __future__ import annotations

import socket
import threading
from typing import Any

from . import _workflow_service_wire as wire
from ._workflow_service_wire import (
    PreparedWorkflowAppend,
    WorkflowServiceError,
    WorkflowServiceLimits,
)
from .authority import AuthorityPolicy, WorkflowTransition
from .errors import ValidationError
from .workflow import WorkflowBundle
from .workflow_storage import (
    StoredWorkflow,
    WorkflowCheckpoint,
    WorkflowCommit,
    _bytes,
    _request_digest,
)


class _AcknowledgedError(WorkflowServiceError):
    """Only a fully framed, closed-schema remote error can refine an outcome."""


class WorkflowClient:
    """One owned socket per call; no discovery, redirects, proxy, retry or rebase.

    The operator must trust endpoint and token distribution. Plain loopback bearer
    authentication is not cryptographic server authentication or secure erasure.
    """

    def __init__(
        self,
        *,
        address: tuple[str, int],
        token: str,
        service_id: str,
        actor_id: str,
        workflow_id: str,
        context_digest: str,
        authority: AuthorityPolicy,
        limits: WorkflowServiceLimits | None = None,
    ) -> None:
        self._limits = wire.limits_copy(limits)
        if (
            type(address) is not tuple
            or len(address) != 2
            or type(address[0]) is not str
            or address[0] != "127.0.0.1"
        ):
            raise ValidationError("client requires a numeric IPv4 loopback endpoint")
        self._address = ("127.0.0.1", wire.integer(address[1], 65535))
        self._token = wire.digest(token)
        self._service_id = wire.identifier(service_id)
        self._actor_id = wire.identifier(actor_id)
        self._workflow_id = wire.identifier(workflow_id)
        self._context = wire.digest(context_digest)
        self._authority = wire.authority_copy(authority, self._limits)
        if self._actor_id not in {actor.actor_id for actor in self._authority.actors}:
            raise ValidationError("client actor is absent from trusted authority")
        self._busy = threading.Lock()
        self._connection: socket.socket | None = None
        self._retained_outcome: wire.Outcome = "none"
        self._retained_id: str | None = None
        self._retained_digest: str | None = None

    def close(self) -> None:
        """Retry a retained failed close; never cancel a concurrent active call."""
        if not self._busy.acquire(blocking=False):
            raise WorkflowServiceError("lifecycle_error")
        try:
            if self._connection is not None:
                try:
                    self._connection.close()
                except BaseException as error:
                    if not isinstance(error, Exception):
                        error.add_note(f"workflow client outcome={self._retained_outcome}")
                        raise
                    raise WorkflowServiceError(
                        "transport_error",
                        self._retained_outcome,
                        request_id=self._retained_id,
                        request_digest=self._retained_digest,
                    ) from None
                self._connection = None
        finally:
            self._busy.release()

    def prepare_append(
        self,
        transitions: list[WorkflowTransition] | tuple[WorkflowTransition, ...],
        *,
        request_id: str,
        expected: WorkflowCheckpoint,
    ) -> PreparedWorkflowAppend:
        public = wire.identifier(request_id, 58)
        before = wire.checkpoint(expected, self._context)
        commands = wire.transitions_copy(transitions, self._actor_id, self._limits)
        core_id = wire.namespace_id(self._service_id, self._context, self._actor_id, public)
        digest = _request_digest(core_id, before, commands, self._limits.store_limits())
        prepared = PreparedWorkflowAppend(
            self._service_id,
            self._workflow_id,
            self._context,
            self._actor_id,
            public,
            before,
            commands,
            digest,
        )
        prepared.admit(self._limits)
        return prepared

    def snapshot(self, *, expected: WorkflowCheckpoint | None = None) -> StoredWorkflow:
        before = None if expected is None else wire.checkpoint(expected, self._context)
        result = self._request(
            "snapshot",
            {
                "schema_version": "1.0",
                "expected_checkpoint": None if before is None else before.to_dict(),
            },
            expected=before,
        )
        if type(result) is not StoredWorkflow:
            raise WorkflowServiceError("invalid_response")
        return result

    def append(self, prepared: PreparedWorkflowAppend) -> WorkflowCommit:
        if type(prepared) is not PreparedWorkflowAppend:
            raise ValidationError("append requires exact prepared intent")
        if (
            prepared.service_id,
            prepared.workflow_id,
            prepared.context_digest,
            prepared.actor_id,
        ) != (
            self._service_id,
            self._workflow_id,
            self._context,
            self._actor_id,
        ):
            raise WorkflowServiceError("conflict")
        prepared.admit(self._limits)
        result = self._request("append", prepared.body(), prepared=prepared)
        if type(result) is not WorkflowCommit:
            raise WorkflowServiceError("invalid_response", "unknown")
        return result

    def lookup(self, *, request_id: str, expected_request_digest: str) -> WorkflowCommit | None:
        result = self._request(
            "lookup",
            {
                "schema_version": "1.0",
                "request_id": wire.identifier(request_id, 58),
                "request_digest": wire.digest(expected_request_digest),
            },
        )
        if result is not None and type(result) is not WorkflowCommit:
            raise WorkflowServiceError("invalid_response", "unknown")
        return result

    def _stored(self, value: Any) -> StoredWorkflow:
        node = wire.object_fields(value, {"bundle", "checkpoint"})
        _bytes(node["bundle"], self._limits.max_bundle_bytes)
        raw_bundle = node["bundle"]
        if type(raw_bundle) is not dict or type(raw_bundle.get("records")) is not list:
            raise ValidationError("invalid response workflow records")
        wire.integer(len(raw_bundle["records"]), self._limits.max_records, 0)
        for record in raw_bundle["records"]:
            _bytes(record, self._limits.max_receipt_bytes)
        bundle = WorkflowBundle.from_dict(node["bundle"], authority=self._authority)
        if bundle.context_digest != self._context or bundle.workflow_id != self._workflow_id:
            raise ValidationError("response workflow pin mismatch")
        before = WorkflowCheckpoint.from_dict(node["checkpoint"])
        wire.integer(before.operation_count, self._limits.max_operations, 0)
        return StoredWorkflow(bundle, before)

    def _decode(
        self,
        status: int,
        node: Any,
        operation: str,
        body: dict[str, Any],
        *,
        prepared: PreparedWorkflowAppend | None,
        expected: WorkflowCheckpoint | None,
    ) -> StoredWorkflow | WorkflowCommit | None:
        public, digest = body.get("request_id"), body.get("request_digest")
        if status != 200:
            error = wire.object_fields(
                node,
                {
                    "schema_version",
                    "error_code",
                    "outcome",
                    "request_id",
                    "request_digest",
                },
            )
            if (
                error["schema_version"] != "1.0"
                or error["request_id"] not in (None, public)
                or error["request_digest"] not in (None, digest)
            ):
                raise ValidationError("invalid error acknowledgement")
            failure = WorkflowServiceError(
                error["error_code"], error["outcome"], request_id=public, request_digest=digest
            )
            if failure.status != status or (status not in (500, 503) and failure.outcome != "none"):
                raise ValidationError("inconsistent error acknowledgement")
            raise _AcknowledgedError(
                failure.code, failure.outcome, request_id=public, request_digest=digest
            )
        envelope = wire.object_fields(
            node,
            {
                "schema_version",
                "service_id",
                "workflow_id",
                "context_digest",
                "actor_id",
                "operation",
                "request_id",
                "request_digest",
                "outcome",
                "result",
            },
        )
        if any(
            envelope[name] != value
            for name, value in {
                "schema_version": "1.0",
                "service_id": self._service_id,
                "workflow_id": self._workflow_id,
                "context_digest": self._context,
                "actor_id": self._actor_id,
                "operation": operation,
                "request_id": public,
                "request_digest": digest,
            }.items()
        ):
            raise ValidationError("response envelope pin mismatch")
        value = envelope["result"]
        outcome = "none" if operation == "snapshot" or value is None else "complete"
        if envelope["outcome"] != outcome:
            raise ValidationError("response outcome mismatch")
        if operation == "snapshot":
            stored = self._stored(value)
            if expected is not None and stored.checkpoint != expected:
                raise ValidationError("snapshot anchor mismatch")
            return stored
        if value is None and operation == "lookup":
            return None
        commit = wire.object_fields(value, {"request_id", "request_digest", "previous", "result"})
        result = WorkflowCommit(
            commit["request_id"],
            commit["request_digest"],
            WorkflowCheckpoint.from_dict(commit["previous"]),
            self._stored(commit["result"]),
        )
        if (
            result.request_id
            != wire.namespace_id(
                self._service_id, self._context, self._actor_id, wire.identifier(public, 58)
            )
            or result.request_digest != digest
        ):
            raise ValidationError("response request binding mismatch")
        if prepared is not None and (
            result.previous != prepared.expected_checkpoint
            or tuple(
                item.transition
                for item in result.result.bundle.records[result.previous.record_count :]
            )
            != prepared.transitions
        ):
            raise ValidationError("response intent mismatch")
        return result

    def _request(
        self,
        operation: str,
        body: dict[str, Any],
        *,
        prepared: PreparedWorkflowAppend | None = None,
        expected: WorkflowCheckpoint | None = None,
    ) -> StoredWorkflow | WorkflowCommit | None:
        if not self._busy.acquire(blocking=False):
            raise WorkflowServiceError("lifecycle_error")
        try:
            if self._connection is not None:
                raise WorkflowServiceError("lifecycle_error")
            return self._request_owned(operation, body, prepared=prepared, expected=expected)
        finally:
            self._busy.release()

    def _request_owned(
        self,
        operation: str,
        body: dict[str, Any],
        *,
        prepared: PreparedWorkflowAppend | None,
        expected: WorkflowCheckpoint | None,
    ) -> StoredWorkflow | WorkflowCommit | None:
        payload = wire.native_json(body, self._limits)
        wire.parse_json(payload, self._limits)
        request = (
            f"POST /v1/workflow/{operation} HTTP/1.1\r\nHost: 127.0.0.1:{self._address[1]}\r\n"
            f"Authorization: Bearer {self._token}\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n"
        ).encode("ascii") + payload
        public, digest = body.get("request_id"), body.get("request_digest")
        connection: socket.socket | None = None
        outcome: wire.Outcome = "none"
        primary: BaseException | None = None
        result: StoredWorkflow | WorkflowCommit | None = None
        try:
            connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._connection = connection
            connection.settimeout(self._limits.header_ms / 1000)
            connection.connect(self._address)
            outcome = "none" if operation == "snapshot" else "unknown"
            wire.send(connection, request, wire.deadline(self._limits.io_ms))
            line, headers, tail = wire.read_headers(
                connection,
                wire.deadline(self._limits.header_ms),
                self._limits,
                response=True,
            )
            parts = line.split(" ")
            if len(parts) != 3 or parts[0] != "HTTP/1.1" or not re_status(parts[1]):
                raise ValidationError("invalid response status")
            if set(headers) != {"content-type", "content-length", "connection", "cache-control"}:
                raise ValidationError("invalid response headers")
            if (
                headers["content-type"] != "application/json"
                or headers["connection"] != "close"
                or headers["cache-control"] != "no-store"
            ):
                raise ValidationError("unsupported response encoding")
            size = wire.content_length(headers, self._limits.response_bytes)
            if len(tail) > size:
                raise ValidationError("extra response bytes")
            end = wire.deadline(self._limits.io_ms)
            raw = wire.read_body(connection, tail, size, end)
            connection.settimeout(wire.remaining(end))
            if connection.recv(1):
                raise ValidationError("extra response bytes")
            result = self._decode(
                int(parts[1]),
                wire.parse_json(raw, self._limits, response=True),
                operation,
                body,
                prepared=prepared,
                expected=expected,
            )
            outcome = "complete" if type(result) is WorkflowCommit else "none"
        except BaseException as error:
            if type(error) is _AcknowledgedError:
                outcome = error.outcome
                primary = WorkflowServiceError(
                    error.code, outcome, request_id=public, request_digest=digest
                )
            elif isinstance(error, Exception):
                code = (
                    "invalid_response"
                    if isinstance(error, (ValidationError, ValueError, WorkflowServiceError))
                    else "transport_error"
                )
                primary = WorkflowServiceError(
                    code, outcome, request_id=public, request_digest=digest
                )
            else:
                primary = error
        if connection is not None:
            self._retained_outcome = outcome
            self._retained_id = public
            self._retained_digest = digest
            try:
                connection.close()
                self._connection = None
            except BaseException as error:
                primary = wire.primary_failure(primary, error)
        if primary is not None:
            if not isinstance(primary, Exception):
                primary.add_note(f"workflow client outcome={outcome}; retain prepared request")
                raise primary
            if type(primary) is not WorkflowServiceError:
                primary = WorkflowServiceError(
                    "transport_error", outcome, request_id=public, request_digest=digest
                )
            raise primary from None
        return result


def re_status(value: str) -> bool:
    return len(value) == 3 and value.isascii() and value.isdecimal() and 100 <= int(value) <= 599
