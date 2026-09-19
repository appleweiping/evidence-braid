"""Private bounded local-service wire; existing workflow hash semantics are reused."""

from __future__ import annotations

import hashlib
import re
import socket
import threading
import time
from dataclasses import dataclass, fields
from typing import Any, Literal, cast

from .authority import AuthorityPolicy, WorkflowTransition
from .errors import EvidenceBraidError, ValidationError
from .io import _loads
from .workflow_storage import WorkflowCheckpoint, WorkflowStoreLimits, _bytes, _request_digest

Outcome = Literal["none", "unknown", "complete"]
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_ROUTES = {f"/v1/workflow/{name}": name for name in ("snapshot", "append", "lookup")}
_CODES = {
    "invalid_request": 400,
    "unauthorized": 401,
    "forbidden": 403,
    "not_found": 404,
    "method_not_allowed": 405,
    "conflict": 409,
    "limit_exceeded": 413,
    "unsupported_media_type": 415,
    "workflow_rejected": 422,
    "rate_limited": 429,
    "unavailable": 503,
    "internal_error": 500,
    "transport_error": 0,
    "invalid_response": 0,
    "shutdown_timeout": 0,
    "lifecycle_error": 0,
}


class WorkflowServiceError(EvidenceBraidError):
    """Sanitized local service/SDK failure; outcome is not a rollback assertion."""

    code: str
    outcome: Outcome
    request_id: str | None
    request_digest: str | None
    status: int

    def __init__(
        self,
        code: str,
        outcome: Outcome = "none",
        *,
        request_id: str | None = None,
        request_digest: str | None = None,
    ) -> None:
        if type(code) is not str or code not in _CODES:
            raise ValidationError("invalid service error code")
        if type(outcome) is not str or outcome not in ("none", "unknown", "complete"):
            raise ValidationError("invalid service outcome")
        if request_id is not None:
            identifier(request_id, 58)
        if request_digest is not None:
            digest(request_digest)
        self.code = code
        self.outcome = outcome
        self.request_id = request_id
        self.request_digest = request_digest
        self.status = _CODES[code]
        super().__init__(f"workflow service {code}; outcome={outcome}")


def integer(value: Any, maximum: int, minimum: int = 1) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValidationError("service integer exceeds its exact native bounds")
    return value


def identifier(value: Any, maximum: int = 128) -> str:
    if type(value) is not str or len(value) > maximum or not _IDENTIFIER.fullmatch(value):
        raise ValidationError("invalid service identifier")
    return value


def digest(value: Any) -> str:
    if type(value) is not str or len(value) != 64 or not _HASH.fullmatch(value):
        raise ValidationError("invalid service digest or token syntax")
    return value


def object_fields(value: Any, names: set[str]) -> dict[str, Any]:
    if (
        type(value) is not dict
        or len(value) != len(names)
        or any(type(key) is not str for key in value)
    ):
        raise ValidationError("service wire requires an exact object")
    if value.keys() != names:
        raise ValidationError("service wire has unexpected fields")
    return value


@dataclass(frozen=True, slots=True)
class WorkflowServiceLimits:
    """Lowerable local profile; byte limits do not bound native CPU time or RSS."""

    max_credentials: int = 256
    max_authority_bytes: int = 4 * 1024 * 1024
    max_workers: int = 4
    max_request_line: int = 2048
    max_header_bytes: int = 16384
    max_headers: int = 32
    max_header_line: int = 4096
    max_request_bytes: int = 1024 * 1024
    max_request_depth: int = 16
    max_request_nodes: int = 8192
    max_append_records: int = 128
    max_records: int = 1000
    max_receipt_bytes: int = 128 * 1024
    max_bundle_bytes: int = 8 * 1024 * 1024
    max_operations: int = 1000
    max_operation_bytes: int = 8192
    max_operations_bytes: int = 1024 * 1024
    header_ms: int = 5000
    body_ms: int = 10000
    admission_ms: int = 2000
    io_ms: int = 10000
    sqlite_ms: int = 1000
    close_ms: int = 10000

    def __post_init__(self) -> None:
        durations = {
            "header_ms": 10000,
            "body_ms": 30000,
            "admission_ms": 5000,
            "io_ms": 30000,
            "sqlite_ms": 5000,
            "close_ms": 30000,
        }
        for item in fields(self):
            maximum = durations[item.name] if item.name in durations else cast(int, item.default)
            integer(getattr(self, item.name), maximum)
        if (
            self.max_append_records > self.max_records
            or self.max_operations > self.max_records
            or self.max_operation_bytes > self.max_operations_bytes
            or self.max_receipt_bytes > self.max_bundle_bytes
            or self.max_request_line > self.max_header_bytes
            or self.max_header_line > self.max_header_bytes
        ):
            raise ValidationError("incoherent service limits")

    @property
    def response_bytes(self) -> int:
        return self.max_bundle_bytes + 65536

    def store_limits(self) -> WorkflowStoreLimits:
        return WorkflowStoreLimits(
            **{item.name: getattr(self, item.name) for item in fields(WorkflowStoreLimits)}
        )


def limits_copy(value: WorkflowServiceLimits | None) -> WorkflowServiceLimits:
    if value is None:
        return WorkflowServiceLimits()
    if type(value) is not WorkflowServiceLimits:
        raise ValidationError("service limits require exact native type")
    return WorkflowServiceLimits(**{item.name: getattr(value, item.name) for item in fields(value)})


def authority_copy(value: AuthorityPolicy, limits: WorkflowServiceLimits) -> AuthorityPolicy:
    if type(value) is not AuthorityPolicy:
        raise ValidationError("service requires independently trusted exact authority")
    document = value.to_dict()
    _bytes(document, limits.max_authority_bytes)
    return AuthorityPolicy.from_dict(document)


def checkpoint(value: Any, context: str) -> WorkflowCheckpoint:
    if type(value) is not WorkflowCheckpoint:
        raise ValidationError("service requires exact checkpoint")
    result = WorkflowCheckpoint.from_dict(value.to_dict())
    if result.context_digest != context:
        raise WorkflowServiceError("conflict")
    return result


def namespace_id(service: str, context: str, actor: str, public: str) -> str:
    node = {
        "kind": "evidence-braid-workflow-service-request-namespace",
        "schema_version": "1.0",
        "service_id": identifier(service),
        "context_digest": digest(context),
        "actor_id": identifier(actor),
    }
    suffix = identifier(public, 58)
    return "svc1." + hashlib.sha256(_bytes(node, 4096)).hexdigest() + "." + suffix


def transitions_copy(
    value: Any,
    actor: str,
    limits: WorkflowServiceLimits,
) -> tuple[WorkflowTransition, ...]:
    if type(value) not in (list, tuple) or not 1 <= len(value) <= limits.max_append_records:
        raise ValidationError("service command count exceeds limit")
    if any(type(item) is not WorkflowTransition for item in value):
        raise ValidationError("service requires exact transitions")
    # Actor equality precedes even pure store helpers. Models are already immutable.
    if any(item.actor_id != actor for item in value):
        raise WorkflowServiceError("forbidden")
    return tuple(WorkflowTransition.from_dict(item.to_dict()) for item in value)


@dataclass(frozen=True, slots=True)
class PreparedWorkflowAppend:
    """Immutable, token-free caller-retained intent; no I/O or automatic rebasing."""

    service_id: str
    workflow_id: str
    context_digest: str
    actor_id: str
    request_id: str
    expected_checkpoint: WorkflowCheckpoint
    transitions: tuple[WorkflowTransition, ...]
    request_digest: str

    def __post_init__(self) -> None:
        limits = WorkflowServiceLimits()
        identifier(self.service_id)
        identifier(self.workflow_id)
        identifier(self.actor_id)
        digest(self.context_digest)
        identifier(self.request_id, 58)
        digest(self.request_digest)
        cp = checkpoint(self.expected_checkpoint, self.context_digest)
        commands = transitions_copy(self.transitions, self.actor_id, limits)
        object.__setattr__(self, "expected_checkpoint", cp)
        object.__setattr__(self, "transitions", commands)
        if (
            _request_digest(self.core_request_id, cp, commands, limits.store_limits())
            != self.request_digest
        ):
            raise WorkflowServiceError("conflict")
        self.admit(limits)

    @property
    def core_request_id(self) -> str:
        return namespace_id(self.service_id, self.context_digest, self.actor_id, self.request_id)

    def body(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "request_id": self.request_id,
            "request_digest": self.request_digest,
            "expected_checkpoint": self.expected_checkpoint.to_dict(),
            "transitions": [item.to_dict() for item in self.transitions],
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "service_id": self.service_id,
            "workflow_id": self.workflow_id,
            "context_digest": self.context_digest,
            "actor_id": self.actor_id,
        }

    def admit(self, limits: WorkflowServiceLimits) -> bytes:
        transitions_copy(self.transitions, self.actor_id, limits)
        _request_digest(
            self.core_request_id, self.expected_checkpoint, self.transitions, limits.store_limits()
        )
        parse_json(_bytes(self.to_dict(), limits.max_request_bytes), limits)
        return _bytes(self.body(), limits.max_request_bytes)

    @classmethod
    def from_dict(cls, value: Any) -> PreparedWorkflowAppend:
        node = object_fields(
            value,
            {
                "schema_version",
                "service_id",
                "workflow_id",
                "context_digest",
                "actor_id",
                "request_id",
                "expected_checkpoint",
                "transitions",
                "request_digest",
            },
        )
        # Admit before recursive conversion; native objects may be hostile subclasses.
        native_json(node, WorkflowServiceLimits())
        if node["schema_version"] != "1.0" or type(node["transitions"]) is not list:
            raise ValidationError("invalid prepared request")
        integer(len(node["transitions"]), 128)
        return cls(
            node["service_id"],
            node["workflow_id"],
            node["context_digest"],
            node["actor_id"],
            node["request_id"],
            WorkflowCheckpoint.from_dict(node["expected_checkpoint"]),
            tuple(WorkflowTransition.from_dict(item) for item in node["transitions"]),
            node["request_digest"],
        )


def native_json(value: Any, limits: WorkflowServiceLimits) -> bytes:
    """Native admission before invoking JSON conversion or custom-object hooks."""
    remaining = limits.max_request_nodes - 1
    pending = [(value, 0)]
    while pending:
        node, depth = pending.pop()
        kind = type(node)
        if kind in (dict, list):
            depth += 1
        if depth > limits.max_request_depth:
            raise WorkflowServiceError("limit_exceeded")
        if kind is dict:
            if len(node) * 2 > remaining:
                raise WorkflowServiceError("limit_exceeded")
            remaining -= len(node) * 2
            for key, item in node.items():
                if type(key) is not str:
                    raise ValidationError("invalid native JSON key")
                pending.extend(((key, depth), (item, depth)))
        elif kind is list:
            if len(node) > remaining:
                raise WorkflowServiceError("limit_exceeded")
            remaining -= len(node)
            pending.extend((item, depth) for item in node)
        elif kind is str:
            if len(node) > limits.max_request_bytes:
                raise WorkflowServiceError("limit_exceeded")
        elif kind is int:
            if node.bit_length() > 2127:
                raise WorkflowServiceError("limit_exceeded")
        elif node is not None and kind is not bool:
            raise ValidationError("invalid native JSON value")
    return _bytes(value, limits.max_request_bytes)


def parse_json(raw: bytes, limits: WorkflowServiceLimits, *, response: bool = False) -> Any:
    maximum = limits.response_bytes if response else limits.max_request_bytes
    max_depth = 128 if response else limits.max_request_depth
    max_nodes = maximum if response else limits.max_request_nodes
    if type(raw) is not bytes or len(raw) > maximum:
        raise WorkflowServiceError("limit_exceeded")
    depth = nodes = 0
    index = 0
    while index < len(raw):
        char = raw[index]
        if char == 34:
            nodes += 1
            index += 1
            while index < len(raw):
                if raw[index] == 92:
                    index += 2
                elif raw[index] == 34:
                    break
                else:
                    index += 1
        elif char in (123, 91):
            depth += 1
            nodes += 1
        elif char in (125, 93):
            depth -= 1
        elif char in b"-0123456789tfn":
            start = index
            while index + 1 < len(raw) and raw[index + 1] not in b" \r\n\t,]}:":
                index += 1
            # Preserve the existing 640-digit integer domain, including its sign.
            if index - start + 1 - (char == 45) > 640:
                raise WorkflowServiceError("limit_exceeded")
            nodes += 1
        if depth > max_depth or nodes > max_nodes:
            raise WorkflowServiceError("limit_exceeded")
        index += 1
    try:
        node = _loads(raw.decode("utf-8"))
        if _bytes(node, maximum) != raw:
            raise ValidationError("service JSON must be canonical")
        return node
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ValidationError("invalid service JSON") from error


def deadline(milliseconds: int) -> float:
    return time.monotonic() + milliseconds / 1000


def remaining(end: float) -> float:
    result = end - time.monotonic()
    if result <= 0:
        raise TimeoutError("local service I/O deadline")
    return result


def send(connection: socket.socket, payload: bytes, end: float) -> None:
    view = memoryview(payload)
    position = 0
    while position < len(view):
        connection.settimeout(remaining(end))
        written = connection.send(view[position:])
        if type(written) is not int or not 1 <= written <= len(view) - position:
            raise OSError("invalid socket write result")
        position += written


def _recv(
    connection: socket.socket,
    size: int,
    end: float,
    stop: threading.Event | None,
) -> bytes:
    while True:
        if stop is not None and stop.is_set():
            raise OSError("local service is draining")
        wait = remaining(end)
        connection.settimeout(wait if stop is None else min(wait, 0.05))
        try:
            return connection.recv(size)
        except TimeoutError:
            if stop is None:
                raise


def read_headers(
    connection: socket.socket,
    end: float,
    limits: WorkflowServiceLimits,
    *,
    response: bool = False,
    stop: threading.Event | None = None,
) -> tuple[str, dict[str, str], bytes]:
    maximum = 4096 if response else limits.max_header_bytes
    line_max = 1024 if response else limits.max_header_line
    first_max = 1024 if response else limits.max_request_line
    count_max = 8 if response else limits.max_headers
    raw = bytearray()
    while b"\r\n\r\n" not in raw:
        if len(raw) >= maximum:
            raise WorkflowServiceError("limit_exceeded")
        piece = _recv(connection, min(1024, maximum - len(raw)), end, stop)
        if not piece:
            raise OSError("premature HTTP header EOF")
        raw.extend(piece)
    header, tail = bytes(raw).split(b"\r\n\r\n", 1)
    lines = header.split(b"\r\n")
    if len(lines[0]) > first_max or len(lines) - 1 > count_max:
        raise WorkflowServiceError("limit_exceeded")
    headers: dict[str, str] = {}
    try:
        if any(char < 32 or char > 126 for char in lines[0]):
            raise ValueError
        for line in lines[1:]:
            if len(line) > line_max:
                raise WorkflowServiceError("limit_exceeded")
            name, value = line.split(b": ", 1)
            if not name or any(
                char not in b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-"
                for char in name
            ):
                raise ValueError
            if (
                not value
                or value != value.strip()
                or any(char < 32 or char > 126 for char in value)
            ):
                raise ValueError
            key = name.decode("ascii").lower()
            if key in headers:
                raise ValueError
            headers[key] = value.decode("ascii")
        return lines[0].decode("ascii"), headers, tail
    except ValueError:
        raise WorkflowServiceError("invalid_request") from None


def content_length(headers: dict[str, str], maximum: int) -> int:
    value = headers.get("content-length", "")
    if not value or len(value) > len(str(maximum)) or not value.isascii() or not value.isdecimal():
        raise WorkflowServiceError("invalid_request")
    if len(value) > 1 and value[0] == "0":
        raise WorkflowServiceError("invalid_request")
    size = int(value)
    if size > maximum:
        raise WorkflowServiceError("limit_exceeded")
    return size


def read_body(
    connection: socket.socket,
    tail: bytes,
    size: int,
    end: float,
    *,
    stop: threading.Event | None = None,
) -> bytes:
    raw = bytearray(tail[:size])
    while len(raw) < size:
        piece = _recv(connection, min(65536, size - len(raw)), end, stop)
        if not piece:
            raise OSError("premature HTTP body EOF")
        raw.extend(piece)
    return bytes(raw)


def response_frame(status: int, body: bytes) -> bytes:
    header = (
        f"HTTP/1.1 {status} Response\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n"
    ).encode("ascii")
    return header + body


def error_frame(error: WorkflowServiceError) -> bytes:
    return response_frame(
        error.status or 500,
        _bytes(
            {
                "schema_version": "1.0",
                "error_code": error.code,
                "outcome": error.outcome,
                "request_id": error.request_id,
                "request_digest": error.request_digest,
            },
            4096,
        ),
    )


def primary_failure(primary: BaseException | None, cleanup: BaseException) -> BaseException:
    if primary is None or (isinstance(primary, Exception) and not isinstance(cleanup, Exception)):
        if primary is not None:
            cleanup.add_note("prior local service failure retained during cleanup")
        return cleanup
    primary.add_note("local service cleanup also failed")
    return primary


EMERGENCY = {
    outcome: error_frame(WorkflowServiceError("internal_error", outcome))
    for outcome in ("none", "unknown", "complete")
}
