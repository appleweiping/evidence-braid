"""Bounded local CLI around the existing durable authority-workflow engine."""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Never, TextIO

from .authority import AuthorityPolicy, WorkflowTransition, _identifier
from .errors import InputFormatError, ValidationError
from .io import _loads
from .ledger import _fields, _hash
from .limits import DEFAULT_MAX_POLICY_BYTES
from .workflow import MAX_WORKFLOW_BYTES, WorkflowBundle
from .workflow_storage import (
    SQLiteWorkflowStore,
    WorkflowCheckpoint,
    WorkflowConflictError,
    WorkflowStorageError,
    _file_identity,
    _path,
)
from .workflow_storage import create_workflow_store as _create

_MAX_COMMANDS = 8 * 1024 * 1024
_MAX_REPORT = 64 * 1024 * 1024 + 64 * 1024


class _Arguments(Exception):
    pass


class _HelpDone(Exception):
    pass


class _DeliveryError(Exception):
    pass


def _write(stream: TextIO, content: str) -> None:
    # Native text wrappers may translate LF and use a locale encoding, notably
    # for redirected Windows stdout. Own the wire bytes without reconfiguring
    # or closing the caller's wrapper. Text-only injected streams receive the
    # same logical string; their external encoding is the caller's responsibility.
    target: Any = getattr(stream, "buffer", None)
    value: str | bytes
    if target is None:
        target, value = stream, content
    else:
        value = content.encode("utf-8")
    count = target.write(value)
    if type(count) is not int or count != len(value):
        raise _DeliveryError("incomplete command report")
    target.flush()


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        raise _Arguments("invalid workflow-store arguments")

    def exit(self, status: int = 0, message: str | None = None) -> Never:
        if status == 0:
            raise _HelpDone
        raise _Arguments("invalid workflow-store arguments")

    def _print_message(self, message: str, file: Any = None) -> None:
        if message:
            _write(sys.stderr if file is None else file, message)


def _parser() -> _Parser:
    parser = _Parser(
        prog="evidence-braid workflow-store",
        description="Operate a local authority workflow with explicit anchors and request IDs.",
        allow_abbrev=False,
    )
    commands = parser.add_subparsers(dest="operation", required=True)
    for name in ("create", "snapshot", "export", "request-digest", "append", "lookup"):
        operation = commands.add_parser(name, allow_abbrev=False)
        operation.add_argument("database", type=Path)
        operation.add_argument("--authority", required=True, type=Path)
        operation.add_argument("--expected-context", required=True)
        operation.add_argument("--timeout", type=float, default=10.0)
        if name == "create":
            operation.add_argument("--bundle", required=True, type=Path)
            operation.add_argument("--expected-head", required=True)
        if name in ("snapshot", "export", "request-digest", "append"):
            operation.add_argument(
                "--expected-checkpoint", type=Path, required=name in ("request-digest", "append")
            )
        if name in ("request-digest", "append"):
            operation.add_argument("--commands", required=True, type=Path)
        if name in ("request-digest", "append", "lookup"):
            operation.add_argument("--request-id", required=True)
        if name in ("append", "lookup"):
            operation.add_argument("--expected-request-digest", required=True)
    return parser


def _fingerprint(info: os.stat_result) -> tuple[int, int, int, int]:
    device, inode = _file_identity(info)
    return device, inode, info.st_size, info.st_mtime_ns


def _read(source: Path, maximum: int) -> bytes:
    path = _path(source)
    before = _fingerprint(path.lstat())
    if before[2] > maximum:
        raise InputFormatError("workflow-store input exceeds byte limit")
    handle = path.open("rb")
    primary: BaseException | None = None
    try:
        if _fingerprint(os.fstat(handle.fileno())) != before:
            raise InputFormatError("workflow-store input changed while opening")
        raw = bytearray()
        while True:
            requested = min(64 * 1024, maximum - len(raw) + 1)
            block = handle.read(requested)
            if type(block) is not bytes or len(block) > requested:
                raise InputFormatError("workflow-store input returned invalid bytes")
            if not block:
                break
            if len(raw) + len(block) > maximum:
                raise InputFormatError("workflow-store input exceeds byte limit")
            raw.extend(block)
        if (
            len(raw) != before[2]
            or _fingerprint(os.fstat(handle.fileno())) != before
            or _fingerprint(path.lstat()) != before
        ):
            raise InputFormatError("workflow-store input changed while reading")
        return bytes(raw)
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            handle.close()
        except BaseException as cleanup:
            if primary is None or (
                isinstance(primary, Exception) and not isinstance(cleanup, Exception)
            ):
                raise
            primary.add_note("workflow-store input close also failed")


def _json_file(path: Path, maximum: int) -> Any:
    return _loads(_read(path, maximum).decode("utf-8"))


def _commands(path: Path) -> tuple[WorkflowTransition, ...]:
    document = _fields(
        _json_file(path, _MAX_COMMANDS), {"schema_version", "transitions"}, "commands"
    )
    if type(document["schema_version"]) is not str or document["schema_version"] != "1.0":
        raise ValidationError("unsupported workflow commands version")
    values = document["transitions"]
    if type(values) is not list or not 1 <= len(values) <= 1000:
        raise ValidationError("workflow commands must be a bounded nonempty array")
    return tuple(WorkflowTransition.from_dict(value) for value in values)


def _report(value: Any) -> str:
    parts: list[str] = []
    size = 1  # One required LF belongs to the output-byte budget.
    encoder = json.JSONEncoder(
        ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    )
    for part in encoder.iterencode(value):
        size += len(part.encode("utf-8"))
        if size > _MAX_REPORT:
            raise _DeliveryError("workflow-store report exceeds byte limit")
        parts.append(part)
    return "".join(parts) + "\n"


@dataclass(slots=True)
class _Operation:
    outcome: str = "none"
    acknowledgement_pending: bool = False
    request_id: str | None = None
    request_digest: str | None = None

    def observe_failure(self, error: BaseException) -> None:
        if isinstance(error, WorkflowStorageError) and self.outcome != "complete":
            self.outcome = error.outcome
        elif (
            not isinstance(error, Exception)
            and self.acknowledgement_pending
            and self.outcome != "complete"
        ):
            # A control can interrupt mutation or historical-request lookup
            # before its return acknowledgement. Lookup itself is read-only.
            # Preserve its precise core notes; do not parse exception prose or
            # invent a no-write outcome at this outer boundary.
            self.outcome = "unknown"
        # Recovery metadata was admitted from CLI arguments before the call;
        # never replace it with unvalidated exception attributes.

    def diagnostic(self, error: Exception) -> dict[str, Any]:
        code = (
            "arguments"
            if isinstance(error, _Arguments)
            else "conflict"
            if isinstance(error, WorkflowConflictError)
            else "storage"
            if isinstance(error, WorkflowStorageError)
            else "delivery"
            if isinstance(error, _DeliveryError)
            else "rejected"
        )
        return {
            "error": "workflow-store command did not complete",
            "code": code,
            "outcome": self.outcome,
            "request_id": self.request_id,
            "request_digest": self.request_digest,
        }


def _execute(args: argparse.Namespace, state: _Operation) -> Any:
    _hash(args.expected_context, "expected_context")
    if not math.isfinite(args.timeout) or not 0 <= args.timeout <= 60:
        raise ValidationError("workflow-store timeout must be finite within 0..60")
    if hasattr(args, "expected_head"):
        _hash(args.expected_head, "expected_head")
    if hasattr(args, "request_id"):
        state.request_id = _identifier(args.request_id, "request_id")
    if hasattr(args, "expected_request_digest"):
        _hash(args.expected_request_digest, "expected_request_digest")
        state.request_digest = args.expected_request_digest
    policy = AuthorityPolicy.from_dict(_json_file(args.authority, DEFAULT_MAX_POLICY_BYTES))
    checkpoint = None
    if getattr(args, "expected_checkpoint", None) is not None:
        checkpoint = WorkflowCheckpoint.from_dict(_json_file(args.expected_checkpoint, 8192))
        if checkpoint.context_digest != args.expected_context:
            raise WorkflowConflictError("checkpoint belongs to a different context")
    commands = _commands(args.commands) if hasattr(args, "commands") else ()
    if args.operation == "create":
        bundle = WorkflowBundle.from_dict(
            _json_file(args.bundle, MAX_WORKFLOW_BYTES),
            authority=policy,
            expected_head=args.expected_head,
        )
        state.acknowledgement_pending = True
        store = _create(
            args.database,
            bundle,
            authority=policy,
            expected_context=args.expected_context,
            expected_head=args.expected_head,
            timeout=args.timeout,
        )
        state.outcome = "complete"
        state.acknowledgement_pending = False
        # A concurrent writer may advance the store before this separate read;
        # this command reports verified CURRENT state, not an invented creation receipt.
        return store.snapshot().to_dict()
    store = SQLiteWorkflowStore(
        args.database,
        authority=policy,
        expected_context=args.expected_context,
        timeout=args.timeout,
    )
    if args.operation in ("snapshot", "export"):
        current = store.snapshot(expected=checkpoint)
        return current.to_dict() if args.operation == "snapshot" else current.bundle.to_dict()
    if args.operation == "lookup":
        state.acknowledgement_pending = True
        commit = store.lookup(args.request_id, expected_request_digest=args.expected_request_digest)
        if commit is not None:
            state.outcome = "complete"
        state.acknowledgement_pending = False
        return None if commit is None else commit.to_dict()
    if checkpoint is None:
        raise ValidationError("request requires an explicit checkpoint")
    digest = store.request_digest(commands, request_id=args.request_id, expected=checkpoint)
    if args.operation == "request-digest":
        state.request_digest = digest
        return {
            "request_id": args.request_id,
            "request_digest": digest,
            "expected_checkpoint": checkpoint.to_dict(),
        }
    if digest != args.expected_request_digest:
        raise WorkflowConflictError("request does not match its external digest")
    state.acknowledgement_pending = True
    appended = store.append(commands, request_id=args.request_id, expected=checkpoint)
    state.outcome = "complete"
    state.acknowledgement_pending = False
    return appended.to_dict()


def run(argv: Sequence[str]) -> int:
    state = _Operation()
    try:
        if (
            type(argv) not in (tuple, list)
            or len(argv) > 40
            or any(type(value) is not str for value in argv)
            or sum(len(value) for value in argv) > 32 * 1024
            or sum(len(value.encode("utf-8")) for value in argv) > 32 * 1024
        ):
            raise _Arguments("workflow-store argument budget exceeded")
        try:
            args = _parser().parse_args(argv)
        except _HelpDone:
            return 0
        payload = _report(_execute(args, state))
        try:
            _write(sys.stdout, payload)
        except Exception as error:
            raise _DeliveryError("workflow-store report delivery failed") from error
        return 0
    except BaseException as error:
        state.observe_failure(error)
        if not isinstance(error, Exception):
            error.add_note(
                f"workflow-store outcome={state.outcome}; retain request identity for recovery"
            )
            raise
        try:
            diagnostic = json.dumps(state.diagnostic(error), sort_keys=True) + "\n"
            _write(sys.stderr, diagnostic)
        except Exception:
            # Failure reporting is best effort; it never changes failure into success.
            return 2
        except BaseException as control:
            control.add_note(f"workflow-store outcome={state.outcome}; error report interrupted")
            raise
        return 2
