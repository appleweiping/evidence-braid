"""Strict JSON and JSONL adapters with bounded reads."""

from __future__ import annotations

import json
from collections.abc import Iterator
from math import isfinite
from pathlib import Path
from typing import Any

from .errors import InputFormatError, ValidationError
from .limits import (
    DEFAULT_MAX_EVENT_FILE_BYTES,
    DEFAULT_MAX_LINE_BYTES,
    DEFAULT_MAX_POLICY_BYTES,
    MAX_EVENT_FILE_BYTES,
    MAX_LINE_BYTES,
    MAX_POLICY_BYTES,
)
from .models import EvidenceEvent, Policy


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-standard numeric constant: {value}")


def _parse_finite_float(value: str) -> float:
    result = float(value)
    if not isfinite(result):
        raise ValueError("JSON number is outside the finite float range")
    return result


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate object key: {key!a}")
        result[key] = value
    return result


def _limit(value: object, name: str, ceiling: int) -> int:
    """Validate a caller-supplied byte limit against its compiled ceiling.

    A caller may tighten a limit for one untrusted feed. Raising it above the
    ceiling is refused, so the ceiling remains a property of the build rather
    than of the argument list.
    """
    if type(value) is not int or not 1 <= value <= ceiling:
        raise ValidationError(f"{name} must be an integer between 1 and {ceiling}")
    return value


def _read_bounded(source: Path, maximum: int, label: str) -> bytes:
    """Read at most ``maximum`` bytes and refuse a larger document outright.

    One extra byte is requested so an oversized file is reported instead of
    being silently truncated to the limit.
    """
    try:
        with source.open("rb") as handle:
            raw = handle.read(maximum + 1)
    except OSError as exc:
        raise InputFormatError(f"cannot read {source}: {exc}") from exc
    if len(raw) > maximum:
        raise InputFormatError(f"{label} {source} exceeds the {maximum}-byte limit")
    return raw


def _decode(raw: bytes, source: Path) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeError as exc:
        raise InputFormatError(f"cannot decode {source} as UTF-8: {exc}") from exc


def _loads(text: str) -> Any:
    return json.loads(
        text,
        parse_constant=_reject_constant,
        parse_float=_parse_finite_float,
        object_pairs_hook=_reject_duplicate_keys,
    )


def _iter_json_lines(
    source: Path,
    maximum: int,
    line_maximum: int,
    label: str,
) -> Iterator[tuple[int, str]]:
    """Yield every non-blank line of a bounded JSONL document with its number.

    ``bytes.splitlines`` recognizes exactly the newline forms Python's text
    mode normalizes, so line numbers match the ones an operator sees in an
    editor. Each line is measured before it is decoded.
    """
    raw = _read_bounded(source, maximum, label)
    for line_number, chunk in enumerate(raw.splitlines(), 1):
        if len(chunk) > line_maximum:
            raise InputFormatError(
                f"{source} line {line_number} exceeds the {line_maximum}-byte limit"
            )
        line = _decode(chunk, source)
        if line.strip():
            yield line_number, line


def load_json(path: str | Path, *, max_bytes: int = DEFAULT_MAX_POLICY_BYTES) -> Any:
    source = Path(path)
    maximum = _limit(max_bytes, "max_bytes", MAX_POLICY_BYTES)
    text = _decode(_read_bounded(source, maximum, "JSON file"), source)
    try:
        return _loads(text)
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        if isinstance(exc, json.JSONDecodeError):
            location = f" at line {exc.lineno}, column {exc.colno}"
        else:
            location = f": {exc}"
        raise InputFormatError(f"invalid JSON in {source}{location}") from exc


def load_policy(path: str | Path, *, max_bytes: int = DEFAULT_MAX_POLICY_BYTES) -> Policy:
    return Policy.from_dict(load_json(path, max_bytes=max_bytes))


def load_events(
    path: str | Path,
    *,
    max_bytes: int = DEFAULT_MAX_EVENT_FILE_BYTES,
    max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
) -> list[EvidenceEvent]:
    source = Path(path)
    maximum = _limit(max_bytes, "max_bytes", MAX_EVENT_FILE_BYTES)
    line_maximum = _limit(max_line_bytes, "max_line_bytes", MAX_LINE_BYTES)
    events: list[EvidenceEvent] = []
    for line_number, line in _iter_json_lines(source, maximum, line_maximum, "event file"):
        try:
            raw = _loads(line)
        except (json.JSONDecodeError, RecursionError, ValueError) as exc:
            column = exc.colno if isinstance(exc, json.JSONDecodeError) else 1
            detail = "" if isinstance(exc, json.JSONDecodeError) else f": {exc}"
            raise InputFormatError(
                f"invalid JSONL in {source} at line {line_number}, column {column}{detail}"
            ) from exc
        try:
            events.append(EvidenceEvent.from_dict(raw, f"events[{line_number}]"))
        except ValidationError as exc:
            raise ValidationError(f"{source}: {exc}") from exc
    return events


def canonical_json(value: Any, *, pretty: bool = True) -> str:
    """Serialize consistently for files, stdout, and golden examples."""
    try:
        if pretty:
            return (
                json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False)
                + "\n"
            )
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (RecursionError, TypeError, UnicodeError, ValueError) as exc:
        raise InputFormatError(f"value cannot be serialized as strict JSON: {exc}") from exc


def write_text(path: str | Path, content: str) -> None:
    # `Path("")` silently becomes `Path(".")`, so an empty destination — which is
    # what an unset shell variable expands to — would otherwise be reported as a
    # permission error on the working directory rather than as the bad argument
    # it is.
    if not str(path):
        raise InputFormatError("cannot write output: destination path is empty")
    destination = Path(path)
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8", newline="\n")
    except (OSError, UnicodeError) as exc:
        raise InputFormatError(f"cannot write {destination}: {exc}") from exc
