"""Strict JSON and JSONL adapters."""

from __future__ import annotations

import json
from math import isfinite
from pathlib import Path
from typing import Any

from .errors import InputFormatError, ValidationError
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


def load_json(path: str | Path) -> Any:
    source = Path(path)
    try:
        with source.open("r", encoding="utf-8") as handle:
            return json.load(
                handle,
                parse_constant=_reject_constant,
                parse_float=_parse_finite_float,
                object_pairs_hook=_reject_duplicate_keys,
            )
    except UnicodeError as exc:
        raise InputFormatError(f"cannot decode {source} as UTF-8: {exc}") from exc
    except OSError as exc:
        raise InputFormatError(f"cannot read {source}: {exc}") from exc
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        if isinstance(exc, json.JSONDecodeError):
            location = f" at line {exc.lineno}, column {exc.colno}"
        else:
            location = f": {exc}"
        raise InputFormatError(f"invalid JSON in {source}{location}") from exc


def load_policy(path: str | Path) -> Policy:
    return Policy.from_dict(load_json(path))


def load_events(path: str | Path) -> list[EvidenceEvent]:
    source = Path(path)
    events: list[EvidenceEvent] = []
    try:
        with source.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    raw = json.loads(
                        line,
                        parse_constant=_reject_constant,
                        parse_float=_parse_finite_float,
                        object_pairs_hook=_reject_duplicate_keys,
                    )
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
    except UnicodeError as exc:
        raise InputFormatError(f"cannot decode {source} as UTF-8: {exc}") from exc
    except OSError as exc:
        raise InputFormatError(f"cannot read {source}: {exc}") from exc
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
    destination = Path(path)
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8", newline="\n")
    except (OSError, UnicodeError) as exc:
        raise InputFormatError(f"cannot write {destination}: {exc}") from exc
