from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from conftest import event_dict, policy_dict

from evidence_braid.errors import EvidenceBraidError, InputFormatError, ValidationError
from evidence_braid.io import load_events, load_json, load_policy
from evidence_braid.limits import (
    DEFAULT_MAX_EVENT_FILE_BYTES,
    DEFAULT_MAX_LINE_BYTES,
    DEFAULT_MAX_POLICY_BYTES,
    MAX_EVENT_FILE_BYTES,
    MAX_LINE_BYTES,
    MAX_POLICY_BYTES,
)

MEBIBYTE = 1024 * 1024


def _write(path: Path, text: str) -> int:
    """Write UTF-8 bytes and return the exact on-disk size the limits measure."""
    raw = text.encode("utf-8")
    path.write_bytes(raw)
    return len(raw)


def _byte_length(text: str) -> int:
    return len(text.encode("utf-8"))


def test_documented_limits_match_the_published_boundary() -> None:
    # The README and architecture notes quote these numbers. Pinning them here
    # keeps prose and behavior from drifting apart silently.
    assert DEFAULT_MAX_POLICY_BYTES == 4 * MEBIBYTE
    assert DEFAULT_MAX_EVENT_FILE_BYTES == 64 * MEBIBYTE
    assert DEFAULT_MAX_LINE_BYTES == 1 * MEBIBYTE
    assert MAX_POLICY_BYTES == 16 * MEBIBYTE
    assert MAX_EVENT_FILE_BYTES == 256 * MEBIBYTE
    assert MAX_LINE_BYTES == 16 * MEBIBYTE


@pytest.mark.parametrize(
    ("default", "ceiling"),
    [
        (DEFAULT_MAX_POLICY_BYTES, MAX_POLICY_BYTES),
        (DEFAULT_MAX_EVENT_FILE_BYTES, MAX_EVENT_FILE_BYTES),
        (DEFAULT_MAX_LINE_BYTES, MAX_LINE_BYTES),
    ],
)
def test_every_default_is_a_positive_integer_within_its_ceiling(default: int, ceiling: int) -> None:
    assert type(default) is int
    assert type(ceiling) is int
    assert 1 <= default <= ceiling


def test_load_json_accepts_a_document_of_exactly_the_permitted_size(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    size = _write(path, json.dumps(policy_dict()))
    assert load_json(path, max_bytes=size)["policy_id"] == "test-policy"


def test_load_json_refuses_a_document_one_byte_over_the_limit(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    size = _write(path, json.dumps(policy_dict()))
    with pytest.raises(InputFormatError) as error:
        load_json(path, max_bytes=size - 1)
    message = str(error.value)
    assert isinstance(error.value, EvidenceBraidError)
    assert str(path) in message
    assert f"{size - 1}-byte limit" in message


def test_load_json_refuses_rather_than_truncating_to_a_valid_prefix(tmp_path: Path) -> None:
    # The first eight bytes are by themselves a complete JSON document. A reader
    # that stopped at the limit would accept a decision input it never saw whole.
    path = tmp_path / "policy.json"
    _write(path, '{"a": 1}{"b": 2}')
    with pytest.raises(InputFormatError, match="exceeds the 8-byte limit"):
        load_json(path, max_bytes=8)


def test_load_policy_applies_a_tightened_limit(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    size = _write(path, json.dumps(policy_dict()))
    assert load_policy(path, max_bytes=size).policy_id == "test-policy"
    with pytest.raises(InputFormatError, match="JSON file"):
        load_policy(path, max_bytes=size - 1)


def test_load_events_accepts_a_file_of_exactly_the_permitted_size(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    size = _write(path, json.dumps(event_dict("e1")) + "\n")
    assert [event.event_id for event in load_events(path, max_bytes=size)] == ["e1"]


def test_load_events_refuses_an_oversized_file_without_returning_a_prefix(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    first = json.dumps(event_dict("e1"))
    size = _write(path, first + "\n" + json.dumps(event_dict("e2")) + "\n")
    assert len(load_events(path, max_bytes=size)) == 2
    with pytest.raises(InputFormatError) as error:
        load_events(path, max_bytes=_byte_length(first) + 1)
    assert "event file" in str(error.value)


def test_load_events_accepts_a_line_of_exactly_the_permitted_size(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    wide = json.dumps(event_dict("e2", attributes={"note": "x" * 400}))
    size = _write(path, json.dumps(event_dict("e1")) + "\n" + wide + "\n")
    events = load_events(path, max_bytes=size, max_line_bytes=_byte_length(wide))
    assert [event.event_id for event in events] == ["e1", "e2"]


def test_load_events_refuses_one_oversized_line_inside_a_permitted_file(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    narrow = json.dumps(event_dict("e1"))
    wide = json.dumps(event_dict("e2", attributes={"note": "x" * 400}))
    size = _write(path, narrow + "\n" + wide + "\n")
    line_limit = _byte_length(narrow)
    with pytest.raises(InputFormatError) as error:
        load_events(path, max_bytes=size, max_line_bytes=line_limit)
    message = str(error.value)
    assert isinstance(error.value, EvidenceBraidError)
    assert str(path) in message
    assert "line 2" in message
    assert f"{line_limit}-byte limit" in message


def test_load_events_measures_lines_before_decoding_them(tmp_path: Path) -> None:
    # Bytes, not characters, are the resource being bounded: a line that fits the
    # limit in characters is still refused on its wider encoded length.
    path = tmp_path / "events.jsonl"
    text = json.dumps(event_dict("e1", attributes={"note": "e" * 40}), ensure_ascii=False)
    wide_text = text.replace("e" * 40, "é" * 40)
    size = _write(path, wide_text + "\n")
    assert len(wide_text) < size - 1
    with pytest.raises(InputFormatError, match="line 1"):
        load_events(path, max_bytes=size, max_line_bytes=len(wide_text))


def test_policy_limit_may_be_tightened_but_never_raised(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    _write(path, json.dumps(policy_dict()))
    assert load_json(path, max_bytes=MAX_POLICY_BYTES)["policy_id"] == "test-policy"
    with pytest.raises(ValidationError) as error:
        load_json(path, max_bytes=MAX_POLICY_BYTES + 1)
    assert str(error.value) == f"max_bytes must be an integer between 1 and {MAX_POLICY_BYTES}"


def test_event_file_limit_may_be_tightened_but_never_raised(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    _write(path, json.dumps(event_dict("e1")) + "\n")
    assert len(load_events(path, max_bytes=MAX_EVENT_FILE_BYTES)) == 1
    with pytest.raises(ValidationError) as error:
        load_events(path, max_bytes=MAX_EVENT_FILE_BYTES + 1)
    assert str(error.value) == f"max_bytes must be an integer between 1 and {MAX_EVENT_FILE_BYTES}"


def test_line_limit_may_be_tightened_but_never_raised(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    _write(path, json.dumps(event_dict("e1")) + "\n")
    assert len(load_events(path, max_line_bytes=MAX_LINE_BYTES)) == 1
    with pytest.raises(ValidationError) as error:
        load_events(path, max_line_bytes=MAX_LINE_BYTES + 1)
    assert str(error.value) == f"max_line_bytes must be an integer between 1 and {MAX_LINE_BYTES}"


def test_a_limit_above_its_ceiling_is_refused_before_any_file_is_opened(tmp_path: Path) -> None:
    # A refused limit must not degrade into an I/O error message; the caller's
    # argument is wrong whether or not the path exists.
    missing = tmp_path / "absent.json"
    with pytest.raises(ValidationError, match="max_bytes must be an integer"):
        load_json(missing, max_bytes=MAX_POLICY_BYTES + 1)
    with pytest.raises(ValidationError, match="max_line_bytes must be an integer"):
        load_events(missing, max_line_bytes=MAX_LINE_BYTES + 1)


@pytest.mark.parametrize("value", [0, -1, True, 1.0, "4096", None])
def test_a_limit_that_is_not_a_positive_integer_is_refused(tmp_path: Path, value: Any) -> None:
    path = tmp_path / "policy.json"
    _write(path, json.dumps(policy_dict()))
    with pytest.raises(ValidationError, match="max_bytes must be an integer"):
        load_json(path, max_bytes=value)
