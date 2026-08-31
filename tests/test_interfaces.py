from __future__ import annotations

import json
import sys
from io import StringIO
from pathlib import Path
from xml.etree import ElementTree

import pytest
from conftest import event_dict, policy_dict

from evidence_braid.cli import _emit, _emit_error, run
from evidence_braid.engine import evaluate
from evidence_braid.errors import InputFormatError, ValidationError
from evidence_braid.io import canonical_json, load_events, load_json, write_text
from evidence_braid.models import MAX_ATTRIBUTE_INTEGER_DIGITS, Policy, parse_timestamp
from evidence_braid.replay import replay
from evidence_braid.report import render_html, render_svg


def test_load_events_skips_blank_lines(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text("\n" + json.dumps(event_dict()) + "\n\n", encoding="utf-8")
    assert [event.event_id for event in load_events(path)] == ["e1"]


def test_load_events_reports_line_number(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text(json.dumps(event_dict()) + "\n{bad}\n", encoding="utf-8")
    with pytest.raises(InputFormatError, match="line 2"):
        load_events(path)


def test_load_events_wraps_model_path(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text(json.dumps(event_dict(confidence=2)), encoding="utf-8")
    with pytest.raises(ValidationError, match=r"events\[1\]\.confidence"):
        load_events(path)


def test_load_json_reports_location(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_text('{"oops":}', encoding="utf-8")
    with pytest.raises(InputFormatError, match="line 1, column"):
        load_json(path)


def test_load_json_rejects_nonstandard_nan(tmp_path: Path) -> None:
    path = tmp_path / "input.json"
    path.write_text('{"value": NaN}', encoding="utf-8")
    with pytest.raises(InputFormatError, match="non-standard"):
        load_json(path)


def test_load_json_rejects_finite_syntax_that_overflows_float(tmp_path: Path) -> None:
    path = tmp_path / "input.json"
    path.write_text('{"value": 1e400}', encoding="utf-8")
    with pytest.raises(InputFormatError, match="finite float range"):
        load_json(path)


def test_load_json_rejects_duplicate_keys_at_any_depth(tmp_path: Path) -> None:
    path = tmp_path / "input.json"
    path.write_text('{"outer": {"value": 1, "value": 2}}', encoding="utf-8")
    with pytest.raises(InputFormatError, match=r"duplicate object key.*value"):
        load_json(path)


def test_load_events_rejects_duplicate_keys_with_line_number(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    raw = json.dumps(event_dict())
    duplicate = raw[:-1] + ', "event_id": "replacement"}'
    path.write_text("\n" + duplicate + "\n", encoding="utf-8")
    with pytest.raises(InputFormatError, match=r"line 2.*duplicate object key.*event_id"):
        load_events(path)


def test_load_events_rejects_overflowed_float_with_line_number(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    raw = json.dumps(event_dict()).replace('"confidence": 0.9', '"confidence": 1e400')
    path.write_text(raw, encoding="utf-8")
    with pytest.raises(InputFormatError, match=r"line 1.*finite float range"):
        load_events(path)


@pytest.mark.parametrize("loader", [load_json, load_events])
def test_loaders_wrap_invalid_utf8(tmp_path: Path, loader) -> None:
    path = tmp_path / "invalid-input"
    path.write_bytes(b'{"field":"\xff"}')
    with pytest.raises(InputFormatError, match="UTF-8"):
        loader(path)


def test_canonical_json_rejects_nonfinite_number() -> None:
    with pytest.raises(InputFormatError, match="strict JSON"):
        canonical_json({"value": float("inf")})


@pytest.mark.parametrize("loader", [load_json, load_events])
def test_loaders_wrap_missing_file(tmp_path: Path, loader) -> None:
    with pytest.raises(InputFormatError, match="cannot read"):
        loader(tmp_path / "missing")


def test_write_text_wraps_filesystem_error(tmp_path: Path) -> None:
    with pytest.raises(InputFormatError, match="cannot write"):
        write_text(tmp_path, "content")


def test_replay_emits_one_result_per_ingestion_time(make_event) -> None:
    policy = Policy.from_dict(policy_dict())
    events = [
        make_event("a", ingested_at="2026-08-31T11:59:31Z"),
        make_event("b", ingested_at="2026-08-31T11:59:31Z"),
        make_event("c", ingested_at="2026-08-31T11:59:45Z"),
    ]
    results = replay(policy, events)
    assert len(results) == 2
    assert [result.considered_event_count for result in results] == [2, 3]


def test_replay_is_deterministic(make_event) -> None:
    policy = Policy.from_dict(policy_dict())
    events = [make_event("b"), make_event("a")]
    assert [result.to_dict() for result in replay(policy, events)] == [
        result.to_dict() for result in replay(policy, reversed(events))
    ]


def test_replay_snapshots_are_prefix_stable_and_do_not_reveal_future_events(make_event) -> None:
    policy = Policy.from_dict(policy_dict())
    first = make_event("a", ingested_at="2026-08-31T11:59:31Z")
    second = make_event("b", ingested_at="2026-08-31T11:59:40Z")
    future = make_event("future", ingested_at="2026-08-31T11:59:50Z")

    prefix = replay(policy, [first, second])
    extended = replay(policy, [first, second, future])

    assert [result.to_dict() for result in prefix] == [result.to_dict() for result in extended[:2]]
    assert [result.input_event_count for result in extended] == [1, 2, 3]
    assert all(not result.pending_event_ids for result in extended)


def test_replay_uses_same_source_clock_rule_as_fixed_evaluation(policy, make_event) -> None:
    event = make_event(
        observed_at="2026-08-31T12:00:04Z",
        ingested_at="2026-08-31T12:00:00Z",
    )
    with pytest.raises(ValidationError, match="future of ingestion"):
        replay(policy, [event])


def test_replay_rejects_duplicate_ids(make_event) -> None:
    with pytest.raises(ValidationError, match="duplicate"):
        replay(Policy.from_dict(policy_dict()), [make_event(), make_event()])


def test_html_escapes_claim_and_contains_digest(make_event) -> None:
    raw_policy = policy_dict(quorum=1, min_sources=1, min_modalities=1)
    raw_policy["claims"]["<script>alert(1)</script>"] = raw_policy["claims"].pop("incident")
    policy = Policy.from_dict(raw_policy)
    event = make_event(claim="<script>alert(1)</script>")
    result = evaluate(policy, [event], parse_timestamp("2026-08-31T12:00:00Z", "test"))
    html = render_html(result)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert result.digest in html


def test_svg_is_accessible_and_contains_outcome(policy, make_event) -> None:
    result = evaluate(policy, [make_event()], parse_timestamp("2026-08-31T12:00:00Z", "test"))
    svg = render_svg(result)
    assert 'role="img"' in svg
    assert "<title" in svg
    assert "REVIEW" in svg
    assert ElementTree.fromstring(svg).tag == "{http://www.w3.org/2000/svg}svg"


def test_maximum_attribute_integer_is_safe_through_result_and_reports(policy, make_event) -> None:
    maximum = 10**MAX_ATTRIBUTE_INTEGER_DIGITS - 1
    get_limit = getattr(sys, "get_int_max_str_digits", None)
    set_limit = getattr(sys, "set_int_max_str_digits", None)
    if get_limit is None or set_limit is None:
        pytest.skip("runtime integer-string limit is unavailable")
    previous = get_limit()
    try:
        set_limit(MAX_ATTRIBUTE_INTEGER_DIGITS)
        event = make_event(attributes={"positive": maximum, "negative": -maximum, "zero": 0})
        assert canonical_json(event.to_dict()).endswith("\n")

        result = evaluate(policy, [event], parse_timestamp("2026-08-31T12:00:00Z", "test"))

        assert result.digest.startswith("sha256:")
        assert canonical_json(result.to_dict()).endswith("\n")
        assert render_html(result).startswith("<!doctype html>")
        assert ElementTree.fromstring(render_svg(result)).tag.endswith("svg")
    finally:
        set_limit(previous)


def _write_cli_inputs(tmp_path: Path) -> tuple[Path, Path]:
    policy_path = tmp_path / "policy.json"
    event_path = tmp_path / "events.jsonl"
    policy_path.write_text(json.dumps(policy_dict()), encoding="utf-8")
    event_path.write_text(json.dumps(event_dict()), encoding="utf-8")
    return policy_path, event_path


def test_cli_evaluate_writes_all_formats(tmp_path: Path) -> None:
    policy_path, event_path = _write_cli_inputs(tmp_path)
    output = tmp_path / "result.json"
    html = tmp_path / "result.html"
    svg = tmp_path / "result.svg"
    code = run(
        [
            "evaluate",
            str(policy_path),
            str(event_path),
            "--as-of",
            "2026-08-31T12:00:00Z",
            "--output",
            str(output),
            "--html",
            str(html),
            "--svg",
            str(svg),
        ]
    )
    assert code == 0
    assert json.loads(output.read_text(encoding="utf-8"))["policy_id"] == "test-policy"
    assert html.read_text(encoding="utf-8").startswith("<!doctype html>")
    assert svg.read_text(encoding="utf-8").startswith("<svg")


def test_cli_replay_writes_jsonl(tmp_path: Path) -> None:
    policy_path, event_path = _write_cli_inputs(tmp_path)
    output = tmp_path / "replay.jsonl"
    assert run(["replay", str(policy_path), str(event_path), "--output", str(output)]) == 0
    assert len(output.read_text(encoding="utf-8").splitlines()) == 1


def test_cli_returns_two_for_domain_error(tmp_path: Path, capsys) -> None:
    policy_path, event_path = _write_cli_inputs(tmp_path)
    assert run(["evaluate", str(policy_path), str(event_path), "--as-of", "not-a-time"]) == 2
    assert "error:" in capsys.readouterr().err


def test_cli_evaluate_can_write_to_stdout(tmp_path: Path, capsys) -> None:
    policy_path, event_path = _write_cli_inputs(tmp_path)
    assert (
        run(
            [
                "evaluate",
                str(policy_path),
                str(event_path),
                "--as-of",
                "2026-08-31T12:00:00Z",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["policy_id"] == "test-policy"


def test_stdout_encoding_failure_is_wrapped(monkeypatch) -> None:
    class BrokenStdout:
        def write(self, content: str) -> None:
            raise UnicodeEncodeError("ascii", content, 0, 1, "unsupported")

    with monkeypatch.context() as context:
        context.setattr("sys.stdout", BrokenStdout())
        with pytest.raises(InputFormatError, match="cannot encode output"):
            _emit("-", "é")


def test_domain_error_is_safe_on_restricted_stderr(monkeypatch) -> None:
    class AsciiStream(StringIO):
        encoding = "ascii"

        def write(self, content: str) -> int:
            content.encode("ascii")
            return super().write(content)

    stream = AsciiStream()
    monkeypatch.setattr(sys, "stderr", stream)
    _emit_error(InputFormatError("不存在\n\x1b[2J"))
    assert stream.getvalue() == "error: \\u4e0d\\u5b58\\u5728\\n\\x1b[2J\n"
