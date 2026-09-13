"""Admission, stable-file ownership, and all-or-nothing local CLI intent."""

import io
import json
import os
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from evidence_braid import WorkflowTransition
from evidence_braid import workflow_store_cli as module
from evidence_braid.cli import run
from tests.test_workflow_storage import audit, command, create, reopen
from tests.test_workflow_store_cli import arguments, request_files, write_json
from tests.test_workflow_store_cli_delivery import Output, prepared


@pytest.mark.parametrize(
    "argv",
    [
        (),
        [],
        ["PRIVATE"] * 41,
        ["😀" * 8193],
        ["x" * 32769],
        [None],
        [1],
        ["\ud800"],
        {"PRIVATE": "secret"},
        "snapshot",
    ],
)
def test_argv_admission_never_echoes_tokens_or_reaches_input_reads(monkeypatch, capsys, argv):
    def forbidden(*args):
        pytest.fail("invalid argv must be rejected before input reads")

    monkeypatch.setattr(module, "_json_file", forbidden)
    assert module.run(argv) == 2
    captured = capsys.readouterr()
    assert not captured.out
    assert "PRIVATE" not in captured.err and "secret" not in captured.err
    assert json.loads(captured.err)["outcome"] == "none"


@pytest.mark.parametrize(
    "argv",
    [
        ["--help"],
        ["create", "--help"],
        ["snapshot", "--help"],
        ["export", "--help"],
        ["request-digest", "--help"],
        ["append", "--help"],
        ["lookup", "--help"],
        ["--help", "PRIVATE"],  # Argparse's immediate help action never executes an operation.
    ],
)
def test_help_writes_complete_usage_and_returns_without_input_io(argv, capsys, monkeypatch):
    monkeypatch.setattr(module, "_json_file", lambda *args: pytest.fail("help read input"))
    assert module.run(argv) == 0
    captured = capsys.readouterr()
    assert captured.out.startswith("usage: evidence-braid workflow-store")
    assert not captured.err


@pytest.mark.parametrize("failure", ["write", "short", "none", "bool", "over", "flush"])
def test_help_checks_output_delivery(failure, monkeypatch):
    errors = io.StringIO()
    with monkeypatch.context() as patch:
        patch.setattr(module.sys, "stdout", Output(failure))
        patch.setattr(module.sys, "stderr", errors)
        assert module.run(["--help"]) == 2
    assert json.loads(errors.getvalue())["outcome"] == "none"


@pytest.mark.parametrize("failure", ["write", "short", "none", "bool", "over", "flush"])
def test_failed_error_report_still_returns_failure(monkeypatch, failure):
    with monkeypatch.context() as patch:
        patch.setattr(module.sys, "stderr", Output(failure))
        assert module.run([]) == 2


@pytest.mark.parametrize("control_type", [KeyboardInterrupt, SystemExit])
def test_error_report_control_is_not_swallowed(monkeypatch, control_type):
    control = control_type("PRIVATE stderr")
    with monkeypatch.context() as patch:
        patch.setattr(module.sys, "stderr", Output(control))
        with pytest.raises(control_type) as caught:
            module.run([])
    assert caught.value is control
    assert "workflow-store outcome=none; error report interrupted" in control.__notes__


@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema_version":"1.0","transitions":[],"PRIVATE":1}',
        b'{"schema_version":"2.0","transitions":[]}',
        b'{"schema_version":1,"transitions":[]}',
        b'{"schema_version":"1.0","transitions":[]}',
        b'{"schema_version":"1.0","transitions":{}}',
        b'{"schema_version":"1.0","transitions":[{}]}',
        b'{"schema_version":"1.0","transitions":[NaN]}',
        b'{"schema_version":"1.0","schema_version":"1.0","transitions":[]}',
        b"\xff",
        b"[]",
        b"null",
        b'"PRIVATE"',
        b"{",
    ],
)
def test_commands_are_closed_strict_json_before_database_access(tmp_path, monkeypatch, capsys, raw):
    store = create(tmp_path / "workflow.db")
    fields = request_files(tmp_path, store.snapshot().checkpoint)
    (tmp_path / "commands.json").write_bytes(raw)
    argv = arguments(tmp_path, "request-digest", *fields)
    monkeypatch.setattr(module, "SQLiteWorkflowStore", lambda *a, **k: pytest.fail("opened DB"))
    assert run(argv) == 2
    captured = capsys.readouterr()
    assert not captured.out and "PRIVATE" not in captured.err


@pytest.mark.parametrize("count", [0, 1001])
def test_command_count_rejects_before_constructing_any_transition(tmp_path, monkeypatch, count):
    source = write_json(
        tmp_path / "commands.json",
        {
            "schema_version": "1.0",
            "transitions": [{}] * count,
        },
    )
    monkeypatch.setattr(WorkflowTransition, "from_dict", lambda value: pytest.fail("constructed"))
    with pytest.raises(module.ValidationError):
        module._commands(source)


def test_command_count_exact_boundary_uses_all_real_transitions(tmp_path):
    values = [command(str(index)) for index in range(1000)]
    source = write_json(
        tmp_path / "commands.json",
        {
            "schema_version": "1.0",
            "transitions": [value.to_dict() for value in values],
        },
    )
    assert module._commands(source) == tuple(values)


@pytest.mark.parametrize("kind", ["authority", "commands", "checkpoint", "bundle"])
def test_each_input_has_its_declared_file_admission_cap(tmp_path, monkeypatch, capsys, kind):
    if kind == "bundle":
        argv, _ = prepared(tmp_path, "create")
        filename, maximum = "initial.json", module.MAX_WORKFLOW_BYTES
    else:
        argv, _ = prepared(tmp_path, "append")
        filename, maximum = {
            "authority": ("authority.json", module.DEFAULT_MAX_POLICY_BYTES),
            "commands": ("commands.json", module._MAX_COMMANDS),
            "checkpoint": ("checkpoint.json", 8192),
        }[kind]
    # Real sparse regular file exercises pre-open metadata admission without
    # constructing a huge JSON value or substituting the product limit.
    with (tmp_path / filename).open("wb") as handle:
        handle.truncate(maximum + 1)
    monkeypatch.setattr(module, "SQLiteWorkflowStore", lambda *a, **k: pytest.fail("opened DB"))
    monkeypatch.setattr(module, "_create", lambda *a, **k: pytest.fail("created DB"))
    assert run(argv) == 2
    assert json.loads(capsys.readouterr().err)["outcome"] == "none"


@pytest.mark.parametrize("size", [0, 1, 65535, 65536, 65537])
def test_real_file_exact_byte_boundary_and_one_over(tmp_path, size):
    path = tmp_path / "input.bin"
    raw = b"x" * size
    path.write_bytes(raw)
    assert module._read(path, size) == raw
    if size:
        with pytest.raises(module.InputFormatError):
            module._read(path, size - 1)


@pytest.mark.parametrize("kind", ["missing", "directory", "symlink", "protocol", "unc"])
def test_invalid_input_path_is_not_followed(tmp_path, kind):
    path = tmp_path / "input.json"
    if kind == "directory":
        path.mkdir()
    elif kind == "symlink":
        target = tmp_path / "real.json"
        target.write_bytes(b"{}")
        try:
            path.symlink_to(target)
        except OSError as error:
            if os.name == "nt" and error.winerror == 1314:
                pytest.skip("Windows symbolic-link privilege is unavailable")
            raise
    elif kind == "protocol":
        path = "https://private.example/input"
    elif kind == "unc":
        path = "//private/share/input"
    with pytest.raises((OSError, module.ValidationError)):
        module._read(path, 100)


@pytest.mark.parametrize("stage", ["opened", "finished-handle", "finished-path", "identity"])
def test_changed_or_unavailable_file_identity_rejects_and_closes_owned_handle(
    tmp_path, monkeypatch, stage
):
    path = tmp_path / "input.json"
    path.write_bytes(b"{}")
    original_open, original_stat = Path.open, module.os.fstat
    opened, calls = [], 0

    def open_handle(target, *args, **kwargs):
        handle = original_open(target, *args, **kwargs)
        opened.append(handle)
        return handle

    def fstat(descriptor):
        nonlocal calls
        calls += 1
        info = original_stat(descriptor)
        changed = (stage == "opened" and calls == 1) or (stage == "finished-handle" and calls == 2)
        if stage == "identity" or changed:
            return SimpleNamespace(
                st_dev=info.st_dev,
                st_ino=0 if stage == "identity" else info.st_ino + 1,
                st_size=info.st_size,
                st_mtime_ns=info.st_mtime_ns,
                st_mode=info.st_mode,
            )
        if stage == "finished-path" and calls == 2:
            os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns + 1000000000))
        return info

    monkeypatch.setattr(Path, "open", open_handle)
    monkeypatch.setattr(module.os, "fstat", fstat)
    with pytest.raises((module.InputFormatError, module.ValidationError)):
        module._read(path, 100)
    assert len(opened) == 1 and opened[0].closed


@pytest.mark.parametrize("mode", ["bytearray", "none", "text", "oversized-block", "growing"])
def test_invalid_or_unbounded_read_blocks_are_rejected(tmp_path, monkeypatch, mode):
    path = tmp_path / "input.json"
    path.write_bytes(b"{}")
    original_open = Path.open
    owned = []

    class InvalidReader:
        def __init__(self, handle):
            self.handle = handle

        def fileno(self):
            return self.handle.fileno()

        def read(self, size):
            return {
                "bytearray": bytearray(b"{}"),
                "none": None,
                "text": "{}",
                "oversized-block": b"x" * (size + 1),
                "growing": b"x" * size,
            }[mode]

        def close(self):
            self.handle.close()

    def open_handle(target, *args, **kwargs):
        handle = original_open(target, *args, **kwargs)
        owned.append(handle)
        return InvalidReader(handle)

    monkeypatch.setattr(Path, "open", open_handle)
    with pytest.raises(module.InputFormatError):
        module._read(path, 10)
    assert owned[0].closed


@pytest.mark.parametrize("primary_type", [None, OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("cleanup_type", [None, OSError, KeyboardInterrupt, SystemExit])
def test_owned_input_cleanup_preserves_control_priority_and_identity(
    tmp_path, monkeypatch, primary_type, cleanup_type
):
    path = tmp_path / "input.json"
    path.write_bytes(b"{}")
    primary = None if primary_type is None else primary_type("PRIVATE read")
    cleanup = None if cleanup_type is None else cleanup_type("PRIVATE close")
    original_open = Path.open
    owned = []

    class FaultReader:
        def __init__(self, handle):
            self.handle = handle

        def fileno(self):
            return self.handle.fileno()

        def read(self, size):
            if primary is not None:
                raise primary
            return self.handle.read(size)

        def close(self):
            self.handle.close()
            if cleanup is not None:
                raise cleanup

    def open_handle(target, *args, **kwargs):
        handle = original_open(target, *args, **kwargs)
        owned.append(handle)
        return FaultReader(handle)

    expected = primary
    if primary is None or (
        isinstance(primary, Exception)
        and cleanup is not None
        and not isinstance(cleanup, Exception)
    ):
        expected = cleanup
    monkeypatch.setattr(Path, "open", open_handle)
    if expected is None:
        assert module._read(path, 100) == b"{}"
    else:
        with pytest.raises(type(expected)) as caught:
            module._read(path, 100)
        assert caught.value is expected
    assert len(owned) == 1 and owned[0].closed


def test_late_batch_authorization_failure_changes_no_sql_table(tmp_path, capsys):
    store = create(tmp_path / "workflow.db")
    before = store.snapshot().checkpoint
    values = [command(), command("two", actor_id="reviewer")]
    fields = request_files(tmp_path, before)
    write_json(
        tmp_path / "commands.json",
        {
            "schema_version": "1.0",
            "transitions": [value.to_dict() for value in values],
        },
    )
    digest = store.request_digest(values, request_id="one", expected=before)
    previous = audit(store.path)
    raw = store.path.read_bytes()
    assert run(arguments(tmp_path, "append", *fields, "--expected-request-digest", digest)) == 2
    assert json.loads(capsys.readouterr().err)["outcome"] == "none"
    assert audit(store.path) == previous and store.path.read_bytes() == raw


def test_held_sqlite_writer_lock_obeys_zero_busy_timeout_without_partial_append(tmp_path, capsys):
    argv, digest = prepared(tmp_path, "append")
    path = tmp_path / "workflow.db"
    previous = path.read_bytes()
    writer = sqlite3.connect(path)
    try:
        writer.execute("BEGIN IMMEDIATE")
        assert run([*argv, "--timeout", "0"]) == 2
    finally:
        writer.rollback()
        writer.close()
    diagnostic = json.loads(capsys.readouterr().err)
    assert diagnostic["outcome"] == "none" and diagnostic["code"] == "storage"
    assert path.read_bytes() == previous
    assert reopen(path).lookup("one", expected_request_digest=digest) is None


@pytest.mark.parametrize("value", [None, {}, {"a": "é"}, [1, True, "😀"]])
def test_report_byte_limit_counts_utf8_and_required_lf(monkeypatch, value):
    raw = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n"
    monkeypatch.setattr(module, "_MAX_REPORT", len(raw.encode("utf-8")))
    assert module._report(value) == raw
    monkeypatch.setattr(module, "_MAX_REPORT", len(raw.encode("utf-8")) - 1)
    with pytest.raises(module._DeliveryError):
        module._report(value)


def test_private_parser_exit_and_empty_message_do_not_echo_untrusted_prose():
    parser, output = module._parser(), io.StringIO()
    parser._print_message("", output)
    assert output.getvalue() == ""
    with pytest.raises(module._Arguments, match=r"^invalid workflow-store arguments$"):
        parser.exit(2, "PRIVATE")


def test_private_request_execution_defends_missing_anchor_even_after_parser(tmp_path):
    argv, _ = prepared(tmp_path, "append")
    parsed = module._parser().parse_args(argv[1:])
    parsed.expected_checkpoint = None
    original = (tmp_path / "workflow.db").read_bytes()
    with pytest.raises(module.ValidationError, match="explicit checkpoint"):
        module._execute(parsed, module._Operation())
    assert (tmp_path / "workflow.db").read_bytes() == original
