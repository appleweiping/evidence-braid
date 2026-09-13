"""Actual command integration and durable mutation/delivery boundary tests."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from evidence_braid import WorkflowCheckpoint
from evidence_braid import workflow_store_cli as module
from evidence_braid.cli import run
from tests.test_workflow_storage import authority, command, create, initial, reopen


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
    return path


def arguments(tmp_path, operation, *extra):
    policy = write_json(tmp_path / "authority.json", authority().to_dict())
    return [
        "workflow-store",
        operation,
        str(tmp_path / "workflow.db"),
        "--authority",
        str(policy),
        "--expected-context",
        initial().context_digest,
        *map(str, extra),
    ]


def request_files(tmp_path, checkpoint, *, identifier="one"):
    expected = write_json(tmp_path / "checkpoint.json", checkpoint.to_dict())
    commands = write_json(
        tmp_path / "commands.json",
        {
            "schema_version": "1.0",
            "transitions": [command(identifier).to_dict()],
        },
    )
    return ["--commands", commands, "--request-id", identifier, "--expected-checkpoint", expected]


def invoke(tmp_path, argv):
    process = subprocess.run(
        [sys.executable, "-I", "-B", "-m", "evidence_braid", *map(str, argv)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert process.returncode == 0, process.stderr
    assert not process.stderr
    assert process.stdout.endswith("\n") and not process.stdout.endswith("\n\n")
    return json.loads(process.stdout)


def test_workflow_store_help_is_a_real_isolated_command(tmp_path):
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-m", "evidence_braid", "workflow-store", "--help"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert all(name in result.stdout for name in ("create", "snapshot", "append", "lookup"))


def test_real_isolated_command_lifecycle_retry_lookup_and_portable_export(tmp_path):
    bundle = initial()
    source = write_json(tmp_path / "initial.json", bundle.to_dict())
    created = invoke(
        tmp_path,
        arguments(
            tmp_path,
            "create",
            "--bundle",
            source,
            "--expected-head",
            bundle.head_digest,
        ),
    )
    assert created == reopen(tmp_path / "workflow.db").snapshot().to_dict()
    before = WorkflowCheckpoint.from_dict(created["checkpoint"])
    fields = request_files(tmp_path, before)
    identity = invoke(tmp_path, arguments(tmp_path, "request-digest", *fields))
    expected_digest = reopen(tmp_path / "workflow.db").request_digest(
        [command()],
        request_id="one",
        expected=before,
    )
    assert identity == {
        "request_id": "one",
        "request_digest": expected_digest,
        "expected_checkpoint": before.to_dict(),
    }
    append_args = arguments(
        tmp_path,
        "append",
        *fields,
        "--expected-request-digest",
        expected_digest,
    )
    committed = invoke(tmp_path, append_args)
    store = reopen(tmp_path / "workflow.db")
    later = store.append([command("two")], request_id="two", expected=store.snapshot().checkpoint)
    assert invoke(tmp_path, append_args) == committed
    assert (
        invoke(
            tmp_path,
            arguments(
                tmp_path,
                "lookup",
                "--request-id",
                "one",
                "--expected-request-digest",
                expected_digest,
            ),
        )
        == committed
    )
    assert (
        invoke(
            tmp_path,
            arguments(
                tmp_path,
                "lookup",
                "--request-id",
                "absent",
                "--expected-request-digest",
                "0" * 64,
            ),
        )
        is None
    )
    assert invoke(tmp_path, arguments(tmp_path, "snapshot")) == later.result.to_dict()
    assert invoke(tmp_path, arguments(tmp_path, "export")) == later.result.bundle.to_dict()
    assert reopen(tmp_path / "workflow.db").snapshot() == later.result


@pytest.mark.parametrize(
    "extra",
    [
        ["--unexpected-secret", "private-token"],
        ["--auth", "secret.json"],
        ["--timeout", "nan"],
        ["--timeout", "inf"],
        ["--timeout", "-1"],
        ["--timeout", "60.1"],
        ["--expected-context", "PRIVATE_SECRET"],
    ],
)
def test_bad_arguments_are_private_and_never_create_database(tmp_path, capsys, extra):
    assert run(arguments(tmp_path, "snapshot", *extra)) == 2
    captured = capsys.readouterr()
    assert not captured.out and "private" not in captured.err.lower()
    assert "secret" not in captured.err.lower()
    assert json.loads(captured.err)["outcome"] == "none"
    assert not (tmp_path / "workflow.db").exists()


@pytest.mark.parametrize("kind", ["digest", "stale", "commands", "authority", "context"])
def test_invalid_intent_preserves_all_existing_database_state(tmp_path, capsys, kind):
    store = create(tmp_path / "workflow.db")
    before = store.snapshot().checkpoint
    fields = request_files(tmp_path, before)
    digest = store.request_digest([command()], request_id="one", expected=before)
    argv = arguments(tmp_path, "append", *fields, "--expected-request-digest", digest)
    if kind == "digest":
        argv[-1] = "0" * 64
    elif kind == "stale":
        store.append([command("other")], request_id="other", expected=before)
    elif kind == "commands":
        (tmp_path / "commands.json").write_text(
            '{"secret":"SENSITIVE", "secret":0}', encoding="utf-8"
        )
    elif kind == "authority":
        write_json(tmp_path / "authority.json", {"SECRET": "SENSITIVE"})
    else:
        argv[argv.index("--expected-context") + 1] = "0" * 64
    original = (tmp_path / "workflow.db").read_bytes()
    assert run(argv) == 2
    captured = capsys.readouterr()
    assert not captured.out and "SENSITIVE" not in captured.err
    assert (tmp_path / "workflow.db").read_bytes() == original


def test_short_file_eof_cannot_accept_only_a_valid_prefix(tmp_path, monkeypatch):
    source = tmp_path / "truncated.json"
    source.write_bytes(b"{}" + b" " * 30)
    original_open = Path.open

    class PrefixOnly:
        def __init__(self, handle):
            self.handle = handle

        def read(self, size):
            return self.handle.read(2) if self.handle.tell() == 0 else b""

        def fileno(self):
            return self.handle.fileno()

        def close(self):
            self.handle.close()

    monkeypatch.setattr(
        Path, "open", lambda path, *a, **k: PrefixOnly(original_open(path, *a, **k))
    )
    with pytest.raises(module.InputFormatError):
        module._json_file(source, 100)


def test_in_process_commands_bind_exact_checkpoints_and_recover_later_history(tmp_path, capsys):
    store = create(tmp_path / "workflow.db")
    before = store.snapshot().checkpoint
    fields = request_files(tmp_path, before)

    def success(*args):
        assert run(arguments(tmp_path, *args)) == 0
        captured = capsys.readouterr()
        assert not captured.err
        value = json.loads(captured.out)
        assert captured.out == module._report(value)
        return value

    digest = success("request-digest", *fields)["request_digest"]
    committed = success("append", *fields, "--expected-request-digest", digest)
    later = store.append([command("two")], request_id="two", expected=store.snapshot().checkpoint)
    assert success("append", *fields, "--expected-request-digest", digest) == committed
    for identifier, expected in [("one", committed), ("absent", None)]:
        assert (
            success("lookup", "--request-id", identifier, "--expected-request-digest", digest)
            == expected
        )
    checkpoint = write_json(tmp_path / "current.json", later.result.checkpoint.to_dict())
    assert success("snapshot", "--expected-checkpoint", checkpoint) == later.result.to_dict()
    assert success("export", "--expected-checkpoint", checkpoint) == later.result.bundle.to_dict()
    assert (
        run(arguments(tmp_path, "snapshot", "--expected-checkpoint", tmp_path / "checkpoint.json"))
        == 2
    )
    assert json.loads(capsys.readouterr().err)["code"] == "conflict"
    assert store.snapshot() == later.result


@pytest.mark.parametrize("utf8_mode", [[], ["-X", "utf8=0"]], ids=["default", "utf8-disabled"])
def test_redirected_subprocess_export_preserves_exact_utf8_bytes_and_lf(tmp_path, utf8_mode):
    bundle = initial().append([command(statement="Café 漢字 🎞")], authority=authority())
    create(tmp_path / "workflow.db", bundle)
    process = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            *utf8_mode,
            "-m",
            "evidence_braid",
            *arguments(tmp_path, "export"),
        ],
        cwd=tmp_path,
        capture_output=True,
        timeout=30,
        check=False,
    )
    expected = (
        json.dumps(
            bundle.to_dict(),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    assert process.returncode == 0 and not process.stderr
    assert process.stdout == expected and not process.stdout.endswith(b"\r\n")


@pytest.mark.parametrize("optimized", [False, True])
def test_actual_subprocess_example_runs_checks_even_when_optimized(tmp_path, optimized):
    example = Path(__file__).resolve().parents[1] / "examples" / "workflow_store_cli.py"
    process = subprocess.run(
        [sys.executable, "-I", "-B", *(["-O"] if optimized else []), str(example)],
        cwd=tmp_path,
        capture_output=True,
        check=False,
        timeout=60,
    )
    assert process.returncode == 0, process.stderr
    assert not process.stderr
    assert json.loads(process.stdout) == {
        "commands": ["create", "snapshot", "export", "request-digest", "append", "lookup"],
        "record_count": 2,
        "operation_count": 2,
        "historical_retry_equal": True,
        "portable_export_equal": True,
        "actor_authentication_provided": False,
    }
