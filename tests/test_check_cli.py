"""Real offline files/process integration with explicit command exit semantics."""

import json
import subprocess
import sys
from pathlib import Path

import pytest
from test_check_workflow import case, policy_for

from evidence_braid import CheckLimits
from evidence_braid.cli import _check_contents, _check_file, run
from evidence_braid.errors import InputFormatError
from evidence_braid.io import canonical_json
from evidence_braid.workflow import write_workflow_bundle


def files(tmp_path, raw=b'{"ok":true}'):
    bundle, trusted, plan, _, contents = case(raw)
    mappings = []
    for name, value in contents.items():
        path = tmp_path / f"{name}.json"
        path.write_bytes(value)
        mappings.extend(["--artifact", f"{name}={path}"])
    (tmp_path / "authority.json").write_text(canonical_json(trusted.to_dict()))
    (tmp_path / "policy.json").write_bytes(policy_for(plan).to_bytes())
    write_workflow_bundle(tmp_path / "workflow.json", bundle, authority=trusted)
    gate = [
        "checks",
        "gate",
        str(tmp_path / "authority.json"),
        str(tmp_path / "workflow.json"),
        str(tmp_path / "policy.json"),
        "--expected-head",
        bundle.head_digest,
        "--expected-evidence-head",
        bundle.evidence.head_digest,
        *mappings,
    ]
    evaluate = [
        "checks",
        "evaluate",
        str(tmp_path / "plan.json"),
        "--expected-plan-digest",
        plan.digest,
        "--artifact",
        f"analysis={tmp_path / 'analysis.json'}",
    ]
    return gate, evaluate


@pytest.mark.parametrize(
    "raw,exit_code,outcome",
    [
        (b'{"ok":true}', 0, "pass"),
        (b'{"ok":false}', 1, "fail"),
        (b"{}", 1, "unknown"),
    ],
)
def test_cli_evaluate_and_gate_report_real_semantics(tmp_path, capsys, raw, exit_code, outcome):
    gate, evaluate = files(tmp_path, raw)
    assert run(evaluate) == exit_code
    captured = capsys.readouterr()
    assert json.loads(captured.out)["outcome"] == outcome
    assert captured.err == ""
    assert run(gate) == exit_code
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["evaluation"]["outcome"] == outcome
    assert report["accepted"] is (exit_code == 0)
    assert captured.err == ""


def test_cli_external_pin_and_malformed_metadata_use_exit_two_without_echo(tmp_path, capsys):
    gate, evaluate = files(tmp_path)
    evaluate[evaluate.index("--expected-plan-digest") + 1] = "a" * 64
    assert run(evaluate) == 2
    assert capsys.readouterr().out == ""
    secret = "do-not-echo-retained-secret"
    (tmp_path / "authority.json").write_text('{"' + secret + '":0,"' + secret + '":1}')
    assert run(gate) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert secret not in captured.err
    assert "checks rejected" in captured.err


@pytest.mark.parametrize("mappings", [["a"], ["=file"], ["a="], ["a=x", "a=y"], ["x=file"] * 19])
def test_cli_mapping_admission_before_file_reads(mappings):
    with pytest.raises(InputFormatError):
        _check_contents(mappings, CheckLimits(), extra=2)


def test_cli_local_regular_file_and_aggregate_byte_admission(tmp_path):
    with pytest.raises(InputFormatError):
        _check_file(tmp_path, 10)
    with pytest.raises(InputFormatError):
        _check_file(tmp_path / "absent", 10)
    with pytest.raises(InputFormatError):
        _check_file(Path("//server/share/file"), 10)
    first, second = tmp_path / "first", tmp_path / "second"
    first.write_bytes(b"123")
    second.write_bytes(b"456")
    with pytest.raises(InputFormatError):
        _check_contents(
            [f"a={first}", f"b={second}"], CheckLimits(max_total_input_bytes=5), extra=0
        )
    assert _check_contents(
        [f"a={first}", f"b={second}"], CheckLimits(max_total_input_bytes=6), extra=0
    ) == {
        "a": b"123",
        "b": b"456",
    }


def test_real_new_process_offline_example_and_cli_gate(tmp_path):
    directory = tmp_path / "demo"
    script = Path(__file__).parents[1] / "examples" / "offline_claim_checks.py"
    completed = subprocess.run(
        [sys.executable, str(script), str(directory)],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    report = json.loads(completed.stdout)
    assert report["accepted"] is True
    assert (directory / "artifacts.zip").is_file()
    arguments = [
        sys.executable,
        "-m",
        "evidence_braid",
        "checks",
        "gate",
        str(directory / "authority.json"),
        str(directory / "workflow.json"),
        str(directory / "check-policy.json"),
        "--expected-head",
        report["workflow_head"],
        "--expected-evidence-head",
        report["evidence_head"],
    ]
    for name in ("analysis", "expected", "plan", "evaluation"):
        arguments.extend(["--artifact", f"{name}={directory / (name + '.json')}"])
    repeated = subprocess.run(arguments, check=True, capture_output=True, text=True, timeout=30)
    assert json.loads(repeated.stdout) == report
