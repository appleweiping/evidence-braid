"""Real durable commits followed by interrupted acknowledgement and result delivery."""

import io
import json
from types import SimpleNamespace

import pytest

from evidence_braid import SQLiteWorkflowStore, WorkflowStorageError
from evidence_braid import workflow_store_cli as module
from evidence_braid.cli import run
from tests.test_workflow_storage import command, create, initial, reopen
from tests.test_workflow_store_cli import arguments, request_files, write_json


def prepared(tmp_path, operation):
    if operation == "create":
        bundle = initial()
        source = write_json(tmp_path / "initial.json", bundle.to_dict())
        return arguments(
            tmp_path, operation, "--bundle", source, "--expected-head", bundle.head_digest
        ), None
    store = create(tmp_path / "workflow.db")
    before = store.snapshot().checkpoint
    fields = request_files(tmp_path, before)
    digest = store.request_digest([command()], request_id="one", expected=before)
    return arguments(tmp_path, operation, *fields, "--expected-request-digest", digest), digest


class Output:
    def __init__(self, failure, *, binary=False):
        self.failure = failure
        self.content = b"" if binary else ""
        self.flushes = 0

    def write(self, text):
        if self.failure == "write":
            raise OSError("PRIVATE write fault")
        if self.failure == "short":
            self.content += text[:3]
            return 3
        self.content += text
        if self.failure == "none":
            return None
        if self.failure == "bool":
            return True
        if self.failure == "over":
            return len(text) + 1
        if isinstance(self.failure, BaseException):
            raise self.failure
        return len(text)

    def flush(self):
        self.flushes += 1
        if self.failure == "flush":
            raise OSError("PRIVATE flush fault")


@pytest.mark.parametrize("operation", ["create", "append"])
@pytest.mark.parametrize("failure", ["write", "short", "none", "bool", "over", "flush"])
@pytest.mark.parametrize("binary", [False, True])
def test_output_failure_after_acknowledged_mutation_preserves_complete_database(
    tmp_path, monkeypatch, operation, failure, binary
):
    argv, digest = prepared(tmp_path, operation)
    output, errors = Output(failure, binary=binary), io.StringIO()
    with monkeypatch.context() as patch:
        patch.setattr(module.sys, "stdout", SimpleNamespace(buffer=output) if binary else output)
        patch.setattr(module.sys, "stderr", errors)
        assert run(argv) == 2
    diagnostic = json.loads(errors.getvalue())
    assert diagnostic == {
        "error": "workflow-store command did not complete",
        "code": "delivery",
        "outcome": "complete",
        "request_id": "one" if digest else None,
        "request_digest": digest,
    }
    store = reopen(tmp_path / "workflow.db")
    assert store.snapshot().checkpoint.record_count == (operation == "append")
    if digest:
        assert store.lookup("one", expected_request_digest=digest).result == store.snapshot()
    assert output.flushes == (failure == "flush")


@pytest.mark.parametrize("operation", ["create", "append"])
@pytest.mark.parametrize("when", ["before", "after", "close"])
def test_actual_core_acknowledgement_faults_have_truthful_outcomes(
    tmp_path, monkeypatch, capsys, operation, when
):
    argv, digest = prepared(tmp_path, operation)

    def commit(connection):
        if when != "before":
            connection.commit()
        if when != "close":
            raise OSError("PRIVATE lost acknowledgement")

    def close(connection):
        connection.close()
        if when == "close":
            raise OSError("PRIVATE lost close acknowledgement")

    with monkeypatch.context() as patch:
        patch.setattr(SQLiteWorkflowStore, "_commit", staticmethod(commit))
        # Do not fail the constructor's earlier read-only close.
        if when == "close":
            original_append, original_create = SQLiteWorkflowStore.append, module._create

            def append(self, *args, **kwargs):
                patch.setattr(self, "_close", close)
                return original_append(self, *args, **kwargs)

            def create_with_fault(*args, **kwargs):
                patch.setattr(SQLiteWorkflowStore, "_close", staticmethod(close))
                return original_create(*args, **kwargs)

            patch.setattr(SQLiteWorkflowStore, "append", append)
            patch.setattr(module, "_create", create_with_fault)
        assert run(argv) == 2
    diagnostic = json.loads(capsys.readouterr().err)
    assert diagnostic["outcome"] == ("complete" if when == "close" else "unknown")
    assert diagnostic["code"] == "storage"
    assert diagnostic["request_digest"] == digest
    assert "PRIVATE" not in json.dumps(diagnostic)
    path = tmp_path / "workflow.db"
    assert path.exists()  # Even uncertain, uncommitted creation is retained.
    if operation == "append" or when != "before":
        store = reopen(path)
        assert store.snapshot().checkpoint.record_count == (
            operation == "append" and when != "before"
        )
        if digest:
            assert (store.lookup("one", expected_request_digest=digest) is not None) == (
                when != "before"
            )


@pytest.mark.parametrize("operation", ["create", "append"])
@pytest.mark.parametrize("control_type", [KeyboardInterrupt, SystemExit])
def test_control_during_commit_never_claims_no_mutation(
    tmp_path, monkeypatch, operation, control_type
):
    argv, _ = prepared(tmp_path, operation)
    control = control_type("PRIVATE interrupt")

    def commit(connection):
        connection.commit()
        raise control

    with monkeypatch.context() as patch:
        patch.setattr(SQLiteWorkflowStore, "_commit", staticmethod(commit))
        with pytest.raises(control_type) as caught:
            run(argv)
    assert caught.value is control
    cli_notes = [note for note in control.__notes__ if note.startswith("workflow-store")]
    assert cli_notes and all("outcome=unknown" in note for note in cli_notes)
    assert reopen(tmp_path / "workflow.db").snapshot().checkpoint.record_count == (
        operation == "append"
    )


@pytest.mark.parametrize("error", [OSError("PRIVATE snapshot"), WorkflowStorageError("none")])
def test_creation_followup_read_failure_cannot_downgrade_acknowledged_creation(
    tmp_path, monkeypatch, capsys, error
):
    argv, _ = prepared(tmp_path, "create")

    def fail_snapshot(self, **kwargs):
        raise error

    with monkeypatch.context() as patch:
        patch.setattr(SQLiteWorkflowStore, "snapshot", fail_snapshot)
        assert run(argv) == 2
    assert json.loads(capsys.readouterr().err)["outcome"] == "complete"
    assert reopen(tmp_path / "workflow.db").snapshot().bundle == initial()


@pytest.mark.parametrize("operation", ["create", "append"])
@pytest.mark.parametrize("control_type", [KeyboardInterrupt, SystemExit])
def test_output_control_after_commit_retains_identity_and_complete_note(
    tmp_path, monkeypatch, operation, control_type
):
    argv, _ = prepared(tmp_path, operation)
    control = control_type("PRIVATE output")
    with monkeypatch.context() as patch:
        patch.setattr(module.sys, "stdout", Output(control))
        with pytest.raises(control_type) as caught:
            run(argv)
    assert caught.value is control
    assert any("workflow-store outcome=complete" in note for note in control.__notes__)
    assert reopen(tmp_path / "workflow.db").snapshot().checkpoint.record_count == (
        operation == "append"
    )


@pytest.mark.parametrize("found", [False, True])
@pytest.mark.parametrize("binary", [False, True])
def test_lookup_delivery_failure_preserves_found_or_absent_request_acknowledgement(
    tmp_path, monkeypatch, found, binary
):
    store = create(tmp_path / "workflow.db")
    checkpoint = store.snapshot().checkpoint
    digest = store.request_digest([command()], request_id="one", expected=checkpoint)
    store.append([command()], request_id="one", expected=checkpoint)
    original = store.path.read_bytes()
    identifier = "one" if found else "absent"
    argv = arguments(
        tmp_path, "lookup", "--request-id", identifier, "--expected-request-digest", digest
    )
    output, errors = Output("flush", binary=binary), io.StringIO()
    with monkeypatch.context() as patch:
        patch.setattr(module.sys, "stdout", SimpleNamespace(buffer=output) if binary else output)
        patch.setattr(module.sys, "stderr", errors)
        assert run(argv) == 2
    diagnostic = json.loads(errors.getvalue())
    assert diagnostic["outcome"] == ("complete" if found else "none")
    assert (diagnostic["request_id"], diagnostic["request_digest"]) == (identifier, digest)
    assert store.path.read_bytes() == original


@pytest.mark.parametrize("found", [False, True])
@pytest.mark.parametrize("control_type", [KeyboardInterrupt, SystemExit])
def test_unreturned_lookup_control_has_unknown_outer_ack_without_writing(
    tmp_path, monkeypatch, found, control_type
):
    store = create(tmp_path / "workflow.db")
    checkpoint = store.snapshot().checkpoint
    digest = store.request_digest([command()], request_id="one", expected=checkpoint)
    store.append([command()], request_id="one", expected=checkpoint)
    original = store.path.read_bytes()
    control = control_type("PRIVATE lookup close")
    original_lookup = SQLiteWorkflowStore.lookup

    def lookup(self, *args, **kwargs):
        def close(connection):
            connection.close()
            raise control

        monkeypatch.setattr(self, "_close", close)
        return original_lookup(self, *args, **kwargs)

    monkeypatch.setattr(SQLiteWorkflowStore, "lookup", lookup)
    with pytest.raises(control_type) as caught:
        run(
            arguments(
                tmp_path,
                "lookup",
                "--request-id",
                "one" if found else "absent",
                "--expected-request-digest",
                digest,
            )
        )
    assert caught.value is control and store.path.read_bytes() == original
    assert any(
        note.startswith(f"workflow commit outcome={'complete' if found else 'none'}")
        for note in control.__notes__
    )
    assert any(note.startswith("workflow-store outcome=unknown") for note in control.__notes__)
