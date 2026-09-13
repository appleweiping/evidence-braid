from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import sqlite3
from contextlib import closing
from dataclasses import FrozenInstanceError, replace
from types import SimpleNamespace

import pytest

import evidence_braid
from evidence_braid import (
    ActorKind,
    AuthorityPolicy,
    AuthorityRole,
    EvidenceLedger,
    LedgerEntry,
    ScopeGrant,
    SQLiteWorkflowStore,
    StoredWorkflow,
    ValidationError,
    WorkflowActor,
    WorkflowBundle,
    WorkflowCheckpoint,
    WorkflowCommit,
    WorkflowConflictError,
    WorkflowStorageError,
    WorkflowStoreLimits,
    WorkflowTransition,
    build_ledger,
    build_workflow,
    create_workflow_store,
    replay_workflow,
)
from tests import test_workflow as workflow_cases


@pytest.mark.parametrize(
    "name",
    [
        "WorkflowStoreLimits",
        "WorkflowCheckpoint",
        "StoredWorkflow",
        "WorkflowCommit",
        "WorkflowConflictError",
        "WorkflowStorageError",
        "SQLiteWorkflowStore",
        "create_workflow_store",
    ],
)
def test_public_durable_workflow_api_exists(name):
    assert hasattr(evidence_braid, name)
    assert name in evidence_braid.__all__


def authority():
    return AuthorityPolicy(
        "runtime-v1",
        (
            WorkflowActor(
                "author", ActorKind.HUMAN, (ScopeGrant("scope/a", AuthorityRole.AUTHOR),)
            ),
            WorkflowActor(
                "reviewer", ActorKind.HUMAN, (ScopeGrant("scope/a", AuthorityRole.REVIEWER),)
            ),
        ),
    )


def initial():
    return build_workflow("workflow-one", authority=authority(), evidence=build_ledger([]))


def command(identifier="one", **changes):
    return WorkflowTransition.from_dict(
        {
            "transition_id": identifier,
            "action": "create",
            "actor_id": "author",
            "scope": "scope/a",
            "claim_id": "claim-" + identifier,
            "expected_revision": 0,
            "statement": "A bounded procedural claim.",
            "reference_id": None,
            "reference_digest": None,
            "reason": None,
            **changes,
        }
    )


def create(path, bundle=None, **options):
    bundle = initial() if bundle is None else bundle
    return create_workflow_store(
        path,
        bundle,
        authority=authority(),
        expected_context=bundle.context_digest,
        expected_head=bundle.head_digest,
        **options,
    )


def reopen(path, **options):
    return SQLiteWorkflowStore(
        path, authority=authority(), expected_context=initial().context_digest, **options
    )


def canonical(value):
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, allow_nan=False, separators=(",", ":")
    ).encode("utf-8")


def audit(path):
    """Independent direct-SQL canonical hash/range audit, no product store internals."""
    with closing(sqlite3.connect(path)) as connection:
        context = json.loads(
            connection.execute("SELECT document FROM workflow_context").fetchone()[0]
        )
        receipts = [
            json.loads(r[0])
            for r in connection.execute("SELECT document FROM workflow_receipts ORDER BY sequence")
        ]
        operations = [
            json.loads(r[0])
            for r in connection.execute(
                "SELECT document FROM workflow_operations ORDER BY sequence"
            )
        ]
        actual = json.loads(connection.execute("SELECT document FROM workflow_meta").fetchone()[0])
    head = context["context_digest"]
    for index, receipt in enumerate(receipts):
        body = {key: value for key, value in receipt.items() if key != "digest"}
        assert receipt["sequence"] == index and receipt["previous_digest"] == head
        head = hashlib.sha256(canonical(body)).hexdigest()
        assert receipt["digest"] == head
    genesis = {
        "kind": "evidence-braid-workflow-operation-genesis",
        "schema_version": "1.0",
        "context_digest": context["context_digest"],
        "initial_record_count": context["initial_record_count"],
        "initial_workflow_head": context["initial_workflow_head"],
    }
    count = context["initial_record_count"]
    previous = {
        "schema_version": "1.0",
        "context_digest": context["context_digest"],
        "record_count": count,
        "workflow_head": context["initial_workflow_head"],
        "operation_count": 0,
        "operation_head": hashlib.sha256(canonical(genesis)).hexdigest(),
    }
    for index, operation in enumerate(operations):
        assert operation["expected_checkpoint"] == previous
        assert operation["previous_digest"] == previous["operation_head"]
        assert operation["sequence"] == index
        end = operation["result_record_count"]
        request = {
            "kind": "evidence-braid-workflow-request",
            "schema_version": "1.0",
            "request_id": operation["request_id"],
            "expected_checkpoint": previous,
            "transitions": [r["transition"] for r in receipts[count:end]],
        }
        assert hashlib.sha256(canonical(request)).hexdigest() == operation["request_digest"]
        body = {key: value for key, value in operation.items() if key != "digest"}
        assert hashlib.sha256(canonical(body)).hexdigest() == operation["digest"]
        count = end
        previous = {
            **previous,
            "record_count": count,
            "workflow_head": receipts[count - 1]["digest"],
            "operation_count": index + 1,
            "operation_head": operation["digest"],
        }
    assert previous == actual and count == len(receipts)
    return context, receipts, operations, actual


def test_real_create_append_reopen_and_independent_audit(tmp_path):
    path = tmp_path / "workflow.db"
    store = create(path)
    before = store.snapshot()
    commands = (command(), command("two"))
    digest = store.request_digest(commands, request_id="r1", expected=before.checkpoint)
    commit = store.append(commands, request_id="r1", expected=before.checkpoint)
    assert digest == commit.request_digest
    assert commit.result.bundle == before.bundle.append(commands, authority=authority())
    assert len(replay_workflow(commit.result.bundle, authority=authority()).claims) == 2
    assert reopen(path, expected=commit.result.checkpoint).snapshot() == commit.result
    assert store.lookup("r1", expected_request_digest=digest) == commit
    assert store.lookup("absent", expected_request_digest="0" * 64) is None
    audit(path)


def test_identical_retry_after_later_append_returns_exact_historical_prefix(tmp_path):
    store = create(tmp_path / "workflow.db")
    before = store.snapshot()
    first = store.append([command()], request_id="r1", expected=before.checkpoint)
    last = store.append([command("two")], request_id="r2", expected=first.result.checkpoint)
    assert store.append([command()], request_id="r1", expected=before.checkpoint) == first
    assert store.lookup("r1", expected_request_digest=first.request_digest) == first
    assert store.snapshot() == last.result
    with pytest.raises(WorkflowConflictError):
        store.snapshot(expected=first.result.checkpoint)
    with pytest.raises(WorkflowConflictError):
        reopen(store.path, expected=first.result.checkpoint)
    audit(store.path)


def test_conflicting_id_input_and_stale_checkpoint_do_not_mutate(tmp_path):
    store = create(tmp_path / "workflow.db")
    before = store.snapshot()
    first = store.append([command()], request_id="r1", expected=before.checkpoint)
    for commands, identifier, expected in (
        ([command("two")], "r1", before.checkpoint),
        ([command()], "r1", first.result.checkpoint),
        ([command("two")], "r2", before.checkpoint),
    ):
        with pytest.raises(WorkflowConflictError):
            store.append(commands, request_id=identifier, expected=expected)
    with pytest.raises(WorkflowConflictError):
        store.lookup("r1", expected_request_digest="a" * 64)
    assert store.snapshot() == first.result
    assert len(audit(store.path)[2]) == 1


def test_nonempty_imported_prefix_has_explicit_journal_genesis(tmp_path):
    bundle = initial().append([command()], authority=authority())
    store = create(tmp_path / "workflow.db", bundle)
    before = store.snapshot()
    assert before.checkpoint.record_count == 1 and before.checkpoint.operation_count == 0
    result = store.append([command("two")], request_id="r2", expected=before.checkpoint)
    context, _, operations, _ = audit(store.path)
    assert context["initial_workflow_head"] == bundle.head_digest
    assert context["initial_record_count"] == 1 and len(operations) == 1
    assert result.previous == before.checkpoint


def test_late_batch_denial_leaves_all_tables_unchanged(tmp_path):
    store = create(tmp_path / "workflow.db")
    before = store.snapshot()
    prior = audit(store.path)
    with pytest.raises(ValidationError, match="scoped role"):
        store.append(
            [command(), command("two", actor_id="reviewer")],
            request_id="denied",
            expected=before.checkpoint,
        )
    assert audit(store.path) == prior and store.snapshot() == before


def test_commit_then_lost_ack_is_recoverable_with_precomputed_digest(tmp_path, monkeypatch):
    store = create(tmp_path / "workflow.db")
    before = store.snapshot()
    digest = store.request_digest([command()], request_id="r1", expected=before.checkpoint)

    def commit_then_fail(connection):
        connection.commit()
        raise OSError("lost acknowledgement")

    monkeypatch.setattr(store, "_commit", commit_then_fail)
    with pytest.raises(WorkflowStorageError) as caught:
        store.append([command()], request_id="r1", expected=before.checkpoint)
    assert caught.value.outcome == "unknown"
    assert caught.value.request_digest == digest
    recovered = reopen(store.path).lookup("r1", expected_request_digest=digest)
    assert recovered.result.checkpoint.record_count == 1
    assert store.append([command()], request_id="r1", expected=before.checkpoint) == recovered
    audit(store.path)


def test_close_failure_after_commit_reports_complete(tmp_path, monkeypatch):
    store = create(tmp_path / "workflow.db")
    before = store.snapshot()

    def close_then_fail(connection):
        connection.close()
        raise OSError("lost close acknowledgement")

    monkeypatch.setattr(store, "_close", close_then_fail)
    with pytest.raises(WorkflowStorageError) as caught:
        store.append([command()], request_id="r1", expected=before.checkpoint)
    assert caught.value.outcome == "complete"
    assert reopen(store.path).lookup("r1", expected_request_digest=caught.value.request_digest)
    audit(store.path)


def append_worker(path, checkpoint, identifier, request_id, barrier, queue):
    """Top-level target: spawn, including on Windows, with independent connections."""
    try:
        store = reopen(path)
        barrier.wait(timeout=15)
        result = store.append(
            [command(identifier)],
            request_id=request_id,
            expected=WorkflowCheckpoint.from_dict(checkpoint),
        )
        queue.put(("complete", result.to_dict()))
    except WorkflowConflictError:
        queue.put(("conflict", identifier))
    except BaseException as error:
        queue.put(("error", repr(error)))


@pytest.mark.parametrize("identical", [False, True])
def test_real_spawn_writers_cas_no_lost_update_and_idempotency(tmp_path, identical):
    store = create(tmp_path / "workflow.db")
    before = store.snapshot().checkpoint
    context = multiprocessing.get_context("spawn")
    barrier, queue = context.Barrier(2), context.Queue()
    second = "one" if identical else "two"
    processes = [
        context.Process(
            target=append_worker,
            args=(str(store.path), before.to_dict(), name, "request-" + name, barrier, queue),
        )
        for name in ("one", second)
    ]
    try:
        for process in processes:
            process.start()
        results = [queue.get(timeout=30) for _ in processes]
        for process in processes:
            process.join(timeout=10)
            assert not process.is_alive() and process.exitcode == 0
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=10)
        queue.close()
        queue.join_thread()
    current = store.snapshot()
    assert current.checkpoint.record_count == current.checkpoint.operation_count == 1
    if identical:
        assert results[0] == results[1] and results[0][0] == "complete"
    else:
        assert sorted(r[0] for r in results) == ["complete", "conflict"]
        loser = next(r[1] for r in results if r[0] == "conflict")
        rebased = store.append(
            [command(loser)], request_id="request-" + loser, expected=current.checkpoint
        )
        state = replay_workflow(rebased.result.bundle, authority=authority())
        assert set(state.claims) == {"claim-one", "claim-two"}
        assert rebased.result.checkpoint.operation_count == 2
    audit(store.path)


def crash_worker(path, checkpoint):
    store = reopen(path)

    def die_before_commit(connection):
        # Real uncommitted receipt/journal/meta writes have already happened.
        os._exit(29)

    store._commit = die_before_commit
    store.append([command()], request_id="crash", expected=WorkflowCheckpoint.from_dict(checkpoint))


def test_real_process_death_before_commit_recovers_unchanged_database(tmp_path):
    store = create(tmp_path / "workflow.db")
    before = store.snapshot()
    digest = store.request_digest([command()], request_id="crash", expected=before.checkpoint)
    process = multiprocessing.get_context("spawn").Process(
        target=crash_worker, args=(str(store.path), before.checkpoint.to_dict())
    )
    process.start()
    process.join(timeout=20)
    if process.is_alive():
        process.terminate()
        process.join(timeout=10)
        pytest.fail("crash worker did not finish")
    assert process.exitcode == 29
    assert reopen(store.path).snapshot() == before
    assert store.lookup("crash", expected_request_digest=digest) is None
    assert not audit(store.path)[1]


def test_real_busy_lock_failure_has_none_outcome_and_no_retry(tmp_path):
    store = create(tmp_path / "workflow.db", timeout=0)
    before = store.snapshot()
    with closing(sqlite3.connect(store.path, isolation_level=None)) as writer:
        writer.execute("BEGIN IMMEDIATE")
        with pytest.raises(WorkflowStorageError) as caught:
            store.append([command()], request_id="busy", expected=before.checkpoint)
        assert caught.value.outcome == "none" and caught.value.request_digest is not None
        writer.rollback()
    assert store.snapshot() == before


def test_current_anchor_detects_valid_rollback_and_fork_but_context_does_not(tmp_path):
    original = create(tmp_path / "original.db")
    before = original.snapshot()
    latest = original.append([command()], request_id="r1", expected=before.checkpoint)
    rollback = create(tmp_path / "rollback.db")
    fork = create(tmp_path / "fork.db")
    fork.append([command("two")], request_id="r2", expected=fork.snapshot().checkpoint)
    for other in (rollback, fork):
        assert reopen(other.path).snapshot().bundle.context_digest == before.bundle.context_digest
        with pytest.raises(WorkflowConflictError, match="external anchor"):
            reopen(other.path, expected=latest.result.checkpoint)
    imported = create(tmp_path / "import.db", latest.result.bundle)
    assert imported.snapshot().bundle == latest.result.bundle
    # Same workflow head but different journal genesis is not the same full checkpoint.
    with pytest.raises(WorkflowConflictError):
        imported.snapshot(expected=latest.result.checkpoint)


@pytest.mark.parametrize("kind", ["list-subclass", "generator", "dict", "empty", "item"])
def test_bad_commands_rejected_before_database_access(tmp_path, monkeypatch, kind):
    store = create(tmp_path / "workflow.db")
    before = store.snapshot().checkpoint

    class TrappedList(list):
        def __iter__(self):
            raise AssertionError("must not execute caller iterator")

    inputs = {
        "list-subclass": TrappedList([command()]),
        "generator": (command() for _ in range(1)),
        "dict": {"command": command()},
        "empty": [],
        "item": [command().to_dict()],
    }

    def no_database(*args):
        raise AssertionError("admission must happen before connection")

    monkeypatch.setattr(store, "_connect", no_database)
    for method in (store.append, store.request_digest):
        with pytest.raises(ValidationError):
            method(inputs[kind], request_id="r1", expected=before)
    assert len(store.request_digest([command()], request_id="r1", expected=before)) == 64


def test_prelock_input_snapshot_is_detached_and_result_is_immutable(tmp_path, monkeypatch):
    store = create(tmp_path / "workflow.db")
    before = store.snapshot().checkpoint
    commands = [command()]
    connect = store._connect

    def change_source_then_connect(writable):
        commands.clear()
        return connect(writable)

    monkeypatch.setattr(store, "_connect", change_source_then_connect)
    commit = store.append(commands, request_id="r1", expected=before)
    assert not commands and len(commit.result.bundle.records) == 1
    exported = commit.to_dict()
    exported["result"]["bundle"]["records"].clear()
    assert len(commit.result.bundle.records) == 1
    for value, field in (
        (commit, "request_id"),
        (commit.result, "bundle"),
        (before, "workflow_head"),
    ):
        with pytest.raises(FrozenInstanceError):
            setattr(value, field, None)


def test_request_order_changes_identity_and_conflicts(tmp_path):
    store = create(tmp_path / "workflow.db")
    before = store.snapshot().checkpoint
    commands = [command(), command("two")]
    first = store.append(commands, request_id="r1", expected=before)
    assert (
        store.request_digest(commands[::-1], request_id="r1", expected=before)
        != first.request_digest
    )
    with pytest.raises(WorkflowConflictError):
        store.append(commands[::-1], request_id="r1", expected=before)


@pytest.mark.parametrize("version", ["1.0", "2.0"])
def test_real_existing_lifecycle_oracle_and_wire_unchanged(tmp_path, version):
    event = workflow_cases.evidence_event()
    if version == "1.0":
        genesis = hashlib.sha256(b"evidence-braid-ledger:v1").hexdigest()
        digest = hashlib.sha256(genesis.encode() + b"\n" + canonical(event.to_dict())).hexdigest()
        ledger = EvidenceLedger((LedgerEntry(0, event.event_id, event.to_dict(), genesis, digest),))
    else:
        ledger = build_ledger([event])
    bundle = workflow_cases.empty_bundle(evidence=ledger)
    policy = workflow_cases.authority()
    store = create_workflow_store(
        tmp_path / "workflow.db",
        bundle,
        authority=policy,
        expected_context=bundle.context_digest,
        expected_head=bundle.head_digest,
    )
    descriptions = (
        workflow_cases.FIXTURE["draft_to_submitted"] + workflow_cases.FIXTURE["cases"][0]["steps"]
    )
    commands = workflow_cases.steps(bundle, descriptions)
    commit = store.append(commands, request_id="review", expected=store.snapshot().checkpoint)
    expected = bundle.append(commands, authority=policy)
    assert canonical(commit.result.bundle.to_dict()) == canonical(expected.to_dict())
    state = replay_workflow(commit.result.bundle, authority=policy)
    assert state.claims["incident"].status.value == "approved"
    assert state.claims["incident"].approvals == ("carol", "ellen")
    assert state.claims["incident"].authors == ("alice", "bob")
    audit(store.path)


@pytest.mark.parametrize("case", workflow_cases.FIXTURE["cases"], ids=lambda c: c["name"])
def test_complete_handwritten_lifecycle_matrix_persists_all_or_none(tmp_path, case):
    bundle = workflow_cases.empty_bundle()
    policy = workflow_cases.authority()
    store = create_workflow_store(
        tmp_path / "workflow.db",
        bundle,
        authority=policy,
        expected_context=bundle.context_digest,
        expected_head=bundle.head_digest,
    )
    before = store.snapshot()
    commands = workflow_cases.steps(
        bundle, workflow_cases.FIXTURE["draft_to_submitted"][: case["prefix"]] + case["steps"]
    )
    if "error" in case:
        with pytest.raises(ValidationError, match=case["error"]):
            store.append(commands, request_id="review", expected=before.checkpoint)
        assert store.snapshot() == before and not audit(store.path)[1]
    else:
        committed = store.append(commands, request_id="review", expected=before.checkpoint)
        state = replay_workflow(committed.result.bundle, authority=policy)
        assert state.claims["incident"].status.value == case["status"]
        assert list(state.claims["incident"].approvals) == case["approvals"]
        assert state.claims["incident"].revision == len(commands)
        audit(store.path)


@pytest.mark.parametrize(
    "changes",
    [
        {"authority": None},
        {"authority": replace(authority(), policy_id="other")},
        {"expected_context": "0" * 64},
        {"expected_context": "invalid"},
        {"timeout": True},
        {"timeout": -1},
        {"timeout": 61},
        {"timeout": float("nan")},
        {"timeout": float("inf")},
        {"timeout": 10**1000},
        {"limits": {}},
    ],
)
def test_open_requires_independent_authority_context_and_finite_timeout(tmp_path, changes):
    store = create(tmp_path / "workflow.db")
    options = {"authority": authority(), "expected_context": initial().context_digest, **changes}
    with pytest.raises(ValidationError):
        SQLiteWorkflowStore(store.path, **options)


@pytest.mark.parametrize("name", WorkflowStoreLimits.__dataclass_fields__)
@pytest.mark.parametrize("value", [True, 0, -1, 1.0, None, "1", 10**10])
def test_all_logical_budgets_are_exact_positive_and_never_raise_ceiling(name, value):
    with pytest.raises(ValidationError):
        WorkflowStoreLimits(**{name: value})
    assert getattr(WorkflowStoreLimits(**{name: 1}), name) == 1


def test_lowerable_request_and_append_count_budgets_admit_exact_boundary(tmp_path):
    store = create(tmp_path / "workflow.db")
    before = store.snapshot().checkpoint
    request = {
        "kind": "evidence-braid-workflow-request",
        "schema_version": "1.0",
        "request_id": "r1",
        "expected_checkpoint": before.to_dict(),
        "transitions": [command().to_dict()],
    }
    size = len(canonical(request))
    tight = reopen(
        store.path, limits=WorkflowStoreLimits(max_request_bytes=size, max_append_records=1)
    )
    assert (
        tight.request_digest([command()], request_id="r1", expected=before)
        == hashlib.sha256(canonical(request)).hexdigest()
    )
    smaller = reopen(store.path, limits=WorkflowStoreLimits(max_request_bytes=size - 1))
    with pytest.raises(ValidationError, match="byte limit"):
        smaller.append([command()], request_id="r1", expected=before)
    with pytest.raises(ValidationError, match="bounded"):
        tight.append([command(), command("two")], request_id="r1", expected=before)
    tight.append([command()], request_id="r1", expected=before)
    with pytest.raises(ValidationError, match="byte limit"):
        reopen(store.path, limits=WorkflowStoreLimits(max_request_bytes=size - 1))


@pytest.mark.parametrize(
    "name", ["max_bundle_bytes", "max_receipt_bytes", "max_operation_bytes", "max_operations_bytes"]
)
def test_output_byte_budget_exact_acceptance_and_one_byte_refusal(tmp_path, name):
    source = create(tmp_path / "source.db")
    before = source.snapshot().checkpoint
    result = source.append([command()], request_id="r1", expected=before)
    with closing(sqlite3.connect(source.path)) as sql:
        context_size = sql.execute("SELECT length(document) FROM workflow_context").fetchone()[0]
        receipt_size = sql.execute("SELECT length(document) FROM workflow_receipts").fetchone()[0]
        operation_size = sql.execute("SELECT length(document) FROM workflow_operations").fetchone()[
            0
        ]
    size = {
        "max_bundle_bytes": max(
            len(canonical(result.result.bundle.to_dict())), context_size + receipt_size
        ),
        "max_receipt_bytes": receipt_size,
        "max_operation_bytes": operation_size,
        "max_operations_bytes": operation_size,
    }[name]
    exact = create(tmp_path / "exact.db", limits=WorkflowStoreLimits(**{name: size}))
    committed = exact.append([command()], request_id="r1", expected=exact.snapshot().checkpoint)
    assert committed == result
    assert (
        reopen(exact.path, limits=WorkflowStoreLimits(**{name: size})).snapshot()
        == committed.result
    )
    refused = create(tmp_path / "refused.db", limits=WorkflowStoreLimits(**{name: size - 1}))
    prior = refused.snapshot()
    with pytest.raises(ValidationError, match="byte limit"):
        refused.append([command()], request_id="r1", expected=prior.checkpoint)
    assert refused.snapshot() == prior
    with pytest.raises(ValidationError, match="limit"):
        reopen(source.path, limits=WorkflowStoreLimits(**{name: size - 1}))


@pytest.mark.parametrize("name", ["max_records", "max_operations"])
def test_record_operation_budget_and_retry_at_capacity(tmp_path, name):
    store = create(tmp_path / "workflow.db", limits=WorkflowStoreLimits(**{name: 1}))
    before = store.snapshot().checkpoint
    result = store.append([command()], request_id="r1", expected=before)
    assert store.append([command()], request_id="r1", expected=before) == result
    with pytest.raises(ValidationError, match="record or operation"):
        store.append([command("two")], request_id="r2", expected=result.result.checkpoint)
    assert store.snapshot() == result.result


def mutate_document(path, table, edit, *, sequence=0):
    """Adversarial direct SQL rewrite, restoring the exact mandatory trigger."""
    assert table in {
        "workflow_context",
        "workflow_receipts",
        "workflow_operations",
        "workflow_meta",
    }
    with closing(sqlite3.connect(path)) as sql:
        trigger = sql.execute(
            "SELECT name, sql FROM sqlite_schema WHERE name=?", (table + "_no_update",)
        ).fetchone()
        if trigger:
            sql.execute(f"DROP TRIGGER {trigger[0]}")
        key = "singleton" if table in {"workflow_context", "workflow_meta"} else "sequence"
        number = 1 if key == "singleton" else sequence
        raw = sql.execute(f"SELECT document FROM {table} WHERE {key}=?", (number,)).fetchone()[0]
        document = json.loads(raw)
        value = edit(document)
        value = canonical(document) if value is None else value
        sql.execute(f"UPDATE {table} SET document=? WHERE {key}=?", (value, number))
        if trigger:
            sql.execute(trigger[1])
        sql.commit()


@pytest.mark.parametrize(
    "table,field,value",
    [
        ("workflow_context", "kind", "other"),
        ("workflow_context", "schema_version", "2.0"),
        ("workflow_context", "initial_record_count", True),
        ("workflow_context", "initial_record_count", 99),
        ("workflow_context", "initial_workflow_head", "0" * 64),
        ("workflow_context", "artifacts", {}),
        ("workflow_receipts", "previous_digest", "0" * 64),
        ("workflow_receipts", "sequence", 5),
        ("workflow_operations", "sequence", True),
        ("workflow_operations", "sequence", 3),
        ("workflow_operations", "kind", "other"),
        ("workflow_operations", "schema_version", "2.0"),
        ("workflow_operations", "request_id", "another"),
        ("workflow_operations", "request_digest", "0" * 64),
        ("workflow_operations", "result_record_count", 0),
        ("workflow_operations", "result_record_count", 3),
        ("workflow_operations", "result_workflow_head", "0" * 64),
        ("workflow_operations", "expected_checkpoint", {}),
        ("workflow_operations", "previous_digest", "0" * 64),
        ("workflow_operations", "digest", "0" * 64),
        ("workflow_meta", "operation_head", "0" * 64),
        ("workflow_meta", "record_count", 2),
    ],
)
def test_all_context_receipt_journal_and_checkpoint_fields_are_replayed(
    tmp_path, table, field, value
):
    store = create(tmp_path / "workflow.db")
    result = store.append([command()], request_id="r1", expected=store.snapshot().checkpoint)
    mutate_document(store.path, table, lambda node: node.update({field: value}))
    with pytest.raises(ValidationError):
        store.snapshot()
    with pytest.raises(ValidationError):
        store.lookup("r1", expected_request_digest=result.request_digest)


@pytest.mark.parametrize(
    "payload",
    [
        b"\xff",
        b"{",
        b"[]",
        b'{"a":1,"a":2}',
        b'{"a":NaN}',
        b'{"a":1e999}',
        b'{"a":"\\ud800"}',
        b"[" * 2000,
    ],
)
def test_stored_json_is_strict_canonical_bounded_unicode_and_finite(tmp_path, payload):
    store = create(tmp_path / "workflow.db")
    mutate_document(store.path, "workflow_meta", lambda _: payload)
    with pytest.raises(ValidationError):
        store.snapshot()


def test_rehashed_unauthorized_receipt_and_operation_cannot_bypass_acl(tmp_path):
    store = create(tmp_path / "workflow.db")
    store.append([command()], request_id="r1", expected=store.snapshot().checkpoint)

    def forge(node):
        node["transition"]["actor_id"] = "reviewer"
        node["digest"] = hashlib.sha256(
            canonical({k: v for k, v in node.items() if k != "digest"})
        ).hexdigest()

    mutate_document(store.path, "workflow_receipts", forge)
    with pytest.raises(ValidationError, match="scoped role"):
        store.snapshot()


@pytest.mark.parametrize(
    "sql",
    [
        "PRAGMA application_id=1",
        "PRAGMA user_version=2",
        "CREATE TABLE unrelated (document BLOB)",
        "DROP TRIGGER workflow_receipts_no_update",
    ],
)
def test_complete_schema_and_versions_are_guarded_before_blob_reads(tmp_path, monkeypatch, sql):
    store = create(tmp_path / "workflow.db")
    with closing(sqlite3.connect(store.path)) as connection:
        connection.execute(sql)
        connection.commit()
    queries = []
    connect = store._connect

    def tracing(writable):
        connection = connect(writable)
        connection.set_trace_callback(queries.append)
        return connection

    monkeypatch.setattr(store, "_connect", tracing)
    with pytest.raises(ValidationError):
        store.snapshot()
    assert not any("SELECT document" in query for query in queries)


@pytest.mark.parametrize(
    "table,payload",
    [
        ("workflow_context", "text"),
        ("workflow_meta", 1),
        ("workflow_receipts", b"x" * (256 * 1024 + 1)),
        ("workflow_operations", b"x" * (8192 + 1)),
    ],
    ids=["context-text", "meta-integer", "receipt-large", "operation-large"],
)
def test_all_table_types_and_lengths_admitted_before_any_blob_fetch(
    tmp_path, monkeypatch, table, payload
):
    store = create(tmp_path / "workflow.db")
    store.append([command()], request_id="r1", expected=store.snapshot().checkpoint)
    mutate_document(store.path, table, lambda _: payload)
    queries = []
    connect = store._connect

    def tracing(writable):
        connection = connect(writable)
        connection.set_trace_callback(queries.append)
        return connection

    monkeypatch.setattr(store, "_connect", tracing)
    with pytest.raises(ValidationError, match="BLOB type/count/byte"):
        store.snapshot()
    assert not any(
        "SELECT document" in query or "SELECT sequence, document" in query for query in queries
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("record_count", True),
        ("record_count", -1),
        ("record_count", 10001),
        ("operation_count", 1),
        ("workflow_head", "f" * 64),
        ("operation_head", "bad"),
        ("schema_version", "2.0"),
        ("extra", 0),
    ],
)
def test_checkpoint_closed_serialization_and_constructor_invariants(tmp_path, field, value):
    before = create(tmp_path / "workflow.db").snapshot().checkpoint
    assert WorkflowCheckpoint.from_dict(before.to_dict()) == before
    raw = {**before.to_dict(), field: value}
    with pytest.raises(ValidationError):
        WorkflowCheckpoint.from_dict(raw)


def test_snapshot_commit_constructor_invariants_are_not_only_store_checks(tmp_path):
    store = create(tmp_path / "workflow.db")
    before = store.snapshot()
    commit = store.append([command()], request_id="r1", expected=before.checkpoint)
    for args in (
        (None, before.checkpoint),
        (before.bundle, None),
        (before.bundle, commit.result.checkpoint),
    ):
        with pytest.raises(ValidationError):
            StoredWorkflow(*args)
    for args in (
        ("r1", commit.request_digest, None, commit.result),
        ("r1", commit.request_digest, before.checkpoint, before),
        ("r1", "0" * 64, before.checkpoint, commit.result),
        (
            "r1",
            commit.request_digest,
            before.checkpoint,
            replace(
                commit.result, checkpoint=replace(commit.result.checkpoint, operation_head="0" * 64)
            ),
        ),
    ):
        with pytest.raises(ValidationError):
            WorkflowCommit(*args)
    with pytest.raises(ValueError, match="outcome"):
        WorkflowStorageError("invented")


@pytest.mark.parametrize("operation", ["append", "digest", "lookup", "snapshot"])
def test_wrong_checkpoint_id_and_hash_fail_before_locks(tmp_path, monkeypatch, operation):
    store = create(tmp_path / "workflow.db")

    def trap(*args):
        raise AssertionError("database must not be opened")

    monkeypatch.setattr(store, "_connect", trap)
    with pytest.raises(ValidationError):
        if operation == "append":
            store.append([command()], request_id="bad id", expected=None)
        elif operation == "digest":
            store.request_digest([command()], request_id="r1", expected=None)
        elif operation == "lookup":
            store.lookup("r1", expected_request_digest="wrong")
        else:
            store.snapshot(expected={})


def test_cross_context_expected_is_refused_without_io(tmp_path, monkeypatch):
    store = create(tmp_path / "workflow.db")
    before = store.snapshot().checkpoint

    def trap(*args):
        raise AssertionError("database must not be opened")

    monkeypatch.setattr(store, "_connect", trap)
    other = replace(before, context_digest="0" * 64, workflow_head="0" * 64)
    with pytest.raises(WorkflowConflictError, match="another context"):
        store.append([command()], request_id="r1", expected=other)


@pytest.mark.parametrize(
    "input_path", [None, "", "http://example/db", "//server/db", "a\x00b", "x:stream"]
)
def test_nonlocal_malformed_paths_are_rejected(input_path):
    with pytest.raises(ValidationError):
        reopen(input_path)


def test_missing_constructor_parent_and_existing_destination_are_not_created_or_overwritten(
    tmp_path,
):
    missing = tmp_path / "missing.db"
    with pytest.raises(WorkflowStorageError) as caught:
        reopen(missing)
    assert caught.value.outcome == "none" and not missing.exists()
    with pytest.raises(WorkflowStorageError):
        create(tmp_path / "no-parent" / "workflow.db")
    unrelated = tmp_path / "foreign.db"
    unrelated.write_bytes(b"unrelated data")
    with pytest.raises(WorkflowStorageError):
        create(unrelated)
    assert unrelated.read_bytes() == b"unrelated data"
    with pytest.raises(WorkflowStorageError):
        reopen(unrelated)
    with pytest.raises(ValidationError, match="regular"):
        reopen(tmp_path)
    existing = create(tmp_path / "existing.db")
    prior = existing.path.read_bytes()
    with pytest.raises(WorkflowStorageError):
        create(existing.path)
    assert existing.path.read_bytes() == prior


def test_symbolic_database_path_is_never_followed(tmp_path):
    source = create(tmp_path / "source.db")
    link = tmp_path / "link.db"
    try:
        link.symlink_to(source.path)
    except OSError as error:
        pytest.skip(f"platform cannot create test symlink: {error}")
    with pytest.raises(ValidationError, match="regular"):
        reopen(link)
    with pytest.raises(WorkflowStorageError):
        create(link)
    assert link.is_symlink() and source.snapshot().checkpoint.record_count == 0


def test_replaced_database_identity_is_refused_and_not_removed(tmp_path):
    store = create(tmp_path / "workflow.db")
    foreign = create(tmp_path / "foreign.db")
    old = store.path.with_suffix(".old")
    store.path.rename(old)
    foreign.path.rename(store.path)
    with pytest.raises(ValidationError, match="replaced"):
        store.snapshot()
    assert store.path.exists() and old.exists()


class ConnectionFault:
    def __init__(self, real, *, execute=None, rollback=None):
        self.real = real
        self.execute_fault = execute
        self.rollback_fault = rollback
        self.statements = []

    def execute(self, sql, *args):
        self.statements.append(sql)
        if self.execute_fault is not None:
            self.execute_fault(sql)
        return self.real.execute(sql, *args)

    def rollback(self):
        if self.rollback_fault is not None:
            self.rollback_fault()
        self.real.rollback()

    def close(self):
        self.real.close()

    def commit(self):
        self.real.commit()


def test_late_policy_failure_executes_no_insert_at_all(tmp_path, monkeypatch):
    store = create(tmp_path / "workflow.db")
    before = store.snapshot()
    connect = store._connect
    captured = []

    def spy(writable):
        proxy = ConnectionFault(connect(writable))
        captured.append(proxy)
        return proxy

    monkeypatch.setattr(store, "_connect", spy)
    with pytest.raises(ValidationError):
        store.append(
            [command(), command("two", actor_id="reviewer")],
            request_id="r1",
            expected=before.checkpoint,
        )
    assert not any(sql.startswith("INSERT") for sql in captured[0].statements)
    assert store.snapshot() == before


@pytest.mark.parametrize("failure_point", ["receipt-two", "operation", "metadata"])
def test_sql_failure_after_insert_prefix_rolls_back_all_tables(
    tmp_path, monkeypatch, failure_point
):
    store = create(tmp_path / "workflow.db")
    before = store.snapshot()
    connect = store._connect
    receipt_inserts = 0

    def fail(sql):
        nonlocal receipt_inserts
        if sql.startswith("INSERT INTO workflow_receipts"):
            receipt_inserts += 1
        if (
            (failure_point == "receipt-two" and receipt_inserts == 2)
            or (failure_point == "operation" and sql.startswith("INSERT INTO workflow_operations"))
            or (failure_point == "metadata" and sql.startswith("UPDATE workflow_meta"))
        ):
            raise sqlite3.OperationalError("injected storage write failure")

    monkeypatch.setattr(
        store, "_connect", lambda writable: ConnectionFault(connect(writable), execute=fail)
    )
    with pytest.raises(WorkflowStorageError) as caught:
        store.append([command(), command("two")], request_id="r1", expected=before.checkpoint)
    assert caught.value.outcome == "none" and caught.value.request_id == "r1"
    assert "bounded procedural claim" not in str(caught.value)
    assert reopen(store.path).snapshot() == before and not audit(store.path)[2]


@pytest.mark.parametrize("control", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("when", ["before-commit", "after-commit", "cleanup"])
def test_control_exceptions_propagate_with_truthful_outcome(tmp_path, monkeypatch, control, when):
    store = create(tmp_path / "workflow.db")
    before = store.snapshot()

    def interrupted_commit(connection):
        if when == "after-commit":
            connection.commit()
        if when != "cleanup":
            raise control("stop")
        raise OSError("ordinary commit failure")

    def close(connection):
        connection.close()
        if when == "cleanup":
            raise control("cleanup stop")
        raise OSError("ordinary close failure")

    monkeypatch.setattr(store, "_commit", interrupted_commit)
    monkeypatch.setattr(store, "_close", close)
    with pytest.raises(control) as caught:
        store.append([command()], request_id="r1", expected=before.checkpoint)
    assert any("outcome=unknown" in note for note in caught.value.__notes__)
    assert reopen(store.path).snapshot().checkpoint.record_count == (when == "after-commit")


def test_read_rollback_and_close_faults_preserve_primary_validation(tmp_path, monkeypatch):
    store = create(tmp_path / "workflow.db")
    before = store.snapshot()
    connect = store._connect

    def fail_rollback():
        raise OSError("rollback failed")

    def close(connection):
        connection.close()
        raise OSError("close failed")

    monkeypatch.setattr(
        store,
        "_connect",
        lambda writable: ConnectionFault(connect(writable), rollback=fail_rollback),
    )
    monkeypatch.setattr(store, "_close", close)
    with pytest.raises(ValidationError) as caught:
        store.append([command(actor_id="reviewer")], request_id="r1", expected=before.checkpoint)
    assert any("rollback also failed" in note for note in caught.value.__notes__)
    assert any("close also failed" in note for note in caught.value.__notes__)
    with pytest.raises(WorkflowStorageError) as storage_error:
        store.snapshot()
    assert storage_error.value.outcome == "none"
    assert reopen(store.path).snapshot() == before


@pytest.mark.parametrize("when", ["before", "after", "close"])
def test_failed_creation_never_removes_possibly_committed_database(tmp_path, monkeypatch, when):
    path = tmp_path / "workflow.db"

    def commit(connection):
        if when != "before":
            connection.commit()
        if when != "close":
            raise OSError("commit acknowledgement unavailable")

    def close(connection):
        connection.close()
        if when == "close":
            raise OSError("close acknowledgement unavailable")

    monkeypatch.setattr(SQLiteWorkflowStore, "_commit", staticmethod(commit))
    monkeypatch.setattr(SQLiteWorkflowStore, "_close", staticmethod(close))
    with pytest.raises(WorkflowStorageError) as caught:
        create(path)
    assert caught.value.outcome == ("complete" if when == "close" else "unknown")
    assert path.exists()
    monkeypatch.undo()
    if when != "before":
        assert reopen(path).snapshot().bundle == initial()


def test_precommit_creation_failure_removes_only_owned_closed_reservation(tmp_path, monkeypatch):
    path = tmp_path / "workflow.db"
    connect = SQLiteWorkflowStore._connect

    def fail(sql):
        if sql.startswith("CREATE TABLE workflow_receipts"):
            raise OSError("create failure before data")

    monkeypatch.setattr(
        SQLiteWorkflowStore,
        "_connect",
        lambda self, writable: ConnectionFault(connect(self, writable), execute=fail),
    )
    with pytest.raises(WorkflowStorageError) as caught:
        create(path)
    assert caught.value.outcome == "none" and not path.exists()
    assert not list(tmp_path.iterdir())


def test_creation_cleanup_never_removes_foreign_replacement(tmp_path, monkeypatch):
    path = tmp_path / "workflow.db"
    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"foreign")
    connect = SQLiteWorkflowStore._connect

    def fail(sql):
        raise OSError("creation failed")

    def close_then_replace(connection):
        connection.close()
        path.rename(path.with_suffix(".reserved"))
        replacement.rename(path)

    monkeypatch.setattr(
        SQLiteWorkflowStore,
        "_connect",
        lambda self, writable: ConnectionFault(connect(self, writable), execute=fail),
    )
    monkeypatch.setattr(SQLiteWorkflowStore, "_close", staticmethod(close_then_replace))
    with pytest.raises(WorkflowStorageError) as caught:
        create(path)
    assert path.read_bytes() == b"foreign" and path.with_suffix(".reserved").exists()
    assert any("cleanup incomplete" in note for note in caught.value.__notes__)


def test_creation_sidecar_preserved_for_inspection(tmp_path, monkeypatch):
    path = tmp_path / "workflow.db"
    connect = SQLiteWorkflowStore._connect

    def fail(sql):
        raise OSError("creation failed")

    def close(connection):
        connection.close()
        path.with_name(path.name + "-journal").write_bytes(b"foreign sidecar")

    monkeypatch.setattr(
        SQLiteWorkflowStore,
        "_connect",
        lambda self, writable: ConnectionFault(connect(self, writable), execute=fail),
    )
    monkeypatch.setattr(SQLiteWorkflowStore, "_close", staticmethod(close))
    with pytest.raises(WorkflowStorageError):
        create(path)
    assert path.exists() and path.with_name(path.name + "-journal").exists()


def test_history_verification_materializes_one_bundle_not_every_operation_prefix(
    tmp_path, monkeypatch
):
    store = create(tmp_path / "workflow.db")
    first = None
    for number in range(12):
        result = store.append(
            [command(str(number))],
            request_id="r" + str(number),
            expected=store.snapshot().checkpoint,
        )
        if first is None:
            first = result
    lengths = []
    post_init = WorkflowBundle.__post_init__

    def track(bundle):
        lengths.append(len(bundle.records))
        post_init(bundle)

    monkeypatch.setattr(WorkflowBundle, "__post_init__", track)
    store.snapshot()
    assert lengths == [12]
    lengths.clear()
    assert store.lookup("r0", expected_request_digest=first.request_digest) == first
    assert lengths == [12, 1]


@pytest.mark.parametrize("identifier", [b"binary", "x" * 129, "bad id"])
def test_stored_request_id_sql_type_length_and_syntax_are_not_trusted(tmp_path, identifier):
    store = create(tmp_path / "workflow.db")
    store.append([command()], request_id="r1", expected=store.snapshot().checkpoint)
    with closing(sqlite3.connect(store.path)) as sql:
        trigger = sql.execute(
            "SELECT sql FROM sqlite_schema WHERE name='workflow_operations_no_update'"
        ).fetchone()[0]
        sql.execute("DROP TRIGGER workflow_operations_no_update")
        sql.execute("UPDATE workflow_operations SET request_id=?", (identifier,))
        sql.execute(trigger)
        sql.commit()
    with pytest.raises(ValidationError):
        store.snapshot()


@pytest.mark.parametrize("table", ["workflow_context", "workflow_meta"])
def test_missing_singleton_rejected_without_payload_materialization(tmp_path, table):
    store = create(tmp_path / "workflow.db")
    with closing(sqlite3.connect(store.path)) as sql:
        if table == "workflow_context":
            trigger = sql.execute(
                "SELECT sql FROM sqlite_schema WHERE name='workflow_context_no_delete'"
            ).fetchone()[0]
            sql.execute("DROP TRIGGER workflow_context_no_delete")
            sql.execute("DELETE FROM workflow_context")
            sql.execute(trigger)
        else:
            sql.execute("DELETE FROM workflow_meta")
        sql.commit()
    with pytest.raises(ValidationError, match="context/meta"):
        store.snapshot()


def test_receipt_sequence_hole_is_not_accepted(tmp_path):
    store = create(tmp_path / "workflow.db")
    store.append([command()], request_id="r1", expected=store.snapshot().checkpoint)
    with closing(sqlite3.connect(store.path)) as sql:
        trigger = sql.execute(
            "SELECT sql FROM sqlite_schema WHERE name='workflow_receipts_no_update'"
        ).fetchone()[0]
        sql.execute("DROP TRIGGER workflow_receipts_no_update")
        sql.execute("UPDATE workflow_receipts SET sequence=3")
        sql.execute(trigger)
        sql.commit()
    with pytest.raises(ValidationError, match="sequence"):
        store.snapshot()


def test_stored_append_limit_is_enforced_during_replay(tmp_path):
    store = create(tmp_path / "workflow.db")
    store.append([command(), command("two")], request_id="r1", expected=store.snapshot().checkpoint)
    with pytest.raises(ValidationError, match="append count"):
        reopen(store.path, limits=WorkflowStoreLimits(max_append_records=1))


def test_create_preflight_authority_head_context_and_record_limits_no_reservation(tmp_path):
    bundle = initial().append([command(), command("two")], authority=authority())
    for changes in (
        {"initial": None},
        {"expected_head": "0" * 64},
        {"expected_context": "0" * 64},
        {"limits": WorkflowStoreLimits(max_records=1)},
        {"limits": WorkflowStoreLimits(max_receipt_bytes=1)},
    ):
        path = tmp_path / "workflow.db"
        options = dict(
            initial=bundle,
            authority=authority(),
            expected_context=bundle.context_digest,
            expected_head=bundle.head_digest,
        )
        options.update(changes)
        with pytest.raises(ValidationError):
            create_workflow_store(path, **options)
        assert not path.exists()


@pytest.mark.parametrize("failure", ["ordinary", "control"])
def test_connection_setup_error_closes_and_preserves_control_exception(
    tmp_path, monkeypatch, failure
):
    import evidence_braid.workflow_storage as module

    store = create(tmp_path / "workflow.db")
    connect = module.sqlite3.connect
    closed = []

    class SetupFailure(ConnectionFault):
        def execute(self, sql, *args):
            if sql.startswith("PRAGMA trusted_schema"):
                raise OSError("setup failed")
            return super().execute(sql, *args)

        def close(self):
            super().close()
            closed.append(True)
            if failure == "control":
                raise KeyboardInterrupt("cleanup stop")
            raise OSError("cleanup failed")

    monkeypatch.setattr(module.sqlite3, "connect", lambda *a, **kw: SetupFailure(connect(*a, **kw)))
    with pytest.raises(
        KeyboardInterrupt if failure == "control" else WorkflowStorageError
    ) as caught:
        store.snapshot()
    assert closed == [True]
    primary = caught.value if failure == "control" else caught.value.__cause__
    assert any("outcome=none" in note for note in primary.__notes__)


def test_identity_change_during_open_closes_connection_and_refuses(tmp_path, monkeypatch):
    import evidence_braid.workflow_storage as module

    store = create(tmp_path / "workflow.db")
    real = module._regular
    calls = 0

    def changed(path):
        nonlocal calls
        calls += 1
        dev, ino = real(path)
        return (dev, ino) if calls == 1 else (dev, ino + 1)

    monkeypatch.setattr(module, "_regular", changed)
    with pytest.raises(ValidationError, match="changed while opening"):
        store.snapshot()
    monkeypatch.undo()
    assert reopen(store.path).snapshot().bundle == initial()


@pytest.mark.parametrize("cleanup", ["missing", "interrupt"])
def test_failed_reservation_cleanup_missing_and_interrupt_paths(tmp_path, monkeypatch, cleanup):
    from pathlib import Path

    path = tmp_path / "workflow.db"
    connect = SQLiteWorkflowStore._connect

    def fail(sql):
        raise OSError("creation failed")

    def close(connection):
        connection.close()
        if cleanup == "missing":
            path.unlink()

    def interrupt(*args):
        raise KeyboardInterrupt("cleanup stop")

    monkeypatch.setattr(
        SQLiteWorkflowStore,
        "_connect",
        lambda self, writable: ConnectionFault(connect(self, writable), execute=fail),
    )
    monkeypatch.setattr(SQLiteWorkflowStore, "_close", staticmethod(close))
    if cleanup == "interrupt":
        monkeypatch.setattr(Path, "unlink", interrupt)
    with pytest.raises(KeyboardInterrupt if cleanup == "interrupt" else WorkflowStorageError):
        create(path)
    assert path.exists() == (cleanup == "interrupt")


def test_setup_two_control_failures_preserve_original_exact_identity(tmp_path, monkeypatch):
    import evidence_braid.workflow_storage as module

    store = create(tmp_path / "workflow.db")
    connect = module.sqlite3.connect
    primary = KeyboardInterrupt("original setup control")
    secondary = SystemExit("secondary close control")

    class DoubleControl(ConnectionFault):
        def execute(self, sql, *args):
            raise primary

        def close(self):
            super().close()
            raise secondary

    monkeypatch.setattr(
        module.sqlite3, "connect", lambda *a, **kw: DoubleControl(connect(*a, **kw))
    )
    with pytest.raises(BaseException) as caught:
        store.snapshot()
    assert caught.value is primary


def test_schema_exact_sql_checked_after_metadata_bounds(tmp_path):
    store = create(tmp_path / "workflow.db")
    with closing(sqlite3.connect(store.path)) as connection:
        connection.execute("DROP TRIGGER workflow_receipts_no_update")
        connection.execute(
            "CREATE TRIGGER workflow_receipts_no_update BEFORE UPDATE ON workflow_receipts "
            "BEGIN SELECT 1; END"
        )
        connection.commit()
    with pytest.raises(ValidationError, match="schema differs"):
        store.snapshot()


def test_sqlite_check_constraints_are_not_trusted_for_singleton_identity(tmp_path):
    store = create(tmp_path / "workflow.db")
    with closing(sqlite3.connect(store.path)) as connection:
        connection.execute("PRAGMA ignore_check_constraints=ON")
        connection.execute("UPDATE workflow_meta SET singleton=2")
        connection.commit()
    with pytest.raises(ValidationError, match="singleton"):
        store.snapshot()


def test_durable_workflow_core_example(capsys):
    from examples.durable_workflow import main

    main()
    assert json.loads(capsys.readouterr().out) == {
        "actor_authentication_provided": False,
        "historical_retry_equal": True,
        "operation_count": 2,
        "portable_replay_equal": True,
        "record_count": 6,
        "status": "approved",
    }


def test_create_setup_close_before_failure_never_unlinks_live_connection(tmp_path, monkeypatch):
    from pathlib import Path

    import evidence_braid.workflow_storage as module

    path = tmp_path / "workflow.db"
    connect = module.sqlite3.connect
    held = []
    unlinked = []

    class Unclosed(ConnectionFault):
        def execute(self, sql, *args):
            raise OSError("connection setup failed")

        def close(self):
            raise OSError("close failed BEFORE closing")

    def capture(*args, **kwargs):
        real = connect(*args, **kwargs)
        held.append(real)
        return Unclosed(real)

    def unlink_spy(self, *args, **kwargs):
        unlinked.append(self)
        raise AssertionError("must never unlink while owned SQLite connection may remain open")

    monkeypatch.setattr(module.sqlite3, "connect", capture)
    monkeypatch.setattr(Path, "unlink", unlink_spy)
    try:
        with pytest.raises(WorkflowStorageError) as caught:
            create(path)
        assert caught.value.outcome == "none"
        assert held[0].execute("SELECT 1").fetchone() == (1,)
        assert unlinked == [] and path.exists()
    finally:
        for connection in held:
            connection.close()


def test_creation_cleanup_two_controls_preserves_original_identity(tmp_path, monkeypatch):
    from pathlib import Path

    primary = KeyboardInterrupt("original create control")
    secondary = SystemExit("secondary unlink control")
    connect = SQLiteWorkflowStore._connect

    def fail(sql):
        raise primary

    def fail_unlink(*args):
        raise secondary

    monkeypatch.setattr(
        SQLiteWorkflowStore,
        "_connect",
        lambda self, writable: ConnectionFault(connect(self, writable), execute=fail),
    )
    monkeypatch.setattr(Path, "unlink", fail_unlink)
    with pytest.raises(BaseException) as caught:
        create(tmp_path / "workflow.db")
    assert caught.value is primary


@pytest.mark.parametrize(
    "body,cleanup",
    [(KeyboardInterrupt, SystemExit), (KeyboardInterrupt, None), (OSError, SystemExit)],
)
def test_reservation_body_and_close_controls_preserve_original_identity(
    tmp_path, monkeypatch, body, cleanup
):
    from pathlib import Path

    import evidence_braid.workflow_storage as module

    primary = body("original reservation body failure")
    secondary = None if cleanup is None else cleanup("secondary reservation close control")
    original_open = Path.open

    class Reservation:
        def __init__(self, real):
            self.real = real

        def fileno(self):
            return self.real.fileno()

        def close(self):
            self.real.close()
            if secondary is not None:
                raise secondary

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()

    def opening(path, *args, **kwargs):
        real = original_open(path, *args, **kwargs)
        return Reservation(real) if args and args[0] == "xb" else real

    def interrupt_stat(*args):
        raise primary

    monkeypatch.setattr(Path, "open", opening)
    monkeypatch.setattr(module.os, "fstat", interrupt_stat)
    with pytest.raises(BaseException) as caught:
        create(tmp_path / "workflow.db")
    assert caught.value is (secondary if body is OSError else primary)


def test_imported_initial_bundle_and_stored_payload_each_obey_same_byte_ceiling(tmp_path):
    bundle = initial().append([command()], authority=authority())
    # The separately domain-tagged context and receipt payloads are slightly
    # larger than the portable bundle. Both must fit; portable fit alone is insufficient.
    size = len(canonical(bundle.to_dict()))
    path = tmp_path / "workflow.db"
    with pytest.raises(ValidationError, match="stored aggregate byte"):
        create(path, bundle, limits=WorkflowStoreLimits(max_bundle_bytes=size))
    assert not path.exists()


def identity_stat(info, **changes):
    return SimpleNamespace(
        **{
            "st_dev": info.st_dev,
            "st_ino": info.st_ino,
            "st_mode": info.st_mode,
            "st_file_attributes": getattr(info, "st_file_attributes", 0),
            **changes,
        }
    )


def test_unknown_file_identity_never_authorizes_foreign_creation_cleanup(tmp_path, monkeypatch):
    from pathlib import Path

    import evidence_braid.workflow_storage as module

    path = tmp_path / "workflow.db"
    foreign = tmp_path / "foreign.db"
    foreign.write_bytes(b"foreign content must survive")
    fstat, lstat = module.os.fstat, Path.lstat
    connect = SQLiteWorkflowStore._connect

    def fail(sql):
        raise OSError("precommit failure")

    def replace_after_close(connection):
        connection.close()
        path.rename(path.with_suffix(".reserved"))
        foreign.rename(path)

    monkeypatch.setattr(module.os, "fstat", lambda fd: identity_stat(fstat(fd), st_ino=0))
    monkeypatch.setattr(Path, "lstat", lambda self: identity_stat(lstat(self), st_ino=0))
    monkeypatch.setattr(
        SQLiteWorkflowStore,
        "_connect",
        lambda self, writable: ConnectionFault(connect(self, writable), execute=fail),
    )
    monkeypatch.setattr(SQLiteWorkflowStore, "_close", staticmethod(replace_after_close))
    with pytest.raises((WorkflowStorageError, ValidationError)):
        create(path)
    assert foreign.exists() or (
        path.exists() and path.read_bytes() == b"foreign content must survive"
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"st_ino": 0},
        {"st_ino": -1},
        {"st_ino": True},
        {"st_ino": None},
        {"st_ino": 1 << 128},
        {"st_dev": -1},
        {"st_dev": True},
        {"st_dev": None},
        {"st_dev": 1 << 128},
    ],
)
@pytest.mark.parametrize("boundary", ["reservation", "open"])
def test_invalid_stable_identity_is_refused_before_sqlite_access(
    tmp_path, monkeypatch, changes, boundary
):
    from pathlib import Path

    import evidence_braid.workflow_storage as module

    path = tmp_path / "workflow.db"
    if boundary == "open":
        create(path)
        lstat = Path.lstat
        monkeypatch.setattr(Path, "lstat", lambda self: identity_stat(lstat(self), **changes))
    else:
        fstat = module.os.fstat
        monkeypatch.setattr(module.os, "fstat", lambda fd: identity_stat(fstat(fd), **changes))

    def forbidden(*args, **kwargs):
        raise AssertionError("invalid identity must not reach SQLite acquisition")

    monkeypatch.setattr(module.sqlite3, "connect", forbidden)
    with pytest.raises(ValidationError, match="stable file identity"):
        create(path) if boundary == "reservation" else reopen(path)
    assert path.exists()  # Unknown ownership never authorizes removal of the reservation.
