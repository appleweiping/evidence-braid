"""RED first: durable case claim, byte publication, and independent reopen."""

from __future__ import annotations

import hashlib
import json
import multiprocessing as mp
import os
import shutil
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from threading import Barrier

import pytest

import evidence_braid as api
from evidence_braid import case_storage as case_storage_module
from evidence_braid.case_storage import (
    CaseStoreCheckpoint,
    CaseStoreConflictError,
    CaseStoreError,
    SQLiteCaseStore,
    create_case_store,
)
from evidence_braid.errors import ValidationError
from evidence_braid.examples import durable_case
from evidence_braid.io import canonical_json

ASSERTION = b"The cache is stale."
INPUT = b'{"incident":"cache","revision":"B"}'


def test_documented_durable_case_example_runs_end_to_end(capsys):
    durable_case.main()
    lines = dict(line.split("=", 1) for line in capsys.readouterr().out.splitlines())
    assert set(lines) == {"plan", "observation", "verdict", "outcome"}
    assert lines["outcome"] == "supported"
    for key in ("plan", "observation", "verdict"):
        assert len(lines[key]) == 64
        assert all(character in "0123456789abcdef" for character in lines[key])
    assert len({lines["plan"], lines["observation"], lines["verdict"]}) == 3


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def fixture():
    authority = api.CaseAuthority(
        "case-policy",
        (
            api.CaseActor(
                "model", api.CaseActorKind.MODEL, (api.CaseGrant("site/a", api.CaseRole.PROPOSE),)
            ),
            api.CaseActor(
                "observer", api.CaseActorKind.TOOL, (api.CaseGrant("site/a", api.CaseRole.OBSERVE),)
            ),
            api.CaseActor(
                "evaluator",
                api.CaseActorKind.TOOL,
                (api.CaseGrant("site/a", api.CaseRole.EVALUATE),),
            ),
        ),
    )
    plan = api.CasePlan(
        "case-1",
        "workflow-1",
        "claim-1",
        "site/a",
        "model",
        "assertion-1",
        sha(ASSERTION),
        "The report cache is stale.",
        "A bypass should return the current revision.",
        "revision-B",
        "input-1",
        sha(INPUT),
        sha(b"revision-B"),
        "cache-bypass",
        "fixture-cache",
        "1",
        "sha256-equality-v1",
        authority.digest,
    )
    journal = api.CaseJournal.empty(authority).append((plan,), authority=authority)
    return authority, journal


def registry(callback):
    return api.ObservationRegistry(
        (api.ObservationAdapter("cache-bypass", "fixture-cache", "1", "observer", callback),)
    )


def store(tmp_path: Path):
    authority, journal = fixture()
    path = tmp_path / "case.db"
    result = create_case_store(
        path,
        journal,
        authority=authority,
        expected_plan_head=journal.head_digest,
        assertion_bytes=ASSERTION,
        input_bytes=INPUT,
    )
    return path, authority, journal, result


def test_red_create_reopen_full_checkpoint_and_format(tmp_path):
    path, authority, journal, opened = store(tmp_path)
    first = opened.snapshot()
    assert first.journal.to_bytes() == journal.to_bytes()
    assert first.checkpoint.record_count == 1
    assert first.checkpoint.operation_count == 0
    assert first.assertion_bytes == ASSERTION and first.input_bytes == INPUT
    reopened = SQLiteCaseStore(
        path, authority=authority, expected_plan_head=journal.head_digest, expected=first.checkpoint
    )
    assert reopened.snapshot(expected=first.checkpoint) == first
    with pytest.raises(ValidationError):
        create_case_store(
            path,
            journal,
            authority=authority,
            expected_plan_head=journal.head_digest,
            assertion_bytes=ASSERTION,
            input_bytes=INPUT,
        )
    wrong_authority = api.CaseAuthority("other-policy", authority.actors)
    with pytest.raises(ValidationError):
        SQLiteCaseStore(path, authority=wrong_authority, expected_plan_head=journal.head_digest)


def test_claim_before_callback_and_reopen_no_reentry(tmp_path):
    path, authority, journal, opened = store(tmp_path)
    calls = []
    selected = registry(lambda raw: calls.append(raw) or b"revision-B")
    before = opened.snapshot().checkpoint
    expected_digest = opened.claim_request_digest(selected, request_id="req-1", expected=before)
    claimed = opened.claim_observation(selected, request_id="req-1", expected=before)
    assert claimed.request_digest == expected_digest
    assert calls == []
    assert claimed.result.checkpoint.record_count == 1
    assert claimed.result.checkpoint.operation_count == 1
    assert claimed.result.checkpoint.case_head == before.case_head
    reopened = SQLiteCaseStore(
        path,
        authority=authority,
        expected_plan_head=journal.head_digest,
        expected=claimed.result.checkpoint,
    )
    assert reopened.snapshot().pending_request_id == "req-1"
    with pytest.raises(CaseStoreConflictError):
        reopened.execute_observation(
            selected, request_id="req-1", finish_id="finish-1", expected=claimed.result.checkpoint
        )
    assert calls == []
    assert reopened.lookup("req-1", expected_request_digest=claimed.request_digest) == claimed


def test_bad_finish_identity_preflight_invokes_nothing(tmp_path):
    _, _, _, opened = store(tmp_path)
    calls = []
    before = opened.snapshot().checkpoint
    with pytest.raises(ValidationError):
        opened.execute_observation(
            registry(lambda raw: calls.append(raw) or b"revision-B"),
            request_id="req-1",
            finish_id="req-1",
            expected=before,
        )
    assert calls == []
    assert opened.snapshot().checkpoint == before


def test_unpersisted_custom_limits_rejected_before_claim(tmp_path):
    _, _, _, opened = store(tmp_path)
    calls = []
    narrowed = api.ObservationRegistry(
        (
            api.ObservationAdapter(
                "cache-bypass",
                "fixture-cache",
                "1",
                "observer",
                lambda raw: calls.append(raw) or b"revision-B",
            ),
        ),
        limits=api.ObservationLimits(output_bytes=1),
    )
    before = opened.snapshot().checkpoint
    with pytest.raises(ValidationError, match="fixed observation byte limits"):
        opened.execute_observation(
            narrowed, request_id="req-1", finish_id="finish-1", expected=before
        )
    assert calls == []
    assert opened.snapshot().checkpoint == before


def test_execute_reopen_verified_bytes_and_checked_verdict(tmp_path):
    path, authority, journal, opened = store(tmp_path)
    calls = []

    def observed_callback(raw):
        calls.append(raw)
        independent = SQLiteCaseStore(
            path, authority=authority, expected_plan_head=journal.head_digest
        ).snapshot()
        assert independent.pending_request_id == "req-1"
        assert independent.checkpoint.operation_count == 1
        assert independent.journal.head_digest == journal.head_digest
        assert independent.observed_bytes is None
        return b"revision-B"

    selected = registry(observed_callback)
    result = opened.execute_observation(
        selected, request_id="req-1", finish_id="finish-1", expected=opened.snapshot().checkpoint
    )
    assert calls == [INPUT]
    after = result.result
    assert after.observed_bytes == b"revision-B"
    assert after.journal.receipts[1].record.observed_sha256 == sha(b"revision-B")
    reopened = SQLiteCaseStore(
        path, authority=authority, expected_plan_head=journal.head_digest, expected=after.checkpoint
    )
    assert reopened.snapshot().observed_bytes == b"revision-B"
    with closing(sqlite3.connect(path)) as independent_connection:
        stored_raw = independent_connection.execute(
            "SELECT content FROM case_payloads WHERE role='output'"
        ).fetchone()[0]
    assert type(stored_raw) is bytes
    assert stored_raw == b"revision-B"
    assert (
        hashlib.sha256(stored_raw).hexdigest() == after.journal.receipts[1].record.observed_sha256
    )
    verified = reopened.append_checked_verdict(
        operation_id="verdict-1", evaluator_id="evaluator", expected=after.checkpoint
    )
    assert verified.result.journal.receipts[2].record.outcome is api.CaseVerdictOutcome.SUPPORTED
    assert reopened.lookup("finish-1", expected_request_digest=result.request_digest) == result
    assert reopened.lookup_operation("finish-1") == result


def test_stale_writer_and_output_validation(tmp_path):
    _, _, _, opened = store(tmp_path)
    before = opened.snapshot().checkpoint
    selected = registry(lambda _: b"revision-B")
    claim = opened.claim_observation(selected, request_id="req-1", expected=before)
    with pytest.raises(CaseStoreConflictError):
        opened.claim_observation(selected, request_id="req-2", expected=before)
    with pytest.raises(ValidationError):
        opened.finish_observation(
            request_id="req-1",
            operation_id="finish-bad",
            output=b"x" * 4097,
            expected=claim.result.checkpoint,
        )
    assert opened.snapshot().pending_request_id == "req-1"
    complete = opened.finish_observation(
        request_id="req-1",
        operation_id="finish-1",
        output=b"revision-C",
        expected=claim.result.checkpoint,
    )
    verdict = opened.append_checked_verdict(
        operation_id="verdict-1", evaluator_id="evaluator", expected=complete.result.checkpoint
    )
    assert verdict.result.journal.receipts[2].record.outcome is api.CaseVerdictOutcome.REFUTED


def _claim_worker(path, authority, head, checkpoint, barrier, queue, request_id):
    case_store = SQLiteCaseStore(path, authority=authority, expected_plan_head=head)
    selected = registry(lambda _: b"revision-B")
    barrier.wait()
    try:
        case_store.claim_observation(selected, request_id=request_id, expected=checkpoint)
    except CaseStoreConflictError:
        queue.put("conflict")
    else:
        queue.put("won")


def test_independent_process_claim_race(tmp_path):
    path, authority, journal, opened = store(tmp_path)
    checkpoint = opened.snapshot().checkpoint
    ctx = mp.get_context("spawn")
    barrier, queue = ctx.Barrier(2), ctx.Queue()
    children = [
        ctx.Process(
            target=_claim_worker,
            args=(path, authority, journal.head_digest, checkpoint, barrier, queue, f"req-{i}"),
        )
        for i in (1, 2)
    ]
    for child in children:
        child.start()
    for child in children:
        child.join(60)
        assert child.exitcode == 0
    assert sorted([queue.get(timeout=1), queue.get(timeout=1)]) == ["conflict", "won"]
    assert opened.snapshot().checkpoint.operation_count == 1


def test_reopen_detects_output_tamper_and_unsupported_format(tmp_path):
    path, authority, journal, opened = store(tmp_path)
    selected = registry(lambda _: b"revision-B")
    opened.execute_observation(
        selected, request_id="req-1", finish_id="finish-1", expected=opened.snapshot().checkpoint
    )
    with closing(sqlite3.connect(path)) as connection:
        trigger = connection.execute(
            "SELECT sql FROM sqlite_schema WHERE name='case_payloads_no_update'"
        ).fetchone()[0]
        connection.execute("DROP TRIGGER case_payloads_no_update")
        connection.execute(
            "UPDATE case_payloads SET content=? WHERE role='output'", (b"revision-C",)
        )
        connection.execute(trigger)
        connection.commit()
    with pytest.raises(ValidationError):
        SQLiteCaseStore(path, authority=authority, expected_plan_head=journal.head_digest)


def _crash_child(path, authority, head, marker, mode):
    opened = SQLiteCaseStore(path, authority=authority, expected_plan_head=head)
    if mode == "before":
        opened.claim_observation(
            registry(lambda _: b"revision-B"),
            request_id="req-1",
            expected=opened.snapshot().checkpoint,
        )
        marker.write_text("claimed", encoding="utf-8")
        os._exit(0)

    def entered(_):
        marker.write_text("entered", encoding="utf-8")
        os._exit(0)

    opened.execute_observation(
        registry(entered),
        request_id="req-1",
        finish_id="finish-1",
        expected=opened.snapshot().checkpoint,
    )


@pytest.mark.parametrize("mode", ["before", "entered"])
def test_process_exit_after_claim_never_reenters(tmp_path, mode):
    path, authority, journal, _ = store(tmp_path)
    marker = tmp_path / "child.marker"
    child = mp.get_context("spawn").Process(
        target=_crash_child, args=(path, authority, journal.head_digest, marker, mode)
    )
    child.start()
    child.join(15)
    assert child.exitcode == 0
    assert marker.read_text(encoding="utf-8") == ("entered" if mode == "entered" else "claimed")
    reopened = SQLiteCaseStore(path, authority=authority, expected_plan_head=journal.head_digest)
    assert reopened.snapshot().pending_request_id == "req-1"
    assert reopened.snapshot().observed_bytes is None
    calls = []
    with pytest.raises(CaseStoreConflictError):
        reopened.execute_observation(
            registry(lambda raw: calls.append(raw) or b"revision-B"),
            request_id="req-1",
            finish_id="finish-1",
            expected=reopened.snapshot().checkpoint,
        )
    assert calls == []


def test_finish_commit_acknowledgement_unknown_is_recoverable(tmp_path, monkeypatch):
    path, authority, journal, opened = store(tmp_path)
    claim = opened.claim_observation(
        registry(lambda _: b"revision-B"), request_id="req-1", expected=opened.snapshot().checkpoint
    )
    finish_digest = opened.finish_request_digest(
        request_id="req-1",
        operation_id="finish-1",
        expected=claim.result.checkpoint,
        output=b"revision-B",
    )
    real_commit = SQLiteCaseStore._commit

    def commit_then_lose_ack(connection):
        real_commit(connection)
        raise OSError("lost commit acknowledgement")

    monkeypatch.setattr(SQLiteCaseStore, "_commit", staticmethod(commit_then_lose_ack))
    with pytest.raises(CaseStoreError) as caught:
        opened.finish_observation(
            request_id="req-1",
            operation_id="finish-1",
            expected=claim.result.checkpoint,
            output=b"revision-B",
        )
    assert caught.value.outcome == "unknown"
    assert caught.value.request_digest == finish_digest
    monkeypatch.setattr(SQLiteCaseStore, "_commit", staticmethod(real_commit))
    reopened = SQLiteCaseStore(path, authority=authority, expected_plan_head=journal.head_digest)
    with pytest.raises(CaseStoreConflictError):
        reopened.finish_observation(
            request_id="req-1",
            operation_id="finish-1",
            expected=claim.result.checkpoint,
            output=b"revision-B",
        )
    recovered = reopened.lookup("finish-1", expected_request_digest=finish_digest)
    assert recovered is not None and recovered.result.observed_bytes == b"revision-B"
    assert reopened.lookup_operation("finish-1") == recovered
    assert recovered.result.journal.checkpoint.record_count == 2


def test_finish_before_commit_failure_leaves_no_torn_output(tmp_path, monkeypatch):
    path, authority, journal, opened = store(tmp_path)
    claim = opened.claim_observation(
        registry(lambda _: b"revision-B"), request_id="req-1", expected=opened.snapshot().checkpoint
    )
    finish_digest = opened.finish_request_digest(
        request_id="req-1",
        operation_id="finish-1",
        expected=claim.result.checkpoint,
        output=b"revision-B",
    )
    real_commit = SQLiteCaseStore._commit

    def deny_commit(_):
        raise OSError("commit unavailable")

    monkeypatch.setattr(SQLiteCaseStore, "_commit", staticmethod(deny_commit))
    with pytest.raises(CaseStoreError) as caught:
        opened.finish_observation(
            request_id="req-1",
            operation_id="finish-1",
            expected=claim.result.checkpoint,
            output=b"revision-B",
        )
    assert caught.value.outcome == "unknown"
    monkeypatch.setattr(SQLiteCaseStore, "_commit", staticmethod(real_commit))
    reopened = SQLiteCaseStore(path, authority=authority, expected_plan_head=journal.head_digest)
    assert reopened.snapshot().pending_request_id == "req-1"
    assert reopened.snapshot().observed_bytes is None
    assert reopened.lookup("finish-1", expected_request_digest=finish_digest) is None
    assert reopened.lookup_operation("finish-1") is None


def test_bridge_retains_measured_bytes_on_finish_failure(tmp_path, monkeypatch):
    path, authority, journal, opened = store(tmp_path)
    real_commit = SQLiteCaseStore._commit
    commits = 0

    def reject_second_commit(connection):
        nonlocal commits
        commits += 1
        if commits == 2:
            raise OSError("finish commit unavailable")
        real_commit(connection)

    monkeypatch.setattr(SQLiteCaseStore, "_commit", staticmethod(reject_second_commit))
    with pytest.raises(CaseStoreError) as caught:
        opened.execute_observation(
            registry(lambda _: b"revision-B"),
            request_id="req-1",
            finish_id="finish-1",
            expected=opened.snapshot().checkpoint,
        )
    assert caught.value.outcome == "unknown"
    assert caught.value.observed_bytes == b"revision-B"
    reopened = SQLiteCaseStore(path, authority=authority, expected_plan_head=journal.head_digest)
    assert reopened.snapshot().pending_request_id == "req-1"
    assert reopened.snapshot().observed_bytes is None


def test_bridge_reentrant_request_is_rejected_before_nested_callback(tmp_path):
    path, authority, journal, opened = store(tmp_path)
    before = opened.snapshot().checkpoint
    nested_calls = []

    def callback(_):
        with pytest.raises(ValidationError, match="bridge is already active"):
            opened.execute_observation(
                registry(lambda raw: nested_calls.append(raw) or b"nested"),
                request_id="nested",
                finish_id="nested-finish",
                expected=before,
            )
        return b"revision-B"

    finished = opened.execute_observation(
        registry(callback), request_id="req-1", finish_id="finish-1", expected=before
    )
    assert nested_calls == []
    reopened = SQLiteCaseStore(path, authority=authority, expected_plan_head=journal.head_digest)
    assert reopened.snapshot().checkpoint == finished.result.checkpoint
    assert reopened.lookup_operation("nested") is None


def test_uncertain_claim_ack_never_enters_adapter(tmp_path, monkeypatch):
    path, authority, journal, opened = store(tmp_path)
    calls = []
    selected = registry(lambda raw: calls.append(raw) or b"revision-B")
    before = opened.snapshot().checkpoint
    digest = opened.claim_request_digest(selected, request_id="req-1", expected=before)
    real_commit = SQLiteCaseStore._commit

    def commit_then_lose_ack(connection):
        real_commit(connection)
        raise OSError("lost claim acknowledgement")

    monkeypatch.setattr(SQLiteCaseStore, "_commit", staticmethod(commit_then_lose_ack))
    with pytest.raises(CaseStoreError) as caught:
        opened.execute_observation(
            selected, request_id="req-1", finish_id="finish-1", expected=before
        )
    assert caught.value.outcome == "unknown"
    assert calls == []
    monkeypatch.setattr(SQLiteCaseStore, "_commit", staticmethod(real_commit))
    reopened = SQLiteCaseStore(path, authority=authority, expected_plan_head=journal.head_digest)
    with pytest.raises(CaseStoreConflictError):
        reopened.execute_observation(
            selected, request_id="req-1", finish_id="finish-1", expected=before
        )
    assert calls == []
    assert reopened.lookup("req-1", expected_request_digest=digest) is not None
    assert reopened.snapshot().pending_request_id == "req-1"


def test_external_checkpoint_detects_coherent_older_copy(tmp_path):
    path, authority, journal, opened = store(tmp_path)
    copied = tmp_path / "older.db"
    shutil.copyfile(path, copied)
    latest = opened.execute_observation(
        registry(lambda _: b"revision-B"),
        request_id="req-1",
        finish_id="finish-1",
        expected=opened.snapshot().checkpoint,
    ).result.checkpoint
    assert SQLiteCaseStore(copied, authority=authority, expected_plan_head=journal.head_digest)
    with pytest.raises(CaseStoreConflictError):
        SQLiteCaseStore(
            copied, authority=authority, expected_plan_head=journal.head_digest, expected=latest
        )


def test_output_bound_and_invalid_utf8_are_error_not_supported(tmp_path):
    path, authority, journal, opened = store(tmp_path)
    result = opened.execute_observation(
        registry(lambda _: b"x" * 4097),
        request_id="req-1",
        finish_id="finish-1",
        expected=opened.snapshot().checkpoint,
    )
    assert result.result.observed_bytes is None
    assert result.result.journal.receipts[1].record.status is api.CaseObservationStatus.ERROR
    reopened = SQLiteCaseStore(path, authority=authority, expected_plan_head=journal.head_digest)
    verdict = reopened.append_checked_verdict(
        operation_id="verdict-1", evaluator_id="evaluator", expected=result.result.checkpoint
    )
    assert verdict.result.journal.receipts[2].record.outcome is api.CaseVerdictOutcome.INCONCLUSIVE

    second = tmp_path / "second"
    second.mkdir()
    _, _, _, second_store = store(second)
    second_result = second_store.execute_observation(
        registry(lambda _: b"\xff"),
        request_id="req-1",
        finish_id="finish-1",
        expected=second_store.snapshot().checkpoint,
    )
    assert second_result.result.observed_bytes is None
    assert second_result.result.journal.receipts[1].record.error_code == "invalid_adapter_output"


def test_exact_4096_output_is_retained_after_reopen(tmp_path):
    path, authority, journal, opened = store(tmp_path)
    value = b"z" * 4096
    result = opened.execute_observation(
        registry(lambda _: value),
        request_id="req-1",
        finish_id="finish-1",
        expected=opened.snapshot().checkpoint,
    )
    reopened = SQLiteCaseStore(
        path,
        authority=authority,
        expected_plan_head=journal.head_digest,
        expected=result.result.checkpoint,
    )
    assert reopened.snapshot().observed_bytes == value
    assert reopened.snapshot().journal.receipts[1].record.observed_sha256 == sha(value)


def test_unsupported_store_version_fails_closed(tmp_path):
    path, authority, journal, _ = store(tmp_path)
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("PRAGMA user_version=2")
        connection.commit()
    with pytest.raises(ValidationError):
        SQLiteCaseStore(path, authority=authority, expected_plan_head=journal.head_digest)


def _update_protected(path, table, statement, parameters=()):
    """Mutate a test database while restoring its original closed trigger schema."""
    trigger_name = f"{table}_no_update"
    with closing(sqlite3.connect(path)) as connection:
        trigger = connection.execute(
            "SELECT sql FROM sqlite_schema WHERE name=?", (trigger_name,)
        ).fetchone()[0]
        connection.execute(f"DROP TRIGGER {trigger_name}")
        connection.execute(statement, parameters)
        connection.execute(trigger)
        connection.commit()


def _delete_protected(path, table, where):
    trigger_name = f"{table}_no_delete"
    with closing(sqlite3.connect(path)) as connection:
        trigger = connection.execute(
            "SELECT sql FROM sqlite_schema WHERE name=?", (trigger_name,)
        ).fetchone()[0]
        connection.execute(f"DROP TRIGGER {trigger_name}")
        connection.execute(f"DELETE FROM {table} WHERE {where}")
        connection.execute(trigger)
        connection.commit()


_STORE_DOMAIN = b"evidence-braid:case-store:v1\x00"
_CASE_DOMAIN = b"evidence-braid:epistemic-case:v1\x00"
_OP_INPUT_FIELDS = (
    "operation_type",
    "operation_id",
    "request_id",
    "expected",
    "adapter_key",
    "payload_digest",
    "status",
    "record_digest",
    "evaluator_id",
)


def _rewrite_operation(path, sequence, change, *, rehash=True):
    with closing(sqlite3.connect(path)) as connection:
        raw = connection.execute(
            "SELECT document FROM case_operations WHERE sequence=?", (sequence,)
        ).fetchone()[0]
    node = json.loads(raw)
    node.update(change)
    if rehash:
        content = {name: node[name] for name in _OP_INPUT_FIELDS}
        node["request_digest"] = sha(
            _STORE_DOMAIN + b"Q" + canonical_json(content, pretty=False).encode("utf-8")
        )
        node["digest"] = sha(
            _STORE_DOMAIN
            + b"O"
            + canonical_json(
                {key: value for key, value in node.items() if key != "digest"}, pretty=False
            ).encode("utf-8")
        )
    admitted = canonical_json(node, pretty=False).encode("utf-8")
    _update_protected(
        path,
        "case_operations",
        "UPDATE case_operations SET document=? WHERE sequence=?",
        (admitted, sequence),
    )


@pytest.mark.parametrize(
    "target",
    [
        "context",
        "receipt",
        "operation",
        "meta",
        "payload_digest",
        "payload_type",
        "orphan_payload",
        "extra_schema",
    ],
)
def test_closed_store_rejects_tampered_history_or_schema(tmp_path, target):
    path, authority, journal, opened = store(tmp_path)
    opened.execute_observation(
        registry(lambda _: b"revision-B"),
        request_id="req-1",
        finish_id="finish-1",
        expected=opened.snapshot().checkpoint,
    )
    if target == "context":
        _update_protected(path, "case_context", "UPDATE case_context SET document=?", (b"{}",))
    elif target == "receipt":
        _update_protected(
            path, "case_receipts", "UPDATE case_receipts SET document=? WHERE sequence=1", (b"{}",)
        )
    elif target == "operation":
        _update_protected(
            path,
            "case_operations",
            "UPDATE case_operations SET document=? WHERE sequence=1",
            (b"{}",),
        )
    elif target == "meta":
        with closing(sqlite3.connect(path)) as connection:
            connection.execute("UPDATE case_meta SET document=?", (b"{}",))
            connection.commit()
    elif target == "payload_digest":
        _update_protected(
            path,
            "case_payloads",
            "UPDATE case_payloads SET digest=? WHERE role='output'",
            ("0" * 64,),
        )
    elif target == "payload_type":
        _update_protected(
            path,
            "case_payloads",
            "UPDATE case_payloads SET content=? WHERE role='output'",
            ("text",),
        )
    elif target == "orphan_payload":
        with closing(sqlite3.connect(path)) as connection:
            connection.execute(
                "INSERT INTO case_payloads VALUES (?,?,?,?)",
                ("extra", "extra-1", sha(b"extra"), b"extra"),
            )
            connection.commit()
    else:
        with closing(sqlite3.connect(path)) as connection:
            connection.execute("CREATE TABLE attacker (x BLOB)")
            connection.commit()
    with pytest.raises((ValidationError, CaseStoreError)):
        SQLiteCaseStore(path, authority=authority, expected_plan_head=journal.head_digest)


@pytest.mark.parametrize(
    "sequence, change, expected_error, rehash",
    [
        (0, {"operation_id": "mismatch"}, "header differs", True),
        (0, {"request_id": "other-request"}, "claim structure differs", True),
        (
            0,
            {"adapter_key": ["other-test", "fixture-cache", "1", "observer"]},
            "claimed adapter differs",
            True,
        ),
        (
            0,
            {"adapter_key": ["cache-bypass", "fixture-cache", "1", "model"]},
            "claimed observer lacks authority",
            True,
        ),
        (0, {"request_digest": "0" * 64}, "request digest differs", False),
        (0, {"previous_digest": "0" * 64}, "previous checkpoint differs", True),
        (0, {"digest": "0" * 64}, "operation does not bind", False),
        (0, {"operation_type": "unknown"}, "unsupported case store operation type", True),
        (
            1,
            {"adapter_key": ["cache-bypass", "fixture-cache", "1", "observer"]},
            "finish structure differs",
            True,
        ),
        (1, {"record_digest": "0" * 64}, "finish does not bind", True),
        (2, {"status": "observed"}, "verdict structure differs", True),
        (2, {"record_digest": "0" * 64}, "verdict operation differs", True),
    ],
)
def test_coherently_rehashed_operation_forgery_rejected(
    tmp_path, sequence, change, expected_error, rehash
):
    path, authority, journal, opened = store(tmp_path)
    finished = opened.execute_observation(
        registry(lambda _: b"revision-B"),
        request_id="req-1",
        finish_id="finish-1",
        expected=opened.snapshot().checkpoint,
    )
    opened.append_checked_verdict(
        operation_id="verdict-1", evaluator_id="evaluator", expected=finished.result.checkpoint
    )
    _rewrite_operation(path, sequence, change, rehash=rehash)
    with pytest.raises(ValidationError, match=expected_error):
        SQLiteCaseStore(path, authority=authority, expected_plan_head=journal.head_digest)


@pytest.mark.parametrize(
    "target, expected_error",
    [
        ("missing_meta", "singleton missing"),
        ("changed_context_case", "context differs from exact plan"),
        ("receipt_gap", "receipt sequence is not contiguous"),
        ("missing_payload", "payload inventory differs"),
        ("unknown_payload_role", "payload role differs"),
        ("orphan_output", "orphan output BLOB"),
        ("operation_gap", "operation sequence differs"),
        ("wrong_meta_head", "checkpoint differs from its history"),
    ],
)
def test_reopen_rejects_structural_tamper(tmp_path, target, expected_error):
    path, authority, journal, opened = store(tmp_path)
    if target in {"operation_gap", "wrong_meta_head"}:
        opened.claim_observation(
            registry(lambda _: b"revision-B"),
            request_id="req-1",
            expected=opened.snapshot().checkpoint,
        )
    if target == "missing_meta":
        with closing(sqlite3.connect(path)) as connection:
            connection.execute("DELETE FROM case_meta")
            connection.commit()
    elif target == "changed_context_case":
        with closing(sqlite3.connect(path)) as connection:
            value = json.loads(
                connection.execute("SELECT document FROM case_context").fetchone()[0]
            )
        value["case_id"] = "other-case"
        _update_protected(
            path,
            "case_context",
            "UPDATE case_context SET document=?",
            (canonical_json(value, pretty=False).encode("utf-8"),),
        )
    elif target == "receipt_gap":
        _update_protected(
            path, "case_receipts", "UPDATE case_receipts SET sequence=7 WHERE sequence=0"
        )
    elif target == "missing_payload":
        _delete_protected(path, "case_payloads", "role='input'")
    elif target == "unknown_payload_role":
        with closing(sqlite3.connect(path)) as connection:
            connection.execute(
                "INSERT INTO case_payloads VALUES (?,?,?,?)", ("other", "other-1", sha(b"x"), b"x")
            )
            connection.commit()
    elif target == "orphan_output":
        with closing(sqlite3.connect(path)) as connection:
            connection.execute(
                "INSERT INTO case_payloads VALUES (?,?,?,?)",
                ("output", "observed-fake", sha(b"x"), b"x"),
            )
            connection.commit()
    elif target == "operation_gap":
        _update_protected(
            path, "case_operations", "UPDATE case_operations SET sequence=7 WHERE sequence=0"
        )
    else:
        with closing(sqlite3.connect(path)) as connection:
            value = json.loads(connection.execute("SELECT document FROM case_meta").fetchone()[0])
            value["case_head"] = "0" * 64
            connection.execute(
                "UPDATE case_meta SET document=?",
                (canonical_json(value, pretty=False).encode("utf-8"),),
            )
            connection.commit()
    with pytest.raises(ValidationError, match=expected_error):
        SQLiteCaseStore(path, authority=authority, expected_plan_head=journal.head_digest)


@pytest.mark.parametrize("missing", ["finish", "verdict"])
def test_reopen_rejects_operation_with_missing_receipt_as_validation_error(tmp_path, missing):
    path, authority, journal, opened = store(tmp_path)

    def unavailable(_):
        raise RuntimeError("adapter unavailable")

    finished = opened.execute_observation(
        registry(unavailable),
        request_id="req-1",
        finish_id="finish-1",
        expected=opened.snapshot().checkpoint,
    )
    if missing == "verdict":
        opened.append_checked_verdict(
            operation_id="verdict-1",
            evaluator_id="evaluator",
            expected=finished.result.checkpoint,
        )
    _delete_protected(path, "case_receipts", f"sequence={1 if missing == 'finish' else 2}")
    with pytest.raises(ValidationError, match=f"case {missing} receipt missing"):
        SQLiteCaseStore(path, authority=authority, expected_plan_head=journal.head_digest)


@pytest.mark.parametrize(
    "raw",
    [
        b"not-json",
        b'{"duplicate":1,"duplicate":2}',
        b'{"x":NaN}',
        b'{"x":1.5}',
        b' {"x":1}',
    ],
)
def test_noncanonical_context_document_rejected(tmp_path, raw):
    path, authority, journal, _ = store(tmp_path)
    _update_protected(path, "case_context", "UPDATE case_context SET document=?", (raw,))
    with pytest.raises((ValidationError, CaseStoreError)):
        SQLiteCaseStore(path, authority=authority, expected_plan_head=journal.head_digest)


def test_lookup_digest_conflict_and_stale_verdict(tmp_path):
    _, _, _, opened = store(tmp_path)
    first = opened.snapshot().checkpoint
    claim = opened.claim_observation(
        registry(lambda _: b"revision-B"), request_id="req-1", expected=first
    )
    with pytest.raises(CaseStoreConflictError):
        opened.claim_observation(
            registry(lambda _: b"revision-B"), request_id="req-1", expected=first
        )
    assert opened.lookup("req-1", expected_request_digest=claim.request_digest) == claim
    with pytest.raises(CaseStoreConflictError):
        opened.lookup("req-1", expected_request_digest="0" * 64)
    with pytest.raises(CaseStoreConflictError):
        opened.claim_observation(
            registry(lambda _: b"revision-B"), request_id="req-2", expected=first
        )
    finished = opened.finish_observation(
        request_id="req-1",
        operation_id="finish-1",
        expected=claim.result.checkpoint,
        output=b"revision-B",
    )
    with pytest.raises(CaseStoreConflictError):
        opened.finish_observation(
            request_id="req-1",
            operation_id="finish-1",
            expected=claim.result.checkpoint,
            output=b"revision-B",
        )
    assert opened.lookup("finish-1", expected_request_digest=finished.request_digest) == finished
    with pytest.raises(CaseStoreConflictError):
        opened.append_checked_verdict(
            operation_id="verdict-1", evaluator_id="evaluator", expected=claim.result.checkpoint
        )
    with pytest.raises(ValidationError):
        opened.append_checked_verdict(
            operation_id="verdict-1", evaluator_id="model", expected=finished.result.checkpoint
        )
    assert opened.snapshot().checkpoint == finished.result.checkpoint


@pytest.mark.parametrize(
    "behavior, code",
    [
        ("raise", "adapter_error"),
        ("nonbytes", "invalid_adapter_output"),
        ("bad_utf8", "invalid_adapter_output"),
    ],
)
def test_callback_failure_stays_error_and_unpublished_output(tmp_path, behavior, code):
    path, authority, journal, opened = store(tmp_path)

    def callback(_):
        if behavior == "raise":
            raise RuntimeError("secret details")
        if behavior == "nonbytes":
            return bytearray(b"revision-B")
        return b"\xff"

    result = opened.execute_observation(
        registry(callback),
        request_id="req-1",
        finish_id="finish-1",
        expected=opened.snapshot().checkpoint,
    )
    observation = result.result.journal.receipts[1].record
    assert observation.status is api.CaseObservationStatus.ERROR
    assert observation.error_code == code
    assert result.result.observed_bytes is None
    reopened = SQLiteCaseStore(path, authority=authority, expected_plan_head=journal.head_digest)
    assert reopened.snapshot().observed_bytes is None


def test_direct_finish_rejects_inconsistent_status_and_output(tmp_path):
    _, _, _, opened = store(tmp_path)
    claim = opened.claim_observation(
        registry(lambda _: b"revision-B"), request_id="req-1", expected=opened.snapshot().checkpoint
    )
    before = claim.result.checkpoint
    with pytest.raises(ValidationError, match="invalid case observation status"):
        opened.finish_observation(
            request_id="req-1",
            operation_id="finish-1",
            expected=before,
            status="observed",
            output=b"revision-B",
        )
    with pytest.raises(CaseStoreConflictError, match="claim differs"):
        opened.finish_observation(
            request_id="other-request",
            operation_id="finish-1",
            expected=before,
            output=b"revision-B",
        )
    with pytest.raises(ValidationError):
        opened.finish_observation(
            request_id="req-1",
            operation_id="finish-1",
            expected=before,
            status=api.CaseObservationStatus.ERROR,
            error_code="bad",
            output=b"revision-B",
        )
    with pytest.raises(ValidationError):
        opened.finish_observation(
            request_id="req-1",
            operation_id="finish-1",
            expected=before,
            status=api.CaseObservationStatus.ERROR,
        )
    with pytest.raises(ValidationError):
        opened.finish_observation(
            request_id="req-1",
            operation_id="finish-1",
            expected=before,
            output=b"revision-B",
            error_code="bad",
        )
    assert opened.snapshot().checkpoint == before


@pytest.mark.parametrize(
    "change",
    [
        {"schema_version": "2.0"},
        {"generation": True},
        {"record_count": 0},
        {"case_head": "not-a-hash"},
    ],
)
def test_checkpoint_parser_rejects_malformed_external_anchor(tmp_path, change):
    _, _, _, opened = store(tmp_path)
    value = opened.snapshot().checkpoint.to_dict()
    value.update(change)
    with pytest.raises(ValidationError):
        CaseStoreCheckpoint.from_dict(value)


@pytest.mark.parametrize(
    "fault", ["wrong-authority", "wrong-head", "timeout", "snapshot-anchor-type", "lookup-digest"]
)
def test_open_and_read_reject_invalid_external_contract(tmp_path, fault):
    path, authority, journal, opened = store(tmp_path)
    if fault == "wrong-authority":
        with pytest.raises(ValidationError):
            SQLiteCaseStore(path, authority="untrusted", expected_plan_head=journal.head_digest)
    elif fault == "wrong-head":
        with pytest.raises(ValidationError):
            SQLiteCaseStore(path, authority=authority, expected_plan_head="x")
    elif fault == "timeout":
        with pytest.raises(ValidationError):
            SQLiteCaseStore(
                path, authority=authority, expected_plan_head=journal.head_digest, timeout=-1
            )
    elif fault == "snapshot-anchor-type":
        with pytest.raises(ValidationError):
            opened.snapshot(expected="not-a-checkpoint")
    else:
        with pytest.raises(ValidationError):
            opened.lookup("req-1", expected_request_digest="bad")


@pytest.mark.parametrize(
    "fault",
    ["wrong-assertion", "wrong-input", "oversize-assertion", "wrong-head", "wrong-authority"],
)
def test_create_rejects_invalid_independent_input(tmp_path, fault):
    authority, journal = fixture()
    path = tmp_path / "rejected.db"
    kwargs = {
        "authority": authority,
        "expected_plan_head": journal.head_digest,
        "assertion_bytes": ASSERTION,
        "input_bytes": INPUT,
    }
    if fault == "wrong-assertion":
        kwargs["assertion_bytes"] = b"different"
    elif fault == "wrong-input":
        kwargs["input_bytes"] = b"different"
    elif fault == "oversize-assertion":
        kwargs["assertion_bytes"] = b"x" * (64 * 1024 + 1)
    elif fault == "wrong-head":
        kwargs["expected_plan_head"] = "0" * 64
    else:
        kwargs["authority"] = api.CaseAuthority("wrong", authority.actors)
    with pytest.raises(ValidationError):
        create_case_store(path, journal, **kwargs)
    assert not path.exists()


def test_create_rejects_untyped_or_already_observed_journal(tmp_path):
    path, authority, journal, opened = store(tmp_path)
    invalid_path = tmp_path / "invalid.db"
    with pytest.raises(ValidationError, match="typed journal and authority"):
        create_case_store(
            invalid_path,
            journal.to_dict(),
            authority=authority,
            expected_plan_head=journal.head_digest,
            assertion_bytes=ASSERTION,
            input_bytes=INPUT,
        )
    assert not invalid_path.exists()
    observed = opened.execute_observation(
        registry(lambda _: b"revision-B"),
        request_id="req-1",
        finish_id="finish-1",
        expected=opened.snapshot().checkpoint,
    )
    with pytest.raises(ValidationError, match="exactly one plan"):
        create_case_store(
            invalid_path,
            observed.result.journal,
            authority=authority,
            expected_plan_head=observed.result.journal.head_digest,
            assertion_bytes=ASSERTION,
            input_bytes=INPUT,
        )
    assert path.exists() and not invalid_path.exists()


def test_unresolved_claim_cannot_be_verdicted_or_reclaimed(tmp_path):
    _, _, _, opened = store(tmp_path)
    selected = registry(lambda _: b"revision-B")
    claimed = opened.claim_observation(
        selected, request_id="req-1", expected=opened.snapshot().checkpoint
    )
    with pytest.raises(ValidationError):
        opened.append_checked_verdict(
            operation_id="verdict-1", evaluator_id="evaluator", expected=claimed.result.checkpoint
        )
    with pytest.raises(CaseStoreConflictError):
        opened.claim_observation(selected, request_id="req-2", expected=claimed.result.checkpoint)
    assert opened.snapshot().pending_request_id == "req-1"


def test_file_identity_replacement_is_rejected(tmp_path):
    path, _, _, opened = store(tmp_path)
    replacement_dir = tmp_path / "replacement"
    replacement_dir.mkdir()
    other_path, _, _, _ = store(replacement_dir)
    displaced = tmp_path / "displaced.db"
    path.rename(displaced)
    shutil.copyfile(other_path, path)
    with pytest.raises(ValidationError, match="identity changed"):
        opened.snapshot()


@pytest.mark.parametrize(
    "actual, expected",
    [
        (b"revision-C", api.CaseVerdictOutcome.REFUTED),
        (b"", api.CaseVerdictOutcome.REFUTED),
    ],
)
def test_reopen_computes_refutation_from_stored_bytes(tmp_path, actual, expected):
    path, authority, journal, opened = store(tmp_path)
    result = opened.execute_observation(
        registry(lambda _: actual),
        request_id="req-1",
        finish_id="finish-1",
        expected=opened.snapshot().checkpoint,
    )
    reopened = SQLiteCaseStore(path, authority=authority, expected_plan_head=journal.head_digest)
    verdict = reopened.append_checked_verdict(
        operation_id="verdict-1", evaluator_id="evaluator", expected=result.result.checkpoint
    )
    assert verdict.result.journal.receipts[2].record.outcome is expected


def test_unavailable_is_inconclusive_and_keeps_no_output(tmp_path):
    path, authority, journal, opened = store(tmp_path)

    def unavailable(_):
        raise api.ObservationUnavailable()

    result = opened.execute_observation(
        registry(unavailable),
        request_id="req-1",
        finish_id="finish-1",
        expected=opened.snapshot().checkpoint,
    )
    assert result.result.observed_bytes is None
    reopened = SQLiteCaseStore(path, authority=authority, expected_plan_head=journal.head_digest)
    verdict = reopened.append_checked_verdict(
        operation_id="verdict-1", evaluator_id="evaluator", expected=result.result.checkpoint
    )
    assert verdict.result.journal.receipts[2].record.outcome is api.CaseVerdictOutcome.INCONCLUSIVE


def test_failed_observation_cannot_gain_output_blob(tmp_path):
    path, authority, journal, opened = store(tmp_path)

    def unavailable(_):
        raise api.ObservationUnavailable()

    opened.execute_observation(
        registry(unavailable),
        request_id="req-1",
        finish_id="finish-1",
        expected=opened.snapshot().checkpoint,
    )
    with closing(sqlite3.connect(path)) as connection:
        connection.execute(
            "INSERT INTO case_payloads VALUES (?,?,?,?)",
            ("output", "observed-fake", sha(b"x"), b"x"),
        )
        connection.commit()
    with pytest.raises(ValidationError, match="failed observation has output BLOB"):
        SQLiteCaseStore(path, authority=authority, expected_plan_head=journal.head_digest)


@pytest.mark.parametrize(
    "removed, expected_error",
    [
        ("output", "observation and stored output differ"),
        ("input", "retained input inventory differs"),
    ],
)
def test_observed_case_requires_complete_payload_inventory(tmp_path, removed, expected_error):
    path, authority, journal, opened = store(tmp_path)
    opened.execute_observation(
        registry(lambda _: b"revision-B"),
        request_id="req-1",
        finish_id="finish-1",
        expected=opened.snapshot().checkpoint,
    )
    _delete_protected(path, "case_payloads", f"role='{removed}'")
    with pytest.raises(ValidationError, match=expected_error):
        SQLiteCaseStore(path, authority=authority, expected_plan_head=journal.head_digest)


def test_close_failure_after_claim_ack_is_complete_and_lookup_recovers(tmp_path, monkeypatch):
    path, authority, journal, opened = store(tmp_path)
    before = opened.snapshot().checkpoint
    selected = registry(lambda _: b"revision-B")
    digest = opened.claim_request_digest(selected, request_id="req-1", expected=before)
    real_close = SQLiteCaseStore._close
    closes = 0

    def close_then_fail(connection):
        nonlocal closes
        closes += 1
        real_close(connection)
        if closes == 2:
            raise OSError("close acknowledgement unavailable")

    monkeypatch.setattr(SQLiteCaseStore, "_close", staticmethod(close_then_fail))
    with pytest.raises(CaseStoreError) as caught:
        opened.claim_observation(selected, request_id="req-1", expected=before)
    assert caught.value.outcome == "complete"
    monkeypatch.setattr(SQLiteCaseStore, "_close", staticmethod(real_close))
    reopened = SQLiteCaseStore(path, authority=authority, expected_plan_head=journal.head_digest)
    assert reopened.lookup("req-1", expected_request_digest=digest) is not None


def test_close_failure_after_finish_ack_retains_atomic_output(tmp_path, monkeypatch):
    path, authority, journal, opened = store(tmp_path)
    claim = opened.claim_observation(
        registry(lambda _: b"revision-B"), request_id="req-1", expected=opened.snapshot().checkpoint
    )
    digest = opened.finish_request_digest(
        request_id="req-1",
        operation_id="finish-1",
        expected=claim.result.checkpoint,
        output=b"revision-B",
    )
    real_close = SQLiteCaseStore._close

    def close_then_fail_after_write(connection):
        wrote = connection.total_changes > 0
        real_close(connection)
        if wrote:
            raise OSError("finish close acknowledgement unavailable")

    monkeypatch.setattr(SQLiteCaseStore, "_close", staticmethod(close_then_fail_after_write))
    with pytest.raises(CaseStoreError) as caught:
        opened.finish_observation(
            request_id="req-1",
            operation_id="finish-1",
            expected=claim.result.checkpoint,
            output=b"revision-B",
        )
    assert caught.value.outcome == "complete"
    assert caught.value.request_digest == digest
    monkeypatch.setattr(SQLiteCaseStore, "_close", staticmethod(real_close))
    reopened = SQLiteCaseStore(path, authority=authority, expected_plan_head=journal.head_digest)
    recovered = reopened.lookup("finish-1", expected_request_digest=digest)
    assert recovered is not None and recovered.result.observed_bytes == b"revision-B"


def test_database_replacement_during_open_is_rejected(tmp_path, monkeypatch):
    _, _, _, opened = store(tmp_path)
    real_regular = case_storage_module._regular
    calls = 0

    def changing_identity(path):
        nonlocal calls
        calls += 1
        value = real_regular(path)
        return value if calls == 1 else (value[0], value[1] + 1)

    monkeypatch.setattr(case_storage_module, "_regular", changing_identity)
    with pytest.raises(ValidationError, match="changed during open"):
        opened.snapshot()
    monkeypatch.setattr(case_storage_module, "_regular", real_regular)
    assert opened.snapshot().checkpoint.operation_count == 0


def test_writers_racing_after_successful_preflight_recheck_cas(tmp_path, monkeypatch):
    path, authority, journal, first = store(tmp_path)
    second = SQLiteCaseStore(path, authority=authority, expected_plan_head=journal.head_digest)
    before = first.snapshot().checkpoint
    original_preflight = SQLiteCaseStore._claim_key
    barrier = Barrier(2)

    def synchronized_preflight(self, registry_value, *, request_id, expected):
        key = original_preflight(self, registry_value, request_id=request_id, expected=expected)
        barrier.wait(timeout=10)
        return key

    monkeypatch.setattr(SQLiteCaseStore, "_claim_key", synchronized_preflight)

    def submit(selected_store, request_id):
        try:
            selected_store.claim_observation(
                registry(lambda _: b"revision-B"), request_id=request_id, expected=before
            )
        except CaseStoreConflictError:
            return "conflict"
        return "won"

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(submit, selected_store, request_id)
            for selected_store, request_id in ((first, "req-1"), (second, "req-2"))
        ]
        results = sorted(future.result(timeout=15) for future in futures)
    assert results == ["conflict", "won"]
    assert first.snapshot().checkpoint.operation_count == 1


def test_coherently_rehashed_fake_observation_artifact_is_rejected(tmp_path):
    path, authority, journal, opened = store(tmp_path)
    opened.execute_observation(
        registry(lambda _: b"revision-B"),
        request_id="req-1",
        finish_id="finish-1",
        expected=opened.snapshot().checkpoint,
    )
    with closing(sqlite3.connect(path)) as connection:
        receipt = json.loads(
            connection.execute("SELECT document FROM case_receipts WHERE sequence=1").fetchone()[0]
        )
    receipt["record"]["artifact_id"] = "observed-fake"
    observation_bytes = canonical_json(receipt["record"], pretty=False).encode("utf-8")
    observation_digest = sha(_CASE_DOMAIN + b"O" + observation_bytes)
    receipt["digest"] = sha(
        _CASE_DOMAIN
        + b"R"
        + (1).to_bytes(4, "big")
        + bytes.fromhex(receipt["previous_digest"])
        + observation_bytes
    )
    _update_protected(
        path,
        "case_receipts",
        "UPDATE case_receipts SET document=? WHERE sequence=1",
        (canonical_json(receipt, pretty=False).encode("utf-8"),),
    )
    _update_protected(
        path,
        "case_payloads",
        "UPDATE case_payloads SET artifact_id=? WHERE role='output'",
        ("observed-fake",),
    )
    _rewrite_operation(
        path, 1, {"record_digest": observation_digest, "result_case_head": receipt["digest"]}
    )
    with closing(sqlite3.connect(path)) as connection:
        operation = json.loads(
            connection.execute("SELECT document FROM case_operations WHERE sequence=1").fetchone()[
                0
            ]
        )
        meta = json.loads(connection.execute("SELECT document FROM case_meta").fetchone()[0])
        meta["case_head"] = receipt["digest"]
        meta["operation_head"] = operation["digest"]
        connection.execute(
            "UPDATE case_meta SET document=?", (canonical_json(meta, pretty=False).encode("utf-8"),)
        )
        connection.commit()
    with pytest.raises(ValidationError, match="observed artifact identity differs"):
        SQLiteCaseStore(path, authority=authority, expected_plan_head=journal.head_digest)


@pytest.mark.parametrize(
    "target", ["payload_role", "artifact_id", "payload_digest", "operation_id", "schema_name"]
)
def test_oversized_untrusted_metadata_rejected_before_row_fetch(tmp_path, target):
    path, authority, journal, _ = store(tmp_path)
    oversized = "x" * (128 * 1024)
    if target == "payload_role":
        with closing(sqlite3.connect(path)) as connection:
            connection.execute(
                "INSERT INTO case_payloads VALUES (?,?,?,?)",
                (oversized, "artifact-1", sha(b""), b""),
            )
            connection.commit()
    elif target == "artifact_id":
        _update_protected(
            path,
            "case_payloads",
            "UPDATE case_payloads SET artifact_id=? WHERE role='assertion'",
            (oversized,),
        )
    elif target == "payload_digest":
        _update_protected(
            path,
            "case_payloads",
            "UPDATE case_payloads SET digest=? WHERE role='assertion'",
            (oversized,),
        )
    elif target == "operation_id":
        with closing(sqlite3.connect(path)) as connection:
            connection.execute("INSERT INTO case_operations VALUES (?,?,?)", (0, oversized, b"{}"))
            connection.commit()
    else:
        with closing(sqlite3.connect(path)) as connection:
            connection.execute(f'CREATE TABLE "{oversized}" (x BLOB)')
            connection.commit()
    with pytest.raises(ValidationError, match="metadata bounds"):
        SQLiteCaseStore(path, authority=authority, expected_plan_head=journal.head_digest)


def test_mistyped_schema_sql_rejected_before_schema_row_fetch(tmp_path):
    path, authority, journal, _ = store(tmp_path)
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("PRAGMA writable_schema=ON")
        connection.execute(
            "UPDATE sqlite_schema SET sql=cast(sql AS BLOB) WHERE name='case_payloads_no_update'"
        )
        connection.commit()
    with pytest.raises(ValidationError, match="schema metadata bounds"):
        SQLiteCaseStore(path, authority=authority, expected_plan_head=journal.head_digest)


def test_bounded_but_altered_schema_sql_rejected(tmp_path):
    path, authority, journal, _ = store(tmp_path)
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("PRAGMA writable_schema=ON")
        connection.execute(
            "UPDATE sqlite_schema SET sql=sql||' ' WHERE name='case_payloads_no_update'"
        )
        connection.commit()
    with pytest.raises(ValidationError, match="closed format"):
        SQLiteCaseStore(path, authority=authority, expected_plan_head=journal.head_digest)


@pytest.mark.parametrize("target", ["role", "artifact_id", "digest", "operation_id"])
def test_mistyped_sqlite_metadata_rejected_before_row_fetch(tmp_path, target):
    path, authority, journal, opened = store(tmp_path)
    if target == "operation_id":
        opened.claim_observation(
            registry(lambda _: b"revision-B"),
            request_id="req-1",
            expected=opened.snapshot().checkpoint,
        )
        _update_protected(
            path,
            "case_operations",
            "UPDATE case_operations SET operation_id=? WHERE sequence=0",
            (b"req-1",),
        )
    else:
        current = {
            "role": b"assertion",
            "artifact_id": b"assertion-1",
            "digest": sha(ASSERTION).encode("ascii"),
        }[target]
        _update_protected(
            path,
            "case_payloads",
            f"UPDATE case_payloads SET {target}=? WHERE role='assertion'",
            (current,),
        )
    with pytest.raises(ValidationError, match="metadata bounds"):
        SQLiteCaseStore(path, authority=authority, expected_plan_head=journal.head_digest)
