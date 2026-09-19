from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import evidence_braid as eb
from evidence_braid import _workflow_service_wire as wire
from tests.test_workflow import evidence_event
from tests.test_workflow_service import canonical
from tests.test_workflow_service_oracles import TOKENS, configured, sdk
from tests.test_workflow_storage import command


@pytest.mark.parametrize("optimized", [False, True])
def test_actual_isolated_loopback_example(optimized):
    example = Path(__file__).parents[1] / "examples" / "local_workflow_service.py"
    result = subprocess.run(
        [sys.executable, "-I", *(["-O"] if optimized else []), str(example)],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert json.loads(result.stdout) == {
        "record_count": 2,
        "operation_count": 2,
        "historical_count": 1,
        "service_closed": True,
    }
    assert result.stderr == ""


def test_whole_scope_disclosure_and_maximum_existing_attribute_domain(tmp_path):
    policy = eb.AuthorityPolicy(
        "scopes",
        tuple(
            eb.WorkflowActor(
                actor, eb.ActorKind.HUMAN, (eb.ScopeGrant(scope, eb.AuthorityRole.AUTHOR),)
            )
            for actor, scope in (("alice", "scope/a"), ("bob", "scope/b"))
        ),
    )
    nested = -(10**640 - 1)
    # LedgerEntry freezes the whole event: its attributes wrapper consumes one
    # extra level compared with EvidenceEvent's standalone attribute validator.
    for _ in range(62):
        nested = {"x": nested}
    event = evidence_event(attributes={"nested": nested})
    bundle = eb.build_workflow(
        "whole-scope", authority=policy, evidence=eb.build_ledger([event])
    ).append(
        [command("one", actor_id="alice"), command("two", actor_id="bob", scope="scope/b")],
        authority=policy,
    )
    store = eb.create_workflow_store(
        tmp_path / "whole.db",
        bundle,
        authority=policy,
        expected_context=bundle.context_digest,
        expected_head=bundle.head_digest,
    )
    before = store.snapshot()
    credential = eb.WorkflowServiceCredential(
        "reader", "alice", hashlib.sha256(bytes.fromhex(TOKENS["alice"])).hexdigest(), "read"
    )
    server = eb.LocalWorkflowService(
        database=store.path,
        authority=policy,
        expected_workflow_id=bundle.workflow_id,
        expected_context=bundle.context_digest,
        startup_checkpoint=before.checkpoint,
        service_id="whole",
        credentials=(credential,),
    )
    with server:
        client = eb.WorkflowClient(
            address=server.address,
            token=TOKENS["alice"],
            service_id="whole",
            actor_id="alice",
            workflow_id=bundle.workflow_id,
            context_digest=bundle.context_digest,
            authority=policy,
        )
        result = client.snapshot()
        assert result == before
        assert [item.transition.scope for item in result.bundle.records] == ["scope/a", "scope/b"]
        client.close()


def test_maximum_envelope_reservation_has_independent_byte_proof():
    cp = {
        "schema_version": "1.0",
        "context_digest": "f" * 64,
        "record_count": 1000,
        "workflow_head": "f" * 64,
        "operation_count": 1000,
        "operation_head": "f" * 64,
    }
    envelope = {
        "schema_version": "1.0",
        "service_id": "a" * 128,
        "workflow_id": "b" * 128,
        "context_digest": "c" * 64,
        "actor_id": "d" * 128,
        "operation": "snapshot",
        "request_id": "e" * 58,
        "request_digest": "f" * 64,
        "outcome": "complete",
        "result": {
            "request_id": "a" * 128,
            "request_digest": "b" * 64,
            "previous": cp,
            "result": {"bundle": {}, "checkpoint": cp},
        },
    }
    # Variable wrapper IDs/digests/counts use maxima; bundle bytes are separate.
    overhead = len(canonical(envelope)) - len(canonical({}))
    assert overhead < 4096 < 65536
    assert (
        eb.WorkflowServiceLimits().response_bytes - eb.WorkflowServiceLimits().max_bundle_bytes
        == 65536
    )


def test_maximum_append_count_and_plus_one_are_actual_admission(tmp_path):
    server, _, before, policy = configured(tmp_path)
    with server:
        alice = sdk(server, policy)
        commands = [command(f"item-{index}", actor_id="alice") for index in range(128)]
        prepared = alice.prepare_append(commands, request_id="batch", expected=before.checkpoint)
        result = alice.append(prepared)
        assert (
            result.result.checkpoint.record_count == 128
            and result.result.checkpoint.operation_count == 1
        )
        with pytest.raises(eb.ValidationError):
            alice.prepare_append(
                [*commands, commands[0]], request_id="bad", expected=result.result.checkpoint
            )


@pytest.mark.parametrize("what", ["workflow", "checkpoint", "bind", "thread"])
def test_startup_failure_releases_owned_listener_and_cannot_restart(tmp_path, monkeypatch, what):
    server, _, _, _ = configured(tmp_path)
    if what == "workflow":
        server._workflow_id = "wrong"
    elif what == "checkpoint":
        server._checkpoint = eb.WorkflowCheckpoint(server._context, 0, server._context, 0, "0" * 64)
    elif what == "bind":

        class FailingSocket:
            closed = False

            def bind(self, address):
                raise OSError("bind denied")

            def close(self):
                self.closed = True

        peer = FailingSocket()
        monkeypatch.setattr(wire.socket, "socket", lambda *a: peer)
    else:
        monkeypatch.setattr(
            threading.Thread, "start", lambda *a: (_ for _ in ()).throw(OSError("start denied"))
        )
    with pytest.raises((eb.EvidenceBraidError, OSError)):
        server.start()
    assert server.state == "CLOSED" and server._listener is None
    with pytest.raises(eb.WorkflowServiceError):
        server.start()


def test_start_and_close_busy_guards_do_not_mutate_ownership(tmp_path):
    server, _, _, _ = configured(tmp_path)
    with pytest.raises(eb.WorkflowServiceError):
        _ = server.address
    with server:
        assert server.last_error is None
        with pytest.raises(eb.WorkflowServiceError):
            server.start()
        server._closer = threading.current_thread()
        try:
            with pytest.raises(eb.WorkflowServiceError):
                server.close()
            assert server.state == "RUNNING"
        finally:
            server._closer = None


def test_close_wait_is_bounded_for_concurrent_owner_and_startup(tmp_path):
    server, _, _, _ = configured(tmp_path)
    server._close_lock.acquire()
    try:
        with pytest.raises(eb.WorkflowServiceError) as caught:
            server.close(timeout_ms=1)
        assert caught.value.code == "shutdown_timeout"
    finally:
        server._close_lock.release()
    server._start_done.clear()
    try:
        with pytest.raises(eb.WorkflowServiceError) as caught:
            server.close(timeout_ms=1)
        assert caught.value.code == "shutdown_timeout"
    finally:
        server._start_done.set()
        server.close()


@pytest.mark.parametrize("credentials", [(), [], ({},)])
def test_registry_container_admission_without_side_effects(tmp_path, credentials):
    server, _, before, policy = configured(tmp_path)
    with pytest.raises(eb.ValidationError):
        eb.LocalWorkflowService(
            database=server._store.path,
            authority=policy,
            expected_workflow_id="pinned-one",
            expected_context=server._context,
            startup_checkpoint=before.checkpoint,
            service_id="one",
            credentials=credentials,
        )


def test_duplicate_credential_and_unknown_actor_rejected(tmp_path):
    server, _, before, policy = configured(tmp_path)
    for credentials in [
        (server._credentials[0], server._credentials[0]),
        (eb.WorkflowServiceCredential("new", "missing", "0" * 64, "read"),),
    ]:
        with pytest.raises(eb.ValidationError):
            eb.LocalWorkflowService(
                database=server._store.path,
                authority=policy,
                expected_workflow_id="pinned-one",
                expected_context=server._context,
                startup_checkpoint=before.checkpoint,
                service_id="one",
                credentials=credentials,
            )


def test_core_slot_admission_timeout_and_missing_checkpoint(tmp_path):
    from tests.test_workflow_service import raw

    server, _, _before, policy = configured(
        tmp_path, limits=eb.WorkflowServiceLimits(admission_ms=1)
    )
    with server:
        server._core.acquire()
        try:
            with pytest.raises(eb.WorkflowServiceError) as caught:
                sdk(server, policy).snapshot()
            assert caught.value.code == "unavailable" and caught.value.outcome == "none"
        finally:
            server._core.release()
        status, response = raw(
            server,
            "append",
            {
                "schema_version": "1.0",
                "request_id": "one",
                "request_digest": "0" * 64,
                "expected_checkpoint": None,
                "transitions": [command(actor_id="alice").to_dict()],
            },
            token=TOKENS["alice"],
        )
        assert status == 400 and response["outcome"] == "none"
