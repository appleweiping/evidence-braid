from __future__ import annotations

import hashlib
import json
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

import evidence_braid as eb
from tests.test_workflow_service import canonical, raw
from tests.test_workflow_storage import audit, command

TOKENS = {"alice": "02" * 32, "bob": "03" * 32, "rotate": "04" * 32, "read": "05" * 32}


def configured(tmp_path, *, limits=None):
    policy = eb.AuthorityPolicy(
        "service-policy",
        tuple(
            eb.WorkflowActor(
                name, eb.ActorKind.HUMAN, (eb.ScopeGrant("scope/a", eb.AuthorityRole.AUTHOR),)
            )
            for name in ("alice", "bob")
        ),
    )
    bundle = eb.build_workflow("pinned-one", authority=policy, evidence=eb.build_ledger([]))
    path = tmp_path / "pinned.db"
    store = eb.create_workflow_store(
        path,
        bundle,
        authority=policy,
        expected_context=bundle.context_digest,
        expected_head=bundle.head_digest,
    )
    before = store.snapshot()
    credentials = tuple(
        eb.WorkflowServiceCredential(
            label,
            label if label in ("alice", "bob") else "alice",
            hashlib.sha256(bytes.fromhex(token)).hexdigest(),
            "read" if label == "read" else "act",
        )
        for label, token in TOKENS.items()
    )
    server = eb.LocalWorkflowService(
        database=path,
        authority=policy,
        expected_workflow_id="pinned-one",
        expected_context=bundle.context_digest,
        startup_checkpoint=before.checkpoint,
        service_id="service-one",
        credentials=credentials,
        limits=limits,
    )
    return server, path, before, policy


def sdk(server, policy, *, label="alice", limits=None):
    return eb.WorkflowClient(
        address=server.address,
        token=TOKENS[label],
        service_id="service-one",
        actor_id=label if label in ("alice", "bob") else "alice",
        workflow_id="pinned-one",
        context_digest=server._context,
        authority=policy,
        limits=limits,
    )


def independent_id(actor, context, public):
    namespace = hashlib.sha256(
        canonical(
            {
                "kind": "evidence-braid-workflow-service-request-namespace",
                "schema_version": "1.0",
                "service_id": "service-one",
                "context_digest": context,
                "actor_id": actor,
            }
        )
    ).hexdigest()
    return "svc1." + namespace + "." + public


def refill(server):
    # Non-rate tests explicitly replenish finite buckets; rate tests have a separate clock oracle.
    with server._lock:
        for bucket in [server._global_bucket, *server._buckets.values()]:
            bucket.credit = bucket.rate * 1_000_000_000


def test_independent_namespace_and_digest_exact_maximum(tmp_path):
    server, _, before, policy = configured(tmp_path)
    with server:
        actor = sdk(server, policy)
        prepared = actor.prepare_append(
            [command(actor_id="alice")], request_id="a" * 58, expected=before.checkpoint
        )
        expected_id = independent_id("alice", before.checkpoint.context_digest, "a" * 58)
        assert len(expected_id) == len(prepared.core_request_id) == 128
        assert prepared.core_request_id == expected_id
        expected = {
            "kind": "evidence-braid-workflow-request",
            "schema_version": "1.0",
            "request_id": expected_id,
            "expected_checkpoint": before.checkpoint.to_dict(),
            "transitions": [command(actor_id="alice").to_dict()],
        }
        assert prepared.request_digest == hashlib.sha256(canonical(expected)).hexdigest()
        with pytest.raises(eb.ValidationError):
            actor.prepare_append(
                [command(actor_id="alice")], request_id="a" * 59, expected=before.checkpoint
            )


def test_rotation_historical_recovery_and_changed_intent(tmp_path):
    server, path, before, policy = configured(tmp_path)
    with server:
        alice = sdk(server, policy)
        prepared = alice.prepare_append(
            [command(actor_id="alice")], request_id="public-one", expected=before.checkpoint
        )
        first = alice.append(prepared)
        later = sdk(server, policy, label="bob").append(
            sdk(server, policy, label="bob").prepare_append(
                [command("second", actor_id="bob")],
                request_id="public-one",
                expected=first.result.checkpoint,
            )
        )
        assert later.request_id != first.request_id
        assert sdk(server, policy, label="rotate").append(prepared) == first
        assert (
            sdk(server, policy, label="read").lookup(
                request_id="public-one", expected_request_digest=prepared.request_digest
            )
            == first
        )
        refill(server)
        assert alice.snapshot().checkpoint == later.result.checkpoint
        assert alice.lookup(request_id="missing", expected_request_digest="0" * 64) is None
        changed = alice.prepare_append(
            [command("changed", actor_id="alice")],
            request_id="public-one",
            expected=before.checkpoint,
        )
        with pytest.raises(eb.WorkflowServiceError) as caught:
            alice.append(changed)
        assert (caught.value.code, caught.value.outcome) == ("conflict", "none")
    assert len(audit(path)[2]) == 2


def test_real_two_actor_competing_checkpoint_has_one_atomic_winner(tmp_path):
    server, path, before, policy = configured(tmp_path)
    with server:
        clients = [sdk(server, policy, label=actor) for actor in ("alice", "bob")]
        prepared = [
            item.prepare_append(
                [command(actor_id=name)], request_id="same-public", expected=before.checkpoint
            )
            for item, name in zip(clients, ("alice", "bob"), strict=True)
        ]
        barrier = threading.Barrier(2)

        def run(index):
            barrier.wait(timeout=5)
            try:
                return clients[index].append(prepared[index])
            except eb.WorkflowServiceError as error:
                return error

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(run, (0, 1)))
        assert sum(type(value) is eb.WorkflowCommit for value in results) == 1
        errors = [value for value in results if type(value) is eb.WorkflowServiceError]
        assert [(value.code, value.outcome) for value in errors] == [("conflict", "none")]
    assert len(audit(path)[1]) == len(audit(path)[2]) == 1


@pytest.mark.parametrize(
    "label, body_actor, expected",
    [
        ("alice", "bob", 403),
        ("read", "alice", 403),
        ("alice", "alice", 409),
    ],
)
def test_http_actor_capability_digest_bound_before_database(
    tmp_path, monkeypatch, label, body_actor, expected
):
    server, path, before, _ = configured(tmp_path)
    with server:
        calls = []
        monkeypatch.setattr(server._store, "_connect", lambda *a: calls.append(a))
        status, result = raw(
            server,
            "append",
            {
                "schema_version": "1.0",
                "request_id": "one",
                "request_digest": "0" * 64,
                "expected_checkpoint": before.checkpoint.to_dict(),
                "transitions": [command(actor_id=body_actor).to_dict()],
            },
            token=TOKENS[label],
        )
        assert status == expected and result["outcome"] == "none"
        assert calls == []
    assert audit(path)[2] == []


@pytest.mark.parametrize("token", ["ff" * 32, "secret", "AA" * 32])
def test_unknown_and_malformed_auth_does_not_open_store(tmp_path, monkeypatch, token):
    server, _, _, _ = configured(tmp_path)
    with server:
        monkeypatch.setattr(
            server._store, "_connect", lambda *a: pytest.fail("unauthenticated DB access")
        )
        status, reply = raw(
            server, "snapshot", {"schema_version": "1.0", "expected_checkpoint": None}, token=token
        )
        assert status == 401 and reply["outcome"] == "none"
        assert token not in json.dumps(reply)


@pytest.mark.parametrize(
    "phase, expected_outcome, expected_rows",
    [
        ("open", "none", 0),
        ("commit", "unknown", 1),
        ("close", "complete", 1),
    ],
)
def test_real_store_fault_acknowledgement(
    tmp_path, monkeypatch, phase, expected_outcome, expected_rows
):
    server, path, before, policy = configured(tmp_path)
    with server:
        alice = sdk(server, policy)
        prepared = alice.prepare_append(
            [command(actor_id="alice")], request_id="one", expected=before.checkpoint
        )
        with monkeypatch.context() as patch:
            if phase == "open":
                patch.setattr(
                    server._store,
                    "_connect",
                    lambda *a: (_ for _ in ()).throw(OSError("open failure")),
                )
            else:

                def fail(connection):
                    getattr(connection, phase)()
                    raise OSError("after native operation returned")

                patch.setattr(server._store, "_" + phase, fail)
            with pytest.raises(eb.WorkflowServiceError) as caught:
                alice.append(prepared)
            assert caught.value.outcome == expected_outcome
        recovered = alice.lookup(request_id="one", expected_request_digest=prepared.request_digest)
        assert (recovered is not None) == bool(expected_rows)
    assert len(audit(path)[2]) == expected_rows


@pytest.mark.parametrize("found", [False, True])
def test_lookup_outcome_survives_report_failure(tmp_path, monkeypatch, found):
    server, path, before, policy = configured(tmp_path)
    with server:
        alice = sdk(server, policy)
        prepared = alice.prepare_append(
            [command(actor_id="alice")], request_id="one", expected=before.checkpoint
        )
        if found:
            alice.append(prepared)
        monkeypatch.setattr(server, "_success", lambda *a: (_ for _ in ()).throw(MemoryError()))
        with pytest.raises(eb.WorkflowServiceError) as caught:
            alice.lookup(request_id="one", expected_request_digest=prepared.request_digest)
        assert caught.value.outcome == ("complete" if found else "none")
    assert len(audit(path)[2]) == int(found)


def test_real_disconnect_after_request_recovers_original_commit(tmp_path):
    server, path, before, policy = configured(tmp_path)
    with server:
        alice = sdk(server, policy)
        prepared = alice.prepare_append(
            [command(actor_id="alice")], request_id="one", expected=before.checkpoint
        )
        settled = threading.Event()
        success = server._success

        def staged(*args):
            result = success(*args)
            settled.set()
            return result

        server._success = staged
        payload = canonical(prepared.body())
        header = (
            f"POST /v1/workflow/append HTTP/1.1\r\nHost: 127.0.0.1:{server.address[1]}\r\n"
            f"Authorization: Bearer {TOKENS['alice']}\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(payload)}\r\n\r\n"
        ).encode()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(5)
            connection.connect(server.address)
            connection.sendall(header + payload)
        assert settled.wait(5)
        recovered = alice.lookup(request_id="one", expected_request_digest=prepared.request_digest)
        assert recovered is not None
        assert recovered.previous == before.checkpoint
        assert recovered.request_id == independent_id("alice", server._context, "one")
    assert len(audit(path)[2]) == 1


def test_reached_history_cap_keeps_snapshot_and_lookup_readable(tmp_path):
    limits = eb.WorkflowServiceLimits(max_records=1, max_operations=1, max_append_records=1)
    server, path, before, policy = configured(tmp_path, limits=limits)
    with server:
        alice = sdk(server, policy, limits=limits)
        prepared = alice.prepare_append(
            [command(actor_id="alice")], request_id="one", expected=before.checkpoint
        )
        committed = alice.append(prepared)
        second = alice.prepare_append(
            [command("second", actor_id="alice")],
            request_id="two",
            expected=committed.result.checkpoint,
        )
        with pytest.raises(eb.WorkflowServiceError) as caught:
            alice.append(second)
        assert (caught.value.code, caught.value.outcome) == ("workflow_rejected", "none")
        assert alice.snapshot() == committed.result
        assert (
            alice.lookup(request_id="one", expected_request_digest=prepared.request_digest)
            == committed
        )
    assert len(audit(path)[2]) == 1


def test_snapshot_anchor_and_prepared_pins_do_not_rebase(tmp_path):
    server, _, before, policy = configured(tmp_path)
    with server:
        alice = sdk(server, policy)
        prepared = alice.prepare_append(
            [command(actor_id="alice")], request_id="one", expected=before.checkpoint
        )
        alice.append(prepared)
        with pytest.raises(eb.WorkflowServiceError) as caught:
            alice.snapshot(expected=before.checkpoint)
        assert caught.value.code == "conflict"
        with pytest.raises(eb.WorkflowServiceError):
            alice.prepare_append(
                [command(actor_id="bob")], request_id="bad", expected=before.checkpoint
            )
        with pytest.raises(eb.WorkflowServiceError):
            alice.append(replace(prepared, service_id="other"))
