from __future__ import annotations

import hashlib
import socket
import threading

import pytest

import evidence_braid as eb
from evidence_braid import _workflow_service_wire as wire
from tests.test_workflow_service import canonical
from tests.test_workflow_service_boundaries import SocketPeer
from tests.test_workflow_service_lifecycle import Control, verified_client_peer
from tests.test_workflow_service_oracles import TOKENS, configured, sdk
from tests.test_workflow_storage import command


def prepared_peer(tmp_path):
    server, _, before, policy = configured(tmp_path)
    server._address = ("127.0.0.1", 1)
    alice = sdk(server, policy)
    prepared = alice.prepare_append(
        [command(actor_id="alice")], request_id="one", expected=before.checkpoint
    )
    commit = server._store.append(
        prepared.transitions, request_id=prepared.core_request_id, expected=before.checkpoint
    )
    envelope = {
        "schema_version": "1.0",
        "service_id": "service-one",
        "workflow_id": "pinned-one",
        "context_digest": before.checkpoint.context_digest,
        "actor_id": "alice",
        "operation": "append",
        "request_id": "one",
        "request_digest": prepared.request_digest,
        "outcome": "complete",
        "result": commit.to_dict(),
    }
    return alice, prepared, envelope, server, policy


def frame(body, *, status="200", content_type="application/json", extra=b"", suffix=b""):
    return (
        (
            f"HTTP/1.1 {status} Response\r\nContent-Type: {content_type}\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\nCache-Control: no-store\r\n"
        ).encode()
        + extra
        + b"\r\n"
        + body
        + suffix
    )


@pytest.mark.parametrize(
    "path,value",
    [
        (("schema_version",), "2.0"),
        (("service_id",), "other"),
        (("workflow_id",), "other"),
        (("context_digest",), "0" * 64),
        (("actor_id",), "bob"),
        (("operation",), "lookup"),
        (("request_id",), "two"),
        (("request_digest",), "0" * 64),
        (("outcome",), "none"),
        (("result",), None),
        (("result", "request_digest"), "0" * 64),
        (("result", "result", "bundle", "records"), {}),
        (("result", "result", "checkpoint", "operation_head"), "0" * 64),
    ],
)
def test_independent_malformed_success_peer_never_acknowledges(tmp_path, monkeypatch, path, value):
    alice, prepared, envelope, _, _ = prepared_peer(tmp_path)
    target = envelope
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    peer = SocketPeer(frame(canonical(envelope)))
    monkeypatch.setattr(wire.socket, "socket", lambda *a: peer)
    with pytest.raises(eb.WorkflowServiceError) as caught:
        alice.append(prepared)
    assert caught.value.outcome == "unknown" and caught.value.code == "invalid_response"
    assert peer.closed and alice._connection is None


@pytest.mark.parametrize("change", ["status", "headers", "media", "extra", "truncated", "bad-json"])
def test_invalid_transport_response_is_not_an_error_ack(tmp_path, monkeypatch, change):
    alice, prepared, envelope, _, _ = prepared_peer(tmp_path)
    body = canonical(envelope)
    payload = frame(body)
    if change == "status":
        payload = frame(body, status="99")
    elif change == "headers":
        payload = frame(body, extra=b"X-Unknown: one\r\n")
    elif change == "media":
        payload = frame(body, content_type="text/plain")
    elif change == "extra":
        payload += b"unexpected"
    elif change == "truncated":
        payload = payload[:-5]
    elif change == "bad-json":
        payload = frame(b'{"x":NaN}')
    peer = SocketPeer(payload)
    monkeypatch.setattr(wire.socket, "socket", lambda *a: peer)
    with pytest.raises(eb.WorkflowServiceError) as caught:
        alice.append(prepared)
    assert caught.value.outcome == "unknown" and peer.closed


@pytest.mark.parametrize(
    "changes,status",
    [
        ({"schema_version": "2.0"}, "503"),
        ({"request_id": "another"}, "503"),
        ({"request_digest": "0" * 64}, "503"),
        ({"error_code": "forged"}, "503"),
        ({"outcome": "forged"}, "503"),
        ({"outcome": "complete", "error_code": "forbidden"}, "403"),
        ({}, "500"),
    ],
)
def test_unbound_error_peer_cannot_refine_outcome(tmp_path, monkeypatch, changes, status):
    alice, prepared, _, _, _ = prepared_peer(tmp_path)
    envelope = {
        "schema_version": "1.0",
        "request_id": prepared.request_id,
        "request_digest": prepared.request_digest,
        "error_code": "unavailable",
        "outcome": "none",
        **changes,
    }
    peer = SocketPeer(frame(canonical(envelope), status=status))
    monkeypatch.setattr(wire.socket, "socket", lambda *a: peer)
    with pytest.raises(eb.WorkflowServiceError) as caught:
        alice.append(prepared)
    assert caught.value.outcome == "unknown" and caught.value.code == "invalid_response"


def test_valid_but_different_committed_request_is_rejected(tmp_path, monkeypatch):
    alice, prepared, envelope, server, _ = prepared_peer(tmp_path)
    second = alice.prepare_append(
        [command("two", actor_id="alice")],
        request_id="two",
        expected=eb.WorkflowCheckpoint.from_dict(envelope["result"]["result"]["checkpoint"]),
    )
    envelope["result"] = server._store.append(
        second.transitions, request_id=second.core_request_id, expected=second.expected_checkpoint
    ).to_dict()
    monkeypatch.setattr(wire.socket, "socket", lambda *a: SocketPeer(frame(canonical(envelope))))
    with pytest.raises(eb.WorkflowServiceError) as caught:
        alice.append(prepared)
    assert caught.value.code == "invalid_response" and caught.value.outcome == "unknown"


def test_decoder_checks_additional_prepared_intent_and_snapshot_anchor(tmp_path):
    alice, prepared, envelope, server, _ = prepared_peer(tmp_path)
    current = server._store.snapshot()
    other = alice.prepare_append(
        [command("two", actor_id="alice")], request_id="two", expected=current.checkpoint
    )
    with pytest.raises(eb.ValidationError):
        alice._decode(200, envelope, "append", prepared.body(), prepared=other, expected=None)
    snapshot = {
        **envelope,
        "operation": "snapshot",
        "request_id": None,
        "request_digest": None,
        "outcome": "none",
        "result": current.to_dict(),
    }
    with pytest.raises(eb.ValidationError):
        alice._decode(
            200, snapshot, "snapshot", {}, prepared=None, expected=prepared.expected_checkpoint
        )


def test_valid_other_workflow_and_lower_record_profile_are_rejected(tmp_path):
    alice, _, _, server, policy = prepared_peer(tmp_path)
    other = eb.build_workflow("another", authority=policy, evidence=eb.build_ledger([]))
    store = eb.create_workflow_store(
        tmp_path / "other.db",
        other,
        authority=policy,
        expected_context=other.context_digest,
        expected_head=other.head_digest,
    )
    with pytest.raises(eb.ValidationError):
        alice._stored(store.snapshot().to_dict())
    alice._limits = eb.WorkflowServiceLimits(max_records=1, max_operations=1, max_append_records=1)
    server._store.append(
        [command("two", actor_id="alice")],
        request_id="local-two",
        expected=server._store.snapshot().checkpoint,
    )
    with pytest.raises(eb.ValidationError):
        alice._stored(server._store.snapshot().to_dict())


@pytest.mark.parametrize("cleanup", [OSError(), Control()])
def test_sdk_failed_retry_retains_capability_and_complete_outcome(tmp_path, monkeypatch, cleanup):
    alice, _, peer, _ = verified_client_peer(tmp_path, monkeypatch)
    original = peer.close
    peer.close = lambda: (_ for _ in ()).throw(cleanup)
    with pytest.raises(
        type(cleanup) if isinstance(cleanup, Control) else eb.WorkflowServiceError
    ) as caught:
        alice.close()
    if isinstance(cleanup, Control):
        assert caught.value is cleanup
        assert "outcome=complete" in " ".join(cleanup.__notes__)
    else:
        assert caught.value.outcome == "complete"
    assert alice._connection is peer
    peer.close = original
    alice.close()
    alice.close()
    assert alice._connection is None


def test_sdk_controls_keep_original_priority_and_owned_socket(tmp_path, monkeypatch):
    alice, prepared, _, _, _ = prepared_peer(tmp_path)
    original, cleanup = Control(), Control()

    class Peer(SocketPeer):
        def send(self, value):
            raise original

        def close(self):
            raise cleanup

    peer = Peer(b"")
    monkeypatch.setattr(wire.socket, "socket", lambda *a: peer)
    with pytest.raises(Control) as caught:
        alice.append(prepared)
    assert caught.value is original and alice._connection is peer
    assert "outcome=unknown" in " ".join(original.__notes__)
    peer.close = lambda: None
    alice.close()


def test_sdk_rejects_overlap_without_cancellation_or_new_socket(tmp_path, monkeypatch):
    alice, prepared, _, _, _ = prepared_peer(tmp_path)
    alice._busy.acquire()
    try:
        with pytest.raises(eb.WorkflowServiceError):
            alice.append(prepared)
        with pytest.raises(eb.WorkflowServiceError):
            alice.close()
        assert alice._connection is None
    finally:
        alice._busy.release()


def test_sdk_never_uses_dns_or_proxy_and_real_fake_peer(tmp_path, monkeypatch):
    alice, prepared, envelope, _, _ = prepared_peer(tmp_path)
    # A genuinely independent real socket peer; no production response-frame helper.
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(5)
    alice._address = listener.getsockname()
    payload = frame(canonical(envelope))
    received = []

    def run():
        with listener:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(5)
                data = bytearray()
                while b"\r\n\r\n" not in data:
                    data.extend(connection.recv(1024))
                header, body = bytes(data).split(b"\r\n\r\n", 1)
                size = int(
                    next(
                        line.split(b": ")[1]
                        for line in header.split(b"\r\n")
                        if line.startswith(b"Content-Length:")
                    )
                )
                while len(body) < size:
                    body += connection.recv(size - len(body))
                received.append(body)
                connection.sendall(payload)

    worker = threading.Thread(target=run)
    worker.start()
    monkeypatch.setenv("HTTP_PROXY", "http://example.invalid:1")
    monkeypatch.setenv("ALL_PROXY", "http://example.invalid:1")
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: pytest.fail("unexpected DNS"))
    try:
        assert alice.append(prepared).request_digest == prepared.request_digest
    finally:
        worker.join(5)
    assert not worker.is_alive() and received == [canonical(prepared.body())]


@pytest.mark.parametrize("kind", ["snapshot", "append", "lookup"])
def test_sdk_rejects_internal_wrong_return_type(tmp_path, kind):
    alice, prepared, _, _, _ = prepared_peer(tmp_path)
    alice._request = lambda *a, **k: object()
    with pytest.raises(eb.WorkflowServiceError):
        if kind == "snapshot":
            alice.snapshot()
        elif kind == "append":
            alice.append(prepared)
        else:
            alice.lookup(request_id="one", expected_request_digest=prepared.request_digest)


@pytest.mark.parametrize(
    "address", [("localhost", 1), ("0.0.0.0", 1), ("::1", 1), ["127.0.0.1", 1], ("127.0.0.1",)]
)
def test_constructor_rejects_nonliteral_endpoint_without_socket(tmp_path, address):
    _, _, before, policy = configured(tmp_path)
    with pytest.raises(eb.ValidationError):
        eb.WorkflowClient(
            address=address,
            token=TOKENS["alice"],
            service_id="one",
            actor_id="alice",
            workflow_id="pinned-one",
            context_digest=before.checkpoint.context_digest,
            authority=policy,
        )


def test_native_exact_type_guards_and_prepared_snapshot(tmp_path):
    alice, prepared, _, _, policy = prepared_peer(tmp_path)

    class Hostile(str):
        def __len__(self):
            raise AssertionError("hostile length invoked")

        def __hash__(self):
            raise AssertionError("hostile hash invoked")

    for value in [Hostile("alice"), "", "!", object()]:
        with pytest.raises(eb.ValidationError):
            wire.identifier(value)
    with pytest.raises(eb.ValidationError):
        eb.WorkflowServiceCredential("one", "alice", "0" * 64, Hostile("act"))
    with pytest.raises(eb.ValidationError):
        alice.append({})
    with pytest.raises(eb.ValidationError):
        alice.prepare_append([{}], request_id="x", expected=prepared.expected_checkpoint)
    with pytest.raises(eb.ValidationError):
        alice.prepare_append([], request_id="x", expected=prepared.expected_checkpoint)
    with pytest.raises(eb.ValidationError):
        alice.prepare_append([command(actor_id="alice")], request_id="x", expected={})
    document = prepared.to_dict()
    loaded = eb.PreparedWorkflowAppend.from_dict(document)
    document["transitions"].clear()
    assert loaded == prepared
    with pytest.raises(eb.ValidationError):
        eb.PreparedWorkflowAppend.from_dict({**loaded.to_dict(), "schema_version": "2"})
    with pytest.raises(eb.ValidationError):
        eb.PreparedWorkflowAppend.from_dict({"extra": 1})
    with pytest.raises(eb.WorkflowServiceError):
        wire.checkpoint(prepared.expected_checkpoint, "0" * 64)
    with pytest.raises(eb.ValidationError):
        wire.authority_copy({}, eb.WorkflowServiceLimits())
    with pytest.raises(eb.ValidationError):
        eb.WorkflowClient(
            address=("127.0.0.1", 1),
            token=TOKENS["alice"],
            service_id="one",
            actor_id="missing",
            workflow_id="pinned-one",
            context_digest=prepared.context_digest,
            authority=policy,
        )
    assert TOKENS["alice"] not in repr(alice)
    assert hashlib.sha256(bytes.fromhex(TOKENS["alice"])).hexdigest() not in repr(
        eb.WorkflowServiceCredential(
            "one", "alice", hashlib.sha256(bytes.fromhex(TOKENS["alice"])).hexdigest(), "act"
        )
    )
