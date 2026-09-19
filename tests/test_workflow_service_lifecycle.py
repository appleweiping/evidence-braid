from __future__ import annotations

import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress

import pytest

import evidence_braid as eb
from evidence_braid import _workflow_service_wire as wire
from evidence_braid.workflow_service import _Bucket, _Connection
from tests.test_workflow_service import canonical
from tests.test_workflow_service_boundaries import SocketPeer
from tests.test_workflow_service_oracles import configured, sdk
from tests.test_workflow_storage import command


class Control(BaseException):
    pass


def test_close_timeout_retains_live_core_owner_until_real_join(tmp_path):
    server, _, before, policy = configured(tmp_path)
    server.start()
    alice = sdk(server, policy)
    prepared = alice.prepare_append(
        [command(actor_id="alice")], request_id="one", expected=before.checkpoint
    )
    entered, release = threading.Event(), threading.Event()
    original = server._store.append

    def blocked(*args, **kwargs):
        entered.set()
        if not release.wait(5):
            raise AssertionError("test failed to release core")
        return original(*args, **kwargs)

    server._store.append = blocked
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(alice.append, prepared)
        try:
            assert entered.wait(5)
            with pytest.raises(eb.WorkflowServiceError) as caught:
                server.close(timeout_ms=10)
            assert caught.value.code == "shutdown_timeout"
            assert server.state == "DRAINING"
            assert any(thread.is_alive() for thread in server._workers)
            assert server._core.locked()
        finally:
            release.set()
        committed = future.result(timeout=5)
        assert committed.request_digest == prepared.request_digest
    server.close()
    assert server.state == "CLOSED" and not server._workers and not server._core.locked()


def test_worker_control_is_unknown_and_retained_for_owner(tmp_path):
    server, _, before, policy = configured(tmp_path)
    server.start()
    alice = sdk(server, policy)
    prepared = alice.prepare_append(
        [command(actor_id="alice")], request_id="one", expected=before.checkpoint
    )
    control = Control("not a wire message")
    server._store.append = lambda *a, **k: (_ for _ in ()).throw(control)
    with pytest.raises(eb.WorkflowServiceError) as caught:
        alice.append(prepared)
    assert caught.value.outcome == "unknown"
    with pytest.raises(Control) as observed:
        server.close()
    assert observed.value is control
    assert "outcome=unknown" in " ".join(control.__notes__)
    assert server.state == "CLOSED" and not server._core.locked()
    with pytest.raises(Control):
        server.check()


@pytest.mark.parametrize("body_is_control", [False, True])
def test_context_body_control_cleanup_priority(tmp_path, body_is_control):
    server, _, _, _ = configured(tmp_path)
    primary = Control() if body_is_control else ValueError()
    cleanup = Control()
    server.close = lambda: (_ for _ in ()).throw(cleanup)
    if body_is_control:
        server.__exit__(type(primary), primary, None)
        assert "shutdown" in " ".join(primary.__notes__)
    else:
        with pytest.raises(Control) as caught:
            server.__exit__(type(primary), primary, None)
        assert caught.value is cleanup


def test_close_releases_reading_socket_and_all_worker_permits(tmp_path):
    server, _, _, _ = configured(tmp_path)
    server.start()
    opened = []
    try:
        for _ in range(4):
            connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            connection.settimeout(5)
            connection.connect(server.address)
            connection.sendall(b"P")
            opened.append(connection)
        server.close(timeout_ms=1000)
        assert server.state == "CLOSED" and not server._workers
        assert server._permits._value == 4
        server.close()
        with pytest.raises(eb.WorkflowServiceError):
            server.start()
    finally:
        for connection in opened:
            connection.close()
        with suppress(eb.WorkflowServiceError):
            server.close()


def test_failed_worker_close_is_retained_then_retried(tmp_path):
    server, _, _, _ = configured(tmp_path)

    class Peer(SocketPeer):
        attempts = 0

        def close(self):
            self.attempts += 1
            if self.attempts == 1:
                raise OSError("unacknowledged close")
            self.closed = True

    peer = Peer(b"")
    record = _Connection(peer)
    server._read = lambda item: ("lookup", server._credentials[0], {})

    def dispatch(*args):
        record.operation.outcome = "complete"
        return b"delivered"

    server._dispatch = dispatch
    worker = threading.Thread(target=server._worker, args=(record,))
    server._permits.acquire()
    server._workers[worker] = record
    worker.start()
    worker.join(5)
    assert not worker.is_alive() and not record.closed
    assert server.state == "DRAINING"
    with pytest.raises(eb.WorkflowServiceError) as caught:
        server.close()
    assert caught.value.outcome == "complete"
    assert peer.attempts == 2 and server.state == "CLOSED" and not server._workers


def test_bucket_integer_clock_and_rotation_share_actor(tmp_path, monkeypatch):
    server, _, _, _ = configured(tmp_path)
    now = server._buckets["alice"].at
    monkeypatch.setattr(wire.time, "monotonic_ns", lambda: now)
    for _ in range(4):
        server._rate("alice")
    with pytest.raises(eb.WorkflowServiceError) as caught:
        server._rate("alice")
    assert caught.value.code == "rate_limited"
    assert set(server._buckets) == {"alice", "bob"}
    now += 249_999_999
    with pytest.raises(eb.WorkflowServiceError):
        server._rate("alice")
    now += 1
    server._rate("alice")
    assert server._buckets["alice"].credit == 0
    bucket = _Bucket(4, now)
    bucket.credit = 0
    bucket.refill(now - 10)
    assert bucket.credit == 0 and bucket.at == now
    bucket.refill(now + 10**100)
    assert bucket.credit == 4_000_000_000


def verified_client_peer(tmp_path, monkeypatch):
    server, _, before, policy = configured(tmp_path)
    server._address = ("127.0.0.1", 1)
    alice = sdk(server, policy)
    prepared = alice.prepare_append(
        [command(actor_id="alice")], request_id="one", expected=before.checkpoint
    )
    commit = server._store.append(
        prepared.transitions, request_id=prepared.core_request_id, expected=before.checkpoint
    )
    body = canonical(
        {
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
    )

    class Peer(SocketPeer):
        attempts = 0

        def close(self):
            self.attempts += 1
            if self.attempts == 1:
                raise OSError("post-verified close failed")
            self.closed = True

    peer = Peer(
        (
            f"HTTP/1.1 200 Response\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n"
        ).encode()
        + body
    )
    created = []

    def factory(*args):
        created.append(args)
        return peer

    monkeypatch.setattr(wire.socket, "socket", factory)
    with pytest.raises(eb.WorkflowServiceError) as caught:
        alice.append(prepared)
    assert caught.value.outcome == "complete"
    assert (
        caught.value.request_id == "one" and caught.value.request_digest == prepared.request_digest
    )
    return alice, prepared, peer, created


def test_sdk_retains_failed_close_for_explicit_retry(tmp_path, monkeypatch):
    alice, _, peer, created = verified_client_peer(tmp_path, monkeypatch)
    alice.close()
    assert peer.closed and peer.attempts == 2 and len(created) == 1


def test_sdk_retained_owner_prevents_a_second_network_operation(tmp_path, monkeypatch):
    alice, prepared, peer, created = verified_client_peer(tmp_path, monkeypatch)
    with pytest.raises(eb.WorkflowServiceError) as caught:
        alice.append(prepared)
    assert caught.value.code == "lifecycle_error"
    assert len(created) == 1
    alice.close()
    assert peer.closed


def test_stop_and_worker_admission_have_one_lock_order(tmp_path, monkeypatch):
    import evidence_braid.workflow_service as service_module

    server, _, _, _ = configured(tmp_path)
    server.start()
    constructing, release = threading.Event(), threading.Event()
    original_thread = threading.Thread

    def factory(*args, **kwargs):
        if getattr(kwargs.get("target"), "__name__", "") == "_worker":
            constructing.set()
            if not release.wait(5):
                raise AssertionError("test did not release worker construction")
        return original_thread(*args, **kwargs)

    failures = []

    def stop():
        try:
            server.close()
        except BaseException as error:
            failures.append(error)

    closer = original_thread(target=stop)
    monkeypatch.setattr(service_module.threading, "Thread", factory)
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        connection.settimeout(5)
        connection.connect(server.address)
        assert constructing.wait(5)
        closer.start()
        assert server._stop.wait(5)
        release.set()
        closer.join(5)
        assert not closer.is_alive()
        assert failures == []
        assert server.state == "CLOSED" and not server._workers
    finally:
        release.set()
        connection.close()
        closer.join(5)
        with suppress(eb.WorkflowServiceError):
            server.close()


def test_retained_worker_control_wins_later_listener_close_failure(tmp_path):
    server, _, _, _ = configured(tmp_path)
    control = Control("original worker control")
    server._fatal(control)

    class Listener:
        attempts = 0

        def close(self):
            self.attempts += 1
            if self.attempts == 1:
                raise OSError("later cleanup failure")

    server._listener = Listener()
    with pytest.raises(Control) as caught:
        server.close()
    assert caught.value is control and server.state == "DRAINING"
    with pytest.raises(Control):
        server.close()
    assert server.state == "CLOSED"
