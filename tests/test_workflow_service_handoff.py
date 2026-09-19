"""Independent handoff control arbitration with real owned native sockets."""

import socket
import threading
from contextlib import suppress

import pytest

from evidence_braid import WorkflowServiceError
from tests.test_workflow_service_oracles import configured


@pytest.mark.parametrize("stage", ["start", "constructor"])
@pytest.mark.parametrize("primary_type", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("cleanup_type", [OSError, KeyboardInterrupt, SystemExit])
def test_failed_worker_setup_preserves_original_control_and_retained_socket(
    tmp_path, monkeypatch, primary_type, cleanup_type, stage
):
    server, _, _, _ = configured(tmp_path)
    primary = primary_type("original thread start")
    cleanup = cleanup_type("secondary accepted socket close")
    owned, remote = socket.socketpair()

    class Accepted:
        allow_close = False
        attempts = 0

        def close(self):
            self.attempts += 1
            if not self.allow_close:
                raise cleanup
            owned.close()

    accepted = Accepted()

    class Listener:
        def accept(self):
            return accepted, ("127.0.0.1", 1)

        def close(self):
            pass

    server._listener = Listener()

    def failed_start(*args, **kwargs):
        raise primary

    if stage == "start":
        monkeypatch.setattr(threading.Thread, "start", failed_start)
    else:
        monkeypatch.setattr(threading, "Thread", failed_start)
    try:
        server._accept()
        assert server.state == "DRAINING"
        assert server._pending_socket is accepted
        assert server._permits._value == 4 and not server._workers
        assert owned.fileno() >= 0 and accepted.attempts == 1
        with pytest.raises(BaseException) as caught:
            server.check()
        expected = (
            cleanup
            if isinstance(primary, Exception) and not isinstance(cleanup, Exception)
            else primary
        )
        assert caught.value is expected
    finally:
        accepted.allow_close = True
        with suppress(BaseException):
            server.close()
        owned.close()
        remote.close()
        for error in (primary, cleanup):
            error.__traceback__ = error.__context__ = error.__cause__ = None
    assert server.state == "CLOSED"
    assert server._pending_socket is None and owned.fileno() == -1 and remote.fileno() == -1


@pytest.mark.parametrize("reason", ["stopped", "peer-rejected", "saturated"])
@pytest.mark.parametrize("cleanup_type", [None, OSError, KeyboardInterrupt, SystemExit])
def test_unhanded_continue_path_closes_or_retains_real_socket(tmp_path, reason, cleanup_type):
    server, _, _, _ = configured(tmp_path)
    cleanup = None if cleanup_type is None else cleanup_type("unhanded cleanup")
    owned, remote = socket.socketpair()

    class Accepted:
        allow_close = cleanup is None
        attempts = 0

        def close(self):
            self.attempts += 1
            if not self.allow_close:
                raise cleanup
            owned.close()

    accepted = Accepted()

    class Listener:
        accepts = 0

        def accept(self):
            self.accepts += 1
            if self.accepts > 1:
                server._stop.set()
                raise TimeoutError
            if reason == "stopped":
                server._stop.set()
            peer = "192.0.2.1" if reason == "peer-rejected" else "127.0.0.1"
            return accepted, (peer, 1)

        def close(self):
            pass

    server._listener = Listener()
    reservations = 4 if reason == "saturated" else 0
    for _ in range(reservations):
        assert server._permits.acquire(blocking=False)
    try:
        server._accept()
        assert not server._workers and accepted.attempts == 1
        assert server._permits._value == 4 - reservations
        if cleanup is None:
            server.check()
            assert server._pending_socket is None and owned.fileno() == -1
        else:
            assert server.state == "DRAINING" and server._pending_socket is accepted
            assert owned.fileno() >= 0
            with pytest.raises(BaseException) as caught:
                server.check()
            assert caught.value is cleanup
    finally:
        for _ in range(reservations):
            server._permits.release()
        accepted.allow_close = True
        with suppress(BaseException):
            server.close()
        owned.close()
        remote.close()
        if cleanup is not None:
            cleanup.__traceback__ = cleanup.__context__ = cleanup.__cause__ = None
        assert server.state == "CLOSED" and server._pending_socket is None
        assert owned.fileno() == -1 and remote.fileno() == -1


@pytest.mark.parametrize("primary_type", [OSError, KeyboardInterrupt, SystemExit])
def test_started_worker_owns_socket_and_permit_despite_start_ack_failure(
    tmp_path, monkeypatch, primary_type
):
    server, _, _, _ = configured(tmp_path)
    primary = primary_type("start raised after native worker entered")
    owned, remote = socket.socketpair()
    entered, release = threading.Event(), threading.Event()
    native_start = threading.Thread.start
    workers = []
    worker_failures = []

    class Accepted:
        attempts = 0

        def close(self):
            self.attempts += 1
            owned.close()

    accepted = Accepted()

    class Listener:
        def accept(self):
            return accepted, ("127.0.0.1", 1)

        def close(self):
            pass

    def work(record):
        try:
            record.phase = "core"
            entered.set()
            if not release.wait(5):
                raise AssertionError("test failed to release actual owned worker")
        except BaseException as error:
            worker_failures.append(error)
        finally:
            record.socket.close()
            record.closed = True

    def started_then_failed(worker):
        workers.append(worker)
        native_start(worker)
        if not entered.wait(5):
            raise AssertionError("actual worker did not enter")
        raise primary

    server._listener = Listener()
    server._worker = work
    monkeypatch.setattr(threading.Thread, "start", started_then_failed)
    try:
        server._accept()
        (worker,) = workers
        assert worker.is_alive() and worker.ident is not None
        assert server.state == "DRAINING" and server._pending_socket is None
        assert server._workers[worker].socket is accepted
        assert server._permits._value == 3 and accepted.attempts == 0
        assert owned.fileno() >= 0
        with pytest.raises(BaseException) as caught:
            server.check()
        assert caught.value is primary
        # A timed-out close cannot close or release a still-owned core worker.
        with pytest.raises(BaseException) as timed_out:
            server.close(timeout_ms=1)
        if isinstance(primary, Exception):
            assert type(timed_out.value) is WorkflowServiceError
            assert timed_out.value.code == "transport_error"
        else:
            assert timed_out.value is primary
        assert worker.is_alive() and server._permits._value == 3
        assert accepted.attempts == 0 and server._workers[worker].socket is accepted
    finally:
        release.set()
        for worker in workers:
            if worker.ident is not None:
                worker.join(5)
        with suppress(BaseException):
            server.close()
        owned.close()
        remote.close()
        primary.__traceback__ = primary.__context__ = primary.__cause__ = None
        assert all(not worker.is_alive() for worker in workers)
        assert worker_failures == [] and server.state == "CLOSED"
        assert server._pending_socket is None and not server._workers
        assert server._permits._value == 4 and accepted.attempts == 1
        assert owned.fileno() == -1 and remote.fileno() == -1


@pytest.mark.parametrize(
    "primary_type,close_type,release_type",
    [
        (primary, None, cleanup)
        for primary in (None, OSError, KeyboardInterrupt, SystemExit)
        for cleanup in (OSError, KeyboardInterrupt, SystemExit)
    ]
    + [(KeyboardInterrupt, SystemExit, OSError)],
)
def test_observed_native_release_then_fault_arbitrates_without_losing_prior_failure(
    tmp_path, monkeypatch, primary_type, close_type, release_type
):
    server, _, _, _ = configured(tmp_path)
    primary = None if primary_type is None else primary_type("handoff failed")
    close_error = None if close_type is None else close_type("socket close failed")
    release_error = release_type("fault after observed native semaphore release")
    native_permits = server._permits
    owned, remote = socket.socketpair()

    class Permits:
        releases = 0

        def acquire(self, *, blocking):
            return native_permits.acquire(blocking=blocking)

        def release(self):
            self.releases += 1
            # Deliberately observable after-success fault, not a claim that an
            # unknown/before-release failure restored a semaphore reservation.
            native_permits.release()
            assert native_permits._value == 4
            raise release_error

    permits = Permits()
    server._permits = permits

    class Accepted:
        allow_close = close_error is None

        def close(self):
            if not self.allow_close:
                raise close_error
            owned.close()

    accepted = Accepted()

    class Listener:
        def accept(self):
            if primary is None:
                server._stop.set()
            return accepted, ("127.0.0.1", 1)

        def close(self):
            pass

    server._listener = Listener()

    def failed_start(*args, **kwargs):
        raise primary

    monkeypatch.setattr(threading.Thread, "start", failed_start)
    try:
        server._accept()
        assert server.state == "DRAINING" and not server._workers
        assert permits.releases == 1 and native_permits._value == 4
        assert (server._pending_socket is accepted) == (close_error is not None)
        assert (owned.fileno() >= 0) == (close_error is not None)
        # Independent first-failure/control selection, not the helper under test.
        expected = None
        for error in (primary, close_error, release_error):
            if error is not None and (
                expected is None
                or (isinstance(expected, Exception) and not isinstance(error, Exception))
            ):
                expected = error
        with pytest.raises(BaseException) as caught:
            server.check()
        assert caught.value is expected
    finally:
        accepted.allow_close = True
        with suppress(BaseException):
            server.close()
        owned.close()
        remote.close()
        for error in (primary, close_error, release_error):
            if error is not None:
                error.__traceback__ = error.__context__ = error.__cause__ = None
        assert server.state == "CLOSED" and server._pending_socket is None
        assert permits.releases == 1 and native_permits._value == 4
        assert owned.fileno() == -1 and remote.fileno() == -1
