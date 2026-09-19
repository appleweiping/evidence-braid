from __future__ import annotations

import pytest

import evidence_braid as eb
from evidence_braid import _workflow_service_wire as wire
from tests.test_workflow_service import TOKEN, service
from tests.test_workflow_storage import authority, command, initial


class SocketPeer:
    def __init__(self, response):
        self.response = bytearray(response)
        self.closed = False

    def settimeout(self, value):
        pass

    def connect(self, address):
        assert address == ("127.0.0.1", 1)

    def send(self, value):
        return len(value)

    def recv(self, size):
        piece = bytes(self.response[:size])
        del self.response[:size]
        return piece

    def close(self):
        self.closed = True

    def shutdown(self, how):
        pass


@pytest.mark.parametrize(
    "headers",
    [
        b"Content-Length: 99999999999999999\r\n",
        b"Content-Length: 0\r\nContent-Length: 0\r\n",
    ],
)
def test_malformed_peer_does_not_downgrade_unknown_append(headers, tmp_path, monkeypatch):
    _, _, before = service(tmp_path)
    sdk = eb.WorkflowClient(
        address=("127.0.0.1", 1),
        token=TOKEN,
        service_id="local-one",
        actor_id="author",
        workflow_id="workflow-one",
        context_digest=initial().context_digest,
        authority=authority(),
    )
    prepared = sdk.prepare_append([command()], request_id="one", expected=before.checkpoint)
    peer = SocketPeer(
        b"HTTP/1.1 200 Response\r\nContent-Type: application/json\r\n"
        b"Connection: close\r\nCache-Control: no-store\r\n" + headers + b"\r\n"
    )
    monkeypatch.setattr(wire.socket, "socket", lambda *a: peer)
    with pytest.raises(eb.WorkflowServiceError) as caught:
        sdk.append(prepared)
    assert caught.value.outcome == "unknown"
    assert peer.closed


def test_unhanded_socket_close_failure_retains_owned_handle(tmp_path):
    server, _, _ = service(tmp_path)

    class FailedClose:
        attempts = 0

        def close(self):
            self.attempts += 1
            if self.attempts == 1:
                raise OSError("injected unacknowledged close")

    accepted = FailedClose()

    class Listener:
        def accept(self):
            server._stop.set()
            return accepted, ("127.0.0.1", 1)

        def close(self):
            pass

    server._listener = Listener()
    server._accept()
    assert server.state == "DRAINING"
    with pytest.raises(eb.WorkflowServiceError):
        server.close()
    assert accepted.attempts == 2
    assert server.state == "CLOSED"


@pytest.mark.parametrize("sign", [b"", b"-"])
def test_existing_640_digit_response_domain(sign):
    raw = b'{"value":' + sign + b"9" * 640 + b"}"
    assert wire.parse_json(raw, eb.WorkflowServiceLimits(), response=True)["value"] == int(
        sign + b"9" * 640
    )
    with pytest.raises(eb.WorkflowServiceError):
        wire.parse_json(
            b'{"value":' + sign + b"9" * 641 + b"}", eb.WorkflowServiceLimits(), response=True
        )
