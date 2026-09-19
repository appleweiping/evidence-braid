"""SDK transport/cleanup controls preserve caller-owned recovery and outcomes."""

import pytest

import evidence_braid as eb
from evidence_braid import _workflow_service_wire as wire
from tests.test_workflow_client_adversarial import canonical, frame, prepared_peer


@pytest.mark.parametrize(
    "stage,primary_type",
    [
        (stage, kind)
        for stage in ("connect", "send")
        for kind in (OSError, KeyboardInterrupt, SystemExit)
    ]
    + [("verified", OSError)],
)
@pytest.mark.parametrize("cleanup_type", [OSError, KeyboardInterrupt, SystemExit])
def test_owned_socket_control_identity_and_known_outcome(
    tmp_path, monkeypatch, stage, primary_type, cleanup_type
):
    client, prepared, envelope, _, _ = prepared_peer(tmp_path)
    original = primary_type("original transport boundary")
    cleanup = cleanup_type("cleanup boundary")
    expected_outcome = {"connect": "none", "send": "unknown", "verified": "complete"}[stage]

    class Peer:
        def __init__(self):
            self.data = frame(canonical(envelope))
            self.allow_close = False
            self.closed = False

        def settimeout(self, value):
            assert value > 0

        def connect(self, address):
            if stage == "connect":
                raise original

        def send(self, value):
            if stage == "send":
                raise original
            return len(value)

        def recv(self, size):
            # Exercise complete framing across small independent fragments.
            value, self.data = self.data[: min(17, size)], self.data[min(17, size) :]
            return value

        def close(self):
            if not self.allow_close:
                raise cleanup
            self.closed = True

    peer = Peer()
    acquisitions = []

    def acquire(*args):
        acquisitions.append(peer)
        return peer

    monkeypatch.setattr(wire.socket, "socket", acquire)
    with pytest.raises(BaseException) as caught:
        client.append(prepared)
    selected = caught.value
    expected_control = None
    if stage != "verified" and not isinstance(original, Exception):
        expected_control = original
    elif not isinstance(cleanup, Exception):
        expected_control = cleanup
    if expected_control is not None:
        assert selected is expected_control
        assert f"outcome={expected_outcome}" in " ".join(selected.__notes__)
    else:
        assert type(selected) is eb.WorkflowServiceError
        assert selected.outcome == expected_outcome
        assert selected.request_id == prepared.request_id
        assert selected.request_digest == prepared.request_digest
    assert client._connection is peer and not peer.closed
    for error in (original, cleanup, selected):
        error.__traceback__ = error.__context__ = error.__cause__ = None
    with pytest.raises(eb.WorkflowServiceError) as blocked:
        client.append(prepared)
    assert blocked.value.code == "lifecycle_error"
    assert len(acquisitions) == 1
    peer.allow_close = True
    client.close()
    client.close()
    assert client._connection is None and peer.closed and len(acquisitions) == 1
