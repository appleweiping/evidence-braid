from __future__ import annotations

import threading
from dataclasses import fields, replace

import pytest

import evidence_braid as eb
from evidence_braid import _workflow_service_wire as wire
from tests.test_workflow_service_boundaries import SocketPeer


@pytest.mark.parametrize("name", [item.name for item in fields(eb.WorkflowServiceLimits)])
@pytest.mark.parametrize("value", [False, 0, -1, 10**20, 1.5])
def test_limit_exact_native_domain(name, value):
    with pytest.raises(eb.ValidationError):
        eb.WorkflowServiceLimits(**{name: value})


@pytest.mark.parametrize(
    "changes",
    [
        {"max_records": 1},
        {"max_operations_bytes": 1},
        {"max_bundle_bytes": 1},
        {"max_header_bytes": 1},
        {"max_request_line": 1, "max_header_bytes": 100},
        {"max_append_records": 1, "max_records": 2},
    ],
)
def test_incoherent_profile(changes):
    with pytest.raises(eb.ValidationError):
        eb.WorkflowServiceLimits(**changes)


def test_coherent_lower_profile_and_derived_delivery_reserve():
    limits = eb.WorkflowServiceLimits(max_records=2, max_operations=2, max_append_records=1)
    assert limits.response_bytes == limits.max_bundle_bytes + 65536
    assert limits.store_limits().max_records == 2
    assert wire.limits_copy(limits) == limits
    assert wire.limits_copy(limits) is not limits
    with pytest.raises(eb.ValidationError):
        wire.limits_copy({})


@pytest.mark.parametrize(
    "raw",
    [
        b'{"x":NaN}',
        b'{"x":Infinity}',
        b'{"x":1e999}',
        b'{"x":1,"x":2}',
        b'{"x":"\xff"}',
        b'{"x":"\\ud800"}',
        b'{"x":1} ',
        b' {"x":1}',
        b'{"x":1}\n',
        b'{"x":1,"y":}',
        b'{"x":"unterminated}',
        b"{{{{",
    ],
)
def test_strict_canonical_json_rejections(raw):
    with pytest.raises((eb.ValidationError, eb.InputFormatError, eb.WorkflowServiceError)):
        wire.parse_json(raw, eb.WorkflowServiceLimits())


@pytest.mark.parametrize(
    "raw, expected",
    [
        (b"{}", {}),
        (b"[]", []),
        (b'{"a":true,"b":false,"c":null}', {"a": True, "b": False, "c": None}),
        (b'{"x":"a\\"b\\\\c"}', {"x": 'a"b\\c'}),
        (b'{"x":-1}', {"x": -1}),
    ],
)
def test_native_and_lexical_tokens_agree(raw, expected):
    limits = eb.WorkflowServiceLimits()
    assert wire.parse_json(raw, limits) == expected
    assert wire.native_json(expected, limits) == raw


def test_exact_native_depth_matches_lexical_container_depth():
    limits = eb.WorkflowServiceLimits(max_request_depth=1)
    assert wire.parse_json(b'{"x":1}', limits) == {"x": 1}
    assert wire.native_json({"x": 1}, limits) == b'{"x":1}'


@pytest.mark.parametrize("raw", [b"[[[]]]", b"[1,2,3,4]", b'"123456789"'])
def test_lexical_limit_plus_one(raw):
    limits = eb.WorkflowServiceLimits(
        max_request_depth=2, max_request_nodes=4, max_request_bytes=10
    )
    with pytest.raises(eb.WorkflowServiceError):
        wire.parse_json(raw, limits)


@pytest.mark.parametrize("value", [object(), {1: 2}, {"x": object()}, {"x": 1.0}, 10**1000])
def test_native_json_rejects_unadmitted_objects(value):
    with pytest.raises((eb.ValidationError, eb.WorkflowServiceError)):
        wire.native_json(value, eb.WorkflowServiceLimits())


def test_native_json_node_budget_and_cycle():
    limits = eb.WorkflowServiceLimits(max_request_nodes=3)
    assert wire.native_json({"x": 1}, limits) == b'{"x":1}'
    with pytest.raises(eb.WorkflowServiceError):
        wire.native_json({"x": [1]}, limits)
    cyclic = []
    cyclic.append(cyclic)
    with pytest.raises(eb.WorkflowServiceError):
        wire.native_json(cyclic, eb.WorkflowServiceLimits())
    with pytest.raises(eb.WorkflowServiceError):
        wire.native_json("a" * 11, replace(limits, max_request_bytes=10))


@pytest.mark.parametrize("value", ["", "00", "-1", "+1", "1.0", "\uff11\uff12", "9" * 100])
def test_content_length_lexical_rejection(value):
    with pytest.raises(eb.WorkflowServiceError):
        wire.content_length({"content-length": value}, 100)


def test_content_length_exact_bound():
    assert wire.content_length({"content-length": "100"}, 100) == 100
    assert wire.content_length({"content-length": "0"}, 100) == 0
    with pytest.raises(eb.WorkflowServiceError) as caught:
        wire.content_length({"content-length": "101"}, 100)
    assert caught.value.code == "limit_exceeded"


@pytest.mark.parametrize(
    "raw",
    [
        b"HTTP/1.1 200 Response\nX: y\r\n\r\n",
        b"HTTP/1.1 200 Response\r\n X: y\r\n\r\n",
        b"HTTP/1.1 200 Response\r\nX : y\r\n\r\n",
        b"HTTP/1.1 200 Response\r\nX: y\r\nx: y\r\n\r\n",
        b"HTTP/1.1 200 Response\r\nX: \t\r\n\r\n",
        b"HTTP/1.1 200 Response\r\nX: y \r\n\r\n",
        b"HTTP/1.1 200 Response\r\nX:y\r\n\r\n",
    ],
)
def test_ambiguous_http_header_rejection(raw):
    with pytest.raises(eb.WorkflowServiceError):
        wire.read_headers(SocketPeer(raw), wire.deadline(100), eb.WorkflowServiceLimits())


def test_fragmented_header_and_body_are_exact():
    class BytePeer(SocketPeer):
        def recv(self, size):
            return super().recv(1)

    peer = BytePeer(b"HTTP/1.1 200 Response\r\nX: y\r\n\r\n{}")
    line, headers, tail = wire.read_headers(peer, wire.deadline(100), eb.WorkflowServiceLimits())
    assert (line, headers) == ("HTTP/1.1 200 Response", {"x": "y"})
    assert wire.read_body(peer, tail, 2, wire.deadline(100)) == b"{}"


@pytest.mark.parametrize(
    "changes, raw",
    [
        ({"max_request_line": 1}, b"XX\r\n\r\n"),
        ({"max_headers": 1}, b"X\r\nA: b\r\nB: c\r\n\r\n"),
        ({"max_header_line": 3}, b"X\r\nA: b\r\n\r\n"),
    ],
)
def test_header_dimension_cap(changes, raw):
    with pytest.raises(eb.WorkflowServiceError):
        wire.read_headers(SocketPeer(raw), wire.deadline(100), eb.WorkflowServiceLimits(**changes))


def test_total_header_cap_and_premature_eof():
    with pytest.raises(eb.WorkflowServiceError):
        wire.read_headers(SocketPeer(b"x" * 16385), wire.deadline(100), eb.WorkflowServiceLimits())
    with pytest.raises(OSError):
        wire.read_headers(SocketPeer(b""), wire.deadline(100), eb.WorkflowServiceLimits())
    with pytest.raises(OSError):
        wire.read_body(SocketPeer(b""), b"", 1, wire.deadline(100))


@pytest.mark.parametrize("result", [0, -1, False, None, 1.0, 4])
def test_invalid_socket_send_count(result):
    class Sender(SocketPeer):
        def send(self, value):
            return result

    with pytest.raises(OSError):
        wire.send(Sender(b""), b"abc", wire.deadline(100))


def test_short_writes_use_absolute_deadline(monkeypatch):
    times = iter([0, 0.02, 0.04, 0.06])
    monkeypatch.setattr(wire.time, "monotonic", lambda: next(times))

    class Sender(SocketPeer):
        def __init__(self, response):
            super().__init__(response)
            self.timeouts = []
            self.written = bytearray()

        def settimeout(self, value):
            self.timeouts.append(value)

        def send(self, value):
            self.written.extend(value[:1])
            return 1

    sender = Sender(b"")
    wire.send(sender, b"abc", wire.deadline(100))
    assert sender.written == b"abc"
    assert sender.timeouts == pytest.approx([0.08, 0.06, 0.04])


def test_deadline_cannot_reset_on_progress(monkeypatch):
    monkeypatch.setattr(wire.time, "monotonic", lambda: 1.0)
    with pytest.raises(TimeoutError):
        wire.remaining(1.0)


def test_primary_control_is_preserved():
    class Control(BaseException):
        pass

    primary, secondary = Control(), Control()
    assert wire.primary_failure(primary, secondary) is primary
    assert wire.primary_failure(ValueError(), secondary) is secondary
    assert wire.primary_failure(None, secondary) is secondary


def test_server_read_observes_stop_after_bounded_poll_without_os_wakeup():
    stop = threading.Event()

    class Peer(SocketPeer):
        calls = 0
        timeout = None

        def settimeout(self, value):
            self.timeout = value

        def recv(self, size):
            self.calls += 1
            stop.set()
            raise TimeoutError

    peer = Peer(b"")
    with pytest.raises(OSError):
        wire.read_headers(peer, wire.deadline(5000), eb.WorkflowServiceLimits(), stop=stop)
    assert peer.calls == 1 and peer.timeout == 0.05
    with pytest.raises(TimeoutError):
        wire.read_headers(Peer(b""), wire.deadline(100), eb.WorkflowServiceLimits())
