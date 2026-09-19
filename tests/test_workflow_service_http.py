from __future__ import annotations

import socket

import pytest

from tests.test_workflow_service_oracles import TOKENS, configured


def exchange(
    server, body, *, method="POST", target="/v1/workflow/snapshot", extra=b"", change=None
):
    headers = [
        f"Host: 127.0.0.1:{server.address[1]}",
        f"Authorization: Bearer {TOKENS['alice']}",
        "Content-Type: application/json",
        f"Content-Length: {len(body)}",
    ]
    if change is not None:
        headers = change(headers)
    request = (
        (f"{method} {target} HTTP/1.1\r\n" + "\r\n".join(headers) + "\r\n").encode()
        + extra
        + b"\r\n"
        + body
    )
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        connection.connect(server.address)
        connection.sendall(request)
        connection.shutdown(socket.SHUT_WR)
        received = bytearray()
        while chunk := connection.recv(65536):
            received.extend(chunk)
    return int(bytes(received).split(b" ")[1]), bytes(received)


@pytest.mark.parametrize(
    "body",
    [
        b'{"schema_version":"1.0","schema_version":"1.0"}',
        b'{"expected_checkpoint":NaN,"schema_version":"1.0"}',
        b'{"expected_checkpoint":1e999,"schema_version":"1.0"}',
        b'{"expected_checkpoint":null,"schema_version":"bad"}',
        b'{"expected_checkpoint":null,"schema_version":"1.0","x":null}',
        b'{"expected_checkpoint":[],"schema_version":"1.0"}',
        b' {"expected_checkpoint":null,"schema_version":"1.0"}',
    ],
)
def test_invalid_body_is_400_before_database(tmp_path, monkeypatch, body):
    server, _, _, _ = configured(tmp_path)
    with server:
        monkeypatch.setattr(
            server._store, "_connect", lambda *a: pytest.fail("invalid request reached DB")
        )
        status, response = exchange(server, body)
        assert status == 400
        assert b'"outcome":"none"' in response


@pytest.mark.parametrize(
    "extra",
    [
        b"Origin: null\r\n",
        b"Referer: http://example.invalid\r\n",
        b"Transfer-Encoding: chunked\r\n",
        b"Content-Encoding: gzip\r\n",
        b"Host: example.invalid\r\n",
        b"Expect: 100-continue\r\n",
        b"Sec-Fetch-Site: cross-site\r\n",
        b"X-Unknown: value\r\n",
    ],
)
def test_forbidden_headers_are_rejected_without_db(tmp_path, monkeypatch, extra):
    server, _, _, _ = configured(tmp_path)
    with server:
        monkeypatch.setattr(
            server._store, "_connect", lambda *a: pytest.fail("invalid headers reached DB")
        )
        assert exchange(server, b"{}", extra=extra)[0] == 400


@pytest.mark.parametrize(
    "method,target,status",
    [
        ("GET", "/v1/workflow/snapshot", 405),
        ("POST", "/missing", 404),
        ("POST", "http://127.0.0.1/v1/workflow/snapshot", 400),
        ("POST", "/v1/workflow/snapshot?actor=bob", 400),
        ("POST", "/v1/workflow/%73napshot", 400),
        ("POST", "/v1/workflow/snapshot#x", 400),
    ],
)
def test_only_three_exact_post_routes(tmp_path, method, target, status):
    server, _, _, _ = configured(tmp_path)
    with server:
        assert exchange(server, b"{}", method=method, target=target)[0] == status


@pytest.mark.parametrize(
    "header,value,status",
    [
        ("Host", "localhost:1", 400),
        ("Content-Type", "text/plain", 415),
        ("Connection", "keep-alive", 400),
        ("Accept", "text/html", 400),
        ("Content-Length", "1048577", 413),
    ],
)
def test_header_value_admission(tmp_path, header, value, status):
    server, _, _, _ = configured(tmp_path)
    with server:

        def change(headers):
            return [item for item in headers if not item.startswith(header + ":")] + [
                f"{header}: {value}"
            ]

        assert exchange(server, b"{}", change=change)[0] == status


def test_append_missing_checkpoint_and_empty_batch_are_not_store_calls(tmp_path, monkeypatch):
    from tests.test_workflow_service import raw

    server, _, _, _ = configured(tmp_path)
    with server:
        monkeypatch.setattr(
            server._store, "_connect", lambda *a: pytest.fail("unadmitted DB access")
        )
        status, _ = raw(
            server,
            "append",
            {
                "schema_version": "1.0",
                "request_id": "one",
                "request_digest": "0" * 64,
                "expected_checkpoint": None,
                "transitions": [],
            },
            token=TOKENS["alice"],
        )
        assert status == 413
