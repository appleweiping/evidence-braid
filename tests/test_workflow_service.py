from __future__ import annotations

import hashlib
import json
import socket

import pytest

import evidence_braid as eb
from tests.test_workflow_storage import audit, command, create, initial

TOKEN = "01" * 32


def canonical(value):
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":")
    ).encode()


def service(tmp_path, **options):
    path = tmp_path / "workflow.db"
    store = create(path)
    before = store.snapshot()
    from tests.test_workflow_storage import authority

    result = eb.LocalWorkflowService(
        database=path,
        authority=authority(),
        expected_workflow_id="workflow-one",
        expected_context=initial().context_digest,
        startup_checkpoint=before.checkpoint,
        service_id="local-one",
        credentials=(
            eb.WorkflowServiceCredential(
                "token-one", "author", hashlib.sha256(bytes.fromhex(TOKEN)).hexdigest(), "act"
            ),
        ),
        **options,
    )
    return result, path, before


def client(server, token=TOKEN, actor="author"):
    from tests.test_workflow_storage import authority

    return eb.WorkflowClient(
        address=server.address,
        token=token,
        service_id="local-one",
        actor_id=actor,
        workflow_id="workflow-one",
        context_digest=initial().context_digest,
        authority=authority(),
    )


def raw(server, operation, body, token=TOKEN):
    payload = canonical(body)
    header = (
        f"POST /v1/workflow/{operation} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{server.address[1]}\r\nAuthorization: Bearer {token}\r\n"
        f"Content-Type: application/json\r\nContent-Length: {len(payload)}\r\n\r\n"
    ).encode()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        connection.connect(server.address)
        connection.sendall(header + payload)
        received = bytearray()
        while piece := connection.recv(65536):
            received.extend(piece)
    headers, data = bytes(received).split(b"\r\n\r\n", 1)
    return int(headers.split(b" ")[1]), json.loads(data)


@pytest.mark.parametrize(
    "name",
    [
        "WorkflowServiceLimits",
        "WorkflowServiceCredential",
        "LocalWorkflowService",
        "WorkflowClient",
        "PreparedWorkflowAppend",
        "WorkflowServiceError",
    ],
)
def test_public_service_api_missing_red(name):
    assert hasattr(eb, name)
    assert name in eb.__all__


def test_real_sdk_append_retry_and_independent_sql_audit(tmp_path):
    server, path, before = service(tmp_path)
    with server:
        sdk = client(server)
        prepared = sdk.prepare_append([command()], request_id="one", expected=before.checkpoint)
        restored = eb.PreparedWorkflowAppend.from_dict(prepared.to_dict())
        committed = sdk.append(restored)
        assert (
            sdk.lookup(request_id="one", expected_request_digest=prepared.request_digest)
            == committed
        )
        assert sdk.append(prepared) == committed
    _, receipts, operations, checkpoint = audit(path)
    assert len(receipts) == len(operations) == 1
    assert checkpoint == committed.result.checkpoint.to_dict()
    assert server.state == "CLOSED"


def test_actor_mismatch_precedes_every_store_access(tmp_path, monkeypatch):
    server, _, before = service(tmp_path)
    with server:

        def forbidden(*args, **kwargs):
            raise AssertionError("store accessed before actor binding")

        monkeypatch.setattr(eb.SQLiteWorkflowStore, "_connect", forbidden)
        status, response = raw(
            server,
            "append",
            {
                "schema_version": "1.0",
                "request_id": "forged",
                "request_digest": "0" * 64,
                "expected_checkpoint": before.checkpoint.to_dict(),
                "transitions": [command(actor_id="reviewer").to_dict()],
            },
        )
        assert status == 403
        assert response["outcome"] == "none"


@pytest.mark.parametrize("failure", [MemoryError(), eb.ValidationError("encoded output failed")])
def test_returned_commit_remains_complete_after_response_allocation_failure(
    tmp_path, monkeypatch, failure
):
    server, path, before = service(tmp_path)
    with server:
        sdk = client(server)
        prepared = sdk.prepare_append([command()], request_id="one", expected=before.checkpoint)
        monkeypatch.setattr(server, "_success", lambda *a, **k: (_ for _ in ()).throw(failure))
        with pytest.raises(eb.WorkflowServiceError) as caught:
            sdk.append(prepared)
        assert caught.value.outcome == "complete"
    assert len(audit(path)[2]) == 1
