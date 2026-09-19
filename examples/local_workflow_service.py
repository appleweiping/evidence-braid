"""Offline real loopback service/SDK with independent full receipt/journal checks."""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from contextlib import ExitStack, closing
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from evidence_braid import (
    ActorKind,
    AuthorityPolicy,
    AuthorityRole,
    LocalWorkflowService,
    ScopeGrant,
    WorkflowActor,
    WorkflowClient,
    WorkflowServiceCredential,
    WorkflowTransition,
    build_ledger,
    build_workflow,
    create_workflow_store,
)


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def digest(value: Any) -> str:
    raw = json.dumps(
        value, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def expected_append(
    base: dict[str, Any],
    previous: dict[str, Any],
    records: list[dict[str, Any]],
    command: dict[str, Any],
    public_id: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Independent documented wire calculation, not service/SDK serializer calls."""
    context = base["context_digest"]
    namespace = digest(
        {
            "kind": "evidence-braid-workflow-service-request-namespace",
            "schema_version": "1.0",
            "service_id": "offline-service",
            "context_digest": context,
            "actor_id": command["actor_id"],
        }
    )
    request_id = "svc1." + namespace + "." + public_id
    request_digest = digest(
        {
            "kind": "evidence-braid-workflow-request",
            "schema_version": "1.0",
            "request_id": request_id,
            "expected_checkpoint": previous,
            "transitions": [command],
        }
    )
    receipt = {
        "schema_version": "1.0",
        "sequence": len(records),
        "context_digest": context,
        "previous_digest": previous["workflow_head"],
        "transition": command,
    }
    receipt["digest"] = digest(receipt)
    rows = [*records, receipt]
    operation = {
        "kind": "evidence-braid-workflow-operation",
        "schema_version": "1.0",
        "sequence": previous["operation_count"],
        "request_id": request_id,
        "request_digest": request_digest,
        "expected_checkpoint": previous,
        "result_record_count": len(rows),
        "result_workflow_head": receipt["digest"],
        "previous_digest": previous["operation_head"],
    }
    operation["digest"] = digest(operation)
    checkpoint = {
        "schema_version": "1.0",
        "context_digest": context,
        "record_count": len(rows),
        "workflow_head": receipt["digest"],
        "operation_count": previous["operation_count"] + 1,
        "operation_head": operation["digest"],
    }
    bundle = {**base, "records": rows, "record_count": len(rows), "head_digest": receipt["digest"]}
    return {
        "request_id": request_id,
        "request_digest": request_digest,
        "previous": previous,
        "result": {"bundle": bundle, "checkpoint": checkpoint},
    }, operation


def main() -> None:
    policy = AuthorityPolicy(
        "offline-actors",
        tuple(
            WorkflowActor(
                name,
                ActorKind.HUMAN,
                (ScopeGrant("demo", AuthorityRole.AUTHOR),),
            )
            for name in ("alice", "bob")
        ),
    )
    initial = build_workflow("offline-workflow", authority=policy, evidence=build_ledger([]))
    commands = [
        {
            "transition_id": "create-" + name,
            "action": "create",
            "actor_id": name,
            "scope": "demo",
            "claim_id": "claim-" + name,
            "expected_revision": 0,
            "statement": "A procedural claim by " + name + ".",
            "reference_id": None,
            "reference_digest": None,
            "reason": None,
        }
        for name in ("alice", "bob")
    ]
    tokens = {name: secrets.token_hex(32) for name in ("alice", "bob")}
    credentials = tuple(
        WorkflowServiceCredential(
            name + "-credential",
            name,
            hashlib.sha256(bytes.fromhex(tokens[name])).hexdigest(),
            "act",
        )
        for name in tokens
    )
    with TemporaryDirectory(prefix="evidence-local-service-") as directory:
        database = Path(directory) / "workflow.db"
        store = create_workflow_store(
            database,
            initial,
            authority=policy,
            expected_context=initial.context_digest,
            expected_head=initial.head_digest,
        )
        before = store.snapshot()
        first_expected, first_operation = expected_append(
            initial.to_dict(), before.checkpoint.to_dict(), [], commands[0], "first"
        )
        second_expected, second_operation = expected_append(
            initial.to_dict(),
            first_expected["result"]["checkpoint"],
            first_expected["result"]["bundle"]["records"],
            commands[1],
            "second",
        )
        server = LocalWorkflowService(
            database=database,
            authority=policy,
            expected_workflow_id=initial.workflow_id,
            expected_context=initial.context_digest,
            startup_checkpoint=before.checkpoint,
            service_id="offline-service",
            credentials=credentials,
        )
        with ExitStack() as owners:
            owners.enter_context(server)
            clients = {
                name: WorkflowClient(
                    address=server.address,
                    token=tokens[name],
                    service_id="offline-service",
                    actor_id=name,
                    workflow_id=initial.workflow_id,
                    context_digest=initial.context_digest,
                    authority=policy,
                )
                for name in tokens
            }
            for client in clients.values():
                owners.callback(client.close)
            expect(
                clients["alice"].snapshot(expected=before.checkpoint) == before, "startup snapshot"
            )
            first = clients["alice"].prepare_append(
                [WorkflowTransition.from_dict(commands[0])],
                request_id="first",
                expected=before.checkpoint,
            )
            committed = clients["alice"].append(first)
            expect(committed.to_dict() == first_expected, "full first commit mismatch")
            second = clients["bob"].prepare_append(
                [WorkflowTransition.from_dict(commands[1])],
                request_id="second",
                expected=committed.result.checkpoint,
            )
            later = clients["bob"].append(second)
            expect(later.to_dict() == second_expected, "full second commit mismatch")
            recovered = clients["alice"].lookup(
                request_id="first", expected_request_digest=first.request_digest
            )
            expect(
                recovered is not None and recovered.to_dict() == first_expected,
                "historical recovery",
            )
        expect(server.state == "CLOSED", "server did not finish owned shutdown")
        with closing(sqlite3.connect(database)) as connection:
            receipts = [
                json.loads(row[0])
                for row in connection.execute(
                    "SELECT document FROM workflow_receipts ORDER BY sequence"
                )
            ]
            operations = [
                json.loads(row[0])
                for row in connection.execute(
                    "SELECT document FROM workflow_operations ORDER BY sequence"
                )
            ]
            checkpoint = json.loads(
                connection.execute("SELECT document FROM workflow_meta").fetchone()[0]
            )
        expect(receipts == second_expected["result"]["bundle"]["records"], "full receipt rows")
        expect(operations == [first_operation, second_operation], "full operation journal")
        expect(checkpoint == second_expected["result"]["checkpoint"], "complete checkpoint")
        expect(
            (len(receipts), len(operations), len(first_expected["result"]["bundle"]["records"]))
            == (2, 2, 1),
            "exact record/operation/historical counters",
        )
        print(
            json.dumps(
                {
                    "record_count": 2,
                    "operation_count": 2,
                    "historical_count": 1,
                    "service_closed": True,
                },
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    main()
