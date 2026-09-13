"""Offline real subprocess CLI: anchored append, recovery and portable export."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from evidence_braid import (
    ActorKind,
    AuthorityPolicy,
    AuthorityRole,
    ScopeGrant,
    SQLiteWorkflowStore,
    WorkflowAction,
    WorkflowActor,
    WorkflowCheckpoint,
    WorkflowTransition,
    build_ledger,
    build_workflow,
)


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def write_json(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    return path


def main() -> None:
    policy = AuthorityPolicy(
        "demo-authority",
        (WorkflowActor("author", ActorKind.HUMAN, (ScopeGrant("demo", AuthorityRole.AUTHOR),)),),
    )
    initial = build_workflow("command-demo", authority=policy, evidence=build_ledger([]))
    with TemporaryDirectory(prefix="evidence-braid-workflow-cli-") as directory:
        root = Path(directory)
        database = root / "workflow.db"
        policy_file = write_json(root / "authority.json", policy.to_dict())
        initial_file = write_json(root / "initial.json", initial.to_dict())

        def invoke(operation: str, *options: str | Path) -> object:
            process = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-m",
                    "evidence_braid",
                    "workflow-store",
                    operation,
                    str(database),
                    "--authority",
                    str(policy_file),
                    "--expected-context",
                    initial.context_digest,
                    *map(str, options),
                ],
                cwd=root,
                capture_output=True,
                check=False,
                timeout=30,
            )
            expect(process.returncode == 0 and not process.stderr, "command failed")
            value = json.loads(process.stdout.decode("utf-8"))
            canonical = (
                json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
            )
            expect(process.stdout == canonical.encode("utf-8"), "noncanonical command report")
            return value

        created = invoke("create", "--bundle", initial_file, "--expected-head", initial.head_digest)
        store = SQLiteWorkflowStore(
            database, authority=policy, expected_context=initial.context_digest
        )
        expect(created == store.snapshot().to_dict(), "creation report differs from database")

        def request(identifier: str, checkpoint: WorkflowCheckpoint):
            transition = WorkflowTransition(
                identifier,
                WorkflowAction.CREATE,
                "author",
                "demo",
                "claim-" + identifier,
                0,
                statement="The local command workflow produced this draft claim.",
            )
            checkpoint_file = write_json(
                root / f"{identifier}-checkpoint.json", checkpoint.to_dict()
            )
            commands = write_json(
                root / f"{identifier}-commands.json",
                {
                    "schema_version": "1.0",
                    "transitions": [transition.to_dict()],
                },
            )
            options = (
                "--commands",
                commands,
                "--request-id",
                identifier,
                "--expected-checkpoint",
                checkpoint_file,
            )
            identity = invoke("request-digest", *options)
            digest = store.request_digest([transition], request_id=identifier, expected=checkpoint)
            expect(
                identity
                == {
                    "request_id": identifier,
                    "request_digest": digest,
                    "expected_checkpoint": checkpoint.to_dict(),
                },
                "request identity differs from intended transition",
            )
            # A real deployment retains these independently BEFORE append.
            # Same-directory demo files are not independent witnesses.
            write_json(root / f"{identifier}-identity.json", identity)
            append_options = (*options, "--expected-request-digest", digest)
            return invoke("append", *append_options), append_options, digest

        first, first_options, first_digest = request("one", store.snapshot().checkpoint)
        second, _, _ = request("two", store.snapshot().checkpoint)
        expect(invoke("append", *first_options) == first, "historical retry changed its prefix")
        recovered = invoke(
            "lookup", "--request-id", "one", "--expected-request-digest", first_digest
        )
        expect(recovered == first, "lookup did not recover the original commit")
        expect(
            invoke("lookup", "--request-id", "absent", "--expected-request-digest", "0" * 64)
            is None,
            "unknown request was fabricated",
        )
        latest = store.snapshot()
        anchor_file = write_json(root / "current-checkpoint.json", latest.checkpoint.to_dict())
        expect(
            invoke("snapshot", "--expected-checkpoint", anchor_file) == latest.to_dict(),
            "anchored snapshot differs from database",
        )
        expect(
            invoke("export", "--expected-checkpoint", anchor_file) == latest.bundle.to_dict(),
            "portable export differs from existing format",
        )
        expect(second["result"] == latest.to_dict(), "later append is not the current state")
        expect(
            (latest.checkpoint.record_count, latest.checkpoint.operation_count) == (2, 2),
            "retries changed record or operation count",
        )
        expect(
            [record.transition.transition_id for record in latest.bundle.records] == ["one", "two"],
            "commands were not committed exactly once in order",
        )
        print(
            json.dumps(
                {
                    "commands": [
                        "create",
                        "snapshot",
                        "export",
                        "request-digest",
                        "append",
                        "lookup",
                    ],
                    "record_count": 2,
                    "operation_count": 2,
                    "historical_retry_equal": True,
                    "portable_export_equal": True,
                    "actor_authentication_provided": False,
                },
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    main()
