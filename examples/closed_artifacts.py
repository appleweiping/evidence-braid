"""Create, move, and verify a real closed artifact archive entirely offline."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from evidence_braid import (
    ActorKind,
    ArtifactReference,
    AuthorityPolicy,
    AuthorityRole,
    EvidenceEvent,
    ScopeGrant,
    WorkflowAction,
    WorkflowActor,
    WorkflowTransition,
    build_artifact_bundle,
    build_ledger,
    build_workflow,
    verify_artifact_bundle,
)


def main() -> None:
    authority = AuthorityPolicy(
        "offline-bench-review",
        (
            WorkflowActor("author", ActorKind.HUMAN, (ScopeGrant("bench", AuthorityRole.AUTHOR),)),
            WorkflowActor(
                "reviewer", ActorKind.HUMAN, (ScopeGrant("bench", AuthorityRole.REVIEWER),)
            ),
        ),
    )
    evidence = build_ledger(
        [
            EvidenceEvent.from_dict(
                {
                    "event_id": "reading-1",
                    "claim": "stable",
                    "modality": "sensor",
                    "source": "bench-1",
                    "signal": "support",
                    "confidence": 0.8,
                    "observed_at": "2026-09-07T12:00:00Z",
                    "ingested_at": "2026-09-07T12:00:01Z",
                    "attributes": {"workflow_scope": "bench"},
                }
            )
        ]
    )
    contents = b"Bench result: no instability observed during the bounded experiment.\n"
    reference = ArtifactReference(
        "bench-result",
        "bench",
        "stable",
        hashlib.sha256(contents).hexdigest(),
        len(contents),
        "text/plain",
    )
    transitions = (
        WorkflowTransition(
            "create",
            WorkflowAction.CREATE,
            "author",
            "bench",
            "stable",
            0,
            statement="Stable within the bounded experiment.",
        ),
        WorkflowTransition(
            "reading",
            WorkflowAction.BIND_EVIDENCE,
            "author",
            "bench",
            "stable",
            1,
            reference_id="reading-1",
            reference_digest=evidence.entries[0].digest,
        ),
        WorkflowTransition(
            "artifact",
            WorkflowAction.BIND_ARTIFACT,
            "author",
            "bench",
            "stable",
            2,
            reference_id=reference.artifact_id,
            reference_digest=reference.sha256,
        ),
        WorkflowTransition("submit", WorkflowAction.SUBMIT, "author", "bench", "stable", 3),
        WorkflowTransition("review", WorkflowAction.APPROVE, "reviewer", "bench", "stable", 4),
    )
    workflow = build_workflow(
        "closed-bench-review",
        authority=authority,
        evidence=evidence,
        artifacts=(reference,),
        transitions=transitions,
    )
    # In a real exchange, retain these and the trusted authority outside the archive.
    workflow_head, evidence_head = workflow.head_digest, evidence.head_digest
    with TemporaryDirectory(prefix="evidence-closed-artifacts-") as directory:
        root = Path(directory)
        source = root / "private-notes.txt"
        source.write_bytes(contents)
        archive = root / "closed.zip"
        built = build_artifact_bundle(
            archive, workflow, {reference.artifact_id: source}, authority=authority
        )
        source.unlink()
        moved = root / "recipient.zip"
        archive.rename(moved)
        verified = verify_artifact_bundle(
            moved,
            authority=authority,
            expected_head=workflow_head,
            expected_evidence_head=evidence_head,
            expected_bundle_digest=built.bundle_digest,
        )
        assert verified == built and verified.state.claims["stable"].status.value == "approved"
        print(
            json.dumps(
                {
                    **verified.to_dict(),
                    "source_removed_before_verification": True,
                    "actor_authentication_provided": False,
                },
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    main()
