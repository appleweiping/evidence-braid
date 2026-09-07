"""Persist real evidence, review a claim, export receipts, and replay offline."""

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
    SQLiteLedger,
    WorkflowAction,
    WorkflowActor,
    WorkflowTransition,
    build_workflow,
    load_workflow_bundle,
    replay_workflow,
    write_workflow_bundle,
)


def main() -> None:
    scope = "laboratory/a"
    authority = AuthorityPolicy(
        "laboratory-review-v1",
        (
            WorkflowActor("author", ActorKind.HUMAN, (ScopeGrant(scope, AuthorityRole.AUTHOR),)),
            WorkflowActor(
                "reviewer-1", ActorKind.HUMAN, (ScopeGrant(scope, AuthorityRole.REVIEWER),)
            ),
            WorkflowActor(
                "reviewer-2", ActorKind.HUMAN, (ScopeGrant(scope, AuthorityRole.REVIEWER),)
            ),
        ),
        approval_quorum=2,
    )
    # This registry is a trusted caller configuration, not obtained from the bundle.
    event = EvidenceEvent.from_dict(
        {
            "event_id": "measurement-1",
            "claim": "sensor-stable",
            "modality": "sensor",
            "source": "bench-1",
            "signal": "support",
            "confidence": 0.8,
            "observed_at": "2026-09-07T12:00:00Z",
            "ingested_at": "2026-09-07T12:00:01Z",
            "attributes": {"workflow_scope": scope},
        }
    )
    content = b"Bench notes: no instability observed during the bounded test.\n"
    artifact = ArtifactReference(
        "bench-notes",
        scope,
        "sensor-stable",
        hashlib.sha256(content).hexdigest(),
        len(content),
        "text/plain",
    )
    with TemporaryDirectory(prefix="evidence-braid-workflow-") as directory:
        root = Path(directory)
        stored = SQLiteLedger(root / "evidence.db").append([event])
        evidence = SQLiteLedger(root / "evidence.db", create=False).snapshot(
            expected_head=stored.head_digest
        )

        def intent(identifier: str, action: WorkflowAction, revision: int, **fields):
            return WorkflowTransition(
                identifier,
                action,
                fields.pop("actor", "author"),
                scope,
                "sensor-stable",
                revision,
                **fields,
            )

        bundle = build_workflow(
            "bench-review-1",
            authority=authority,
            evidence=evidence,
            artifacts=(artifact,),
            transitions=(
                intent(
                    "create",
                    WorkflowAction.CREATE,
                    0,
                    statement="The sensor is stable within this test.",
                ),
                intent(
                    "evidence",
                    WorkflowAction.BIND_EVIDENCE,
                    1,
                    reference_id=event.event_id,
                    reference_digest=evidence.entries[0].digest,
                ),
                intent(
                    "notes",
                    WorkflowAction.BIND_ARTIFACT,
                    2,
                    reference_id=artifact.artifact_id,
                    reference_digest=artifact.sha256,
                ),
                intent("submit", WorkflowAction.SUBMIT, 3),
                intent("review-1", WorkflowAction.APPROVE, 4, actor="reviewer-1"),
                intent("review-2", WorkflowAction.APPROVE, 5, actor="reviewer-2"),
            ),
        )
        head = bundle.head_digest  # Retain independently in a real deployment.
        write_workflow_bundle(root / "workflow.json", bundle, authority=authority)
        restored = load_workflow_bundle(
            root / "workflow.json",
            authority=authority,
            expected_head=head,
            expected_evidence_head=stored.head_digest,
        )
        state = replay_workflow(restored, authority=authority)
        assert restored.verify_artifacts({artifact.artifact_id: content})
        print(
            json.dumps(
                {
                    "workflow_id": state.workflow_id,
                    "status": state.claims["sensor-stable"].status.value,
                    "approval_count": len(state.claims["sensor-stable"].approvals),
                    "record_count": state.record_count,
                    "workflow_head": head,
                    "evidence_head": evidence.head_digest,
                    "offline_replay_equal": restored == bundle,
                    "artifact_content_verified": True,
                    "actor_authentication_provided": False,
                },
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    main()
