"""Run a local authority workflow with CAS, idempotent recovery and portable export."""

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
    SQLiteWorkflowStore,
    WorkflowAction,
    WorkflowActor,
    WorkflowTransition,
    build_ledger,
    build_workflow,
    create_workflow_store,
    load_workflow_bundle,
    replay_workflow,
    write_workflow_bundle,
)


def main() -> None:
    scope = "bench/a"
    policy = AuthorityPolicy(
        "bench-review-v1",
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
    event = EvidenceEvent.from_dict(
        {
            "event_id": "observation-1",
            "claim": "bounded-observation",
            "modality": "sensor",
            "source": "bench-1",
            "signal": "support",
            "confidence": 0.8,
            "observed_at": "2026-09-12T00:00:00Z",
            "ingested_at": "2026-09-12T00:00:01Z",
            "attributes": {"workflow_scope": scope},
        }
    )
    content = b"The bounded bench observation was recorded.\n"
    artifact = ArtifactReference(
        "notes", scope, event.claim, hashlib.sha256(content).hexdigest(), len(content), "text/plain"
    )
    evidence = build_ledger([event])
    initial = build_workflow(
        "bench-review", authority=policy, evidence=evidence, artifacts=(artifact,)
    )

    def intent(identifier: str, action: WorkflowAction, revision: int, **fields):
        return WorkflowTransition(
            identifier,
            action,
            fields.pop("actor", "author"),
            scope,
            event.claim,
            revision,
            **fields,
        )

    submission = (
        intent(
            "create",
            WorkflowAction.CREATE,
            0,
            statement="The bounded observation has material to review.",
        ),
        intent(
            "bind-evidence",
            WorkflowAction.BIND_EVIDENCE,
            1,
            reference_id=event.event_id,
            reference_digest=evidence.entries[0].digest,
        ),
        intent(
            "bind-notes",
            WorkflowAction.BIND_ARTIFACT,
            2,
            reference_id=artifact.artifact_id,
            reference_digest=artifact.sha256,
        ),
        intent("submit", WorkflowAction.SUBMIT, 3),
    )
    with TemporaryDirectory(prefix="evidence-braid-durable-workflow-") as directory:
        root = Path(directory)
        store = create_workflow_store(
            root / "workflow.db",
            initial,
            authority=policy,
            expected_context=initial.context_digest,
            expected_head=initial.head_digest,
        )
        before = store.snapshot().checkpoint
        # Retain ID + digest + expected checkpoint + intent independently in production.
        digest = store.request_digest(submission, request_id="submission-1", expected=before)
        submitted = store.append(submission, request_id="submission-1", expected=before)
        reviewed = store.append(
            (
                intent("review-1", WorkflowAction.APPROVE, 4, actor="reviewer-1"),
                intent("review-2", WorkflowAction.APPROVE, 5, actor="reviewer-2"),
            ),
            request_id="review-1",
            expected=submitted.result.checkpoint,
        )
        anchor = reviewed.result.checkpoint
        reopened = SQLiteWorkflowStore(
            store.path, authority=policy, expected_context=initial.context_digest, expected=anchor
        )
        assert reopened.lookup("submission-1", expected_request_digest=digest) == submitted
        assert reopened.append(submission, request_id="submission-1", expected=before) == submitted
        latest = reopened.snapshot(expected=anchor)
        assert latest == reviewed.result and latest.bundle.verify_artifacts(
            {artifact.artifact_id: content}
        )
        write_workflow_bundle(root / "workflow.json", latest.bundle, authority=policy)
        portable = load_workflow_bundle(
            root / "workflow.json",
            authority=policy,
            expected_head=anchor.workflow_head,
            expected_evidence_head=evidence.head_digest,
        )
        assert portable == latest.bundle
        state = replay_workflow(portable, authority=policy)
        print(
            json.dumps(
                {
                    "status": state.claims[event.claim].status.value,
                    "record_count": anchor.record_count,
                    "operation_count": anchor.operation_count,
                    "historical_retry_equal": True,
                    "portable_replay_equal": True,
                    "actor_authentication_provided": False,
                },
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    main()
