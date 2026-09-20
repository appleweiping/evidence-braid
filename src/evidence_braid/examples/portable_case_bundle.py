"""Offline installed-package smoke: durable case to independently verified ZIP."""

from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

from evidence_braid import (
    ActorKind,
    ArtifactReference,
    AuthorityPolicy,
    AuthorityRole,
    CaseActor,
    CaseActorKind,
    CaseAuthority,
    CaseGrant,
    CaseJournal,
    CaseObservation,
    CasePlan,
    CaseRole,
    EvidenceEvent,
    ObservationAdapter,
    ObservationRegistry,
    ScopeGrant,
    WorkflowAction,
    WorkflowActor,
    WorkflowTransition,
    build_artifact_bundle,
    build_ledger,
    build_workflow,
    create_case_store,
    verify_supported_case_bundle,
)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def run_fixture() -> tuple[str, str, str]:
    assertion = b"The cache is stale."
    test_input = b'{"incident":"cache","revision":"B"}'
    expected_output = b"revision-B"
    case_authority = CaseAuthority(
        "offline-case-policy",
        (
            CaseActor("model", CaseActorKind.MODEL, (CaseGrant("site/a", CaseRole.PROPOSE),)),
            CaseActor("observer", CaseActorKind.TOOL, (CaseGrant("site/a", CaseRole.OBSERVE),)),
            CaseActor("evaluator", CaseActorKind.TOOL, (CaseGrant("site/a", CaseRole.EVALUATE),)),
        ),
    )
    plan = CasePlan(
        "case-1",
        "workflow-1",
        "claim-1",
        "site/a",
        "model",
        "assertion-1",
        _sha(assertion),
        "The cache is stale.",
        "A bypass should read the source.",
        "revision-B",
        "input-1",
        _sha(test_input),
        _sha(expected_output),
        "cache-bypass",
        "fixture-cache",
        "1",
        "sha256-equality-v1",
        case_authority.digest,
    )
    planned = CaseJournal.empty(case_authority).append((plan,), authority=case_authority)

    def adapter(raw: bytes) -> bytes:
        if raw != test_input:
            raise ValueError("unexpected committed fixture input")
        return expected_output

    registry = ObservationRegistry(
        (ObservationAdapter("cache-bypass", "fixture-cache", "1", "observer", adapter),)
    )
    workflow_authority = AuthorityPolicy(
        "offline-workflow-policy",
        (
            WorkflowActor("author", ActorKind.HUMAN, (ScopeGrant("site/a", AuthorityRole.AUTHOR),)),
            WorkflowActor(
                "reviewer", ActorKind.HUMAN, (ScopeGrant("site/a", AuthorityRole.REVIEWER),)
            ),
        ),
    )
    event = EvidenceEvent.from_dict(
        {
            "event_id": "event-1",
            "claim": "claim-1",
            "modality": "sensor",
            "source": "offline-bench",
            "signal": "support",
            "confidence": 0.8,
            "observed_at": "2026-09-07T12:00:00Z",
            "ingested_at": "2026-09-07T12:00:01Z",
            "attributes": {"workflow_scope": "site/a"},
        }
    )
    evidence = build_ledger([event])
    with tempfile.TemporaryDirectory(prefix="evidence-portable-case-") as directory:
        root = Path(directory)
        database = root / "case.db"
        store = create_case_store(
            database,
            planned,
            authority=case_authority,
            expected_plan_head=planned.head_digest,
            assertion_bytes=assertion,
            input_bytes=test_input,
        )
        finished = store.execute_observation(
            registry,
            request_id="run-1",
            finish_id="finish-1",
            expected=store.snapshot().checkpoint,
        )
        checked = store.append_checked_verdict(
            operation_id="verdict-1",
            evaluator_id="evaluator",
            expected=finished.result.checkpoint,
        )
        owned = checked.result
        observation = owned.journal.receipts[1].record
        if (
            type(observation) is not CaseObservation
            or observation.artifact_id is None
            or owned.observed_bytes is None
        ):
            raise RuntimeError("fixture observation was not retained")
        journal_id = "journal-1"
        contents = {
            journal_id: owned.journal.to_bytes(),
            plan.assertion_artifact_id: owned.assertion_bytes,
            plan.input_artifact_id: owned.input_bytes,
            observation.artifact_id: owned.observed_bytes,
        }
        references = tuple(
            ArtifactReference(
                identifier,
                plan.scope,
                plan.claim_id,
                _sha(raw),
                len(raw),
                "application/vnd.evidence-braid.case-journal+json"
                if identifier == journal_id
                else "application/octet-stream",
            )
            for identifier, raw in contents.items()
        )
        transitions = [
            WorkflowTransition(
                "create",
                WorkflowAction.CREATE,
                "author",
                plan.scope,
                plan.claim_id,
                0,
                statement="The bypass result supports this claim.",
            ),
            WorkflowTransition(
                "evidence",
                WorkflowAction.BIND_EVIDENCE,
                "author",
                plan.scope,
                plan.claim_id,
                1,
                reference_id="event-1",
                reference_digest=evidence.entries[0].digest,
            ),
        ]
        for reference in references:
            transitions.append(
                WorkflowTransition(
                    f"bind-{reference.artifact_id}",
                    WorkflowAction.BIND_ARTIFACT,
                    "author",
                    plan.scope,
                    plan.claim_id,
                    len(transitions),
                    reference_id=reference.artifact_id,
                    reference_digest=reference.sha256,
                )
            )
        transitions.extend(
            (
                WorkflowTransition(
                    "submit",
                    WorkflowAction.SUBMIT,
                    "author",
                    plan.scope,
                    plan.claim_id,
                    len(transitions),
                ),
                WorkflowTransition(
                    "approve",
                    WorkflowAction.APPROVE,
                    "reviewer",
                    plan.scope,
                    plan.claim_id,
                    len(transitions) + 1,
                ),
            )
        )
        workflow = build_workflow(
            plan.workflow_id,
            authority=workflow_authority,
            evidence=evidence,
            artifacts=references,
            transitions=transitions,
        )
        sources = {}
        for identifier, raw in contents.items():
            source = root / f"source-{identifier}.bin"
            source.write_bytes(raw)
            sources[identifier] = source
        archive = root / "closed.zip"
        built = build_artifact_bundle(archive, workflow, sources, authority=workflow_authority)
        moved = root / "moved.zip"
        archive.replace(moved)
        database.unlink()
        for source in sources.values():
            source.unlink()
        verified = verify_supported_case_bundle(
            moved,
            workflow_authority=workflow_authority,
            case_authority=case_authority,
            case_journal_artifact_id=journal_id,
            expected_workflow_head=workflow.head_digest,
            expected_evidence_head=evidence.head_digest,
            expected_case_head=owned.journal.head_digest,
            expected_bundle_digest=built.bundle_digest,
        )
        if (
            verified.case_state.outcome is None
            or verified.case_state.outcome.value != "supported"
            or verified.archive.bundle_digest != built.bundle_digest
            or verified.journal.head_digest != owned.journal.head_digest
            or _sha(contents[observation.artifact_id]) != observation.observed_sha256
        ):
            raise RuntimeError("portable case verification differs")
        return verified.journal.head_digest, workflow.head_digest, built.bundle_digest


def main() -> None:
    case_head, workflow_head, bundle_digest = run_fixture()
    print(f"case={case_head}")
    print(f"workflow={workflow_head}")
    print(f"bundle={bundle_digest}")
    print("outcome=supported")


if __name__ == "__main__":
    main()
