"""Create an original offline claim, retained checks, approvals, and closed ZIP.

Run: python examples/offline_claim_checks.py NEW_OUTPUT_DIRECTORY
No network, models, user callbacks, or credentials are involved.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from evidence_braid import (
    ActorKind,
    ArtifactReference,
    AuthorityPolicy,
    AuthorityRole,
    CheckOperator,
    CheckPlan,
    CheckPolicy,
    CheckRule,
    EvidenceEvent,
    ScopeGrant,
    WorkflowAction,
    WorkflowActor,
    WorkflowTransition,
    build_artifact_bundle,
    build_ledger,
    build_workflow,
    evaluate_checks,
    verify_artifact_bundle,
    verify_claim_checks,
    write_workflow_bundle,
)
from evidence_braid.io import canonical_json


def main(directory: Path) -> dict[str, object]:
    scope, claim_id, workflow_id = "lab/a", "retained-analysis", "checks-demo"
    authority = AuthorityPolicy(
        "independent-review",
        (
            WorkflowActor("author", ActorKind.HUMAN, (ScopeGrant(scope, AuthorityRole.AUTHOR),)),
            WorkflowActor(
                "reviewer", ActorKind.HUMAN, (ScopeGrant(scope, AuthorityRole.REVIEWER),)
            ),
        ),
    )
    ledger = build_ledger(
        [
            EvidenceEvent.from_dict(
                {
                    "event_id": "observation",
                    "claim": claim_id,
                    "modality": "sensor",
                    "source": "local-fixture",
                    "signal": "support",
                    "confidence": 1,
                    "observed_at": "2026-09-08T00:00:00Z",
                    "ingested_at": "2026-09-08T00:00:00Z",
                    "attributes": {"workflow_scope": scope},
                }
            )
        ]
    )
    retained = {"analysis": b'{"items":3,"ok":true}', "expected": b'{"items":3}'}

    def reference(name: str, raw: bytes) -> ArtifactReference:
        return ArtifactReference(
            name, scope, claim_id, hashlib.sha256(raw).hexdigest(), len(raw), "application/json"
        )

    statement = "Retained analysis is marked ok and has the expected bounded item count."
    plan = CheckPlan(
        "three-items-v1",
        workflow_id,
        scope,
        claim_id,
        hashlib.sha256(statement.encode()).hexdigest(),
        authority.digest,
        ledger.head_digest,
        tuple(reference(name, raw) for name, raw in retained.items()),
        (
            CheckRule("ok", CheckOperator.EQUALS, "analysis", ("ok",), expected=True),
            CheckRule(
                "bounded",
                CheckOperator.INTEGER_RANGE,
                "analysis",
                ("items",),
                minimum=1,
                maximum=10,
            ),
            CheckRule(
                "count",
                CheckOperator.SAME_VALUE,
                "analysis",
                ("items",),
                other_artifact_id="expected",
                other_path=("items",),
            ),
        ),
    )
    evaluation = evaluate_checks(plan, retained)
    retained.update(plan=plan.to_bytes(), evaluation=evaluation.to_bytes())
    policy = CheckPolicy(
        "require-three-checks",
        workflow_id,
        scope,
        claim_id,
        authority.digest,
        "plan",
        plan.digest,
        "evaluation",
    )
    artifacts = tuple(reference(name, raw) for name, raw in retained.items())
    transitions = [
        WorkflowTransition(
            "create", WorkflowAction.CREATE, "author", scope, claim_id, 0, statement=statement
        ),
        WorkflowTransition(
            "evidence",
            WorkflowAction.BIND_EVIDENCE,
            "author",
            scope,
            claim_id,
            1,
            reference_id="observation",
            reference_digest=ledger.entries[0].digest,
        ),
    ]
    for item in artifacts:
        transitions.append(
            WorkflowTransition(
                f"bind-{item.artifact_id}",
                WorkflowAction.BIND_ARTIFACT,
                "author",
                scope,
                claim_id,
                len(transitions),
                reference_id=item.artifact_id,
                reference_digest=item.sha256,
            )
        )
    transitions.append(
        WorkflowTransition(
            "submit", WorkflowAction.SUBMIT, "author", scope, claim_id, len(transitions)
        )
    )
    transitions.append(
        WorkflowTransition(
            "approve", WorkflowAction.APPROVE, "reviewer", scope, claim_id, len(transitions)
        )
    )
    bundle = build_workflow(
        workflow_id,
        authority=authority,
        evidence=ledger,
        artifacts=artifacts,
        transitions=transitions,
    )
    checked = verify_claim_checks(
        bundle,
        authority=authority,
        policy=policy,
        contents=retained,
        expected_head=bundle.head_digest,
        expected_evidence_head=ledger.head_digest,
    )
    directory.mkdir()  # The demonstration never replaces an existing output directory.
    sources = {name: directory / f"{name}.json" for name in retained}
    for name, path in sources.items():
        path.write_bytes(retained[name])
    (directory / "authority.json").write_bytes(
        canonical_json(authority.to_dict(), pretty=False).encode()
    )
    (directory / "check-policy.json").write_bytes(policy.to_bytes())
    write_workflow_bundle(directory / "workflow.json", bundle, authority=authority)
    archive = directory / "artifacts.zip"
    built = build_artifact_bundle(archive, bundle, sources, authority=authority)
    verify_artifact_bundle(
        archive,
        authority=authority,
        expected_head=bundle.head_digest,
        expected_evidence_head=ledger.head_digest,
        expected_bundle_digest=built.bundle_digest,
    )
    return checked.to_dict()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    print(json.dumps(main(parser.parse_args().directory), sort_keys=True))
