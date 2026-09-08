"""A semantic gate separate from existing procedural approval/quorum rules.

Authority, check policy, and final heads are independently trusted inputs.
Caller-declared actor names and locally calculated hashes are not authentication.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from .authority import AuthorityPolicy, ClaimStatus, _identifier
from .checks import (
    CheckEvaluation,
    CheckLimitError,
    CheckLimits,
    CheckOutcome,
    CheckPlan,
    _Budget,
    _document,
    _encoded,
    _evaluate,
    _limits,
    _snapshot,
    _wire,
)
from .errors import InputFormatError, ValidationError
from .ledger import _fields, _hash
from .workflow import WorkflowBundle, replay_workflow


@dataclass(frozen=True, slots=True)
class CheckPolicy:
    """One externally pinned claim/plan; never infer trust from bundle contents."""

    policy_id: str
    workflow_id: str
    scope: str
    claim_id: str
    authority_digest: str
    plan_artifact_id: str
    plan_digest: str
    evaluation_artifact_id: str

    def __post_init__(self) -> None:
        for name in (
            "policy_id",
            "workflow_id",
            "scope",
            "claim_id",
            "plan_artifact_id",
            "evaluation_artifact_id",
        ):
            _identifier(getattr(self, name), name)
        _hash(self.authority_digest, "policy.authority_digest")
        _hash(self.plan_digest, "policy.plan_digest")
        if self.plan_artifact_id == self.evaluation_artifact_id:
            raise ValidationError("plan and evaluation artifact IDs must be distinct")

    def to_dict(self) -> dict[str, str]:
        return {
            "kind": "evidence-braid-check-policy",
            "schema_version": "1.0",
            "policy_id": self.policy_id,
            "workflow_id": self.workflow_id,
            "scope": self.scope,
            "claim_id": self.claim_id,
            "authority_digest": self.authority_digest,
            "plan_artifact_id": self.plan_artifact_id,
            "plan_digest": self.plan_digest,
            "evaluation_artifact_id": self.evaluation_artifact_id,
        }

    def to_bytes(self) -> bytes:
        return _encoded(self.to_dict())

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    @classmethod
    def from_dict(cls, value: Any) -> CheckPolicy:
        if type(value) is not dict:
            raise ValidationError("check policy must be a plain closed object")
        fields = {
            "policy_id",
            "workflow_id",
            "scope",
            "claim_id",
            "authority_digest",
            "plan_artifact_id",
            "plan_digest",
            "evaluation_artifact_id",
        }
        data = _fields(value, fields | {"kind", "schema_version"}, "check policy")
        _wire(data, "evidence-braid-check-policy")
        return cls(**{key: data[key] for key in fields})


@dataclass(frozen=True, slots=True)
class CheckedClaim:
    """A result description, not an independently verifiable trust certificate."""

    workflow_id: str
    scope: str
    claim_id: str
    workflow_head: str
    evidence_head: str
    authority_digest: str
    policy_digest: str
    plan_digest: str
    procedural_status: ClaimStatus
    evaluation: CheckEvaluation

    def __post_init__(self) -> None:
        for name in ("workflow_id", "scope", "claim_id"):
            _identifier(getattr(self, name), name)
        for name in (
            "workflow_head",
            "evidence_head",
            "authority_digest",
            "policy_digest",
            "plan_digest",
        ):
            _hash(getattr(self, name), name)
        if type(self.procedural_status) is not ClaimStatus:
            raise ValidationError("checked claim requires a typed procedural status")
        if (
            type(self.evaluation) is not CheckEvaluation
            or self.evaluation.plan_digest != self.plan_digest
        ):
            raise ValidationError("checked claim evaluation must refer to the same plan")

    @property
    def accepted(self) -> bool:
        return (
            self.procedural_status is ClaimStatus.APPROVED
            and self.evaluation.outcome is CheckOutcome.PASS
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": "evidence-braid-checked-claim",
            "schema_version": "1.0",
            "workflow_id": self.workflow_id,
            "scope": self.scope,
            "claim_id": self.claim_id,
            "workflow_head": self.workflow_head,
            "evidence_head": self.evidence_head,
            "authority_digest": self.authority_digest,
            "policy_digest": self.policy_digest,
            "plan_digest": self.plan_digest,
            "evaluation_digest": self.evaluation.digest,
            "procedural_status": self.procedural_status.value,
            "evaluation": self.evaluation.to_dict(),
            "accepted": self.accepted,
        }

    def to_bytes(self) -> bytes:
        return _encoded(self.to_dict())


def parse_check_policy(raw: bytes, *, limits: CheckLimits | None = None) -> CheckPolicy:
    bounds = _limits(limits)
    budget = _Budget(bounds)
    policy = CheckPolicy.from_dict(_document(raw, budget, 4096))
    encoded = policy.to_bytes()
    budget.charge(len(encoded) + len(raw))
    if encoded != raw:
        raise InputFormatError("check policies require their exact canonical bytes")
    return policy


def verify_claim_checks(
    bundle: WorkflowBundle,
    *,
    authority: AuthorityPolicy,
    policy: CheckPolicy,
    contents: dict[str, bytes],
    expected_head: str,
    expected_evidence_head: str,
    limits: CheckLimits | None = None,
) -> CheckedClaim:
    """Replay approvals, then recompute the pinned plan from retained bytes.

    The same immutable snapshot supplies every hash, parse, predicate, and
    claimed-result comparison. Invalid input or resource exhaustion raises;
    legitimate fail/unknown evaluations return accepted=False. Legacy workflow
    replay has its own finite admission limits, separate from check-work units.
    """
    if (
        type(bundle) is not WorkflowBundle
        or type(authority) is not AuthorityPolicy
        or type(policy) is not CheckPolicy
    ):
        raise ValidationError("check gate requires typed workflow, authority, and external policy")
    _hash(expected_head, "expected_head")
    _hash(expected_evidence_head, "expected_evidence_head")
    if (
        bundle.workflow_id != policy.workflow_id
        or authority.digest != policy.authority_digest
        or bundle.evidence.head_digest != expected_evidence_head
    ):
        raise ValidationError(
            "workflow does not match the externally pinned policy or evidence head"
        )
    state = replay_workflow(bundle, authority=authority, expected_head=expected_head)
    claim = state.claims.get(policy.claim_id)
    if claim is None or claim.scope != policy.scope:
        raise ValidationError("policy claim is missing or belongs to another scope")
    bounds = _limits(limits)
    budget = _Budget(bounds)
    budget.charge(len(policy.to_bytes()))
    retained = _snapshot(contents, bounds, extra=2)
    artifacts = {item.artifact_id: item for item in bundle.artifacts}
    for identifier in (policy.plan_artifact_id, policy.evaluation_artifact_id):
        item = artifacts.get(identifier)
        if (
            item is None
            or identifier not in claim.artifact_ids
            or identifier not in retained
            or item.claim_id != claim.claim_id
            or item.scope != claim.scope
            or item.media_type != "application/json"
        ):
            raise ValidationError("check plan and evaluation must be retained bound JSON artifacts")
        budget.charge(len(retained[identifier]))
        if not item.matches(retained[identifier]):
            raise ValidationError("check metadata bytes differ from the workflow commitment")
    raw_plan = retained[policy.plan_artifact_id]
    budget.charge(len(raw_plan))
    if hashlib.sha256(raw_plan).hexdigest() != policy.plan_digest:
        raise ValidationError("retained plan differs from the external plan pin")
    plan = CheckPlan.from_dict(_document(raw_plan, budget, bounds.max_plan_bytes))
    encoded_plan = plan.to_bytes()
    budget.charge(len(encoded_plan) + len(raw_plan))
    if encoded_plan != raw_plan:
        raise InputFormatError("retained plan must use its exact canonical bytes")
    budget.charge(len(claim.statement.encode("utf-8")))
    if (
        plan.workflow_id != bundle.workflow_id
        or plan.scope != claim.scope
        or plan.claim_id != claim.claim_id
        or plan.authority_digest != authority.digest
        or plan.evidence_head != expected_evidence_head
        or plan.statement_digest != hashlib.sha256(claim.statement.encode("utf-8")).hexdigest()
    ):
        raise ValidationError("plan context does not match the authorized claim and evidence")
    input_ids = {item.artifact_id for item in plan.inputs}
    metadata_ids = {policy.plan_artifact_id, policy.evaluation_artifact_id}
    if input_ids & metadata_ids:
        raise ValidationError("plan inputs cannot include the plan or its evaluation")
    if set(retained) != input_ids | metadata_ids:
        raise ValidationError("retained gate inventory must exactly match plan inputs and metadata")
    if any(
        item.artifact_id not in claim.artifact_ids or artifacts.get(item.artifact_id) != item
        for item in plan.inputs
    ):
        raise ValidationError("plan inputs must match exact bound claim artifact commitments")
    evaluation = _evaluate(plan, {key: retained[key] for key in input_ids}, budget)
    claimed = retained[policy.evaluation_artifact_id]
    _document(claimed, budget, bounds.max_output_bytes)
    actual = evaluation.to_bytes()
    budget.charge(len(actual) + len(claimed))
    if actual != claimed:
        raise ValidationError("retained evaluation differs from independent recomputation")
    result = CheckedClaim(
        bundle.workflow_id,
        claim.scope,
        claim.claim_id,
        state.head_digest,
        bundle.evidence.head_digest,
        authority.digest,
        policy.digest,
        plan.digest,
        claim.status,
        evaluation,
    )
    output = result.to_bytes()
    if len(output) > bounds.max_output_bytes:
        raise CheckLimitError("checked-claim output exceeds its configured bound")
    budget.charge(len(output))
    return result
