"""Read-only supported-case gate for an existing closed artifact archive."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .artifacts import (
    ArtifactBundleLimits,
    VerifiedArtifactBundle,
    _verify_artifact_bundle_internal,
)
from .authority import AuthorityPolicy, ClaimStatus, _identifier
from .case_observation import ObservationLimits, _output
from .epistemic_case import (
    CaseAuthority,
    CaseJournal,
    CaseObservation,
    CasePhase,
    CasePlan,
    CaseState,
    CaseVerdictOutcome,
    replay_case,
)
from .errors import ValidationError

_JOURNAL_MEDIA_TYPE = "application/vnd.evidence-braid.case-journal+json"


@dataclass(frozen=True, slots=True)
class VerifiedSupportedCaseBundle:
    """Detached result; direct construction does not verify archive contents."""

    archive: VerifiedArtifactBundle
    journal: CaseJournal
    case_state: CaseState
    case_id: str
    claim_id: str
    artifact_ids: tuple[str, str, str, str]


def verify_supported_case_bundle(
    path: str | Path,
    *,
    workflow_authority: AuthorityPolicy,
    case_authority: CaseAuthority,
    case_journal_artifact_id: str,
    expected_workflow_head: str,
    expected_evidence_head: str,
    expected_case_head: str,
    expected_bundle_digest: str | None = None,
    limits: ArtifactBundleLimits | None = None,
) -> VerifiedSupportedCaseBundle:
    """Verify archived case bytes, scoped procedural approval and fixed support.

    The policies, heads and selected journal ID must be independently retained.
    This checks declared history and bytes, not adapter execution or identity.
    """
    _identifier(case_journal_artifact_id, "case journal artifact ID")
    if type(case_authority) is not CaseAuthority:
        raise ValidationError("case authority must be independently supplied")
    archive, journal, captured = _verify_artifact_bundle_internal(
        path,
        authority=workflow_authority,
        expected_head=expected_workflow_head,
        expected_evidence_head=expected_evidence_head,
        expected_bundle_digest=expected_bundle_digest,
        limits=limits,
        case_journal_artifact_id=case_journal_artifact_id,
        case_authority=case_authority,
        expected_case_head=expected_case_head,
    )
    # Case capture admits exactly three replayed observed receipts or raises.
    journal = cast(CaseJournal, journal)
    state = replay_case(journal, authority=case_authority, expected_head=expected_case_head)
    if state.phase is not CasePhase.VERDICTED or state.outcome is not CaseVerdictOutcome.SUPPORTED:
        raise ValidationError("archived case is not supported")
    plan = cast(CasePlan, journal.receipts[0].record)
    observation = cast(CaseObservation, journal.receipts[1].record)
    workflow = archive.workflow
    claim = archive.state.claims.get(plan.claim_id)
    if (
        plan.workflow_id != workflow.workflow_id
        or claim is None
        or claim.scope != plan.scope
        or claim.status is not ClaimStatus.APPROVED
    ):
        raise ValidationError("case and currently approved workflow claim differ")
    output_id = cast(str, observation.artifact_id)
    ids = (
        case_journal_artifact_id,
        plan.assertion_artifact_id,
        plan.input_artifact_id,
        output_id,
    )
    if len(set(ids)) != 4 or not set(ids).issubset(claim.artifact_ids):
        raise ValidationError("case artifacts are not all bound to the approved claim")
    references = {item.artifact_id: item for item in workflow.artifacts}
    if references[case_journal_artifact_id].media_type != _JOURNAL_MEDIA_TYPE:
        raise ValidationError("case journal media type differs")
    # Workflow replay checks every bound reference's claim/scope; archive verification
    # hashes the captured objects on the same handle. CaseJournal.from_bytes requires
    # exact canonical bytes, so rechecking those commitments here cannot reject a
    # new archive state.
    assertion = captured[plan.assertion_artifact_id]
    test_input = captured[plan.input_artifact_id]
    output = captured[output_id]
    if (
        hashlib.sha256(assertion).hexdigest() != plan.assertion_sha256
        or hashlib.sha256(test_input).hexdigest() != plan.input_sha256
        or hashlib.sha256(test_input).hexdigest() != observation.input_sha256
    ):
        raise ValidationError("case input bytes differ from the plan")
    _output(output, ObservationLimits(), len(assertion) + len(test_input))
    if (
        hashlib.sha256(output).hexdigest() != observation.observed_sha256
        or hashlib.sha256(output).hexdigest() != plan.prediction_sha256
    ):
        raise ValidationError("case output bytes do not support the prediction")
    return VerifiedSupportedCaseBundle(archive, journal, state, plan.case_id, plan.claim_id, ids)
