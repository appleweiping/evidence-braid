"""Deterministic authority-checked workflow replay and portable receipt envelopes.

Existing evidence receipts remain unchanged. A separate workflow context binds
their head, an authority-policy digest, and a manifest of artifact commitments.
Approval is a procedural state, never a computed assurance of real-world truth.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .authority import (
    MAX_WORKFLOW_ARTIFACTS,
    MAX_WORKFLOW_RECORDS,
    ActorKind,
    ArtifactReference,
    AuthorityPolicy,
    AuthorityRole,
    ClaimStatus,
    WorkflowAction,
    WorkflowTransition,
    _array,
    _description,
    _identifier,
    _integer,
)
from .errors import InputFormatError, ValidationError
from .io import _decode, _loads, _read_bounded, canonical_json
from .ledger import EvidenceLedger, _fields, _hash

MAX_WORKFLOW_BYTES = 64 * 1024 * 1024


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value, pretty=False).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class WorkflowReceipt:
    sequence: int
    context_digest: str
    previous_digest: str
    transition: WorkflowTransition
    digest: str

    def __post_init__(self) -> None:
        _integer(self.sequence, "receipt.sequence", MAX_WORKFLOW_RECORDS - 1)
        for name in ("context_digest", "previous_digest", "digest"):
            _hash(getattr(self, name), f"receipt.{name}")
        if type(self.transition) is not WorkflowTransition:
            raise ValidationError("receipt.transition must be a WorkflowTransition")

    def content(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "sequence": self.sequence,
            "context_digest": self.context_digest,
            "previous_digest": self.previous_digest,
            "transition": self.transition.to_dict(),
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.content(), "digest": self.digest}

    @classmethod
    def from_dict(cls, value: Any) -> WorkflowReceipt:
        data = _fields(
            value,
            {
                "schema_version",
                "sequence",
                "context_digest",
                "previous_digest",
                "transition",
                "digest",
            },
            "receipt",
        )
        if data["schema_version"] != "1.0":
            raise ValidationError("unsupported workflow receipt version")
        return cls(
            data["sequence"],
            data["context_digest"],
            data["previous_digest"],
            WorkflowTransition.from_dict(data["transition"]),
            data["digest"],
        )


@dataclass(frozen=True, slots=True)
class WorkflowBundle:
    """An immutable materialized bundle. Replay requires a separate trusted policy.

    Constructing this object verifies receipt integrity, not actor authority.
    Use ``replay_workflow`` to authorize it, or ``from_dict(..., authority=...)``
    when accepting a serialized bundle. Retain its head separately for anchoring.
    """

    workflow_id: str
    authority_digest: str
    evidence: EvidenceLedger
    artifacts: tuple[ArtifactReference, ...]
    records: tuple[WorkflowReceipt, ...]

    def __post_init__(self) -> None:
        _identifier(self.workflow_id, "workflow.workflow_id")
        _hash(self.authority_digest, "workflow.authority_digest")
        if type(self.evidence) is not EvidenceLedger or not self.evidence.verify():
            raise ValidationError("workflow requires a verified evidence ledger")
        if (
            type(self.artifacts) is not tuple
            or len(self.artifacts) > MAX_WORKFLOW_ARTIFACTS
            or any(type(item) is not ArtifactReference for item in self.artifacts)
        ):
            raise ValidationError("workflow artifacts must be a bounded ArtifactReference tuple")
        if len({item.artifact_id for item in self.artifacts}) != len(self.artifacts):
            raise ValidationError("workflow artifact IDs must be unique")
        object.__setattr__(
            self, "artifacts", tuple(sorted(self.artifacts, key=lambda a: a.artifact_id))
        )
        if (
            type(self.records) is not tuple
            or len(self.records) > MAX_WORKFLOW_RECORDS
            or any(type(record) is not WorkflowReceipt for record in self.records)
        ):
            raise ValidationError("workflow records must be a bounded WorkflowReceipt tuple")
        context = self.context_digest
        previous = context
        identifiers: set[str] = set()
        for sequence, record in enumerate(self.records):
            if (
                record.sequence != sequence
                or record.context_digest != context
                or record.previous_digest != previous
                or record.digest != _digest(record.content())
                or record.transition.transition_id in identifiers
            ):
                raise ValidationError("workflow receipt integrity/order verification failed")
            identifiers.add(record.transition.transition_id)
            previous = record.digest
        if len(canonical_json(self.to_dict(), pretty=False).encode("utf-8")) > MAX_WORKFLOW_BYTES:
            raise ValidationError("workflow bundle exceeds the 64 MiB limit")

    @property
    def context_digest(self) -> str:
        return _digest(
            {
                "kind": "evidence-braid-workflow-context",
                "schema_version": "1.0",
                "workflow_id": self.workflow_id,
                "authority_digest": self.authority_digest,
                "evidence_head": self.evidence.head_digest,
                "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            }
        )

    @property
    def head_digest(self) -> str:
        return self.records[-1].digest if self.records else self.context_digest

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": "evidence-braid-workflow-bundle",
            "schema_version": "1.0",
            "workflow_id": self.workflow_id,
            "authority_digest": self.authority_digest,
            "evidence": self.evidence.to_dict(),
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "context_digest": self.context_digest,
            "head_digest": self.head_digest,
            "record_count": len(self.records),
            "records": [record.to_dict() for record in self.records],
        }

    @classmethod
    def from_dict(
        cls,
        value: Any,
        *,
        authority: AuthorityPolicy,
        expected_head: str | None = None,
        expected_evidence_head: str | None = None,
    ) -> WorkflowBundle:
        data = _fields(
            value,
            {
                "kind",
                "schema_version",
                "workflow_id",
                "authority_digest",
                "evidence",
                "artifacts",
                "context_digest",
                "head_digest",
                "record_count",
                "records",
            },
            "workflow",
        )
        if data["kind"] != "evidence-braid-workflow-bundle" or data["schema_version"] != "1.0":
            raise ValidationError("unsupported workflow bundle format")
        records = _array(data["records"], "workflow.records", MAX_WORKFLOW_RECORDS)
        if type(data["record_count"]) is not int or data["record_count"] != len(records):
            raise ValidationError("workflow record_count does not match records")
        result = cls(
            data["workflow_id"],
            data["authority_digest"],
            EvidenceLedger.from_dict(data["evidence"], expected_head=expected_evidence_head),
            tuple(
                ArtifactReference.from_dict(item)
                for item in _array(data["artifacts"], "artifacts", MAX_WORKFLOW_ARTIFACTS)
            ),
            tuple(WorkflowReceipt.from_dict(record) for record in records),
        )
        if canonical_json(data, pretty=False) != canonical_json(result.to_dict(), pretty=False):
            raise ValidationError("workflow bundle must use its exact canonical representation")
        replay_workflow(result, authority=authority, expected_head=expected_head)
        return result

    def append(
        self, transitions: Iterable[WorkflowTransition], *, authority: AuthorityPolicy
    ) -> WorkflowBundle:
        """Return a new authorized bundle or raise; the original is never changed."""
        replay_workflow(self, authority=authority)
        records = list(self.records)
        previous = self.head_digest
        context = self.context_digest
        for transition in transitions:
            if type(transition) is not WorkflowTransition or len(records) >= MAX_WORKFLOW_RECORDS:
                raise ValidationError("append requires bounded WorkflowTransition instances")
            pending = WorkflowReceipt(len(records), context, previous, transition, "0" * 64)
            receipt = replace(pending, digest=_digest(pending.content()))
            records.append(receipt)
            previous = receipt.digest
        result = replace(self, records=tuple(records))
        replay_workflow(result, authority=authority)
        return result

    def verify_artifacts(self, contents: Mapping[str, bytes]) -> bool:
        """Check an exact supplied content inventory, separately from workflow replay."""
        return (
            isinstance(contents, Mapping)
            and set(contents) == {item.artifact_id for item in self.artifacts}
            and all(item.matches(contents[item.artifact_id]) for item in self.artifacts)
        )


@dataclass(frozen=True, slots=True)
class ClaimWorkflow:
    claim_id: str
    scope: str
    statement: str
    status: ClaimStatus
    revision: int
    authors: tuple[str, ...]
    evidence_ids: tuple[str, ...] = ()
    artifact_ids: tuple[str, ...] = ()
    approvals: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _identifier(self.claim_id, "claim.claim_id")
        _identifier(self.scope, "claim.scope")
        _description(self.statement, "claim.statement")
        _integer(self.revision, "claim.revision", MAX_WORKFLOW_RECORDS, 1)
        if type(self.status) is not ClaimStatus:
            raise ValidationError("claim.status must be a ClaimStatus")
        for name, maximum, minimum in (
            ("authors", 256, 1),
            ("evidence_ids", MAX_WORKFLOW_RECORDS, 0),
            ("artifact_ids", MAX_WORKFLOW_ARTIFACTS, 0),
            ("approvals", 16, 0),
        ):
            values = getattr(self, name)
            if type(values) is not tuple or not minimum <= len(values) <= maximum:
                raise ValidationError(f"claim.{name} must be a bounded immutable tuple")
            for item in values:
                _identifier(item, f"claim.{name}")
            if len(set(values)) != len(values):
                raise ValidationError(f"claim.{name} must contain unique identities")
        if set(self.authors) & set(self.approvals):
            raise ValidationError("claim authors and approvers must be independent")

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "scope": self.scope,
            "statement": self.statement,
            "status": self.status.value,
            "revision": self.revision,
            "authors": list(self.authors),
            "evidence_ids": list(self.evidence_ids),
            "artifact_ids": list(self.artifact_ids),
            "approvals": list(self.approvals),
        }


@dataclass(frozen=True, slots=True)
class WorkflowState:
    workflow_id: str
    head_digest: str
    record_count: int
    claims: Mapping[str, ClaimWorkflow]

    def __post_init__(self) -> None:
        _identifier(self.workflow_id, "state.workflow_id")
        _hash(self.head_digest, "state.head_digest")
        _integer(self.record_count, "state.record_count", MAX_WORKFLOW_RECORDS)
        if (
            not isinstance(self.claims, Mapping)
            or len(self.claims) > MAX_WORKFLOW_RECORDS
            or any(
                type(claim) is not ClaimWorkflow or key != claim.claim_id
                for key, claim in self.claims.items()
            )
        ):
            raise ValidationError("state.claims must map matching IDs to ClaimWorkflow instances")
        if sum(claim.revision for claim in self.claims.values()) != self.record_count:
            raise ValidationError("state claim revisions must account for every workflow record")
        object.__setattr__(self, "claims", MappingProxyType(dict(self.claims)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "workflow_id": self.workflow_id,
            "head_digest": self.head_digest,
            "record_count": self.record_count,
            "claims": {key: value.to_dict() for key, value in sorted(self.claims.items())},
        }


def replay_workflow(
    bundle: WorkflowBundle,
    *,
    authority: AuthorityPolicy,
    expected_head: str | None = None,
) -> WorkflowState:
    """Verify integrity and every transition against an independently supplied policy.

    Failure raises without returning a partially authorized state. This is an
    offline permission check of declarations, not proof that an actor acted.
    """
    if type(bundle) is not WorkflowBundle or type(authority) is not AuthorityPolicy:
        raise ValidationError("replay requires a WorkflowBundle and trusted AuthorityPolicy")
    if authority.digest != bundle.authority_digest:
        raise ValidationError("workflow authority does not match the trusted policy")
    if expected_head is not None:
        _hash(expected_head, "expected_head")
        if bundle.head_digest != expected_head:
            raise ValidationError("workflow does not match the expected head")
    actors = {actor.actor_id: actor for actor in authority.actors}
    evidence = {entry.event_id: entry for entry in bundle.evidence.entries}
    artifacts = {item.artifact_id: item for item in bundle.artifacts}
    claims: dict[str, ClaimWorkflow] = {}
    for receipt in bundle.records:
        command = receipt.transition
        role = (
            AuthorityRole.REVIEWER
            if command.action in (WorkflowAction.APPROVE, WorkflowAction.REJECT)
            else AuthorityRole.REVOKER
            if command.action is WorkflowAction.REVOKE
            else AuthorityRole.AUTHOR
        )
        actor = actors.get(command.actor_id)
        if actor is None or not actor.permits(command.scope, role):
            raise ValidationError("transition actor lacks the exact scoped role")
        if role is not AuthorityRole.AUTHOR and actor.kind is not ActorKind.HUMAN:
            raise ValidationError("review and revocation require a declared human actor")
        claim = claims.get(command.claim_id)
        if command.action is WorkflowAction.CREATE:
            if claim is not None or command.expected_revision != 0:
                raise ValidationError("create requires a new claim and revision zero")
            # The transition constructor guarantees a create statement is present.
            claims[command.claim_id] = ClaimWorkflow(
                command.claim_id,
                command.scope,
                str(command.statement),
                ClaimStatus.DRAFT,
                1,
                (command.actor_id,),
            )
            continue
        if claim is None or claim.scope != command.scope:
            raise ValidationError("transition claim is missing or belongs to another scope")
        if command.expected_revision != claim.revision:
            raise ValidationError("transition expected_revision is stale or out of order")
        if role is AuthorityRole.AUTHOR:
            if claim.status is not ClaimStatus.DRAFT:
                raise ValidationError("only draft claims can be authored or submitted")
            authors = tuple(sorted(set(claim.authors) | {command.actor_id}))
            if command.action is WorkflowAction.BIND_EVIDENCE:
                entry = evidence.get(str(command.reference_id))
                if (
                    entry is None
                    or entry.digest != command.reference_digest
                    or entry.event["claim"] != claim.claim_id
                    or entry.event.get("attributes", {}).get("workflow_scope") != claim.scope
                    or entry.event_id in claim.evidence_ids
                ):
                    raise ValidationError(
                        "evidence reference is missing, mismatched, or duplicated"
                    )
                claim = replace(claim, evidence_ids=(*claim.evidence_ids, entry.event_id))
            elif command.action is WorkflowAction.BIND_ARTIFACT:
                artifact = artifacts.get(str(command.reference_id))
                if (
                    artifact is None
                    or artifact.sha256 != command.reference_digest
                    or artifact.claim_id != claim.claim_id
                    or artifact.scope != claim.scope
                    or artifact.artifact_id in claim.artifact_ids
                ):
                    raise ValidationError(
                        "artifact reference is missing, mismatched, or duplicated"
                    )
                claim = replace(claim, artifact_ids=(*claim.artifact_ids, artifact.artifact_id))
            else:
                if not claim.evidence_ids or not claim.artifact_ids:
                    raise ValidationError("submit requires bound evidence and an artifact")
                claim = replace(claim, status=ClaimStatus.SUBMITTED)
            claim = replace(claim, authors=authors)
        elif role is AuthorityRole.REVIEWER:
            if claim.status is not ClaimStatus.SUBMITTED:
                raise ValidationError("only submitted claims can be reviewed")
            if command.actor_id in claim.authors or command.actor_id in claim.approvals:
                raise ValidationError("reviewer must be independent and may vote only once")
            if command.action is WorkflowAction.REJECT:
                claim = replace(claim, status=ClaimStatus.REJECTED)
            else:
                approvals = (*claim.approvals, command.actor_id)
                status = (
                    ClaimStatus.APPROVED
                    if len(approvals) >= authority.approval_quorum
                    else ClaimStatus.SUBMITTED
                )
                claim = replace(claim, approvals=approvals, status=status)
        else:
            if claim.status is not ClaimStatus.APPROVED:
                raise ValidationError("only approved claims can be revoked")
            if command.actor_id in claim.authors or command.actor_id in claim.approvals:
                raise ValidationError("revoker must be independent of authors and approvers")
            claim = replace(claim, status=ClaimStatus.REVOKED)
        claims[claim.claim_id] = replace(claim, revision=claim.revision + 1)
    return WorkflowState(bundle.workflow_id, bundle.head_digest, len(bundle.records), claims)


def build_workflow(
    workflow_id: str,
    *,
    authority: AuthorityPolicy,
    evidence: EvidenceLedger,
    artifacts: tuple[ArtifactReference, ...] = (),
    transitions: Iterable[WorkflowTransition] = (),
) -> WorkflowBundle:
    if type(authority) is not AuthorityPolicy:
        raise ValidationError("build requires a trusted AuthorityPolicy")
    return WorkflowBundle(workflow_id, authority.digest, evidence, artifacts, ()).append(
        transitions, authority=authority
    )


def load_workflow_bundle(
    path: str | Path,
    *,
    authority: AuthorityPolicy,
    expected_head: str | None = None,
    expected_evidence_head: str | None = None,
) -> WorkflowBundle:
    """Read bounded strict JSON and authorize the complete workflow before return."""
    source = Path(path)
    raw = _read_bounded(source, MAX_WORKFLOW_BYTES, "workflow")
    try:
        document = _loads(_decode(raw, source))
    except (ValueError, RecursionError) as exc:
        raise InputFormatError("invalid workflow JSON") from exc
    return WorkflowBundle.from_dict(
        document,
        authority=authority,
        expected_head=expected_head,
        expected_evidence_head=expected_evidence_head,
    )


def write_workflow_bundle(
    path: str | Path, bundle: WorkflowBundle, *, authority: AuthorityPolicy
) -> None:
    """Authorize then atomically replace a file; no partial JSON is published.

    This flushes file contents before replacement but does not claim directory
    metadata durability across power loss on every platform. It is not CAS.
    """
    replay_workflow(bundle, authority=authority)
    content = canonical_json(bundle.to_dict(), pretty=False).encode("utf-8")
    destination = Path(path)
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as handle:
            temporary = handle.name
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    except OSError as exc:
        raise InputFormatError("cannot publish workflow bundle") from exc
    finally:
        if temporary is not None and os.path.exists(temporary):
            os.unlink(temporary)
