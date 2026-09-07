"""Immutable authority declarations and commands, not actor authentication.

Actor names and kind declarations come from a caller-trusted policy. There is
no identity provider, signature, role discovery, or implicit scope inheritance.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .errors import ValidationError
from .io import canonical_json
from .ledger import _fields, _hash
from .models import _text

MAX_WORKFLOW_RECORDS = 10_000
MAX_WORKFLOW_ARTIFACTS = 1_024


def _identifier(value: Any, path: str) -> str:
    if type(value) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", value) is None:
        raise ValidationError(f"{path} must be a 1..128 character ASCII identifier")
    return value


def _description(value: Any, path: str, maximum: int = 8_192) -> str:
    text = _text(value, path, trim=False)
    if text != text.strip() or len(text) > maximum:
        raise ValidationError(f"{path} must be canonical text of at most {maximum} characters")
    return text


def _integer(value: Any, path: str, maximum: int, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValidationError(f"{path} must be an integer between {minimum} and {maximum}")
    return value


def _array(value: Any, path: str, maximum: int) -> list[Any]:
    if type(value) is not list or len(value) > maximum:
        raise ValidationError(f"{path} must be an array of at most {maximum} items")
    return value


def _enum(value: Any, kind: type[StrEnum], path: str) -> Any:
    if type(value) is not str:
        raise ValidationError(f"{path} must be a known enum string")
    try:
        return kind(value)
    except ValueError as exc:
        raise ValidationError(f"{path} must be a known enum string") from exc


class ActorKind(StrEnum):
    HUMAN = "human"
    AUTOMATION = "automation"


class AuthorityRole(StrEnum):
    AUTHOR = "author"
    REVIEWER = "reviewer"
    REVOKER = "revoker"


class WorkflowAction(StrEnum):
    CREATE = "create"
    BIND_EVIDENCE = "bind_evidence"
    BIND_ARTIFACT = "bind_artifact"
    SUBMIT = "submit"
    APPROVE = "approve"
    REJECT = "reject"
    REVOKE = "revoke"


class ClaimStatus(StrEnum):
    DRAFT = "draft"
    SUBMITTED = "submitted"
    APPROVED = "approved"
    REJECTED = "rejected"
    REVOKED = "revoked"


@dataclass(frozen=True, slots=True)
class ScopeGrant:
    scope: str
    role: AuthorityRole

    def __post_init__(self) -> None:
        _identifier(self.scope, "grant.scope")
        if type(self.role) is not AuthorityRole:
            raise ValidationError("grant.role must be an AuthorityRole")

    def to_dict(self) -> dict[str, str]:
        return {"scope": self.scope, "role": self.role.value}

    @classmethod
    def from_dict(cls, value: Any) -> ScopeGrant:
        data = _fields(value, {"scope", "role"}, "grant")
        return cls(data["scope"], _enum(data["role"], AuthorityRole, "grant.role"))


@dataclass(frozen=True, slots=True)
class WorkflowActor:
    actor_id: str
    kind: ActorKind
    grants: tuple[ScopeGrant, ...]

    def __post_init__(self) -> None:
        _identifier(self.actor_id, "actor.actor_id")
        if type(self.kind) is not ActorKind:
            raise ValidationError("actor.kind must be an ActorKind")
        if (
            type(self.grants) is not tuple
            or not 1 <= len(self.grants) <= 128
            or any(type(grant) is not ScopeGrant for grant in self.grants)
        ):
            raise ValidationError("actor.grants must contain 1..128 ScopeGrant instances")
        if len(set(self.grants)) != len(self.grants):
            raise ValidationError("actor grants must be unique")
        object.__setattr__(
            self, "grants", tuple(sorted(self.grants, key=lambda g: (g.scope, g.role)))
        )

    def permits(self, scope: str, role: AuthorityRole) -> bool:
        return ScopeGrant(scope, role) in self.grants

    def to_dict(self) -> dict[str, Any]:
        return {
            "actor_id": self.actor_id,
            "kind": self.kind.value,
            "grants": [grant.to_dict() for grant in self.grants],
        }

    @classmethod
    def from_dict(cls, value: Any) -> WorkflowActor:
        data = _fields(value, {"actor_id", "kind", "grants"}, "actor")
        return cls(
            data["actor_id"],
            _enum(data["kind"], ActorKind, "actor.kind"),
            tuple(ScopeGrant.from_dict(item) for item in _array(data["grants"], "grants", 128)),
        )


@dataclass(frozen=True, slots=True)
class AuthorityPolicy:
    """A fixed, externally trusted actor registry for one workflow context.

    Policy evolution requires a new context, not retroactive permission changes.
    Approval counts do not measure evidence strength or establish claim truth.
    """

    policy_id: str
    actors: tuple[WorkflowActor, ...]
    approval_quorum: int = 1

    def __post_init__(self) -> None:
        _identifier(self.policy_id, "authority.policy_id")
        _integer(self.approval_quorum, "authority.approval_quorum", 16, 1)
        if (
            type(self.actors) is not tuple
            or not 1 <= len(self.actors) <= 256
            or any(type(actor) is not WorkflowActor for actor in self.actors)
        ):
            raise ValidationError("authority.actors must contain 1..256 WorkflowActor instances")
        if len({actor.actor_id for actor in self.actors}) != len(self.actors):
            raise ValidationError("authority actor IDs must be unique")
        object.__setattr__(
            self, "actors", tuple(sorted(self.actors, key=lambda actor: actor.actor_id))
        )

    @property
    def digest(self) -> str:
        return hashlib.sha256(
            canonical_json(self.to_dict(), pretty=False).encode("utf-8")
        ).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "kind": "evidence-braid-authority",
            "policy_id": self.policy_id,
            "approval_quorum": self.approval_quorum,
            "actors": [actor.to_dict() for actor in self.actors],
        }

    @classmethod
    def from_dict(cls, value: Any) -> AuthorityPolicy:
        data = _fields(
            value, {"schema_version", "kind", "policy_id", "approval_quorum", "actors"}, "authority"
        )
        if data["schema_version"] != "1.0" or data["kind"] != "evidence-braid-authority":
            raise ValidationError("unsupported authority format")
        return cls(
            data["policy_id"],
            tuple(
                WorkflowActor.from_dict(actor) for actor in _array(data["actors"], "actors", 256)
            ),
            data["approval_quorum"],
        )


@dataclass(frozen=True, slots=True)
class ArtifactReference:
    """A scoped content commitment, not proof of content availability or truth."""

    artifact_id: str
    scope: str
    claim_id: str
    sha256: str
    size_bytes: int
    media_type: str

    def __post_init__(self) -> None:
        for name in ("artifact_id", "scope", "claim_id"):
            _identifier(getattr(self, name), f"artifact.{name}")
        _hash(self.sha256, "artifact.sha256")
        _integer(self.size_bytes, "artifact.size_bytes", 64 * 1024 * 1024)
        _description(self.media_type, "artifact.media_type", 128)

    def matches(self, content: bytes) -> bool:
        """Check caller-supplied bytes; no file paths or network requests are opened."""
        return (
            type(content) is bytes
            and len(content) == self.size_bytes
            and hashlib.sha256(content).hexdigest() == self.sha256
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "scope": self.scope,
            "claim_id": self.claim_id,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "media_type": self.media_type,
        }

    @classmethod
    def from_dict(cls, value: Any) -> ArtifactReference:
        data = _fields(
            value,
            {"artifact_id", "scope", "claim_id", "sha256", "size_bytes", "media_type"},
            "artifact",
        )
        return cls(**data)


@dataclass(frozen=True, slots=True)
class WorkflowTransition:
    """One immutable intent with exact revision and content-reference preconditions."""

    transition_id: str
    action: WorkflowAction
    actor_id: str
    scope: str
    claim_id: str
    expected_revision: int
    statement: str | None = None
    reference_id: str | None = None
    reference_digest: str | None = None
    reason: str | None = None

    def __post_init__(self) -> None:
        for name in ("transition_id", "actor_id", "scope", "claim_id"):
            _identifier(getattr(self, name), f"transition.{name}")
        if type(self.action) is not WorkflowAction:
            raise ValidationError("transition.action must be a WorkflowAction")
        _integer(self.expected_revision, "transition.expected_revision", MAX_WORKFLOW_RECORDS)
        if self.action is WorkflowAction.CREATE:
            _description(self.statement, "transition.statement")
        elif self.statement is not None:
            raise ValidationError("only create accepts a statement")
        if self.action in (WorkflowAction.BIND_EVIDENCE, WorkflowAction.BIND_ARTIFACT):
            _identifier(self.reference_id, "transition.reference_id")
            _hash(self.reference_digest, "transition.reference_digest")
        elif self.reference_id is not None or self.reference_digest is not None:
            raise ValidationError("only bind actions accept a reference")
        if self.action in (WorkflowAction.REJECT, WorkflowAction.REVOKE):
            _description(self.reason, "transition.reason")
        elif self.reason is not None:
            raise ValidationError("only reject/revoke accept a reason")

    def to_dict(self) -> dict[str, Any]:
        return {
            "transition_id": self.transition_id,
            "action": self.action.value,
            "actor_id": self.actor_id,
            "scope": self.scope,
            "claim_id": self.claim_id,
            "expected_revision": self.expected_revision,
            "statement": self.statement,
            "reference_id": self.reference_id,
            "reference_digest": self.reference_digest,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, value: Any) -> WorkflowTransition:
        data = dict(_fields(value, set(cls.__dataclass_fields__), "transition"))
        data["action"] = _enum(data["action"], WorkflowAction, "transition.action")
        return cls(**data)
