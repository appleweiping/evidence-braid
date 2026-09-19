"""A bounded, replayable epistemic-case core, separate from procedural approval.

This module records declarations and checks their internal order, authority and
digest relationships. It neither runs an external test nor establishes that an
observer actually produced the committed bytes. Those are later trust boundaries.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .authority import _description, _identifier, _integer
from .errors import InputFormatError, ValidationError
from .io import _reject_constant, _reject_duplicate_keys, canonical_json
from .ledger import _hash
from .models import _is_xml_character

_DOMAIN = b"evidence-braid:epistemic-case:v1\x00"
_MAX_ACTORS = 64
_MAX_GRANTS = 64
_MAX_RECORDS = 512
_MAX_WIRE_BYTES = 2 * 1024 * 1024
_MAX_RECORD_BYTES = 16 * 1024
_MAX_AUTHORITY_BYTES = 64 * 1024
_MAX_JSON_DEPTH = 16
_MAX_JSON_NODES = 8_192
_MAX_TEXT = 2_048
_MAX_JSON_TEXT = 4_096


def _encoded(value: Any) -> bytes:
    return canonical_json(value, pretty=False).encode("utf-8")


def _fields(value: Any, names: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != names:
        raise ValidationError(f"{label} requires exactly its versioned fields")
    return value


def _profile(value: dict[str, Any], kind: str) -> None:
    if (
        type(value["kind"]) is not str
        or value["kind"] != kind
        or type(value["schema_version"]) is not str
        or value["schema_version"] != "1.0"
    ):
        raise ValidationError("unsupported epistemic case wire profile")


def _enum(value: Any, kind: type[StrEnum], label: str) -> Any:
    if type(value) is not str:
        raise ValidationError(f"{label} must be a known enum string")
    try:
        return kind(value)
    except ValueError as exc:
        raise ValidationError(f"{label} must be a known enum string") from exc


def _tuple(value: Any, maximum: int, label: str) -> tuple[Any, ...]:
    if type(value) is not list or not len(value) <= maximum:
        raise ValidationError(f"{label} must be a bounded array")
    return tuple(value)


def _integer_token(text: str) -> int:
    if len(text) > 10:
        raise ValueError("case integer token is too long")
    return int(text)


def _reject_float(_: str) -> None:
    raise ValueError("case wires do not admit floating-point numbers")


def _document(raw: bytes, maximum: int) -> dict[str, Any]:
    if type(raw) is not bytes or len(raw) > maximum:
        raise InputFormatError("case document is not bounded immutable bytes")
    depth = 0
    quoted = escaped = False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > _MAX_JSON_DEPTH:
                raise InputFormatError("case JSON nesting exceeds the bound")
        elif byte in (93, 125):
            depth -= 1
    try:
        value = json.loads(
            raw.decode("utf-8"),
            parse_int=_integer_token,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (ValueError, UnicodeError, RecursionError):
        raise InputFormatError("invalid epistemic case JSON") from None
    stack = [value]
    nodes = 0
    while stack:
        item = stack.pop()
        nodes += 1
        if nodes > _MAX_JSON_NODES:
            raise InputFormatError("case JSON node count exceeds the bound")
        if type(item) is dict:
            for key in item:
                if len(key) > _MAX_JSON_TEXT or not _is_xml_character(key):
                    raise InputFormatError("case JSON key is outside the text profile")
            stack.extend(item.values())
        elif type(item) is list:
            stack.extend(item)
        elif type(item) is str:
            if len(item) > _MAX_JSON_TEXT or not _is_xml_character(item):
                raise InputFormatError("case JSON text is outside the text profile")
        elif type(item) not in (int, bool, type(None)):
            raise InputFormatError("case JSON scalar is outside the profile")
    if type(value) is not dict or _encoded(value) != raw:
        raise InputFormatError("case JSON must be a canonical object")
    return value


def _bounded(value: Any, maximum: int, label: str) -> bytes:
    try:
        raw = _encoded(value)
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValidationError(f"{label} cannot be encoded") from exc
    if len(raw) > maximum:
        raise ValidationError(f"{label} exceeds its byte bound")
    return raw


class CaseActorKind(StrEnum):
    MODEL = "model"
    TOOL = "tool"
    HUMAN = "human"
    POLICY = "policy"


class CaseRole(StrEnum):
    PROPOSE = "propose"
    OBSERVE = "observe"
    EVALUATE = "evaluate"
    DECIDE = "decide"


@dataclass(frozen=True, slots=True)
class CaseGrant:
    scope: str
    role: CaseRole

    def __post_init__(self) -> None:
        _identifier(self.scope, "case grant scope")
        if type(self.role) is not CaseRole:
            raise ValidationError("case grant needs a typed role")

    def to_dict(self) -> dict[str, str]:
        return {"scope": self.scope, "role": self.role.value}

    @classmethod
    def from_dict(cls, value: Any) -> CaseGrant:
        data = _fields(value, {"scope", "role"}, "case grant")
        return cls(data["scope"], _enum(data["role"], CaseRole, "case grant role"))


@dataclass(frozen=True, slots=True)
class CaseActor:
    actor_id: str
    kind: CaseActorKind
    grants: tuple[CaseGrant, ...]

    def __post_init__(self) -> None:
        _identifier(self.actor_id, "case actor ID")
        if type(self.kind) is not CaseActorKind:
            raise ValidationError("case actor needs a typed kind")
        if (
            type(self.grants) is not tuple
            or not 1 <= len(self.grants) <= _MAX_GRANTS
            or any(type(grant) is not CaseGrant for grant in self.grants)
            or len(set(self.grants)) != len(self.grants)
        ):
            raise ValidationError("case actor needs unique bounded grants")
        allowed = {
            CaseActorKind.MODEL: {CaseRole.PROPOSE},
            CaseActorKind.TOOL: {CaseRole.OBSERVE, CaseRole.EVALUATE},
            CaseActorKind.HUMAN: {CaseRole.PROPOSE, CaseRole.EVALUATE, CaseRole.DECIDE},
            CaseActorKind.POLICY: {CaseRole.EVALUATE, CaseRole.DECIDE},
        }[self.kind]
        if any(grant.role not in allowed for grant in self.grants):
            raise ValidationError("case actor kind cannot hold the requested role")

    def permits(self, scope: str, role: CaseRole) -> bool:
        return CaseGrant(scope, role) in self.grants

    def to_dict(self) -> dict[str, Any]:
        return {
            "actor_id": self.actor_id,
            "kind": self.kind.value,
            "grants": [grant.to_dict() for grant in self.grants],
        }

    @classmethod
    def from_dict(cls, value: Any) -> CaseActor:
        data = _fields(value, {"actor_id", "kind", "grants"}, "case actor")
        return cls(
            data["actor_id"],
            _enum(data["kind"], CaseActorKind, "case actor kind"),
            tuple(
                CaseGrant.from_dict(item) for item in _tuple(data["grants"], _MAX_GRANTS, "grants")
            ),
        )


@dataclass(frozen=True, slots=True)
class CaseAuthority:
    policy_id: str
    actors: tuple[CaseActor, ...]

    def __post_init__(self) -> None:
        _identifier(self.policy_id, "case policy ID")
        if (
            type(self.actors) is not tuple
            or not 1 <= len(self.actors) <= _MAX_ACTORS
            or any(type(actor) is not CaseActor for actor in self.actors)
            or len({actor.actor_id for actor in self.actors}) != len(self.actors)
        ):
            raise ValidationError("case authority needs unique bounded actors")
        _bounded(self.to_dict(), _MAX_AUTHORITY_BYTES, "case authority")

    @property
    def digest(self) -> str:
        return hashlib.sha256(_DOMAIN + b"A" + self.to_bytes()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": "evidence-braid-case-authority",
            "schema_version": "1.0",
            "policy_id": self.policy_id,
            "actors": [actor.to_dict() for actor in self.actors],
        }

    def to_bytes(self) -> bytes:
        return _bounded(self.to_dict(), _MAX_AUTHORITY_BYTES, "case authority")

    @classmethod
    def from_dict(cls, value: Any) -> CaseAuthority:
        data = _fields(value, {"kind", "schema_version", "policy_id", "actors"}, "case authority")
        _profile(data, "evidence-braid-case-authority")
        return cls(
            data["policy_id"],
            tuple(
                CaseActor.from_dict(item) for item in _tuple(data["actors"], _MAX_ACTORS, "actors")
            ),
        )

    @classmethod
    def from_bytes(cls, raw: bytes) -> CaseAuthority:
        return cls.from_dict(_document(raw, _MAX_AUTHORITY_BYTES))


class CaseObservationStatus(StrEnum):
    OBSERVED = "observed"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


class CaseVerdictOutcome(StrEnum):
    SUPPORTED = "supported"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"


class CaseDisposition(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"
    DEFER = "defer"


class CasePhase(StrEnum):
    EMPTY = "empty"
    PLANNED = "planned"
    OBSERVED = "observed"
    VERDICTED = "verdicted"
    DECIDED = "decided"


@dataclass(frozen=True, slots=True)
class CasePlan:
    case_id: str
    workflow_id: str
    claim_id: str
    scope: str
    proposer_id: str
    assertion_artifact_id: str
    assertion_sha256: str
    hypothesis: str
    prediction: str
    expected_observation_text: str
    input_artifact_id: str
    input_sha256: str
    prediction_sha256: str
    test_id: str
    adapter_id: str
    adapter_version: str
    comparator_profile: str
    authority_digest: str

    def __post_init__(self) -> None:
        for name in (
            "case_id",
            "workflow_id",
            "claim_id",
            "scope",
            "proposer_id",
            "assertion_artifact_id",
            "input_artifact_id",
            "test_id",
            "adapter_id",
            "adapter_version",
        ):
            _identifier(getattr(self, name), f"case plan {name}")
        for name in ("assertion_sha256", "input_sha256", "prediction_sha256", "authority_digest"):
            _hash(getattr(self, name), f"case plan {name}")
        _description(self.hypothesis, "case plan hypothesis", maximum=_MAX_TEXT)
        _description(self.prediction, "case plan prediction", maximum=_MAX_TEXT)
        if type(self.expected_observation_text) is not str:
            raise ValidationError("expected observation must be exact UTF-8 text")
        if not _is_xml_character(self.expected_observation_text):
            raise ValidationError("expected observation contains unsupported text")
        expected_bytes = self.expected_observation_text.encode("utf-8")
        if len(expected_bytes) > 4_096:
            raise ValidationError("expected observation exceeds the byte bound")
        if hashlib.sha256(expected_bytes).hexdigest() != self.prediction_sha256:
            raise ValidationError("expected observation text and prediction digest differ")
        if self.assertion_artifact_id == self.input_artifact_id:
            raise ValidationError("case assertion and input artifact IDs must differ")
        if (
            type(self.comparator_profile) is not str
            or self.comparator_profile != "sha256-equality-v1"
        ):
            raise ValidationError("case plan comparator profile is unsupported")
        _bounded(self.to_dict(), _MAX_RECORD_BYTES, "case plan")

    @property
    def digest(self) -> str:
        return hashlib.sha256(_DOMAIN + b"P" + self.to_bytes()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": "evidence-braid-case-plan",
            "schema_version": "1.0",
            **{name: getattr(self, name) for name in self.__dataclass_fields__},
        }

    def to_bytes(self) -> bytes:
        return _bounded(self.to_dict(), _MAX_RECORD_BYTES, "case plan")

    @classmethod
    def from_dict(cls, value: Any) -> CasePlan:
        fields = set(cls.__dataclass_fields__)
        data = _fields(value, fields | {"kind", "schema_version"}, "case plan")
        _profile(data, "evidence-braid-case-plan")
        return cls(**{name: data[name] for name in fields})

    @classmethod
    def from_bytes(cls, raw: bytes) -> CasePlan:
        return cls.from_dict(_document(raw, _MAX_RECORD_BYTES))


@dataclass(frozen=True, slots=True)
class CaseObservation:
    plan_digest: str
    request_id: str
    observer_id: str
    status: CaseObservationStatus
    input_sha256: str
    observed_sha256: str | None
    artifact_id: str | None
    error_code: str | None

    def __post_init__(self) -> None:
        _hash(self.plan_digest, "case observation plan digest")
        _hash(self.input_sha256, "case observation input digest")
        _identifier(self.request_id, "case observation request ID")
        _identifier(self.observer_id, "case observation actor ID")
        if type(self.status) is not CaseObservationStatus:
            raise ValidationError("case observation needs a typed status")
        if self.status is CaseObservationStatus.OBSERVED:
            _hash(self.observed_sha256, "case observation output digest")
            _identifier(self.artifact_id, "case observation artifact ID")
            if self.error_code is not None:
                raise ValidationError("observed case cannot also report an error")
        elif (
            self.observed_sha256 is not None
            or self.artifact_id is not None
            or self.error_code is None
        ):
            raise ValidationError("failed observation needs only a bounded error code")
        else:
            _identifier(self.error_code, "case observation error code")
        _bounded(self.to_dict(), _MAX_RECORD_BYTES, "case observation")

    @property
    def digest(self) -> str:
        return hashlib.sha256(_DOMAIN + b"O" + self.to_bytes()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": "evidence-braid-case-observation",
            "schema_version": "1.0",
            "plan_digest": self.plan_digest,
            "request_id": self.request_id,
            "observer_id": self.observer_id,
            "status": self.status.value,
            "input_sha256": self.input_sha256,
            "observed_sha256": self.observed_sha256,
            "artifact_id": self.artifact_id,
            "error_code": self.error_code,
        }

    def to_bytes(self) -> bytes:
        return _bounded(self.to_dict(), _MAX_RECORD_BYTES, "case observation")

    @classmethod
    def from_dict(cls, value: Any) -> CaseObservation:
        fields = set(cls.__dataclass_fields__)
        data = _fields(value, fields | {"kind", "schema_version"}, "case observation")
        _profile(data, "evidence-braid-case-observation")
        return cls(
            **{
                **{name: data[name] for name in fields},
                "status": _enum(data["status"], CaseObservationStatus, "case observation status"),
            }
        )

    @classmethod
    def from_bytes(cls, raw: bytes) -> CaseObservation:
        return cls.from_dict(_document(raw, _MAX_RECORD_BYTES))


@dataclass(frozen=True, slots=True)
class CaseVerdict:
    plan_digest: str
    observation_digest: str
    evaluator_id: str
    outcome: CaseVerdictOutcome

    def __post_init__(self) -> None:
        _hash(self.plan_digest, "case verdict plan digest")
        _hash(self.observation_digest, "case verdict observation digest")
        _identifier(self.evaluator_id, "case evaluator ID")
        if type(self.outcome) is not CaseVerdictOutcome:
            raise ValidationError("case verdict needs a typed outcome")

    @property
    def digest(self) -> str:
        return hashlib.sha256(_DOMAIN + b"V" + self.to_bytes()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": "evidence-braid-case-verdict",
            "schema_version": "1.0",
            "plan_digest": self.plan_digest,
            "observation_digest": self.observation_digest,
            "evaluator_id": self.evaluator_id,
            "outcome": self.outcome.value,
        }

    def to_bytes(self) -> bytes:
        return _bounded(self.to_dict(), _MAX_RECORD_BYTES, "case verdict")

    @classmethod
    def from_dict(cls, value: Any) -> CaseVerdict:
        data = _fields(
            value, set(cls.__dataclass_fields__) | {"kind", "schema_version"}, "case verdict"
        )
        _profile(data, "evidence-braid-case-verdict")
        return cls(
            data["plan_digest"],
            data["observation_digest"],
            data["evaluator_id"],
            _enum(data["outcome"], CaseVerdictOutcome, "case verdict outcome"),
        )

    @classmethod
    def from_bytes(cls, raw: bytes) -> CaseVerdict:
        return cls.from_dict(_document(raw, _MAX_RECORD_BYTES))


@dataclass(frozen=True, slots=True)
class CaseDecision:
    verdict_digest: str
    decider_id: str
    disposition: CaseDisposition
    reason: str

    def __post_init__(self) -> None:
        _hash(self.verdict_digest, "case decision verdict digest")
        _identifier(self.decider_id, "case decider ID")
        if type(self.disposition) is not CaseDisposition:
            raise ValidationError("case decision needs a typed disposition")
        _description(self.reason, "case decision reason", maximum=512)

    @property
    def digest(self) -> str:
        return hashlib.sha256(_DOMAIN + b"D" + self.to_bytes()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": "evidence-braid-case-decision",
            "schema_version": "1.0",
            "verdict_digest": self.verdict_digest,
            "decider_id": self.decider_id,
            "disposition": self.disposition.value,
            "reason": self.reason,
        }

    def to_bytes(self) -> bytes:
        return _bounded(self.to_dict(), _MAX_RECORD_BYTES, "case decision")

    @classmethod
    def from_dict(cls, value: Any) -> CaseDecision:
        data = _fields(
            value, set(cls.__dataclass_fields__) | {"kind", "schema_version"}, "case decision"
        )
        _profile(data, "evidence-braid-case-decision")
        return cls(
            data["verdict_digest"],
            data["decider_id"],
            _enum(data["disposition"], CaseDisposition, "case decision disposition"),
            data["reason"],
        )

    @classmethod
    def from_bytes(cls, raw: bytes) -> CaseDecision:
        return cls.from_dict(_document(raw, _MAX_RECORD_BYTES))


CaseRecord = CasePlan | CaseObservation | CaseVerdict | CaseDecision
_RECORD_TYPES = (CasePlan, CaseObservation, CaseVerdict, CaseDecision)


def _record(value: Any) -> CaseRecord:
    if type(value) is not dict or type(value.get("kind")) is not str:
        raise ValidationError("case record needs a known kind")
    if value["kind"] == "evidence-braid-case-plan":
        return CasePlan.from_dict(value)
    if value["kind"] == "evidence-braid-case-observation":
        return CaseObservation.from_dict(value)
    if value["kind"] == "evidence-braid-case-verdict":
        return CaseVerdict.from_dict(value)
    if value["kind"] == "evidence-braid-case-decision":
        return CaseDecision.from_dict(value)
    raise ValidationError("case record kind is unsupported")


def _genesis(authority_digest: str) -> str:
    return hashlib.sha256(_DOMAIN + b"G" + bytes.fromhex(authority_digest)).hexdigest()


def _receipt_digest(sequence: int, previous: str, record: CaseRecord) -> str:
    return hashlib.sha256(
        _DOMAIN + b"R" + sequence.to_bytes(4, "big") + bytes.fromhex(previous) + record.to_bytes()
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class CaseReceipt:
    sequence: int
    previous_digest: str
    record: CaseRecord
    digest: str

    def __post_init__(self) -> None:
        _integer(self.sequence, "case receipt sequence", _MAX_RECORDS - 1)
        _hash(self.previous_digest, "case receipt previous digest")
        _hash(self.digest, "case receipt digest")
        if type(self.record) not in _RECORD_TYPES:
            raise ValidationError("case receipt record has an unsupported type")
        if self.digest != _receipt_digest(self.sequence, self.previous_digest, self.record):
            raise ValidationError("case receipt content digest is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "previous_digest": self.previous_digest,
            "record": self.record.to_dict(),
            "digest": self.digest,
        }

    @classmethod
    def from_dict(cls, value: Any) -> CaseReceipt:
        data = _fields(value, {"sequence", "previous_digest", "record", "digest"}, "case receipt")
        return cls(
            data["sequence"], data["previous_digest"], _record(data["record"]), data["digest"]
        )


@dataclass(frozen=True, slots=True)
class CaseCheckpoint:
    record_count: int
    head_digest: str

    def __post_init__(self) -> None:
        _integer(self.record_count, "case checkpoint record count", _MAX_RECORDS)
        _hash(self.head_digest, "case checkpoint head")


@dataclass(frozen=True, slots=True)
class CaseState:
    phase: CasePhase
    case_id: str | None
    outcome: CaseVerdictOutcome | None
    decision: CaseDecision | None
    checkpoint: CaseCheckpoint


@dataclass(frozen=True, slots=True)
class CaseJournal:
    authority_digest: str
    receipts: tuple[CaseReceipt, ...]

    def __post_init__(self) -> None:
        _hash(self.authority_digest, "case journal authority")
        if (
            type(self.receipts) is not tuple
            or len(self.receipts) > _MAX_RECORDS
            or any(type(receipt) is not CaseReceipt for receipt in self.receipts)
        ):
            raise ValidationError("case journal needs bounded immutable receipts")
        previous = _genesis(self.authority_digest)
        for sequence, receipt in enumerate(self.receipts):
            if receipt.sequence != sequence or receipt.previous_digest != previous:
                raise ValidationError("case receipt chain is not contiguous")
            previous = receipt.digest
        _bounded(self.to_dict(), _MAX_WIRE_BYTES, "case journal")

    @classmethod
    def empty(cls, authority: CaseAuthority) -> CaseJournal:
        if type(authority) is not CaseAuthority:
            raise ValidationError("case journal requires a trusted authority")
        return cls(authority.digest, ())

    @property
    def head_digest(self) -> str:
        return self.receipts[-1].digest if self.receipts else _genesis(self.authority_digest)

    @property
    def checkpoint(self) -> CaseCheckpoint:
        return CaseCheckpoint(len(self.receipts), self.head_digest)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": "evidence-braid-case-journal",
            "schema_version": "1.0",
            "authority_digest": self.authority_digest,
            "receipts": [receipt.to_dict() for receipt in self.receipts],
        }

    def to_bytes(self) -> bytes:
        return _bounded(self.to_dict(), _MAX_WIRE_BYTES, "case journal")

    @classmethod
    def from_dict(
        cls,
        value: Any,
        *,
        authority: CaseAuthority,
        expected_head: str | None = None,
    ) -> CaseJournal:
        data = _fields(
            value, {"kind", "schema_version", "authority_digest", "receipts"}, "case journal"
        )
        _profile(data, "evidence-braid-case-journal")
        journal = cls(
            data["authority_digest"],
            tuple(
                CaseReceipt.from_dict(item)
                for item in _tuple(data["receipts"], _MAX_RECORDS, "receipts")
            ),
        )
        replay_case(journal, authority=authority, expected_head=expected_head)
        return journal

    @classmethod
    def from_bytes(
        cls,
        raw: bytes,
        *,
        authority: CaseAuthority,
        expected_head: str | None = None,
    ) -> CaseJournal:
        return cls.from_dict(
            _document(raw, _MAX_WIRE_BYTES), authority=authority, expected_head=expected_head
        )

    def append(
        self,
        records: tuple[CaseRecord, ...],
        *,
        authority: CaseAuthority,
        expected: CaseCheckpoint | None = None,
    ) -> CaseJournal:
        replay_case(self, authority=authority)
        if (
            type(records) is not tuple
            or not records
            or len(self.receipts) + len(records) > _MAX_RECORDS
        ):
            raise ValidationError("case append needs a bounded nonempty immutable record tuple")
        if expected is not None and (
            type(expected) is not CaseCheckpoint or expected != self.checkpoint
        ):
            raise ValidationError("case append checkpoint is stale")
        supplied = list(self.receipts)
        previous = self.head_digest
        for record in records:
            if type(record) not in _RECORD_TYPES:
                raise ValidationError("case append contains an unsupported record")
            sequence = len(supplied)
            receipt = CaseReceipt(
                sequence, previous, record, _receipt_digest(sequence, previous, record)
            )
            supplied.append(receipt)
            previous = receipt.digest
        candidate = CaseJournal(self.authority_digest, tuple(supplied))
        replay_case(candidate, authority=authority)
        return candidate


def replay_case(
    journal: CaseJournal,
    *,
    authority: CaseAuthority,
    expected_head: str | None = None,
) -> CaseState:
    """Verify one full immutable history; return no state on any invalid prefix."""
    if type(journal) is not CaseJournal or type(authority) is not CaseAuthority:
        raise ValidationError("case replay needs a typed journal and authority")
    if journal.authority_digest != authority.digest:
        raise ValidationError("case journal authority differs from the trusted policy")
    if expected_head is not None:
        _hash(expected_head, "expected case head")
        if journal.head_digest != expected_head:
            raise ValidationError("case journal differs from the expected head")
    actors = {actor.actor_id: actor for actor in authority.actors}
    plan: CasePlan | None = None
    observation: CaseObservation | None = None
    verdict: CaseVerdict | None = None
    decision: CaseDecision | None = None
    phase = CasePhase.EMPTY
    for receipt in journal.receipts:
        record = receipt.record
        if isinstance(record, CasePlan):
            if phase is not CasePhase.EMPTY or record.authority_digest != authority.digest:
                raise ValidationError("case plan must be first and use trusted authority")
            actor = actors.get(record.proposer_id)
            if actor is None or not actor.permits(record.scope, CaseRole.PROPOSE):
                raise ValidationError("case proposer lacks exact scoped authority")
            plan = record
            phase = CasePhase.PLANNED
        elif isinstance(record, CaseObservation):
            if phase is not CasePhase.PLANNED or plan is None:
                raise ValidationError("case observation needs one preceding plan")
            actor = actors.get(record.observer_id)
            if (
                record.plan_digest != plan.digest
                or record.input_sha256 != plan.input_sha256
                or record.observer_id == plan.proposer_id
                or record.artifact_id in {plan.assertion_artifact_id, plan.input_artifact_id}
                or actor is None
                or actor.kind is not CaseActorKind.TOOL
                or not actor.permits(plan.scope, CaseRole.OBSERVE)
            ):
                raise ValidationError(
                    "case observation lacks plan binding or independent authority"
                )
            observation = record
            phase = CasePhase.OBSERVED
        elif isinstance(record, CaseVerdict):
            if phase is not CasePhase.OBSERVED or plan is None or observation is None:
                raise ValidationError("case verdict needs one preceding observation")
            actor = actors.get(record.evaluator_id)
            if (
                record.plan_digest != plan.digest
                or record.observation_digest != observation.digest
                or record.evaluator_id in {plan.proposer_id, observation.observer_id}
                or actor is None
                or actor.kind is CaseActorKind.MODEL
                or not actor.permits(plan.scope, CaseRole.EVALUATE)
            ):
                raise ValidationError("case verdict lacks bindings or independent authority")
            expected = (
                CaseVerdictOutcome.INCONCLUSIVE
                if observation.status is not CaseObservationStatus.OBSERVED
                else CaseVerdictOutcome.SUPPORTED
                if observation.observed_sha256 == plan.prediction_sha256
                else CaseVerdictOutcome.REFUTED
            )
            if record.outcome is not expected:
                raise ValidationError("case verdict conflicts with the committed observation")
            verdict = record
            phase = CasePhase.VERDICTED
        elif isinstance(record, CaseDecision):
            if phase is not CasePhase.VERDICTED or plan is None or verdict is None:
                raise ValidationError("case decision needs one preceding verdict")
            actor = actors.get(record.decider_id)
            if (
                record.verdict_digest != verdict.digest
                or record.decider_id
                in {
                    plan.proposer_id,
                    observation.observer_id if observation else "",
                    verdict.evaluator_id,
                }
                or actor is None
                or actor.kind not in (CaseActorKind.HUMAN, CaseActorKind.POLICY)
                or not actor.permits(plan.scope, CaseRole.DECIDE)
            ):
                raise ValidationError(
                    "case decision lacks verdict binding or independent authority"
                )
            if (
                record.disposition is CaseDisposition.APPROVE
                and verdict.outcome is not CaseVerdictOutcome.SUPPORTED
            ):
                raise ValidationError("unsupported case cannot be approved")
            decision = record
            phase = CasePhase.DECIDED
        else:
            raise ValidationError("case journal contains an unsupported record")
    return CaseState(
        phase,
        plan.case_id if plan is not None else None,
        verdict.outcome if verdict is not None else None,
        decision,
        journal.checkpoint,
    )
