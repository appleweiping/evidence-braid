"""Typed immutable models and strict schema parsing.

The parser deliberately rejects unknown fields. A decision system should fail
closed when a policy contains a typo instead of silently ignoring it.
"""

from __future__ import annotations

import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from math import isfinite
from types import MappingProxyType
from typing import Any, TypeVar

from .errors import ValidationError

_EnumT = TypeVar("_EnumT", bound=StrEnum)

MAX_ATTRIBUTE_DEPTH = 64
STABLE_FLOAT_DIGITS = 12
_FALLBACK_INTEGER_DIGIT_THRESHOLD = 640
MAX_ATTRIBUTE_INTEGER_DIGITS = getattr(
    sys.int_info,
    "str_digits_check_threshold",
    _FALLBACK_INTEGER_DIGIT_THRESHOLD,
)
_MAX_ATTRIBUTE_INTEGER = 10**MAX_ATTRIBUTE_INTEGER_DIGITS - 1


class Modality(StrEnum):
    VISION = "vision"
    AUDIO = "audio"
    TEXT = "text"
    SENSOR = "sensor"


class Signal(StrEnum):
    SUPPORT = "support"
    CONTRADICT = "contradict"


class Outcome(StrEnum):
    ESCALATE = "escalate"
    REJECT = "reject"
    REVIEW = "review"


class Verdict(StrEnum):
    """Ground truth about one observation, decided outside this library."""

    CORRECT = "correct"
    INCORRECT = "incorrect"


def _is_xml_character(value: str) -> bool:
    """Return whether every code point is permitted by XML 1.0."""
    return all(
        character in "\t\n\r"
        or "\u0020" <= character <= "\ud7ff"
        or "\ue000" <= character <= "\ufffd"
        or "\U00010000" <= character <= "\U0010ffff"
        for character in value
    )


def _text(value: Any, path: str, *, trim: bool = True) -> str:
    """Validate user-controlled text before it reaches JSON or reports."""
    if type(value) is not str:
        raise ValidationError(f"{path} must be a non-empty string")
    if not _is_xml_character(value):
        raise ValidationError(f"{path} contains a character not allowed by XML 1.0")
    result = value.strip() if trim else value
    if not result:
        raise ValidationError(f"{path} must be a non-empty string")
    return result


def normalize_datetime(value: Any, path: str) -> datetime:
    """Validate a timezone-aware datetime and normalize it to UTC."""
    # A datetime subclass can override ``astimezone`` or retain mutable
    # instance state.  Reject subclasses so every accepted public model owns a
    # real, immutable built-in datetime after normalization.
    if type(value) is not datetime:
        raise ValidationError(f"{path} must be a timezone-aware datetime")
    try:
        offset = value.utcoffset()
    except (OverflowError, TypeError, ValueError) as exc:
        raise ValidationError(f"{path} must be a valid timezone-aware datetime") from exc
    if value.tzinfo is None or offset is None:
        raise ValidationError(f"{path} must include a UTC offset")
    try:
        normalized = value.astimezone(UTC)
    except (OverflowError, TypeError, ValueError) as exc:
        raise ValidationError(f"{path} must be a valid timezone-aware datetime") from exc
    if type(normalized) is not datetime:  # Defensive guard around runtime behavior.
        raise ValidationError(f"{path} must be a valid timezone-aware datetime")
    return normalized


def parse_timestamp(value: Any, path: str) -> datetime:
    """Parse a timezone-aware ISO-8601 timestamp and normalize it to UTC."""
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{path} must be a non-empty ISO-8601 string")
    normalized = _text(value, path)
    if normalized.endswith("Z"):
        normalized = f"{normalized[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValidationError(f"{path} is not a valid ISO-8601 timestamp") from exc
    return normalize_datetime(parsed, path)


def format_timestamp(value: datetime) -> str:
    """Return the canonical UTC representation."""
    return normalize_datetime(value, "timestamp").isoformat().replace("+00:00", "Z")


def _mapping(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValidationError(f"{path} must be an object")
    if not all(type(key) is str for key in value):
        raise ValidationError(f"{path} keys must be strings")
    return value


def _only(data: Mapping[str, Any], allowed: set[str], path: str) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        names = ", ".join(ascii(name) for name in unknown)
        raise ValidationError(f"{path} contains unknown field(s): {names}")


def _required_string(data: Mapping[str, Any], key: str, path: str) -> str:
    return _text(data.get(key), f"{path}.{key}")


def _number(value: Any, path: str, minimum: float, maximum: float | None = None) -> float:
    if type(value) not in (int, float):
        raise ValidationError(f"{path} must be a number")
    try:
        result = float(value)
    except (OverflowError, ValueError) as exc:
        raise ValidationError(f"{path} must be a finite number") from exc
    if not isfinite(result) or result < minimum or (maximum is not None and result > maximum):
        interval = f"[{minimum}, {maximum}]" if maximum is not None else f">= {minimum}"
        raise ValidationError(f"{path} must be finite and in {interval}")
    # JSON distinguishes -0.0 lexically even though Python and the decision
    # domain treat both zero encodings as the same value.  Canonicalize here so
    # typed inputs, direct output models, and digests cannot retain negative
    # zero.
    return 0.0 if result == 0.0 else result


def _stable_float(value: float) -> float:
    """Return the shared precision used by comparisons and public output."""
    result = round(value, STABLE_FLOAT_DIGITS)
    return 0.0 if result == 0.0 else result


def _positive_int(value: Any, path: str) -> int:
    if type(value) is not int or value < 1:
        raise ValidationError(f"{path} must be an integer >= 1")
    if value > _MAX_ATTRIBUTE_INTEGER:
        raise ValidationError(
            f"{path} integer must contain at most {MAX_ATTRIBUTE_INTEGER_DIGITS} digits"
        )
    return value


def _nonnegative_int(value: Any, path: str) -> int:
    if type(value) is not int or value < 0:
        raise ValidationError(f"{path} must be an integer >= 0")
    if value > _MAX_ATTRIBUTE_INTEGER:
        raise ValidationError(
            f"{path} integer must contain at most {MAX_ATTRIBUTE_INTEGER_DIGITS} digits"
        )
    return value


def _enum(value: Any, enum_type: type[_EnumT], path: str) -> _EnumT:
    """Validate that a value already is a member of ``enum_type``."""
    if not isinstance(value, enum_type):
        choices = ", ".join(member.value for member in enum_type)
        raise ValidationError(f"{path} must be one of: {choices}")
    return value


def _enum_from_json(value: Any, enum_type: type[_EnumT], path: str) -> _EnumT:
    """Resolve a JSON string into a member of ``enum_type``."""
    choices = ", ".join(member.value for member in enum_type)
    if not isinstance(value, str):
        raise ValidationError(f"{path} must be one of: {choices}")
    try:
        return enum_type(value)
    except ValueError as exc:
        raise ValidationError(f"{path} must be one of: {choices}") from exc


def _immutable_text_tuple(value: Any, path: str, *, canonical: bool = True) -> tuple[str, ...]:
    """Validate and snapshot a sequence of operator-visible strings."""
    if isinstance(value, str | bytes) or not isinstance(value, Sequence):
        raise ValidationError(f"{path} must be a sequence of strings")
    result: list[str] = []
    for index, item in enumerate(value):
        text = _text(item, f"{path}[{index}]", trim=False)
        if canonical and text != text.strip():
            raise ValidationError(f"{path}[{index}] must not have surrounding whitespace")
        result.append(text)
    return tuple(result)


def _canonical_text_tuple(value: Any, path: str) -> tuple[str, ...]:
    """Validate a set-like sequence of identifiers into sorted, unique order."""
    items = _immutable_text_tuple(value, path)
    if len(set(items)) != len(items):
        raise ValidationError(f"{path} must not contain duplicates")
    return tuple(sorted(items))


def _freeze_json(
    value: Any,
    path: str,
    ancestors: frozenset[int] = frozenset(),
    *,
    depth: int = 0,
    allow_frozen_sequences: bool = False,
) -> Any:
    """Validate and recursively freeze a JSON value supplied through the Python API."""
    if depth > MAX_ATTRIBUTE_DEPTH:
        raise ValidationError(
            f"{path} exceeds the maximum attribute nesting depth of {MAX_ATTRIBUTE_DEPTH}"
        )
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        if abs(value) > _MAX_ATTRIBUTE_INTEGER:
            raise ValidationError(
                f"{path} integer must contain at most {MAX_ATTRIBUTE_INTEGER_DIGITS} digits"
            )
        return value
    if type(value) is float:
        if not isfinite(value):
            raise ValidationError(f"{path} must contain only finite JSON numbers")
        return value
    if type(value) is str:
        if not _is_xml_character(value):
            raise ValidationError(f"{path} contains a character not allowed by XML 1.0")
        return value
    if isinstance(value, Mapping):
        identity = id(value)
        if identity in ancestors:
            raise ValidationError(f"{path} must not contain a reference cycle")
        next_ancestors = ancestors | {identity}
        frozen: dict[str, Any] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise ValidationError(f"{path} keys must be strings")
            if not _is_xml_character(key):
                raise ValidationError(f"{path} contains a key not allowed by XML 1.0")
            frozen[key] = _freeze_json(
                item,
                f"{path}.{key}",
                next_ancestors,
                depth=depth + 1,
                allow_frozen_sequences=allow_frozen_sequences,
            )
        return MappingProxyType(frozen)
    if isinstance(value, list) or (allow_frozen_sequences and isinstance(value, tuple)):
        identity = id(value)
        if identity in ancestors:
            raise ValidationError(f"{path} must not contain a reference cycle")
        next_ancestors = ancestors | {identity}
        return tuple(
            _freeze_json(
                item,
                f"{path}[{index}]",
                next_ancestors,
                depth=depth + 1,
                allow_frozen_sequences=allow_frozen_sequences,
            )
            for index, item in enumerate(value)
        )
    raise ValidationError(f"{path} must contain only JSON values")


def _thaw_json(value: Any) -> Any:
    """Return a detached JSON-ready copy of an internally frozen value."""
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


def _named_mapping(value: Any, path: str) -> Mapping[str, Any]:
    """Validate a mapping whose keys are canonical domain identifiers."""
    data = _mapping(value, path)
    result: dict[str, Any] = {}
    for name, item in data.items():
        validated = _text(name, f"{path} key", trim=False)
        if validated != validated.strip():
            raise ValidationError(f"{path} keys must not have leading or trailing whitespace")
        result[validated] = item
    return result


@dataclass(frozen=True, slots=True)
class EvidenceEvent:
    """One observation about one claim.

    ``correlation_group`` identifies observations that share a causal origin.
    They are collapsed before quorum and score calculations.
    """

    event_id: str
    claim: str
    modality: Modality
    source: str
    signal: Signal
    confidence: float
    observed_at: datetime
    ingested_at: datetime
    correlation_group: str | None = None
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "event_id", _text(self.event_id, "event.event_id"))
        object.__setattr__(self, "claim", _text(self.claim, "event.claim"))
        object.__setattr__(self, "modality", _enum(self.modality, Modality, "event.modality"))
        object.__setattr__(self, "source", _text(self.source, "event.source"))
        object.__setattr__(self, "signal", _enum(self.signal, Signal, "event.signal"))
        object.__setattr__(
            self,
            "confidence",
            _number(self.confidence, "event.confidence", 0.0, 1.0),
        )
        object.__setattr__(
            self,
            "observed_at",
            normalize_datetime(self.observed_at, "event.observed_at"),
        )
        object.__setattr__(
            self,
            "ingested_at",
            normalize_datetime(self.ingested_at, "event.ingested_at"),
        )
        if self.correlation_group is not None:
            object.__setattr__(
                self,
                "correlation_group",
                _text(self.correlation_group, "event.correlation_group"),
            )
        attributes = _mapping(self.attributes, "event.attributes")
        object.__setattr__(
            self,
            "attributes",
            _freeze_json(
                attributes,
                "event.attributes",
                allow_frozen_sequences=isinstance(attributes, MappingProxyType),
            ),
        )

    @classmethod
    def from_dict(cls, raw: Any, path: str = "event") -> EvidenceEvent:
        data = _mapping(raw, path)
        _only(
            data,
            {
                "event_id",
                "claim",
                "modality",
                "source",
                "signal",
                "confidence",
                "observed_at",
                "ingested_at",
                "correlation_group",
                "attributes",
            },
            path,
        )
        event_id = _required_string(data, "event_id", path)
        claim = _required_string(data, "claim", path)
        source = _required_string(data, "source", path)
        modality = _enum_from_json(data.get("modality"), Modality, f"{path}.modality")
        signal = _enum_from_json(data.get("signal"), Signal, f"{path}.signal")
        confidence = _number(data.get("confidence"), f"{path}.confidence", 0.0, 1.0)
        observed_at = parse_timestamp(data.get("observed_at"), f"{path}.observed_at")
        ingested_at = parse_timestamp(data.get("ingested_at"), f"{path}.ingested_at")
        correlation_group = data.get("correlation_group")
        if correlation_group is not None:
            try:
                correlation_group = _text(correlation_group, f"{path}.correlation_group")
            except ValidationError as exc:
                raise ValidationError(
                    f"{path}.correlation_group must be null or valid non-empty text"
                ) from exc
        attributes_raw = _mapping(data.get("attributes", {}), f"{path}.attributes")
        attributes = _freeze_json(attributes_raw, f"{path}.attributes")
        return cls(
            event_id=event_id,
            claim=claim,
            modality=modality,
            source=source,
            signal=signal,
            confidence=confidence,
            observed_at=observed_at,
            ingested_at=ingested_at,
            correlation_group=correlation_group,
            attributes=attributes,
        )

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "event_id": self.event_id,
            "claim": self.claim,
            "modality": self.modality.value,
            "source": self.source,
            "signal": self.signal.value,
            "confidence": self.confidence,
            "observed_at": format_timestamp(self.observed_at),
            "ingested_at": format_timestamp(self.ingested_at),
        }
        if self.correlation_group is not None:
            result["correlation_group"] = self.correlation_group
        if self.attributes:
            result["attributes"] = _thaw_json(self.attributes)
        return result


@dataclass(frozen=True, slots=True)
class Adjudication:
    """One caller-supplied judgement about whether an observation was right.

    Evidence fusion cannot discover whether a source was correct; something
    outside this library must decide and say so. ``adjudicated_at`` is the
    ingestion analogue for ground truth: it controls when a judgement becomes
    knowable, so a replay snapshot stays a function of its own prefix.
    """

    event_id: str
    source: str
    verdict: Verdict
    adjudicated_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "event_id", _text(self.event_id, "adjudication.event_id"))
        object.__setattr__(self, "source", _text(self.source, "adjudication.source"))
        object.__setattr__(self, "verdict", _enum(self.verdict, Verdict, "adjudication.verdict"))
        object.__setattr__(
            self,
            "adjudicated_at",
            normalize_datetime(self.adjudicated_at, "adjudication.adjudicated_at"),
        )

    @classmethod
    def from_dict(cls, raw: Any, path: str = "adjudication") -> Adjudication:
        data = _mapping(raw, path)
        _only(data, {"event_id", "source", "verdict", "adjudicated_at"}, path)
        return cls(
            event_id=_required_string(data, "event_id", path),
            source=_required_string(data, "source", path),
            verdict=_enum_from_json(data.get("verdict"), Verdict, f"{path}.verdict"),
            adjudicated_at=parse_timestamp(data.get("adjudicated_at"), f"{path}.adjudicated_at"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "source": self.source,
            "verdict": self.verdict.value,
            "adjudicated_at": format_timestamp(self.adjudicated_at),
        }


@dataclass(frozen=True, slots=True)
class SourcePolicy:
    reliability: float

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "reliability",
            _number(self.reliability, "source.reliability", 0.0, 1.0),
        )

    @classmethod
    def from_dict(cls, raw: Any, path: str) -> SourcePolicy:
        data = _mapping(raw, path)
        _only(data, {"reliability"}, path)
        return cls(reliability=_number(data.get("reliability"), f"{path}.reliability", 0.0, 1.0))


@dataclass(frozen=True, slots=True)
class DecayPolicy:
    default_half_life_seconds: float
    modality_half_life_seconds: Mapping[Modality, float] = field(default_factory=dict)
    max_future_skew_seconds: float = 0.0

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "default_half_life_seconds",
            _number(
                self.default_half_life_seconds,
                "decay.default_half_life_seconds",
                0.000001,
            ),
        )
        if not isinstance(self.modality_half_life_seconds, Mapping):
            raise ValidationError("decay.modality_half_life_seconds must be an object")
        modalities_raw = self.modality_half_life_seconds
        modalities: dict[Modality, float] = {}
        for modality, value in modalities_raw.items():
            validated_modality = _enum(
                modality,
                Modality,
                "decay.modality_half_life_seconds key",
            )
            modalities[validated_modality] = _number(
                value,
                f"decay.modality_half_life_seconds.{validated_modality.value}",
                0.000001,
            )
        object.__setattr__(self, "modality_half_life_seconds", MappingProxyType(modalities))
        object.__setattr__(
            self,
            "max_future_skew_seconds",
            _number(self.max_future_skew_seconds, "decay.max_future_skew_seconds", 0.0),
        )

    @classmethod
    def from_dict(cls, raw: Any, path: str = "policy.decay") -> DecayPolicy:
        data = _mapping(raw, path)
        _only(
            data,
            {"default_half_life_seconds", "modality_half_life_seconds", "max_future_skew_seconds"},
            path,
        )
        default = _number(
            data.get("default_half_life_seconds"), f"{path}.default_half_life_seconds", 0.000001
        )
        modalities_raw = _named_mapping(
            data.get("modality_half_life_seconds", {}), f"{path}.modality_half_life_seconds"
        )
        modalities: dict[Modality, float] = {}
        for name, value in modalities_raw.items():
            try:
                modality = Modality(name)
            except ValueError as exc:
                raise ValidationError(
                    f"{path}.modality_half_life_seconds has unknown modality: {name}"
                ) from exc
            modalities[modality] = _number(
                value, f"{path}.modality_half_life_seconds.{name}", 0.000001
            )
        skew = _number(
            data.get("max_future_skew_seconds", 0), f"{path}.max_future_skew_seconds", 0.0
        )
        return cls(default, MappingProxyType(modalities), skew)

    def half_life_for(self, modality: Modality) -> float:
        return self.modality_half_life_seconds.get(modality, self.default_half_life_seconds)


@dataclass(frozen=True, slots=True)
class ReliabilityUpdatePolicy:
    """Opt-in closed form for moving a declared source reliability.

    ``prior_weight`` is denominated in adjudications: it is how many
    adjudications are needed to move a weight halfway from its declared value
    to the observed correct rate. ``max_adjustment`` bounds how far the applied
    weight may sit from the declared one, so a policy can keep updating from
    ever fully overriding an operator's stated number. The default of ``1.0``
    imposes no bound beyond the ``[0, 1]`` range reliabilities already have.
    """

    prior_weight: float
    max_adjustment: float = 1.0

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "prior_weight",
            _number(self.prior_weight, "reliability_updates.prior_weight", 0.000001),
        )
        object.__setattr__(
            self,
            "max_adjustment",
            _number(self.max_adjustment, "reliability_updates.max_adjustment", 0.0, 1.0),
        )

    @classmethod
    def from_dict(
        cls, raw: Any, path: str = "policy.reliability_updates"
    ) -> ReliabilityUpdatePolicy:
        data = _mapping(raw, path)
        _only(data, {"prior_weight", "max_adjustment"}, path)
        return cls(
            prior_weight=_number(data.get("prior_weight"), f"{path}.prior_weight", 0.000001),
            max_adjustment=_number(
                data.get("max_adjustment", 1.0), f"{path}.max_adjustment", 0.0, 1.0
            ),
        )


@dataclass(frozen=True, slots=True)
class ClaimRule:
    support_threshold: float
    contradiction_threshold: float
    min_margin: float
    quorum: int
    min_sources: int
    min_modalities: int
    min_evidence_confidence: float

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "support_threshold",
            _number(self.support_threshold, "claim_rule.support_threshold", 0.0, 1.0),
        )
        object.__setattr__(
            self,
            "contradiction_threshold",
            _number(
                self.contradiction_threshold,
                "claim_rule.contradiction_threshold",
                0.0,
                1.0,
            ),
        )
        object.__setattr__(
            self,
            "min_margin",
            _number(self.min_margin, "claim_rule.min_margin", 0.0, 1.0),
        )
        object.__setattr__(self, "quorum", _positive_int(self.quorum, "claim_rule.quorum"))
        object.__setattr__(
            self,
            "min_sources",
            _positive_int(self.min_sources, "claim_rule.min_sources"),
        )
        object.__setattr__(
            self,
            "min_modalities",
            _positive_int(self.min_modalities, "claim_rule.min_modalities"),
        )
        object.__setattr__(
            self,
            "min_evidence_confidence",
            _number(
                self.min_evidence_confidence,
                "claim_rule.min_evidence_confidence",
                0.0,
                1.0,
            ),
        )

    @classmethod
    def from_dict(cls, raw: Any, path: str) -> ClaimRule:
        data = _mapping(raw, path)
        allowed = {
            "support_threshold",
            "contradiction_threshold",
            "min_margin",
            "quorum",
            "min_sources",
            "min_modalities",
            "min_evidence_confidence",
        }
        _only(data, allowed, path)
        return cls(
            support_threshold=_number(
                data.get("support_threshold"), f"{path}.support_threshold", 0.0, 1.0
            ),
            contradiction_threshold=_number(
                data.get("contradiction_threshold"),
                f"{path}.contradiction_threshold",
                0.0,
                1.0,
            ),
            min_margin=_number(data.get("min_margin", 0.0), f"{path}.min_margin", 0.0, 1.0),
            quorum=_positive_int(data.get("quorum", 1), f"{path}.quorum"),
            min_sources=_positive_int(data.get("min_sources", 1), f"{path}.min_sources"),
            min_modalities=_positive_int(data.get("min_modalities", 1), f"{path}.min_modalities"),
            min_evidence_confidence=_number(
                data.get("min_evidence_confidence", 0.0),
                f"{path}.min_evidence_confidence",
                0.0,
                1.0,
            ),
        )


@dataclass(frozen=True, slots=True)
class Policy:
    schema_version: int
    policy_id: str
    default_source_reliability: float
    sources: Mapping[str, SourcePolicy]
    decay: DecayPolicy
    claims: Mapping[str, ClaimRule]
    reliability_updates: ReliabilityUpdatePolicy | None = None

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise ValidationError("policy.schema_version must be 1")
        object.__setattr__(self, "policy_id", _text(self.policy_id, "policy.policy_id"))
        object.__setattr__(
            self,
            "default_source_reliability",
            _number(
                self.default_source_reliability,
                "policy.default_source_reliability",
                0.0,
                1.0,
            ),
        )
        sources_raw = _named_mapping(self.sources, "policy.sources")
        sources: dict[str, SourcePolicy] = {}
        for name, source_policy in sources_raw.items():
            if not isinstance(source_policy, SourcePolicy):
                raise ValidationError(f"policy.sources.{name} must be a SourcePolicy instance")
            sources[name] = source_policy
        object.__setattr__(self, "sources", MappingProxyType(sources))
        if not isinstance(self.decay, DecayPolicy):
            raise ValidationError("policy.decay must be a DecayPolicy instance")
        if self.reliability_updates is not None and not isinstance(
            self.reliability_updates, ReliabilityUpdatePolicy
        ):
            raise ValidationError(
                "policy.reliability_updates must be a ReliabilityUpdatePolicy instance or null"
            )
        claims_raw = _named_mapping(self.claims, "policy.claims")
        if not claims_raw:
            raise ValidationError("policy.claims must contain at least one claim")
        claims: dict[str, ClaimRule] = {}
        for name, rule in claims_raw.items():
            if not isinstance(rule, ClaimRule):
                raise ValidationError(f"policy.claims.{name} must be a ClaimRule instance")
            claims[name] = rule
        object.__setattr__(self, "claims", MappingProxyType(claims))

    @classmethod
    def from_dict(cls, raw: Any) -> Policy:
        data = _mapping(raw, "policy")
        _only(
            data,
            {
                "schema_version",
                "policy_id",
                "default_source_reliability",
                "sources",
                "decay",
                "claims",
                "reliability_updates",
            },
            "policy",
        )
        version = data.get("schema_version")
        if type(version) is not int or version != 1:
            raise ValidationError("policy.schema_version must be 1")
        policy_id = _required_string(data, "policy_id", "policy")
        default_reliability = _number(
            data.get("default_source_reliability", 1.0),
            "policy.default_source_reliability",
            0.0,
            1.0,
        )
        sources_raw = _named_mapping(data.get("sources", {}), "policy.sources")
        sources = {
            name: SourcePolicy.from_dict(value, f"policy.sources.{name}")
            for name, value in sources_raw.items()
        }
        claims_raw = _named_mapping(data.get("claims"), "policy.claims")
        if not claims_raw:
            raise ValidationError("policy.claims must contain at least one claim")
        claims = {
            name: ClaimRule.from_dict(value, f"policy.claims.{name}")
            for name, value in claims_raw.items()
        }
        # A policy that says nothing about reliability updating gets none: the
        # feature has to be asked for by name before any weight can move.
        updates_raw = data.get("reliability_updates")
        return cls(
            schema_version=version,
            policy_id=policy_id,
            default_source_reliability=default_reliability,
            sources=MappingProxyType(sources),
            decay=DecayPolicy.from_dict(data.get("decay")),
            claims=MappingProxyType(claims),
            reliability_updates=(
                None if updates_raw is None else ReliabilityUpdatePolicy.from_dict(updates_raw)
            ),
        )

    def reliability_for(self, source: str) -> float:
        configured = self.sources.get(source)
        return configured.reliability if configured else self.default_source_reliability
