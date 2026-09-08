"""Bounded deterministic predicates over retained bytes, not producer assertions.

There is no callback, expression language, provider, or test-command execution.
An evaluation states only what these committed bytes imply under this fixed
integer/scalar profile. Recompute it before trusting a serialized result.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, cast

from .authority import ArtifactReference, _array, _identifier, _integer
from .errors import InputFormatError, ValidationError
from .io import _reject_constant, _reject_duplicate_keys, canonical_json
from .ledger import _fields, _hash
from .models import _is_xml_character

CHECK_ENGINE_VERSION = "retained-integer-scalars-v1"
_SAFE_INTEGER = (1 << 53) - 1
_MAX_PLAN_BYTES = 256 * 1024
_MAX_RULES = 256
_MAX_INPUTS = 64
_MAX_DEPTH = 32
_MAX_NODES = 500_000
_MAX_WORK = 256 * 1024 * 1024
_MAX_OUTPUT_BYTES = 256 * 1024


class CheckLimitError(ValidationError):
    """Admission or work exhausted; no unknown/pass evaluation is returned."""


class CheckOperator(StrEnum):
    EXISTS = "exists"
    EQUALS = "equals"
    INTEGER_RANGE = "integer_range"
    SAME_VALUE = "same_value"
    BYTES_EQUAL = "bytes_equal"


class CheckOutcome(StrEnum):
    # Public predicate outcome, not an authentication secret.
    PASS = "pass"  # nosec B105
    FAIL = "fail"
    UNKNOWN = "unknown"


class CheckReason(StrEnum):
    PASSED = "passed"
    PREDICATE_FALSE = "predicate_false"
    PATH_MISSING = "path_missing"
    TYPE_UNSUPPORTED = "type_unsupported"


class _Absent:
    __slots__ = ()


_ABSENT = _Absent()


def _scalar(value: Any) -> bool:
    return (
        value is None
        or type(value) is bool
        or (type(value) is int and -_SAFE_INTEGER <= value <= _SAFE_INTEGER)
        or (type(value) is str and len(value) <= 65_536 and _is_xml_character(value))
    )


def _path(value: Any) -> None:
    if type(value) is not tuple or len(value) > _MAX_DEPTH:
        raise ValidationError("check path must be an immutable bounded tuple")
    for part in value:
        if type(part) is int and 0 <= part <= _SAFE_INTEGER:
            continue
        if type(part) is str and len(part) <= 256 and _is_xml_character(part):
            continue
        raise ValidationError(
            "check path requires bounded string keys or nonnegative integer indices"
        )


def _wire(data: Mapping[str, Any], kind: str) -> None:
    if (
        type(data["kind"]) is not str
        or data["kind"] != kind
        or type(data["schema_version"]) is not str
        or data["schema_version"] != "1.0"
    ):
        raise ValidationError("unsupported check wire profile")


def _encoded(value: Any) -> bytes:
    return canonical_json(value, pretty=False).encode("utf-8")


@dataclass(frozen=True, slots=True)
class CheckRule:
    rule_id: str
    operator: CheckOperator
    artifact_id: str
    path: tuple[str | int, ...] = ()
    expected: Any = _ABSENT
    minimum: int | None = None
    maximum: int | None = None
    other_artifact_id: str | None = None
    other_path: tuple[str | int, ...] | None = None

    def __post_init__(self) -> None:
        _identifier(self.rule_id, "rule.rule_id")
        _identifier(self.artifact_id, "rule.artifact_id")
        if type(self.operator) is not CheckOperator:
            raise ValidationError("rule operator must be CheckOperator")
        _path(self.path)
        if self.operator is CheckOperator.EQUALS:
            if not _scalar(self.expected) or (
                type(self.expected) is str and len(self.expected) > 4096
            ):
                raise ValidationError("expected must be an explicit bounded integer-profile scalar")
        elif self.expected is not _ABSENT:
            raise ValidationError("expected is only valid for equals")
        if self.operator is CheckOperator.INTEGER_RANGE:
            if (
                type(self.minimum) is not int
                or type(self.maximum) is not int
                or not -_SAFE_INTEGER <= self.minimum <= self.maximum <= _SAFE_INTEGER
            ):
                raise ValidationError("integer range requires ordered safe integer endpoints")
        elif self.minimum is not None or self.maximum is not None:
            raise ValidationError("range endpoints are only valid for integer_range")
        if self.operator in (CheckOperator.SAME_VALUE, CheckOperator.BYTES_EQUAL):
            _identifier(self.other_artifact_id, "rule.other_artifact_id")
            if self.operator is CheckOperator.SAME_VALUE:
                _path(self.other_path)
            elif self.other_path is not None or self.path:
                raise ValidationError("byte equality cannot carry JSON paths")
        elif self.other_artifact_id is not None or self.other_path is not None:
            raise ValidationError("other input is only valid for cross-artifact equality")

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "rule_id": self.rule_id,
            "operator": self.operator.value,
            "artifact_id": self.artifact_id,
        }
        if self.operator is not CheckOperator.BYTES_EQUAL:
            result["path"] = list(self.path)
        if self.operator is CheckOperator.EQUALS:
            result["expected"] = self.expected
        if self.operator is CheckOperator.INTEGER_RANGE:
            result.update(minimum=self.minimum, maximum=self.maximum)
        if self.other_artifact_id is not None:
            result["other_artifact_id"] = self.other_artifact_id
        if self.other_path is not None:
            result["other_path"] = list(self.other_path)
        return result

    @classmethod
    def from_dict(cls, value: Any) -> CheckRule:
        if type(value) is not dict or "operator" not in value:
            raise ValidationError("rule must be a closed object")
        if type(value["operator"]) is not str or value["operator"] not in {
            item.value for item in CheckOperator
        }:
            raise ValidationError("rule operator must be a known enum string")
        operator = CheckOperator(value["operator"])
        names = {"rule_id", "operator", "artifact_id"}
        if operator is not CheckOperator.BYTES_EQUAL:
            names.add("path")
        names.update(
            {
                CheckOperator.EXISTS: set(),
                CheckOperator.EQUALS: {"expected"},
                CheckOperator.INTEGER_RANGE: {"minimum", "maximum"},
                CheckOperator.SAME_VALUE: {"other_artifact_id", "other_path"},
                CheckOperator.BYTES_EQUAL: {"other_artifact_id"},
            }[operator]
        )
        data = dict(_fields(value, names, "rule"))
        data["operator"] = operator
        for name in ("path", "other_path"):
            if name in data:
                data[name] = tuple(_array(data[name], name, _MAX_DEPTH))
        return cls(**data)


@dataclass(frozen=True, slots=True)
class CheckLimits:
    max_inputs: int = 16
    max_rules: int = 64
    max_input_bytes: int = 1024 * 1024
    max_total_input_bytes: int = 4 * 1024 * 1024
    max_json_depth: int = 16
    max_json_nodes: int = 100_000
    max_work_units: int = 32 * 1024 * 1024
    max_plan_bytes: int = 64 * 1024
    max_output_bytes: int = 64 * 1024

    def __post_init__(self) -> None:
        for name, ceiling in (
            ("max_inputs", _MAX_INPUTS),
            ("max_rules", _MAX_RULES),
            ("max_input_bytes", 4 * 1024 * 1024),
            ("max_total_input_bytes", 16 * 1024 * 1024),
            ("max_json_depth", _MAX_DEPTH),
            ("max_json_nodes", _MAX_NODES),
            ("max_work_units", _MAX_WORK),
            ("max_plan_bytes", _MAX_PLAN_BYTES),
            ("max_output_bytes", _MAX_OUTPUT_BYTES),
        ):
            _integer(getattr(self, name), name, ceiling, 1)


def _limits(value: CheckLimits | None) -> CheckLimits:
    result = CheckLimits() if value is None else value
    if type(result) is not CheckLimits:
        raise ValidationError("limits must be CheckLimits")
    return result


@dataclass(frozen=True, slots=True)
class CheckPlan:
    plan_id: str
    workflow_id: str
    scope: str
    claim_id: str
    statement_digest: str
    authority_digest: str
    evidence_head: str
    inputs: tuple[ArtifactReference, ...]
    rules: tuple[CheckRule, ...]

    def __post_init__(self) -> None:
        for name in ("plan_id", "workflow_id", "scope", "claim_id"):
            _identifier(getattr(self, name), name)
        for name in ("statement_digest", "authority_digest", "evidence_head"):
            _hash(getattr(self, name), name)
        if (
            type(self.inputs) is not tuple
            or not 1 <= len(self.inputs) <= _MAX_INPUTS
            or any(type(item) is not ArtifactReference for item in self.inputs)
        ):
            raise ValidationError(
                "plan inputs require a nonempty bounded immutable reference tuple"
            )
        inputs = {item.artifact_id: item for item in self.inputs}
        if len(inputs) != len(self.inputs) or any(
            item.scope != self.scope or item.claim_id != self.claim_id for item in self.inputs
        ):
            raise ValidationError("plan input IDs must be unique and match its claim and scope")
        if (
            type(self.rules) is not tuple
            or not 1 <= len(self.rules) <= _MAX_RULES
            or any(type(rule) is not CheckRule for rule in self.rules)
            or len({rule.rule_id for rule in self.rules}) != len(self.rules)
        ):
            raise ValidationError(
                "plan rules require a nonempty ordered tuple with unique rule IDs"
            )
        used: set[str] = set()
        for rule in self.rules:
            for identifier in (rule.artifact_id, rule.other_artifact_id):
                if identifier is None:
                    continue
                if identifier not in inputs:
                    raise ValidationError("rule refers to an undeclared input")
                used.add(identifier)
                if (
                    rule.operator is not CheckOperator.BYTES_EQUAL
                    and inputs[identifier].media_type != "application/json"
                ):
                    raise ValidationError("JSON rules require application/json input commitments")
        if used != set(inputs):
            raise ValidationError("every declared input must participate in a rule")
        object.__setattr__(
            self, "inputs", tuple(sorted(self.inputs, key=lambda item: item.artifact_id))
        )
        if len(self.to_bytes()) > _MAX_PLAN_BYTES:
            raise CheckLimitError("plan exceeds the compiled byte bound")

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": "evidence-braid-check-plan",
            "schema_version": "1.0",
            "engine_version": CHECK_ENGINE_VERSION,
            "plan_id": self.plan_id,
            "workflow_id": self.workflow_id,
            "scope": self.scope,
            "claim_id": self.claim_id,
            "statement_digest": self.statement_digest,
            "authority_digest": self.authority_digest,
            "evidence_head": self.evidence_head,
            "inputs": [item.to_dict() for item in self.inputs],
            "rules": [rule.to_dict() for rule in self.rules],
        }

    def to_bytes(self) -> bytes:
        return _encoded(self.to_dict())

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    @classmethod
    def from_dict(cls, value: Any) -> CheckPlan:
        if type(value) is not dict:
            raise ValidationError("plan must be a plain closed object")
        data = _fields(
            value,
            {
                "kind",
                "schema_version",
                "engine_version",
                "plan_id",
                "workflow_id",
                "scope",
                "claim_id",
                "statement_digest",
                "authority_digest",
                "evidence_head",
                "inputs",
                "rules",
            },
            "plan",
        )
        _wire(data, "evidence-braid-check-plan")
        if (
            type(data["engine_version"]) is not str
            or data["engine_version"] != CHECK_ENGINE_VERSION
        ):
            raise ValidationError("unsupported check engine version")
        inputs = _array(data["inputs"], "inputs", _MAX_INPUTS)
        if any(type(item) is not dict for item in inputs):
            raise ValidationError("plan input commitments must be plain closed objects")
        return cls(
            data["plan_id"],
            data["workflow_id"],
            data["scope"],
            data["claim_id"],
            data["statement_digest"],
            data["authority_digest"],
            data["evidence_head"],
            tuple(ArtifactReference.from_dict(item) for item in inputs),
            tuple(CheckRule.from_dict(item) for item in _array(data["rules"], "rules", _MAX_RULES)),
        )


@dataclass(frozen=True, slots=True)
class CheckResult:
    rule_id: str
    outcome: CheckOutcome
    reason: CheckReason

    def __post_init__(self) -> None:
        _identifier(self.rule_id, "result.rule_id")
        if type(self.outcome) is not CheckOutcome or type(self.reason) is not CheckReason:
            raise ValidationError("result outcome and reason must be typed enums")
        expected = {
            CheckReason.PASSED: CheckOutcome.PASS,
            CheckReason.PREDICATE_FALSE: CheckOutcome.FAIL,
            CheckReason.PATH_MISSING: CheckOutcome.UNKNOWN,
            CheckReason.TYPE_UNSUPPORTED: CheckOutcome.UNKNOWN,
        }[self.reason]
        if self.outcome is not expected:
            raise ValidationError("result outcome contradicts its reason")

    def to_dict(self) -> dict[str, str]:
        return {"rule_id": self.rule_id, "outcome": self.outcome.value, "reason": self.reason.value}


@dataclass(frozen=True, slots=True)
class CheckEvaluation:
    """Immutable output description; only recomputation verifies claimed results."""

    plan_digest: str
    results: tuple[CheckResult, ...]

    def __post_init__(self) -> None:
        _hash(self.plan_digest, "evaluation.plan_digest")
        if (
            type(self.results) is not tuple
            or not 1 <= len(self.results) <= _MAX_RULES
            or any(type(item) is not CheckResult for item in self.results)
            or len({item.rule_id for item in self.results}) != len(self.results)
        ):
            raise ValidationError("evaluation requires nonempty immutable unique rule results")

    @property
    def outcome(self) -> CheckOutcome:
        if any(item.outcome is CheckOutcome.FAIL for item in self.results):
            return CheckOutcome.FAIL
        if any(item.outcome is CheckOutcome.UNKNOWN for item in self.results):
            return CheckOutcome.UNKNOWN
        return CheckOutcome.PASS

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": "evidence-braid-check-evaluation",
            "schema_version": "1.0",
            "engine_version": CHECK_ENGINE_VERSION,
            "plan_digest": self.plan_digest,
            "outcome": self.outcome.value,
            "counts": {
                state.value: sum(item.outcome is state for item in self.results)
                for state in CheckOutcome
            },
            "results": [item.to_dict() for item in self.results],
        }

    def to_bytes(self) -> bytes:
        return _encoded(self.to_dict())

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()


@dataclass(slots=True)
class _Budget:
    limits: CheckLimits
    used: int = 0
    nodes: int = 0

    def charge(self, count: int) -> None:
        if count > self.limits.max_work_units - self.used:
            raise CheckLimitError("check work budget exhausted")
        self.used += count


def _safe_integer(text: str) -> int:
    if len(text) > 17:
        raise ValueError("integer token exceeds the check profile")
    value = int(text)
    if abs(value) > _SAFE_INTEGER:
        raise ValueError("integer exceeds the check profile")
    return value


def _no_float(text: str) -> None:
    raise ValueError("the check profile accepts lexical integers, not floating-point numbers")


def _document(raw: bytes, budget: _Budget, maximum: int) -> Any:
    if type(raw) is not bytes or len(raw) > maximum:
        raise CheckLimitError("check document exceeds its byte bound or is not immutable bytes")
    budget.charge(len(raw))
    # The finite byte bound and this lexical nesting scan precede JSON allocation.
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
            if depth > budget.limits.max_json_depth:
                raise CheckLimitError("check JSON nesting exceeds its bound")
        elif byte in (93, 125):
            depth -= 1
    try:
        value = json.loads(
            raw.decode("utf-8"),
            parse_int=_safe_integer,
            parse_float=_no_float,
            parse_constant=_reject_constant,
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (ValueError, UnicodeError, RecursionError):
        raise InputFormatError(
            "invalid JSON for the retained integer/scalar check profile"
        ) from None
    stack = [value]
    while stack:
        item = stack.pop()
        budget.charge(1)
        budget.nodes += 1
        if budget.nodes > budget.limits.max_json_nodes:
            raise CheckLimitError("shared check JSON node budget exhausted")
        if type(item) is dict:
            for key in item:
                if len(key) > 65_536 or not _is_xml_character(key):
                    raise InputFormatError("JSON key is outside the check text profile")
            stack.extend(item.values())
        elif type(item) is list:
            stack.extend(item)
        elif not _scalar(item):
            raise InputFormatError("JSON scalar is outside the check profile")
    return value


def _snapshot(
    contents: dict[str, bytes], limits: CheckLimits, *, extra: int = 0
) -> dict[str, bytes]:
    if type(contents) is not dict or len(contents) > limits.max_inputs + extra:
        raise ValidationError("retained contents require a bounded plain dict")
    result: dict[str, bytes] = {}
    total = 0
    try:
        for identifier, raw in contents.items():
            if len(result) >= limits.max_inputs + extra:
                raise CheckLimitError("retained input count exceeds its bound")
            _identifier(identifier, "retained artifact ID")
            if type(raw) is not bytes:
                raise ValidationError("retained inputs must be exact immutable bytes")
            total += len(raw)
            if len(raw) > limits.max_input_bytes or total > limits.max_total_input_bytes:
                raise CheckLimitError("retained input byte budget exceeded")
            result[identifier] = raw
    except RuntimeError:
        raise ValidationError("retained input mapping changed during admission") from None
    return result


def _at(value: Any, path: tuple[str | int, ...], budget: _Budget) -> Any:
    for part in path:
        budget.charge(1 + (len(part) if type(part) is str else 0))
        if (type(part) is str and type(value) is dict and part in value) or (
            type(part) is int and type(value) is list and part < len(value)
        ):
            value = cast(Any, value)[part]
        else:
            return _ABSENT
    return value


def _equal(left: Any, right: Any, budget: _Budget) -> bool:
    budget.charge(
        1 + (len(left) if type(left) is str else 0) + (len(right) if type(right) is str else 0)
    )
    return type(left) is type(right) and left == right


def _rule(
    rule: CheckRule, parsed: dict[str, Any], raw: dict[str, bytes], budget: _Budget
) -> CheckResult:
    budget.charge(1)
    if rule.operator is CheckOperator.BYTES_EQUAL:
        left, right = raw[rule.artifact_id], raw[str(rule.other_artifact_id)]
        budget.charge(len(left) + len(right))
        passed = left == right
    else:
        value = _at(parsed[rule.artifact_id], rule.path, budget)
        if rule.operator is CheckOperator.EXISTS:
            passed = value is not _ABSENT
        else:
            other = (
                _at(parsed[str(rule.other_artifact_id)], rule.other_path or (), budget)
                if rule.operator is CheckOperator.SAME_VALUE
                else rule.expected
            )
            if value is _ABSENT or (rule.operator is CheckOperator.SAME_VALUE and other is _ABSENT):
                return CheckResult(rule.rule_id, CheckOutcome.UNKNOWN, CheckReason.PATH_MISSING)
            if not _scalar(value) or (
                rule.operator is CheckOperator.SAME_VALUE and not _scalar(other)
            ):
                return CheckResult(rule.rule_id, CheckOutcome.UNKNOWN, CheckReason.TYPE_UNSUPPORTED)
            if rule.operator is CheckOperator.INTEGER_RANGE:
                if type(value) is not int:
                    return CheckResult(
                        rule.rule_id, CheckOutcome.UNKNOWN, CheckReason.TYPE_UNSUPPORTED
                    )
                budget.charge(2)
                passed = cast(int, rule.minimum) <= value <= cast(int, rule.maximum)
            else:
                passed = _equal(value, other, budget)
    return CheckResult(
        rule.rule_id,
        CheckOutcome.PASS if passed else CheckOutcome.FAIL,
        CheckReason.PASSED if passed else CheckReason.PREDICATE_FALSE,
    )


def _evaluate(plan: CheckPlan, retained: dict[str, bytes], budget: _Budget) -> CheckEvaluation:
    limits = budget.limits
    if type(plan) is not CheckPlan:
        raise ValidationError("evaluation requires CheckPlan")
    encoded = plan.to_bytes()
    if (
        len(encoded) > limits.max_plan_bytes
        or len(plan.rules) > limits.max_rules
        or len(plan.inputs) > limits.max_inputs
    ):
        raise CheckLimitError("plan exceeds the configured admission bound")
    budget.charge(len(encoded))
    if set(retained) != {item.artifact_id for item in plan.inputs}:
        raise ValidationError("retained input inventory must exactly match the plan")
    for item in plan.inputs:
        raw = retained[item.artifact_id]
        budget.charge(len(raw))
        if not item.matches(raw):
            raise ValidationError("retained artifact content differs from its plan commitment")
    json_inputs = {
        identifier
        for rule in plan.rules
        if rule.operator is not CheckOperator.BYTES_EQUAL
        for identifier in (rule.artifact_id, rule.other_artifact_id)
        if identifier is not None
    }
    parsed = {
        name: _document(retained[name], budget, limits.max_input_bytes)
        for name in sorted(json_inputs)
    }
    result = CheckEvaluation(
        hashlib.sha256(encoded).hexdigest(),
        tuple(_rule(rule, parsed, retained, budget) for rule in plan.rules),
    )
    output = result.to_bytes()
    if len(output) > limits.max_output_bytes:
        raise CheckLimitError("check result exceeds the configured output bound")
    budget.charge(len(output))
    return result


def evaluate_checks(
    plan: CheckPlan,
    contents: dict[str, bytes],
    *,
    limits: CheckLimits | None = None,
) -> CheckEvaluation:
    """Recompute all ordered rules; malformed data or exhausted work raises.

    Caller-supplied result/pass fields have no special interpretation. Plain
    dict inputs are snapshotted to immutable bytes before any content checks.
    """
    bounds = _limits(limits)
    return _evaluate(plan, _snapshot(contents, bounds), _Budget(bounds))


def parse_check_plan(raw: bytes, *, limits: CheckLimits | None = None) -> CheckPlan:
    bounds = _limits(limits)
    budget = _Budget(bounds)
    plan = CheckPlan.from_dict(_document(raw, budget, bounds.max_plan_bytes))
    if len(plan.inputs) > bounds.max_inputs or len(plan.rules) > bounds.max_rules:
        raise CheckLimitError("parsed plan exceeds the configured count bounds")
    encoded = plan.to_bytes()
    budget.charge(len(encoded) + len(raw))
    if encoded != raw:
        raise InputFormatError("check plans require their exact canonical bytes")
    return plan
