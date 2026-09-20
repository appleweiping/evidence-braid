"""Trusted, synchronous offline execution for one epistemic-case observation.

The runner owns returned bytes in one process. It does not sandbox trusted
Python callbacks, authenticate declared actors or make a durable claim.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import InitVar, dataclass
from threading import Event, Lock, RLock
from weakref import WeakValueDictionary

from .authority import _identifier, _integer
from .epistemic_case import (
    CaseActorKind,
    CaseAuthority,
    CaseCheckpoint,
    CaseJournal,
    CaseObservation,
    CaseObservationStatus,
    CasePhase,
    CasePlan,
    CaseRole,
    CaseVerdict,
    CaseVerdictOutcome,
    replay_case,
)
from .errors import ValidationError
from .ledger import _hash
from .models import _is_xml_character

_MAX_ASSERTION = 64 * 1024
_MAX_INPUT = 256 * 1024
_MAX_TOTAL = 512 * 1024
_MAX_OUTPUT = 4096
_MAX_ADAPTERS = 64
_PREPARED_KEY = object()
_RETAINED_KEY = object()


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _snapshot(raw: object, maximum: int, label: str) -> bytes:
    if type(raw) is not bytes or len(raw) > maximum:
        raise ValidationError(f"{label} must be bounded built-in bytes")
    return bytes(raw)


def _output(raw: object, limits: ObservationLimits, input_total: int) -> bytes:
    if type(raw) is not bytes or len(raw) > limits.output_bytes:
        raise ValidationError("adapter output must be bounded built-in bytes")
    if input_total + len(raw) > limits.total_bytes:
        raise ValidationError("retained observation exceeds the total byte bound")
    output = bytes(raw)
    try:
        text = output.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ValidationError("adapter output is not strict UTF-8") from exc
    if not _is_xml_character(text):
        raise ValidationError("adapter output has unsupported text")
    return output


@dataclass(frozen=True, slots=True)
class ObservationLimits:
    assertion_bytes: int = _MAX_ASSERTION
    input_bytes: int = _MAX_INPUT
    total_bytes: int = _MAX_TOTAL
    output_bytes: int = _MAX_OUTPUT

    def __post_init__(self) -> None:
        for label, maximum in (
            ("assertion_bytes", _MAX_ASSERTION),
            ("input_bytes", _MAX_INPUT),
            ("total_bytes", _MAX_TOTAL),
            ("output_bytes", _MAX_OUTPUT),
        ):
            _integer(getattr(self, label), f"observation {label}", maximum)


@dataclass(frozen=True, slots=True)
class ObservationAdapter:
    test_id: str
    adapter_id: str
    adapter_version: str
    observer_id: str
    callback: Callable[[bytes], bytes]

    def __post_init__(self) -> None:
        for label in ("test_id", "adapter_id", "adapter_version", "observer_id"):
            _identifier(getattr(self, label), f"observation adapter {label}")
        if not callable(self.callback):
            raise ValidationError("observation adapter requires a trusted callable")

    @property
    def key(self) -> tuple[str, str, str, str]:
        return self.test_id, self.adapter_id, self.adapter_version, self.observer_id


class ObservationRegistry:
    """Closed in-memory entries provisioned by the trusted application."""

    __slots__ = ("_entries", "_limits")
    _entries: tuple[ObservationAdapter, ...]
    _limits: ObservationLimits

    def __init__(
        self, entries: tuple[ObservationAdapter, ...], *, limits: ObservationLimits | None = None
    ) -> None:
        if (
            type(entries) is not tuple
            or not 1 <= len(entries) <= _MAX_ADAPTERS
            or any(type(entry) is not ObservationAdapter for entry in entries)
        ):
            raise ValidationError("registry requires bounded immutable adapter entries")
        keys = [entry.key for entry in entries]
        if len(set(keys)) != len(keys) or len({key[:3] for key in keys}) != len(keys):
            raise ValidationError("registry adapter identity must be unique and unambiguous")
        if limits is not None and type(limits) is not ObservationLimits:
            raise ValidationError("registry limits require exact ObservationLimits")
        object.__setattr__(self, "_entries", entries)
        object.__setattr__(self, "_limits", ObservationLimits() if limits is None else limits)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("observation registry entries cannot be replaced")

    @property
    def limits(self) -> ObservationLimits:
        return self._limits

    @property
    def entries(self) -> tuple[ObservationAdapter, ...]:
        return self._entries

    def select(self, plan: CasePlan, authority: CaseAuthority) -> ObservationAdapter:
        if type(plan) is not CasePlan or type(authority) is not CaseAuthority:
            raise ValidationError("observation lookup requires plan and authority")
        matches = [
            item
            for item in self._entries
            if item.key[:3] == (plan.test_id, plan.adapter_id, plan.adapter_version)
        ]
        if len(matches) != 1:
            raise ValidationError("registered observation adapter is unavailable")
        selected = matches[0]
        actor = next(
            (item for item in authority.actors if item.actor_id == selected.observer_id), None
        )
        if (
            actor is None
            or actor.kind is not CaseActorKind.TOOL
            or selected.observer_id == plan.proposer_id
            or not actor.permits(plan.scope, CaseRole.OBSERVE)
        ):
            raise ValidationError("registered observer lacks exact scoped authority")
        return selected


class ObservationUnavailable(Exception):
    """Explicit, nonsecret offline-adapter unavailability signal."""


class ObservationCancelled(ValidationError):
    """Cancellation before callback entry; the intent remains consumed."""


class ObservationInterrupted(ValidationError):
    """Cancellation after entry; no observation has been published."""

    def __init__(self, observed_bytes: bytes | None) -> None:
        super().__init__("observation entered but was interrupted before publication")
        self.observed_bytes = observed_bytes


class ObservationPublicationError(ValidationError):
    """Measured output exists, but immutable journal append did not succeed."""

    def __init__(self, observed_bytes: bytes | None) -> None:
        super().__init__("observation ran but journal publication failed")
        self.observed_bytes = observed_bytes


class ObservationCancelToken:
    __slots__ = ("_event", "_lock", "_published", "_publishing")

    def __init__(self) -> None:
        self._event = Event()
        self._lock = RLock()
        self._published = False
        self._publishing = False

    def cancel(self) -> bool:
        """Accept cancellation before publication; return False once committed."""
        with self._lock:
            if self._publishing:
                raise ValidationError("reentrant cancellation during observation publication")
            if self._published:
                return False
            self._event.set()
            return True

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()


class PreparedObservation:
    """Opaque, runner-owned one-process, at-most-once adapter intent."""

    __slots__ = (
        "_adapter",
        "_assertion",
        "_authority",
        "_checkpoint",
        "_consumed",
        "_input",
        "_journal",
        "_lock",
        "_plan",
        "_registry",
        "_request_id",
        "_sealed",
    )

    def __init__(
        self,
        journal: CaseJournal,
        authority: CaseAuthority,
        registry: ObservationRegistry,
        adapter: ObservationAdapter,
        plan: CasePlan,
        assertion: bytes,
        input_bytes: bytes,
        request_id: str,
        *,
        _key: object,
    ) -> None:
        if _key is not _PREPARED_KEY:
            raise ValidationError("prepared observation must come from preflight")
        self._journal = journal
        self._authority = authority
        self._registry = registry
        self._adapter = adapter
        self._plan = plan
        self._assertion = assertion
        self._input = input_bytes
        self._request_id = request_id
        self._checkpoint = journal.checkpoint
        self._lock = Lock()
        self._consumed = False
        self._sealed = True

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError("prepared observation intent is immutable")
        object.__setattr__(self, name, value)

    def _claim(self) -> None:
        with self._lock:
            if self._consumed:
                raise ValidationError("prepared observation was already consumed")
            object.__setattr__(self, "_consumed", True)


@dataclass(frozen=True, slots=True)
class ObservationArtifact:
    artifact_id: str
    sha256: str


@dataclass(frozen=True, slots=True, weakref_slot=True)
class RetainedObservation:
    journal: CaseJournal
    plan_checkpoint: CaseCheckpoint
    observation_checkpoint: CaseCheckpoint
    observation: CaseObservation
    adapter_key: tuple[str, str, str, str]
    request_id: str
    assertion_bytes: bytes
    input_bytes: bytes
    observed_bytes: bytes | None
    artifact_inventory: tuple[ObservationArtifact, ...]
    limits: ObservationLimits
    _key: InitVar[object] = None

    def __post_init__(self, _key: object) -> None:
        if _key is not _RETAINED_KEY:
            raise ValidationError("retained observation must be minted by the runner")


# An in-process issuance marker, not a signature or proof about arbitrary Python code.
# Identity (rather than dataclass equality) rejects copies and caller-crafted envelopes.
_ISSUED_LOCK = Lock()
_ISSUED: WeakValueDictionary[int, RetainedObservation] = WeakValueDictionary()


@dataclass(frozen=True, slots=True)
class CheckedObservation:
    journal: CaseJournal
    verdict: CaseVerdict
    plan_checkpoint: CaseCheckpoint
    observation_checkpoint: CaseCheckpoint
    verdict_checkpoint: CaseCheckpoint
    assertion_bytes: bytes
    input_bytes: bytes
    observed_bytes: bytes | None


def prepare_observation(
    journal: CaseJournal,
    authority: CaseAuthority,
    registry: ObservationRegistry,
    assertion_bytes: bytes,
    input_bytes: bytes,
    *,
    expected_plan_head: str,
    request_id: str,
) -> PreparedObservation:
    """Validate exact plan, authority, identity and input commitments before entry."""
    if type(registry) is not ObservationRegistry:
        raise ValidationError("observation requires trusted registry")
    _hash(expected_plan_head, "expected observation plan head")
    state = replay_case(journal, authority=authority, expected_head=expected_plan_head)
    if state.phase is not CasePhase.PLANNED or len(journal.receipts) != 1:
        raise ValidationError("observation requires an exactly one-record planned journal")
    plan = journal.receipts[0].record
    if type(plan) is not CasePlan:
        raise ValidationError("observation requires a case plan")
    _identifier(request_id, "observation request ID")
    limits = registry.limits
    assertion = _snapshot(assertion_bytes, limits.assertion_bytes, "assertion")
    source = _snapshot(input_bytes, limits.input_bytes, "test input")
    if len(assertion) + len(source) > limits.total_bytes:
        raise ValidationError("retained observation exceeds the total byte bound")
    if _sha(assertion) != plan.assertion_sha256 or _sha(source) != plan.input_sha256:
        raise ValidationError("observation input artifact commitment differs from plan")
    adapter = registry.select(plan, authority)
    return PreparedObservation(
        journal,
        authority,
        registry,
        adapter,
        plan,
        assertion,
        source,
        request_id,
        _key=_PREPARED_KEY,
    )


def _retained(
    intent: PreparedObservation,
    observation: CaseObservation,
    output: bytes | None,
    cancel: ObservationCancelToken | None,
) -> RetainedObservation:
    if cancel is None:
        try:
            journal = intent._journal.append(
                (observation,), authority=intent._authority, expected=intent._checkpoint
            )
        except Exception:
            raise ObservationPublicationError(output) from None
    else:
        # The append is the publication linearization point. An accepted cancel
        # gets here first, or a concurrent cancel waits and is refused afterward.
        with cancel._lock:
            if cancel.cancelled:
                raise ObservationInterrupted(output)
            cancel._publishing = True
            try:
                journal = intent._journal.append(
                    (observation,), authority=intent._authority, expected=intent._checkpoint
                )
            except Exception:
                raise ObservationPublicationError(output) from None
            else:
                cancel._published = True
            finally:
                cancel._publishing = False
    artifacts: tuple[ObservationArtifact, ...] = (
        ObservationArtifact(intent._plan.assertion_artifact_id, _sha(intent._assertion)),
        ObservationArtifact(intent._plan.input_artifact_id, _sha(intent._input)),
    )
    if output is not None:
        artifact_id = observation.artifact_id
        if artifact_id is None:
            raise ValidationError("observed output lacks its artifact ID")
        artifacts += (ObservationArtifact(artifact_id, _sha(output)),)
    retained = RetainedObservation(
        journal,
        intent._checkpoint,
        journal.checkpoint,
        observation,
        intent._adapter.key,
        intent._request_id,
        intent._assertion,
        intent._input,
        output,
        artifacts,
        intent._registry.limits,
        _key=_RETAINED_KEY,
    )
    with _ISSUED_LOCK:
        _ISSUED[id(retained)] = retained
    return retained


def run_observation(
    prepared: PreparedObservation,
    *,
    registry: ObservationRegistry,
    cancel: ObservationCancelToken | None = None,
) -> RetainedObservation:
    """Claim once, call one trusted synchronous adapter, then append immutably."""
    if type(prepared) is not PreparedObservation or type(registry) is not ObservationRegistry:
        raise ValidationError("observation execution requires prepared intent and registry")
    if (
        registry is not prepared._registry
        or registry.select(prepared._plan, prepared._authority) is not prepared._adapter
    ):
        raise ValidationError("observation registry changed after preparation")
    if cancel is not None and type(cancel) is not ObservationCancelToken:
        raise ValidationError("observation cancellation requires an exact token")
    prepared._claim()
    if cancel is not None:
        with cancel._lock:
            if cancel.cancelled:
                raise ObservationCancelled("observation cancelled before adapter entry")
    status = CaseObservationStatus.OBSERVED
    code = None
    raw: object = None
    try:
        raw = prepared._adapter.callback(prepared._input)
    except ObservationUnavailable:
        status, code = CaseObservationStatus.UNAVAILABLE, "adapter_unavailable"
    except Exception:
        status, code = CaseObservationStatus.ERROR, "adapter_error"
    output = None
    if status is CaseObservationStatus.OBSERVED:
        try:
            output = _output(raw, registry.limits, len(prepared._assertion) + len(prepared._input))
        except ValidationError:
            status, code = CaseObservationStatus.ERROR, "invalid_adapter_output"
    if cancel is not None and cancel.cancelled:
        raise ObservationInterrupted(output)
    observation = CaseObservation(
        plan_digest=prepared._plan.digest,
        request_id=prepared._request_id,
        observer_id=prepared._adapter.observer_id,
        status=status,
        input_sha256=prepared._plan.input_sha256,
        observed_sha256=_sha(output) if output is not None else None,
        artifact_id=(
            "observed-"
            + _sha(
                prepared._plan.digest.encode("ascii")
                + prepared._request_id.encode("ascii")
                + output
            )
        )
        if output is not None
        else None,
        error_code=code,
    )
    return _retained(prepared, observation, output, cancel)


def verify_observed_bytes(
    journal: CaseJournal,
    authority: CaseAuthority,
    retained: RetainedObservation,
    *,
    expected_plan_head: str,
    expected_observation_head: str,
    evaluator_id: str,
) -> CheckedObservation:
    """Rehash owned bytes and independently compute a scoped Stage A verdict."""
    if type(retained) is not RetainedObservation:
        raise ValidationError("verification requires retained observation bytes")
    with _ISSUED_LOCK:
        if _ISSUED.get(id(retained)) is not retained:
            raise ValidationError("retained observation was not issued by the runner")
    _hash(expected_plan_head, "expected observation plan head")
    _hash(expected_observation_head, "expected observation head")
    state = replay_case(journal, authority=authority, expected_head=expected_observation_head)
    if state.phase is not CasePhase.OBSERVED or len(journal.receipts) != 2:
        raise ValidationError("verification requires exactly one recorded observation")
    if (
        journal != retained.journal
        or retained.observation_checkpoint != journal.checkpoint
        or journal.receipts[0].digest != expected_plan_head
        or retained.plan_checkpoint != CaseCheckpoint(1, expected_plan_head)
        or retained.observation != journal.receipts[1].record
        or retained.request_id != retained.observation.request_id
    ):
        raise ValidationError("retained observation differs from pinned journal anchors")
    plan = journal.receipts[0].record
    observation = retained.observation
    if type(plan) is not CasePlan or type(observation) is not CaseObservation:
        raise ValidationError("retained case record types differ")
    if retained.adapter_key != (
        plan.test_id,
        plan.adapter_id,
        plan.adapter_version,
        observation.observer_id,
    ):
        raise ValidationError("retained adapter identity differs from plan")
    if type(retained.limits) is not ObservationLimits:
        raise ValidationError("retained observation limits differ from the profile")
    assertion = _snapshot(
        retained.assertion_bytes, retained.limits.assertion_bytes, "retained assertion"
    )
    source = _snapshot(retained.input_bytes, retained.limits.input_bytes, "retained test input")
    if _sha(assertion) != plan.assertion_sha256 or _sha(source) != plan.input_sha256:
        raise ValidationError("retained input bytes differ from plan commitments")
    if len(assertion) + len(source) > retained.limits.total_bytes:
        raise ValidationError("retained input exceeds total byte bound")
    artifacts: tuple[ObservationArtifact, ...] = (
        ObservationArtifact(plan.assertion_artifact_id, _sha(assertion)),
        ObservationArtifact(plan.input_artifact_id, _sha(source)),
    )
    output = None
    if observation.status is CaseObservationStatus.OBSERVED:
        output = _output(retained.observed_bytes, retained.limits, len(assertion) + len(source))
        if _sha(output) != observation.observed_sha256:
            raise ValidationError("retained output differs from observation commitment")
        artifact_id = observation.artifact_id
        if artifact_id is None:
            raise ValidationError("observed output lacks its artifact ID")
        artifacts += (ObservationArtifact(artifact_id, _sha(output)),)
        outcome = (
            CaseVerdictOutcome.SUPPORTED
            if _sha(output) == _sha(plan.expected_observation_text.encode("utf-8"))
            else CaseVerdictOutcome.REFUTED
        )
    else:
        if retained.observed_bytes is not None:
            raise ValidationError("failed observation cannot retain a successful output")
        outcome = CaseVerdictOutcome.INCONCLUSIVE
    if type(retained.artifact_inventory) is not tuple or retained.artifact_inventory != artifacts:
        raise ValidationError("retained artifact inventory is missing or mismatched")
    verdict = CaseVerdict(plan.digest, observation.digest, evaluator_id, outcome)
    evaluated = journal.append((verdict,), authority=authority, expected=journal.checkpoint)
    return CheckedObservation(
        evaluated,
        verdict,
        retained.plan_checkpoint,
        retained.observation_checkpoint,
        evaluated.checkpoint,
        assertion,
        source,
        output,
    )
