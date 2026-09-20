"""A controlled cache-bypass case; no provider, disk, network or shell I/O.

Run: ``python -m evidence_braid.examples.cache_bypass_case``.
The fixture proves only its in-memory A/B comparison, not a real incident.
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections.abc import Callable
from dataclasses import dataclass, field

from evidence_braid.case_observation import (
    ObservationAdapter,
    ObservationRegistry,
    ObservationUnavailable,
    prepare_observation,
    run_observation,
    verify_observed_bytes,
)
from evidence_braid.epistemic_case import (
    CaseActor,
    CaseActorKind,
    CaseAuthority,
    CaseGrant,
    CaseJournal,
    CasePlan,
    CaseRole,
    CaseVerdictOutcome,
)
from evidence_braid.errors import ValidationError
from evidence_braid.io import canonical_json
from evidence_braid.models import _is_xml_character

_MAX_DOCUMENT_BYTES = 4096
_MAX_NODES = 32
_MAX_DEPTH = 4
_MAX_TEXT = 128
ASSERTION = b"Fixture assertion: the cached report may be stale."
INCIDENT = canonical_json(
    {"incident": "stale-report", "requested_field": "revision"}, pretty=False
).encode("utf-8")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate fixture key")
        result[key] = value
    return result


def _parse_incident(raw: bytes) -> dict[str, str]:
    if type(raw) is not bytes or len(raw) > _MAX_DOCUMENT_BYTES:
        raise ValidationError("fixture incident exceeds its byte profile")
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
            if depth > _MAX_DEPTH:
                raise ValidationError("fixture incident nesting exceeds its profile")
        elif byte in (93, 125):
            depth -= 1
    try:
        decoded = raw.decode("utf-8", errors="strict")
        document = json.loads(
            decoded,
            object_pairs_hook=_pairs,
            parse_float=lambda _: (_ for _ in ()).throw(ValueError()),
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ValidationError("fixture incident is not strict JSON") from exc
    stack = [document]
    nodes = 0
    while stack:
        item = stack.pop()
        nodes += 1
        if nodes > _MAX_NODES:
            raise ValidationError("fixture incident node count exceeds its profile")
        if type(item) is dict:
            for key in item:
                if type(key) is not str or len(key) > _MAX_TEXT or not _is_xml_character(key):
                    raise ValidationError("fixture incident key exceeds its text profile")
            stack.extend(item.values())
        elif type(item) is list:
            stack.extend(item)
        elif type(item) is str:
            if len(item) > _MAX_TEXT or not _is_xml_character(item):
                raise ValidationError("fixture incident text exceeds its profile")
        elif type(item) not in (int, bool, type(None)):
            raise ValidationError("fixture incident scalar is unsupported")
    if (
        type(document) is not dict
        or set(document) != {"incident", "requested_field"}
        or document != {"incident": "stale-report", "requested_field": "revision"}
        or canonical_json(document, pretty=False).encode("utf-8") != raw
    ):
        raise ValidationError("fixture incident is not the canonical named test input")
    return document


@dataclass(slots=True)
class ReportEnvironment:
    cached_revision: str = "revision-A"
    source_revision: str | None = "revision-B"
    reads: list[bool] = field(default_factory=list)

    def read_report(self, *, bypass_cache: bool) -> str:
        self.reads.append(bypass_cache)
        if bypass_cache:
            if self.source_revision is None:
                raise ObservationUnavailable()
            return self.source_revision
        return self.cached_revision


def make_cache_bypass_adapter(environment: ReportEnvironment) -> Callable[[bytes], bytes]:
    """Closure receives only incident bytes; the expected answer is not passed in."""

    if type(environment) is not ReportEnvironment:
        raise ValidationError("fixture requires a trusted in-memory environment")

    def observe(raw: bytes) -> bytes:
        _parse_incident(raw)
        baseline = environment.read_report(bypass_cache=False)
        if baseline != "revision-A":
            raise ValidationError("fixture baseline differs")
        current = environment.read_report(bypass_cache=True)
        return current.encode("utf-8")

    return observe


@dataclass(frozen=True, slots=True)
class FixtureResult:
    outcome: CaseVerdictOutcome
    plan_head: str
    observation_head: str
    verdict_head: str
    observed_bytes: bytes | None
    observed_sha256: str | None
    reads: tuple[bool, ...]


def run_fixture(source_revision: str | None = "revision-B") -> FixtureResult:
    """Execute A/B, independently check retained bytes, and return pinned heads."""
    environment = ReportEnvironment(source_revision=source_revision)
    authority = CaseAuthority(
        "fixture-policy",
        (
            CaseActor("model", CaseActorKind.MODEL, (CaseGrant("fixture", CaseRole.PROPOSE),)),
            CaseActor("probe", CaseActorKind.TOOL, (CaseGrant("fixture", CaseRole.OBSERVE),)),
            CaseActor("judge", CaseActorKind.TOOL, (CaseGrant("fixture", CaseRole.EVALUATE),)),
        ),
    )
    plan = CasePlan(
        case_id="fixture-cache-case",
        workflow_id="fixture-workflow",
        claim_id="fixture-incident",
        scope="fixture",
        proposer_id="model",
        assertion_artifact_id="fixture-assertion",
        assertion_sha256=_sha(ASSERTION),
        hypothesis="The cache may be stale.",
        prediction="The cache bypass should return revision-B.",
        expected_observation_text="revision-B",
        input_artifact_id="fixture-incident-input",
        input_sha256=_sha(INCIDENT),
        prediction_sha256=_sha(b"revision-B"),
        test_id="cache-bypass",
        adapter_id="fixture-cache",
        adapter_version="1",
        comparator_profile="sha256-equality-v1",
        authority_digest=authority.digest,
    )
    journal = CaseJournal.empty(authority).append((plan,), authority=authority)
    registry = ObservationRegistry(
        (
            ObservationAdapter(
                "cache-bypass",
                "fixture-cache",
                "1",
                "probe",
                make_cache_bypass_adapter(environment),
            ),
        )
    )
    intent = prepare_observation(
        journal,
        authority,
        registry,
        ASSERTION,
        INCIDENT,
        expected_plan_head=journal.head_digest,
        request_id="fixture-request",
    )
    retained = run_observation(intent, registry=registry)
    result = verify_observed_bytes(
        retained.journal,
        authority,
        retained,
        expected_plan_head=journal.head_digest,
        expected_observation_head=retained.journal.head_digest,
        evaluator_id="judge",
    )
    if environment.reads != [False, True]:
        raise ValidationError("fixture did not compare cached and bypassed reads")
    if (
        _sha(retained.assertion_bytes) != plan.assertion_sha256
        or _sha(retained.input_bytes) != plan.input_sha256
    ):
        raise ValidationError("fixture retained inputs differ from plan")
    if (
        retained.observed_bytes is not None
        and _sha(retained.observed_bytes) != retained.observation.observed_sha256
    ):
        raise ValidationError("fixture retained output differs from observation")
    independent = (
        CaseVerdictOutcome.INCONCLUSIVE
        if retained.observed_bytes is None
        else CaseVerdictOutcome.SUPPORTED
        if _sha(retained.observed_bytes) == _sha(b"revision-B")
        else CaseVerdictOutcome.REFUTED
    )
    if result.verdict.outcome is not independent:
        raise ValidationError("fixture verdict differs from independent byte oracle")
    return FixtureResult(
        result.verdict.outcome,
        journal.head_digest,
        retained.journal.head_digest,
        result.journal.head_digest,
        retained.observed_bytes,
        retained.observation.observed_sha256,
        tuple(environment.reads),
    )


def main() -> int:
    if len(sys.argv) > 2 or (len(sys.argv) == 2 and sys.argv[1] not in ("B", "C", "unavailable")):
        print(
            "usage: python -m evidence_braid.examples.cache_bypass_case [B|C|unavailable]",
            file=sys.stderr,
        )
        return 2
    selected = sys.argv[1] if len(sys.argv) == 2 else "B"
    source = None if selected == "unavailable" else f"revision-{selected}"
    result = run_fixture(source)
    print(
        json.dumps(
            {
                "outcome": result.outcome.value,
                "plan_head": result.plan_head,
                "observation_head": result.observation_head,
                "verdict_head": result.verdict_head,
                "observed_sha256": result.observed_sha256,
                "observed_text": result.observed_bytes.decode("utf-8")
                if result.observed_bytes is not None
                else None,
                "read_sequence": list(result.reads),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
