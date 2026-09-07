"""Explain how one policy differs from another.

A textual diff of two policy files answers what characters changed. It does not
answer the question an operator actually has before adopting a new version:
which decisions can move, and in which direction.

Every field here is classified by what it does to the machinery, not merely by
whether it changed. Raising a threshold tightens the gate it belongs to;
lengthening a half-life loosens every gate, because evidence keeps more of its
weight. A change that cannot be ordered -- turning reliability updating on, for
instance, whose effect depends entirely on adjudications the caller supplies --
says so instead of guessing a direction.

Direction is a statement about one gate, never about the final outcome. A claim
whose contradiction gate closes does not thereby escalate; it becomes a review.
For the empirical answer, :func:`decision_impact` evaluates both policies over
the same evidence and reports the claims whose outcome actually moved.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .engine import evaluate
from .errors import ValidationError
from .migrations import CURRENT_POLICY_SCHEMA_VERSION
from .models import Adjudication, EvidenceEvent, Policy

# What a change does to the gate it belongs to.
TIGHTENS = "tightens"
LOOSENS = "loosens"
STRUCTURAL = "structural"
UNORDERED = "unordered"

DIRECTIONS = (TIGHTENS, LOOSENS, STRUCTURAL, UNORDERED)


@dataclass(frozen=True, slots=True)
class PolicyChange:
    """One difference, with what it does rather than only that it happened."""

    path: str
    before: Any
    after: Any
    direction: str
    effect: str

    def __post_init__(self) -> None:
        if not isinstance(self.path, str) or not self.path:
            raise ValidationError("change path must be a non-empty string")
        if self.direction not in DIRECTIONS:
            raise ValidationError(f"change direction must be one of {', '.join(DIRECTIONS)}")
        if not isinstance(self.effect, str) or not self.effect:
            raise ValidationError("change effect must be a non-empty string")

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "before": self.before,
            "after": self.after,
            "direction": self.direction,
            "effect": self.effect,
        }


@dataclass(frozen=True, slots=True)
class PolicyComparison:
    """Every difference between two policies, ordered by path."""

    changes: tuple[PolicyChange, ...]

    @property
    def identical(self) -> bool:
        """Whether the two policies decide identically on every input."""

        return not self.changes

    def counts(self) -> dict[str, int]:
        """How many changes fall in each direction."""

        tally = dict.fromkeys(DIRECTIONS, 0)
        for change in self.changes:
            tally[change.direction] += 1
        return tally

    def to_dict(self) -> dict[str, Any]:
        return {
            "identical": self.identical,
            "change_count": len(self.changes),
            "counts": self.counts(),
            "changes": [change.to_dict() for change in self.changes],
        }


def _number(value: float) -> float:
    return float(value)


def _threshold_change(
    path: str, before: float, after: float, *, higher_tightens: bool, effect_noun: str
) -> PolicyChange | None:
    """Compare one numeric control whose direction of strictness is known."""

    if before == after:
        return None
    higher = after > before
    tightens = higher == higher_tightens
    direction = TIGHTENS if tightens else LOOSENS
    movement = "raises" if higher else "lowers"
    consequence = "harder" if tightens else "easier"
    moved = f"{movement} {effect_noun} from {before} to {after}"
    return PolicyChange(
        path=path,
        before=_number(before),
        after=_number(after),
        direction=direction,
        effect=f"{moved}, making it {consequence} to pass",
    )


def _compare_decay(before: Policy, after: Policy) -> list[PolicyChange]:
    changes: list[PolicyChange] = []
    change = _threshold_change(
        "decay.default_half_life_seconds",
        before.decay.default_half_life_seconds,
        after.decay.default_half_life_seconds,
        higher_tightens=False,
        effect_noun="the default half-life",
    )
    if change is not None:
        changes.append(change)
    change = _threshold_change(
        "decay.max_future_skew_seconds",
        before.decay.max_future_skew_seconds,
        after.decay.max_future_skew_seconds,
        higher_tightens=False,
        effect_noun="the tolerated clock skew",
    )
    if change is not None:
        changes.append(change)
    old_map = {str(key): value for key, value in before.decay.modality_half_life_seconds.items()}
    new_map = {str(key): value for key, value in after.decay.modality_half_life_seconds.items()}
    for modality in sorted(set(old_map) | set(new_map)):
        path = f"decay.modality_half_life_seconds.{modality}"
        if modality not in old_map:
            changes.append(
                PolicyChange(
                    path=path,
                    before=None,
                    after=_number(new_map[modality]),
                    direction=TIGHTENS
                    if new_map[modality] < before.decay.default_half_life_seconds
                    else LOOSENS,
                    effect=(
                        f"overrides the default half-life for {modality} evidence with "
                        f"{new_map[modality]}"
                    ),
                )
            )
            continue
        if modality not in new_map:
            changes.append(
                PolicyChange(
                    path=path,
                    before=_number(old_map[modality]),
                    after=None,
                    direction=TIGHTENS
                    if old_map[modality] > after.decay.default_half_life_seconds
                    else LOOSENS,
                    effect=(
                        f"drops the {modality} half-life override, returning it to the default "
                        f"{after.decay.default_half_life_seconds}"
                    ),
                )
            )
            continue
        change = _threshold_change(
            path,
            old_map[modality],
            new_map[modality],
            higher_tightens=False,
            effect_noun=f"the {modality} half-life",
        )
        if change is not None:
            changes.append(change)
    return changes


def _compare_sources(before: Policy, after: Policy) -> list[PolicyChange]:
    changes: list[PolicyChange] = []
    change = _threshold_change(
        "default_source_reliability",
        before.default_source_reliability,
        after.default_source_reliability,
        higher_tightens=False,
        effect_noun="the reliability of undeclared sources",
    )
    if change is not None:
        changes.append(change)
    for name in sorted(set(before.sources) | set(after.sources)):
        path = f"sources.{name}.reliability"
        if name not in before.sources:
            value = after.sources[name].reliability
            changes.append(
                PolicyChange(
                    path=f"sources.{name}",
                    before=None,
                    after=_number(value),
                    direction=STRUCTURAL,
                    effect=(
                        f"declares source {name!r} with reliability {value}, replacing the default "
                        f"{before.default_source_reliability} it was scored with"
                    ),
                )
            )
            continue
        if name not in after.sources:
            value = before.sources[name].reliability
            changes.append(
                PolicyChange(
                    path=f"sources.{name}",
                    before=_number(value),
                    after=None,
                    direction=STRUCTURAL,
                    effect=(
                        f"removes source {name!r}, so its evidence now scores at the default "
                        f"reliability {after.default_source_reliability}"
                    ),
                )
            )
            continue
        change = _threshold_change(
            path,
            before.sources[name].reliability,
            after.sources[name].reliability,
            higher_tightens=False,
            effect_noun=f"the reliability of {name!r}",
        )
        if change is not None:
            changes.append(change)
    return changes


_CLAIM_CONTROLS: tuple[tuple[str, bool, str], ...] = (
    ("support_threshold", True, "the support threshold"),
    ("contradiction_threshold", True, "the contradiction threshold"),
    ("min_margin", True, "the required margin"),
    ("quorum", True, "the required number of independent groups"),
    ("min_sources", True, "the required number of distinct sources"),
    ("min_modalities", True, "the required number of distinct modalities"),
    ("min_evidence_confidence", True, "the confidence an event needs to qualify"),
)


def _compare_claims(before: Policy, after: Policy) -> list[PolicyChange]:
    changes: list[PolicyChange] = []
    for claim in sorted(set(before.claims) | set(after.claims)):
        if claim not in before.claims:
            changes.append(
                PolicyChange(
                    path=f"claims.{claim}",
                    before=None,
                    after=claim,
                    direction=STRUCTURAL,
                    effect=f"adds claim {claim!r}, which was not evaluated before",
                )
            )
            continue
        if claim not in after.claims:
            changes.append(
                PolicyChange(
                    path=f"claims.{claim}",
                    before=claim,
                    after=None,
                    direction=STRUCTURAL,
                    effect=f"removes claim {claim!r}, which is no longer evaluated",
                )
            )
            continue
        old_rule = before.claims[claim]
        new_rule = after.claims[claim]
        for field, higher_tightens, noun in _CLAIM_CONTROLS:
            change = _threshold_change(
                f"claims.{claim}.{field}",
                getattr(old_rule, field),
                getattr(new_rule, field),
                higher_tightens=higher_tightens,
                effect_noun=noun,
            )
            if change is not None:
                changes.append(change)
        old_required = set(old_rule.required_modalities)
        new_required = set(new_rule.required_modalities)
        for modality in sorted(new_required - old_required):
            changes.append(
                PolicyChange(
                    path=f"claims.{claim}.required_modalities",
                    before=sorted(old_required),
                    after=sorted(new_required),
                    direction=TIGHTENS,
                    effect=(
                        f"requires {modality} evidence, so a signal without it no longer passes "
                        f"its independence gate however many other modalities corroborate it"
                    ),
                )
            )
        for modality in sorted(old_required - new_required):
            changes.append(
                PolicyChange(
                    path=f"claims.{claim}.required_modalities",
                    before=sorted(old_required),
                    after=sorted(new_required),
                    direction=LOOSENS,
                    effect=f"no longer requires {modality} evidence",
                )
            )
    return changes


def _compare_reliability_updates(before: Policy, after: Policy) -> list[PolicyChange]:
    old_updates = before.reliability_updates
    new_updates = after.reliability_updates
    if old_updates is None and new_updates is None:
        return []
    if old_updates is None:
        return [
            PolicyChange(
                path="reliability_updates",
                before=None,
                after={
                    "prior_weight": _number(new_updates.prior_weight),
                    "max_adjustment": _number(new_updates.max_adjustment),
                }
                if new_updates is not None
                else None,
                direction=UNORDERED,
                effect=(
                    "starts maintaining source reliability from adjudications; the direction "
                    "depends entirely on the ground truth the caller supplies"
                ),
            )
        ]
    if new_updates is None:
        return [
            PolicyChange(
                path="reliability_updates",
                before={
                    "prior_weight": _number(old_updates.prior_weight),
                    "max_adjustment": _number(old_updates.max_adjustment),
                },
                after=None,
                direction=UNORDERED,
                effect=(
                    "stops maintaining source reliability, so every source keeps the reliability "
                    "the policy declares and supplying adjudications becomes an error"
                ),
            )
        ]
    changes: list[PolicyChange] = []
    change = _threshold_change(
        "reliability_updates.prior_weight",
        old_updates.prior_weight,
        new_updates.prior_weight,
        higher_tightens=True,
        effect_noun="the weight of the declared reliability",
    )
    if change is not None:
        changes.append(change)
    change = _threshold_change(
        "reliability_updates.max_adjustment",
        old_updates.max_adjustment,
        new_updates.max_adjustment,
        higher_tightens=False,
        effect_noun="how far a reliability may move",
    )
    if change is not None:
        changes.append(change)
    return changes


def compare_policies(before: Policy, after: Policy) -> PolicyComparison:
    """Report every difference between two policies and what each one does.

    Both policies are already at the current schema, because loading upgrades
    them, so a comparison is never confused by a field one version simply did
    not have: a schema 1 document arrives here with the defaults its upgrade
    wrote down explicitly.
    """

    for name, value in (("before", before), ("after", after)):
        if not isinstance(value, Policy):
            raise ValidationError(f"{name} must be a Policy")
    changes: list[PolicyChange] = []
    if before.policy_id != after.policy_id:
        changes.append(
            PolicyChange(
                path="policy_id",
                before=before.policy_id,
                after=after.policy_id,
                direction=STRUCTURAL,
                effect=(
                    f"renames the policy from {before.policy_id!r} to {after.policy_id!r}; "
                    f"results record this identifier, so stored decisions will not match by name"
                ),
            )
        )
    if before.source_schema_version != after.source_schema_version:
        changes.append(
            PolicyChange(
                path="schema_version",
                before=before.source_schema_version,
                after=after.source_schema_version,
                direction=STRUCTURAL,
                effect=(
                    f"the documents declare different schema versions; both were read as schema "
                    f"{CURRENT_POLICY_SCHEMA_VERSION}, so this alone moves no decision"
                ),
            )
        )
    changes.extend(_compare_sources(before, after))
    changes.extend(_compare_decay(before, after))
    changes.extend(_compare_claims(before, after))
    changes.extend(_compare_reliability_updates(before, after))
    changes.sort(key=lambda change: (change.path, change.effect))
    return PolicyComparison(changes=tuple(changes))


@dataclass(frozen=True, slots=True)
class ClaimOutcomeChange:
    """One claim whose outcome moved between two policies."""

    claim: str
    before: str
    after: str
    before_reason: str
    after_reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim": self.claim,
            "before": self.before,
            "after": self.after,
            "before_reason": self.before_reason,
            "after_reason": self.after_reason,
        }


@dataclass(frozen=True, slots=True)
class DecisionImpact:
    """What the two policies actually decide on one body of evidence."""

    evaluated_at: str
    claims_compared: int
    changes: tuple[ClaimOutcomeChange, ...]
    before_digest: str
    after_digest: str

    @property
    def identical(self) -> bool:
        return self.before_digest == self.after_digest

    def to_dict(self) -> dict[str, Any]:
        return {
            "evaluated_at": self.evaluated_at,
            "identical": self.identical,
            "claims_compared": self.claims_compared,
            "changed_count": len(self.changes),
            "changes": [change.to_dict() for change in self.changes],
            "before_digest": self.before_digest,
            "after_digest": self.after_digest,
        }


def decision_impact(
    before: Policy,
    after: Policy,
    events: Iterable[EvidenceEvent],
    as_of: datetime,
    *,
    adjudications: Sequence[Adjudication] = (),
) -> DecisionImpact:
    """Evaluate both policies over the same evidence and report what moved.

    A field-level comparison says which gates changed; this says which claims
    that actually reached. The two answer different questions and neither
    replaces the other: a tightened threshold that no claim was near moves
    nothing here, and an unordered change can move a great deal.

    Both runs see the identical events at the identical instant, so any
    difference is attributable to the policies alone.
    """

    materialized = tuple(events)
    before_result = evaluate(before, materialized, as_of, adjudications=adjudications)
    after_result = evaluate(after, materialized, as_of, adjudications=adjudications)
    before_rows = {row["claim"]: row for row in before_result.to_dict()["decisions"]}
    after_rows = {row["claim"]: row for row in after_result.to_dict()["decisions"]}
    changes: list[ClaimOutcomeChange] = []
    for claim in sorted(set(before_rows) | set(after_rows)):
        old_row: Mapping[str, Any] | None = before_rows.get(claim)
        new_row: Mapping[str, Any] | None = after_rows.get(claim)
        old_outcome = str(old_row["outcome"]) if old_row is not None else "not evaluated"
        new_outcome = str(new_row["outcome"]) if new_row is not None else "not evaluated"
        if old_outcome == new_outcome:
            continue
        changes.append(
            ClaimOutcomeChange(
                claim=claim,
                before=old_outcome,
                after=new_outcome,
                before_reason=str(old_row["reason"]) if old_row is not None else "claim absent",
                after_reason=str(new_row["reason"]) if new_row is not None else "claim absent",
            )
        )
    return DecisionImpact(
        evaluated_at=before_result.to_dict()["evaluated_at"],
        claims_compared=len(set(before_rows) | set(after_rows)),
        changes=tuple(changes),
        before_digest=before_result.digest,
        after_digest=after_result.digest,
    )


__all__ = [
    "DIRECTIONS",
    "LOOSENS",
    "STRUCTURAL",
    "TIGHTENS",
    "UNORDERED",
    "ClaimOutcomeChange",
    "DecisionImpact",
    "PolicyChange",
    "PolicyComparison",
    "compare_policies",
    "decision_impact",
]
