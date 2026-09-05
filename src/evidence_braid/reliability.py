"""Opt-in source reliability updating from caller-supplied adjudications.

A reliability moves only when the caller supplies ground truth. Evidence fusion
cannot observe whether a source was right, and this module invents no proxy for
correctness: an :class:`~evidence_braid.models.Adjudication` is an input, not an
inference.

The rule is a fixed weighted average of the policy's declared reliability and
the observed correct rate, so a reviewer can reproduce any published number
with a calculator::

    observations = correct + incorrect
    posterior    = (prior_weight * declared + correct) / (prior_weight + observations)
    delta        = min(max(posterior - declared, -max_adjustment), max_adjustment)
    applied      = declared + delta

Equivalently, ``posterior`` is ``declared`` and the observed rate
``correct / observations`` averaged with weights ``prior_weight`` and
``observations``: after exactly ``prior_weight`` adjudications the weight has
moved halfway from the declared value to the observed rate.

Three properties follow directly and are what make the rule safe to ship under
a determinism contract:

* only counts enter, so the order adjudications arrive in cannot change a
  result, and neither can the order they are stored in;
* ``posterior`` lies in ``[0, 1]`` because ``correct <= observations`` and
  ``declared <= 1``, and ``applied`` lies between ``declared`` and
  ``posterior``, so a weight can never leave the range a policy could declare;
* a source with no adjudications keeps its declared reliability exactly and
  produces no record at all.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from .errors import ValidationError
from .models import (
    Adjudication,
    EvidenceEvent,
    Policy,
    Verdict,
    _canonical_text_tuple,
    _number,
    _stable_float,
    _text,
)


@dataclass(frozen=True, slots=True)
class ReliabilityAdjustment:
    """One source's declared weight, its adjudications, and the applied weight."""

    source: str
    declared_reliability: float
    posterior_reliability: float
    applied_reliability: float
    correct_event_ids: tuple[str, ...]
    incorrect_event_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "source", _text(self.source, "adjustment.source"))
        for field_name in (
            "declared_reliability",
            "posterior_reliability",
            "applied_reliability",
        ):
            object.__setattr__(
                self,
                field_name,
                _number(getattr(self, field_name), f"adjustment.{field_name}", 0.0, 1.0),
            )
        correct = _canonical_text_tuple(self.correct_event_ids, "adjustment.correct_event_ids")
        incorrect = _canonical_text_tuple(
            self.incorrect_event_ids, "adjustment.incorrect_event_ids"
        )
        if set(correct) & set(incorrect):
            raise ValidationError("adjustment event IDs must not be both correct and incorrect")
        if not correct and not incorrect:
            raise ValidationError("adjustment must record at least one adjudication")
        object.__setattr__(self, "correct_event_ids", correct)
        object.__setattr__(self, "incorrect_event_ids", incorrect)


def validate_adjudication_set(
    policy: Policy,
    events: Sequence[EvidenceEvent],
    adjudications: Iterable[Adjudication],
) -> list[Adjudication]:
    """Validate stream-wide adjudication invariants shared by evaluation and replay.

    Failures are reported over sorted identities so the message a caller sees
    does not depend on the order the adjudications were supplied in.
    """
    if not isinstance(policy, Policy):
        raise ValidationError("policy must be a Policy instance")
    items = list(adjudications)
    for index, item in enumerate(items):
        if not isinstance(item, Adjudication):
            raise ValidationError(f"adjudications[{index}] must be an Adjudication instance")
    if items and policy.reliability_updates is None:
        raise ValidationError(
            "adjudications were supplied but the policy does not configure reliability_updates"
        )
    counts = Counter(item.event_id for item in items)
    duplicates = sorted(event_id for event_id, count in counts.items() if count > 1)
    if duplicates:
        raise ValidationError(f"duplicate adjudicated event_id(s): {', '.join(duplicates)}")
    # A weight may only move for a source the policy names. An adjudication for
    # an undeclared source would otherwise be a typo that silently adjusts
    # nothing, or that invents a weight the policy never stated.
    unknown = sorted({item.source for item in items} - set(policy.sources))
    if unknown:
        raise ValidationError(
            f"adjudicated source(s) missing from policy.sources: {', '.join(unknown)}"
        )
    events_by_id = {event.event_id: event for event in events}
    mismatched: list[str] = []
    premature: list[str] = []
    for item in items:
        # Adjudications outlive the evidence window, so an event that is absent
        # here is normal and carries nothing to cross-check.
        event = events_by_id.get(item.event_id)
        if event is None:
            continue
        if event.source != item.source:
            mismatched.append(item.event_id)
        elif item.adjudicated_at < event.ingested_at:
            premature.append(item.event_id)
    if mismatched:
        raise ValidationError(
            "adjudication(s) naming a source the event did not come from: "
            f"{', '.join(sorted(mismatched))}"
        )
    if premature:
        raise ValidationError(
            "adjudication(s) dated before the observation they judge was ingested: "
            f"{', '.join(sorted(premature))}"
        )
    return items


def adjust_reliabilities(
    policy: Policy, adjudications: Iterable[Adjudication]
) -> tuple[ReliabilityAdjustment, ...]:
    """Apply the documented closed form to every adjudicated source.

    Returns one record per source with at least one adjudication, ordered by
    source name. Sources without adjudications are absent: they keep the
    reliability the policy declares.
    """
    rule = policy.reliability_updates
    if rule is None:
        return ()
    verdicts: dict[str, dict[Verdict, list[str]]] = {}
    for item in adjudications:
        by_verdict = verdicts.setdefault(item.source, {Verdict.CORRECT: [], Verdict.INCORRECT: []})
        by_verdict[item.verdict].append(item.event_id)
    adjustments: list[ReliabilityAdjustment] = []
    for source in sorted(verdicts):
        correct = tuple(sorted(verdicts[source][Verdict.CORRECT]))
        incorrect = tuple(sorted(verdicts[source][Verdict.INCORRECT]))
        declared = _stable_float(policy.reliability_for(source))
        observations = len(correct) + len(incorrect)
        posterior = _stable_float(
            (rule.prior_weight * declared + len(correct)) / (rule.prior_weight + observations)
        )
        delta = min(max(posterior - declared, -rule.max_adjustment), rule.max_adjustment)
        adjustments.append(
            ReliabilityAdjustment(
                source=source,
                declared_reliability=declared,
                posterior_reliability=posterior,
                applied_reliability=_stable_float(declared + delta),
                correct_event_ids=correct,
                incorrect_event_ids=incorrect,
            )
        )
    return tuple(adjustments)
