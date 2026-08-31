"""Correlation-aware evidence collapsing."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from .decay import WeightedEvent
from .errors import ValidationError
from .models import Signal, _enum, _stable_float, _text


@dataclass(frozen=True, slots=True)
class CorrelationSelection:
    """The strongest event for one signal in one independent group."""

    group_id: str
    signal: Signal
    representative: WeightedEvent
    suppressed: tuple[WeightedEvent, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "group_id", _text(self.group_id, "selection.group_id"))
        object.__setattr__(self, "signal", _enum(self.signal, Signal, "selection.signal"))
        if not isinstance(self.representative, WeightedEvent):
            raise ValidationError("selection.representative must be a WeightedEvent instance")
        if isinstance(self.suppressed, str | bytes) or not isinstance(self.suppressed, Sequence):
            raise ValidationError(
                "selection.suppressed must be a sequence of WeightedEvent objects"
            )
        suppressed = tuple(self.suppressed)
        for index, item in enumerate(suppressed):
            if not isinstance(item, WeightedEvent):
                raise ValidationError(
                    f"selection.suppressed[{index}] must be a WeightedEvent instance"
                )
        suppressed = tuple(sorted(suppressed, key=lambda item: item.event.event_id))
        all_events = (self.representative, *suppressed)
        if any(item.event.signal is not self.signal for item in all_events):
            raise ValidationError("selection events must have the selection signal")
        if any(correlation_key(item) != self.group_id for item in all_events):
            raise ValidationError("selection events must have the selection correlation group")
        event_ids = [item.event.event_id for item in all_events]
        if len(set(event_ids)) != len(event_ids):
            raise ValidationError("selection contains duplicate event IDs")
        object.__setattr__(self, "suppressed", suppressed)


def correlation_key(weighted: WeightedEvent) -> str:
    """Give ungrouped observations independent identities."""
    explicit = weighted.event.correlation_group
    return f"group:{explicit}" if explicit is not None else f"event:{weighted.event.event_id}"


def collapse_correlated(events: Iterable[WeightedEvent]) -> tuple[CorrelationSelection, ...]:
    """Keep at most one observation per correlation group and signal.

    The strongest effective confidence wins. Equal values are resolved by
    event ID, making the result independent of input order.
    """
    buckets: dict[tuple[str, Signal], list[WeightedEvent]] = {}
    for weighted in events:
        key = (correlation_key(weighted), weighted.event.signal)
        buckets.setdefault(key, []).append(weighted)

    selections: list[CorrelationSelection] = []
    for (group_id, signal), candidates in buckets.items():
        ranked = sorted(
            candidates,
            key=lambda item: (
                -_stable_float(item.effective_confidence),
                item.event.event_id,
            ),
        )
        selections.append(
            CorrelationSelection(
                group_id=group_id,
                signal=signal,
                representative=ranked[0],
                suppressed=tuple(sorted(ranked[1:], key=lambda item: item.event.event_id)),
            )
        )
    return tuple(sorted(selections, key=lambda item: (item.group_id, item.signal.value)))
