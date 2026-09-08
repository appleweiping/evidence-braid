"""Retain and reopen a filtered historical prefix after a backdated append."""

from __future__ import annotations

import json
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from evidence_braid import EvidenceEvent, LedgerIndex, LedgerQuery, Modality, Signal, SQLiteLedger


def main() -> None:
    start = datetime(2026, 9, 1, tzinfo=UTC)
    with tempfile.TemporaryDirectory(prefix="evidence-braid-query-") as directory:
        store = SQLiteLedger(Path(directory) / "events.sqlite")
        original = store.append(
            [
                EvidenceEvent(
                    f"event-{number}",
                    "door-open",
                    Modality.SENSOR,
                    "door-switch",
                    Signal.SUPPORT,
                    0.9,
                    start,
                    start + timedelta(seconds=number),
                )
                for number in range(5)
            ]
        )
        query = LedgerQuery(sources=("door-switch",))
        selected = LedgerIndex(original, expected_head=original.head_digest).select(query)
        first = selected.page(limit=2)
        store.append(
            [
                EvidenceEvent(
                    "late-arrival",
                    "door-open",
                    Modality.SENSOR,
                    "door-switch",
                    Signal.CONTRADICT,
                    0.8,
                    start,
                    start,
                )
            ]
        )
        reopened = SQLiteLedger(store.path, create=False).snapshot()
        restored = LedgerIndex(reopened, expected_head=original.head_digest, prefix_count=5).select(
            query
        )
        rest = restored.page(cursor=first.next_cursor)
        assert [item.event_id for item in (*first.entries, *rest.entries)] == [
            f"event-{n}" for n in range(5)
        ]
        print(
            json.dumps(
                {
                    "snapshot_entries": rest.snapshot_entries,
                    "latest_entries": len(reopened.entries),
                    "first": first.to_dict(),
                    "rest": rest.to_dict(),
                }
            )
        )


if __name__ == "__main__":
    main()
