"""Run an isolated durable-store round trip and compare the original decision."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from evidence_braid import EvidenceEvent, SQLiteLedger, evaluate, load_ledger, write_ledger
from evidence_braid.io import load_events, load_policy
from evidence_braid.models import parse_timestamp


def main() -> None:
    examples = Path(__file__).parent
    events = load_events(examples / "events.jsonl")
    policy = load_policy(examples / "policy.json")
    instant = parse_timestamp("2026-08-31T12:00:00Z", "example")
    with TemporaryDirectory(prefix="evidence-braid-") as directory:
        root = Path(directory)
        committed = SQLiteLedger(root / "events.db").append(events)
        reopened = SQLiteLedger(root / "events.db", create=False).snapshot()
        write_ledger(root / "receipt.json", reopened)
        imported = SQLiteLedger(root / "copy.db").import_snapshot(
            load_ledger(root / "receipt.json")
        )
        restored = [EvidenceEvent.from_dict(entry.to_dict()["event"]) for entry in imported.entries]
        assert committed == reopened == imported
        assert evaluate(policy, restored, instant) == evaluate(policy, events, instant)
        print(
            json.dumps(
                {
                    "entry_count": len(imported.entries),
                    "head_digest": imported.head_digest,
                    "reopened": True,
                    "evaluation_unchanged": True,
                },
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    main()
