"""Offline selective receipt disclosure, verified without the full ledger."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from evidence_braid import (
    EvidenceEvent,
    LedgerIndex,
    LedgerMembershipBundle,
    LedgerProofIndex,
    LedgerQuery,
    Modality,
    Signal,
    build_ledger,
    verify_ledger_membership,
)


def main() -> None:
    base = datetime(2026, 9, 1, tzinfo=UTC)
    ledger = build_ledger(
        EvidenceEvent(
            event_id=str(position),
            claim="classification",
            source="offline-sensor",
            modality=Modality.SENSOR,
            signal=Signal.SUPPORT,
            confidence=0.8,
            observed_at=base + timedelta(seconds=position),
            ingested_at=base + timedelta(seconds=position),
            attributes={"sample": position},
        )
        for position in range(9)
    )
    index = LedgerProofIndex(LedgerIndex(ledger, expected_head=ledger.head_digest))
    # A real recipient must obtain this through a separately trusted channel.
    # Copying it out of the incoming proof only proves self-consistency.
    retained_commitment_digest = index.commitment.digest
    page = index.index.select(LedgerQuery(event_ids=("1", "4", "7"))).page()
    raw = index.prove_page(page).to_bytes()
    del index, ledger, page

    received = LedgerMembershipBundle.from_bytes(raw)
    rows = verify_ledger_membership(received, expected_commitment_digest=retained_commitment_digest)
    print(
        json.dumps(
            {
                "verified_sequences": [row.sequence for row in rows],
                "retained_commitment_digest": retained_commitment_digest,
                "proof_bytes": len(raw),
                "query_completeness_proven": False,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
