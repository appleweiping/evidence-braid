"""Offline prefix consistency using two independently retained commitments."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from evidence_braid import (
    EvidenceEvent,
    LedgerConsistencyProof,
    LedgerIndex,
    LedgerProofIndex,
    Modality,
    Signal,
    build_ledger,
    prove_ledger_consistency,
    verify_ledger_consistency,
)


def main() -> None:
    base = datetime(2026, 9, 1, tzinfo=UTC)
    events = [
        EvidenceEvent(
            event_id=str(i),
            claim="claim",
            source="source",
            modality=Modality.TEXT,
            signal=Signal.SUPPORT,
            confidence=0.5,
            observed_at=base + timedelta(seconds=i),
            ingested_at=base + timedelta(seconds=i),
        )
        for i in range(7)
    ]
    older = build_ledger(events[:3])
    old = LedgerProofIndex(LedgerIndex(older, expected_head=older.head_digest)).commitment
    newer = build_ledger(events)
    new = LedgerProofIndex(LedgerIndex(newer, expected_head=newer.head_digest))
    # Establish both digests separately from the incoming proof, through channels
    # trusted by the recipient. The library cannot determine where they came from.
    retained_old_digest, retained_new_digest = old.digest, new.commitment.digest
    raw = prove_ledger_consistency(new, old).to_bytes()
    del old, new, older, newer, events

    proof = LedgerConsistencyProof.from_bytes(raw)
    verify_ledger_consistency(
        proof,
        expected_old_commitment_digest=retained_old_digest,
        expected_new_commitment_digest=retained_new_digest,
    )
    print(
        json.dumps(
            {
                "old_entries": proof.old_commitment.entry_count,
                "new_entries": proof.new_commitment.entry_count,
                "path_hashes": len(proof.path),
                "proof_bytes": len(raw),
                "hidden_chain_links_revalidated": False,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
