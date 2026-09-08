"""Generate actual receipt proofs in Python and verify only detached bytes in Node."""

from __future__ import annotations

import json
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from importlib.resources import files
from pathlib import Path

from evidence_braid import (
    EvidenceEvent,
    LedgerIndex,
    LedgerProofIndex,
    Modality,
    Signal,
    build_ledger,
    prove_ledger_consistency,
)


def main() -> None:
    node = shutil.which("node")
    if node is None:
        raise SystemExit("This optional offline example requires Node.js 22 or later.")
    packaged = files("evidence_braid").joinpath("verification/ledger-consistency.mjs")
    verifier = (
        Path(str(packaged))
        if packaged.is_file()
        else Path(__file__).resolve().parents[1] / "verification" / "ledger-consistency.mjs"
    )
    base = datetime(2026, 9, 1, tzinfo=UTC)
    ledger = build_ledger(
        EvidenceEvent(
            event_id=str(i),
            claim="offline",
            source="sensor",
            modality=Modality.SENSOR,
            signal=Signal.SUPPORT,
            confidence=0.5,
            observed_at=base + timedelta(seconds=i),
            ingested_at=base + timedelta(seconds=i),
        )
        for i in range(7)
    )
    current = LedgerProofIndex(LedgerIndex(ledger, expected_head=ledger.head_digest))
    older = LedgerProofIndex(
        LedgerIndex(ledger, expected_head=ledger.entries[2].digest, prefix_count=3)
    )
    anchors = {
        "expectedOldCommitmentDigest": older.commitment.digest,
        "expectedNewCommitmentDigest": current.commitment.digest,
    }
    raw = prove_ledger_consistency(current, older.commitment).to_bytes()
    del ledger, current, older
    script = f"""
import {{verifyLedgerConsistency}} from {json.dumps(verifier.as_uri())};
let data = '';
for await (const chunk of process.stdin) data += chunk;
const input = JSON.parse(data);
const verified = verifyLedgerConsistency(Buffer.from(input.proof, 'utf8'), input.anchors);
process.stdout.write(JSON.stringify(verified));
"""
    checked = subprocess.run(
        [node, "--input-type=module", "-e", script],
        input=json.dumps({"proof": raw.decode(), "anchors": anchors}),
        encoding="utf-8",
        capture_output=True,
        check=True,
        timeout=60,
    )
    result = json.loads(checked.stdout)
    assert result["oldEntryCount"] == 3 and result["newEntryCount"] == 7
    assert result["oldCommitmentDigest"] == anchors["expectedOldCommitmentDigest"]
    assert result["newCommitmentDigest"] == anchors["expectedNewCommitmentDigest"]
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
