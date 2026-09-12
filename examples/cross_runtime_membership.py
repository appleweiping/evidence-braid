"""Verify detached complete receipts in Node without transferring a Python ledger."""

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
    LedgerMembershipBundle,
    LedgerProofIndex,
    Modality,
    Signal,
    build_ledger,
)


def main() -> None:
    node = shutil.which("node")
    if node is None:
        raise SystemExit("This optional offline example requires Node.js 22 or later.")
    packaged = files("evidence_braid").joinpath("verification/ledger-membership.mjs")
    verifier = (
        Path(str(packaged))
        if packaged.is_file()
        else Path(__file__).resolve().parents[1] / "verification" / "ledger-membership.mjs"
    )
    base = datetime(2026, 9, 1, tzinfo=UTC)
    ledger = build_ledger(
        EvidenceEvent(
            event_id=f"observation-{i}",
            claim="跨语言",
            source="sensor",
            modality=Modality.SENSOR,
            signal=Signal.SUPPORT,
            confidence=0.5,
            observed_at=base + timedelta(seconds=i),
            ingested_at=base + timedelta(seconds=i),
            attributes={"integer": 9007199254740993, "negative_zero": -0.0, "𐀀": True},
        )
        for i in range(5)
    )
    index = LedgerProofIndex(LedgerIndex(ledger, expected_head=ledger.head_digest))
    anchor = index.commitment.digest
    wire = LedgerMembershipBundle(
        index.commitment, tuple(index.prove(position).members[0] for position in (0, 2, 4))
    ).to_bytes()
    del ledger, index
    script = f"""
import {{verifyLedgerMembership}} from {json.dumps(verifier.as_uri())};
let input = '';
for await (const chunk of process.stdin) input += chunk;
const data = JSON.parse(input);
const result = verifyLedgerMembership(Buffer.from(data.wire, 'utf8'), {{
  expectedCommitmentDigest: data.anchor,
}});
process.stdout.write(JSON.stringify(result));
"""
    result = subprocess.run(
        [node, "--input-type=module", "-e", script],
        input=json.dumps({"wire": wire.decode(), "anchor": anchor}),
        encoding="utf-8",
        capture_output=True,
        check=True,
        timeout=60,
    )
    assert result.stderr == ""
    verified = json.loads(result.stdout)
    assert verified["commitmentDigest"] == anchor and verified["entryCount"] == 5
    assert [member["sequence"] for member in verified["members"]] == [0, 2, 4]
    assert all("event" not in member for member in verified["members"])
    print(json.dumps(verified, indent=2))


if __name__ == "__main__":
    main()
