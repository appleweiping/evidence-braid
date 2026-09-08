"""Real independent-runtime conformance using only detached proof bytes/anchors."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from evidence_braid import (
    EvidenceEvent,
    EvidenceLedger,
    LedgerEntry,
    LedgerIndex,
    LedgerProofIndex,
    Modality,
    Signal,
    build_ledger,
    prove_ledger_consistency,
)

VERIFIER = Path(__file__).resolve().parents[1] / "verification" / "ledger-consistency.mjs"


def node_binary():
    node = shutil.which("node")
    if node is None and os.environ.get("EVIDENCE_REQUIRE_NODE") == "1":
        pytest.fail("independent verifier CI requires Node.js")
    if node is None:
        pytest.skip("Node.js is optional for Python-only installations")
    return node


def invoke(rows):
    script = f"""
import {{ verifyLedgerConsistency }} from {json.dumps(VERIFIER.as_uri())};
let input = '';
for await (const chunk of process.stdin) input += chunk;
const answers = JSON.parse(input).map(row => {{
  try {{
    const result = verifyLedgerConsistency(Buffer.from(row.proof, 'utf8'), row.anchors);
    if (!Object.isFrozen(result)) throw Error('result is mutable');
    return {{accepted:true, ...result}};
  }} catch (error) {{ return {{accepted:false, name:error.name}}; }}
}});
process.stdout.write(JSON.stringify(answers));
"""
    result = subprocess.run(
        [node_binary(), "--input-type=module", "-e", script],
        input=json.dumps(rows),
        encoding="utf-8",
        capture_output=True,
        check=True,
        timeout=60,
    )
    assert result.stderr == ""
    return json.loads(result.stdout)


def index(size, version="2.0"):
    base = datetime(2026, 9, 1, tzinfo=UTC)
    events = [
        EvidenceEvent(
            event_id=str(position),
            claim="跨语言🔬",
            source="source",
            modality=Modality.TEXT,
            signal=Signal.SUPPORT,
            confidence=0.5,
            observed_at=base + timedelta(seconds=position),
            ingested_at=base + timedelta(seconds=position),
            attributes={"integer": 10**300, "float": 1e-20, "null": None},
        )
        for position in range(size)
    ]
    ledger = build_ledger(events)
    if version == "1.0":
        genesis = hashlib.sha256(b"evidence-braid-ledger:v1").hexdigest()
        previous = genesis
        entries = []
        for sequence, event in enumerate(events):
            payload = json.dumps(
                event.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")
            )
            digest = hashlib.sha256(f"{previous}\n{payload}".encode()).hexdigest()
            entries.append(LedgerEntry(sequence, event.event_id, event.to_dict(), previous, digest))
            previous = digest
        ledger = EvidenceLedger(tuple(entries), genesis, "1.0")
    return LedgerProofIndex(LedgerIndex(ledger, expected_head=ledger.head_digest))


def row(proof):
    return {
        "proof": proof.to_bytes().decode(),
        "anchors": {
            "expectedOldCommitmentDigest": proof.old_commitment.digest,
            "expectedNewCommitmentDigest": proof.new_commitment.digest,
        },
    }


@pytest.mark.parametrize("version", ["1.0", "2.0"])
def test_python_proofs_match_independent_node_verifier_for_all_prefixes(version):
    cases = []
    expected = []
    for size in (0, 1, 2, 3, 4, 7, 8, 9, 16, 17, 31, 32, 33, 65):
        new = index(size, version)
        for prefix in range(size + 1):
            old = LedgerProofIndex(
                LedgerIndex(
                    new.index.ledger,
                    expected_head=(
                        new.index.ledger.entries[prefix - 1].digest
                        if prefix
                        else new.index.ledger.genesis
                    ),
                    prefix_count=prefix,
                )
            )
            cases.append(row(prove_ledger_consistency(new, old.commitment)))
            expected.append((prefix, size))
    answers = invoke(cases)
    assert [(answer["oldEntryCount"], answer["newEntryCount"]) for answer in answers] == expected
    assert all(answer["accepted"] for answer in answers)
    for answer, case in zip(answers, cases, strict=True):
        assert answer["oldCommitmentDigest"] == case["anchors"]["expectedOldCommitmentDigest"]
        assert answer["newCommitmentDigest"] == case["anchors"]["expectedNewCommitmentDigest"]


def test_real_receipt_path_mutations_and_external_anchor_rejection():
    new = index(33)
    old = index(7)
    valid = row(prove_ledger_consistency(new, old.commitment))
    document = json.loads(valid["proof"])
    cases = [valid]
    for position, sibling in enumerate(document["path"]):
        for bit in range(256):
            changed = json.loads(valid["proof"])
            changed["path"][position] = f"{int(sibling, 16) ^ (1 << bit):064x}"
            cases.append(
                {**valid, "proof": json.dumps(changed, sort_keys=True, separators=(",", ":"))}
            )
    for anchor in valid["anchors"]:
        cases.append({**valid, "anchors": {**valid["anchors"], anchor: "0" * 64}})
    answers = invoke(cases)
    assert answers[0]["accepted"]
    assert all(not answer["accepted"] for answer in answers[1:])
    assert all(answer["name"] == "ConsistencyVerificationError" for answer in answers[1:])
