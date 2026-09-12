"""Independent Node acceptance of exact Python receipt and membership wire bytes."""

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
    LedgerMembershipBundle,
    LedgerProofIndex,
    Modality,
    Signal,
    build_ledger,
)

VERIFICATION = Path(__file__).resolve().parents[1] / "verification"


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def invoke(rows, *, directory=None):
    node = shutil.which("node")
    if node is None and os.environ.get("EVIDENCE_REQUIRE_NODE") == "1":
        pytest.fail("independent verifier CI requires Node.js")
    if node is None:
        pytest.skip("Node.js is optional for Python-only installations")
    module = ((directory or VERIFICATION) / "ledger-membership.mjs").as_uri()
    script = f"""
import {{ verifyLedgerMembership, verifyLedgerReceipt }} from {json.dumps(module)};
let input = '';
for await (const chunk of process.stdin) input += chunk;
const output = JSON.parse(input).map(row => {{
  try {{
    const verify = row.receipt ? verifyLedgerReceipt : verifyLedgerMembership;
    const result = verify(Buffer.from(row.wire, 'utf8'), row.options);
    if (!Object.isFrozen(result) || (result.members &&
        (!Object.isFrozen(result.members) || !result.members.every(Object.isFrozen)))) {{
      throw Error('mutable result');
    }}
    return {{accepted:true, ...result}};
  }} catch (error) {{ return {{accepted:false, name:error.name, message:error.message}}; }}
}});
process.stdout.write(JSON.stringify(output));
"""
    result = subprocess.run(
        [node, "--input-type=module", "-e", script],
        input=json.dumps(rows),
        encoding="utf-8",
        capture_output=True,
        check=True,
        timeout=120,
        cwd=directory,
    )
    assert result.stderr == ""
    return json.loads(result.stdout)


def index(size, version="2.0"):
    base = datetime(2026, 9, 1, microsecond=1, tzinfo=UTC)
    events = [
        EvidenceEvent(
            event_id=f"é𐀀{position}",
            claim="\ufeff跨语言🔬\ufeff",
            source="source",
            modality=Modality.TEXT,
            signal=Signal.SUPPORT,
            confidence=(0.0, 0.1, 1.0, 5e-324)[position % 4],
            observed_at=base + timedelta(seconds=position),
            ingested_at=base + timedelta(seconds=position),
            correlation_group="é",
            attributes={
                "integer": 9007199254740993,
                "large": 10**640 - 1,
                "negative": -(10**640 - 1),
                "float": [1.0, -0.0, 1e16, 1e-5, 1.7976931348623157e308],
                "null": None,
                "\ue000": "composed-é",
                "𐀀": "decomposed-é",
                "controls": "\t\n\r",
                "": {"": []},
            },
        )
        for position in range(size)
    ]
    ledger = build_ledger(events)
    if version == "1.0":
        genesis = hashlib.sha256(b"evidence-braid-ledger:v1").hexdigest()
        previous = genesis
        entries = []
        for sequence, event in enumerate(events):
            digest = hashlib.sha256(
                f"{previous}\n{canonical(event.to_dict())}".encode()
            ).hexdigest()
            entries.append(LedgerEntry(sequence, event.event_id, event.to_dict(), previous, digest))
            previous = digest
        ledger = EvidenceLedger(tuple(entries), genesis, version)
    return LedgerProofIndex(LedgerIndex(ledger, expected_head=ledger.head_digest))


def row(bundle):
    return {
        "wire": bundle.to_bytes().decode(),
        "options": {"expectedCommitmentDigest": bundle.commitment.digest},
    }


def receipt_row(entry, version):
    return {
        "receipt": True,
        "wire": canonical(entry.to_dict()),
        "options": {
            "ledgerVersion": version,
            "expectedReceiptDigest": entry.digest,
            "expectedPreviousDigest": entry.previous_digest,
            "expectedSequence": entry.sequence,
        },
    }


@pytest.mark.parametrize("version", ["1.0", "2.0"])
def test_every_position_across_ragged_and_binary_tree_boundaries(version):
    rows = []
    expected = []
    for size in (1, 2, 3, 4, 5, 7, 8, 9, 16, 17, 31, 32, 33, 65):
        proof_index = index(size, version)
        for position in range(size):
            rows.append(row(proof_index.prove(position)))
            expected.append((size, position))
    answers = invoke(rows)
    assert all(answer["accepted"] for answer in answers), answers
    assert [
        (answer["entryCount"], answer["members"][0]["sequence"]) for answer in answers
    ] == expected


@pytest.mark.parametrize("version", ["1.0", "2.0"])
def test_receipts_sparse_members_and_relocated_offline_modules(version, tmp_path):
    proof_index = index(5, version)
    bundle = LedgerMembershipBundle(
        proof_index.commitment,
        tuple(proof_index.prove(position).members[0] for position in (0, 2, 4)),
    )
    for name in ("ledger-membership.mjs", "receipt-wire.mjs", "receipt-numbers.mjs"):
        shutil.copyfile(VERIFICATION / name, tmp_path / name)
    rows = [row(bundle)] + [
        receipt_row(entry, version) for entry in proof_index.index.ledger.entries
    ]
    answers = invoke(rows, directory=tmp_path)
    assert all(answer["accepted"] for answer in answers), answers
    assert [member["sequence"] for member in answers[0]["members"]] == [0, 2, 4]
    assert all("event" not in answer for answer in answers)


def test_rejects_noncanonical_event_even_if_receipt_hash_and_external_digest_are_recomputed():
    original = index(1).index.ledger.entries[0]
    invalid = []
    for key, value in (
        ("confidence", 1),
        ("confidence", True),
        ("confidence", -0.0),
        ("confidence", 1.1),
        ("confidence", -0.1),
        ("source", "\u0085source"),
        ("source", "source\u00a0"),
        ("claim", ""),
        ("correlation_group", None),
        ("attributes", {}),
        ("attributes", []),
        ("modality", "image"),
        ("signal", "positive"),
        ("extra", 1),
        ("observed_at", "2024-02-29T00:00:00.000000Z"),
        ("observed_at", "2023-02-29T00:00:00Z"),
        ("observed_at", "1900-02-29T00:00:00Z"),
        ("observed_at", "0000-01-01T00:00:00Z"),
        ("observed_at", "2026-13-01T00:00:00Z"),
        ("observed_at", "2026-01-01T24:00:00Z"),
        ("observed_at", "2026-01-01T00:00:60Z"),
        ("observed_at", "2026-01-01T00:00:00+00:00"),
        ("observed_at", "2026-01-01T00:00:00.1Z"),
    ):
        data = original.to_dict()
        data["event"][key] = value
        payload = {
            "event": data["event"],
            "previous_digest": data["previous_digest"],
            "schema_version": "2.0",
            "sequence": data["sequence"],
        }
        data["digest"] = hashlib.sha256(canonical(payload).encode()).hexdigest()
        case = receipt_row(original, "2.0")
        case["wire"] = canonical(data)
        case["options"]["expectedReceiptDigest"] = data["digest"]
        invalid.append(case)
    answers = invoke(invalid)
    assert all(
        not answer["accepted"] and answer["name"] == "LedgerVerificationError" for answer in answers
    ), answers


@pytest.mark.parametrize("version", ["1.0", "2.0"])
def test_original_external_anchor_rejects_byte_and_structural_mutations(version):
    proof_index = index(5, version)
    case = row(proof_index.prove(2))
    cases = []
    for mutate in (
        lambda data: data["members"][0]["entry"].update(sequence=3),
        lambda data: data["members"][0]["entry"].update(event_id="different"),
        lambda data: data["members"][0]["entry"]["event"].update(claim="other"),
        lambda data: data["members"][0]["siblings"].reverse(),
        lambda data: data["members"][0]["siblings"].append("0" * 64),
        lambda data: data["members"][0]["siblings"].pop(),
        lambda data: data["members"].append(data["members"][0]),
        lambda data: data["commitment"].update(entry_count=6),
        lambda data: data["commitment"].update(root_hash="0" * 64),
        lambda data: data.update(members=[]),
        lambda data: data.update(kind="another-kind"),
        lambda data: data.update(extra=True),
    ):
        data = json.loads(case["wire"])
        mutate(data)
        cases.append({**case, "wire": canonical(data)})
    cases += [
        {**case, "wire": wire}
        for wire in (
            case["wire"] + "\n",
            " " + case["wire"],
            case["wire"].replace("é", "\\u00e9"),
            case["wire"].replace("9007199254740993", "9007199254740992"),
            case["wire"].replace('"confidence":1.0', '"confidence":1'),
        )
    ]
    cases.append({**case, "options": {"expectedCommitmentDigest": "0" * 64}})
    answers = invoke(cases)
    assert all(
        not answer["accepted"] and answer["name"] == "LedgerVerificationError" for answer in answers
    ), answers


def test_v1_sequence_is_separate_context_but_member_leaf_binds_it():
    proof_index = index(5, "1.0")
    entry = proof_index.index.ledger.entries[2]
    data = entry.to_dict()
    data["sequence"] = 3
    case = receipt_row(entry, "1.0")
    case["wire"] = canonical(data)
    changed_context = {**case, "options": {**case["options"], "expectedSequence": 3}}
    original_member = row(proof_index.prove(2))
    bundle_data = json.loads(original_member["wire"])
    bundle_data["members"][0]["entry"]["sequence"] = 3
    forged_member = {**original_member, "wire": canonical(bundle_data)}
    answers = invoke([case, changed_context, forged_member])
    assert [answer["accepted"] for answer in answers] == [False, True, False]


def test_full_event_depth_bound_does_not_silently_truncate_attributes():
    proof_index = index(1)
    original = proof_index.index.ledger.entries[0]
    data = original.to_dict()
    nested = 0
    for _ in range(63):
        nested = [nested]
    data["event"]["attributes"] = {"nested": nested}
    payload = {
        "event": data["event"],
        "previous_digest": data["previous_digest"],
        "schema_version": "2.0",
        "sequence": 0,
    }
    data["digest"] = hashlib.sha256(canonical(payload).encode()).hexdigest()
    case = receipt_row(original, "2.0")
    case["wire"] = canonical(data)
    case["options"]["expectedReceiptDigest"] = data["digest"]
    assert invoke([case])[0]["accepted"] is False
    data["event"]["attributes"]["nested"] = nested[0]
    payload["event"] = data["event"]
    data["digest"] = hashlib.sha256(canonical(payload).encode()).hexdigest()
    case["wire"] = canonical(data)
    case["options"]["expectedReceiptDigest"] = data["digest"]
    assert invoke([case])[0]["accepted"] is True


def test_maximum_thousand_selected_receipts_are_all_verified():
    proof_index = index(1000)
    bundle = LedgerMembershipBundle(
        proof_index.commitment,
        tuple(proof_index.prove(position).members[0] for position in range(1000)),
    )
    result = invoke([row(bundle)])[0]
    assert result["accepted"], result
    assert len(result["members"]) == 1000
    assert [member["sequence"] for member in result["members"]] == list(range(1000))
