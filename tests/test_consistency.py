from __future__ import annotations

import hashlib
import json
import random
import runpy
import subprocess
import sys
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from evidence_braid import (
    EvidenceEvent,
    EvidenceLedger,
    LedgerCommitment,
    LedgerConsistencyProof,
    LedgerEntry,
    LedgerIndex,
    LedgerProofIndex,
    Modality,
    Signal,
    SQLiteLedger,
    ValidationError,
    build_ledger,
    consistency,
    prove_ledger_consistency,
    verify_ledger_consistency,
)

BASE = datetime(2026, 9, 1, tzinfo=UTC)
DOMAIN = b"evidence-braid:ledger-membership:v1\x00"


def canonical(value):
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def event(number, **attributes):
    return EvidenceEvent(
        event_id=str(number),
        claim="claim",
        source="source",
        modality=Modality.TEXT,
        signal=Signal.SUPPORT,
        confidence=0.5,
        observed_at=BASE + timedelta(seconds=number),
        ingested_at=BASE + timedelta(seconds=number),
        attributes=attributes,
    )


def index(count):
    ledger = build_ledger(event(number) for number in range(count))
    return LedgerProofIndex(LedgerIndex(ledger, expected_head=ledger.head_digest))


def node(left, right):
    return hashlib.sha256(DOMAIN + b"N" + left + right).digest()


def leaf_hashes(ledger):
    return [
        hashlib.sha256(
            DOMAIN
            + b"L"
            + canonical({"ledger_version": ledger.schema_version, "receipt": entry.to_dict()})
        ).digest()
        for entry in ledger.entries
    ]


def frontier_root(leaves):
    # Independent iterative frontier; no production cached nodes or split recursion.
    if not leaves:
        return hashlib.sha256(DOMAIN + b"E").digest()
    stack = []
    for value in leaves:
        size = 1
        while stack and stack[-1][0] == size:
            value = node(stack.pop()[1], value)
            size *= 2
        stack.append((size, value))
    result = stack.pop()[1]
    while stack:
        result = node(stack.pop()[1], result)
    return result


def old_header(new, count):
    ledger = new.index.ledger
    return LedgerCommitment(
        ledger.schema_version,
        ledger.genesis,
        ledger.entries[count - 1].digest if count else ledger.genesis,
        count,
        frontier_root(leaf_hashes(ledger)[:count]).hex(),
    )


def bit_verify(first, second, before, after, path):
    # Independent index/bit verifier, intentionally unlike paired recursive recovery.
    if first == 0:
        return path == ()
    if first == second:
        return path == () and before == after
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    values = iter(bytes.fromhex(value) for value in path)
    older = newer = before if first & (first - 1) == 0 else next(values)
    for value in values:
        if not sn:
            return False
        if fn & 1 or fn == sn:
            older, newer = node(value, older), node(value, newer)
            while fn and not fn & 1:
                fn >>= 1
                sn >>= 1
        else:
            newer = node(newer, value)
        fn >>= 1
        sn >>= 1
    return older == before and newer == after and sn == 0


def verify(proof):
    return verify_ledger_consistency(
        proof,
        expected_old_commitment_digest=proof.old_commitment.digest,
        expected_new_commitment_digest=proof.new_commitment.digest,
    )


@pytest.mark.parametrize("count", [0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65])
def test_every_old_prefix_against_independent_frontier_and_bit_verifiers(count):
    current = index(count)
    assert current.commitment.root_hash == frontier_root(leaf_hashes(current.index.ledger)).hex()
    for before in range(count + 1):
        old = old_header(current, before)
        proof = prove_ledger_consistency(current, old)
        assert verify(proof) is None
        assert bit_verify(
            before,
            count,
            bytes.fromhex(old.root_hash),
            bytes.fromhex(current.commitment.root_hash),
            proof.path,
        )
        assert len(proof.path) <= (count - 1).bit_length() + 1
        assert LedgerConsistencyProof.from_bytes(proof.to_bytes()) == proof


def test_fixed_receipt_three_to_seven_vector_and_power_boundaries():
    current = index(7)
    proof = prove_ledger_consistency(current, old_header(current, 3))
    assert (
        proof.old_commitment.digest
        == "f712823d691e82f919bfb0a0802fc320ccfde86e667492338ed8931d2c7243f4"
    )
    assert (
        current.commitment.digest
        == "aadd78975357b2e3c135995eb61163e8206b0f7c85b8229faeaa33cc60312c30"
    )
    assert proof.path == (
        "ea93aa420ba78e06d7ea7cc8bd14a478ade237287780c15bc74a7eb4e10cbfb7",
        "9211314f65191e8619a28e5683a4386e1c745365a11e7dace765b8b972a3b47c",
        "fcec6b57f5ae99765bb77bbf1d67de06af80a15c2ed43d4d11ac90bad3513d1f",
        "4264b4692c4efdae6054f23c7b87a3573d2ee94eb69a548ffb15898fcb251a97",
    )
    assert [
        len(prove_ledger_consistency(current, old_header(current, n)).path) for n in (3, 4, 6)
    ] == [4, 1, 3]


def test_every_path_bit_and_reordering_fail_under_retained_anchors():
    current = index(7)
    proof = prove_ledger_consistency(current, old_header(current, 3))
    for position, value in enumerate(proof.path):
        for bit in range(256):
            changed = bytearray.fromhex(value)
            changed[bit // 8] ^= 1 << (bit % 8)
            path = (*proof.path[:position], changed.hex(), *proof.path[position + 1 :])
            with pytest.raises(ValidationError, match="both committed roots"):
                verify(replace(proof, path=path))
    with pytest.raises(ValidationError, match="both committed roots"):
        verify(replace(proof, path=tuple(reversed(proof.path))))
    for path in ((), proof.path[:-1], (*proof.path, "0" * 64)):
        with pytest.raises(ValidationError, match="path length"):
            replace(proof, path=path)


@pytest.mark.parametrize("side", ["old", "new"])
@pytest.mark.parametrize("anchor", [None, True, "bad", "A" * 64, "0" * 64])
def test_two_external_anchors_are_mandatory_exact_and_independent(side, anchor):
    current = index(7)
    proof = prove_ledger_consistency(current, old_header(current, 3))
    anchors = {
        "expected_old_commitment_digest": proof.old_commitment.digest,
        "expected_new_commitment_digest": proof.new_commitment.digest,
    }
    anchors[f"expected_{side}_commitment_digest"] = anchor
    with pytest.raises(ValidationError):
        verify_ledger_consistency(proof, **anchors)
    with pytest.raises(TypeError):
        verify_ledger_consistency(proof)
    del anchors[f"expected_{side}_commitment_digest"]
    with pytest.raises(TypeError):
        verify_ledger_consistency(proof, **anchors)


def test_old_chain_heads_swapped_anchors_and_wrong_proof_types_cannot_verify():
    current = index(7)
    proof = prove_ledger_consistency(current, old_header(current, 3))
    for older, newer in (
        (proof.old_commitment.head_digest, proof.new_commitment.head_digest),
        (proof.new_commitment.digest, proof.old_commitment.digest),
    ):
        with pytest.raises(ValidationError, match="external anchor"):
            verify_ledger_consistency(
                proof, expected_old_commitment_digest=older, expected_new_commitment_digest=newer
            )
    with pytest.raises(ValidationError, match="LedgerConsistencyProof"):
        verify_ledger_consistency(
            None,
            expected_old_commitment_digest=proof.old_commitment.digest,
            expected_new_commitment_digest=proof.new_commitment.digest,
        )


@pytest.mark.parametrize("side", ["old_commitment", "new_commitment"])
@pytest.mark.parametrize("field", ["root_hash", "head_digest"])
def test_complete_headers_are_bound_to_the_separately_retained_digests(side, field):
    current = index(7)
    proof = prove_ledger_consistency(current, old_header(current, 3))
    changed = replace(proof, **{side: replace(getattr(proof, side), **{field: "0" * 64})})
    with pytest.raises(ValidationError, match="external anchor"):
        verify_ledger_consistency(
            changed,
            expected_old_commitment_digest=proof.old_commitment.digest,
            expected_new_commitment_digest=proof.new_commitment.digest,
        )
    if field == "root_hash":
        with pytest.raises(ValidationError, match="both committed roots"):
            verify(changed)


def test_consistency_is_not_independent_validation_of_hidden_new_chain_head():
    current = index(7)
    proof = prove_ledger_consistency(current, old_header(current, 3))
    # A dishonest anchor publisher can bind a head unrelated to hidden receipts.
    # Prefix hashes cannot discover that if the recipient trusts that new header.
    dishonest = replace(proof, new_commitment=replace(proof.new_commitment, head_digest="0" * 64))
    assert verify(dishonest) is None
    with pytest.raises(ValidationError, match="actual indexed prefix"):
        prove_ledger_consistency(current, replace(proof.old_commitment, head_digest="0" * 64))


def test_equal_counts_require_full_identical_headers_not_just_roots():
    current = index(3)
    same = prove_ledger_consistency(current, current.commitment)
    assert same.path == () and verify(same) is None
    with pytest.raises(ValidationError, match="identical complete"):
        LedgerConsistencyProof(
            current.commitment, replace(current.commitment, head_digest="0" * 64), ()
        )
    with pytest.raises(ValidationError, match="path length"):
        replace(same, path=("0" * 64,))
    empty = index(0)
    assert verify(prove_ledger_consistency(empty, empty.commitment)) is None


def test_empty_prefix_is_explicitly_vacuous_not_new_content_or_identity_evidence():
    empty = index(0)
    for count in (1, 3, 7):
        proof = prove_ledger_consistency(index(count), empty.commitment)
        assert proof.path == () and verify(proof) is None
        with pytest.raises(ValidationError, match="path length"):
            replace(proof, path=("0" * 64,))
    with pytest.raises(ValidationError, match="decrease"):
        LedgerConsistencyProof(index(1).commitment, empty.commitment, ())


def test_builder_checks_actual_prefix_and_does_not_rehash_existing_receipts(monkeypatch):
    current = index(9)
    old = old_header(current, 5)
    with pytest.raises(ValidationError, match="head differs"):
        prove_ledger_consistency(current, replace(old, head_digest="0" * 64))
    with pytest.raises(ValidationError, match="root differs"):
        prove_ledger_consistency(current, replace(old, root_hash="0" * 64))
    rewritten = build_ledger(event(i, changed=True) if i == 2 else event(i) for i in range(9))
    rewritten_index = LedgerProofIndex(LedgerIndex(rewritten, expected_head=rewritten.head_digest))
    with pytest.raises(ValidationError, match="head differs"):
        prove_ledger_consistency(rewritten_index, old)
    monkeypatch.setattr(LedgerEntry, "to_dict", lambda *a: pytest.fail("receipt was reserialized"))
    assert verify(prove_ledger_consistency(current, old)) is None


def test_v1_chain_is_preserved_and_cannot_cross_version_boundary():
    genesis = hashlib.sha256(b"evidence-braid-ledger:v1").hexdigest()
    entries = []
    previous = genesis
    for number in range(9):
        value = event(number)
        digest = hashlib.sha256(previous.encode() + b"\n" + canonical(value.to_dict())).hexdigest()
        entries.append(LedgerEntry(number, value.event_id, value.to_dict(), previous, digest))
        previous = digest
    ledger = EvidenceLedger(tuple(entries), genesis, "1.0")
    current = LedgerProofIndex(LedgerIndex(ledger, expected_head=previous))
    proof = prove_ledger_consistency(current, old_header(current, 5))
    assert proof.old_commitment.ledger_version == "1.0" and verify(proof) is None
    assert LedgerConsistencyProof.from_bytes(proof.to_bytes()) == proof
    with pytest.raises(ValidationError, match="different ledger versions"):
        prove_ledger_consistency(index(9), proof.old_commitment)


def test_real_sqlite_append_reopen_detached_verification_in_separate_process(tmp_path):
    path = tmp_path / "ledger.sqlite"
    old_ledger = SQLiteLedger(path).append(event(i, unicode="猫😀") for i in range(5))
    old = LedgerProofIndex(LedgerIndex(old_ledger, expected_head=old_ledger.head_digest)).commitment
    latest = SQLiteLedger(path).append(
        replace(event(i), ingested_at=BASE - timedelta(days=1)) for i in range(5, 9)
    )
    new_index = LedgerProofIndex(LedgerIndex(latest, expected_head=latest.head_digest))
    proof = prove_ledger_consistency(new_index, old)
    assert (
        prove_ledger_consistency(
            LedgerProofIndex(
                LedgerIndex(SQLiteLedger(path).snapshot(), expected_head=latest.head_digest)
            ),
            old,
        )
        == proof
    )
    old_anchor, new_anchor = old.digest, new_index.commitment.digest
    raw = proof.to_bytes()
    del new_index, old_ledger, latest, old, proof
    script = (
        "import sys; from evidence_braid import LedgerConsistencyProof,verify_ledger_consistency; "
        "p=LedgerConsistencyProof.from_bytes(sys.stdin.buffer.read()); "
        "verify_ledger_consistency(p,expected_old_commitment_digest=sys.argv[1],"
        "expected_new_commitment_digest=sys.argv[2]); print('5->9 verified')"
    )
    result = subprocess.run(
        [sys.executable, "-c", script, old_anchor, new_anchor],
        input=raw,
        capture_output=True,
        timeout=20,
        check=True,
    )
    assert result.stdout.strip() == b"5->9 verified"


def test_immutable_records_and_import_snapshots_do_not_alias_caller_values():
    current = index(7)
    proof = prove_ledger_consistency(current, old_header(current, 3))
    data = proof.to_dict()
    restored = LedgerConsistencyProof.from_dict(data)
    data["path"].clear()
    data["old_commitment"]["root_hash"] = "0" * 64
    assert restored == proof
    for target, name in ((proof, "path"), (proof.old_commitment, "head_digest")):
        with pytest.raises(FrozenInstanceError):
            setattr(target, name, None)


@pytest.mark.parametrize("path", [[], None, ("0" * 64,) * 19, (True,) * 4, ("A" * 64,) * 4])
def test_direct_paths_are_exact_immutable_and_bounded(path):
    current = index(7)
    with pytest.raises(ValidationError):
        LedgerConsistencyProof(old_header(current, 3), current.commitment, path)


def test_direct_wrong_index_and_header_types_fail_as_domain_errors():
    current = index(7)
    with pytest.raises(ValidationError, match="LedgerProofIndex"):
        prove_ledger_consistency(current.index, old_header(current, 3))
    with pytest.raises(ValidationError, match="LedgerCommitment"):
        prove_ledger_consistency(current, {})
    with pytest.raises(ValidationError, match="LedgerCommitment"):
        LedgerConsistencyProof(current.commitment, None, ())


@pytest.mark.parametrize(
    "case",
    [
        "root_width",
        "root_key",
        "path_width",
        "path_type",
        "path_hash",
        "late_header",
        "header_width",
        "header_text",
        "header_count",
        "nested",
        "cycle",
        "kind_type",
    ],
)
def test_closed_shape_admission_precedes_any_header_materialization(case, monkeypatch):
    current = index(7)
    data = prove_ledger_consistency(current, old_header(current, 3)).to_dict()
    if case == "root_width":
        data.update({str(i): None for i in range(10_000)})
    elif case == "root_key":
        data[1] = data.pop("kind")
    elif case == "path_width":
        data["path"] *= 10_000
    elif case == "path_type":
        data["path"] = tuple(data["path"])
    elif case == "path_hash":
        data["path"][-1] = object()
    elif case == "late_header":
        data["new_commitment"]["unknown"] = 1
    elif case == "header_width":
        data["old_commitment"].update({str(i): None for i in range(10_000)})
    elif case == "header_text":
        data["new_commitment"]["root_hash"] = "0" * 65
    elif case == "header_count":
        data["new_commitment"]["entry_count"] = 10**1000
    elif case == "nested":
        data["old_commitment"]["root_hash"] = [[[]]]
    elif case == "cycle":
        data["new_commitment"] = data
    else:

        class Unexpected:
            def __eq__(self, other):
                pytest.fail("foreign comparison executed")

        data["kind"] = Unexpected()
    monkeypatch.setattr(
        LedgerCommitment, "from_dict", lambda *a: pytest.fail("header materialized")
    )
    with pytest.raises(ValidationError):
        LedgerConsistencyProof.from_dict(data)


@pytest.mark.parametrize(
    "transform",
    [
        lambda raw: b" " + raw,
        lambda raw: raw + b"\n",
        lambda raw: b"\xef\xbb\xbf" + raw,
        lambda raw: raw.replace(b'"entry_count":3', b'"entry_count":3.0'),
        lambda raw: raw.replace(b'"entry_count":3', b'"entry_count":3000000'),
        lambda raw: raw.replace(b'"entry_count":3', b'"entry_count":1e9999999'),
        lambda raw: raw.replace(b'"entry_count":3', b'"entry_count":NaN'),
        lambda raw: raw.replace(b'"entry_count":3', b'"entry_count":3,"entry_count":3'),
        lambda raw: raw.replace(b'"schema_version":"1.0"', b'"schema_version":"2.0"', 1),
        lambda raw: raw.replace(b'"genesis":"', b'"genesis":"\\ud800'),
        lambda raw: raw.replace(b'"head_digest":"', b'"head_digest":"\xff'),
    ],
)
def test_canonical_wire_rejects_ambiguous_malformed_or_unknown_format(transform):
    current = index(7)
    raw = prove_ledger_consistency(current, old_header(current, 3)).to_bytes()
    with pytest.raises(ValidationError):
        LedgerConsistencyProof.from_bytes(transform(raw))


@pytest.mark.parametrize("raw", [None, bytearray(b"{}"), "{}", b"[]", b"null", b"\xff"])
def test_wire_type_rejection(raw):
    with pytest.raises(ValidationError):
        LedgerConsistencyProof.from_bytes(raw)


def test_raw_size_depth_admission_before_json_and_export_size_bound(monkeypatch):
    current = index(7)
    proof = prove_ledger_consistency(current, old_header(current, 3))
    raw = proof.to_bytes()
    monkeypatch.setattr(consistency.json, "loads", lambda *a, **k: pytest.fail("decoder reached"))
    for invalid in (b" " * 4097, b"[[[]]]"):
        with pytest.raises(ValidationError):
            LedgerConsistencyProof.from_bytes(invalid)
    monkeypatch.setattr(consistency, "_MAX_BYTES", len(raw) - 1)
    with pytest.raises(ValidationError, match="4096"):
        proof.to_bytes()


def test_maximum_tree_size_requires_eighteen_hashes_but_fits_fixed_wire():
    # Shape/serialization only; arbitrary hashes are not claimed as a valid ledger.
    current = index(7)
    old = old_header(current, 3)
    new = replace(current.commitment, entry_count=100_000)
    proof = LedgerConsistencyProof(old, new, ("0" * 64,) * 18)
    assert len(proof.to_bytes()) < 4096
    assert LedgerConsistencyProof.from_bytes(proof.to_bytes()) == proof
    with pytest.raises(ValidationError, match="both committed roots"):
        verify(proof)
    with pytest.raises(ValidationError, match="path length"):
        replace(proof, path=proof.path[:-1])


def test_seeded_unicode_receipts_and_random_prefixes():
    rng = random.Random(18811)
    for _ in range(30):
        count = rng.randrange(2, 60)
        ledger = build_ledger(event(i, text="猫🙂é", value=rng.random()) for i in range(count))
        current = LedgerProofIndex(LedgerIndex(ledger, expected_head=ledger.head_digest))
        old = old_header(current, rng.randrange(count + 1))
        proof = prove_ledger_consistency(current, old)
        assert verify(LedgerConsistencyProof.from_bytes(proof.to_bytes())) is None


def test_offline_consistency_example(capsys):
    runpy.run_path(
        str(Path(__file__).parents[1] / "examples/ledger_consistency.py"), run_name="__main__"
    )
    output = json.loads(capsys.readouterr().out)
    assert (output["old_entries"], output["new_entries"], output["path_hashes"]) == (3, 7, 4)
    assert output["hidden_chain_links_revalidated"] is False
