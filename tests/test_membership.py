from __future__ import annotations

import hashlib
import json
import random
import runpy
import subprocess
import sys
import tracemalloc
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from evidence_braid import (
    EvidenceEvent,
    EvidenceLedger,
    LedgerCommitment,
    LedgerEntry,
    LedgerIndex,
    LedgerMemberProof,
    LedgerMembershipBundle,
    LedgerProofIndex,
    LedgerQuery,
    Modality,
    Signal,
    SQLiteLedger,
    ValidationError,
    build_ledger,
    membership,
    verify_ledger_membership,
)

BASE = datetime(2026, 9, 1, tzinfo=UTC)
DOMAIN = b"evidence-braid:ledger-membership:v1\x00"


def canonical(value):
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


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


def proof_index(count):
    ledger = build_ledger(event(i) for i in range(count))
    return LedgerProofIndex(LedgerIndex(ledger, expected_head=ledger.head_digest))


def oracle_tree(receipts, version="2.0"):
    # Independent definition over array slices, not the production cached node/route algorithms.
    if not receipts:
        return hashlib.sha256(DOMAIN + b"E").digest()
    if len(receipts) == 1:
        return hashlib.sha256(
            DOMAIN + b"L" + canonical({"ledger_version": version, "receipt": receipts[0]})
        ).digest()
    split = 1
    while split * 2 < len(receipts):
        split *= 2
    return hashlib.sha256(
        DOMAIN
        + b"N"
        + oracle_tree(receipts[:split], version)
        + oracle_tree(receipts[split:], version)
    ).digest()


def oracle_path(receipts, position):
    if len(receipts) == 1:
        return []
    split = 1
    while split * 2 < len(receipts):
        split *= 2
    if position < split:
        return [*oracle_path(receipts[:split], position), oracle_tree(receipts[split:]).hex()]
    return [*oracle_path(receipts[split:], position - split), oracle_tree(receipts[:split]).hex()]


@pytest.mark.parametrize("count", [1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65])
def test_every_position_matches_independent_tree_and_path_oracle(count):
    index = proof_index(count)
    receipts = [entry.to_dict() for entry in index.index.ledger.entries]
    assert index.commitment.root_hash == oracle_tree(receipts).hex()
    for position in range(count):
        bundle = index.prove(position)
        assert bundle.members[0].siblings == tuple(oracle_path(receipts, position))
        assert verify_ledger_membership(
            bundle, expected_commitment_digest=index.commitment.digest
        ) == (index.index.ledger.entries[position],)
        assert LedgerMembershipBundle.from_bytes(bundle.to_bytes()) == bundle


def test_hardcoded_three_leaf_commitment_vector_and_no_duplicate_last_padding():
    index = proof_index(3)
    assert (
        index.commitment.root_hash
        == "28b8fa1d0296a6780e8028c0bb59a09a2ee04d2fb9af6d9a28b83435f3e5b1a6"
    )
    assert (
        index.commitment.digest
        == "f712823d691e82f919bfb0a0802fc320ccfde86e667492338ed8931d2c7243f4"
    )
    assert (
        index.prove(0).members[0].siblings[0]
        == "b281b755b628a060bcfef93b0f92d6f4b046468980dda4a3f7de9df716c3fbb9"
    )
    receipts = [entry.to_dict() for entry in index.index.ledger.entries]
    assert oracle_tree(receipts) != oracle_tree([*receipts, receipts[-1]])
    assert len(index.prove(2).members[0].siblings) == 1
    assert len(index.prove(0).members[0].siblings) == 2


def test_empty_commitment_is_valid_but_empty_membership_is_not_a_proof():
    index = proof_index(0)
    assert index.commitment.root_hash == oracle_tree([]).hex()
    assert LedgerCommitment.from_dict(index.commitment.to_dict()) == index.commitment
    assert index.commitment.head_digest == index.commitment.genesis
    for sequence in (0, -1, True):
        with pytest.raises(ValidationError):
            index.prove(sequence)
    with pytest.raises(ValidationError, match="empty pages"):
        index.prove_page(index.index.select().page())
    with pytest.raises(ValidationError):
        LedgerMembershipBundle(index.commitment, ())
    for change in ({"root_hash": "0" * 64}, {"head_digest": "0" * 64}):
        with pytest.raises(ValidationError):
            replace(index.commitment, **change)


def test_singleton_has_no_siblings_and_binds_all_receipt_fields():
    index = proof_index(1)
    bundle = index.prove(0)
    assert bundle.members[0].siblings == ()
    assert verify_ledger_membership(bundle, expected_commitment_digest=index.commitment.digest)
    data = bundle.to_dict()
    data["members"][0]["entry"]["event"]["attributes"] = {"changed": True}
    altered = LedgerMembershipBundle.from_dict(data)
    with pytest.raises(ValidationError, match="chain digest"):
        verify_ledger_membership(altered, expected_commitment_digest=index.commitment.digest)


@pytest.mark.parametrize("anchor", [None, True, "0" * 64, "A" * 64, "not-hash"])
def test_verifier_never_defaults_or_accepts_untrusted_or_malformed_anchors(anchor):
    bundle = proof_index(3).prove(1)
    with pytest.raises(ValidationError):
        verify_ledger_membership(bundle, expected_commitment_digest=anchor)
    with pytest.raises(TypeError):
        verify_ledger_membership(bundle)
    with pytest.raises(ValidationError, match="expected anchor"):
        verify_ledger_membership(bundle, expected_commitment_digest=bundle.commitment.head_digest)
    with pytest.raises(ValidationError):
        verify_ledger_membership(None, expected_commitment_digest=bundle.commitment.digest)


@pytest.mark.parametrize(
    "field,value",
    [
        ("root_hash", "0" * 64),
        ("head_digest", "0" * 64),
        ("entry_count", 4),
    ],
)
def test_commitment_header_changes_cannot_use_the_original_external_anchor(field, value):
    index = proof_index(3)
    original = index.prove(0)
    changed = replace(original, commitment=replace(original.commitment, **{field: value}))
    with pytest.raises(ValidationError, match="expected anchor"):
        verify_ledger_membership(changed, expected_commitment_digest=index.commitment.digest)


def test_sibling_order_and_every_hash_bit_are_binding():
    index = proof_index(7)
    bundle = index.prove(3)
    original = bundle.members[0]
    candidates = [tuple(reversed(original.siblings))]
    for position, sibling in enumerate(original.siblings):
        for byte in range(32):
            mutated = bytearray.fromhex(sibling)
            mutated[byte] ^= 1
            candidates.append(
                (*original.siblings[:position], mutated.hex(), *original.siblings[position + 1 :])
            )
    for siblings in candidates:
        changed = replace(bundle, members=(replace(original, siblings=siblings),))
        with pytest.raises(ValidationError, match="committed root"):
            verify_ledger_membership(changed, expected_commitment_digest=index.commitment.digest)
    for siblings in (original.siblings[:-1], (*original.siblings, "0" * 64)):
        with pytest.raises(ValidationError, match="sibling count"):
            replace(bundle, members=(replace(original, siblings=siblings),))


def test_locally_rehashed_receipt_still_fails_merkle_membership():
    index = proof_index(5)
    bundle = index.prove(2)
    entry = bundle.members[0].entry
    changed_event = {**entry.to_dict()["event"], "source": "forged-source"}
    digest = hashlib.sha256(
        canonical(
            {
                "schema_version": "2.0",
                "sequence": 2,
                "previous_digest": entry.previous_digest,
                "event": changed_event,
            }
        )
    ).hexdigest()
    changed = replace(
        bundle,
        members=(
            replace(bundle.members[0], entry=replace(entry, event=changed_event, digest=digest)),
        ),
    )
    with pytest.raises(ValidationError, match="committed root"):
        verify_ledger_membership(changed, expected_commitment_digest=index.commitment.digest)


def test_first_and_last_local_chain_boundaries_checked_even_under_a_new_header():
    index = proof_index(3)
    last = index.prove(2)
    changed = replace(last, commitment=replace(last.commitment, head_digest="0" * 64))
    with pytest.raises(ValidationError, match="prefix head"):
        verify_ledger_membership(changed, expected_commitment_digest=changed.commitment.digest)
    first = index.prove(0)
    entry = first.members[0].entry
    prev = "0" * 64
    digest = hashlib.sha256(
        canonical(
            {
                "schema_version": "2.0",
                "sequence": 0,
                "previous_digest": prev,
                "event": entry.to_dict()["event"],
            }
        )
    ).hexdigest()
    changed = replace(
        first,
        members=(
            replace(first.members[0], entry=replace(entry, previous_digest=prev, digest=digest)),
        ),
    )
    with pytest.raises(ValidationError, match="genesis"):
        verify_ledger_membership(changed, expected_commitment_digest=changed.commitment.digest)


def test_v1_receipts_preserve_original_digest_and_have_distinct_commitments():
    genesis = hashlib.sha256(b"evidence-braid-ledger:v1").hexdigest()
    entries = []
    previous = genesis
    for number in range(3):
        value = event(number)
        digest = hashlib.sha256(previous.encode() + b"\n" + canonical(value.to_dict())).hexdigest()
        entries.append(LedgerEntry(number, value.event_id, value.to_dict(), previous, digest))
        previous = digest
    ledger = EvidenceLedger(tuple(entries), genesis, "1.0")
    index = LedgerProofIndex(LedgerIndex(ledger, expected_head=previous))
    assert index.commitment.root_hash == oracle_tree([e.to_dict() for e in entries], "1.0").hex()
    assert index.commitment.root_hash != proof_index(3).commitment.root_hash
    for position in range(3):
        bundle = LedgerMembershipBundle.from_bytes(index.prove(position).to_bytes())
        assert verify_ledger_membership(
            bundle, expected_commitment_digest=index.commitment.digest
        ) == (entries[position],)


def test_query_page_receipts_have_membership_but_query_metadata_is_not_authenticated():
    index = proof_index(12)
    page = index.index.select(LedgerQuery(event_ids=("1", "4", "9"))).page()
    bundle = index.prove_page(page)
    assert [m.entry.sequence for m in bundle.members] == [1, 4, 9]
    assert (
        verify_ledger_membership(bundle, expected_commitment_digest=index.commitment.digest)
        == page.entries
    )
    # Directly constructed predicate metadata can lie; no query claim enters the proof.
    assert index.prove_page(replace(page, query_identity="0" * 64, total_matches=12)) == bundle
    assert "query_identity" not in bundle.to_dict()
    forged_entry = replace(
        page.entries[0], event={**page.entries[0].to_dict()["event"], "source": "forged!"}
    )
    forged = replace(
        page,
        entries=(forged_entry, *page.entries[1:]),
        entry_bytes=sum(len(canonical(e.to_dict())) for e in (forged_entry, *page.entries[1:])),
    )
    with pytest.raises(ValidationError, match="differs from"):
        index.prove_page(forged)
    with pytest.raises(ValidationError, match="different prefixes"):
        proof_index(13).prove_page(page)
    with pytest.raises(ValidationError):
        index.prove_page(None)


def test_detached_old_prefix_proofs_survive_backdated_append_reopen_and_process(tmp_path):
    store = SQLiteLedger(tmp_path / "ledger.sqlite")
    snapshot = store.append(event(i, note="猫😀") for i in range(9))
    index = LedgerProofIndex(LedgerIndex(snapshot, expected_head=snapshot.head_digest))
    page = index.index.select(LedgerQuery(event_ids=("2", "6"))).page()
    bundle = index.prove_page(page)
    store.append([replace(event(20), ingested_at=BASE - timedelta(days=1))])
    restored = LedgerProofIndex(
        LedgerIndex(store.snapshot(), expected_head=snapshot.head_digest, prefix_count=9)
    )
    assert restored.commitment == index.commitment
    assert restored.prove_page(page) == bundle
    raw = bundle.to_bytes()
    script = (
        "from evidence_braid import LedgerMembershipBundle,verify_ledger_membership; "
        "import sys,json; b=LedgerMembershipBundle.from_bytes(sys.stdin.buffer.read()); "
        "rows=verify_ledger_membership(b,expected_commitment_digest=sys.argv[1]); "
        "print(json.dumps([r.sequence for r in rows]))"
    )
    result = subprocess.run(
        [sys.executable, "-c", script, index.commitment.digest],
        input=raw,
        capture_output=True,
        timeout=20,
        check=True,
    )
    assert json.loads(result.stdout) == [2, 6]


def test_records_and_imported_graph_are_immutable_and_do_not_alias_caller_data():
    index = proof_index(5)
    original = index.prove(2)
    data = original.to_dict()
    restored = LedgerMembershipBundle.from_dict(data)
    data["members"][0]["entry"]["event"]["attributes"] = {"new": []}
    data["members"][0]["siblings"].clear()
    assert restored == original
    for value, field, change in [
        (index, "commitment", None),
        (original, "members", ()),
        (original.commitment, "entry_count", 0),
        (original.members[0], "siblings", ()),
    ]:
        with pytest.raises(FrozenInstanceError):
            setattr(value, field, change)
    with pytest.raises(TypeError):
        original.members[0].entry.event["source"] = "changed"


@pytest.mark.parametrize(
    "field,value",
    [
        ("ledger_version", "3.0"),
        ("ledger_version", []),
        ("genesis", "0" * 64),
        ("entry_count", True),
        ("entry_count", -1),
        ("entry_count", 100001),
        ("entry_count", 1.0),
        ("root_hash", "A" * 64),
        ("head_digest", "short"),
    ],
)
def test_strict_commitment_constructor(field, value):
    with pytest.raises(ValidationError):
        replace(proof_index(3).commitment, **{field: value})


@pytest.mark.parametrize(
    "change",
    [
        {"kind": "other"},
        {"schema_version": 1.0},
        {"commitment_digest": "0" * 64},
        {"extra": None},
        {"commitment_digest": []},
    ],
)
def test_strict_header_interchange(change):
    with pytest.raises(ValidationError):
        LedgerCommitment.from_dict({**proof_index(3).commitment.to_dict(), **change})


@pytest.mark.parametrize("field", ["kind", "schema_version"])
def test_foreign_profile_objects_are_rejected_without_calling_equality(field):
    class Foreign:
        def __eq__(self, other):
            pytest.fail("foreign comparison invoked")

    data = proof_index(3).prove(1).to_dict()
    data[field] = Foreign()
    with pytest.raises(ValidationError):
        LedgerMembershipBundle.from_dict(data)
    header = proof_index(3).commitment.to_dict()
    header[field] = Foreign()
    with pytest.raises(ValidationError):
        LedgerCommitment.from_dict(header)


def test_unknown_member_fields_and_direct_path_arrays_fail_strict_import():
    proof = proof_index(3).prove(1).members[0]
    for data in (
        None,
        {**proof.to_dict(), "extra": True},
        {**proof.to_dict(), "siblings": ()},
        {**proof.to_dict(), "siblings": ["0" * 64] * 18},
    ):
        with pytest.raises(ValidationError):
            LedgerMemberProof.from_dict(data)
    bundle = proof_index(3).prove(1).to_dict()
    for change in (
        {"kind": "unknown"},
        {"schema_version": "2.0"},
        {"members": ()},
        {"members": []},
    ):
        with pytest.raises(ValidationError):
            LedgerMembershipBundle.from_dict({**bundle, **change})


def test_scalar_utf8_budget_distinguishes_character_count_and_encoded_bytes(monkeypatch):
    # The same preflight is applied before public receipt materialization.
    monkeypatch.setattr(membership, "_MAX_BUNDLE_BYTES", 5)
    membership._preflight({"é": "猫"})
    monkeypatch.setattr(membership, "_MAX_BUNDLE_BYTES", 4)
    with pytest.raises(ValidationError, match="scalar data"):
        membership._preflight({"é": "猫"})


def test_direct_receipt_size_is_refused_before_parsed_copy(monkeypatch):
    entry = proof_index(1).index.ledger.entries[0]
    monkeypatch.setattr(membership, "_MAX_RECEIPT_BYTES", 1)
    monkeypatch.setattr(LedgerEntry, "from_dict", lambda *a, **k: pytest.fail("receipt copied"))
    with pytest.raises(ValidationError, match="receipt bytes"):
        LedgerMemberProof(entry, ())


def test_nested_wide_graph_does_not_queue_depth_times_width_before_rejection(monkeypatch):
    data = proof_index(3).prove(1).to_dict()
    child = [0]
    for _ in range(60):
        child = [0] * 2047 + [child]
    data["members"][0]["entry"]["event"]["attributes"] = {"wide": child}
    monkeypatch.setattr(membership, "_MAX_JSON_NODES", 4096)
    monkeypatch.setattr(membership, "_canonical", lambda *a: pytest.fail("serialization reached"))
    # Exclude the caller-owned graph from this allocation regression. A wide
    # queued-child stack allocated many MiB here despite the small node budget.
    already_tracing = tracemalloc.is_tracing()
    if not already_tracing:
        tracemalloc.start()
    baseline = tracemalloc.get_traced_memory()[0]
    tracemalloc.reset_peak()
    try:
        with pytest.raises(ValidationError, match="node"):
            LedgerMembershipBundle.from_dict(data)
        assert tracemalloc.get_traced_memory()[1] - baseline < 1_000_000
    finally:
        if not already_tracing:
            tracemalloc.stop()


def test_output_graph_budget_matches_import_budget_before_serialization(monkeypatch):
    bundle = proof_index(3).prove(1)
    data = bundle.to_dict()
    monkeypatch.setattr(membership, "_MAX_JSON_NODES", 10)
    monkeypatch.setattr(membership, "_canonical", lambda *a: pytest.fail("serialization reached"))
    # Header.to_dict() derives its digest; use the already prepared detached
    # document to isolate graph admission before the export serialization.
    monkeypatch.setattr(LedgerMembershipBundle, "to_dict", lambda self: data)
    with pytest.raises(ValidationError, match="node"):
        bundle.to_bytes()


@pytest.mark.parametrize("siblings", [[], ("a",), ("A" * 64,), (True,), ("0" * 64,) * 18])
def test_strict_sibling_constructors(siblings):
    with pytest.raises(ValidationError):
        LedgerMemberProof(proof_index(3).index.ledger.entries[0], siblings)


def test_strict_member_and_bundle_type_order_and_count_boundaries():
    index = proof_index(3)
    proof = index.prove(1).members[0]
    for entry in (None, {}):
        with pytest.raises(ValidationError):
            LedgerMemberProof(entry, ())
    for members in (
        [],
        (),
        (None,),
        (proof, proof),
        (proof,) * 1001,
        (index.prove(2).members[0], proof),
    ):
        with pytest.raises(ValidationError):
            LedgerMembershipBundle(index.commitment, members)
    with pytest.raises(ValidationError):
        LedgerMembershipBundle(None, (proof,))
    with pytest.raises(ValidationError):
        LedgerProofIndex(None)
    for sequence in (True, -1, 3, 1.0, 10**1000):
        with pytest.raises(ValidationError):
            index.prove(sequence)


@pytest.mark.parametrize(
    "field,value",
    [
        ("sequence", 10**1000),
        ("sequence", object()),
        ("event_id", object()),
        ("digest", "\ud800"),
        ("previous_digest", float("inf")),
    ],
)
def test_malformed_direct_receipt_fields_are_domain_errors_before_serialization(field, value):
    entry = proof_index(1).index.ledger.entries[0]
    with pytest.raises(ValidationError):
        LedgerMemberProof(replace(entry, **{field: value}), ())


@pytest.mark.parametrize(
    "transform",
    [
        lambda raw: b" " + raw,
        lambda raw: raw + b"\n",
        lambda raw: b"\xef\xbb\xbf" + raw,
        lambda raw: raw + b"{}",
        lambda raw: raw[:-1],
        lambda raw: raw.replace(b'"entry_count":3', b'"entry_count":3.0'),
        lambda raw: raw.replace(b'"entry_count":3', b'"entry_count":true'),
        lambda raw: raw.replace(b'"entry_count":3', b'"entry_count":3,"entry_count":3'),
        lambda raw: raw.replace(b'"confidence":0.5', b'"confidence":NaN'),
        lambda raw: raw.replace(b'"confidence":0.5', b'"confidence":1e9999'),
        lambda raw: raw.replace(b'"sequence":1', b'"sequence":' + b"9" * 641),
        lambda raw: raw.replace(b'"source"', b'"\\ud800"'),
    ],
)
def test_strict_canonical_wire_rejects_noncanonical_or_malformed_json(transform):
    with pytest.raises(ValidationError):
        LedgerMembershipBundle.from_bytes(transform(proof_index(3).prove(1).to_bytes()))


@pytest.mark.parametrize("raw", [None, "{}", bytearray(b"{}"), b"[]", b"null", b"\xff"])
def test_invalid_wire_types_and_values_are_domain_errors(raw):
    with pytest.raises(ValidationError):
        LedgerMembershipBundle.from_bytes(raw)


def test_wire_size_and_depth_admission_precedes_json_decoder(monkeypatch):
    monkeypatch.setattr(membership.json, "loads", lambda *a, **k: pytest.fail("decoder reached"))
    with pytest.raises(ValidationError, match="nesting"):
        LedgerMembershipBundle.from_bytes(b"[" * 73 + b"]" * 73)
    monkeypatch.setattr(membership, "_MAX_BUNDLE_BYTES", 5)
    with pytest.raises(ValidationError, match="20 MiB"):
        LedgerMembershipBundle.from_bytes(b"{}    ")


@pytest.mark.parametrize(
    "case",
    [
        "member_count",
        "last_path_count",
        "receipt_bytes",
        "nodes",
        "depth",
        "text",
        "utf8",
        "cycles",
        "non_json",
        "keys",
        "hugeint",
        "nan",
        "surrogate",
    ],
)
def test_parsed_graph_preflight_precedes_receipt_materialization(case, monkeypatch):
    data = proof_index(3).prove(1).to_dict()
    member = data["members"][0]
    attributes = member["entry"]["event"].setdefault("attributes", {})
    if case == "member_count":
        data["members"] *= 1001
    elif case == "last_path_count":
        data["members"].append({"entry": member["entry"], "siblings": ["0" * 64] * 18})
    elif case == "receipt_bytes":
        monkeypatch.setattr(membership, "_MAX_RECEIPT_BYTES", 1)
    elif case == "nodes":
        monkeypatch.setattr(membership, "_MAX_JSON_NODES", 10)
    elif case == "depth":
        for _ in range(74):
            attributes["nested"] = {}
            attributes = attributes["nested"]
    elif case in {"text", "utf8"}:
        attributes["text"] = ("a" if case == "text" else "猫") * 100
        monkeypatch.setattr(membership, "_MAX_BUNDLE_BYTES", 100)
    elif case == "cycles":
        attributes["cycle"] = attributes
    elif case == "non_json":
        attributes["bad"] = object()
    elif case == "keys":
        attributes[1] = "invalid"
    elif case == "hugeint":
        attributes["bad"] = 10**641
    elif case == "nan":
        attributes["bad"] = float("nan")
    else:
        attributes["bad"] = "\ud800"
    monkeypatch.setattr(
        LedgerEntry, "from_dict", lambda *a, **k: pytest.fail("receipt materialized")
    )
    with pytest.raises(ValidationError):
        LedgerMembershipBundle.from_dict(data)


def test_aggregate_member_bytes_preflight_before_first_receipt_and_output_bytes(monkeypatch):
    index = proof_index(3)
    bundle = index.prove_page(index.index.select().page())
    data = bundle.to_dict()
    monkeypatch.setattr(
        membership, "_MAX_RECEIPT_BYTES", len(canonical(data["members"][0]["entry"])) + 1
    )
    with pytest.raises(ValidationError, match="receipt bytes"):
        LedgerMembershipBundle.from_dict(data)
    with pytest.raises(ValidationError, match="receipt bytes"):
        replace(bundle, members=bundle.members)
    monkeypatch.setattr(membership, "_MAX_BUNDLE_BYTES", 1)
    with pytest.raises(ValidationError, match="20 MiB"):
        bundle.to_bytes()


def test_seeded_unicode_attribute_corpus_detaches_and_verifies():
    rng = random.Random(12021)
    for _ in range(30):
        attrs = {
            "text": "".join(rng.choice('猫😀é\\"\t') for _ in range(100)),
            "values": [None, True, False, rng.randint(-(10**30), 10**30), rng.random()],
        }
        ledger = build_ledger([event(0, **attrs), event(1, shared={"a": [1, 2]})])
        index = LedgerProofIndex(LedgerIndex(ledger, expected_head=ledger.head_digest))
        bundle = index.prove_page(index.index.select().page())
        assert (
            verify_ledger_membership(
                LedgerMembershipBundle.from_bytes(bundle.to_bytes()),
                expected_commitment_digest=index.commitment.digest,
            )
            == ledger.entries
        )


def test_offline_membership_example(capsys):
    runpy.run_path(
        str(Path(__file__).parents[1] / "examples" / "ledger_membership.py"), run_name="__main__"
    )
    value = json.loads(capsys.readouterr().out)
    assert value["verified_sequences"] == [1, 4, 7]
    assert value["query_completeness_proven"] is False
