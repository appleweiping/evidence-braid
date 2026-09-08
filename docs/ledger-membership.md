# Detached ledger membership proofs

`LedgerProofIndex` builds a Merkle commitment over an already verified immutable `LedgerIndex`
prefix. A recipient can verify selected complete receipts using a detached bundle and a separately
retained commitment digest, without receiving the undisclosed receipts or retaining the full chain.
This is an original Evidence Braid proof profile, not a Certificate Transparency wire protocol.

```python
from evidence_braid import (
    LedgerIndex,
    LedgerMembershipBundle,
    LedgerProofIndex,
    LedgerQuery,
    verify_ledger_membership,
)

# ledger is a snapshot; trusted_head was obtained independently.
verified_index = LedgerIndex(ledger, expected_head=trusted_head)
proof_index = LedgerProofIndex(verified_index)
page = verified_index.select(LedgerQuery(sources=("camera-west",))).page(limit=20)
bundle = proof_index.prove_page(page)  # Empty pages intentionally raise.
wire_bytes = bundle.to_bytes()

# Establish this anchor through a trusted channel, not from incoming wire_bytes.
retained_commitment_digest = proof_index.commitment.digest
received = LedgerMembershipBundle.from_bytes(wire_bytes)
receipts = verify_ledger_membership(received, expected_commitment_digest=retained_commitment_digest)
```

Use `proof_index.prove(sequence)` for a single zero-based ledger position. Both operations return
`LedgerMembershipBundle`, with one shared `LedgerCommitment` and a nonempty tuple of
`LedgerMemberProof` records. Records and nested receipts are immutable; `to_dict()` produces
detached values. Parsing or directly constructing records is **not** verification.

## What the anchor means

The expected commitment digest is mandatory and must come through a separately trusted channel.
It binds the Merkle root together with the ledger version, genesis, prefix count and chain head.
An ordinary existing chain head is not this digest and cannot substitute for it. There is no API
default that copies the expected value from the untrusted bundle.

The trusted publisher must first verify the full ledger and construct/recompute this commitment;
`LedgerProofIndex` requires the existing verified `LedgerIndex` for that reason. A recipient checks
membership under the retained commitment, but cannot independently check all undisclosed chain
links from a few leaves. A malicious party can construct an internally consistent replacement tree
and new header. Copying that party's digest from the same untrusted file proves self-consistency,
not independent trust. The library cannot determine how a caller obtained its expected digest.

A successful verification establishes the selected receipt bytes and positions in the anchored
tree, assuming SHA-256 collision/second-preimage resistance and correct trusted anchor establishment.
It does **not** establish:

- the truth of observations, actor/source identity, signatures or authority approval;
- durable database commit, retention, timestamp authenticity or a witness countersignature;
- the validity of every undisclosed chain link, absent a trusted full-chain commitment builder;
- query predicate correctness, query completeness, absence of omitted matches or nonmembership;
- consistency between two differently sized commitments, live append-only behavior or availability.

An in-memory ledger can be committed by this API, so membership is deliberately not called a
durable-commit receipt. There is no encryption/redaction: complete selected event data and attributes
are disclosed. Sibling hashes can also link proofs sharing tree regions. This implementation has
local regression and independent implementation checks, not an external cryptographic audit.

## Byte-for-byte hashing profile

All digests are lowercase hexadecimal SHA-256. Define `D` as these exact bytes:

```python
D = b"evidence-braid:ledger-membership:v1\x00"
```

`J(value)` means the existing Evidence Braid compact Python JSON encoding: sorted object keys,
separators `(',', ':')`, `ensure_ascii=False`, `allow_nan=False`, then strict UTF-8. There is no
trailing newline. This preserves the project's current numeric encoding; it is **not RFC 8785**
or a claim of independent cross-language floating-point canonicalization.

The four distinct domains are:

```text
empty root = SHA256(D || ASCII("E"))
leaf       = SHA256(D || ASCII("L") || J({"ledger_version": version, "receipt": receipt}))
node       = SHA256(D || ASCII("N") || left_digest_32_bytes || right_digest_32_bytes)
commitment = SHA256(D || ASCII("C") || J(header_without_commitment_digest))
```

`receipt` is the complete canonical `LedgerEntry.to_dict()` including `sequence`, `event_id`,
`event`, `previous_digest` and `digest`. Thus the leaf binds more than just the event or its old
chain hash. The version is the original ledger `"1.0"` or `"2.0"`; v1 receipts are not rehashed into v2.

For more than one leaf, split at the largest power of two **strictly less** than the number of
leaves. Hash the recursively constructed left and right subtrees. A one-leaf tree is its leaf
digest; an empty tree uses the empty domain above. No final leaf is duplicated or padded. Tree
shape is determined by the count even at odd sizes, following the unpadded binary-tree shape
described in [RFC 9162 section 2.1](https://www.rfc-editor.org/rfc/rfc9162.html#section-2.1).
This uses its mathematical shape, not copied implementation code or its protocol encodings.

Each proof lists sibling hashes from leaf toward root. Whether each sibling goes on the left or
right, and the **exact** required number of siblings, are derived from the receipt sequence and
committed count. There are no untrusted direction flags. Extra/short paths, reordered siblings,
out-of-range positions and duplicate/nonincreasing selected positions fail.

The commitment header contains exactly:

```text
kind = "evidence-braid-ledger-commitment"
schema_version = "1.0"
ledger_version
genesis
head_digest
entry_count
root_hash
commitment_digest  # Derived from all preceding fields; excluded from its own hash input.
```

The header's genesis must match the original ledger version. For zero entries, the head must be
genesis and the root must be the empty-tree digest. Empty commitments are useful anchors, but
there is no receipt to prove: `prove`, an empty `prove_page`, and empty bundles all reject.
For a singleton, the sibling tuple is empty, but the bundle still contains one receipt.

The bundle contains exactly `kind="evidence-braid-ledger-membership"`, `schema_version="1.0"`,
`commitment`, and `members`. Each member contains exactly `entry` and `siblings`. Canonical
`from_bytes()` rejects whitespace/newline variations, duplicate keys, noncanonical number spellings,
unknown fields, invalid UTF-8/surrogates, nonfinite numbers and malformed integers. `from_dict()`
works with exact built-in parsed JSON types and still rejects noncanonical receipt representations.

Verification checks the external header digest, each receipt's local chain digest, and its Merkle
path. A disclosed first receipt must follow genesis; a disclosed final receipt must equal the
header's chain head. These local boundary checks do not substitute for undisclosed chain verification.

### Fixed three-leaf vector

`tests/test_membership.py` defines three v2 events at consecutive seconds beginning
`2026-09-01T00:00:00Z`: event IDs `"0"`, `"1"`, `"2"`, claim `"claim"`, source `"source"`,
modality `"text"`, signal `"support"`, confidence `0.5`, matching observed/ingested timestamps and
empty attributes/default correlation group. Independently constructing the three leaf inputs,
one two-leaf left node and one root produces these fixed results:

```text
root:   28b8fa1d0296a6780e8028c0bb59a09a2ee04d2fb9af6d9a28b83435f3e5b1a6
anchor: f712823d691e82f919bfb0a0802fc320ccfde86e667492338ed8931d2c7243f4
```

The third leaf has one sibling; the first two have two. An independently computed four-leaf tree
formed by duplicating the third receipt has a different root, not an ambiguous encoding of three.

## Query pages and historical prefixes

`prove_page` checks that the page's head/count match its verified index and that every selected
receipt's **canonical bytes** equal the index's receipt at that position. Direct construction of a
`LedgerPage` cannot smuggle a changed event into a proof merely by claiming the correct head.

The proof intentionally omits query identity, cursor and total match count. A valid receipt can
appear in a falsely described query page, so those claims must not be laundered into cryptographic
approval. A recipient may evaluate its own predicate over the disclosed rows; it cannot conclude
that all qualifying rows were disclosed. The existing [query contract](ledger-query.md) remains intact.

For old prefixes after an append, first reopen `LedgerIndex(latest, expected_head=old_head,
prefix_count=old_count)`. That API verifies the entire supplied chain and pins the old prefix;
rebuilding its `LedgerProofIndex` gives the original commitment. Later backdated appends do not
change old proofs. This does not provide a logarithmic append-consistency proof between different
heads: that remains separate open work.

## Resource bounds and lifecycle

| Boundary | Hard limit |
|---|---:|
| Original verified index | 100,000 receipts / 64 MiB canonical receipt bytes |
| One bundle | 1–1,000 member proofs |
| One path | At most 17 sibling hashes; exact shape-dependent count required |
| Selected canonical receipt bytes, combined | 16 MiB |
| Canonical wire bundle | 20 MiB |
| Raw JSON container nesting | 72 |
| Parsed graph work, including object keys | 1,000,000 nodes |
| JSON integer | Existing attribute limit, normally 640 decimal digits |

These proof limits can be tighter than the full ledger's limits. A large indexed receipt can be
valid for the ledger yet exceed the proof budget; it is rejected, never truncated. Input bytes and
raw container depth are admitted before JSON decoding; the decoder's integer hook bounds conversion
before creating huge integers. Parsed member/path counts, graph work and aggregate selected bytes
are checked before constructing large collections of receipt objects. Python `from_dict` callers
already own their input graphs, and `json.loads` materializes the admitted bounded byte input before
graph checks; neither entry point is a hard preallocation/RSS sandbox. UTF-8 scalar admission and
canonical output checks also apply. A final wire-size check includes headers, paths and punctuation.

Proof-index construction adds O(n) cached tree nodes (at most `2*n-1`) and O(total receipt bytes+n)
hash/encoding work after the query index's existing full-chain verification. Constructing or
verifying k membership paths costs O(k log n + selected receipt bytes), with bounded canonical
serialization/validation passes. Graph admission uses iterator frames with O(depth) pending work,
not a queued tuple per child; shared aliases count again at each occurrence. Export applies the
same aggregate graph limits as import before canonical serialization. Selected receipts, parsed
JSON, canonical byte copies, the query index and cached tree can coexist. There are no wall-time,
RSS or throughput guarantees.

The API owns no files, sockets, database connections or asynchronous tasks. It does not fetch,
extract or execute proof contents. Canonical bytes are returned to callers; durable publication
or bounded file/network transport is their responsibility. No existing storage, archive or CLI
command silently changes behavior.

## Offline demonstration and reference scope

```sh
python examples/ledger_membership.py
```

The example retains an anchor before receiving the proof, selects three receipts, discards the
full ledger/index and verifies the detached canonical bundle. Tests additionally verify through a
separate Python process and reopen an old prefix after a real SQLite append.

Frozen first-party contracts used to establish the comparison surface:

- [Ledger continuous attestation](https://github.com/Perseus-Computing-LLC/ledger/blob/c51af79a70bf8863541e4232d0f2bbaea5897821/docs/continuous-attestation.md)
  calls for independently auditable inclusion and consistency proofs with retained checkpoints.
- [Ledger evidence receipts](https://github.com/Perseus-Computing-LLC/ledger/blob/c51af79a70bf8863541e4232d0f2bbaea5897821/docs/evidence-receipts.md)
  separates structural, attested, replay and inclusion evidence and warns that selected receipts omit links.
- [Itself reasoning receipts](https://github.com/Greater-Expanse/itself/blob/b6057fe96fdecdec34ec28afdffc0628549e8831/docs/REASONING_RECEIPT.md)
  distinguishes receipt shape checks from complete source-ledger recomputation.

This slice adds original detached membership, not their receipt dialects or assurance levels.
Signatures, witnessed checkpoints, key lifecycle, nonmembership/query-completeness proofs,
append-consistency proofs, packaged schema catalogs, independent non-Python verification and
proof-server deployment remain open in the [whole-repository ledger](parity-ledger.md).

## Local verification snapshot

The complete suite passed **947 tests** on both Windows/Python **3.14.5** and **3.12.0**, with
`ResourceWarning` promoted to an error and no skips. The 3.14 coverage run reached **99.01%**
combined statement/branch coverage with the unchanged 98% gate. The **103 membership cases**
reached **98.80%** combined coverage in the new module. Ruff lint/format, strict Mypy (27 source
modules), Bandit, lock consistency, wheel/sdist build, strict Twine metadata, wheel-content checks
and an isolated installed-wheel proof roundtrip passed locally.

Evidence includes independent recursive tree/path oracles over every position in 18 tree sizes,
hardcoded three-leaf root/commitment vectors, Unicode/attribute corpora, detached verification in
a separate process, real SQLite append/reopen of historical prefixes, header/receipt/path mutation,
canonical ingress rejection and admission-before-materialization sentinels. A deep, wide caller
graph regression also checks that rejected input does not allocate a per-child traversal queue.
A separate read-only review used a different frontier-stack tree algorithm for 94 root/header/
proof checks. These are implementation checks, not an external cryptographic audit, remote CI
results or whole-repository parity completion.
