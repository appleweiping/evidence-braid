# Detached ledger append consistency

`LedgerConsistencyProof` verifies that a committed receipt tree preserves the complete prefix
of another committed tree. It uses the existing [membership profile](ledger-membership.md),
including its original domain-separated hashes and unpadded tree shape. The verifier needs
**two separately retained commitment digests**, without downloading either complete ledger.
This is not a signed checkpoint, an identity scheme or a durable-commit attestation.
An [independent Node.js verifier](../verification/README.md) accepts this exact
closed envelope and both external anchors without Python or a receipt parser.
Its distinct bit/index reconstruction is tested against real Python v1/v2 proofs;
it does not generalize this profile to arbitrary JSON canonicalization.

```python
from evidence_braid import (
    LedgerConsistencyProof,
    prove_ledger_consistency,
    verify_ledger_consistency,
)

# new_index is a verified LedgerProofIndex; old_header was retained previously.
# The builder checks both the actual old-prefix root and its actual chain head.
proof = prove_ledger_consistency(new_index, old_header)
raw = proof.to_bytes()

# Both expected digests must have been established independently of incoming raw.
received = LedgerConsistencyProof.from_bytes(raw)
verify_ledger_consistency(
    received,
    expected_old_commitment_digest=retained_old_digest,
    expected_new_commitment_digest=retained_new_digest,
)
```

Successful verification returns `None`; a structural, anchor or proof mismatch raises
`ValidationError`. Parsing and immutable record construction do not verify a proof. Neither
expected digest has a default, and ordinary hash-chain heads cannot substitute for them.
The library cannot determine how the caller obtained its expected values.

## Exact envelope and hash reuse

The canonical UTF-8 JSON envelope has exactly five fields:

```text
kind = "evidence-braid-ledger-consistency"
schema_version = "1.0"
old_commitment = complete LedgerCommitment.to_dict()
new_commitment = complete LedgerCommitment.to_dict()
path = ordered array of lowercase SHA-256 hexadecimal strings
```

Each complete header has its own declared commitment digest, checked on import. Verification
recomputes both header digests and compares them with the two externally supplied values. The
existing `C` domain binds the original ledger version, genesis, head, count and root, together
with its header kind/profile version. Unknown fields and alternative spellings are rejected.
The envelope does not introduce an untrusted algorithm selector, proof-direction flags or a
producer-supplied `verified` assertion. No new proof hash or signature is needed.

All hashing is the existing profile, byte for byte:

```text
D = b"evidence-braid:ledger-membership:v1\x00"
empty root = SHA256(D || ASCII("E"))
leaf       = SHA256(D || ASCII("L") || J({"ledger_version": version, "receipt": receipt}))
node       = SHA256(D || ASCII("N") || left_digest_32_bytes || right_digest_32_bytes)
commitment = SHA256(D || ASCII("C") || J(header_without_commitment_digest))
```

`J` remains sorted-key compact Python JSON, `ensure_ascii=False`, `allow_nan=False`, encoded
as strict UTF-8 with no newline. This is neither RFC 8785 nor Certificate Transparency wire
compatibility. Existing membership bundles, ledger versions, receipt bytes and digests do not
change. The full receipt leaf binds sequence and chain digest as well as event content.

## Compact proof construction and verification

Let `m` be the old entry count, `n` the new count, and `k` the largest power of two strictly
less than the current subtree count. The proof follows the unpadded consistency-tree shape
defined in [RFC 9162 section 2.1.4](https://www.rfc-editor.org/rfc/rfc9162.html#section-2.1.4).
Its algorithm is implemented independently over this project's cached tree, not copied from
an upstream implementation or substituted with a single-receipt membership path.

The generator follows one subtree at each level. If the old prefix fits in the left child,
it recurses there and adds the new right-child root. Otherwise it recurses into the right
child and adds the shared left-child root. At the stopping subtree, it includes a root only
when that root is not already the known original old root. Hashes are ordered from the
deepest stopping subtree outward; no duplicate-last-leaf padding occurs.

The verifier reconstructs **both** roots together from that ordered path. A right sibling
updates only the newer root; a shared left sibling updates both. The required path length
and orientations follow from the two counts alone. Every hash must be consumed exactly
once in the specified route; missing, extra or reordered values fail. No unauthenticated
path flags or intermediate counts choose the traversal.

Before generating a proof, `prove_ledger_consistency` requires an exact verified
`LedgerProofIndex`. It derives the old prefix root from cached nodes and compares the
actual receipt digest at `m-1` with the retained old head. A changed old root or head is
rejected even if it is internally well formed. The full supplied ledger was already
verified by `LedgerIndex`, including when reopening a historical prefix. Existing receipts
are not serialized or rehashed again during cached proof generation.

### Empty, equal and version boundaries

- Decreasing counts are rejected.
- Both headers must have the same original ledger version and genesis. v1 remains v1;
  there is no implicit migration into v2.
- Equal counts require an empty path and **identical complete headers**, not merely equal
  roots. This includes the zero-to-zero case.
- A zero-to-positive proof has an empty path and a valid empty old header. This is explicitly
  **vacuous empty-prefix consistency**, not additional evidence about the new content.
- A positive strict extension needs the exact nonempty count-derived path. For example,
  3-to-7 uses four hashes, 4-to-7 uses one, and 6-to-7 uses three.

Genesis is a version-level constant shared by all ledgers of that version; it is not a
ledger identifier or authenticated tenant identity. A common nonempty anchored prefix is
content evidence, not proof of the parties' identities.

## What is and is not proven about the hash chain

Under the two retained commitments and SHA-256 collision/second-preimage resistance, success
establishes equality of the first `m` committed full receipt leaves, in order. Previously
committed receipt bytes cannot be silently rewritten, removed, reordered or inserted within
that compared prefix while retaining both roots. Later appends with backdated timestamps do
not alter the insertion-order prefix.

This does **not** independently revalidate every hidden new `previous_digest -> digest` link.
It also does not disclose the last leaf to independently compare that leaf's digest with the
new header's head. Correct full-ledger construction and independent establishment of the
headers remain part of the trust boundary. A dishonest publisher can bind an unrelated head
to a root in a new header; accepting that publisher's new digest without establishing its
meaning cannot be repaired by a consistency path. Tests explicitly exercise this limitation.

If boundary receipt disclosure is required, the caller can separately request and verify
existing membership bundles under the corresponding anchors. Those receipts do not replace
complete verification of the undisclosed new chain interval. This API makes no claim of
durable storage, authenticated actors, signatures, wall-clock order, global non-equivocation,
query completeness, retention, future append-only behavior or proof-server availability.
It compares only the two specific supplied commitments. Different clients can still be shown
different anchors without a separately established checkpoint/witness policy.

## Fixed receipt vector

Extend the existing membership vector to seven v2 events at consecutive seconds beginning
`2026-09-01T00:00:00Z`: IDs `0` through `6`, claim `claim`, source `source`, text/support,
confidence `0.5`, matching observed/ingested timestamps and no nondefault optional fields.
The three-to-seven proof is:

```text
old commitment:
f712823d691e82f919bfb0a0802fc320ccfde86e667492338ed8931d2c7243f4
new commitment:
aadd78975357b2e3c135995eb61163e8206b0f7c85b8229faeaa33cc60312c30
path:
ea93aa420ba78e06d7ea7cc8bd14a478ade237287780c15bc74a7eb4e10cbfb7
9211314f65191e8619a28e5683a4386e1c745365a11e7dace765b8b972a3b47c
fcec6b57f5ae99765bb77bbf1d67de06af80a15c2ed43d4d11ac90bad3513d1f
4264b4692c4efdae6054f23c7b87a3573d2ee94eb69a548ffb15898fcb251a97
```

These headers are test fixtures, not trusted anchors for any external ledger.

## Resource and ownership contract

| Boundary | Fixed ceiling |
|---|---:|
| Entry count | 100,000 per header |
| Ordered proof hashes | 18; exact count-derived length also required |
| Canonical wire input/output | 4,096 bytes |
| Raw JSON container depth | 2, counting the root object as one |
| Admitted parsed graph | At most 61 nodes including object keys |
| Header string field | At most 64 characters before header validation |
| Raw count conversion | At most 6 decimal digits before integer materialization |

The 18-hash boundary is real: an old count of 3 and new count of 100,000 requires 18 nodes.
It must not reuse the 17-sibling ceiling of a single-receipt membership proof. Complete
headers and an 18-hash path fit the fixed 4,096-byte envelope without omitting bindings.

Input byte length and raw nesting are admitted before `json.loads`. The small closed shape
is then checked before either header is constructed: exact root/header field counts, exact
built-in types, bounded path count and hash strings, bounded header strings and integer counts.
There are no arbitrary nested attributes, general graph traversals, receipts or dynamic imports.
Duplicate keys, floats/constants, invalid UTF-8, surrogates, unknown fields and noncanonical
byte encodings fail. Export checks the same shape before serialization. A `from_dict` caller
already owns its input memory; the byte parser materializes the bounded 4 KiB input before
shape checks. These guarantees are not an RSS or host-level allocation sandbox.

After the existing O(n) cached proof index has been built, prefix checking/proof generation
and detached verification take O(log n) hash operations and extra space. The original index
still retains its bounded full ledger/tree; the detached proof retains neither. No time-based
complexity guarantee, external callback, network request, file ownership or background task
is introduced. Canonical bytes are returned to the caller for transport/publication.

## Offline example and reference scope

```sh
python examples/ledger_consistency.py
```

The example establishes two anchors before receiving its detached proof, releases its
complete source ledgers/indexes, then verifies the three-to-seven extension. Tests additionally
use a real SQLite append/reopen and a separate verifier process receiving only proof bytes
and the two expected digests.

The frozen first-party [continuous-attestation contract](https://github.com/Perseus-Computing-LLC/ledger/blob/c51af79a70bf8863541e4232d0f2bbaea5897821/docs/continuous-attestation.md)
identifies independently auditable inclusion/consistency with retained checkpoints as a needed
surface. Its [integrity contract](https://github.com/Perseus-Computing-LLC/ledger/blob/c51af79a70bf8863541e4232d0f2bbaea5897821/docs/ledger-integrity.md)
distinguishes an internal chain from an independently retained anchor, and its
[receipt contract](https://github.com/Perseus-Computing-LLC/ledger/blob/c51af79a70bf8863541e4232d0f2bbaea5897821/docs/evidence-receipts.md)
separates assurance claims. This original offline slice supplies no upstream wire compatibility,
signatures, witness/key lifecycle or service deployment. The [whole-repository ledger](parity-ledger.md)
remains open; this implementation has not received an external cryptographic audit.

## Local verification snapshot

The final Windows suite passed **1,028 tests**, with no skips, on Python **3.14.5** and
**3.12.0**, promoting resource warnings to errors. Combined statement/branch coverage was
**98.98%** on 3.14, retaining the existing 98% gate. The **81 new cases** reached **98.55%**
in `consistency.py`; the two uncovered statements are private cached-tree invariant guards.

The cases compare all old prefixes at 18 selected tree sizes with independently encoded
leaves, iterative frontier roots and a separate bit/index consistency verifier. They include
the hardcoded three-to-seven vector, 1,024 single-bit path mutations, exact path lengths,
separately required anchors, empty/equal/version boundaries, rewritten history, real SQLite
append/reopen, a detached verifier process and admission-before-materialization sentinels.
The example's actual four-hash proof is **1,238 bytes**; a synthetic maximum-shape test admits
18 hashes within 4 KiB without representing that synthetic header as a verified ledger.

Ruff lint/format, strict Mypy (28 source modules), Bandit, lock consistency, wheel/sdist build,
strict Twine metadata and wheel-content checks passed locally. An isolated installed-wheel
process also generated, imported and verified a real three-to-seven proof using only the
installed public API. No dependency, version, membership wire or existing CLI/storage
behavior changed. These are local results, not remote CI, an independent cryptographic
audit, or whole-reference-repository parity.
