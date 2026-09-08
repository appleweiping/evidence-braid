# Independent Node.js consistency verification

`ledger-consistency.mjs` is a dependency-free ES module for Node.js 22 or later.
It verifies the same canonical two-anchor append-consistency envelope emitted
by the Python API, using an independently implemented iterative bit/index
algorithm. It never starts Python, loads receipts, accesses files or networks,
or chooses an expected anchor from incoming proof data.

```javascript
import { verifyLedgerConsistency } from "./ledger-consistency.mjs";

// raw is a Buffer/Uint8Array received through your application's transport.
// Both expected values must be established independently of raw.
const result = verifyLedgerConsistency(raw, {
  expectedOldCommitmentDigest: retainedOldDigest,
  expectedNewCommitmentDigest: retainedNewDigest,
});
console.log(result.oldEntryCount, result.newEntryCount);
```

Success returns a frozen record containing the two verified counts and expected
commitment digests. Failure raises `ConsistencyVerificationError` with static
diagnostic text, not proof contents. Invalid wire data and anchor values use
the same error class. The options object is application-owned: supply ordinary
string-valued fields, not hostile getters or proxy hooks.
The verifier is stateless and synchronous; no callback or background task is
introduced. It takes a bounded copy of the caller's byte view before decoding.
Byte-view admission uses native typed-array getters and a native copy, not
shadowable instance properties, conversion hooks or iterators. Detached,
non-byte and proxy-wrapped views are rejected. The module does not sandbox a
host application that replaces built-in intrinsics before importing it.

## Exact profile

The [Python profile](../docs/ledger-consistency.md) specifies the domains, complete
headers, unpadded tree, ordering, empty/equal cases and anchors. This module has
the same 4,096-byte envelope, two-container depth, six-digit integer admission,
100,000-entry count and 18-hash path ceilings. It validates strict UTF-8 and the
complete closed shape, recomputes both header commitments, compares external
anchors, and reconstructs both roots. Every path node must be consumed in the
count-determined position.

Canonical spelling is checked against the exact received text after admission.
Duplicate fields, alternate key order/escapes, whitespace, BOM, trailing input,
unknown fields, floats/exponents, negative zero and malformed hashes are rejected.
Canonicalization is intentionally limited to this closed ASCII header/proof
format. It does **not** implement general Python JSON serialization, RFC 8785,
receipt/event parsing or JavaScript conversion of arbitrary event integers and
floats. Such event data are already bound by the opaque receipt-tree roots.
The Python producer/ledger remains responsible for their full semantic checks.

Input and parse memory are bounded by the small wire profile; Node's VM/runtime
memory, caller buffers and allocator overhead are outside that limit. Count/path
arithmetic stays within 100,000, safely inside JavaScript's integer/bitwise range.
Hash work and additional proof state are O(log n). No constant-time or hard
execution deadline claim is made. Hash comparisons use ordinary equality; these
public commitments are not secret authentication tokens.

## Assurance boundaries

The two anchors must already have a trustworthy application meaning. This module
does not authenticate the sender, guarantee durable storage, compare independent
witnesses or detect global equivocation. An empty-prefix proof is vacuous.
An equal-size proof requires identical complete headers. For a strict extension,
root consistency does not independently revalidate every hidden new receipt's
chain link, or prove an undisclosed last leaf matches the new header's head.
The tests explicitly preserve this limitation. Neither implementation has
received an external cryptographic audit.

## Tests and distribution

From the repository root, with Node.js 22.8 or later:

```sh
node --experimental-test-coverage --test --test-coverage-include=verification/ledger-consistency.mjs --test-coverage-lines=98 --test-coverage-functions=100 --test-coverage-branches=95 verification/ledger-consistency.test.mjs
python -m pytest tests/test_node_consistency.py
```

The JavaScript suite constructs synthetic trees with a separate recursive proof
generator and iterative frontier roots, checks all 2,211 prefix pairs through
65 leaves, then exercises bit mutations and malformed envelopes. These synthetic
headers are protocol fixtures, not independently verified receipt ledgers.
Separate sparse-subtree fixtures cover high index bits and seven prefixes up to
the full 100,000-entry limit without allocating a complete synthetic ledger.

The Python interoperability suite builds real v1/v2 ledgers containing Unicode,
300-digit integers and small floats, emits detached proofs and verifies them in
a separate Node process. Only proof bytes and the two anchors cross that process
boundary, never Python source, the ledger or its receipt parser. It covers all
484 old/new-prefix combinations at 14 selected sizes, then real proof path
mutations and wrong anchors. Node is optional for Python-only installations;
the repository CI explicitly requires it, so these tests cannot silently skip
there.

The source distribution contains this directory and tests. The wheel also ships
the standalone module at `evidence_braid/verification/ledger-consistency.mjs`;
it does not install Node or change any Python runtime dependency. The project MIT
license applies. No npm package, network service or new version is published by
this increment.
