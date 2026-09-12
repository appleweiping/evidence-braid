# Independent Node receipt and membership verification

`verification/ledger-membership.mjs` verifies the existing Python canonical receipt
and selected-membership formats without Python, npm dependencies, filesystem access
or network calls. It works offline on Node.js 22 or later. It complements, rather
than replaces, the [two-anchor consistency verifier](ledger-consistency.md).

```javascript
import { verifyLedgerMembership } from "./verification/ledger-membership.mjs";

const verified = verifyLedgerMembership(receivedBytes, {
  expectedCommitmentDigest: independentlyRetainedDigest,
});
console.log(verified.entryCount, verified.members.map(member => member.sequence));
```

The caller must obtain and authenticate the expected commitment independently.
Reading an anchor from the incoming bundle and supplying it back is not a trust
check. An evidence ledger's chain head is not its Merkle commitment digest.

The result and its `members` array are frozen. Each member contains `sequence`,
`eventId`, `receiptDigest` and `previousDigest`; the outer result contains
`ledgerVersion`, `entryCount` and `commitmentDigest`. No mutable or lossy event
graph is returned. IDs may still be sensitive application data; do not publish
results indiscriminately. Invalid wire or anchor values throw
`LedgerVerificationError` with static diagnostics, not input contents.

## Complete existing canonical wire

The independent byte reader retains original UTF-8 spans and numeric lexemes.
It does not deserialize a receipt through ordinary JavaScript `JSON.parse` and
then hash a potentially rounded reconstruction. After canonical and semantic
admission, hashes consume the exact original event and receipt byte spans.

- Integers up to 640 decimal digits are admitted as `BigInt`, never through a
  temporary `Number`. Integer, float and boolean wire types remain distinct.
- Finite binary64 floats use the existing Python spelling. Exact adjacent-value
  rounding intervals, shortest decimal candidates, nearest/ties-even selection
  and notation checks are independently implemented with bounded integer
  arithmetic. Scientific thresholds, exponent signs/padding and integral `.0`
  are checked. Attribute `-0.0` is preserved; confidence zero must be `0.0`.
- Strict UTF-8 and XML 1.0 scalar admission reject invalid encodings, forbidden
  controls and lone surrogates. Strings are not Unicode-normalized. Object key
  ordering uses Unicode code points, not JavaScript UTF-16 sort order.
- Duplicate keys, alternate escapes, redundant whitespace, BOM, trailing bytes,
  reordered fields and noncanonical numbers are rejected. `U+FEFF` inside a
  string is ordinary preserved data, not an envelope BOM.
- Closed receipt/event field sets, event-ID binding, modalities, signals and
  confidence are checked. Empty attributes and absent correlation groups must
  be omitted. Canonical identifiers use Python's whitespace membership, not
  JavaScript `trim()`. Dates use checked Gregorian UTC with either no fraction
  or exactly six nonzero-as-a-group microsecond digits.

This is neither RFC 8785/JCS nor general Python serialization. It implements
the complete **existing Evidence Braid receipt profile**, including its richer
integer and float domain. No Python production wire, schema catalog, old golden
bytes or dependency/version is changed.

## Hash and proof checks

The [membership profile](ledger-membership.md) specifies exact domain separation.
The verifier checks the header's version/genesis relationship, count, empty-tree
rules, canonical commitment hash and external anchor. It verifies each selected
receipt's v1/v2 chain digest and requires strictly increasing in-range positions.

The unpadded tree shape is determined solely by the committed count and selected
position. Every sibling must be consumed at that exact bottom-up orientation.
Reconstructed leaves bind the complete receipt, ledger version and sequence.
Selected sequence zero must follow genesis; a selected last receipt must match
the committed head. Extra/missing paths and alternate tree shapes are rejected.

For independently retained individual receipt context:

```javascript
import { verifyLedgerReceipt } from "./verification/ledger-membership.mjs";

const receipt = verifyLedgerReceipt(receivedReceiptBytes, {
  ledgerVersion: "2.0",
  expectedReceiptDigest: retainedReceiptDigest,
  expectedPreviousDigest: retainedPreviousDigest,
  expectedSequence: retainedSequence,
});
```

All four options are mandatory. The v1 receipt hash **does not bind sequence**.
Its supplied sequence is checked against the separate caller context; this does
not retroactively authenticate sequence in the legacy hash. Membership leaves
do bind sequence in both ledger versions. No standalone verifier is allowed to
choose its own expected receipt digest from untrusted bytes.

## Resource and trust boundaries

Inputs must be native `Buffer`/`Uint8Array` views. Native typed-array getters and
a bounded native copy bypass shadowed instance length/buffer/iterator hooks.
Proxy-wrapped, detached and non-byte views are rejected. The application-owned
options object should contain ordinary fields, not hostile getters or proxies;
application getter exceptions are not disguised as invalid-wire errors.

Limits preserve the existing profile: 20 MiB envelope; 16 MiB individual and
aggregate selected receipt bytes; 72 envelope container levels and at most depth
72 graph values; 64 full-event nesting depth; one million graph nodes including
object keys; 1..1000 members; at most 17 siblings; at most 100000 ledger entries.
The full-event bound also constrains nested attributes. Integer tokens and float
lexemes are bounded before arbitrary-precision conversion/formatting work.

These are protocol-work limits, **not** VM heap/RSS or hard execution-time limits.
Parsed node objects, byte snapshots and strings incur runtime overhead beyond
the input byte count. Processing is synchronous; applications receiving hostile
traffic must arrange their own scheduling/worker isolation and admission policy.
The module does not sandbox global intrinsics replaced before import. Hash
equality is ordinary comparison of public commitments, not constant-time secret
authentication. No external cryptographic audit is claimed.

Membership proves only selected receipt inclusion under the supplied commitment.
It does not check hidden receipt chain links or undisclosed ID uniqueness, prove
query completeness/non-membership, establish append-only consistency, identify a
sender, authenticate evidence truth, provide signatures or guarantee durability.
An attacker able to replace both data and its externally trusted anchor can
construct a coherent replacement. Authentication and anchor retention are caller
responsibilities, not implicit properties of SHA-256.

## Independent tests and distribution

Run `python examples/cross_runtime_membership.py` for an offline Python-producer /
Node-verifier example with Unicode, an integer beyond JavaScript's safe range,
negative zero and three sparse selected positions. Only detached wire bytes and
the retained anchor cross into Node; no Python ledger/parser crosses with them.

```sh
node --experimental-test-coverage --test --test-concurrency=1 --test-coverage-include=verification/ledger-membership.mjs --test-coverage-include=verification/receipt-wire.mjs --test-coverage-include=verification/receipt-numbers.mjs verification/ledger-membership.test.mjs verification/receipt-wire.test.mjs verification/receipt-numbers.test.mjs
python -m pytest tests/test_node_membership.py tests/test_node_membership_numbers.py
```

The Node suite has independently hand-built 1/3/5-leaf trees and fixed sparse
100000-count routes, byte/node limits, typed-array hook cases, semantic mutation
and v1/v2 checks. A separate Python process supplies `repr()` expectations for
more than 19000 signed finite binary64 vectors, including every binary exponent
boundary and decimal-power neighbors. Bit roundtrip alone is not a Python
canonical-spelling oracle. Real Python producers test both ledger versions at
all positions across ragged and power-of-two sizes, relocated modules and
recomputed-hash semantic forgeries.

The wheel ships `ledger-membership.mjs`, `receipt-wire.mjs` and
`receipt-numbers.mjs` together at `evidence_braid/verification/`; retain their
relative layout when copying them. The latter two are private implementation
modules, not general serialization APIs. The sdist includes modules, Node and
Python tests, documentation and the example. Node remains optional for
Python-only users, but CI explicitly requires the interoperability tests.
