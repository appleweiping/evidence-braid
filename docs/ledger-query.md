# Anchored ledger queries

`LedgerIndex` verifies an immutable receipt chain once and indexes its event ID,
claim, source, modality, signal and correlation group. `LedgerQuery` selects
exact matches and observation/ingestion intervals. `LedgerSelection` retains
the selected positions for bounded pagination without rerunning the complete
query or holding a database lock. Filtering is not adjudication or truth evaluation.

```python
from datetime import UTC, datetime
from evidence_braid import LedgerIndex, LedgerQuery, Modality, SQLiteLedger

snapshot = SQLiteLedger("evidence.sqlite", create=False).snapshot()
# Obtain retained_head separately when replacement/rollback detection matters.
selection = LedgerIndex(snapshot, expected_head=retained_head).select(
    LedgerQuery(
        sources=("camera-west", "camera-east"),
        modalities=(Modality.VISION,),
        ingested_start=datetime(2026, 9, 1, tzinfo=UTC),
        ingested_end=datetime(2026, 9, 2, tzinfo=UTC),
    )
)
page = selection.page(limit=100, max_entry_bytes=4 * 1024 * 1024)
if page.next_cursor is not None:
    next_page = selection.page(cursor=page.next_cursor, limit=50)
```

## Exact matching and clocks

Fields combine with AND; each nonempty tuple combines its values with OR. Empty
tuples impose no restriction. Matching is exact and case-sensitive, with no
wildcard/regex/SQL expression expansion. Query text must already be in the
normalized form stored by `EvidenceEvent`; surrounding whitespace is rejected.
Tuple order is canonicalized and duplicates fail. Python enum filters require
typed `Modality`/`Signal` members.

Each clock has optional inclusive start and exclusive end boundaries: `[start,
end)`. Datetimes must be timezone-aware and are normalized to UTC. Equal/reversed
two-sided intervals fail. Both clocks filter independently; results always retain
ledger sequence order, even when event timestamps go backward. Missing groups
do not match a requested correlation group, but an empty filter includes them.
Filtering specifically for absent groups, confidence ranges, attribute expressions,
full-text search and aggregate queries remain open.

## Stable historical prefixes

The index owns an immutable prefix, not a live database connection. Later appends,
including backdated events, cannot enter its selection. Page metadata includes
the prefix head/count, query identity, total matching count, exact receipt-byte
accounting and continuation token.

Keep the trusted head, prefix count, query and cursor to resume after restart:

```python
restored = LedgerIndex(latest_ledger, expected_head=old_head, prefix_count=old_count).select(
    original_query
)
page = restored.page(cursor=saved_cursor)
```

The complete supplied chain must still verify. Its requested prefix must end at
the retained head; replacement, shortening, a corrupt tail or wrong count fails.
An empty prefix requires that version's genesis. Both v1/v2 receipts remain their
original version. Omitting `prefix_count` selects the complete snapshot and hence
rejects a stale head after an append.

`SQLiteLedger.snapshot()` closes its consistent read transaction before indexing.
This API does not create persistent SQL indexes or avoid reading/verifying the
stored chain initially. Standalone CLI invocations repeat that work; reuse a
Python index/selection for repeated pages within one process.

## Continuation and trust

Canonical unpadded base64url JSON tokens bind ledger version, head/count, query
digest and next ledger sequence. Wrong query/head, unknown fields, duplicate keys,
altered schema/encoding, malformed numbers, Unicode and base64 fail. Page count/
byte limits may change between calls. End of selection returns `next_cursor=None`,
including an empty result.

Tokens are unsigned and unencrypted. A client can construct a valid token selecting
a later position; they are not secret capabilities or proof of earlier-page
consumption. Do not use them as authentication, tenant isolation or complete-export
proof. A separately trusted head is required to detect replacement/rollback;
copying a head from the same untrusted input proves only internal consistency.

A filtered page may omit intervening links and is not an independent cryptographic
inclusion/completeness proof. Its source index verified the complete chain. A
recipient can retain that chain and anchor, or use the separate
[detached membership API](ledger-membership.md) with an independently retained
Merkle commitment. That API proves selected receipt membership, not query completeness.
Direct `LedgerPage` construction checks structure/derived byte counts, not query
membership or trust.

## Bounds and work

- Complete supplied chain: at most 100,000 receipts and 64 MiB of canonical receipt
  bytes, even when reopening a smaller prefix. Sizes are checked before chain
  verification/indexing. Each size calculation serializes a receipt, and Python
  caller inputs are already materialized; this is not a hard preallocation sandbox.
- Each text filter: at most 128 values, 4,096 UTF-8 bytes per value and 64 KiB across
  all text filters. These limits can be tighter than the event text model.
- Page: 1–1,000 receipts, default 4 MiB / ceiling 16 MiB of canonical receipt bytes.
  `entry_bytes` sums compact receipt encodings, excluding page-envelope JSON,
  array punctuation, cursor and encoder overhead; it is not whole wire size.
- If the next receipt alone exceeds the byte budget, raise without skipping it.
  Otherwise return the fitting prefix and a cursor for the first unreturned match.
  Individual receipts are never silently truncated.
- Cursor input: at most 2,048 ASCII characters before decoding.

Index construction processes the bounded chain and builds six inverted indexes,
linear in payload size plus entries. Exact-filter postings are combined before
time checks; selection can still inspect/sort all entries. Positions are retained.
Paging binary-searches its continuation and checks/serializes only page receipts,
plus bounded query/cursor metadata. Receipts, parsed events, indexes, positions
and output copies can coexist. These are representation/work limits, not fixed
RSS, hard runtime bounds or storage-throughput guarantees.

Pages expose actual event payloads/attributes. No redaction or logging is automatic;
review fields before sharing them. Arbitrary application code is still trusted.

## CLI and offline demonstration

```sh
python examples/ledger_query.py
evidence-braid ledger-query evidence.sqlite --expected-head RETAINED_SHA256 \
  --source camera-west --source camera-east --modality vision \
  --ingested-start 2026-09-01T00:00:00Z --ingested-end 2026-09-02T00:00:00Z --limit 50
```

The demo creates a temporary SQLite ledger, retains a page, appends a backdated
event, reopens and resumes the old prefix. Exactly the original five receipts
remain while the latest store contains six. Its temporary data are removed.

The CLI requires an existing database/head and writes one compact page to stdout.
There is no destination option that could overwrite the database. Available
filters: repeatable `--event-id`, `--claim`, `--source`, `--modality`, `--signal`,
`--correlation-group`, and `--observed-start`, `--observed-end`, `--ingested-start`,
`--ingested-end`. Continuation uses `--prefix-count`, `--cursor`, `--limit` and
`--max-entry-bytes`. Errors produce no successful page, although an output-device
failure can interrupt response writing.

Persistent secondary indexes, authenticated HTTP/MCP exports, signed cursors,
query-completeness proofs, retention/compaction, richer query operators and
reference-comparable persistent workloads remain open.

## Verification snapshot

The full Windows / Python 3.14.5 suite passed 844 tests with 99.03% combined
branch-aware coverage; `query.py` reached 100% statement/branch coverage. The 56
new cases include an independent 120-query seeded scan oracle, both clocks,
UTF-8 byte boundaries, immutable views, historical-prefix reopening, concurrent
writer/readers, malformed cursors, strict public records and CLI failures.
Separate read-only review checked 57 additional prefix/filter/page oracles and
rejected 2,450 single-character cursor mutations. It also confirmed that a newly
forged canonical later-position cursor is accepted, consistent with the explicit
unsigned/non-authentication contract. No remote-service or throughput comparison
is inferred from these checks.
