# Durable evidence ledger

`SQLiteLedger` stores a verified append-only chain across process boundaries.
Its storage uses Python's SQLite module and needs no server or third-party
runtime dependency. The original evaluation, replay and adjudication APIs keep
their existing semantics; the store supplies a persistent input history.

## Python workflow

```python
from evidence_braid import SQLiteLedger, load_ledger, write_ledger
from evidence_braid.io import load_events

store = SQLiteLedger("evidence.db")
before = store.snapshot()
committed = store.append(load_events("events.jsonl"), expected_head=before.head_digest)
write_ledger("evidence.json", committed)

# A separate process may open this same file later.
reopened = SQLiteLedger("evidence.db", create=False)
assert reopened.snapshot(expected_head=committed.head_digest) == committed

# Import preserves the original record order, hashes and schema.
copied = SQLiteLedger("evidence-copy.db").import_snapshot(load_ledger("evidence.json"))
assert copied == committed
```

`append` preserves caller order, including late-arriving observations whose
ingestion timestamps precede existing records. `build_ledger` remains an offline
canonical ordering operation: it sorts by ingestion time and event ID before
building a chain. These operations consequently need not produce the same head
for differently ordered inputs. Neither operation changes event timestamps.

Use `EvidenceEvent.from_dict(entry.to_dict()["event"])` to reconstruct input
events from a verified snapshot and pass them to `evaluate` or `replay`. The
executable `examples/durable_ledger.py` demonstrates persistence, export/import
and identical evaluation results using the repository's existing scenario.

## CLI

```bash
evidence-braid ledger append evidence.db examples/events.jsonl
evidence-braid ledger verify evidence.db
evidence-braid ledger export evidence.db --output evidence.json
evidence-braid ledger import restored.db evidence.json
```

All commands accept `--expected-head SHA256` and `--output PATH`; `-` means
stdout. For append the supplied head is the expected current database head; for
import it is the expected incoming snapshot head. Verify and export compare it
to the read snapshot. Append creates a missing store; verify and export refuse
missing stores. Import requires an empty store. Verification errors exit with
code `2`. Export refuses a destination referring to the database itself.

The JSON summary emitted by append describes the transaction that committed.
A failure writing that summary to a destination does not undo the database
commit: callers should inspect the store before retrying. Duplicate event IDs
are errors, including identical payloads; they never silently overwrite data.

## Transaction and concurrency contract

Each operation opens and closes its own connection. Independent threads and
processes may append to the same database. `BEGIN IMMEDIATE` serializes writers;
the whole existing chain is verified while holding the write lock. The batch
and metadata head/count commit together or roll back together. A failed
uniqueness constraint partway through a batch leaves no inserted prefix.
SQLite synchronous mode is `FULL`; crash recovery and filesystem persistence
still depend on SQLite and the operating system honoring their durability
contracts. Use local filesystems with functioning SQLite locks.

`expected_head` is an optional compare-and-append precondition. Concurrent
writers using one head produce one accepted append and a stale-head failure for
the other. Without it, both successful transactions append in lock-acquisition
order. Reading uses one transaction so metadata and rows cannot represent
different committed states. The default busy timeout is 10 seconds, configurable
from 0 through 60; lock timeouts are domain errors, with no implicit retry.

The API has no mutation/delete operation and database triggers reject ordinary
SQL updates/deletes of entries. These are accidental-modification protections.
An operator with database-file access can drop triggers or replace the file.

## Receipt integrity and versions

New chains use ledger schema `2.0`. Each SHA-256 digest binds a canonical JSON
object containing `schema_version`, zero-based `sequence`, `previous_digest`
and the complete event. The first predecessor is
`sha256(b"evidence-braid-ledger:v2")`. Canonical encoding uses sorted keys,
compact JSON separators, unescaped Unicode, finite numbers and UTF-8. This is
the project's existing Python canonical JSON format, not an RFC 8785 claim.

The strict deserializer checks exact fields, types, known schema, contiguous
sequence, unique event IDs, canonical event representation, every digest, the
declared head and count. Nested event data is recursively frozen and each
`to_dict()` returns detached JSON values. Duplicate JSON keys and non-finite
numbers are rejected before model construction.

`EvidenceLedger.from_dict` and `load_ledger` also read schema `1.0` receipts
using their original digest algorithm and preserve their heads. v1 is read-only
for SQLite import. To place v1 events in a v2 store, explicitly reconstruct the
events and append them; retain the original receipt and record the mapping if
both heads matter. There is no silent upgrade or rehash.

A chain is internally consistent evidence, not proof that an observation is
true or that its claimed source signed it. A complete valid replacement and
its recomputed head pass internal verification. A valid prefix also passes.
An independently retained **trusted head** detects replacement or rollback
relative to that retained state. Storing a head beside the same writable
database does not create an independent trust anchor. No signatures, external
witness, replicated consensus or rollback-resistant storage are provided here.

## Resource and performance bounds

| Boundary | Limit |
|---|---:|
| One ledger | 100,000 entries |
| One append call | 10,000 entries |
| One stored canonical event | 1 MiB UTF-8 |
| Sum of stored canonical event payloads | 64 MiB |
| A portable JSON import/export document | 64 MiB |

The portable document also contains chain metadata, so a store near its payload
limit can exceed the export limit. Export then fails explicitly without
replacing a destination. Split applications into separately anchored ledgers
before reaching that boundary; there is no implicit truncation or pagination.
Deserialization also enforces existing event attribute depth/node limits.

Snapshot and append verification read the complete chain: O(n) records and
O(total payload bytes) memory, plus hashing/JSON work. Repeated single-record
append has quadratic cumulative verification cost. Batch appends reduce that
cost; this implementation makes no high-throughput or distributed-ingestion
claim. The byte and entry ceilings bound accepted histories, not arbitrary
filesystem size or database corruption scan time.

## Validation evidence

`tests/test_durable_ledger.py` covers independently computed digest input,
v1 compatibility, canonical round-trips, nested mutation, malformed records,
tampering, trusted-head rollback detection, separate-process and threaded
writers, process death before commit, partial-batch rollback, busy timeout,
resource ceilings, unrelated database protection, CLI round-trip, and unchanged
evaluation of reconstructed records. The complete existing suite remains the
regression gate for scoring and historical replay.
