# Durable authority workflows

`SQLiteWorkflowStore` persists the existing authority-checked workflow lifecycle
with explicit compare-and-append and durable request identity. It is a local
Python core API, not an HTTP service or a new CLI. It needs no server or added
runtime dependency. The existing workflow, evidence v1/v2, artifact and scoring
formats and meanings are unchanged.

Run the self-contained example with `python examples/durable_workflow.py`.
It creates temporary storage, submits evidence and an actual artifact commitment,
records two independent reviews, reopens by full checkpoint, recovers an earlier
request, and exports the unchanged portable workflow format.

## Creation, append and read

```python
from evidence_braid import SQLiteWorkflowStore, create_workflow_store

# initial is an existing WorkflowBundle; policy comes from your trusted configuration.
store = create_workflow_store(
    "workflow.db",
    initial,
    authority=policy,
    expected_context=initial.context_digest,
    expected_head=initial.head_digest,
)
before = store.snapshot()
digest = store.request_digest(commands, request_id="submission-1", expected=before.checkpoint)
commit = store.append(commands, request_id="submission-1", expected=before.checkpoint)
assert commit.request_digest == digest

# Retain this full checkpoint outside the writable store's trust boundary.
anchor = commit.result.checkpoint
reopened = SQLiteWorkflowStore(
    "workflow.db",
    authority=policy,
    expected_context=initial.context_digest,
    expected=anchor,
)
assert reopened.snapshot(expected=anchor) == commit.result
```

The constructor only opens existing storage. Creation exclusively reserves a
new local file and requires an existing parent directory; it never overwrites
an existing file or follows a database symlink/reparse point. The creator checks
the complete initial bundle against separately supplied authority, context and
workflow head before reserving a file. Imported nonempty history is supported:
the operation genesis binds its exact record count/head, without inventing
request IDs for imported records.

The policy is snapshotted and fixed for each store object. Every read replays
the existing workflow integrity and permission engine with this policy. Cached
heads, database-supplied policy declarations and stored final states are not
trusted. Actor names/kinds remain **unsigned declarations, not authentication**;
APPROVED means independent procedural review, not measured truth.

`WorkflowCheckpoint` contains context digest, record count, workflow head,
operation count and operation head. `StoredWorkflow` combines that checkpoint
with an immutable bundle; `WorkflowCommit` contains request ID/digest, the
previous checkpoint, and the exact committed `StoredWorkflow`. Their `to_dict()`
results are detached. `WorkflowCheckpoint.from_dict()` accepts only its closed
versioned representation and revalidates types and bounds.

An optional read/open `expected` means **exact current checkpoint**, not an
allowed historical prefix or a minimum revision. It is checked on that operation;
subsequent reads need their own anchor if desired. Context alone only verifies
internal consistency: a valid rolled-back or alternate same-context branch can
pass. Independently retaining the full checkpoint also distinguishes an imported
copy with the same workflow head but a new operation genesis. Storing the anchor
next to the same writable database does not establish an independent witness.

## Transaction and idempotency

`append` and `request_digest` share the same pre-lock admission. Commands must be
an exact nonempty tuple/list of exact immutable `WorkflowTransition` objects,
within the configured count and complete canonical request-byte bounds. Input is
snapshotted before opening a connection. Caller iterators and conversion hooks
do not execute under SQLite locks. Request IDs are 1..128-character ASCII
identifiers using the existing authority identifier grammar. The full expected
checkpoint is mandatory; there is no unconditional append.

`BEGIN IMMEDIATE` serializes writers. A single transaction checks the closed
schema and byte bounds, verifies the complete workflow and operation history,
and authorizes the whole candidate batch using the existing lifecycle engine.
All output rows and the return object are constructed before the first INSERT.
Receipts, operation record and head metadata commit atomically. A late permission,
reference or revision denial writes nothing; a later SQL failure rolls back the
whole uncommitted prefix. Each operation owns and closes its connection.

A request digest binds the domain/version, request ID, **full expected checkpoint**
and ordered commands. Request lookup occurs before the current-head CAS check.
An identical retained request returns its exact original committed prefix, even
after later appends; changed commands, order or checkpoint with the same ID raise
`WorkflowConflictError`. A new request ID with a stale checkpoint also conflicts.
There is no implicit merge, rebase or automatic retry. Callers can deliberately
reread the new state, reconsider permissions/revisions, and submit a new intent.

`lookup(request_id, expected_request_digest=digest)` verifies the complete current
store, then returns the original commit or `None`. A different digest conflicts.
The supplied digest binds what the caller intended, not merely what that ID now
claims. `request_digest(...)` performs no database access, enabling retention
before an uncertain append. It checks representation, not current ACL permission
or current head; append still validates both under the lock.

## Recovery and failure outcomes

`WorkflowStorageError` carries `outcome`, `request_id` and `request_digest` when
applicable. Transition payloads are not included in its message.

| Outcome | Meaning | Caller action |
|---|---|---|
| `none` | This operation never attempted COMMIT; rollback/close are attempted for owned connections. | Inspect the cause; resolve the failure before retrying. |
| `unknown` | COMMIT was attempted but acknowledgement did not return. The data might be committed. | Reopen and look up the previously retained request ID/digest. |
| `complete` | COMMIT returned, or a previously committed identical request was verified; subsequent cleanup/delivery failed. | Do not assume rollback; recover the exact historical result by lookup. |

Before writing, retain request ID, expected checkpoint, commands and the digest
in a caller-controlled recovery record. A `None` lookup after successful verified
reopen means that request is not in the current store; retries still use the
original ID/checkpoint/commands. Storage unavailability or corrupt history is not
proof of absence. Control exceptions (`KeyboardInterrupt`, `SystemExit`) propagate
with outcome notes and take priority over ordinary cleanup failures. A cleanup
failure never changes an acknowledged commit into a claimed rollback.

Failed creation deletes only its own identified, closed reservation when no
COMMIT was attempted and no sidecar remains. Foreign replacements, uncertain or
acknowledged creation commits, and incomplete cleanup remain for inspection.
Connection setup can fail after acquiring a connection but before handing it to
the transaction owner. Such failure conservatively retains the reservation even
if the setup helper may have closed it; the owner has no close acknowledgement.
If body and cleanup both raise control exceptions, the original control survives.
Reservation, open and cleanup require exact bounded integer device/file IDs with
a positive file ID. Unavailable/zero or malformed file identity fails closed;
an unidentified reservation is retained, never treated as proof of ownership.
After a possibly committed creation, use an existing-only open and compare the
trusted initial context/head or genesis checkpoint before deciding what to do.

SQLite uses synchronous `FULL`. The busy timeout is finite 0..60 seconds (default
10); no hidden retry is performed. Crash recovery and durability depend on SQLite
and the operating system honoring local filesystem locks. File identity checks
detect replacements across opens but do not promise atomic defense against a
hostile filesystem racing every operation. This is not distributed consensus,
hardware rollback protection, signatures or authenticated actor custody.

## Journal and resource contract

The private database format has a fixed application ID/version, four closed
tables and immutable-history triggers. Triggers prevent accidental SQL updates,
not a file owner's deliberate rewrites. Schema count/metadata lengths, exact SQL
schema, all table BLOB types/counts/lengths and request-ID SQL bounds are checked
before any document payload is selected. Canonical UTF-8 JSON rejects duplicate
keys, malformed Unicode, non-finite numbers and noncanonical representations.

Operation records bind consecutive disjoint receipt ranges, from the imported
initial head through the current head. Their request digests are recomputed from
those actual transitions; no second multi-megabyte command copy is stored.
Hashes are domain-separated SHA-256 over compact sorted-key finite Python JSON,
the existing project canonical format, **not RFC 8785**. Counts, ranges, request
IDs, predecessor digests and final metadata must all match replay.

Every `WorkflowStoreLimits` field has an independently lowerable positive integer
hard ceiling. Lower limits also apply when reopening or retrying existing history.

| Field | Default / maximum |
|---|---:|
| `max_bundle_bytes` | 64 MiB, both portable bundle and context + stored receipts |
| `max_records` | 10,000 |
| `max_receipt_bytes` | 256 KiB |
| `max_append_records` | 1,000 |
| `max_request_bytes` | 8 MiB |
| `max_operations` | 10,000 |
| `max_operation_bytes` | 8 KiB |
| `max_operations_bytes` | 16 MiB |

Successful snapshots remain exportable under the existing 64 MiB portable bound.
Bounds admit logical representations, not arbitrary database-file scan time or
a hard RSS/CPU limit. Reads verify O(history + encoded payload) work; only one full
workflow bundle is constructed, plus one selected historical prefix for lookup
or retry. They do not materialize a bundle per old operation. Repeated individual
appends still have quadratic cumulative replay work; batching reduces it. No
persistent secondary index, high-throughput capacity claim, policy migration or
reference-backend equivalence is provided by this bounded local increment.

The focused tests include an independent direct-sqlite3 hash/range audit, real
spawned writers and process death before commit, old lifecycle conformance,
anchor/fork tests, corruption/budget admission, commit acknowledgement recovery
and owned cleanup faults. Full-suite/platform/package and independent review
are separate acceptance steps, not implied by these focused results.
