# Durable epistemic case CAS (local Stage C)

`SQLiteCaseStore` persists **one** planned Stage A case in a new local SQLite
database. It adds a full store checkpoint, a hash-linked operation journal,
an execution claim that commits before a trusted callback is entered, and
exact assertion/input/output BLOB retention. Existing Stage A 1.0 records and
receipts are unchanged. This is a local Python API, not a service or artifact
bundle format.
Run `python -m evidence_braid.examples.durable_case` (also valid under
`python -O`) for a wheel-installed, offline create → claim → execute → reopen
→ checked-verdict smoke.

```python
from evidence_braid import SQLiteCaseStore, create_case_store

# authority, planned_journal, assertion, test_input, registry are supplied by
# your trusted application. planned_journal has exactly one CasePlan.
store = create_case_store(
    "case.db",
    planned_journal,
    authority=authority,
    expected_plan_head=planned_journal.head_digest,
    assertion_bytes=assertion,
    input_bytes=test_input,
)
before = store.snapshot().checkpoint
claim_digest = store.claim_request_digest(registry, request_id="run-1", expected=before)
finished = store.execute_observation(
    registry,
    request_id="run-1",
    finish_id="finish-1",
    expected=before,
)
reopened = SQLiteCaseStore(
    "case.db",
    authority=authority,
    expected_plan_head=planned_journal.head_digest,
    expected=finished.result.checkpoint,
)
checked = reopened.append_checked_verdict(
    operation_id="verdict-1",
    evaluator_id="independent-evaluator",
    expected=finished.result.checkpoint,
)
```

The trusted application supplies the same closed in-process Stage B
`ObservationRegistry` at execution time. No callable is serialized or resolved
by name, URL, shell, environment variable or case document. The bridge
preflights the plan/authority/registry and input commitments, atomically
claims the request, **acknowledges the claim**, then invokes the selected
callback once in that process. A duplicate or stale claim cannot invoke it.
The callback's output is admitted under the Stage B strict UTF-8 and text
profile; invalid output becomes fixed-code `ERROR` and then `INCONCLUSIVE`.
The callback receives only the committed test input bytes, not the prediction.

`claim_observation` and `finish_observation` also expose the explicit protocol
for applications that manage invocation themselves. Directly supplying bytes
to `finish_observation` is a caller assertion, **not** proof that the registered
adapter ran. The trusted bridge has process-local execution provenance, not a
signature or proof against malicious in-process code. Its returned bytes are
durably retained only once `finish_observation` commits. On a bridge storage
failure after a valid callback output, `CaseStoreError.observed_bytes` carries
the owned measured bytes when available; callers must preserve them and
inspect the store before any manual finish attempt.

## Exact state and retention

The store format has its own SQLite application ID and `user_version=1`, closed
schema and canonical versioned context, operation and checkpoint documents.
Every read replays Stage A records under independently supplied authority,
validates all operation links and checks stored byte commitments. The full
`CaseStoreCheckpoint` contains context digest, Stage A count/head, operation
count/head and a monotonic generation. A claim increments the operation count
and generation even though the Stage A journal remains at its plan head.
Every mutation requires the exact current full checkpoint; `BEGIN IMMEDIATE`
serializes writers across processes. At most one of two claimants with the
same checkpoint can win. A separately retained latest checkpoint is needed
to detect a coherent older copy or alternate fork; the store's own hashes
alone cannot do that.

The fixed `case-store/1` limits are one imported plan, one claim, one finish,
one checked verdict; three Stage A receipts and three store operations total.
Each operation document is at most 8192 bytes, aggregate operation documents
at most 24 KiB, each receipt at most 20 KiB, aggregate receipt documents at
most 2 MiB, context/meta documents at most 8192 bytes each. Assertion and
input BLOBs are at most 64 KiB and 256 KiB respectively; measured output is
at most 4096 bytes and the aggregate retained BLOB limit is 512 KiB. There is
no compaction, deletion or decision append in this version. Unknown store
format, schema or version fails closed; migration must be explicit and is not
implemented.
Before reading SQLite metadata values into Python, the store admits at most
15 schema objects, with each schema type/name/SQL text at most 16/128/1024
UTF-8 bytes respectively (and corresponding 15-row aggregate caps). Payload
role/artifact ID/digest TEXT fields are limited to 16/128/64 bytes each over
at most three rows, with aggregate caps of 48/384/192 bytes. Operation IDs are
at most 128 bytes each over at most three rows (384 bytes aggregate). TEXT
types are checked before row fetch. Unknown, oversized or mistyped metadata
fails closed before large strings can be returned to Python.
These caps bound values fetched into Python, not SQLite parser or allocator
memory while opening a hostile database file; use an app-owned, private DB.

Unlike the standalone Stage B runner, this first store profile accepts only
the default `ObservationLimits`; per-registry lower ceilings are not persisted
in the claim format and therefore are rejected rather than forgotten after
restart.

For an `OBSERVED` finish, the exact output BLOB, artifact ID, output SHA-256,
observation receipt, operation and checkpoint commit in one SQLite
transaction. `UNAVAILABLE`/`ERROR` have no output BLOB and yield an
`INCONCLUSIVE` checked verdict. Reopen independently rehashes assertion,
input and output bytes before a verdict operation; a caller-supplied
`SUPPORTED` value and Stage B's process-local `RetainedObservation` identity
are never treated as restart evidence. The output artifact ID identifies the
stored primary payload only; Stage D closed bundle publication is separate.

## Crash recovery and limits of the guarantee

Retain operation IDs, full expected checkpoints and, where available,
`claim_request_digest`/`finish_request_digest` **outside** the writable store
before mutation. `lookup(id, expected_request_digest=...)` verifies the full
current store and returns the original historical result; changed digest
conflicts. `lookup_operation(id)` is a discovery-only recovery aid after a
bridge crash when the output-dependent finish digest was never delivered;
compare its returned bytes and digest to any separately retained intent. It
does not authorize re-execution.

`CaseStoreError.outcome` is `none` (no COMMIT attempted), `unknown` (COMMIT
attempted without acknowledgement), or `complete` (COMMIT returned but later
delivery/cleanup failed). Even if a test callback returned bytes, a failed
finish is **not** a recorded observation until reopen confirms it. A claimed
request with no finished observation stays unresolved after restart; no
automatic callback retry, verdict, or claim takeover occurs. This deliberately
avoids duplicate invocation at the cost of liveness. A new investigation
requires a new case/precommitment; this version does not adjudicate an
uncertain claim in place. SQLite cannot atomically commit foreign callback
effects, so the API does not promise exactly-once external side effects.
Mutation calls are deliberately **not** idempotent-returning: repeating an
existing operation ID, even with identical input, conflicts. Resolve an
uncertain acknowledgement through `lookup` or `lookup_operation`; neither
method invokes the callback or writes a new operation.

The store enforces declared role/scope grants, not actor identity. It is not
a hostile-process filesystem sandbox, signature, non-equivocation witness,
rollback-proof log, service authentication layer, hard callback time/memory
limit, or proof that a real-world assertion is true. Directory metadata power
loss and network-filesystem guarantees are not claimed.
