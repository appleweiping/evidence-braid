# Local durable-workflow commands

`evidence-braid workflow-store` exposes the [durable authority workflow](durable-workflows.md)
through six explicit local commands. It uses the same SQLite transactions, authority
replay, checkpoint CAS and idempotent request journal as the Python API. It adds no
service, authentication, hidden retry, runtime dependency or new portable bundle format.

Run `python examples/workflow_store_cli.py` for a complete offline, temporary-directory
demo using actual isolated child processes. It creates two draft claims in two requests,
recovers the first request after the second commit, and verifies anchored export. This
is a command/recovery demonstration, not an approval or external evidence truth claim.
Its checks and side effects also execute under Python's `-O` mode.

## Commands and required trust inputs

Every command requires a local DATABASE, `--authority FILE` and
`--expected-context SHA256`. Supply these from trusted configuration; a database's
self-reported context or actor declarations do not establish trust. Optional
`--timeout SECONDS` is SQLite's finite 0..60-second busy timeout, default10, not a
total command deadline. There is no implicit database creation or authority default.

| Command | Additional arguments | Successful stdout JSON |
|---|---|---|
| `create` | `--bundle FILE --expected-head SHA256` | Current `StoredWorkflow` after exclusive creation |
| `snapshot` | Optional `--expected-checkpoint FILE` | Current `StoredWorkflow` |
| `export` | Optional `--expected-checkpoint FILE` | Unchanged portable `WorkflowBundle` |
| `request-digest` | `--commands FILE --request-id ID --expected-checkpoint FILE` | Request ID, digest and exact expected checkpoint |
| `append` | Same as request-digest, plus `--expected-request-digest SHA256` | Exact `WorkflowCommit`, including historical retry |
| `lookup` | `--request-id ID --expected-request-digest SHA256` | Original `WorkflowCommit`, or JSON `null` |

For example, with caller-prepared files and retained digest values:

```sh
evidence-braid workflow-store create workflow.db --authority authority.json \
  --expected-context "$CONTEXT" --bundle initial.json --expected-head "$INITIAL_HEAD"
evidence-braid workflow-store request-digest workflow.db --authority authority.json \
  --expected-context "$CONTEXT" --commands commands.json --request-id submission-1 \
  --expected-checkpoint before.json
evidence-braid workflow-store append workflow.db --authority authority.json \
  --expected-context "$CONTEXT" --commands commands.json --request-id submission-1 \
  --expected-checkpoint before.json --expected-request-digest "$REQUEST_DIGEST"
evidence-braid workflow-store lookup workflow.db --authority authority.json \
  --expected-context "$CONTEXT" --request-id submission-1 --expected-request-digest "$REQUEST_DIGEST"
```

The shell placeholders above must be replaced with independently retained, validated
digests. The executable example creates its own synthetic inputs and needs no shell
configuration. A checkpoint file is the exact `WorkflowCheckpoint.to_dict()` document,
not an entire snapshot or commit. Commands have this closed versioned envelope:

```json
{
  "schema_version": "1.0",
  "transitions": [
    {
      "transition_id": "create-1",
      "action": "create",
      "actor_id": "author",
      "scope": "demo",
      "claim_id": "claim-1",
      "expected_revision": 0,
      "statement": "A draft claim for authorized review.",
      "reference_id": null,
      "reference_digest": null,
      "reason": null
    }
  ]
}
```

All six commands use the fixed default store resource profile. The first CLI does
not expose configurable store limits. JSON rejects duplicate/unknown keys, invalid
UTF-8, nonfinite numbers, malformed models and unsupported versions. IDs use the
existing 1..128-character ASCII authority grammar; digests are exact lowercase SHA-256.
The commands list contains 1..1,000 existing transition documents. A valid request
digest proves representation and identity, **not permission or future CAS success**.

Unlike the pure helper on an already configured Python store, the request-digest
CLI opens and verifies the existing database before computing its digest. The
append CLI recomputes and compares the mandatory external digest before writing.
An old expected checkpoint is retained for historical retry, not imposed as the
constructor's current anchor. Identical retry remains valid after later appends;
changed same-ID intent and new stale requests conflict. No automatic rebase occurs.

Snapshot/export's optional checkpoint is exact-current, not a historical selector.
The create report is a separate verified **current** read after acknowledged creation:
a concurrent writer can advance it. It is not an invented receipt of initial creation.
Lookup `null` means verified absence in this currently opened store. Failed opening
or corrupt storage is not absence. Policy/context alone cannot detect valid rollback;
retain complete checkpoints outside the writable database's trust boundary.

## File and representation bounds

| Boundary | Maximum |
|---|---:|
| Command-family arguments | 40 tokens; 32 KiB combined characters and UTF-8 bytes |
| Authority file | 4 MiB |
| Initial bundle file | 64 MiB |
| Commands file | 8 MiB; core canonical whole-request admission still applies |
| Checkpoint file | 8 KiB |
| Encoded stdout result, including its final LF | 64 MiB + 64 KiB |

Files must be observed local regular nonsymlink/nonreparse files. Protocol/UNC
spellings are rejected. No parents are implicitly created. Device/file identity,
size and modification time are checked around bounded 64-KiB binary reads; accepted
bytes must equal the observed length. Missing/unavailable identities, replacement,
growth, truncation and invalid reader blocks reject. Every acquired handle is closed,
with original control exceptions preserved over secondary cleanup failures. Ancestor
resolution, native filesystem scheduling and trusted Python runtime behavior are
not hostile-filesystem atomicity guarantees.

There is no stdin, URL, arbitrary SQL, plugin, import/eval or output-file publishing
interface. Complete output is serialized before stdout as compact sorted-key finite
UTF-8 JSON plus one LF. These bounds admit logical representations, not hard RSS,
encoder temporary memory, total CPU time or a scan-time bound. The existing replay
complexity and cumulative append costs still apply. `--help` is argparse's immediate
nonexecuting action after argument-budget admission; no operation is performed.

Native stdout/stderr use their binary buffer explicitly, avoiding locale encoding
and Windows newline translation without reconfiguring or closing the caller's text
wrapper. In-process callers supplying text-only streams receive the same logical
string; those callers own any subsequent external encoding/translation.

The shell owns redirection. It may truncate a target **before** this process starts;
never redirect over a database or input. Checked stdout writes and flushes detect
incomplete delivery but cannot retract an already emitted prefix. Preserve stdout
only on successful command delivery, and retain recovery identity independently.

## Failure, acknowledgement and recovery

Exit0 means command plus result delivery succeeded (`lookup null` is successful).
Exit2 means argument/intent/storage/resource/delivery failure. Ordinary stderr is
one bounded fixed-message JSON diagnostic with `code`, `outcome`, and admitted
`request_id`/`request_digest` when available. Raw payloads, paths and exception prose
are not echoed. Successful exports intentionally contain caller data; this error
redaction is not encryption. Diagnostic delivery itself is best effort and cannot
turn failure into exit0.

The outcome is `none`, `unknown` or `complete`, following the core's acknowledgement
contract. Once creation or append has returned successfully, a later snapshot,
serialization, stdout short-write or flush failure remains **complete**. The CLI
never deletes that database or treats missing output as rollback. Ordinary core
storage exceptions retain their explicit outcome. Controls such as KeyboardInterrupt
and SystemExit propagate with their original identity and core notes. If a control
interrupts an unreturned mutating call or historical-request lookup, the outer CLI
conservatively adds `unknown`
rather than inventing `none`; more precise core notes remain intact. An acknowledged
complete outcome is never downgraded by a later control or read failure.

A returned found lookup carries `complete` into later result delivery, matching
the core's positively verified historical-request outcome; returned `null` keeps
`none`. An interrupted lookup's outer `unknown` means its request acknowledgement
did not return, not that this read-only lookup performed a write. Precise core
notes remain available without the CLI parsing exception prose.

Before append retain ID, exact checkpoint, ordered commands and request digest.
For unknown/complete acknowledgement, reopen and use lookup with that ID/digest.
Do not invent a new request ID just because output was lost. For uncertain creation,
open existing storage and compare independently retained context/head/checkpoint;
do not overwrite or unlink it. There are no per-command network retries or background
workers. Service deployment, authenticated actor custody, policy migration and the
entire [reference-repository objective](parity-ledger.md) remain separate open work.
