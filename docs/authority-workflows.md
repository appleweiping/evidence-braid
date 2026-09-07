# Authority-checked claim workflows

The workflow layer records **who was declared to authorize which procedural
change**, under a separately supplied authority policy. It does not infer claim
truth from approval, authenticate people, or replace the evidence-fusion engine.
It uses an independently written, deliberately small contract rather than a
compatibility implementation of another protocol.

Run the complete offline example:

```sh
python examples/authority_workflow.py
```

It writes a real observation to `SQLiteLedger`, reopens the committed evidence
snapshot, binds that receipt and an artifact commitment to a claim, collects two
independent approvals, exports a workflow bundle, and replays it with retained
heads. Its temporary files are isolated and cleaned up. The output explicitly
states that actor authentication was not provided.

## Trusted inputs and threat boundary

`AuthorityPolicy` must come from a caller-trusted source independently of the
bundle being evaluated. It declares typed `WorkflowActor` identities, human or
automation kinds, exact `ScopeGrant` roles, and a required approval quorum.
`replay_workflow` and serialized bundle ingestion require this policy explicitly.
There is no embedded bundle policy silently promoted to trust.

- An actor ID is a **name**, not a credential or signature. The caller must
  authenticate submitters and map each name to a real principal before relying
  on these permissions operationally. Human/automation kinds are declarations,
  not something this library can establish.
- Separate names do not prove separate people. The trusted registry must prevent
  aliases from satisfying separation of duty. No service authentication,
  signatures, tokens, tenant isolation, policy revocation service, or external
  identity discovery is implemented here.
- Public hashes bind bytes, not authorship or truth. An attacker able to replace
  the whole bundle can rewrite permitted actor names and recompute hashes. A
  separately retained `expected_head` detects that replacement and valid-prefix
  truncation. Without an external anchor there is no rollback resistance.
- Evidence is bound by existing ledger entry digest, exact event ID and claim,
  and `event.attributes["workflow_scope"]`. This opt-in producer declaration is
  committed by the evidence receipt. It is not inferred from a source name, and
  missing or different scope is rejected. The unchanged event schema still
  accepts ordinary unscoped observations for the existing evaluation API.
- Artifact metadata commits to ID, scope, claim, SHA-256, byte length and media
  type. A declaration does not establish that bytes are available. Call
  `bundle.verify_artifacts({artifact_id: bytes, ...})` to check an exact manifest
  inventory separately. No paths are opened and no network requests are made.

The bundle contains the full evidence snapshot and all transition statements,
reasons, and actor IDs. It is **not** a redacted disclosure format. Only share it
with parties authorized to see that material.

## State and authorization contract

Scope and identity strings are case-sensitive ASCII identifiers of 1–128
characters. Allowed characters after the first alphanumeric are letters,
digits, `.`, `_`, `:`, `/` and `-`. There are no wildcards, prefix matching,
hierarchical grants, or implicit owner privileges.

| Action | Required scoped role | Preconditions | Result |
|---|---|---|---|
| `create` | author | New globally unique claim ID within this workflow, revision 0, non-empty statement | Draft at revision 1; creator recorded as author |
| `bind_evidence` | author | Draft; matching evidence ID, ledger entry digest, claim and committed scope; no duplicate | Adds immutable evidence reference and contributing author |
| `bind_artifact` | author | Draft; matching manifest ID, content digest, claim and scope; no duplicate | Adds immutable artifact reference and contributing author |
| `submit` | author | Draft with at least one bound evidence entry and artifact | Submitted; content frozen; submitter also recorded as author |
| `approve` | reviewer | Submitted; declared human; neither an author nor a prior voter | Records one approval; becomes approved only when quorum is reached |
| `reject` | reviewer | Same independence rules as approval; non-empty reason | Terminal rejected state, retaining any earlier approval history |
| `revoke` | revoker | Approved; declared human; not an author or approver; non-empty reason | Terminal revoked state |

Every successful action increments the claim revision exactly once. Every
non-create intent must supply the current `expected_revision`, even for a
partially approved claim. A reviewer cannot vote twice or approve and then
reject the same submission. Quorum is an integer from 1 to 16. Registry
validation does not guarantee enough independent reviewers are available.

No attachment can be changed or appended after submission. Rejected/revoked
claims cannot be reopened in this contract; start an explicitly new claim if
new work is required. The statement itself cannot be edited. All contributors,
including an automation that prepared material, remain in the immutable author
set. Automation may author when granted permission but cannot review or revoke.

Approval is procedural: it does not check whether an observation supports or
contradicts the claim, run score thresholds, determine scientific adequacy, or
establish that an artifact is accurate. Human reviewers remain responsible for
the content. The pre-existing `evaluate` API retains its original behavior and
is not silently called by this state machine.

## Receipt envelope and offline replay

`build_workflow(workflow_id, authority=..., evidence=..., artifacts=(...),
transitions=...)` creates a bundle. `bundle.append(intents, authority=...)`
returns a new, fully replayed bundle or raises `ValidationError`; the original
is never changed. Transition IDs are unique across the complete workflow.
Receipts preserve supplied order rather than sorting by timestamp.

The context SHA-256 covers a canonical JSON object with kind/version,
workflow ID, authority digest, evidence ledger head, and sorted artifact
manifest. The first predecessor is that context digest. Each receipt digest
covers schema version, contiguous sequence, context digest, predecessor digest,
and the **entire transition**. The workflow head is the final receipt digest,
or the context digest when empty.

Evidence receipts remain `EvidenceLedger` records; workflow operations are not
encoded as fake observations and cannot accidentally become scoring evidence.
All evidence bytes in the embedded ledger are independently verified by its
existing v1/v2 verification rules. The exact evidence snapshot and authority
policy are frozen for the life of a context. Changing either, or changing the
artifact manifest, requires a new workflow context; migration/linkage of such
contexts is not implemented in this increment.

`WorkflowBundle` construction checks structural integrity. Authorization is a
separate explicit operation, `replay_workflow(bundle, authority=trusted_policy)`.
`WorkflowBundle.from_dict` and `load_workflow_bundle` perform both checks before
returning. Unknown fields, invalid scalar types, noncanonical derived metadata,
duplicate transition identities, unresolved/mismatched references, out-of-order
revisions and unauthorized transitions fail closed. No partial replay state is
returned on error. `WorkflowState` exposes a read-only claim mapping and detached
JSON serialization.

```python
bundle = load_workflow_bundle(
    "workflow.json",
    authority=trusted_authority,
    expected_head=retained_workflow_head,
    expected_evidence_head=retained_evidence_head,
)
state = replay_workflow(bundle, authority=trusted_authority)
```

The CLI performs the same offline authorization, with **explicit** policy input:

```sh
evidence-braid workflow-replay trusted-authority.json workflow.json \
  --expected-head RETAINED_WORKFLOW_SHA256 \
  --expected-evidence-head RETAINED_EVIDENCE_SHA256
```

CLI output includes claim statements and identities. Do not treat it as a
privacy-minimized receipt. A bad input emits an error and no partial state.

## Persistence, resource bounds and limitations

`write_workflow_bundle` authorizes first, writes a temporary file in the target
directory, flushes and `fsync`s its contents, then atomically replaces the named
destination. A failure before replacement leaves the old file intact. Parent
directories must already exist. Directory-metadata durability after power loss
is platform-dependent and is not promised. This is **not compare-and-swap**:
two writers may replace each other's valid bundles. Revision checks protect
replay semantics, not concurrent filesystem publication. Use one workflow
publisher until a transactionally persisted workflow service exists.

Limits are 256 actors, 128 grants per actor, 1,024 artifact commitments, 10,000
workflow receipts and a 64 MiB serialized bundle. Each statement/reason is at
most 8,192 characters; each declared artifact is at most 64 MiB. Input JSON uses
bounded reads and rejects duplicate keys, non-finite numeric literals, overflow
to infinity, and malformed UTF-8. Existing evidence limits apply as well.

Bundles and replay state are materialized, not streamed. Append revalidates the
complete prior bundle, chain and state; whole-bundle JSON serialization allocates
temporary representations. `MAX_WORKFLOW_BYTES` is checked **after materializing
and serializing** Python-API construction input; it is not a process-RSS cap.
File loading applies its byte limit before parsing. These ceilings constrain
accepted values but are not a constant-memory or throughput claim. Caller-supplied artifact bytes are
already allocated by the caller; their aggregate allocation is not managed by
this API. This lane supplies no file-tree bundle publisher, content-addressed
artifact store, workflow database, distributed concurrency protocol or durable
authority-registry migration.

The hand-authored cases in `tests/fixtures/workflow-cases.json` specify accepted
and rejected histories. Additional tests include an independent hash oracle,
permission forgery with recomputed hashes, exact scope/claim/reference binding,
cross-workflow transplant, revision replay, terminal states, immutable outputs,
portable process-boundary replay, and failed-publication preservation. Tests
also demonstrate the deliberately unsupported authentication/rollback claims.
