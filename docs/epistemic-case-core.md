# Epistemic case core (original wire 1.0)

This optional pure-Python core records one scoped model/human assertion, one
predeclared prediction and named test, a declared observation, a deterministic
digest-comparison verdict, and a separately authorized decision. It is
**independent of** the older procedural `WorkflowBundle` and its
`DRAFT/SUBMITTED/APPROVED` statuses. A procedural approval is never silently
reinterpreted as support for a hypothesis.

`CaseAuthority` declares exact-scope actor grants: `PROPOSE`, `OBSERVE`,
`EVALUATE`, `DECIDE`. Model actors can only propose. Only a tool actor may
observe, and the evaluator must be distinct from both proposer and observer.
A decision must come from a separately granted human or policy actor. These
names and actor kinds are **declarations**, not cryptographic identities.
The caller must obtain the authority policy independently of the journal.

The plan stores committed hashes of the assertion and input artifacts, a
human-readable hypothesis/prediction, an exact `expected_observation_text`
value and its `prediction_sha256` byte hash, and
an adapter ID/version and fixed `sha256-equality-v1` comparison profile. These
fields do not themselves run an adapter. An `OBSERVED` record names a committed
observation artifact hash; `UNAVAILABLE` and `ERROR` instead carry a bounded
error code. A supported verdict means only that the **declared** observed digest
equals the plan's expected digest. Different digest means refuted under this
exact-byte test; unavailable/error means inconclusive. Only supported verdicts
may receive an `APPROVE` decision. `REJECT` or `DEFER` do not certify support.
The digest must match `SHA256(expected_observation_text.encode("utf-8"))`. The
exact text may be empty or contain significant whitespace; no Unicode
normalization, trimming, added newline or replacement decoding occurs. The
human-readable `prediction` remains explanatory prose, not the machine
comparison target. The core cannot check that this prose honestly describes
the exact expected value, nor that the assertion, input or observation bytes
actually exist. Those are review, retained-byte and external-execution
obligations for later stages.

Use `CaseJournal.empty(authority).append((plan,), authority=authority)` to
obtain the plan checkpoint **before** recording the observation. Later append
observation, verdict and decision with `expected=journal.checkpoint`. The
in-memory append is atomic from the caller's point of view: it returns a new
immutable journal or raises without changing the old one. `replay_case` checks
the entire history and an optional independently retained expected head. A
roundtrip through `CaseJournal.from_bytes(raw, authority=trusted,
expected_head=retained_head)` requires canonical closed JSON, a contiguous
hash chain, valid plan/observation/verdict/decision bindings, exact authority
and a valid deterministic state transition. Typed record `from_bytes` methods
also validate the corresponding bounded wire independently.

The case wire is original to Evidence Braid. Each record has an exact `kind`
and `schema_version: "1.0"`. Canonical JSON is compact, sorted-key, strict
UTF-8, no trailing newline. Duplicate keys, floats/nonfinite numbers, unknown
fields, excessive nesting/nodes/text and oversized wires are refused. SHA-256
digests use domain `b"evidence-braid:epistemic-case:v1\0"`: authority is
`H(D || "A" || canonical-authority)`, genesis is
`H(D || "G" || authority-digest-bytes)`, and receipt `n` is
`H(D || "R" || uint32be(n) || prior-digest-bytes || canonical-record)`.
The plan/observation/verdict/decision content digests use the same domain and
distinct one-byte `P/O/V/D` tags. This is neither Itself's wire nor a signature.

## Deliberate Stage A limit

No external test, model endpoint, callback, subprocess, HTTP request, durable
case store, service route, or artifact bundle integration exists in this core.
The caller can **invent** an observation hash and then obtain a structurally
valid supported case. Neither `CaseObservation`, `CaseVerdict`, `CaseState` nor
a journal proves the bytes exist, the named test ran, the result is true, or
the actors are who they claim. A hash-chain's internal order is not proof of
real-world timing; without an externally retained plan checkpoint, a producer
can fabricate the full history retrospectively. Do not use this Stage A verdict
as an autonomous approval gate. The separate retained-byte checker in
[`claim-checks.md`](claim-checks.md) does recompute its own fixed predicates
over supplied bytes; it does not make this new case a live observation.

The optional [offline Stage B runner](epistemic-case-observation.md) now binds
a trusted, registered synchronous adapter to retained observation bytes and
independently verifies them. It does **not** retroactively strengthen a bare
Stage A `CaseObservation` or verdict. Later stages must add durable
checkpoint/CAS recovery and verify case artifacts alongside an independently
pinned workflow/evidence bundle.
Any public/hosted service, signed/witnessed checkpoints, identity proof or
claim of factual truth needs a separate reviewed trust contract.
