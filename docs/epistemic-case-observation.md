# Epistemic case observation (offline Stage B)

Stage B adds an **optional**, Python-only, synchronous execution path to the
[Stage A case journal](epistemic-case-core.md). Stage A 1.0 authority, plan,
observation, verdict and receipt bytes remain unchanged. In Stage A, callers
could declare an observed SHA-256 without possessing output bytes. Stage B's
`prepare_observation` → `run_observation` → `verify_observed_bytes` path retains
the exact adapter result and independently checks its bytes before creating a
verdict. A plain `CaseVerdict(SUPPORTED)` or `CaseState` is still not evidence
that this Stage B path ran.

The application, **not** a case document or model, creates an
`ObservationRegistry` of at most 64 immutable `ObservationAdapter` entries.
Each entry binds a test ID, adapter ID, caller-pinned version, and TOOL observer
ID to one explicit in-process callable. An entry accepts only one immutable
`bytes` input and returns exact UTF-8 `bytes`. It receives neither expected
text/hash nor model assertion/prose. The version is a declared contract label,
not a hash of executable code. No URL, module name, shell command, entry point
or environment variable from the plan is resolved or run.

`prepare_observation` checks a one-plan journal against an **externally
retained** plan head and trusted authority, rehashes bounded assertion/input
bytes, checks exact adapter identity and observer scope, then returns a
single-use prepared intent without calling the adapter. `run_observation`
atomically claims that intent in this process; a repeated or racing caller
cannot invoke its adapter again, including after failure. It snapshots the
output, validates strict UTF-8 and the Stage A XML-compatible text profile,
and appends a `CaseObservation` only after validation. Its `artifact_id`
identifies the primary output byte payload; the bytes reside in the returned
`RetainedObservation`, not in a durable artifact store. The returned artifact
inventory lists exactly the assertion, input and (only for `OBSERVED`) output
IDs and content digests. The returned object is minted by the runner and
registered by object identity for this live process. A caller-built or copied
`RetainedObservation` cannot be passed to the Stage B verifier, even if its
fields describe an internally consistent journal. This is only an in-process
provenance guard for the trusted application, not cryptographic proof that a
callback executed: code with Python introspection or control of this process
is outside the trust boundary.

`verify_observed_bytes` requires both external plan and observation heads,
rehashes each retained byte sequence, verifies the complete inventory and
adapter key, recomputes `sha256-equality-v1` from the actual output and then
appends a verdict under a separately granted evaluator. It returns a
`CheckedObservation` with owned bytes and all three checkpoints. It never
auto-generates a `CaseDecision(APPROVE)` or reinterprets procedural workflow
`APPROVED`.

Limits are independently lowerable but not raisable: 64 KiB assertion, 256 KiB
input, 512 KiB combined retained bytes, 4096-byte output, 64 registry entries.
Inputs and output must be exact built-in `bytes`; mutable bytearrays and views
are refused. Output length is checked before a second copy or hash. No
trimming, Unicode normalization, newline insertion or replacement decoding
occurs. A mismatch produces a normal `REFUTED` outcome. Explicit
`ObservationUnavailable` produces `UNAVAILABLE`/`INCONCLUSIVE`; unexpected
exceptions or invalid output become fixed-code `ERROR`/`INCONCLUSIVE`, never
support. Caller-facing observation records do not include exception text.
The cancellation token serializes `cancel()` with publication. `cancel()`
returns `True` if accepted before the observation append, including a repeated
early request; it returns `False` once the append has committed and leaves the
token unmarked. A same-thread reentrant cancellation attempt during append
raises a diagnostic error. An accepted cancellation before adapter-entry
authorization invokes nothing. One accepted after entry but before publication
reports `ObservationInterrupted`, with any safely admitted measured bytes,
and no committed observation. A cancellation attempt racing with an append
is ordered by the token lock: if the append wins, the result remains published
and the later request is refused. Cancellation cannot retract an already
published immutable journal. A failed append reports `ObservationPublicationError`
and leaves the original immutable journal unchanged; it is not an automatic
retry signal.

## Controlled executable example

The wheel includes an in-memory cache-bypass comparison:

```shell
python -m evidence_braid.examples.cache_bypass_case
python -O -m evidence_braid.examples.cache_bypass_case C
python -m evidence_braid.examples.cache_bypass_case unavailable
```

The fixture records a model-like assertion but makes no model/provider call.
Its canonical JSON incident is decoded under separate depth, node, text and
byte limits. The trusted adapter checks the incident, reads the cached report
(`revision-A`), then calls `read_report(bypass_cache=True)` to read the source
(`revision-B` by default). The expected `revision-B` is committed in the plan
before either call but is **not** passed to the adapter. Both retained input
digests and the output digest are recomputed independently before the example
prints plan, observation and verdict heads. Changing the source to
`revision-C` gives `REFUTED`; a declared unavailable source gives
`INCONCLUSIVE`. The read sequence is exposed as `[false, true]`.

This checks only that fixture environment's declared comparison. It does not
prove that an external incident, model assertion or chosen test is true or
sufficient. Trusted callback code can allocate, block or perform side effects;
this synchronous profile cannot preempt its CPU, wall time or RSS and is not
an untrusted-plugin sandbox. An application must provision trusted callbacks
and their environment. The registry/version and actor IDs are not signatures,
code attestations or identity proofs. At-most-once applies only to one prepared
intent in one live process; no crash/restart or request-ID deduplication is
claimed. No durable case CAS, closed artifact publication, witness,
non-equivocation or authenticated service is present. Those are separate
future trust boundaries.
