# Deterministic checks of retained artifacts

`CheckPlan` evaluates five fixed predicates over committed bytes.
`verify_claim_checks` separately combines recomputation with the existing
authority-checked workflow. `APPROVED` still means that the required independent
human reviewers approved the history, not that retained inputs pass a plan.
No scoring or quorum rule changed.

No callbacks, commands, expressions, user regexes, model calls or network requests
are executed. This is not a general test runner or truth oracle. `ok == true`
establishes that property of committed JSON, not that a producer performed an
experiment or described the outside world correctly. Meaningful predicates and
trustworthy input provenance remain the policy owner's responsibility.

## Ordered plan and exact predicates

A plan pins workflow ID, exact scope/claim ID, SHA-256 of the statement's UTF-8
bytes, authority digest, complete evidence-ledger head and input references.
References include ID, scope, claim, media type, size and SHA-256. Every declared
input must be used. Inputs are canonically sorted by ID; rule order is retained
and contributes to the hash. Inputs/rules are nonempty and have unique IDs.

Paths are immutable tuples of string object keys and nonnegative integer array
indices. `()` selects the root; `("items", 0)` differs from `("items", "0")`.
Bool is not an index; empty string keys work. Missing keys, out-of-range indices
and incompatible intermediate containers yield a private missing value, not null.

| Operator | Contract |
| --- | --- |
| `EXISTS` | Selected path exists, including null/objects/arrays. Missing is known false: **FAIL**. |
| `EQUALS` | Scalar equals explicit scalar literal with identical type. Missing is **UNKNOWN**; object/array is **UNKNOWN/type_unsupported**. |
| `INTEGER_RANGE` | Exact lexical integer is within inclusive endpoints. Missing/noninteger type is **UNKNOWN**. |
| `SAME_VALUE` | Two paths have equal scalars with identical types. Missing/structured operand is **UNKNOWN**. |
| `BYTES_EQUAL` | Complete retained byte strings match. No JSON parsing or normalization. |

Integers lie in `[-9007199254740991, 9007199254740991]`. True never equals 1;
null is an ordinary scalar. Decimal/exponent numeric tokens, even `1.0`/`1e0`,
are rejected. There is no floating-point tolerance or recursive object equality.
JSON rules require media type exactly `application/json`; binary-only rules
accept arbitrary bytes under the declared media type.

JSON is strict UTF-8: duplicate keys, nonstandard numeric constants, unpaired
surrogates and XML-invalid control characters are rejected. Strings/object keys
are at most 65,536 characters, expected literals 4,096 and path keys 256.
The complete document must satisfy the profile, including unvisited fields.
Invalid JSON/configuration raises; it is not a failed predicate. All rules run
in order unless an error aborts. Aggregate FAIL takes precedence over UNKNOWN,
which takes precedence over PASS. Empty/all-skipped plans cannot pass.

## Noncircular external trust binding

1. Independently choose authority, input commitments and the plan.
2. Evaluate actual immutable bytes; retain canonical plan/evaluation as distinct
   ordinary artifact references.
3. Freeze input/plan/evaluation references into the workflow context; bind all
   to the claim before submission and review.
4. Separately retain `CheckPolicy` and final workflow/evidence heads. Policy pins
   workflow, claim, scope, authority, plan artifact ID/digest and evaluation ID.
5. Call `verify_claim_checks` with those trusted values and retained bytes.

The plan excludes final workflow head and evaluation commitment, preventing a
plan/result/context hash cycle. Neither metadata artifact may be a plan input.
Both must be bound JSON artifacts on the claim, and every input must exactly
match its bound workflow reference. The supplied mapping must contain exactly
plan, evaluation and inputs; unrelated claims may exist in the workflow.

The gate replays original authority/state preconditions, then snapshots a bounded
plain dict of **exact immutable bytes**. That same snapshot supplies hashes,
parsing, predicates and report comparison. It recomputes the complete evaluation
and compares canonical bytes. A forged PASS report is rejected even when its
artifact hash, context and reviewer receipts have been coherently rebuilt.

`CheckedClaim.accepted` requires procedural APPROVED and recomputed PASS. Valid
FAIL/UNKNOWN or submitted/revoked state returns false. Wrong heads/bindings,
mutated bytes, malformed metadata and exhaustion raise without partial results.
A stale approved head cannot replace an independently pinned revoked head.

`CheckEvaluation`/`CheckedClaim` are immutable **output descriptions**, not trust
certificates: anybody can construct them or serialize accepted=true. Replaying
and recomputing with external pins establishes the result. Actor names are still
declarations, not signatures/authenticated people. Replacing both policy and
heads can authorize another history. Hashes are not confidentiality or rollback
prevention.

## Resource accounting, not a process sandbox

All limits are positive exact integers with compiled ceilings.

| Limit | Default | Ceiling |
| --- | ---: | ---: |
| Inputs, excluding two gate metadata files | 16 | 64 |
| Rules | 64 | 256 |
| Each retained file, including gate metadata | 1 MiB | 4 MiB |
| Total retained bytes, including gate metadata | 4 MiB | 16 MiB |
| JSON container nesting | 16 | 32 |
| Shared parsed JSON value nodes | 100,000 | 500,000 |
| Check work units | 32 Mi | 256 Mi |
| Canonical plan bytes | 64 KiB | 256 KiB |
| Evaluation and complete gate output, each | 64 KiB | 256 KiB |

Policy wire bytes have a fixed 4,096-byte cap. Gate plan, inputs and claimed
evaluation share one node/work budget. Each JSON input parses once; repeated
comparisons still consume work. The Python API accepts already-materialized
bytes; CLI count/per-file/aggregate checks bound file accumulation.

Work units are specified accounting units, **not** CPU instructions, wall time,
RSS or every internal hash/Unicode/encoding operation. Charges include plan and
report bytes, input hash/JSON bytes, parsed values and rules, path visits/key
lengths, scalar string lengths, byte comparisons, and gate metadata/comparison/
output work. They increase monotonically. Exhaustion raises `CheckLimitError`,
never UNKNOWN/PASS, and returns no partial evaluation.

Byte and lexical nesting bounds precede parsing. Node count is checked **after
`json.loads` materializes the bounded document**, not before every allocation.
Python plan construction also checks canonical size after bounded fields are
materialized. Trees, encoding and Python objects use more memory than raw bytes.
Legacy workflow replay keeps its separate 64 MiB/10,000-record profile; its work
is outside check-work units. No hostile-filesystem, native-RSS or hard-time
sandbox is claimed.

## API, CLI and offline example

```python
evaluation = evaluate_checks(plan, {"input-id": retained_input_bytes})
checked = verify_claim_checks(
    workflow,
    authority=independently_trusted_authority,
    policy=independently_trusted_check_policy,
    contents=all_retained_input_plan_and_evaluation_bytes,
    expected_head=retained_final_workflow_head,
    expected_evidence_head=retained_evidence_head,
)
```

`parse_check_plan`/`parse_check_policy` require exact canonical UTF-8 JSON: sorted
keys, compact separators, no trailing newline, closed fields and schema version
1.0. Plans also require engine `retained-integer-scalars-v1`. Existing schema
publication `wire-1` is unchanged: new check records are **not** additional
catalog entries. No old artifact/workflow/ledger/proof wire format changes.

```sh
python examples/offline_claim_checks.py new-check-demo
```

The example refuses an existing directory, writes canonical plan/result and
two inputs, constructs approvals, packages actual bytes using the existing
closed ZIP and independently verifies it. It emits the recomputed checked claim.
Demo output provides heads; real exchanges must retain anchors independently.

```sh
evidence-braid checks evaluate new-check-demo/plan.json \
  --expected-plan-digest YOUR_TRUSTED_PLAN_SHA256 \
  --artifact analysis=new-check-demo/analysis.json \
  --artifact expected=new-check-demo/expected.json

evidence-braid checks gate new-check-demo/authority.json \
  new-check-demo/workflow.json new-check-demo/check-policy.json \
  --expected-head YOUR_TRUSTED_WORKFLOW_HEAD \
  --expected-evidence-head YOUR_TRUSTED_EVIDENCE_HEAD \
  --artifact analysis=new-check-demo/analysis.json \
  --artifact expected=new-check-demo/expected.json \
  --artifact plan=new-check-demo/plan.json \
  --artifact evaluation=new-check-demo/evaluation.json
```

CLI emits canonical report JSON to stdout. Exit 0 means PASS/accepted; 1 means
valid non-PASS/not-accepted; 2 means invalid input/binding/limits. Default fixed
limits apply. Primary local-file checks reject protocol/UNC locators and observed
linked/reparse/special files. Higher ancestors and filesystem mutation remain
trusted-environment boundaries. No URL fetching or extraction occurs.

Reports include IDs, hashes and outcomes, not selected values. Plans may contain
sensitive expected literals; outcomes/hash fingerprints reveal information.
Use nonsecret IDs. New parse diagnostics do not echo offending JSON; CLI also
sanitizes old workflow-loader errors. This does not erase caller-held bytes,
traceback locals or caller-written data.

## Remaining scope

This supplies real fixed retained-content verification, not an export wrapper.
Arbitrary oracle adapters/programs, live experiments, floats/structural
predicates, inferred truth, cryptographic signatures/actor identity, services,
reference wire equivalence and whole-reference-repository parity remain open.
