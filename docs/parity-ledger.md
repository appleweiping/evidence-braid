# Whole-repository parity ledger

Audit date: 2026-09-07. Status: **OPEN**. This is a scoped engineering ledger
against frozen upstream repositories, not a declaration of completed parity.
Reference names identify comparison inputs; the implementation in this project
was independently written. No upstream source was copied.

## Frozen comparison inputs

| Repository | Frozen commit | Git tree inventory |
|---|---|---|
| [Greater-Expanse/itself](https://github.com/Greater-Expanse/itself/tree/b6057fe96fdecdec34ec28afdffc0628549e8831) | `b6057fe96fdecdec34ec28afdffc0628549e8831` | 227 blobs; 90 Python files; 41 `tests/` blobs; 10 `docs/` blobs |
| [Perseus-Computing-LLC/ledger](https://github.com/Perseus-Computing-LLC/ledger/tree/c51af79a70bf8863541e4232d0f2bbaea5897821) | `c51af79a70bf8863541e4232d0f2bbaea5897821` | 256 blobs; 157 Python files; 86 test-path blobs; 53 `docs/` blobs |

Inventories were read through GitHub's recursive Git tree API with
`truncated=false`; Python counts include tests and experiments. Test-path counts
are files, not executed assertions. These inventories describe scale only.
README claims and source paths establish candidate comparison surfaces; each
future parity closure still requires a specific behavior contract and tests.

The first-party [Itself README](https://github.com/Greater-Expanse/itself/blob/b6057fe96fdecdec34ec28afdffc0628549e8831/README.md)
describes typed assurance protocol records, authority-checked state transitions,
deterministic replay, portable evidence bundles, receipts, offline schemas and
provider-compatible inference. The first-party [Perseus README](https://github.com/Perseus-Computing-LLC/ledger/blob/c51af79a70bf8863541e4232d0f2bbaea5897821/README.md)
describes persistent event provenance, SDK/HTTP/MCP access, receipts, attestation,
resource attribution and deployable services. Evidence Braid's current decision
engine covers a useful subset of these behaviors; the full surface is broader.

## Capability-by-capability work ledger

| Surface and reference source | Current Evidence Braid evidence | Status and next acceptance work |
|---|---|---|
| Immutable typed evidence and strict inputs (`itself/records.py`, `validation.py`) | `models.py`, plus new `authority.py` actor/grant/transition/artifact types | Partial: typed scoped authority and procedural claim records now exist; generalized hypotheses, predictions, test plans and richer epistemic records remain open. |
| Evidence-backed authorized transitions (`itself/state.py`, bundle conformance fixtures) | New `workflow.py`: exact-scope roles, immutable claim lifecycle, independent review/revocation, per-claim revisions and hand-authored conformance cases | Implemented bounded original procedural slice; richer epistemic states, context migration, lifecycle policy evolution and upstream protocol conformance remain open. |
| Durable append-only history (`itself/ledger.py`, `ledger_agent/db.py`) | New `storage.py`; transactions, separate-process reopen/append, rollback/crash tests | Implemented bounded local slice; full reference backend behavior including Postgres and remote ingestion remains open. |
| Strict portable hash receipts (`itself/receipts.py`, `ledger_agent/receipts.py`) | `ledger.py` v1 reader/v2 chain plus authority/evidence/manifest-bound workflow envelopes | Partial: strict offline workflow replay and authority/action binding now exist; minimized reasoning disclosures and external attestations remain open. |
| Graph/reference provenance (`itself/bundle.py`, `ledger_agent/tool_receipts.py`) | `provenance.py` links plus workflow evidence/claim/scope checks and artifact content commitments | Partial: artifact references now have content bindings and unresolved-reference rejection; execution/tool lineage and artifact custody remain open. |
| Closed artifact bundle publication (`itself/evidence_bundle.py`) | `artifacts.py`: closed canonical content-addressed ZIP32, streamed object digests, exact inventory, no-replace atomic publication and externally anchored replay | Implemented bounded original local profile; not upstream directory/wire equivalence. Authenticated custody, signatures and external artifact-store integrations remain open. |
| Offline versioned schemas and interoperability (`itself/schemas/`, `schema_export.py`, JavaScript conformance) | `schema_catalog.py` / `schema_directory.py`: seven original structural wire profiles, shared defs, closed pinned catalog/SHA inventory, packaged resources, atomic no-replace ZIP and Windows/Linux directories; independent Draft 2020-12 tests plus existing Node append verifier | Partial original profile: broader epistemic records, upstream wire conformance, multi-line loading and independent cross-language receipt/member verification remain open. |
| External inference/check boundary (`itself/inference.py`, `records.py`, `bundle.py`; `ledger_agent/campaigns.py`) | `checks.py` fixed retained-byte predicates and `check_workflow.py` separately pinned recomputation/approval gate | Partial original deterministic slice: explicit ordered plans/results, actual retained bytes and authority lifecycle binding; live oracle adapters, arbitrary programs, inference request/response and richer epistemic protocols remain open. |
| Persistent query and pagination (`ledger_agent/server/api.py`, `test_export_pagination.py`) | `query.py` head-anchored indexes, exact field/time filters, reusable bounded pages and old-prefix reopening from SQLite snapshots | Partial original local retrieval: persistent secondary indexes, authenticated exports, richer expressions/proofs and reference workload comparisons remain open. |
| Detached membership and external commitment (`ledger_agent` continuous-attestation/evidence-receipts contracts) | `membership.py`: selected receipt membership; `consistency.py`: compact two-anchor prefix proofs; `verification/ledger-consistency.mjs`: independent Node bit/index verification of the closed append-proof profile | Partial original proof profile: signed/witnessed heads, hidden new chain-link verification, nonmembership/query-completeness proofs, cross-language receipt/selected-membership verification and broader conformance remain open. |
| HTTP/SDK/MCP service (`ledger_agent/server/`, `mcp_server.py`, `client.py`) | Local Python API and CLI | Open: service protocol, authentication/tenant boundaries, request limits, idempotency, health and contract tests. |
| Attestation and independent witness (`ledger_agent/witness.py`, `continuous-attestation.md`) | Optional caller-retained head comparison | Open: signed/witnessed checkpoints, key lifecycle and externally tested replacement/rollback threat model. |
| Governance/receipts/OSCAL projections (`ledger_agent/context_release.py`, `oscal.py`, `composition.py`) | Existing policy/report mechanics | Open: recorded authority/action/result provenance, policy-bound disclosure, schema-validated projection and compound action receipts. |
| Resource attribution/reconciliation (`ledger_agent/metering.py`, `reconcile*.py`, optional billing) | No equivalent yet | Open under whole-repository scope: explicit resource records, cost rules, reconciliation and optional adapter contracts. |
| Deployment and runtime integrations (`Dockerfile`, `docker-compose.yaml`, `integrations/`) | Python packages and release CI | Open: service deployment assets, integration adapters, secret/config handling and independent deployment smoke tests. |
| Reproducible evaluation and assurance campaigns (`itself/evaluations/`, `ledger_agent/campaigns.py`, concurrency tools) | Synthetic decision baselines plus durable-store adversarial tests | Partial: end-to-end authority/mutation campaigns, persistent workload capacity curves and independently reproduced service workloads remain open. |

## Completion rule

Closing a row requires a concrete user-visible contract, implementation,
negative and cross-boundary tests, executable example, limits/performance
evidence and documentation. Full parity requires every whole-repository row to
be closed, including deployment and optional integration surfaces. Source line
counts, large parameterized test totals and matching capability labels do not
substitute for those outcomes. This increment closes persistence defects and
adds a durable local slice; it does not close this ledger.

## Local verification of this increment

On Windows with Python 3.14.5, the full suite passed **526 tests**, with **98.58%**
combined statement/branch coverage and the existing 98% threshold preserved.
`ResourceWarning` was promoted to an error. The ledger module reached 100%
coverage and storage 99%. Ruff check/format, strict Mypy, Bandit, wheel/sdist
build, strict Twine metadata checks and wheel-content checks passed. These are
local results; remote CI and publication are separate steps.

The current source inventory is 21 Python files / 4,877 lines, with 16 test
Python files / 4,899 lines. Counts include blank lines and comments and are not
used to close functional parity rows. The executable durable-store example is
tested against the existing evaluation result, preserving scoring semantics.

## Authority-workflow increment verification

The next bounded increment adds the original procedural contract documented in
[authority workflows](authority-workflows.md), not the full epistemic protocol
surface. Its actor/grant models, claim lifecycle, reference checks, independent
review quorum and offline receipt replay have **149 focused tests** with 100%
statement/branch coverage for both new source modules. The complete suite passed
**676 tests**, with **98.82%** combined coverage and the unchanged 98% gate, on
Windows/Python 3.14.5. `ResourceWarning` was promoted to an error. Ruff check and
format, strict Mypy (23 source files), Bandit, wheel/sdist build, strict Twine and
wheel-content checks all passed locally. A separate process replays exported
workflow receipts bound to reopened SQLite evidence. Publication and remote CI
remain distinct steps.

The resulting inventory is 23 source Python files / 5,754 lines and 18 test
Python files / 5,773 lines, including blanks/comments. These counts are not a
parity completion criterion. New explicit open boundaries include authenticated
principals, authority-policy evolution, reopening/migration between workflow
contexts, transactionally persisted concurrent workflow publication, packaged
artifact bytes, richer epistemic states and independent non-Python conformance.

## Closed-artifact increment verification

The original profile in [closed artifact bundles](closed-artifacts.md) now
packages actual committed bytes alongside workflow/evidence receipts and replayed
state. It closes that specific packaged-byte gap from the preceding increment,
not upstream directory/wire compatibility or authenticated custody. The frozen
first-party [reference bundle contract](https://github.com/Greater-Expanse/itself/blob/b6057fe96fdecdec34ec28afdffc0628549e8831/docs/EVIDENCE_BUNDLES.md)
was used to identify the inventory/publication/independent-verification acceptance
surface; no implementation code was copied.

On Windows build 26200 / Python 3.14.5, the full suite passed **788 tests**, no
skips, with **98.95%** statement/branch coverage and the unchanged 98% gate.
The 88 new artifact cases reached **99.77%** in `artifacts.py`, including all
114 branches. The separate atomic-publication helper reached **100%**. Resource
warnings were promoted to errors. Ruff lint/format, strict Mypy (25 source
modules), Bandit, wheel/sdist builds, strict Twine metadata and wheel-content
checks passed locally. The existing editable package version in the lock was
mechanically synchronized from stale 0.3.0 metadata to the already-declared
0.5.0; no dependency or project version was changed.

Behavioral evidence includes real no-replace hard-link publication on the local
Windows filesystem, refusal of an existing/concurrently won destination, failed
staging/close/fsync cleanup, exact reproducible ZIP bytes, independent process
verification after moving the archive and deleting source files, anchored
state recomputation, CRC/SHA tampering, malformed directory/local headers,
forbidden archive features and metadata, and source mutation during chunked
copying. Source-read work is capped at **512 MiB including duplicate mappings**,
separately from the 512 MiB unique-object storage ceiling. Filesystems without
hard-link support intentionally fail closed; no cross-filesystem fallback is
claimed. These are local results, not remote CI or a hard process-memory/runtime
sandbox. The remaining whole-repository rows stay open.

## Detached-membership increment verification

The original [membership profile](ledger-membership.md) adds independently anchored selected
receipt proofs over a verified immutable ledger prefix. It binds canonical receipt bytes,
sequence, count, original ledger version, genesis and prefix head using domain-separated hashes
and unpadded Merkle trees. The verifier requires a separately retained commitment digest; an
ordinary chain head is deliberately not interchangeable. Query pages are checked against their
actual indexed receipts before proof construction, without claiming query completeness.

The **103 new cases** include independently implemented tree/path oracles, a hardcoded digest
vector, direct page forgery, changed/reordered proof data, canonical JSON and bounded graph
admission, a separate-process verifier and real historical-prefix reopening after SQLite append.
Post-review tests cover O(depth) traversal state for wide nested input and the same graph budget
on export and import. A separate frontier-stack implementation agreed in 94 read-only root,
header and detached-proof checks.

The final local suite passed **947 tests**, with no skips, on Windows/Python **3.14.5** and
**3.12.0**, promoting resource warnings to errors. Overall combined coverage was **99.01%**
on 3.14, with **98.80%** in the membership module and the existing 98% gate unchanged. Ruff
lint/format, strict Mypy (27 source modules), Bandit, lock consistency, wheel/sdist build,
strict Twine, wheel-content checks and an isolated installed-wheel proof roundtrip passed.
No dependency, version or existing CLI/storage behavior changed. Publication and remote CI
are separate steps.

This closes the specific detached selected-membership gap, not signatures, authenticated
identity, durable-commit attestation, witnessed checkpoints, key lifecycle, append-consistency,
nonmembership/query-completeness proofs, cross-language canonical verification or a proof
service. Those whole-repository comparison rows remain open.

## Append-consistency increment verification

The original [append-consistency profile](ledger-consistency.md) closes the selected
two-snapshot receipt-tree prefix gap. It reuses the existing membership domains and cached
unpadded tree without changing that wire format. Verification requires **two separately
retained complete-commitment digests**, never two ordinary chain heads or anchors supplied
only by the received proof. The builder checks the actual historical prefix head and root;
the detached verifier reconstructs both committed roots from a compact ordered path.

The **81 new cases** include independently encoded leaves, frontier roots and a distinct
bit/index verifier across every old prefix at 18 selected sizes, fixed vectors, 1,024 single-bit
proof mutations, real SQLite append/reopen and verification in a separate process. Admission
tests cover exact closed shapes before header materialization, byte/depth limits before JSON
parsing, canonical encoding, huge integers, cycles and maximum-sized path envelopes. The real
three-to-seven example and isolated installed-wheel roundtrip use a **1,238-byte** proof.

The full local suite passed **1,028 tests**, without skips, on Windows/Python **3.14.5** and
**3.12.0**, with resource warnings promoted to errors. Overall combined coverage was
**98.98%** on 3.14, with **98.55%** in the new module and the unchanged 98% gate. Ruff
lint/format, strict Mypy (28 source modules), Bandit, lock consistency, wheel/sdist build,
strict Twine metadata, wheel-content checks and the isolated installed-wheel roundtrip
passed. No dependency, version or existing CLI/storage behavior changed. Publication and
remote CI remain separate steps.

The proof establishes append consistency of the two anchored receipt trees, not authenticated
identity, durable publication, witnessed non-equivocation, a signature/key lifecycle, or
independent revalidation of every undisclosed new hash-chain link. Empty-prefix consistency
is deliberately vacuous; an equal-size proof requires identical complete headers. Query
completeness, nonmembership, cross-language canonical verification and service operation
remain open. This is an incremental capability, not whole-reference-repository parity or
an externally audited cryptographic protocol.

## Independent Node verifier increment

`verification/ledger-consistency.mjs` independently verifies the existing closed
append-consistency proof with a bit/index algorithm, without Python, receipt
parsing, dependencies, network access or self-selected anchors. Its admission
uses native byte-view getters and bounded copying before strict UTF-8, depth,
integer, closed-shape and canonical-spelling checks. A review-discovered
shadowed-byte-length allocation bypass is fixed and covered by a regression.
The standalone module is included in both the source distribution and wheel.

The final JavaScript suite passed **eight groups**: 2,211 independently generated
prefix pairs through 65 leaves, seven sparse-subtree pairs reaching 100,000
entries, 1,024 single-bit path mutations, malformed envelopes, anchor rejection
and adversarial byte-view hooks. Production-module coverage is **99.01% lines,
98.94% branches and 100% functions**, above the new explicit 98/95/100 gates.
The sparse roots are deliberately opaque protocol fixtures, not actual receipts.

Three final Python/Node interoperability tests passed against real v1/v2
ledgers containing Unicode, 300-digit integers and small floats, covering 484
selected prefix pairs plus mutated paths and wrong anchors in **31.51 seconds**
on Windows/Python 3.14.5, with runtime and resource warnings as errors. This run
includes the byte-view hardening. The hardened implementation also passed
the actual three-to-seven receipt example from an isolated installed wheel.
Python production code is unchanged. The parent's 1,028-test full-suite results
above remain historical evidence, not a claim of a newly executed full suite.

Ruff lint/format (82 Python files), strict Mypy (28 source modules), Bandit,
frozen-lock validation, wheel/sdist builds, strict Twine metadata and wheel
content checks passed. The installed-wheel example used no package index or
runtime dependencies; Node is an explicitly separate runtime requirement.

CI and release checks explicitly require Node, run both implementations, apply
the JavaScript coverage gates and exercise the module from an isolated wheel.
CodeQL now scans Python and JavaScript. No dependency, release version, npm
publication, credentials or branch-protection policy changed. Remote exact-head
results are recorded separately after publication. Arbitrary receipt JSON
canonicalization, selected-membership interoperability, signatures, witnesses
and all remaining whole-repository rows stay open.

## Offline-schema increment verification

The original [offline catalog](offline-schemas.md) adds seven canonical serialized
wire profiles and shared definitions, a closed size/SHA-256 catalog, pinned
publication bytes, a no-fetch URI registry and canonical STORED ZIP exchange.
The frozen first-party [reference schema contract](https://github.com/Greater-Expanse/itself/blob/b6057fe96fdecdec34ec28afdffc0628549e8831/docs/SCHEMAS.md)
identified the catalog/offline/publication comparison surface; no implementation
code was copied. This increment implements atomic **single-file** no-replace
publication, not the reference's directory-export interface or full protocol.

On Windows/Python **3.14.5**, the final full suite passed **1,120 tests**, no
skips, in **257.96 seconds**, with **99.05%** combined statement/branch coverage
and the unchanged **98%** gate. Resource and runtime warnings were errors;
Node **22.21.1** was required for the existing independent proof tests. Both
new source modules reached **100%** statement/branch coverage. The preceding
89-case focused run passed in 137.73 seconds, including actual wheel/sdist builds,
exact packaged resource sets, no-site/no-dependency zipped-wheel execution,
relocated process verification and independent `Draft202012Validator` checks.

The checked-in publication contains 10 files totaling **26,961 bytes**, including
eight schemas, catalog and checksum inventory. Real competing Windows hard-link
publications produced one winner without replacing foreign content or leaking
staging files. Malformed catalog/schema/ZIP inputs and rehashed publisher errors
are rejected. Real schema-valid but unauthorized workflow histories, altered
counts/proofs and mathematical-integer/native-type differences demonstrate that
schema validity does not certify replay permission, canonical bytes or hashes.
The new `jsonschema` dependency is a dev/test extra only; runtime dependencies
remain empty. This local run is not a Linux or remote-CI result. Broader record
schemas, upstream conformance, multi-line loading, directory publication and all
remaining whole-repository rows remain open.

## Atomic offline schema directory increment

The original [directory publication API](schema-directory.md) reuses the fixed ten-resource
`wire-1` publication with no byte, catalog-pin or ZIP-profile changes. It writes and fsyncs explicit
same-parent staging files, verifies their complete content, then uses Windows no-replace rename
or Linux `renameat2(RENAME_NOREPLACE)`. Strict bounded directory verification rejects extra,
missing, linked/reparse, nonregular or altered entries. Cleanup only attempts still-observed owned
paths, retains unknown/replaced residue and reports publication acknowledgement separately from
success of error/report delivery. This closes the previously missing local atomic directory
publication subset, not upstream format compatibility, signed distribution or full repository parity.

The final Windows/Python **3.14.5** full suite passed **1,172 tests**, with only the **3
symlink-privilege skips** below, in **336.32 seconds**. Combined statement/branch coverage was
**99.07%**, exceeding the unchanged **98%** gate. Runtime and resource warnings were errors;
Node was required. The existing schema generator and catalog retained **100%** coverage and
their exact golden bytes. Reports are `build/schema-directory-full.xml` and
`build/schema-directory-coverage.xml` (local ignored build output).

The 55 new filesystem cases cover bounded reads/enumeration, exact publication bytes,
competing publishers, existing-target preservation, descriptor/iterator failures, partial writes,
fsync failures, replaced or unknown residue, lost rename acknowledgements, control-exception
priority and relocated verification in a fresh isolated process. The focused Windows/Python
3.14.5 run passed **52 tests**, with **3 genuine symlink-privilege skips**, in **43.60 seconds**;
the new module reached **99.40%** combined statement/branch coverage (all statements covered).
WSL Linux/Python **3.12.3** passed **all 55 cases** in **42.55 seconds**, exercising actual
`renameat2(RENAME_NOREPLACE)` and all three symlink cases. This was a focused Linux run, not a
Linux full-suite result. Its task-specific venv installed the built wheel without a package index
or runtime dependencies and used the system pytest 9.1.1 read-only. A preceding venv-creation
attempt failed in `ensurepip` before any test ran; the replacement used `--without-pip` and the
system pip frontend targeted only at that venv.

The unchanged independent Node 22.21.1 verifier passed all **8 groups**, with **99.01%** lines,
**98.94%** branches and **100%** functions. Independent peer probes also verified a real
two-publisher race, successful rename followed by a lost acknowledgement, and an interrupted
unknown-location outcome that preserved the complete directory. Native publication support was
tested on Windows and Linux; other operating systems intentionally fail closed.

Ruff lint/format (**91 Python files**), strict Mypy (**31 source modules**), Bandit, frozen-lock
validation, wheel/sdist builds, strict Twine metadata and wheel-content checks passed. The
isolated Windows wheel, installed without an index or dependencies, executed the complete
publish/relocate/new-process verifier example. No runtime dependency, package version, catalog
pin, resource bytes, existing ZIP API or CI policy changed. These are local results, not a claim
of remotely published or merged code; full reference-repository parity remains open.

## Deterministic retained-claim check increment

The [new retained-byte contract](claim-checks.md) closes a genuine semantic gap:
old workflow APPROVED was only independent procedural review, and a hash-correct
artifact containing `{"ok":false}` could correctly accompany that status.
The separate check gate now recomputes five fixed predicates from immutable
retained bytes and refuses semantic acceptance of FAIL/UNKNOWN. It preserves
old review rules instead of silently redefining approval as truth.

The frozen Itself [`records.py`](https://github.com/Greater-Expanse/itself/blob/b6057fe96fdecdec34ec28afdffc0628549e8831/src/itself/records.py)
contains Oracle and test/evidence/verdict records;
[`bundle.py`](https://github.com/Greater-Expanse/itself/blob/b6057fe96fdecdec34ec28afdffc0628549e8831/src/itself/bundle.py)
checks verdict/evidence/scope/order and replay bindings. Its
[`inference_to_evidence` example](https://github.com/Greater-Expanse/itself/blob/b6057fe96fdecdec34ec28afdffc0628549e8831/examples/inference_to_evidence/run.py)
actually performs an external controlled check rather than trusting inference.
The frozen Perseus [`campaigns.py`](https://github.com/Perseus-Computing-LLC/ledger/blob/c51af79a70bf8863541e4232d0f2bbaea5897821/ledger_agent/campaigns.py)
separates receipt structure from target verification and recomputes campaign
counts/status. These primary contracts motivated the acceptance boundary, not
copied implementation or upstream wire equivalence.

Evidence Braid's original engine has no arbitrary callback/eval/regex/network
executor. External plan/authority/context and two final heads are pinned; the
plan excludes final workflow/result hashes to avoid circular commitments.
All retained inputs, report and metadata are compared against one bounded byte
snapshot; a coherently rehashed/reapproved fabricated PASS still fails exact
recomputation. No new schema-catalog entry, old wire byte, package version or
runtime dependency changes. Fixed profile/resource limits and unresolved live
oracle, authentication, richer protocol and service gaps are explicit.

Final-source Windows/Python **3.14.5** verification passed **1,460 tests**, with
the **3 existing Windows symlink-privilege skips**, in **186.11 seconds**. Combined
statement/branch coverage was **99.16%**, exceeding the unchanged **98%** gate.
ResourceWarning and RuntimeWarning were errors; Node interoperability was required.
The gate module covered all 134 statements and 44 branches; the predicate module
covered 380/381 statements and 177/178 branches (**99.64%** combined). The one
uncovered predicate path is the defensive second count check during concurrent
plain-dict admission, not an untested semantic outcome. Reports are
`build/checks-full.xml`, `build/checks-full-coverage.xml` and `build/checks-full.coverage`.

The **288 new focused cases** passed on Windows/Python **3.14.5** in **10.72 seconds**
and in a separate scoped Windows/Python **3.12.13** venv in **8.37 seconds**, both
with runtime/resource warnings treated as errors. Expectations include an
independent 81-pair tagged scalar truth table, integer/path/binary boundaries,
shared resource exhaustion, coherently rehashed forged reports, cross-claim/scope,
unbound references, stale heads, revocation, metadata cycles and output privacy.
The initial five predicate tests and three gate tests first failed because the
respective public functionality did not exist, then passed after implementation.
Two intermediate context tests initially expected a later error despite changing
the external policy too; their fixtures were corrected to hold external context
fixed and exercise the intended inner binding check. No production bound weakened.

Ruff lint/format (**98 Python files**), strict Mypy (**33 source modules**), Bandit,
frozen-lock validation, sdist-to-wheel build, strict Twine and wheel-content
checks passed. Bandit's public enum `PASS = "pass"` false positive has one
explicitly justified line-level B105 suppression, not a global exclusion.
An isolated dependency-free wheel installation executed the full offline example
with `-I`, creating and verifying actual retained files/workflow/closed ZIP.
Runtime modules in the wheel and core/docs/example/tests in the sdist were
compared byte-for-byte with their source. The Python 3.12 test venv used offline
cached pytest and the local wheel; no system environment or other project changed.

These are local Windows full-suite and cross-version focused results, not a Linux
full-suite or hosted-CI claim. Runtime dependencies, package version, existing
schemas/goldens and CI policies remain unchanged. Whole-reference-repository parity
is still open.
