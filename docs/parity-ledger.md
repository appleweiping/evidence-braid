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
| Offline versioned schemas and interoperability (`itself/schemas/`, `schema_export.py`, JavaScript conformance) | Strict Python models and policy migrations | Open: packaged JSON Schemas/catalog/checksums, language-independent fixtures and a second implementation of verification. |
| External inference/check boundary (`itself/inference.py`) | Events accepted from caller | Open: bounded structured request/response adapters, artifact retention, explicit external check result and authority lifecycle. |
| Persistent query and pagination (`ledger_agent/server/api.py`, `test_export_pagination.py`) | `query.py` head-anchored indexes, exact field/time filters, reusable bounded pages and old-prefix reopening from SQLite snapshots | Partial original local retrieval: persistent secondary indexes, authenticated exports, richer expressions/proofs and reference workload comparisons remain open. |
| Detached membership and external commitment (`ledger_agent` continuous-attestation/evidence-receipts contracts) | `membership.py`: canonical receipt leaves, count-derived Merkle paths and an external commitment; `consistency.py`: compact prefix proofs with two externally retained complete commitments | Partial original proof profile: selected membership and two-snapshot receipt-tree consistency. Signed/witnessed heads, hidden new chain-link verification, nonmembership/query-completeness proofs and independent non-Python verification remain open. |
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
