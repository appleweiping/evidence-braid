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
| Closed artifact bundle publication (`itself/evidence_bundle.py`) | No equivalent yet | Open: manifest inventory, bounded streaming file digests, path confinement, no-replace atomic publication, and independent verification. |
| Offline versioned schemas and interoperability (`itself/schemas/`, `schema_export.py`, JavaScript conformance) | Strict Python models and policy migrations | Open: packaged JSON Schemas/catalog/checksums, language-independent fixtures and a second implementation of verification. |
| External inference/check boundary (`itself/inference.py`) | Events accepted from caller | Open: bounded structured request/response adapters, artifact retention, explicit external check result and authority lifecycle. |
| Persistent query and pagination (`ledger_agent/server/api.py`, `test_export_pagination.py`) | Whole-store verified snapshot | Open: bounded event/time/claim/source filters, pagination contract, stable snapshot reads and concurrent-update tests. |
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
