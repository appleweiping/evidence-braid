# Compatibility and release policy

Evidence Braid uses semantic versioning after the `0.x` development series. During `0.x`, a minor
release may change policy semantics or public schemas with a migration note; patch releases preserve
them. All changes are recorded in `CHANGELOG.md`.

Compatibility surfaces include:

- names exported from `evidence_braid`;
- event schema version 1;
- policy schema version 2, and the ability to keep loading a schema 1 document;
- result schema version 1, field meanings, ordering, reason codes, and digest construction;
- CLI commands, documented options, exit code `2` for domain/input failures, and JSON/JSONL formats;
- replay prefix semantics and the determinism contract;
- baseline definitions and metric field names.

Changing a decision comparison, stabilized precision, correlation selection, replay boundary, or
digest input is behaviorally significant even when Python signatures do not change. Such changes
require tests, an explicit changelog entry, and regenerated example artifacts. Incompatible machine
output requires a new schema version; consumers should ignore unknown additive fields. The
`reliability_updates` result section and the adjudication-time replay boundary are additive in
exactly that sense: both appear only for a policy that configures `reliability_updates`, and a
policy that does not keeps its previous output, boundaries, and digest.

A policy schema version is raised only alongside a migration that carries the previous version
forward, and only where that migration is decision-preserving: the upgraded policy must decide
exactly as the document it came from, which is checked over randomized policies rather than
asserted. A change that would move a decision is not an automatic upgrade and belongs in a major
release with a migration note. Documents are read forward only; one declaring a schema newer than
the running build is refused rather than read with older semantics, and the oldest version a build
still upgrades is `EARLIEST_POLICY_SCHEMA_VERSION`.

Supported Python versions are listed in `pyproject.toml` and exercised in CI. Removal is documented
in a minor release and normally follows the version's upstream security end-of-life. Benchmark
timings are not a compatibility guarantee.
