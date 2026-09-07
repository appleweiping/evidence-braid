# Changelog

All notable changes are documented here. The project follows Semantic
Versioning once the first stable release is published.

## [Unreleased]

No unreleased changes.

## [0.5.0] - 2026-09-07

### Added

- Added an offline hash-chained evidence ledger with explicit integrity-only semantics.
- Added a deterministic provenance graph linking claims, sources, events, signals, and correlation groups.

## [0.4.0] - 2026-09-07

### Added

- Deterministic leave-one-out robustness diagnostics through `robustness()` and
  `evidence-braid robustness`. Each visible event is removed once, the same
  policy is evaluated at the same instant, and outcome-changing removals are
  recorded with both decision reasons and margins. The report includes a
  per-claim stability fraction and a baseline result digest.
- An explicit `max_events` cost guard (default `256`) prevents an accidental
  quadratic analysis over an unbounded evidence feed. Pending events are not
  perturbed, and a linked adjudication is removed together with its event.

## [0.3.0] - 2026-09-07

### Added

- `evidence-braid diff-policy`, and the `compare_policies` and `decision_impact` functions
  behind it. The comparison classifies every field by what it does to the machinery rather
  than reporting that it changed: raising a threshold tightens the gate it belongs to,
  lengthening a half-life loosens every gate because evidence keeps more of its weight, and
  adding or removing a source or claim is structural. Each change carries a sentence saying
  what it does.
- A change that cannot be ordered reports `unordered` instead of inventing a direction.
  Turning `reliability_updates` on is the case that matters: whether it raises or lowers a
  source depends entirely on the adjudications the caller supplies.
- `--events` with `--as-of` adds the empirical half: both policies are evaluated over the
  identical evidence at the identical instant, and the report lists the claims whose outcome
  actually moved, with the reason each side gave and both result digests. A field comparison
  can report several tightened gates while one supplied evidence set at one instant shows
  nothing moved. That observation supports an adoption review but is not proof of safety or
  suitability; representative domain evidence and relevant evaluation instants remain necessary.
  Neither half answers the other question.

- Policy schema version 2, and the migration that brings an older document to it.
  `migrate_policy_document` upgrades one version at a time and returns a `MigrationReport`
  naming every field it added; `evidence-braid migrate-policy` performs the same upgrade on
  disk, validates the result before writing it, and can emit that report as JSON. A document
  declaring a schema this build does not know is refused rather than read with older semantics.
- `ClaimRule.required_modalities`, the capability schema 1 could not express. `min_modalities`
  says how many distinct modalities must corroborate a signal; `required_modalities` says which
  ones must be among them, so a claim that should not escalate without a camera can say so
  instead of hoping two of anything else does not arrive. It is applied per signal and defaults
  to empty, which demands nothing.
- `Policy.source_schema_version`, recording the version a document declared, so an upgraded
  policy stays distinguishable from one written against the current schema.
- Opt-in source reliability updating. A policy may declare `reliability_updates` with a
  `prior_weight` and an optional `max_adjustment`; a caller then supplies `Adjudication`
  records — ground truth about whether a named source's observation was correct — through
  `evaluate(..., adjudications=...)`, `replay(..., adjudications=...)`, or `--adjudications`.
  The applied weight is a documented closed form,
  `(prior_weight * declared + correct) / (prior_weight + observations)` bounded by
  `max_adjustment`, so any published number can be rechecked with a calculator. Only counts
  enter it, so arrival order cannot change a weight, and an adjudication becomes knowable at
  its own timestamp, so a replay snapshot stays a pure function of its prefix.
- A `reliability_updates` section in the machine result recording, per adjudicated source, the
  declared weight, the unbounded posterior, the applied weight, the signed change, and the
  adjudicated event IDs on each side. The record cross-checks its own counts and arithmetic, and
  the HTML report shows any weight that moved.
- `Adjudication` and `Verdict` public models and `load_adjudications` for JSONL ground truth,
  read under the existing event-file and event-line bounds.
- Explicit read ceilings for the dependency-free adapters: 4 MiB of policy JSON, 64 MiB of
  event JSONL, and 1 MiB for any single event line. `load_json`, `load_policy`, and
  `load_events` accept `max_bytes`/`max_line_bytes` so a caller can tighten a bound for one
  untrusted feed, and refuse a value above the compiled ceiling before opening the file.

### Changed

- CI and tagged releases now consume the frozen dependency lock with pinned automation actions;
  publishing requires successful cross-platform tests and CodeQL, uses reproducible archive
  timestamps, emits checksums and provenance, and refuses to replace an existing release asset.
- `Policy.from_dict` and `load_policy` accept a schema 1 document and upgrade it on the way in.
  A migration only ever writes down, explicitly, the behaviour the older version already had; it
  never guesses what an operator would have wanted from a capability that did not exist when they
  wrote the file. Schema 1 had no way to require a modality, so the upgrade writes an empty
  requirement, which is the identity for the new gate.
- The upgrade is therefore decision-preserving, and that is checked rather than trusted: over 300
  randomized policies and evidence sets, evaluating a schema 1 document and evaluating its upgraded
  form produce the identical result digest, and adding a requirement is verified never to open a
  gate that was closed. Regenerating the checked-in reference experiment under its recorded protocol
  changed exactly one field, `policy_schema_version`; every prediction digest, the dataset digest,
  the policy SHA-256, and the replay final digest are byte-identical.
- `Policy` objects constructed directly in Python must now declare
  `schema_version=CURRENT_POLICY_SCHEMA_VERSION`. Stored documents are unaffected: a schema 1 file
  keeps loading.
- Oversized policy or event input is now refused with `InputFormatError` naming the path,
  the limit, and the offending line number, instead of being read without a bound. Input is
  never truncated to a prefix that would still parse.
- Corrected the documented scope boundary that claimed adapter file and line sizes were
  uncapped, and recorded the caps as a resource bound rather than a security guarantee.
- Corrected the documented scope boundary that claimed source reliabilities are always static
  within one policy, and recorded what an updated weight is and is not: a reproducible
  accounting rule over judgements the caller supplies, with no calibration claim and no defence
  against ground truth that is biased, sparse, or hostile.
- A policy that does not configure `reliability_updates` is unaffected: the result payload omits
  the section entirely and keeps the digest it produced before the feature existed.

### Fixed

- `docs/evaluation.md` described the checked-in reference run as a 60-event replay. The artifact
  records `event_count: 80`, which is what the run used; the prose now agrees with the artifact.

## [0.2.0] - 2026-09-01

### Added

- Two transparent comparison baselines: equal-event majority vote and confidence/reliability
  weighted vote.
- Dependency-free labeled accuracy, abstention, precision/recall/F1, Brier, ECE, and confusion
  metrics.
- A deterministic synthetic baseline, calibration, performance, and replay experiment with a
  machine-readable environment-qualified reference result.
- Research limitations, evaluation protocol, compatibility policy, governance, citation metadata,
  issue forms, pull request template, and dependency update configuration.
- Stable cross-field validation for baseline decisions, hostile outcome handling, bounded/atomic
  experiment output, full policy/software provenance, and functional reference-result verification.

## [0.1.0] - 2026-08-31

### Added

- Strict typed schemas for vision, audio, text, and sensor evidence.
- Source reliability and modality-specific half-life decay.
- Correlation-aware deduplication of support and contradiction signals.
- Threshold, margin, quorum, source-diversity, and modality-diversity gates.
- Deterministic decision traces and canonical SHA-256 result digests.
- Fixed-time JSONL evaluation and ingestion-time replay commands.
- Standalone HTML and SVG reports.
- Dependency-free Python API and comprehensive test suite.

### Changed

- Stabilized computed values before correlation selection, score aggregation,
  policy comparisons, and serialization.
- Canonicalized negative zero across input, output, and digest models.
- Made replay snapshots prefix-only and decision traces recursively immutable.
- Enforced validation and defensive collection snapshots in direct model
  constructors, including `dataclasses.replace` paths.
- Added a 64-level event-attribute nesting bound with a stable domain error.
- Bounded public-model integers at the runtime-stable 640-digit conversion
  threshold and rejected scalar subclasses so accepted attributes remain
  strict-JSON serializable even at Python's minimum configured safety limit.
- Raised the coverage gate and added distribution plus isolated-wheel CI smoke tests.
- Expanded CI coverage to Linux on Python 3.11/3.14 and Windows on Python 3.12.

### Fixed

- Rejected duplicate JSON keys, invalid UTF-8, unsafe Unicode/XML text, non-finite
  attributes, schema type confusion, and numeric conversion overflow.
- Rejected JSON exponents that would overflow Python's finite float range.
- Applied one source-clock skew rule to fixed evaluation and replay.
- Wrapped naive API timestamps and encoding failures in public domain errors.
- Rejected mutable or behavior-overriding `datetime` subclasses at public model
  boundaries.
