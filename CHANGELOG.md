# Changelog

All notable changes are documented here. The project follows Semantic
Versioning once the first stable release is published.

## [Unreleased]

### Added

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
