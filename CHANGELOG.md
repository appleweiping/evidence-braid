# Changelog

All notable changes are documented here. The project follows Semantic
Versioning once the first stable release is published.

## Unreleased

No changes yet.

## 0.1.0 - 2026-08-31

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
