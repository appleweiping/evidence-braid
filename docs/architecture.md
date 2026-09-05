# Architecture

Evidence Braid separates parsing, evidence mechanics, decision policy, and
presentation so each layer can be reviewed and tested independently.

```text
policy JSON ──> strict models ────────────────┐
                                              │
events JSONL -> strict events -> known-at-T -> weighting -> correlation collapse
                                                            │
                                                            v
                                                      signal summaries
                                                            │
                                                            v
                                                   thresholds and gates
                                                            │
                                       ┌────────────────────┴─────────────┐
                                       v                                  v
                               deterministic JSON                   HTML / SVG
```

## Modules

### `models.py`

Defines frozen event and policy dataclasses, enumerations, timestamp
normalization, and schema validation. It is the trust boundary for untyped
input. Unknown keys, non-finite numbers, invalid Unicode/XML text, invalid
ranges, unsupported schema types or versions, and naive timestamps are rejected
here. Nested attributes are validated as finite JSON and frozen. The I/O layer
rejects duplicate object keys before model construction.
Observation and ingestion clocks may differ; the engine enforces the policy's
explicit future-skew limit.

Validation is also enforced by every model's direct constructor. Mapping and
sequence fields are copied into immutable representations, so callers cannot
bypass the trust boundary with direct construction or `dataclasses.replace`.
Timestamps become built-in UTC `datetime` values; mutable or behavior-changing
subclasses are rejected.
Attribute traversal is capped at 64 levels and fails with `ValidationError`.
Integers accepted by public models are capped at CPython's stable 640-digit
conversion-check threshold (with an explicit 640 fallback on other runtimes),
without converting the candidate to text first. Only exact built-in JSON scalar
types are accepted for attributes.

### `decay.py`

Converts one event into a `WeightedEvent`. It contains no aggregation or policy
outcome logic. Given an event, policy, and time, it is a pure function.

### `grouping.py`

Partitions weighted events by correlation identity and signal, then selects a
representative. Support and contradiction remain separate even when they share
a group: a correlation declaration says observations are not independent; it
does not authorize one signal to erase the other.

### `engine.py`

Computes bounded scores and independence gates, chooses an outcome, and emits a
deeply immutable trace. `evaluate` rejects duplicate IDs, claims absent from
the policy, invalid API types, and source-clock skew before filtering on
ingestion time. Scores are stabilized to the same 12 decimal places used in
public output before correlation ranking, aggregation, thresholds, and margins
are compared. Negative zero is normalized to ordinary zero at model boundaries
and after stabilization.

Rejecting unknown claims is intentional. Silently skipping them could make a
missing policy rule look like absence of evidence.

### `replay.py`

Builds deterministic historical snapshots at distinct ingestion times. It does
not simulate a clock or pass future events into earlier evaluations. Every
snapshot contains only its ingestion prefix, so extending a valid stream cannot
alter an earlier digest. The same engine validates and evaluates each prefix.

### `io.py`, `limits.py`, and `cli.py`

Own filesystem and terminal behavior. JSON objects are parsed with duplicate
key rejection, UTF-8 failures are wrapped as domain errors, and serialization
forbids non-finite constants. Core models, engine, and renderers do not read or
write files. Domain errors produce concise messages and a stable CLI exit code.

Reads are bounded. `limits.py` holds one default and one compiled ceiling for
each input dimension: policy bytes, event-file bytes, and event-line bytes. A
loader requests one byte past its limit, so an oversized document is refused
with `InputFormatError` rather than truncated to a prefix that might still
parse as a complete decision input. The message carries the path, the limit,
and the line number where a line limit was exceeded. A caller may tighten a
bound for one untrusted feed; a value outside `1..ceiling` is a
`ValidationError` raised before the file is opened, so the ceiling stays a
property of the build rather than of an argument list. Line lengths are
measured on encoded bytes before decoding, and `bytes.splitlines` recognizes
exactly the newline forms Python's text mode normalizes, so a reported line
number matches the one an operator sees in an editor.

### `report.py`

Renders standalone HTML and SVG. It escapes all event- and policy-derived text,
loads no remote assets, and runs no JavaScript. Machine JSON remains the source
of truth.

## Decision invariants

1. A duplicate event identity is always an error.
2. An event cannot influence a snapshot before its ingestion time.
3. Future observations are never amplified.
4. One explicit correlation group contributes at most once per signal.
5. Input ordering cannot affect selection, output ordering, or digest.
6. Every configured claim receives exactly one decision.
7. Ambiguity falls back to review.
8. Presentation cannot change a decision.
9. Fixed evaluation and replay enforce the same source-clock relationship.
10. Appending future replay events cannot change an earlier snapshot.
11. Public model instances cannot retain caller-owned mutable collections.
12. Every accepted attribute can be serialized by the strict JSON adapter.
13. Input beyond a configured size bound is refused, never truncated.

## Scoring rationale

Raw sums make scores sensitive to event volume and can exceed one. An average
allows weak events to dilute strong corroboration. Evidence Braid instead uses
the complement product over independent values:

```text
1 - (1 - c1)(1 - c2)...(1 - cn)
```

It stays in `[0, 1]`, is commutative, and has a clear neutral case: no evidence
produces zero. It is a policy mechanism, not a statistical claim that the inputs
are calibrated probabilities.

The score and independence gates are deliberately separate. A strong single
source may cross a numerical threshold while failing quorum or diversity. The
trace distinguishes these cases.

## Deterministic digest

The result payload, excluding the digest, is serialized as UTF-8 JSON with
sorted keys, no insignificant whitespace, and non-ASCII text preserved. SHA-256
is applied to those bytes and prefixed with `sha256:`.

The digest detects accidental changes and supports regression fixtures. It does
not prove authorship and does not protect an untrusted evidence store. Systems
that need authenticity should sign the result envelope outside the core.

## Extending the project

Add new policy capabilities as explicit schema-versioned fields. Do not infer
behavior from arbitrary event attributes. Keep parsing strict and update:

1. model validation;
2. engine behavior;
3. decision trace;
4. architecture documentation;
5. boundary and determinism tests;
6. checked-in example artifacts.

Adapters for databases, queues, signatures, or model runtimes belong outside
the dependency-free core unless they can remain optional.

## Threat considerations

The engine limits schema ambiguity but cannot prevent a trusted source from
lying, replaying a new ID, or selecting a misleading correlation group. A
production boundary should authenticate sources, enforce monotonic or
idempotent ingestion, store original bytes, and record policy approval
separately.

The adapters cap their own reads, which bounds the memory one load can consume
and makes an oversized document a refusal instead of a silent truncation. That
is a resource bound, not a defense against a hostile filesystem: it does not
authenticate the bytes, notice a file that changes between reads, or apply to
input a caller supplies through the Python API.

HTML escaping prevents event content from becoming markup in the included
report. Consumers embedding machine JSON elsewhere must implement the encoding
required by their own context.
