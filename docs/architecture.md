# Architecture

Evidence Braid separates parsing, evidence mechanics, decision policy, and
presentation so each layer can be reviewed and tested independently.

```text
policy JSON ──> strict models ────────────────┐
                                              │
adjudications -> strict truth --> known-at-T -┤   (optional, caller-supplied)
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

### `migrations.py`

Holds the ordered upgrades between policy schema versions, one step per version,
plus the report of what each step changed.

A stored policy outlives the release that wrote it. Refusing an older document
would make every schema change a coordinated rewrite of every operator's files;
quietly reinterpreting one would change decisions without saying so. A migration
does the third thing: it writes down, explicitly, the behaviour the older version
already had, and reports every field it added.

That constraint is what keeps a migration decision-preserving, which
`tests/test_migrations.py` checks over randomized policies rather than trusting.
`Policy.source_schema_version` records the version a document declared, so an
upgraded policy stays distinguishable from one written against the current
schema. A document declaring a schema this build does not know is refused rather
than read with older semantics.

### `decay.py`

Converts one event into a `WeightedEvent`. It contains no aggregation or policy
outcome logic. Given an event, policy, and time, it is a pure function.

### `reliability.py`

Holds the opt-in source-reliability update rule and the stream-wide validation
of the adjudications that drive it. Given a policy and a set of caller-supplied
judgements it is a pure function: no clock, no randomness, and no iteration over
an unordered collection reaches an output.

Reliability moves only from `Adjudication` records. Nothing in this package can
tell whether a source was right, and the module does not invent a stand-in for
that fact. An adjudication must name a source the policy declares, must not
repeat an `event_id`, must not contradict the source of an event that is in the
stream, and must not predate that event's ingestion. Failures are reported over
sorted identities, so even an error message does not depend on input order.

`adjust_reliabilities` returns one record per adjudicated source, in source
order, carrying both the unbounded closed-form value and the bounded value the
engine actually applies. A source without adjudications produces no record and
keeps its declared reliability.

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

Reliability updates are resolved once per evaluation, before any event is
weighted, and emitted as `ReliabilityUpdateTrace` records beside the decisions.
The record cross-checks itself: its counts must match its event IDs, an ID
cannot be both correct and incorrect, and its reported change must equal the
applied weight minus the declared one. A trace that could disagree with the
weight the engine used would be worse than no trace. The result payload omits
the whole section for a policy that does not configure updating, so such a
policy keeps the exact digest it had before the feature existed.

### `replay.py`

Builds deterministic historical snapshots at distinct ingestion times. It does
not simulate a clock or pass future events into earlier evaluations. Every
snapshot contains only its ingestion prefix, so extending a valid stream cannot
alter an earlier digest. The same engine validates and evaluates each prefix.

Ground truth arrives on its own clock, so an adjudication time is a snapshot
boundary exactly as an ingestion time is, and a snapshot sees only the
adjudications knowable at it. A stream with no adjudications produces the
boundaries replay always produced.

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
number matches the one an operator sees in an editor. `load_adjudications`
reads caller-supplied ground truth from JSONL through the same bounded reader
and under the same event-file and event-line limits.

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
14. A source reliability changes only from caller-supplied adjudications that
    are knowable at the evaluated instant, and only under a policy that asked
    for updating.
15. Every reliability change is recorded with the adjudications that caused it
    and the arithmetic that produced it.

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

## Reliability updating rationale

A declared reliability that can never move makes the concept decorative: a
source observed to be wrong repeatedly keeps its stated weight forever. The
opposite failure is worse, though — a weight that drifts under an opaque
estimator is a decision input nobody can review.

The rule is therefore a closed form over counts:

```text
posterior = (prior_weight × declared + correct) / (prior_weight + observations)
applied   = declared + min(max(posterior − declared, −max_adjustment), max_adjustment)
```

which is the declared value and the observed correct rate averaged with weights
`prior_weight` and `observations`. Three consequences are what make it
shippable here. A reviewer can recompute any published weight on a calculator
from numbers the audit trail already contains. Only counts enter, so nothing
depends on arrival order, storage order, or iteration order, and a snapshot
stays a pure function of its prefix. And `posterior` cannot leave `[0, 1]`,
because `correct <= observations` and `declared <= 1`, while `applied` always
lies between `declared` and `posterior`.

Estimators with better statistical properties exist. They were rejected because
none of them can be checked by hand from the machine output, which is the
property this project actually needs. The rule is an accounting convention a
policy adopts, not an estimate of a true reliability, and the documentation
does not claim otherwise.

The baselines in `baselines.py` deliberately keep using declared reliabilities,
so an ablation against them still isolates one mechanism at a time.

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
6. checked-in example artifacts;
7. a migration in `migrations.py`, so documents written against the previous
   schema keep loading.

A new field therefore needs a permissive default that is the identity for
whatever gate or computation it feeds. `required_modalities` is the worked
example: an empty requirement is satisfied by any evidence, so an upgraded
schema 1 policy decides exactly as the original did. A change that cannot offer
such a default is not an automatic upgrade; it belongs in a major release with a
migration note.

Adapters for databases, queues, signatures, or model runtimes belong outside
the dependency-free core unless they can remain optional.

## Threat considerations

The engine limits schema ambiguity but cannot prevent a trusted source from
lying, replaying a new ID, or selecting a misleading correlation group. A
production boundary should authenticate sources, enforce monotonic or
idempotent ingestion, store original bytes, and record policy approval
separately.

Adjudications are a second trusted input and deserve the same treatment. The
engine checks that a judgement is internally consistent with the stream; it
cannot tell a careful adjudication from a careless or hostile one, and whoever
can write the ground-truth feed can move a source's weight within
`max_adjustment`. Authenticate that feed, and record who adjudicated what,
outside this library.

The adapters cap their own reads, which bounds the memory one load can consume
and makes an oversized document a refusal instead of a silent truncation. That
is a resource bound, not a defense against a hostile filesystem: it does not
authenticate the bytes, notice a file that changes between reads, or apply to
input a caller supplies through the Python API.

HTML escaping prevents event content from becoming markup in the included
report. Consumers embedding machine JSON elsewhere must implement the encoding
required by their own context.
