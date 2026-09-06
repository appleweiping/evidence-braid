# Reproducible evaluation

The repository includes a deterministic synthetic experiment so decision semantics, comparison
baselines, labeled metrics, calibration diagnostics, and replay cost can be inspected without a
private dataset or runtime dependency.

```bash
python experiments/synthetic_baselines.py \
  --samples 240 --seed 1729 --repeats 5 --replay-events 80 \
  --output experiment.json
```

Every result records the generator version and seed, dataset SHA-256, class counts, Python and OS,
processor description, logical CPU count, timer, warmup, repetitions, prediction hashes, and timing
distribution. Functional hashes and metrics are deterministic for a given version and seed. Timing
is not deterministic and characterizes only the recorded environment.

## Synthetic generator

Labels alternate between `escalate` and `reject`. Three simulated sources emit evidence with fixed
source-specific error probabilities and seeded confidence ranges. Thirty percent of scenarios, in
expectation, receive a same-cause copy identified by a correlation group. Observation ages are also
seeded. These choices exercise the software's decay, correlation, source reliability, diversity,
threshold, and abstention behavior.

The generated events are not collected observations, do not represent a population, and do not
model any named detector. The experiment therefore cannot establish external validity, fairness,
safety, or operational accuracy.

## Transparent baselines

- `majority_vote` gives one vote to every visible event. It omits confidence, reliability, decay,
  correlation collapse, thresholds, and independence gates.
- `reliability_weighted_vote` sums `confidence * source_reliability` on each side. It omits decay,
  correlation collapse, thresholds, and independence gates.

Both baselines expose support mass, contradiction mass, event count, outcome, and the support share
used as their probability diagnostic. They validate duplicate IDs, unknown claims, timestamps, and
source-clock skew through the same event-set boundary as the main engine.

For Evidence Braid, the experiment reports `support_score / (support_score + contradiction_score)`
when the denominator is non-zero and `0.5` otherwise. This ratio is useful for repeatable Brier and
calibration diagnostics, but the decision engine does not claim that it is a statistically
calibrated posterior probability.

## Metrics

`classification_metrics()` requires binary reference labels (`escalate` or `reject`) and allows a
prediction to abstain as `review`. It reports:

- accuracy over all cases;
- coverage and accuracy among covered, non-review cases;
- precision, recall, and F1 with `escalate` as the explicitly named positive class;
- a confusion matrix that retains review predictions;
- Brier score for supplied support probabilities;
- expected calibration error (ECE) over fixed-width bins, plus the contents of non-empty bins.

Zero denominators use explicit deterministic values: precision is `0` when there are no predicted
escalations, recall is `0` when there are no escalation labels, F1 is `0` when precision plus recall
is zero, and selective accuracy is `0` when coverage is zero. Empty labeled datasets are rejected.
For a baseline or engine score pair whose support plus contradiction mass is zero, the support
probability diagnostic is `0.5` and the outcome is `review`.

ECE depends on binning and sample composition; do not compare values produced with different
protocols as if they were interchangeable.

## Checked-in reference run

[`experiments/results/synthetic-baselines-windows-python314.json`](../experiments/results/synthetic-baselines-windows-python314.json)
is one 120-scenario, seed-1729 run with five repetitions and an 80-event replay. Its complete machine
metadata is part of the artifact. It is checked in to make the result schema, workload digest,
prediction hashes, calibration bins, and protocol reviewable—not as a cross-machine performance
claim.

The artifact also records the Evidence Braid version, fixed `as_of` timestamp, generator version,
and SHA-256 of the complete canonical policy document. Command-line output is written through
same-directory atomic replacement. Resource controls cap scenarios at 5,000, repetitions at 20,
replay events at 500, and the absolute seed at `2^63 - 1`; these are tool-safety limits rather than
performance guarantees.

The replay characterization uses one unique ingestion timestamp per synthetic event, so snapshot
count equals event count. It reports latency per input event for reconstructing the complete replay;
it is not a streaming service throughput measurement.
