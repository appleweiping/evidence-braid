"""Compare Evidence Braid with two transparent baselines on synthetic labels.

The generator is deterministic and intentionally synthetic. Results measure
software behavior and calibration diagnostics; they are not evidence of
accuracy on any operational population.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import random
import statistics
import sys
import tempfile
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from evidence_braid import (
    BaselineDecision,
    EvidenceEvent,
    Outcome,
    Policy,
    __version__,
    classification_metrics,
    evaluate,
    majority_vote,
    reliability_weighted_vote,
    replay,
)

SCHEMA_VERSION = 1
GENERATOR_VERSION = 1
AS_OF = datetime(2026, 8, 31, 12, 0, tzinfo=UTC)
MAX_SAMPLES = 5_000
MAX_REPEATS = 20
MAX_REPLAY_EVENTS = 500
MAX_ABS_SEED = 2**63 - 1


@dataclass(frozen=True, slots=True)
class Scenario:
    scenario_id: str
    label: Outcome
    events: tuple[EvidenceEvent, ...]


def _policy_document() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "policy_id": "synthetic-evaluation-v1",
        "default_source_reliability": 0.7,
        "sources": {
            "source-a": {"reliability": 0.9},
            "source-b": {"reliability": 0.8},
            "source-c": {"reliability": 0.7},
        },
        "decay": {
            "default_half_life_seconds": 300,
            "max_future_skew_seconds": 0,
        },
        "claims": {
            "incident": {
                "support_threshold": 0.6,
                "contradiction_threshold": 0.6,
                "min_margin": 0.08,
                "quorum": 2,
                "min_sources": 2,
                "min_modalities": 2,
                "min_evidence_confidence": 0.15,
            }
        },
    }


def _policy() -> Policy:
    return Policy.from_dict(_policy_document())


def build_synthetic_dataset(*, samples: int, seed: int) -> tuple[Policy, tuple[Scenario, ...]]:
    """Generate balanced, labeled scenarios without external or real-world data."""

    if type(samples) is not int or not 2 <= samples <= MAX_SAMPLES:
        raise ValueError(f"samples must be an integer in [2, {MAX_SAMPLES}]")
    if type(seed) is not int or not -MAX_ABS_SEED <= seed <= MAX_ABS_SEED:
        raise ValueError(f"seed must be an integer in [-{MAX_ABS_SEED}, {MAX_ABS_SEED}]")
    generator = random.Random(seed)
    modalities = ("vision", "audio", "sensor")
    sources = ("source-a", "source-b", "source-c")
    accuracies = (0.84, 0.76, 0.68)
    scenarios: list[Scenario] = []
    for sample_index in range(samples):
        label = Outcome.ESCALATE if sample_index % 2 == 0 else Outcome.REJECT
        causal_group = f"scenario-{sample_index:04d}-shared"
        duplicate_first = generator.random() < 0.3
        events: list[EvidenceEvent] = []
        first_signal = "support"
        first_confidence = 0.0
        for source_index, (source, modality, accuracy) in enumerate(
            zip(sources, modalities, accuracies, strict=True)
        ):
            correct = generator.random() < accuracy
            positive = label is Outcome.ESCALATE
            support = positive if correct else not positive
            confidence = generator.uniform(0.62, 0.98) if correct else generator.uniform(0.4, 0.82)
            if source_index == 0:
                first_signal = "support" if support else "contradict"
                first_confidence = confidence
            age = generator.randint(0, 120)
            raw: dict[str, Any] = {
                "event_id": f"scenario-{sample_index:04d}-{source}",
                "claim": "incident",
                "modality": modality,
                "source": source,
                "signal": "support" if support else "contradict",
                "confidence": round(confidence, 6),
                "observed_at": (AS_OF - timedelta(seconds=age)).isoformat(),
                "ingested_at": (AS_OF - timedelta(seconds=max(age - 2, 0))).isoformat(),
            }
            if source_index == 0 and duplicate_first:
                raw["correlation_group"] = causal_group
            events.append(EvidenceEvent.from_dict(raw))
        if duplicate_first:
            events.append(
                EvidenceEvent.from_dict(
                    {
                        "event_id": f"scenario-{sample_index:04d}-copy",
                        "claim": "incident",
                        "modality": "text",
                        "source": "source-a",
                        "signal": first_signal,
                        "confidence": round(max(first_confidence - 0.03, 0.0), 6),
                        "observed_at": (AS_OF - timedelta(seconds=10)).isoformat(),
                        "ingested_at": (AS_OF - timedelta(seconds=8)).isoformat(),
                        "correlation_group": causal_group,
                    }
                )
            )
        scenarios.append(Scenario(f"scenario-{sample_index:04d}", label, tuple(events)))
    return _policy(), tuple(scenarios)


def _engine_prediction(policy: Policy, events: tuple[EvidenceEvent, ...]) -> tuple[Outcome, float]:
    decision = evaluate(policy, events, AS_OF).decisions[0]
    total = decision.support.score + decision.contradict.score
    probability = decision.support.score / total if total else 0.5
    return decision.outcome, round(probability, 12)


def _baseline_prediction(decisions: tuple[BaselineDecision, ...]) -> tuple[Outcome, float]:
    decision = decisions[0]
    return decision.outcome, decision.support_probability


def _run_method(
    name: str,
    policy: Policy,
    scenarios: tuple[Scenario, ...],
) -> tuple[dict[str, Outcome], dict[str, float]]:
    predictions: dict[str, Outcome] = {}
    probabilities: dict[str, float] = {}
    for scenario in scenarios:
        if name == "evidence_braid":
            outcome, probability = _engine_prediction(policy, scenario.events)
        elif name == "majority_vote":
            outcome, probability = _baseline_prediction(
                majority_vote(policy, scenario.events, AS_OF)
            )
        elif name == "reliability_weighted_vote":
            outcome, probability = _baseline_prediction(
                reliability_weighted_vote(policy, scenario.events, AS_OF)
            )
        else:
            raise ValueError(f"unknown method: {name}")
        predictions[scenario.scenario_id] = outcome
        probabilities[scenario.scenario_id] = probability
    return predictions, probabilities


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def _timing(
    operation: Callable[[], object],
    *,
    repeats: int,
    operation_count: int,
) -> dict[str, float]:
    operation()
    samples: list[float] = []
    for _ in range(repeats):
        started = time.perf_counter()
        operation()
        samples.append((time.perf_counter() - started) * 1_000_000 / operation_count)
    return {
        "median_us_per_operation": round(statistics.median(samples), 3),
        "p95_us_per_operation": round(_percentile(samples, 0.95), 3),
        "min_us_per_operation": round(min(samples), 3),
        "max_us_per_operation": round(max(samples), 3),
    }


def _dataset_digest(scenarios: tuple[Scenario, ...]) -> str:
    value = [
        {
            "scenario_id": scenario.scenario_id,
            "label": scenario.label.value,
            "events": [event.to_dict() for event in scenario.events],
        }
        for scenario in scenarios
    ]
    return _json_digest(value)


def _json_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _prediction_digest(predictions: dict[str, Outcome], probabilities: dict[str, float]) -> str:
    return _json_digest(
        {key: [predictions[key].value, probabilities[key]] for key in sorted(predictions)}
    ).removeprefix("sha256:")


def _replay_stream(count: int) -> tuple[EvidenceEvent, ...]:
    base = datetime(2026, 8, 31, 11, 0, tzinfo=UTC)
    return tuple(
        EvidenceEvent.from_dict(
            {
                "event_id": f"replay-{index:04d}",
                "claim": "incident",
                "modality": ("vision", "audio", "sensor")[index % 3],
                "source": ("source-a", "source-b", "source-c")[index % 3],
                "signal": "support" if index % 3 else "contradict",
                "confidence": 0.65 + (index % 5) * 0.05,
                "observed_at": (base + timedelta(seconds=index)).isoformat(),
                "ingested_at": (base + timedelta(seconds=index + 1)).isoformat(),
            }
        )
        for index in range(count)
    )


def run_experiment(
    *,
    samples: int = 240,
    seed: int = 1729,
    repeats: int = 5,
    replay_events: int = 80,
) -> dict[str, Any]:
    """Run accuracy, calibration, inference, and replay characterization."""

    if type(repeats) is not int or not 3 <= repeats <= MAX_REPEATS:
        raise ValueError(f"repeats must be an integer in [3, {MAX_REPEATS}]")
    if type(replay_events) is not int or not 1 <= replay_events <= MAX_REPLAY_EVENTS:
        raise ValueError(f"replay_events must be an integer in [1, {MAX_REPLAY_EVENTS}]")
    policy, scenarios = build_synthetic_dataset(samples=samples, seed=seed)
    labels = {scenario.scenario_id: scenario.label for scenario in scenarios}
    methods: dict[str, Any] = {}
    for name in ("evidence_braid", "majority_vote", "reliability_weighted_vote"):
        predictions, probabilities = _run_method(name, policy, scenarios)
        methods[name] = {
            "metrics": classification_metrics(labels, predictions, probabilities),
            "timing": _timing(
                lambda selected=name: _run_method(selected, policy, scenarios),
                repeats=repeats,
                operation_count=len(scenarios),
            ),
            "prediction_sha256": _prediction_digest(predictions, probabilities),
        }

    stream = _replay_stream(replay_events)
    replay_results = replay(policy, stream)
    replay_characterization = {
        "event_count": replay_events,
        "snapshot_count": len(replay_results),
        "final_digest": replay_results[-1].digest,
        "timing": _timing(
            lambda: replay(policy, stream),
            repeats=repeats,
            operation_count=replay_events,
        ),
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "software": {"name": "evidence-braid", "version": __version__},
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "evaluation": {
            "as_of": AS_OF.isoformat().replace("+00:00", "Z"),
            "policy_id": policy.policy_id,
            "policy_schema_version": policy.schema_version,
            "policy_sha256": _json_digest(_policy_document()),
        },
        "dataset": {
            "kind": "deterministic_synthetic",
            "generator_version": GENERATOR_VERSION,
            "seed": seed,
            "scenario_count": len(scenarios),
            "positive_count": sum(label is Outcome.ESCALATE for label in labels.values()),
            "negative_count": sum(label is Outcome.REJECT for label in labels.values()),
            "sha256": _dataset_digest(scenarios),
            "real_world_claim": False,
        },
        "environment": {
            "python": platform.python_version(),
            "python_implementation": platform.python_implementation(),
            "operating_system": platform.platform(),
            "machine": platform.machine() or "unknown",
            "processor": platform.processor() or "unknown",
            "logical_cpu_count": os.cpu_count(),
        },
        "protocol": {
            "repeats": repeats,
            "warmup_runs": 1,
            "timer": "time.perf_counter",
            "calibration_bins": 10,
        },
        "method_semantics": {
            "evidence_braid": (
                "configured correlation, decay, reliability, threshold, and independence gates"
            ),
            "majority_vote": "one equal vote per visible event; confidence and correlation ignored",
            "reliability_weighted_vote": (
                "confidence times static reliability; decay, correlation, and gates ignored"
            ),
        },
        "methods": methods,
        "replay": replay_characterization,
        "interpretation": (
            "Synthetic software characterization only; no operational accuracy or "
            "calibration claim."
        ),
    }


def _write_atomic(path: Path, content: str) -> None:
    """Atomically replace one experiment result after a synchronized write."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name or 'evidence-braid-experiment'}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            with suppress(OSError):
                temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=240)
    parser.add_argument("--seed", type=int, default=1729)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--replay-events", type=int, default=80)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        result = run_experiment(
            samples=args.samples,
            seed=args.seed,
            repeats=args.repeats,
            replay_events=args.replay_events,
        )
    except ValueError as exc:
        parser.error(str(exc))
    encoded = json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if args.output is None:
        sys.stdout.write(encoded)
    else:
        _write_atomic(args.output, encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
