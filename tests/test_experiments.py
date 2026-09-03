from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from evidence_braid import __version__, classification_metrics, replay
from evidence_braid.models import Outcome
from experiments.synthetic_baselines import (
    AS_OF,
    GENERATOR_VERSION,
    MAX_ABS_SEED,
    MAX_REPEATS,
    MAX_REPLAY_EVENTS,
    MAX_SAMPLES,
    SCHEMA_VERSION,
    _dataset_digest,
    _json_digest,
    _percentile,
    _policy_document,
    _prediction_digest,
    _replay_stream,
    _run_method,
    _write_atomic,
    build_synthetic_dataset,
    run_experiment,
)


def test_synthetic_dataset_is_seeded_balanced_and_explicitly_synthetic() -> None:
    _, first = build_synthetic_dataset(samples=12, seed=1729)
    _, second = build_synthetic_dataset(samples=12, seed=1729)

    assert first == second
    assert sum(item.label is Outcome.ESCALATE for item in first) == 6
    assert sum(item.label is Outcome.REJECT for item in first) == 6
    assert all(item.events for item in first)


@pytest.mark.parametrize(
    ("samples", "seed"),
    [
        (1, 1),
        (MAX_SAMPLES + 1, 1),
        (True, 1),
        (2, True),
        (2, 1.5),
        (2, MAX_ABS_SEED + 1),
        (2, -MAX_ABS_SEED - 1),
    ],
)
def test_synthetic_dataset_rejects_invalid_protocol(samples: object, seed: object) -> None:
    with pytest.raises(ValueError):
        build_synthetic_dataset(samples=samples, seed=seed)  # type: ignore[arg-type]


def test_experiment_reports_metrics_calibration_replay_and_environment() -> None:
    result = run_experiment(samples=12, seed=1729, repeats=3, replay_events=8)

    assert result["schema_version"] == SCHEMA_VERSION
    assert result["software"] == {"name": "evidence-braid", "version": __version__}
    assert result["evaluation"]["as_of"] == AS_OF.isoformat().replace("+00:00", "Z")
    assert result["evaluation"]["policy_sha256"] == _json_digest(_policy_document())
    assert result["dataset"]["kind"] == "deterministic_synthetic"
    assert result["dataset"]["real_world_claim"] is False
    assert result["dataset"]["scenario_count"] == 12
    assert result["environment"]["python"]
    assert result["protocol"]["repeats"] == 3
    assert set(result["methods"]) == {
        "evidence_braid",
        "majority_vote",
        "reliability_weighted_vote",
    }
    for method in result["methods"].values():
        assert {
            "accuracy",
            "precision",
            "recall",
            "f1",
            "brier_score",
            "expected_calibration_error",
        } <= method["metrics"].keys()
        assert method["timing"]["median_us_per_operation"] > 0
        assert len(method["prediction_sha256"]) == 64
    assert result["replay"]["event_count"] == 8
    assert result["replay"]["snapshot_count"] == 8
    assert result["replay"]["final_digest"].startswith("sha256:")
    json.dumps(result, allow_nan=False)


def test_experiment_functional_outputs_are_reproducible() -> None:
    first = run_experiment(samples=8, seed=4, repeats=3, replay_events=4)
    second = run_experiment(samples=8, seed=4, repeats=3, replay_events=4)

    assert first["dataset"]["sha256"] == second["dataset"]["sha256"]
    assert first["replay"]["final_digest"] == second["replay"]["final_digest"]
    for name in first["methods"]:
        assert first["methods"][name]["metrics"] == second["methods"][name]["metrics"]
        assert (
            first["methods"][name]["prediction_sha256"]
            == second["methods"][name]["prediction_sha256"]
        )


@pytest.mark.parametrize(
    ("repeats", "replay_events"),
    [
        (2, 1),
        (MAX_REPEATS + 1, 1),
        (True, 1),
        (3, 0),
        (3, MAX_REPLAY_EVENTS + 1),
    ],
)
def test_experiment_rejects_invalid_measurement_protocol(
    repeats: object, replay_events: object
) -> None:
    with pytest.raises(ValueError):
        run_experiment(
            samples=2,
            repeats=repeats,  # type: ignore[arg-type]
            replay_events=replay_events,  # type: ignore[arg-type]
        )


def test_experiment_rejects_unknown_method_and_percentile_interpolates() -> None:
    policy, scenarios = build_synthetic_dataset(samples=2, seed=1)
    with pytest.raises(ValueError, match="unknown method"):
        _run_method("unknown", policy, scenarios)
    assert _percentile([4.0, 1.0, 3.0, 2.0], 0.5) == 2.5


def test_atomic_experiment_output_preserves_existing_file_on_replace_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "result.json"
    destination.write_text("original\n", encoding="utf-8")

    def fail_replace(source: object, target: object) -> None:
        raise OSError("replace failed")

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(OSError, match="replace failed"):
        _write_atomic(destination, "replacement\n")

    assert destination.read_text(encoding="utf-8") == "original\n"
    assert list(tmp_path.iterdir()) == [destination]


def test_checked_in_reference_result_has_required_provenance() -> None:
    path = (
        Path(__file__).parents[1]
        / "experiments"
        / "results"
        / "synthetic-baselines-windows-python314.json"
    )
    result = json.loads(path.read_text(encoding="utf-8"))
    assert result["schema_version"] == SCHEMA_VERSION
    assert result["software"] == {"name": "evidence-braid", "version": __version__}
    assert result["dataset"]["real_world_claim"] is False
    assert result["dataset"]["seed"] == 1729
    assert result["protocol"]["repeats"] >= 3
    assert result["environment"]["operating_system"]

    policy, scenarios = build_synthetic_dataset(
        samples=result["dataset"]["scenario_count"],
        seed=result["dataset"]["seed"],
    )
    labels = {scenario.scenario_id: scenario.label for scenario in scenarios}
    assert result["dataset"] == {
        "kind": "deterministic_synthetic",
        "generator_version": GENERATOR_VERSION,
        "seed": 1729,
        "scenario_count": len(scenarios),
        "positive_count": sum(label is Outcome.ESCALATE for label in labels.values()),
        "negative_count": sum(label is Outcome.REJECT for label in labels.values()),
        "sha256": _dataset_digest(scenarios),
        "real_world_claim": False,
    }
    assert result["evaluation"] == {
        "as_of": AS_OF.isoformat().replace("+00:00", "Z"),
        "policy_id": policy.policy_id,
        "policy_schema_version": policy.schema_version,
        "policy_sha256": _json_digest(_policy_document()),
    }
    for name in ("evidence_braid", "majority_vote", "reliability_weighted_vote"):
        predictions, probabilities = _run_method(name, policy, scenarios)
        assert result["methods"][name]["metrics"] == classification_metrics(
            labels, predictions, probabilities
        )
        assert result["methods"][name]["prediction_sha256"] == _prediction_digest(
            predictions, probabilities
        )
    stream = _replay_stream(result["replay"]["event_count"])
    replay_results = replay(policy, stream)
    assert result["replay"]["snapshot_count"] == len(replay_results)
    assert result["replay"]["final_digest"] == replay_results[-1].digest
