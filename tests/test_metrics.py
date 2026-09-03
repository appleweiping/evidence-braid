from __future__ import annotations

import math
from collections.abc import Iterator, Mapping

import pytest

from evidence_braid.errors import ValidationError
from evidence_braid.metrics import classification_metrics
from evidence_braid.models import Outcome


def test_metrics_include_classification_abstention_and_calibration() -> None:
    metrics = classification_metrics(
        {"a": "escalate", "b": "escalate", "c": "reject", "d": "reject"},
        {"a": Outcome.ESCALATE, "b": "review", "c": "escalate", "d": "reject"},
        {"a": 0.9, "b": 0.4, "c": 0.7, "d": 0.1},
        calibration_bins=5,
    )

    assert metrics["sample_count"] == 4
    assert metrics["positive_class"] == "escalate"
    assert metrics["accuracy"] == 0.5
    assert metrics["coverage"] == 0.75
    assert metrics["selective_accuracy"] == pytest.approx(2 / 3)
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 0.5
    assert metrics["f1"] == 0.5
    assert metrics["brier_score"] == 0.2175
    assert metrics["expected_calibration_error"] == 0.375
    assert metrics["confusion_matrix"] == {
        "escalate": {"escalate": 1, "reject": 0, "review": 1},
        "reject": {"escalate": 1, "reject": 1, "review": 0},
    }
    assert sum(item["count"] for item in metrics["calibration_bins"]) == 4


def test_metrics_include_probability_one_and_skip_empty_bins() -> None:
    metrics = classification_metrics(
        {"positive": "escalate", "negative": "reject"},
        {"positive": "escalate", "negative": "reject"},
        {"positive": 1.0, "negative": 0.0},
        calibration_bins=10,
    )

    assert metrics["accuracy"] == 1.0
    assert metrics["brier_score"] == 0.0
    assert metrics["expected_calibration_error"] == 0.0
    assert len(metrics["calibration_bins"]) == 2


def test_calibration_bin_boundaries_are_half_open_except_final_one() -> None:
    metrics = classification_metrics(
        {"low": "reject", "boundary": "reject", "one": "escalate"},
        {"low": "reject", "boundary": "reject", "one": "escalate"},
        {"low": 0.199, "boundary": 0.2, "one": 1.0},
        calibration_bins=5,
    )

    assert [(item["lower"], item["count"]) for item in metrics["calibration_bins"]] == [
        (0.0, 1),
        (0.2, 1),
        (0.8, 1),
    ]


def test_all_review_predictions_have_zero_coverage_and_binary_scores() -> None:
    metrics = classification_metrics(
        {"a": "escalate", "b": "reject"},
        {"a": "review", "b": "review"},
        {"a": 0.5, "b": 0.5},
    )

    assert metrics["coverage"] == 0.0
    assert metrics["selective_accuracy"] == 0.0
    assert metrics["precision"] == 0.0
    assert metrics["recall"] == 0.0
    assert metrics["f1"] == 0.0


@pytest.mark.parametrize(
    ("labels", "predictions", "probabilities", "bins"),
    [
        ({}, {}, {}, 10),
        ({"a": "escalate"}, {"b": "escalate"}, {"a": 0.5}, 10),
        ({" bad ": "escalate"}, {" bad ": "escalate"}, {" bad ": 0.5}, 10),
        ({"a": "review"}, {"a": "review"}, {"a": 0.5}, 10),
        ({"a": "escalate"}, {"a": "unknown"}, {"a": 0.5}, 10),
        ({"a": "escalate"}, {"a": "escalate"}, {"a": math.nan}, 10),
        ({"a": "escalate"}, {"a": "escalate"}, {"a": True}, 10),
        ({"a": "escalate"}, {"a": "escalate"}, {"a": 0.5}, 0),
        ({"a": "escalate"}, {"a": "escalate"}, {"a": 0.5}, True),
    ],
)
def test_metrics_reject_ambiguous_or_incomplete_inputs(
    labels: dict[str, str],
    predictions: dict[str, str],
    probabilities: dict[str, float],
    bins: int,
) -> None:
    with pytest.raises(ValidationError):
        classification_metrics(labels, predictions, probabilities, calibration_bins=bins)


class _BrokenMapping(Mapping[str, object]):
    def __getitem__(self, key: str) -> object:
        raise RuntimeError("broken getitem")

    def __iter__(self) -> Iterator[str]:
        raise RuntimeError("broken iteration")

    def __len__(self) -> int:
        return 1


def test_metrics_wraps_custom_mapping_failures_as_domain_errors() -> None:
    with pytest.raises(ValidationError, match="stable mapping"):
        classification_metrics(
            _BrokenMapping(),  # type: ignore[arg-type]
            {"a": "escalate"},
            {"a": 0.5},
        )


class _HostileOutcome:
    def __eq__(self, other: object) -> bool:
        raise RuntimeError("hostile equality")


def test_metrics_wraps_hostile_outcome_conversion_as_domain_error() -> None:
    with pytest.raises(ValidationError, match="valid outcome"):
        classification_metrics(
            {"a": _HostileOutcome()},  # type: ignore[dict-item]
            {"a": "escalate"},
            {"a": 0.5},
        )
