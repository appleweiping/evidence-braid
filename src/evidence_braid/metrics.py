"""Dependency-free labeled classification and calibration metrics."""

from __future__ import annotations

from collections.abc import Mapping
from math import isfinite
from typing import Any

from .errors import ValidationError
from .models import Outcome

_LABELS = (Outcome.ESCALATE, Outcome.REJECT)
_PREDICTIONS = (*_LABELS, Outcome.REVIEW)


def _outcome(value: object, path: str, *, label: bool) -> Outcome:
    try:
        outcome = value if isinstance(value, Outcome) else Outcome(value)  # type: ignore[arg-type]
    except Exception as exc:
        raise ValidationError(f"{path} is not a valid outcome") from exc
    allowed = _LABELS if label else _PREDICTIONS
    if outcome not in allowed:
        choices = "escalate or reject" if label else "escalate, reject, or review"
        raise ValidationError(f"{path} must be {choices}")
    return outcome


def _snapshot_mapping(value: Mapping[str, object], path: str) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise ValidationError(f"{path} must be a non-empty mapping")
    try:
        items = list(value.items())
    except Exception as exc:
        raise ValidationError(f"{path} could not be read as a stable mapping") from exc
    result: dict[str, object] = {}
    for key, item in items:
        if type(key) is not str or not key or key != key.strip():
            raise ValidationError(f"{path} keys must be canonical non-empty strings")
        if key in result:
            raise ValidationError(f"{path} contains a duplicate key")
        result[key] = item
    if not result:
        raise ValidationError(f"{path} must be a non-empty mapping")
    return result


def classification_metrics(
    labels: Mapping[str, Outcome | str],
    predictions: Mapping[str, Outcome | str],
    support_probabilities: Mapping[str, float],
    *,
    calibration_bins: int = 10,
) -> dict[str, Any]:
    """Score predictions where ``escalate`` is the documented positive class.

    Labels must be binary (``escalate`` or ``reject``); predictions may also
    abstain as ``review``. Calibration uses fixed-width bins over the supplied
    probability of the ``escalate`` label.
    """

    label_values = _snapshot_mapping(labels, "labels")
    prediction_values = _snapshot_mapping(predictions, "predictions")
    probability_values = _snapshot_mapping(support_probabilities, "support_probabilities")
    label_keys = tuple(sorted(label_values))
    prediction_keys = tuple(sorted(prediction_values))
    probability_keys = tuple(sorted(probability_values))
    if label_keys != prediction_keys or label_keys != probability_keys:
        raise ValidationError("labels, predictions, and support_probabilities must share keys")
    if type(calibration_bins) is not int or not 1 <= calibration_bins <= 100:
        raise ValidationError("calibration_bins must be an integer in [1, 100]")

    actual = {key: _outcome(label_values[key], f"labels.{key}", label=True) for key in label_keys}
    predicted = {
        key: _outcome(prediction_values[key], f"predictions.{key}", label=False)
        for key in label_keys
    }
    probabilities: dict[str, float] = {}
    for key in label_keys:
        value = probability_values[key]
        if type(value) not in (int, float) or not isfinite(value) or not 0 <= value <= 1:
            raise ValidationError(f"support_probabilities.{key} must be finite and in [0, 1]")
        probabilities[key] = float(value)

    count = len(label_keys)
    correct = sum(actual[key] is predicted[key] for key in label_keys)
    covered = sum(predicted[key] is not Outcome.REVIEW for key in label_keys)
    true_positive = sum(
        actual[key] is Outcome.ESCALATE and predicted[key] is Outcome.ESCALATE for key in label_keys
    )
    false_positive = sum(
        actual[key] is Outcome.REJECT and predicted[key] is Outcome.ESCALATE for key in label_keys
    )
    false_negative = sum(
        actual[key] is Outcome.ESCALATE and predicted[key] is not Outcome.ESCALATE
        for key in label_keys
    )
    precision = (
        true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
    )
    recall = (
        true_positive / (true_positive + false_negative) if true_positive + false_negative else 0.0
    )
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    brier = (
        sum(
            (probabilities[key] - (1.0 if actual[key] is Outcome.ESCALATE else 0.0)) ** 2
            for key in label_keys
        )
        / count
    )

    bins: list[dict[str, float | int]] = []
    expected_calibration_error = 0.0
    for index in range(calibration_bins):
        lower = index / calibration_bins
        upper = (index + 1) / calibration_bins
        members = [
            key
            for key in label_keys
            if lower <= probabilities[key] < upper
            or (index == calibration_bins - 1 and probabilities[key] == 1.0)
        ]
        if not members:
            continue
        mean_probability = sum(probabilities[key] for key in members) / len(members)
        observed_rate = sum(actual[key] is Outcome.ESCALATE for key in members) / len(members)
        expected_calibration_error += len(members) / count * abs(mean_probability - observed_rate)
        bins.append(
            {
                "lower": lower,
                "upper": upper,
                "count": len(members),
                "mean_probability": round(mean_probability, 12),
                "observed_positive_rate": round(observed_rate, 12),
            }
        )

    confusion = {
        label.value: {
            prediction.value: sum(
                actual[key] is label and predicted[key] is prediction for key in label_keys
            )
            for prediction in _PREDICTIONS
        }
        for label in _LABELS
    }
    selective_correct = sum(
        actual[key] is predicted[key] for key in label_keys if predicted[key] is not Outcome.REVIEW
    )
    return {
        "sample_count": count,
        "positive_class": Outcome.ESCALATE.value,
        "accuracy": round(correct / count, 12),
        "coverage": round(covered / count, 12),
        "selective_accuracy": round(selective_correct / covered if covered else 0.0, 12),
        "precision": round(precision, 12),
        "recall": round(recall, 12),
        "f1": round(f1, 12),
        "brier_score": round(brier, 12),
        "expected_calibration_error": round(expected_calibration_error, 12),
        "calibration_bins": bins,
        "confusion_matrix": confusion,
    }
