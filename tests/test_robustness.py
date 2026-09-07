from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from conftest import event_dict, policy_dict

from evidence_braid import ClaimRobustness, Outcome, RobustnessReport, robustness
from evidence_braid.cli import run
from evidence_braid.errors import ValidationError
from evidence_braid.robustness import RobustnessImpact

AS_OF = datetime(2026, 8, 31, 12, 0, tzinfo=UTC)


def _two_signal_events(make_event):
    return [
        make_event("camera", modality="vision", source="camera-a", confidence=1.0),
        make_event("microphone", modality="audio", source="microphone-a", confidence=1.0),
    ]


def test_robustness_reports_the_event_that_opens_the_gate(policy, make_event) -> None:
    report = robustness(policy, _two_signal_events(make_event), AS_OF)

    assert isinstance(report, RobustnessReport)
    claim = report.claims[0]
    assert claim.baseline_outcome is Outcome.ESCALATE
    assert claim.tested_event_count == 2
    assert claim.changed_event_count == 2
    assert {impact.event_id for impact in claim.impacts} == {"camera", "microphone"}
    assert all(impact.without_event_outcome is Outcome.REVIEW for impact in claim.impacts)
    assert claim.stability == 0.0
    assert report.fragile_claims == ("incident",)


def test_robustness_ignores_pending_events(policy, make_event) -> None:
    pending = make_event("later", ingested_at="2026-08-31T12:01:00Z")
    report = robustness(policy, [*_two_signal_events(make_event), pending], AS_OF)

    assert report.input_event_count == 3
    assert report.considered_event_count == 2
    assert all(impact.event_id != "later" for item in report.claims for impact in item.impacts)


def test_robustness_is_order_independent(policy, make_event) -> None:
    first = robustness(policy, _two_signal_events(make_event), AS_OF)
    second = robustness(policy, reversed(_two_signal_events(make_event)), AS_OF)
    assert first.to_dict() == second.to_dict()


def test_robustness_cost_guard_is_explicit(policy, make_event) -> None:
    with pytest.raises(ValidationError, match="max_events"):
        robustness(policy, _two_signal_events(make_event), AS_OF, max_events=1)


def test_robustness_rejects_invalid_max_events(policy, make_event) -> None:
    with pytest.raises(ValidationError, match="max_events"):
        robustness(policy, [], AS_OF, max_events=0)


def test_robustness_is_stable_when_no_visible_event_changes_review(policy, make_event) -> None:
    report = robustness(policy, [make_event()], AS_OF)

    claim = report.claims[0]
    assert claim.baseline_outcome is Outcome.REVIEW
    assert claim.changed_event_count == 0
    assert claim.stability == 1.0
    assert report.fragile_claims == ()


def test_empty_robustness_window_has_unit_stability(policy) -> None:
    report = robustness(policy, [], AS_OF)
    assert report.considered_event_count == 0
    assert report.claims[0].stability == 1.0


def test_robustness_models_reject_invalid_nested_values() -> None:
    with pytest.raises(ValidationError, match=r"impact\.baseline_outcome"):
        RobustnessImpact(
            event_id="e1",
            claim="incident",
            baseline_outcome="escalate",  # type: ignore[arg-type]
            without_event_outcome=Outcome.REVIEW,
            baseline_reason="ok",
            without_event_reason="missing",
            baseline_margin=0.5,
            without_event_margin=0.0,
        )
    with pytest.raises(ValidationError, match="must change"):
        RobustnessImpact(
            event_id="e1",
            claim="incident",
            baseline_outcome=Outcome.REVIEW,
            without_event_outcome=Outcome.REVIEW,
            baseline_reason="ok",
            without_event_reason="still ok",
            baseline_margin=0.0,
            without_event_margin=0.0,
        )
    with pytest.raises(ValidationError, match="RobustnessImpact"):
        ClaimRobustness(
            claim="incident",
            baseline_outcome=Outcome.REVIEW,
            baseline_margin=0.0,
            tested_event_count=1,
            changed_event_count=1,
            impacts=("not-an-impact",),  # type: ignore[arg-type]
        )


def test_robustness_report_rejects_invalid_shell() -> None:
    claim = ClaimRobustness(
        claim="incident",
        baseline_outcome=Outcome.REVIEW,
        baseline_margin=0.0,
        tested_event_count=0,
        changed_event_count=0,
    )
    with pytest.raises(ValidationError, match="schema_version"):
        RobustnessReport(2, "policy", AS_OF, 0, 0, "sha256:" + "0" * 64, (claim,))
    with pytest.raises(ValidationError, match="considered_event_count"):
        RobustnessReport(1, "policy", AS_OF, 0, 1, "sha256:" + "0" * 64, (claim,))
    with pytest.raises(ValidationError, match="baseline_digest"):
        RobustnessReport(1, "policy", AS_OF, 0, 0, "not-a-digest", (claim,))


def test_robustness_models_reject_inconsistent_impacts() -> None:
    with pytest.raises(ValidationError, match="changed_event_count"):
        ClaimRobustness(
            claim="incident",
            baseline_outcome=Outcome.ESCALATE,
            baseline_margin=0.5,
            tested_event_count=1,
            changed_event_count=1,
            impacts=(),
        )


def test_cli_robustness_writes_machine_report(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.json"
    event_path = tmp_path / "events.jsonl"
    output_path = tmp_path / "robustness.json"
    policy_path.write_text(json.dumps(policy_dict()), encoding="utf-8")
    first = event_dict("camera", modality="vision", source="camera-a", confidence=1.0)
    second = event_dict("microphone", modality="audio", source="microphone-a", confidence=1.0)
    event_path.write_text(
        "\n".join(json.dumps(item) for item in (first, second)) + "\n", encoding="utf-8"
    )

    assert (
        run(
            [
                "robustness",
                str(policy_path),
                str(event_path),
                "--as-of",
                "2026-08-31T12:00:00Z",
                "--output",
                str(output_path),
            ]
        )
        == 0
    )
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["fragile_claims"] == ["incident"]
    assert payload["baseline_digest"].startswith("sha256:")
