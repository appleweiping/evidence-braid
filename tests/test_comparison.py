from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from conftest import event_dict, policy_dict

from evidence_braid.cli import run
from evidence_braid.comparison import (
    LOOSENS,
    STRUCTURAL,
    TIGHTENS,
    UNORDERED,
    ClaimOutcomeChange,
    DecisionImpact,
    PolicyChange,
    PolicyComparison,
    compare_policies,
    decision_impact,
)
from evidence_braid.errors import ValidationError
from evidence_braid.io import canonical_json, load_json
from evidence_braid.models import EvidenceEvent, Policy, parse_timestamp

AS_OF = parse_timestamp("2026-08-31T12:00:00Z", "as_of")


def _current(**claim_overrides: Any) -> dict[str, Any]:
    """A document already at the current schema.

    `policy_dict` is schema 1, and the upgrade refuses a schema 2 field in a
    schema 1 document -- correctly -- so a comparison touching
    `required_modalities` has to start from an upgraded document.
    """

    from evidence_braid.migrations import migrate_policy_document

    document, _report = migrate_policy_document(policy_dict())
    document["claims"]["incident"].update(claim_overrides)
    return document


def _policies(**claim_overrides: Any) -> tuple[Policy, Policy]:
    before = Policy.from_dict(_current())
    return before, Policy.from_dict(_current(**claim_overrides))


def _change(comparison, path: str) -> PolicyChange:
    matching = [item for item in comparison.changes if item.path == path]
    assert matching, f"{path} not reported; got {[c.path for c in comparison.changes]}"
    return matching[0]


# ---------------------------------------------------------------------------
# A comparison says what a change does, not only that it happened.
# ---------------------------------------------------------------------------


def test_an_unchanged_policy_reports_nothing() -> None:
    before = Policy.from_dict(policy_dict())
    comparison = compare_policies(before, Policy.from_dict(policy_dict()))
    assert comparison.identical
    assert comparison.changes == ()
    assert comparison.counts() == {
        TIGHTENS: 0,
        LOOSENS: 0,
        STRUCTURAL: 0,
        UNORDERED: 0,
    }


@pytest.mark.parametrize(
    ("field", "raised", "direction"),
    [
        ("support_threshold", 0.9, TIGHTENS),
        ("support_threshold", 0.1, LOOSENS),
        ("contradiction_threshold", 0.9, TIGHTENS),
        ("min_margin", 0.5, TIGHTENS),
        ("min_margin", 0.0, LOOSENS),
        ("quorum", 5, TIGHTENS),
        ("quorum", 1, LOOSENS),
        ("min_sources", 5, TIGHTENS),
        ("min_modalities", 5, TIGHTENS),
        ("min_evidence_confidence", 0.9, TIGHTENS),
        ("min_evidence_confidence", 0.0, LOOSENS),
    ],
)
def test_each_claim_control_reports_its_direction(
    field: str, raised: float, direction: str
) -> None:
    before, after = _policies(**{field: raised})
    change = _change(compare_policies(before, after), f"claims.incident.{field}")
    assert change.direction == direction
    assert str(raised) in change.effect or str(float(raised)) in change.effect


def test_a_longer_half_life_loosens_every_gate() -> None:
    # Evidence keeps more of its weight, so scores rise everywhere.
    before = Policy.from_dict(policy_dict())
    raw = policy_dict()
    raw["decay"]["default_half_life_seconds"] = 600
    change = _change(
        compare_policies(before, Policy.from_dict(raw)), "decay.default_half_life_seconds"
    )
    assert change.direction == LOOSENS


def test_more_tolerated_skew_loosens() -> None:
    before = Policy.from_dict(policy_dict())
    raw = policy_dict()
    raw["decay"]["max_future_skew_seconds"] = 60
    change = _change(
        compare_policies(before, Policy.from_dict(raw)), "decay.max_future_skew_seconds"
    )
    assert change.direction == LOOSENS


def test_modality_half_life_overrides_are_compared_individually() -> None:
    before = Policy.from_dict(policy_dict())
    raw = policy_dict()
    raw["decay"]["modality_half_life_seconds"] = {"sensor": 30, "vision": 90}
    comparison = compare_policies(before, Policy.from_dict(raw))
    shortened = _change(comparison, "decay.modality_half_life_seconds.sensor")
    added = _change(comparison, "decay.modality_half_life_seconds.vision")
    assert shortened.direction == TIGHTENS
    assert "vision" in added.effect


def test_a_dropped_modality_override_says_what_it_returns_to() -> None:
    raw = policy_dict()
    before = Policy.from_dict(raw)
    without = deepcopy(raw)
    without["decay"]["modality_half_life_seconds"] = {}
    change = _change(
        compare_policies(before, Policy.from_dict(without)),
        "decay.modality_half_life_seconds.sensor",
    )
    assert "default" in change.effect


def test_a_lower_source_reliability_tightens() -> None:
    before = Policy.from_dict(policy_dict())
    raw = policy_dict()
    raw["sources"]["camera-a"] = {"reliability": 0.2}
    change = _change(
        compare_policies(before, Policy.from_dict(raw)), "sources.camera-a.reliability"
    )
    assert change.direction == TIGHTENS
    assert "camera-a" in change.effect


def test_adding_and_removing_a_source_is_structural() -> None:
    raw = policy_dict()
    before = Policy.from_dict(raw)
    extended = deepcopy(raw)
    extended["sources"]["new-sensor"] = {"reliability": 0.4}
    added = _change(compare_policies(before, Policy.from_dict(extended)), "sources.new-sensor")
    assert added.direction == STRUCTURAL
    assert "default" in added.effect

    reduced = deepcopy(raw)
    del reduced["sources"]["camera-a"]
    removed = _change(compare_policies(before, Policy.from_dict(reduced)), "sources.camera-a")
    assert removed.direction == STRUCTURAL


def test_a_changed_default_reliability_is_reported() -> None:
    before = Policy.from_dict(policy_dict())
    raw = policy_dict()
    raw["default_source_reliability"] = 0.3
    change = _change(compare_policies(before, Policy.from_dict(raw)), "default_source_reliability")
    assert change.direction == TIGHTENS


def test_adding_and_removing_a_claim_is_structural() -> None:
    raw = policy_dict()
    before = Policy.from_dict(raw)
    extended = deepcopy(raw)
    extended["claims"]["second"] = deepcopy(raw["claims"]["incident"])
    added = _change(compare_policies(before, Policy.from_dict(extended)), "claims.second")
    assert added.direction == STRUCTURAL
    assert "not evaluated before" in added.effect
    removed = _change(compare_policies(Policy.from_dict(extended), before), "claims.second")
    assert "no longer evaluated" in removed.effect


def test_a_new_required_modality_tightens_and_says_why() -> None:
    before, after = _policies(required_modalities=["vision"])
    change = _change(compare_policies(before, after), "claims.incident.required_modalities")
    assert change.direction == TIGHTENS
    assert "however many other modalities" in change.effect
    relaxed = _change(compare_policies(after, before), "claims.incident.required_modalities")
    assert relaxed.direction == LOOSENS


def test_turning_reliability_updating_on_is_not_orderable() -> None:
    # Whether it helps or hurts a source depends on adjudications the caller
    # supplies, so claiming a direction would be an invention.
    before = Policy.from_dict(policy_dict())
    raw = policy_dict()
    raw["reliability_updates"] = {"prior_weight": 4, "max_adjustment": 0.2}
    after = Policy.from_dict(raw)
    change = _change(compare_policies(before, after), "reliability_updates")
    assert change.direction == UNORDERED
    off = _change(compare_policies(after, before), "reliability_updates")
    assert off.direction == UNORDERED
    assert "becomes an error" in off.effect


def test_reliability_update_parameters_are_compared() -> None:
    raw = policy_dict()
    raw["reliability_updates"] = {"prior_weight": 4, "max_adjustment": 0.2}
    before = Policy.from_dict(raw)
    changed = deepcopy(raw)
    changed["reliability_updates"] = {"prior_weight": 12, "max_adjustment": 0.5}
    comparison = compare_policies(before, Policy.from_dict(changed))
    for path in (
        "reliability_updates.prior_weight",
        "reliability_updates.max_adjustment",
    ):
        change = _change(comparison, path)
        assert change.direction == UNORDERED
        assert "depending on" in change.effect
        reverse = _change(compare_policies(Policy.from_dict(changed), before), path)
        assert reverse.direction == UNORDERED


def test_a_renamed_policy_warns_that_stored_results_will_not_match() -> None:
    before = Policy.from_dict(policy_dict())
    raw = policy_dict()
    raw["policy_id"] = "renamed"
    change = _change(compare_policies(before, Policy.from_dict(raw)), "policy_id")
    assert change.direction == STRUCTURAL
    assert "will not match by name" in change.effect


def test_a_schema_upgrade_alone_moves_no_decision() -> None:
    from evidence_braid.migrations import migrate_policy_document

    legacy = Policy.from_dict(policy_dict())
    upgraded, _report = migrate_policy_document(policy_dict())
    change = _change(compare_policies(legacy, Policy.from_dict(upgraded)), "schema_version")
    assert change.direction == STRUCTURAL
    assert "moves no decision" in change.effect


def test_changes_are_ordered_and_serializable() -> None:
    before = Policy.from_dict(policy_dict())
    raw = policy_dict()
    raw["policy_id"] = "renamed"
    raw["claims"]["incident"]["quorum"] = 5
    raw["decay"]["default_half_life_seconds"] = 600
    comparison = compare_policies(before, Policy.from_dict(raw))
    paths = [change.path for change in comparison.changes]
    assert paths == sorted(paths)
    payload = comparison.to_dict()
    assert payload["change_count"] == len(comparison.changes)
    assert json.loads(canonical_json(payload)) == payload


@pytest.mark.parametrize("bad", [None, "policy", 3])
def test_a_comparison_requires_two_policies(bad: object) -> None:
    before = Policy.from_dict(policy_dict())
    with pytest.raises(ValidationError, match="must be a Policy"):
        compare_policies(before, bad)  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="must be a Policy"):
        compare_policies(bad, before)  # type: ignore[arg-type]


def test_a_change_validates_its_own_fields() -> None:
    with pytest.raises(ValidationError, match="direction"):
        PolicyChange(path="a", before=1, after=2, direction="sideways", effect="x")
    with pytest.raises(ValidationError, match="path"):
        PolicyChange(path="", before=1, after=2, direction=TIGHTENS, effect="x")
    with pytest.raises(ValidationError, match="effect"):
        PolicyChange(path="a", before=1, after=2, direction=TIGHTENS, effect="")


def test_a_change_owns_nested_values_and_returns_detached_json() -> None:
    before = {"required": ["vision"]}
    change = PolicyChange(
        path="claims.incident.required_modalities",
        before=before,
        after={"required": ["audio"]},
        direction=UNORDERED,
        effect="changes the required evidence",
    )
    before["required"].append("audio")
    first = change.to_dict()
    first["before"]["required"].append("sensor")

    assert change.to_dict()["before"] == {"required": ["vision"]}


def test_comparison_snapshots_and_revalidates_its_change_sequence() -> None:
    change = PolicyChange("z", None, 1, STRUCTURAL, "adds z")
    source = [change]
    comparison = PolicyComparison(source)  # type: ignore[arg-type]
    source.clear()

    assert comparison.changes == (change,)
    with pytest.raises(ValidationError, match=r"comparison\.changes\[0\]"):
        replace(comparison, changes=("not-a-change",))  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="must be a sequence"):
        replace(comparison, changes=3)  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="duplicate"):
        replace(comparison, changes=(change, change))


def test_comparison_owns_changes_and_revalidates_nested_tampering() -> None:
    caller_change = PolicyChange("field", 1, 2, TIGHTENS, "raises a gate")
    comparison = PolicyComparison((caller_change,))
    object.__setattr__(caller_change, "direction", "tampered")
    assert comparison.to_dict()["changes"][0]["direction"] == TIGHTENS

    object.__setattr__(comparison.changes[0], "direction", "tampered")
    with pytest.raises(ValidationError, match="direction"):
        comparison.to_dict()
    with pytest.raises(ValidationError, match="direction"):
        comparison.counts()


# ---------------------------------------------------------------------------
# What the two policies actually decide.
# ---------------------------------------------------------------------------


def _events() -> list[EvidenceEvent]:
    return [
        EvidenceEvent.from_dict(
            event_dict("vision-1", modality="vision", source="camera-a", confidence=0.95)
        ),
        EvidenceEvent.from_dict(
            event_dict("audio-1", modality="audio", source="microphone-a", confidence=0.95)
        ),
    ]


def test_a_tightened_threshold_that_nothing_reaches_moves_nothing() -> None:
    # The field comparison says a gate moved; only evaluation says whether any
    # claim was near it. That distinction is the reason both halves exist.
    before, after = _policies(support_threshold=0.05)
    impact = decision_impact(before, after, _events(), AS_OF)
    assert impact.identical
    assert impact.changes == ()
    assert impact.claims_compared == 1


def test_an_impossible_threshold_withholds_the_decision() -> None:
    before, after = _policies(support_threshold=1.0, min_margin=1.0)
    impact = decision_impact(before, after, _events(), AS_OF)
    assert not impact.identical
    assert len(impact.changes) == 1
    change = impact.changes[0]
    assert change.claim == "incident"
    assert change.after == "review"
    assert change.before_reason and change.after_reason


def test_a_claim_only_one_policy_evaluates_is_reported() -> None:
    raw = policy_dict()
    before = Policy.from_dict(raw)
    extended = deepcopy(raw)
    extended["claims"]["second"] = deepcopy(raw["claims"]["incident"])
    impact = decision_impact(before, Policy.from_dict(extended), _events(), AS_OF)
    added = [change for change in impact.changes if change.claim == "second"]
    assert added and added[0].before == "not evaluated"


def test_the_impact_is_serializable_and_records_both_digests() -> None:
    before, after = _policies(support_threshold=1.0, min_margin=1.0)
    payload = decision_impact(before, after, _events(), AS_OF).to_dict()
    assert payload["before_digest"] != payload["after_digest"]
    assert payload["changed_count"] == 1
    assert payload["evaluated_at"].endswith("Z")
    assert json.loads(canonical_json(payload)) == payload


def test_result_digest_metadata_can_change_without_an_outcome_moving() -> None:
    before = Policy.from_dict(policy_dict())
    raw = policy_dict()
    raw["policy_id"] = "renamed"
    impact = decision_impact(before, Policy.from_dict(raw), _events(), AS_OF)

    assert impact.changes == ()
    assert impact.before_digest != impact.after_digest
    assert impact.identical is True


def test_impact_models_revalidate_dataclass_replace() -> None:
    before, after = _policies(support_threshold=1.0, min_margin=1.0)
    impact = decision_impact(before, after, _events(), AS_OF)
    change = impact.changes[0]

    with pytest.raises(ValidationError, match="must move"):
        replace(change, after=change.before)
    with pytest.raises(ValidationError, match="claims_compared"):
        replace(impact, claims_compared=-1)
    with pytest.raises(ValidationError, match=r"impact\.changes\[0\]"):
        replace(impact, changes=("not-a-change",))  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="must be a sequence"):
        replace(impact, changes=3)  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="duplicate"):
        replace(impact, changes=(change, change))
    with pytest.raises(ValidationError, match="cannot exceed"):
        replace(impact, claims_compared=0)
    with pytest.raises(ValidationError, match="before_digest"):
        replace(impact, before_digest="not-a-digest")
    with pytest.raises(ValidationError, match="different result digests"):
        replace(impact, after_digest=impact.before_digest)


def test_outcome_change_rejects_unknown_outcomes() -> None:
    with pytest.raises(ValidationError, match="before"):
        ClaimOutcomeChange("incident", "unknown", "review", "before", "after")


def test_impact_direct_construction_sorts_and_snapshots_changes() -> None:
    one = ClaimOutcomeChange("z", "review", "escalate", "before", "after")
    two = ClaimOutcomeChange("a", "review", "reject", "before", "after")
    source = [one, two]
    impact = DecisionImpact(
        evaluated_at="2026-08-31T07:00:00-05:00",
        claims_compared=2,
        changes=source,  # type: ignore[arg-type]
        before_digest="sha256:" + "0" * 64,
        after_digest="sha256:" + "1" * 64,
    )
    source.clear()

    assert impact.evaluated_at == "2026-08-31T12:00:00Z"
    assert [change.claim for change in impact.changes] == ["a", "z"]


def test_impact_owns_changes_and_revalidates_nested_tampering() -> None:
    caller_change = ClaimOutcomeChange("incident", "review", "escalate", "before", "after")
    impact = DecisionImpact(
        evaluated_at="2026-08-31T12:00:00Z",
        claims_compared=1,
        changes=(caller_change,),
        before_digest="sha256:" + "0" * 64,
        after_digest="sha256:" + "1" * 64,
    )
    object.__setattr__(caller_change, "after", "unknown")
    assert impact.to_dict()["changes"][0]["after"] == "escalate"

    object.__setattr__(impact.changes[0], "after", "unknown")
    with pytest.raises(ValidationError, match="after"):
        impact.to_dict()


# ---------------------------------------------------------------------------
# The command line.
# ---------------------------------------------------------------------------


def _write(path: Path, payload: dict[str, Any]) -> Path:
    path.write_text(canonical_json(payload), encoding="utf-8")
    return path


def test_cli_writes_a_comparison(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    before = _write(tmp_path / "before.json", policy_dict())
    raw = policy_dict()
    raw["claims"]["incident"]["quorum"] = 5
    after = _write(tmp_path / "after.json", raw)
    assert run(["diff-policy", str(before), str(after)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["comparison"]["counts"]["tightens"] == 1
    assert payload["before"].endswith("before.json")
    assert "\\" not in payload["before"]
    assert "decision_impact" not in payload


def test_cli_adds_the_decision_impact_when_given_evidence(tmp_path: Path) -> None:
    before = _write(tmp_path / "before.json", policy_dict())
    raw = policy_dict()
    raw["claims"]["incident"]["support_threshold"] = 1.0
    raw["claims"]["incident"]["min_margin"] = 1.0
    after = _write(tmp_path / "after.json", raw)
    events = tmp_path / "events.jsonl"
    events.write_text(
        "".join(
            canonical_json(item, pretty=False) + "\n"
            for item in (
                event_dict("vision-1", modality="vision", source="camera-a", confidence=0.95),
                event_dict("audio-1", modality="audio", source="microphone-a", confidence=0.95),
            )
        ),
        encoding="utf-8",
    )
    output = tmp_path / "diff.json"
    code = run(
        [
            "diff-policy",
            str(before),
            str(after),
            "--events",
            str(events),
            "--as-of",
            "2026-08-31T12:00:00Z",
            "--output",
            str(output),
        ]
    )
    assert code == 0
    payload = load_json(output)
    assert payload["decision_impact"]["changed_count"] == 1
    assert payload["decision_impact"]["identical"] is False


def test_cli_requires_the_two_options_together(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    before = _write(tmp_path / "before.json", policy_dict())
    after = _write(tmp_path / "after.json", policy_dict())
    events = tmp_path / "events.jsonl"
    events.write_text("", encoding="utf-8")

    assert run(["diff-policy", str(before), str(after), "--events", str(events)]) == 2
    assert "--as-of" in capsys.readouterr().err

    assert run(["diff-policy", str(before), str(after), "--as-of", "2026-08-31T12:00:00Z"]) == 2
    assert "no effect without --events" in capsys.readouterr().err


def test_cli_reports_an_unreadable_policy(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    before = _write(tmp_path / "before.json", policy_dict())
    assert run(["diff-policy", str(before), str(tmp_path / "absent.json")]) == 2
    assert "error:" in capsys.readouterr().err


def test_reliability_update_parameters_may_change_one_at_a_time() -> None:
    # Each parameter is compared independently, so a policy that moves only one
    # of them reports only that one.
    raw = policy_dict()
    raw["reliability_updates"] = {"prior_weight": 4, "max_adjustment": 0.2}
    before = Policy.from_dict(raw)
    for field, value, path in (
        ("prior_weight", 12, "reliability_updates.prior_weight"),
        ("max_adjustment", 0.5, "reliability_updates.max_adjustment"),
    ):
        changed = deepcopy(raw)
        changed["reliability_updates"][field] = value
        comparison = compare_policies(before, Policy.from_dict(changed))
        assert [item.path for item in comparison.changes] == [path]


def test_a_claim_dropped_by_the_new_policy_is_reported_as_moved() -> None:
    raw = policy_dict()
    extended = deepcopy(raw)
    extended["claims"]["second"] = deepcopy(raw["claims"]["incident"])
    impact = decision_impact(Policy.from_dict(extended), Policy.from_dict(raw), _events(), AS_OF)
    dropped = [change for change in impact.changes if change.claim == "second"]
    assert dropped and dropped[0].after == "not evaluated"
    assert dropped[0].after_reason == "claim absent"
