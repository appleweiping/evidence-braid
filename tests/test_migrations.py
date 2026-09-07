from __future__ import annotations

import json
import random
from collections.abc import Iterator, Mapping, Sequence
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from conftest import event_dict, policy_dict

import evidence_braid.migrations as migration_module
import evidence_braid.models as model_module
from evidence_braid.cli import run
from evidence_braid.engine import evaluate
from evidence_braid.errors import ValidationError
from evidence_braid.io import canonical_json, load_json
from evidence_braid.migrations import (
    CURRENT_POLICY_SCHEMA_VERSION,
    EARLIEST_POLICY_SCHEMA_VERSION,
    MigrationNote,
    MigrationReport,
    migrate_policy_document,
    policy_schema_version,
)
from evidence_braid.models import EvidenceEvent, Modality, Policy, parse_timestamp

AS_OF = parse_timestamp("2026-08-31T12:00:00Z", "as_of")
MODALITIES = tuple(modality.value for modality in Modality)


def _at(version: int) -> dict[str, Any]:
    raw = policy_dict()
    raw["schema_version"] = version
    return raw


def _current(**claim_overrides: Any) -> dict[str, Any]:
    document, _report = migrate_policy_document(policy_dict())
    document["claims"]["incident"].update(claim_overrides)
    return document


# --------------------------------------------------------------------------
# Version handling.
# --------------------------------------------------------------------------


def test_reads_the_declared_version() -> None:
    assert policy_schema_version(_at(1)) == 1
    assert policy_schema_version(_current()) == CURRENT_POLICY_SCHEMA_VERSION


@pytest.mark.parametrize("raw", [None, [], "policy", 3])
def test_a_version_cannot_be_read_from_a_non_object(raw: object) -> None:
    with pytest.raises(ValidationError, match="policy must be a JSON object"):
        policy_schema_version(raw)


@pytest.mark.parametrize("version", [True, 1.0, "1", None])
def test_a_version_must_be_an_integer(version: object) -> None:
    raw = policy_dict()
    raw["schema_version"] = version
    with pytest.raises(ValidationError, match="must be an integer"):
        policy_schema_version(raw)


def test_a_version_below_the_earliest_supported_is_refused() -> None:
    with pytest.raises(ValidationError, match="older than the earliest supported"):
        policy_schema_version(_at(EARLIEST_POLICY_SCHEMA_VERSION - 1))


def test_a_newer_document_is_refused_rather_than_read_with_older_semantics() -> None:
    with pytest.raises(ValidationError, match="newer than this build understands"):
        policy_schema_version(_at(CURRENT_POLICY_SCHEMA_VERSION + 1))


@pytest.mark.parametrize("raw", [None, [], "policy"])
def test_migration_refuses_a_non_object(raw: object) -> None:
    with pytest.raises(ValidationError, match="policy must be a JSON object"):
        migrate_policy_document(raw)


# --------------------------------------------------------------------------
# What the upgrade does, and what it refuses to guess.
# --------------------------------------------------------------------------


def test_the_upgrade_states_the_behaviour_schema_1_already_had() -> None:
    document, report = migrate_policy_document(policy_dict())

    assert report.from_version == 1
    assert report.to_version == CURRENT_POLICY_SCHEMA_VERSION
    assert report.migrated is True
    assert document["schema_version"] == CURRENT_POLICY_SCHEMA_VERSION
    assert document["claims"]["incident"]["required_modalities"] == []
    assert [note.path for note in report.notes] == ["policy.claims.incident.required_modalities"]
    assert "schema 1 could not require a modality" in report.notes[0].change


def test_the_upgrade_does_not_modify_its_input() -> None:
    raw = policy_dict()
    before = deepcopy(raw)
    migrate_policy_document(raw)
    assert raw == before


@pytest.mark.parametrize("current", [False, True])
def test_a_migrated_document_shares_no_nested_state_with_its_input(current: bool) -> None:
    raw = _current() if current else policy_dict()
    original = deepcopy(raw)
    document, _report = migrate_policy_document(raw)
    migrated = deepcopy(document)

    document["sources"]["camera-a"]["reliability"] = 0.01
    document["decay"]["default_half_life_seconds"] = 1
    document["claims"]["incident"]["required_modalities"].append("vision")
    assert raw == original

    raw["sources"]["camera-a"]["reliability"] = 0.99
    raw["decay"]["default_half_life_seconds"] = 999
    assert migrated["sources"] != raw["sources"]
    assert migrated["decay"] != raw["decay"]


def test_migration_rejects_a_reference_cycle_with_a_domain_error() -> None:
    raw = _current()
    raw["cycle"] = raw

    with pytest.raises(ValidationError, match="reference cycle"):
        migrate_policy_document(raw)


def test_migration_bounds_a_mapping_that_lies_about_its_length(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class EndlessPolicy(Mapping[str, Any]):
        def __init__(self) -> None:
            self.items_requested = 0

        def __getitem__(self, key: str) -> Any:
            if key == "schema_version":
                return CURRENT_POLICY_SCHEMA_VERSION
            return key

        def __iter__(self) -> Iterator[str]:
            yield "schema_version"
            index = 0
            while True:
                self.items_requested += 1
                yield f"field-{index}"
                index += 1

        def __len__(self) -> int:
            return 1

    raw = EndlessPolicy()
    monkeypatch.setattr(model_module, "MAX_ATTRIBUTE_NODES", 5)

    with pytest.raises(ValidationError, match="maximum JSON value count"):
        migrate_policy_document(raw)
    assert raw.items_requested <= 5


def test_migration_rejects_non_json_state_before_policy_parsing() -> None:
    raw = _current()
    raw["extra"] = object()

    with pytest.raises(ValidationError, match="only JSON values"):
        migrate_policy_document(raw)


def test_migration_dispatches_from_the_owned_version_snapshot() -> None:
    class ChangingVersionPolicy(Mapping[str, Any]):
        def __init__(self) -> None:
            self.document = _current()
            self.version_reads = 0

        def __getitem__(self, key: str) -> Any:
            if key == "schema_version":
                self.version_reads += 1
                return 2 if self.version_reads == 1 else 1
            return self.document[key]

        def __iter__(self) -> Iterator[str]:
            return iter(self.document)

        def __len__(self) -> int:
            return len(self.document)

    document, report = migrate_policy_document(ChangingVersionPolicy())

    assert document["schema_version"] == CURRENT_POLICY_SCHEMA_VERSION
    assert report.from_version == CURRENT_POLICY_SCHEMA_VERSION
    assert report.migrated is False
    Policy.from_dict(document)


def test_a_current_document_is_returned_unchanged() -> None:
    document, report = migrate_policy_document(_current())
    assert report.migrated is False
    assert report.notes == ()
    assert document == _current()


def test_the_upgrade_is_idempotent() -> None:
    once, _first = migrate_policy_document(policy_dict())
    twice, second = migrate_policy_document(deepcopy(once))
    assert twice == once
    assert second.migrated is False


def test_a_schema_1_document_may_not_use_a_schema_2_field() -> None:
    raw = policy_dict(required_modalities=["vision"])
    with pytest.raises(ValidationError, match="not part of schema 1"):
        migrate_policy_document(raw)


@pytest.mark.parametrize("claims", [None, [], "claims", 3])
def test_the_upgrade_requires_a_claims_object(claims: object) -> None:
    raw = policy_dict()
    raw["claims"] = claims
    with pytest.raises(ValidationError, match=r"policy\.claims must be a JSON object"):
        migrate_policy_document(raw)


def test_the_upgrade_requires_each_claim_to_be_an_object() -> None:
    raw = policy_dict()
    raw["claims"]["incident"] = "not-a-rule"
    with pytest.raises(ValidationError, match=r"policy\.claims\.incident must be a JSON object"):
        migrate_policy_document(raw)


def test_notes_serialize_for_a_report_file() -> None:
    _document, report = migrate_policy_document(policy_dict())
    payload = report.to_dict()
    assert payload["from_version"] == 1
    assert payload["migrated"] is True
    assert payload["notes"][0]["path"].endswith("required_modalities")
    assert json.loads(canonical_json(payload)) == payload


@pytest.mark.parametrize(
    ("path", "change", "message"),
    [
        (None, "added a field", "migration_note.path must be a non-empty string"),
        ("   ", "added a field", "migration_note.path must be a non-empty string"),
        ("policy.claim", "", "migration_note.change must be a non-empty string"),
        ("policy.claim", "contains\x00control", "not allowed by XML"),
    ],
)
def test_migration_notes_validate_direct_construction(
    path: object, change: object, message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        MigrationNote(path=path, change=change)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("from_version", "to_version", "notes", "message"),
    [
        (True, 2, (), "from_version must be an integer"),
        (0, 2, (), "from_version must be a supported"),
        (1, 3, (), "to_version must be a supported"),
        (2, 1, (), "to_version must not precede"),
        (1, 2, None, "notes must be a sequence"),
        (1, 2, "note", "notes must be a sequence"),
        (1, 2, ["note"], r"notes\[0\] must be a MigrationNote"),
        (2, 2, [MigrationNote("policy.claim", "changed")], "must not contain"),
    ],
)
def test_migration_reports_validate_direct_construction(
    from_version: object,
    to_version: object,
    notes: object,
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        MigrationReport(  # type: ignore[arg-type]
            from_version=from_version,
            to_version=to_version,
            notes=notes,
        )


def test_a_migration_report_deeply_snapshots_notes() -> None:
    note = MigrationNote("policy.claim", "added a field")
    supplied = [note]
    report = MigrationReport(from_version=1, to_version=2, notes=supplied)  # type: ignore[arg-type]

    supplied.clear()
    object.__setattr__(note, "path", "policy.tampered")

    assert report.to_dict()["notes"] == [{"path": "policy.claim", "change": "added a field"}]


def test_a_migration_report_bounds_a_non_terminating_notes_sequence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class EndlessNotes(Sequence[MigrationNote]):
        def __init__(self) -> None:
            self.items_requested = 0

        def __getitem__(self, index: int) -> MigrationNote:
            self.items_requested += 1
            return MigrationNote(f"policy.claim-{index}", "added a field")

        def __len__(self) -> int:
            return 0

    notes = EndlessNotes()
    monkeypatch.setattr(migration_module, "MAX_MIGRATION_NOTES", 3)

    with pytest.raises(ValidationError, match="may contain at most 3 entries"):
        MigrationReport(from_version=1, to_version=2, notes=notes)  # type: ignore[arg-type]
    assert notes.items_requested <= 4


def test_migration_note_serialization_revalidates_a_tampered_shell() -> None:
    note = MigrationNote("policy.claim", "added a field")
    object.__setattr__(note, "change", "")

    with pytest.raises(ValidationError, match=r"migration_note\.change"):
        note.to_dict()


def test_migration_report_serialization_revalidates_nested_notes() -> None:
    report = MigrationReport(
        from_version=1,
        to_version=2,
        notes=(MigrationNote("policy.claim", "added a field"),),
    )
    object.__setattr__(report.notes[0], "path", "")

    with pytest.raises(ValidationError, match=r"migration_note\.path"):
        report.to_dict()


def test_migration_report_serialization_revalidates_version_fields() -> None:
    report = MigrationReport(from_version=2, to_version=2)
    object.__setattr__(report, "from_version", True)

    with pytest.raises(ValidationError, match="from_version must be an integer"):
        report.to_dict()


def test_an_unmigrated_report_is_reported_as_such() -> None:
    report = MigrationReport(from_version=2, to_version=2)
    assert report.migrated is False


# --------------------------------------------------------------------------
# The loaded policy says where it came from.
# --------------------------------------------------------------------------


def test_a_loaded_policy_records_the_version_its_document_declared() -> None:
    upgraded = Policy.from_dict(policy_dict())
    native = Policy.from_dict(_current())

    assert upgraded.schema_version == CURRENT_POLICY_SCHEMA_VERSION
    assert upgraded.source_schema_version == 1
    assert native.source_schema_version == CURRENT_POLICY_SCHEMA_VERSION
    assert upgraded.claims["incident"].required_modalities == ()


@pytest.mark.parametrize("version", [0, CURRENT_POLICY_SCHEMA_VERSION + 1, True, 1.0, "1", None])
def test_a_policy_bounds_its_recorded_source_version(version: object) -> None:
    parsed = Policy.from_dict(policy_dict())
    with pytest.raises(ValidationError, match="source_schema_version"):
        Policy(
            schema_version=CURRENT_POLICY_SCHEMA_VERSION,
            policy_id=parsed.policy_id,
            default_source_reliability=parsed.default_source_reliability,
            sources=dict(parsed.sources),
            decay=parsed.decay,
            claims=dict(parsed.claims),
            source_schema_version=version,  # type: ignore[arg-type]
        )


# --------------------------------------------------------------------------
# The capability schema 1 could not express.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("modality", MODALITIES)
def test_every_modality_may_be_required(modality: str) -> None:
    rule = Policy.from_dict(_current(required_modalities=[modality])).claims["incident"]
    assert rule.required_modalities == (modality,)


def test_required_modalities_are_stored_in_a_canonical_order() -> None:
    a = Policy.from_dict(_current(required_modalities=["vision", "audio"]))
    b = Policy.from_dict(_current(required_modalities=["audio", "vision"]))
    assert a.claims["incident"].required_modalities == ("audio", "vision")
    assert a.claims["incident"] == b.claims["incident"]


@pytest.mark.parametrize(
    ("value", "message"),
    [
        (["camera"], "not a supported modality"),
        (["vision", "vision"], "must not contain duplicates"),
        ("vision", "must be a sequence of strings"),
        ([1], "must be a non-empty string"),
        ([" vision"], "surrounding whitespace"),
        ({"vision": True}, "must be a sequence of strings"),
        (5, "must be a sequence of strings"),
        (None, "must be a sequence of strings"),
    ],
)
def test_required_modalities_are_validated(value: object, message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        Policy.from_dict(_current(required_modalities=value))


def _events() -> list[EvidenceEvent]:
    return [
        EvidenceEvent.from_dict(
            event_dict("vision-1", modality="vision", source="camera-a", confidence=0.95)
        ),
        EvidenceEvent.from_dict(
            event_dict("audio-1", modality="audio", source="microphone-a", confidence=0.95)
        ),
    ]


def _decision(required: list[str]) -> dict[str, Any]:
    policy = Policy.from_dict(_current(required_modalities=required))
    result = evaluate(policy, _events(), AS_OF).to_dict()
    entry: dict[str, Any] = result["decisions"][0]
    return entry


def test_a_present_requirement_leaves_the_decision_alone() -> None:
    assert _decision([])["outcome"] == "escalate"
    assert _decision(["vision"])["outcome"] == "escalate"
    assert _decision(["audio", "vision"])["outcome"] == "escalate"


def test_an_absent_requirement_withholds_the_decision() -> None:
    # The evidence is strong and diverse enough to clear `min_modalities`, so
    # counting alone would escalate. Naming a modality that never appeared is
    # exactly what schema 1 could not do.
    withheld = _decision(["sensor"])
    assert withheld["outcome"] == "review"
    assert withheld["support"]["gate_passed"] is False
    assert withheld["support"]["qualifying_modalities"] == ["audio", "vision"]


def test_a_requirement_gates_each_signal_separately() -> None:
    # Support is vision+audio; the contradiction below is text only. Requiring
    # vision therefore leaves the support gate open and closes the other one.
    events = [
        *_events(),
        EvidenceEvent.from_dict(
            event_dict(
                "text-1",
                modality="text",
                source="operator-a",
                signal="contradict",
                confidence=0.99,
            )
        ),
    ]
    policy = Policy.from_dict(
        _current(required_modalities=["vision"], quorum=1, min_sources=1, min_modalities=1)
    )
    entry = evaluate(policy, events, AS_OF).to_dict()["decisions"][0]
    assert entry["support"]["gate_passed"] is True
    assert entry["contradict"]["gate_passed"] is False


# --------------------------------------------------------------------------
# The property that makes the upgrade safe to apply without review.
# --------------------------------------------------------------------------


def _random_events(rng: random.Random) -> list[EvidenceEvent]:
    sources = ("camera-a", "microphone-a", "operator-a")
    events = []
    for index in range(rng.randint(1, 6)):
        events.append(
            EvidenceEvent.from_dict(
                event_dict(
                    f"e{index}",
                    modality=rng.choice(MODALITIES),
                    source=rng.choice(sources),
                    signal=rng.choice(("support", "contradict")),
                    confidence=round(rng.uniform(0.0, 1.0), 3),
                )
            )
        )
    return events


def _random_claim(rng: random.Random) -> dict[str, Any]:
    return {
        "support_threshold": round(rng.uniform(0.0, 1.0), 3),
        "contradiction_threshold": round(rng.uniform(0.0, 1.0), 3),
        "min_margin": round(rng.uniform(0.0, 0.4), 3),
        "quorum": rng.randint(1, 3),
        "min_sources": rng.randint(1, 3),
        "min_modalities": rng.randint(1, 3),
        "min_evidence_confidence": round(rng.uniform(0.0, 0.5), 3),
    }


def test_the_upgrade_never_changes_a_decision() -> None:
    """The upgraded policy must decide exactly as the document it came from.

    A migration that silently moved a decision would be worse than refusing the
    old file outright, because nothing downstream would show that it happened.
    An empty requirement is the identity for the new gate, and this checks that
    over randomized policies and evidence rather than asserting it.
    """

    for seed in range(300):
        rng = random.Random(seed)
        raw = policy_dict(**_random_claim(rng))
        events = _random_events(rng)

        from_v1 = evaluate(Policy.from_dict(raw), events, AS_OF)
        upgraded, report = migrate_policy_document(raw)
        from_v2 = evaluate(Policy.from_dict(upgraded), events, AS_OF)

        assert report.from_version == 1
        assert from_v1.digest == from_v2.digest


def test_requiring_a_modality_can_only_ever_withhold_a_decision() -> None:
    """Adding a requirement must never open a gate that was closed.

    This is what makes an empty requirement the permissive default, and so what
    makes the upgrade safe: whatever a schema 1 policy decided, the migrated
    policy still decides.
    """

    for seed in range(300):
        rng = random.Random(seed)
        overrides = _random_claim(rng)
        events = _random_events(rng)
        required = rng.sample(MODALITIES, rng.randint(1, len(MODALITIES)))

        permissive = evaluate(Policy.from_dict(_current(**overrides)), events, AS_OF).to_dict()[
            "decisions"
        ][0]
        demanding = evaluate(
            Policy.from_dict(_current(**overrides, required_modalities=required)),
            events,
            AS_OF,
        ).to_dict()["decisions"][0]

        for signal in ("support", "contradict"):
            if demanding[signal]["gate_passed"]:
                assert permissive[signal]["gate_passed"], (seed, signal, required)
        assert demanding[signal]["score"] == permissive[signal]["score"]


# --------------------------------------------------------------------------
# The command line.
# --------------------------------------------------------------------------


def test_cli_writes_an_upgraded_policy_and_its_report(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "policy.json"
    source.write_text(canonical_json(policy_dict()), encoding="utf-8")
    output = tmp_path / "policy-v2.json"
    report = tmp_path / "report.json"

    assert (
        run(["migrate-policy", str(source), "--output", str(output), "--report", str(report)]) == 0
    )

    upgraded = load_json(output)
    assert upgraded["schema_version"] == CURRENT_POLICY_SCHEMA_VERSION
    assert upgraded["claims"]["incident"]["required_modalities"] == []
    assert load_json(report)["notes"][0]["path"].endswith("required_modalities")
    assert capsys.readouterr().out == ""


def test_cli_writes_the_upgraded_policy_to_stdout(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    source = tmp_path / "policy.json"
    source.write_text(canonical_json(policy_dict()), encoding="utf-8")

    assert run(["migrate-policy", str(source)]) == 0
    written = json.loads(capsys.readouterr().out)
    assert written["schema_version"] == CURRENT_POLICY_SCHEMA_VERSION


def test_cli_emits_only_documents_that_load_again(tmp_path: Path) -> None:
    source = tmp_path / "policy.json"
    source.write_text(canonical_json(policy_dict()), encoding="utf-8")
    output = tmp_path / "policy-v2.json"

    run(["migrate-policy", str(source), "--output", str(output)])
    reloaded = Policy.from_dict(load_json(output))
    assert reloaded.source_schema_version == CURRENT_POLICY_SCHEMA_VERSION


def test_cli_reports_an_unmigratable_policy(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "policy.json"
    source.write_text(canonical_json(_at(CURRENT_POLICY_SCHEMA_VERSION + 1)), encoding="utf-8")

    assert run(["migrate-policy", str(source)]) == 2
    assert "newer than this build understands" in capsys.readouterr().err
