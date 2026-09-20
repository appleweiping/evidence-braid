"""Portable supported-case verification across the existing closed archive."""

from __future__ import annotations

import hashlib
import os
import stat
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

import evidence_braid.artifacts as artifacts
from evidence_braid import (
    ActorKind,
    ArtifactReference,
    AuthorityPolicy,
    AuthorityRole,
    CaseActor,
    CaseActorKind,
    CaseAuthority,
    CaseGrant,
    CaseJournal,
    CasePlan,
    CaseRole,
    EvidenceEvent,
    ObservationAdapter,
    ObservationRegistry,
    ObservationUnavailable,
    ScopeGrant,
    WorkflowAction,
    WorkflowActor,
    WorkflowTransition,
    build_artifact_bundle,
    build_ledger,
    build_workflow,
    create_case_store,
    verify_artifact_bundle,
    verify_supported_case_bundle,
)
from evidence_braid.errors import InputFormatError, ValidationError
from evidence_braid.examples import portable_case_bundle

ASSERTION = b"The cache is stale."
INPUT = b'{"incident":"cache","revision":"B"}'
EXPECTED = b"revision-B"


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def scenario(
    root: Path,
    *,
    output: bytes | None = EXPECTED,
    workflow_id: str = "workflow-1",
    omit_binding: str | None = None,
    journal_media_type: str = "application/vnd.evidence-braid.case-journal+json",
    revoke: bool = False,
    published_output: bytes | None = None,
    published_journal: bytes | None = None,
    published_assertion: bytes | None = None,
    published_input: bytes | None = None,
    assertion_bytes: bytes = ASSERTION,
    input_bytes: bytes = INPUT,
    expected_text: str = "revision-B",
    omit_output_binding: bool = False,
) -> SimpleNamespace:
    case_authority = CaseAuthority(
        "case-policy",
        (
            CaseActor("model", CaseActorKind.MODEL, (CaseGrant("site/a", CaseRole.PROPOSE),)),
            CaseActor("observer", CaseActorKind.TOOL, (CaseGrant("site/a", CaseRole.OBSERVE),)),
            CaseActor("evaluator", CaseActorKind.TOOL, (CaseGrant("site/a", CaseRole.EVALUATE),)),
        ),
    )
    plan = CasePlan(
        "case-1",
        "workflow-1",
        "claim-1",
        "site/a",
        "model",
        "assertion-1",
        sha(assertion_bytes),
        "The cache is stale.",
        "A bypass should return the current revision.",
        expected_text,
        "input-1",
        sha(input_bytes),
        sha(expected_text.encode()),
        "cache-bypass",
        "fixture-cache",
        "1",
        "sha256-equality-v1",
        case_authority.digest,
    )
    planned = CaseJournal.empty(case_authority).append((plan,), authority=case_authority)
    database = root / "case.db"
    store = create_case_store(
        database,
        planned,
        authority=case_authority,
        expected_plan_head=planned.head_digest,
        assertion_bytes=assertion_bytes,
        input_bytes=input_bytes,
    )

    def observe(_: bytes) -> bytes:
        if output is None:
            raise ObservationUnavailable
        return output

    registry = ObservationRegistry(
        (ObservationAdapter("cache-bypass", "fixture-cache", "1", "observer", observe),)
    )
    finished = store.execute_observation(
        registry,
        request_id="run-1",
        finish_id="finish-1",
        expected=store.snapshot().checkpoint,
    )
    checked = store.append_checked_verdict(
        operation_id="verdict-1",
        evaluator_id="evaluator",
        expected=finished.result.checkpoint,
    )
    snapshot = checked.result
    journal_id = "journal-1"
    contents = {
        journal_id: snapshot.journal.to_bytes() if published_journal is None else published_journal,
        plan.assertion_artifact_id: (
            snapshot.assertion_bytes if published_assertion is None else published_assertion
        ),
        plan.input_artifact_id: snapshot.input_bytes
        if published_input is None
        else published_input,
    }
    output_artifact_id = None
    if snapshot.observed_bytes is not None:
        observation = snapshot.journal.receipts[1].record
        assert observation.artifact_id is not None
        output_artifact_id = observation.artifact_id
        contents[observation.artifact_id] = (
            snapshot.observed_bytes if published_output is None else published_output
        )
    workflow_authority = AuthorityPolicy(
        "workflow-policy",
        (
            WorkflowActor("author", ActorKind.HUMAN, (ScopeGrant("site/a", AuthorityRole.AUTHOR),)),
            WorkflowActor(
                "reviewer", ActorKind.HUMAN, (ScopeGrant("site/a", AuthorityRole.REVIEWER),)
            ),
            WorkflowActor(
                "revoker", ActorKind.HUMAN, (ScopeGrant("site/a", AuthorityRole.REVOKER),)
            ),
        ),
    )
    event = EvidenceEvent.from_dict(
        {
            "event_id": "event-1",
            "claim": "claim-1",
            "modality": "sensor",
            "source": "bench",
            "signal": "support",
            "confidence": 0.8,
            "observed_at": "2026-09-07T12:00:00Z",
            "ingested_at": "2026-09-07T12:00:01Z",
            "attributes": {"workflow_scope": "site/a"},
        }
    )
    evidence = build_ledger([event])
    references = tuple(
        ArtifactReference(
            identifier,
            "site/a",
            "claim-1",
            sha(raw),
            len(raw),
            journal_media_type if identifier == journal_id else "application/octet-stream",
        )
        for identifier, raw in contents.items()
    )
    transitions = [
        WorkflowTransition(
            "create",
            WorkflowAction.CREATE,
            "author",
            "site/a",
            "claim-1",
            0,
            statement="The bypass result supports this claim.",
        ),
        WorkflowTransition(
            "evidence",
            WorkflowAction.BIND_EVIDENCE,
            "author",
            "site/a",
            "claim-1",
            1,
            reference_id="event-1",
            reference_digest=evidence.entries[0].digest,
        ),
    ]
    for reference in references:
        if reference.artifact_id == omit_binding or (
            omit_output_binding and reference.artifact_id == output_artifact_id
        ):
            continue
        transitions.append(
            WorkflowTransition(
                f"bind-{reference.artifact_id}",
                WorkflowAction.BIND_ARTIFACT,
                "author",
                "site/a",
                "claim-1",
                len(transitions),
                reference_id=reference.artifact_id,
                reference_digest=reference.sha256,
            )
        )
    transitions.append(
        WorkflowTransition(
            "submit", WorkflowAction.SUBMIT, "author", "site/a", "claim-1", len(transitions)
        )
    )
    transitions.append(
        WorkflowTransition(
            "approve", WorkflowAction.APPROVE, "reviewer", "site/a", "claim-1", len(transitions)
        )
    )
    if revoke:
        transitions.append(
            WorkflowTransition(
                "revoke",
                WorkflowAction.REVOKE,
                "revoker",
                "site/a",
                "claim-1",
                len(transitions),
                reason="Withdrawn after review.",
            )
        )
    workflow = build_workflow(
        workflow_id,
        authority=workflow_authority,
        evidence=evidence,
        artifacts=references,
        transitions=transitions,
    )
    sources = {}
    for identifier, raw in contents.items():
        source = root / f"source-{identifier}.bin"
        source.write_bytes(raw)
        sources[identifier] = source
    archive = root / "closed.zip"
    built = build_artifact_bundle(archive, workflow, sources, authority=workflow_authority)
    return SimpleNamespace(
        archive=archive,
        database=database,
        sources=sources,
        workflow=workflow,
        case_authority=case_authority,
        workflow_authority=workflow_authority,
        journal=snapshot.journal,
        journal_id=journal_id,
        built=built,
        checkpoint=snapshot.checkpoint,
        contents=contents,
    )


def verify(case: SimpleNamespace, **changes: object):
    arguments = {
        "workflow_authority": case.workflow_authority,
        "case_authority": case.case_authority,
        "case_journal_artifact_id": case.journal_id,
        "expected_workflow_head": case.workflow.head_digest,
        "expected_evidence_head": case.workflow.evidence.head_digest,
        "expected_case_head": case.journal.head_digest,
        "expected_bundle_digest": case.built.bundle_digest,
    }
    arguments.update(changes)
    return verify_supported_case_bundle(case.archive, **arguments)


def test_portable_supported_case_verifier_is_public() -> None:
    assert callable(verify_supported_case_bundle)


def test_packaged_offline_example(capsys: pytest.CaptureFixture[str]) -> None:
    portable_case_bundle.main()
    values = dict(line.split("=", 1) for line in capsys.readouterr().out.splitlines())
    assert set(values) == {"case", "workflow", "bundle", "outcome"}
    assert values["outcome"] == "supported"
    for key in ("case", "workflow", "bundle"):
        assert len(values[key]) == 64
        assert all(character in "0123456789abcdef" for character in values[key])


def test_verified_case_survives_move_and_loss_of_db_and_sources(tmp_path: Path) -> None:
    case = scenario(tmp_path)
    moved = tmp_path / "moved.zip"
    os.replace(case.archive, moved)
    case.archive = moved
    case.database.unlink()
    for source in case.sources.values():
        source.unlink()
    checked = verify(case)
    assert checked.case_state.outcome.value == "supported"
    assert checked.case_id == "case-1" and checked.claim_id == "claim-1"
    assert checked.journal.head_digest == case.journal.head_digest
    assert set(checked.artifact_ids) == set(case.contents)
    assert checked.archive.bundle_digest == case.built.bundle_digest
    assert sha(EXPECTED) == case.journal.receipts[1].record.observed_sha256


@pytest.mark.parametrize("output", [b"revision-C", None])
def test_approved_workflow_does_not_turn_bad_or_missing_observation_into_support(
    tmp_path: Path, output: bytes | None
) -> None:
    case = scenario(tmp_path, output=output)
    with pytest.raises(ValidationError):
        verify(case)


@pytest.mark.parametrize(
    ("change", "value"),
    [
        ("expected_case_head", "0" * 64),
        ("expected_workflow_head", "0" * 64),
        ("expected_evidence_head", "0" * 64),
        ("expected_bundle_digest", "0" * 64),
        ("case_journal_artifact_id", "missing"),
    ],
)
def test_independent_anchors_and_selected_journal_are_required(
    tmp_path: Path, change: str, value: str
) -> None:
    case = scenario(tmp_path)
    with pytest.raises(ValidationError):
        verify(case, **{change: value})


@pytest.mark.parametrize("omit_binding", ["journal-1", "assertion-1", "input-1"])
def test_all_case_objects_must_be_bound_to_approved_claim(
    tmp_path: Path, omit_binding: str
) -> None:
    case = scenario(tmp_path, omit_binding=omit_binding)
    with pytest.raises(ValidationError, match="not all bound"):
        verify(case)


def test_wrong_workflow_id_or_revocation_or_journal_media_type_fails(tmp_path: Path) -> None:
    for label, options in (
        ("wrong-workflow", {"workflow_id": "different-workflow"}),
        ("revoked", {"revoke": True}),
        ("media", {"journal_media_type": "application/octet-stream"}),
    ):
        target = tmp_path / label
        target.mkdir()
        case = scenario(target, **options)
        with pytest.raises(ValidationError):
            verify(case)


def test_coherent_archive_cannot_substitute_measured_output(tmp_path: Path) -> None:
    case = scenario(tmp_path, published_output=b"revision-C")
    assert case.built.workflow.head_digest == case.workflow.head_digest
    with pytest.raises(ValidationError, match="output bytes"):
        verify(case)


def test_output_reference_must_be_bound_to_the_approved_claim(tmp_path: Path) -> None:
    case = scenario(tmp_path, omit_output_binding=True)
    with pytest.raises(ValidationError, match="not all bound"):
        verify(case)


def test_exact_case_byte_ceilings_and_duplicate_content_ids(tmp_path: Path) -> None:
    maximum = tmp_path / "maximum"
    maximum.mkdir()
    case = scenario(
        maximum,
        assertion_bytes=b"a" * (64 * 1024),
        input_bytes=b"i" * (256 * 1024),
        expected_text="x" * 4096,
        output=b"x" * 4096,
    )
    assert verify(case).case_state.outcome.value == "supported"
    assert 64 * 1024 + 256 * 1024 + 4096 < 512 * 1024

    duplicate = tmp_path / "duplicate"
    duplicate.mkdir()
    same = scenario(
        duplicate,
        assertion_bytes=b"same",
        input_bytes=b"same",
        expected_text="same",
        output=b"same",
    )
    assert same.built.object_count == 2
    assert len(verify(same).artifact_ids) == 4


@pytest.mark.parametrize(
    ("overrides", "expected_error"),
    [
        ({"published_assertion": b"a" * (64 * 1024 + 1)}, "oversized"),
        ({"published_input": b"i" * (256 * 1024 + 1)}, "oversized"),
        ({"published_output": b"x" * 4097}, "oversized"),
    ],
)
def test_case_reference_byte_ceiling_plus_one_rejected(
    tmp_path: Path, overrides: dict[str, bytes], expected_error: str
) -> None:
    case = scenario(tmp_path, **overrides)
    with pytest.raises(ValidationError, match=expected_error):
        verify(case)


def test_malformed_utf8_output_fails_even_in_coherent_zip(tmp_path: Path) -> None:
    case = scenario(tmp_path, published_output=b"\xff")
    with pytest.raises(ValidationError, match="UTF-8"):
        verify(case)


def test_case_capture_reuses_one_source_handle_and_general_verifier_still_works(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = scenario(tmp_path)
    original_open = artifacts._open_regular
    calls = 0

    def opened(path: Path):
        nonlocal calls
        calls += 1
        if calls > 1:
            raise AssertionError("case capture reopened the archive path")
        return original_open(path)

    monkeypatch.setattr(artifacts, "_open_regular", opened)
    assert verify(case).case_state.outcome.value == "supported"
    assert calls == 1
    monkeypatch.setattr(artifacts, "_open_regular", original_open)
    general = verify_artifact_bundle(
        case.archive,
        authority=case.workflow_authority,
        expected_head=case.workflow.head_digest,
        expected_evidence_head=case.workflow.evidence.head_digest,
        expected_bundle_digest=case.built.bundle_digest,
    )
    assert general.bundle_digest == case.built.bundle_digest


def test_path_replacement_fingerprint_is_rejected_after_same_handle_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = scenario(tmp_path)
    original = artifacts._fingerprint
    calls = 0

    def replaced_path(info: os.stat_result) -> tuple[int, int, int, int]:
        nonlocal calls
        calls += 1
        result = original(info)
        if calls == 3:  # final path stat, after both opened-handle fingerprints
            return (result[0] ^ 1, *result[1:])
        return result

    monkeypatch.setattr(artifacts, "_fingerprint", replaced_path)
    with pytest.raises(InputFormatError, match="changed during verification"):
        verify(case)
    assert calls == 3


def test_oversized_journal_reference_fails_before_case_parse(tmp_path: Path) -> None:
    case = scenario(tmp_path, published_journal=b"x" * (2 * 1024 * 1024 + 1))
    with pytest.raises(ValidationError, match="oversized"):
        verify(case)


def test_independently_supplied_policies_are_required(tmp_path: Path) -> None:
    case = scenario(tmp_path)
    wrong_case = CaseAuthority("other", case.case_authority.actors)
    wrong_workflow = AuthorityPolicy("other", case.workflow_authority.actors)
    with pytest.raises(ValidationError):
        verify(case, case_authority=wrong_case)
    with pytest.raises(ValidationError):
        verify(case, workflow_authority=wrong_workflow)
    with pytest.raises(ValidationError, match="independently supplied"):
        verify(case, case_authority={})


@pytest.mark.parametrize(
    "overrides",
    [{"published_assertion": b"forged-assertion"}, {"published_input": b"forged-input"}],
)
def test_coherent_zip_with_changed_case_input_bytes_is_rejected(
    tmp_path: Path, overrides: dict[str, bytes]
) -> None:
    case = scenario(tmp_path, **overrides)
    with pytest.raises(ValidationError, match="case input bytes"):
        verify(case)


def test_private_archive_capture_requires_both_case_anchors(tmp_path: Path) -> None:
    case = scenario(tmp_path)
    with pytest.raises(ValidationError, match="anchors are required"):
        artifacts._verify_artifact_bundle_internal(
            case.archive,
            authority=case.workflow_authority,
            expected_head=case.workflow.head_digest,
            expected_evidence_head=case.workflow.evidence.head_digest,
            case_journal_artifact_id=case.journal_id,
            case_authority=None,
            expected_case_head=case.journal.head_digest,
        )


def test_crc_consistent_repacked_journal_with_wrong_digest_is_rejected(tmp_path: Path) -> None:
    case = scenario(tmp_path)
    journal_name = "objects/" + sha(case.contents[case.journal_id])
    with zipfile.ZipFile(case.archive) as archive:
        parts = [(info.filename, archive.read(info)) for info in archive.infolist()]
    with zipfile.ZipFile(case.archive, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, payload in parts:
            if name == journal_name:
                payload = b"x" + payload[1:]
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o600) << 16
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, payload)
    with pytest.raises(ValidationError, match="journal artifact bytes differ"):
        verify(case)


def test_archive_builder_os_error_is_explicit_and_does_not_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = scenario(tmp_path)
    target = tmp_path / "failed-copy.zip"

    def fail_copy(*_args: object, **_kwargs: object) -> None:
        raise OSError("injected source read failure")

    monkeypatch.setattr(artifacts, "_copy_source", fail_copy)
    with pytest.raises(InputFormatError, match="cannot publish output"):
        build_artifact_bundle(
            target, case.workflow, case.sources, authority=case.workflow_authority
        )
    assert not target.exists()


@pytest.mark.parametrize("role", ["journal", "assertion", "input", "output"])
def test_archive_object_mutation_never_returns_supported(tmp_path: Path, role: str) -> None:
    case = scenario(tmp_path)
    plan = case.journal.receipts[0].record
    observation = case.journal.receipts[1].record
    identifier = {
        "journal": case.journal_id,
        "assertion": plan.assertion_artifact_id,
        "input": plan.input_artifact_id,
        "output": observation.artifact_id,
    }[role]
    expected = case.contents[identifier]
    member_name = "objects/" + sha(expected)
    with zipfile.ZipFile(case.archive) as archive:
        info = archive.getinfo(member_name)
        assert info.compress_type == zipfile.ZIP_STORED and not info.extra
        offset = info.header_offset + 30 + len(member_name)
    raw = bytearray(case.archive.read_bytes())
    assert raw[offset : offset + len(expected)] == expected
    raw[offset] ^= 1
    case.archive.write_bytes(raw)
    with pytest.raises((ValidationError, InputFormatError)):
        verify(case)
