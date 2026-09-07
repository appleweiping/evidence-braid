from __future__ import annotations

import hashlib
import io
import json
import os
import runpy
import stat
import struct
import subprocess
import sys
import zipfile
from contextlib import contextmanager
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import evidence_braid.artifacts as artifacts
from evidence_braid import (
    ActorKind,
    ArtifactBundleLimits,
    ArtifactReference,
    AuthorityPolicy,
    AuthorityRole,
    EvidenceEvent,
    ScopeGrant,
    WorkflowAction,
    WorkflowActor,
    WorkflowTransition,
    build_artifact_bundle,
    build_ledger,
    build_workflow,
    verify_artifact_bundle,
)
from evidence_braid.cli import run
from evidence_braid.errors import InputFormatError, ValidationError
from evidence_braid.io import canonical_json
from evidence_braid.workflow import write_workflow_bundle


@pytest.fixture
def scenario(tmp_path):
    policy = AuthorityPolicy(
        "lab-policy",
        (
            WorkflowActor("author", ActorKind.HUMAN, (ScopeGrant("lab", AuthorityRole.AUTHOR),)),
            WorkflowActor(
                "reviewer", ActorKind.HUMAN, (ScopeGrant("lab", AuthorityRole.REVIEWER),)
            ),
        ),
    )
    event = EvidenceEvent.from_dict(
        {
            "event_id": "observation",
            "claim": "stable",
            "modality": "sensor",
            "source": "bench",
            "signal": "support",
            "confidence": 0.8,
            "observed_at": "2026-09-07T12:00:00Z",
            "ingested_at": "2026-09-07T12:00:01Z",
            "attributes": {"workflow_scope": "lab"},
        }
    )
    evidence = build_ledger([event])
    content = b"\x00\xff\nMeasured within the declared test scope.\n"
    references = tuple(
        ArtifactReference(
            name,
            "lab",
            "stable",
            hashlib.sha256(content).hexdigest(),
            len(content),
            "application/octet-stream",
        )
        for name in ("agent/result", "artifact/../../private")
    )
    transitions = (
        WorkflowTransition(
            "create",
            WorkflowAction.CREATE,
            "author",
            "lab",
            "stable",
            0,
            statement="Stable within the declared experiment.",
        ),
        WorkflowTransition(
            "evidence",
            WorkflowAction.BIND_EVIDENCE,
            "author",
            "lab",
            "stable",
            1,
            reference_id="observation",
            reference_digest=evidence.entries[0].digest,
        ),
        WorkflowTransition(
            "artifact",
            WorkflowAction.BIND_ARTIFACT,
            "author",
            "lab",
            "stable",
            2,
            reference_id=references[0].artifact_id,
            reference_digest=references[0].sha256,
        ),
        WorkflowTransition("submit", WorkflowAction.SUBMIT, "author", "lab", "stable", 3),
        WorkflowTransition("approve", WorkflowAction.APPROVE, "reviewer", "lab", "stable", 4),
    )
    workflow = build_workflow(
        "measurement-review",
        authority=policy,
        evidence=evidence,
        artifacts=references,
        transitions=transitions,
    )
    sources = {}
    for index, reference in enumerate(references):
        path = tmp_path / f"private-source-{index}.bin"
        path.write_bytes(content)
        sources[reference.artifact_id] = path
    return SimpleNamespace(
        root=tmp_path,
        policy=policy,
        workflow=workflow,
        sources=sources,
        content=content,
        path=tmp_path / "closed.zip",
    )


def build(case, **kwargs):
    return build_artifact_bundle(
        case.path, case.workflow, case.sources, authority=case.policy, **kwargs
    )


def verify(case, **kwargs):
    anchors = {
        "authority": case.policy,
        "expected_head": case.workflow.head_digest,
        "expected_evidence_head": case.workflow.evidence.head_digest,
    }
    return verify_artifact_bundle(case.path, **(anchors | kwargs))


def read_parts(path):
    with zipfile.ZipFile(path) as archive:
        return [(info.filename, archive.read(info)) for info in archive.infolist()]


def write_parts(path, parts, *, compress=zipfile.ZIP_STORED, mode=stat.S_IFREG | 0o600, extra=b""):
    # Independent profile writer, not the implementation's ZIP/manifest helper.
    with zipfile.ZipFile(path, "w", compression=compress) as archive:
        for name, raw in parts:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = mode << 16
            info.compress_type = compress
            info.extra = extra
            archive.writestr(info, raw)


def test_real_closed_bundle_deduplicates_bytes_without_using_ids_as_paths(scenario):
    result = build(scenario)
    assert result.state.claims["stable"].status.value == "approved"
    assert result.object_count == 1 and result.object_bytes == len(scenario.content)
    assert len(result.workflow.artifacts) == 2
    digest = hashlib.sha256(scenario.content).hexdigest()
    parts = read_parts(scenario.path)
    assert [name for name, _ in parts] == [
        "manifest.json",
        "workflow.json",
        "state.json",
        "objects/" + digest,
    ]
    assert parts[-1][1] == scenario.content
    document = json.loads(parts[0][1])
    assert document["artifacts"][0]["object_path"] == "objects/" + digest
    assert b"private-source" not in parts[0][1] and b"private-source" not in parts[1][1]
    assert verify(scenario, expected_bundle_digest=result.bundle_digest) == result
    with pytest.raises(FrozenInstanceError):
        result.object_count = 4
    reported = result.to_dict()
    reported["state"]["claims"]["stable"]["status"] = "draft"
    assert result.state.claims["stable"].status.value == "approved"


def test_reproducible_archive_bytes_and_new_process_relocation_without_sources(scenario):
    result = build(scenario)
    twin = scenario.root / "twin.zip"
    build_artifact_bundle(twin, scenario.workflow, scenario.sources, authority=scenario.policy)
    assert twin.read_bytes() == scenario.path.read_bytes()
    moved = scenario.root / "moved.zip"
    scenario.path.rename(moved)
    for source in scenario.sources.values():
        source.unlink()
    policy = scenario.root / "external-policy.json"
    policy.write_text(canonical_json(scenario.policy.to_dict()), encoding="utf-8")
    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "evidence_braid",
            "artifact-bundle",
            "verify",
            str(policy),
            str(moved),
            "--expected-head",
            result.workflow.head_digest,
            "--expected-evidence-head",
            result.workflow.evidence.head_digest,
            "--expected-bundle-digest",
            result.bundle_digest,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert process.returncode == 0, process.stderr
    assert json.loads(process.stdout)["state"]["claims"]["stable"]["status"] == "approved"


@pytest.mark.parametrize(
    "argument", ["expected_head", "expected_evidence_head", "expected_bundle_digest"]
)
def test_external_anchors_cannot_be_replaced_by_self_consistent_bundle_values(scenario, argument):
    build(scenario)
    with pytest.raises(ValidationError):
        verify(scenario, **{argument: "0" * 64})


def test_external_authority_is_required_not_an_embedded_policy(scenario):
    build(scenario)
    with pytest.raises(ValidationError, match="authority"):
        verify(scenario, authority=replace(scenario.policy, policy_id="foreign-policy"))


def test_empty_artifact_workflow_is_closed_without_fabricating_objects(scenario):
    workflow = build_workflow("empty", authority=scenario.policy, evidence=build_ledger([]))
    result = build_artifact_bundle(scenario.path, workflow, {}, authority=scenario.policy)
    assert result.object_count == result.object_bytes == 0
    assert [name for name, _ in read_parts(scenario.path)] == [
        "manifest.json",
        "workflow.json",
        "state.json",
    ]


@pytest.mark.parametrize("fault", ["missing", "extra", "not-mapping", "bad-path"])
def test_exact_source_mapping_is_required_before_staging(scenario, fault):
    sources = dict(scenario.sources)
    if fault == "missing":
        sources.pop(next(iter(sources)))
    elif fault == "extra":
        sources["extra"] = scenario.root
    elif fault == "bad-path":
        sources[next(iter(sources))] = b"not-a-path"
    else:
        sources = []
    with pytest.raises(ValidationError, match="sources"):
        build_artifact_bundle(scenario.path, scenario.workflow, sources, authority=scenario.policy)
    assert not scenario.path.exists() and not list(scenario.root.glob(".evidence-*.tmp"))


@pytest.mark.parametrize("fault", ["length", "digest", "missing", "directory", "duplicate-source"])
def test_bad_source_never_publishes_even_when_content_is_deduplicated(scenario, fault):
    source = list(scenario.sources.values())[1 if fault == "duplicate-source" else 0]
    if fault in ("digest", "duplicate-source"):
        source.write_bytes(b"x" * len(scenario.content))
    elif fault == "length":
        source.write_bytes(b"short")
    elif fault == "missing":
        source.unlink()
    else:
        source.unlink()
        source.mkdir()
    with pytest.raises((InputFormatError, ValidationError)):
        build(scenario)
    assert not scenario.path.exists() and not list(scenario.root.glob(".evidence-*.tmp"))


def test_digest_size_conflict_is_rejected_before_materializing_sources(scenario):
    bad = replace(scenario.workflow.artifacts[1], size_bytes=len(scenario.content) + 1)
    workflow = build_workflow(
        "conflict",
        authority=scenario.policy,
        evidence=build_ledger([]),
        artifacts=(scenario.workflow.artifacts[0], bad),
    )
    with pytest.raises(ValidationError, match="conflicting"):
        build_artifact_bundle(scenario.path, workflow, scenario.sources, authority=scenario.policy)


def test_no_replace_and_independent_prepublication_verification(scenario, monkeypatch):
    scenario.path.write_bytes(b"prior-destination")
    with pytest.raises(InputFormatError):
        build(scenario)
    assert scenario.path.read_bytes() == b"prior-destination"
    scenario.path.unlink()

    def reject(*args, **kwargs):
        raise ValidationError("independent verifier rejected staged archive")

    monkeypatch.setattr(artifacts, "verify_artifact_bundle", reject)
    with pytest.raises(ValidationError, match="independent"):
        build(scenario)
    assert not scenario.path.exists() and not list(scenario.root.glob(".evidence-*.tmp"))


@pytest.mark.parametrize("mode", [stat.S_IFLNK | 0o600, stat.S_IFDIR | 0o600, stat.S_IFIFO | 0o600])
def test_special_member_modes_are_rejected_without_extraction(scenario, mode):
    build(scenario)
    write_parts(scenario.path, read_parts(scenario.path), mode=mode)
    with pytest.raises(InputFormatError, match="ZIP32 entry"):
        verify(scenario)


@pytest.mark.parametrize(
    "name", ["../escape", "C:/escape", "/absolute", "objects/" + "A" * 64, "unexpected", "é"]
)
def test_unsafe_unknown_or_noncanonical_names_are_rejected(scenario, name):
    build(scenario)
    parts = read_parts(scenario.path)
    parts[-1] = name, parts[-1][1]
    write_parts(scenario.path, parts)
    with pytest.raises(InputFormatError):
        verify(scenario)


@pytest.mark.parametrize(
    "fault", ["compressed", "extra", "duplicate", "reordered", "trailing", "preamble"]
)
def test_noncanonical_zip_features_fail_closed(scenario, fault):
    build(scenario)
    parts = read_parts(scenario.path)
    if fault == "compressed":
        write_parts(scenario.path, parts, compress=zipfile.ZIP_DEFLATED)
    elif fault == "extra":
        write_parts(scenario.path, parts, extra=b"\x01\x00\x00\x00")
    elif fault == "duplicate":
        with pytest.warns(UserWarning, match="Duplicate"):
            write_parts(scenario.path, [*parts, parts[-1]])
    elif fault == "reordered":
        write_parts(scenario.path, [parts[1], parts[0], *parts[2:]])
    elif fault == "trailing":
        scenario.path.write_bytes(scenario.path.read_bytes() + b"extra")
    else:
        scenario.path.write_bytes(b"preamble" + scenario.path.read_bytes())
    with pytest.raises(InputFormatError):
        verify(scenario)


@pytest.mark.parametrize(
    "target", ["object", "state", "workflow", "manifest", "omitted", "extra-object"]
)
def test_self_consistent_zip_crc_does_not_override_semantic_commitments(scenario, target):
    build(scenario)
    parts = read_parts(scenario.path)
    if target == "object":
        parts[-1] = parts[-1][0], b"x" * len(parts[-1][1])
    elif target == "state":
        state = json.loads(parts[2][1])
        state["claims"]["stable"]["status"] = "draft"
        parts[2] = "state.json", canonical_json(state, pretty=False).encode()
    elif target == "workflow":
        document = json.loads(parts[1][1])
        document["records"][-1]["transition"]["actor_id"] = "author"
        parts[1] = "workflow.json", canonical_json(document, pretty=False).encode()
    elif target == "manifest":
        document = json.loads(parts[0][1])
        document["artifacts"][0]["media_type"] = "text/plain"
        parts[0] = "manifest.json", canonical_json(document, pretty=False).encode()
    elif target == "omitted":
        parts.pop()
    else:
        objects = sorted([parts[-1], ("objects/" + "0" * 64, b"uncommitted")])
        parts = [*parts[:3], *objects]
    write_parts(scenario.path, parts)
    with pytest.raises(ValidationError):
        verify(scenario)


@pytest.mark.parametrize(
    "raw", [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}', b"\xff", b"{", b"{}\n"]
)
def test_strict_canonical_metadata_parsing(scenario, raw):
    build(scenario)
    parts = read_parts(scenario.path)
    parts[0] = "manifest.json", raw
    write_parts(scenario.path, parts)
    with pytest.raises(InputFormatError):
        verify(scenario)


@pytest.mark.parametrize("field", list(ArtifactBundleLimits.__dataclass_fields__))
def test_every_configured_limit_is_strict_and_enforced_before_acceptance(scenario, field):
    with pytest.raises(ValidationError):
        ArtifactBundleLimits(**{field: True})
    with pytest.raises(ValidationError):
        ArtifactBundleLimits(**{field: getattr(ArtifactBundleLimits(), field) + 1})
    build(scenario)
    limits = replace(ArtifactBundleLimits(), **{field: 1})
    with pytest.raises((InputFormatError, ValidationError)):
        verify(scenario, limits=limits)
    with pytest.raises((InputFormatError, ValidationError)):
        build_artifact_bundle(
            scenario.root / "too-small.zip",
            scenario.workflow,
            scenario.sources,
            authority=scenario.policy,
            limits=limits,
        )
    assert not (scenario.root / "too-small.zip").exists()


def test_declared_directory_limits_rejected_before_zipfile_constructor(scenario, monkeypatch):
    build(scenario)
    raw = bytearray(scenario.path.read_bytes())
    struct.pack_into("<H", raw, len(raw) - 12, 65535)  # EOCD total entries
    scenario.path.write_bytes(raw)

    def forbidden(*args, **kwargs):
        raise AssertionError("ZipFile materialized before preflight accepted inventory")

    monkeypatch.setattr(artifacts.zipfile, "ZipFile", forbidden)
    with pytest.raises(InputFormatError, match="directory"):
        verify(scenario)


def test_cli_create_verify_and_duplicate_source_diagnostic(scenario, capsys):
    policy = scenario.root / "authority.json"
    policy.write_text(canonical_json(scenario.policy.to_dict()), encoding="utf-8")
    workflow = scenario.root / "workflow.json"
    write_workflow_bundle(workflow, scenario.workflow, authority=scenario.policy)
    common = [
        str(policy),
        str(scenario.path),
        "--expected-head",
        scenario.workflow.head_digest,
        "--expected-evidence-head",
        scenario.workflow.evidence.head_digest,
    ]
    sources = [
        item for key, value in scenario.sources.items() for item in ("--artifact", f"{key}={value}")
    ]
    assert run(["artifact-bundle", "create", *common, "--workflow", str(workflow), *sources]) == 0
    created = json.loads(capsys.readouterr().out)
    assert (
        run(
            [
                "artifact-bundle",
                "verify",
                *common,
                "--expected-bundle-digest",
                created["bundle_digest"],
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == created
    assert (
        run(["artifact-bundle", "create", *common, "--workflow", str(workflow), *sources, *sources])
        == 2
    )
    assert "unique" in capsys.readouterr().err


def test_offline_example_moves_archive_and_removes_original_attachment(capsys):
    runpy.run_path(
        str(Path(__file__).parents[1] / "examples" / "closed_artifacts.py"), run_name="__main__"
    )
    result = json.loads(capsys.readouterr().out)
    assert result["state"]["claims"]["stable"]["status"] == "approved"
    assert result["source_removed_before_verification"] is True
    assert result["actor_authentication_provided"] is False


def test_real_crc_failure_and_truncated_archive_are_rejected(scenario):
    build(scenario)
    raw = bytearray(scenario.path.read_bytes())
    index = raw.index(scenario.content)
    raw[index] ^= 1
    scenario.path.write_bytes(raw)
    with pytest.raises(InputFormatError, match="verify"):
        verify(scenario)
    scenario.path.write_bytes(b"tiny")
    with pytest.raises(InputFormatError, match="size"):
        verify(scenario)


@pytest.mark.parametrize(
    "target", ["local-crc", "local-name", "encrypted", "descriptor", "overlap", "timestamp"]
)
def test_local_central_binding_and_encryption_descriptor_flags(scenario, target):
    build(scenario)
    raw = bytearray(scenario.path.read_bytes())
    central = struct.unpack_from("<I", raw, len(raw) - 6)[0]
    if target == "local-crc":
        raw[14] ^= 1
    elif target == "local-name":
        raw[30] ^= 1
    elif target == "encrypted":
        struct.pack_into("<H", raw, central + 8, 1)
    elif target == "descriptor":
        struct.pack_into("<H", raw, central + 8, 8)
    elif target == "overlap":
        struct.pack_into("<I", raw, central + 42, 1)
    else:
        struct.pack_into("<H", raw, central + 12, 1)
    scenario.path.write_bytes(raw)
    with pytest.raises(InputFormatError):
        verify(scenario)


def test_truncated_central_record_never_reaches_zipfile(scenario, monkeypatch):
    raw = b"PK\x01\x02" + struct.pack("<4s4H2IH", b"PK\x05\x06", 0, 0, 3, 3, 4, 0, 0)
    scenario.path.write_bytes(raw)
    monkeypatch.setattr(
        artifacts.zipfile, "ZipFile", lambda *args, **kwargs: pytest.fail("unbounded parse")
    )
    with pytest.raises(InputFormatError, match="truncated"):
        verify(scenario)


def test_frozen_directory_view_does_not_trust_changed_eocd(scenario, monkeypatch):
    build(scenario)
    original = artifacts.zipfile.ZipFile

    def mutate_then_open(view, **kwargs):
        # Alter source EOCD after preflight, leaving the view's bounded snapshot intact.
        with scenario.path.open("r+b") as raw:
            raw.seek(-10, 2)
            raw.write(struct.pack("<I", 2**31))
        assert view.seek(-22, 2) >= 0
        end = view.read(22)
        assert struct.unpack_from("<I", end, 12)[0] < 256 * 1024
        return original(view, **kwargs)

    monkeypatch.setattr(artifacts.zipfile, "ZipFile", mutate_then_open)
    with pytest.raises(InputFormatError, match="changed"):
        verify(scenario)


def test_archive_view_seek_and_reads_are_bounded_to_file_and_frozen_footer():
    view = artifacts._ArchiveView(io.BytesIO(b"012345"), 4, b"ABCD")
    assert view.read(3) == b"012"
    assert view.seek(0, 1) == 3 and view.read(3) == b"3AB"
    assert view.seek(-2, 2) == 6 and view.read() == b"CD"
    assert view.tell() == 8 and view.read(99) == b""
    assert view.seek(20) == 20 and view.read() == b""
    with pytest.raises(OSError):
        view.seek(-1)
    with pytest.raises(OSError):
        view.seek(0, 7)


@pytest.mark.parametrize("mutation", ["grow", "shrink", "same-size"])
def test_streamed_source_copy_rejects_mutation_and_uses_chunk_bounds(
    scenario, monkeypatch, mutation
):
    original = artifacts._open_regular
    source_path = next(iter(scenario.sources.values()))
    observed_sizes = []

    class ChangingReader:
        def __init__(self, source):
            self.source = source
            self.changed = False

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.source.close()

        def close(self):
            self.source.close()

        def fileno(self):
            return self.source.fileno()

        def read(self, size):
            observed_sizes.append(size)
            raw = self.source.read(size)
            if not self.changed:
                self.changed = True
                if mutation == "grow":
                    with source_path.open("ab") as changed:
                        changed.write(b"extra")
                elif mutation == "shrink":
                    source_path.write_bytes(b"small")
                else:
                    source_path.write_bytes(b"x" * len(scenario.content))
                os.utime(source_path, ns=(0, 1))
            return raw

    monkeypatch.setattr(artifacts, "_CHUNK", 7)
    monkeypatch.setattr(
        artifacts,
        "_open_regular",
        lambda path: ChangingReader(original(path)) if path == source_path else original(path),
    )
    with pytest.raises((ValidationError, InputFormatError), match=r"changed|shorter|digest"):
        build(scenario)
    assert observed_sizes and max(observed_sizes) <= 7
    assert not scenario.path.exists() and not list(scenario.root.glob(".evidence-*.tmp"))


def test_missing_archive_and_symbolic_source_are_rejected(scenario, monkeypatch):
    with pytest.raises(InputFormatError):
        verify(scenario)
    original = artifacts.Path.is_symlink
    monkeypatch.setattr(
        artifacts.Path,
        "is_symlink",
        lambda path: path in scenario.sources.values() or original(path),
    )
    with pytest.raises(InputFormatError, match="symbolic"):
        build(scenario)


def test_public_limits_and_verification_summary_reject_mutable_invalid_fields(scenario):
    with pytest.raises(ValidationError, match="limits"):
        build(scenario, limits={})
    result = build(scenario)
    for fields in (
        {"workflow": {}},
        {"state": {}},
        {"object_count": True},
        {"object_count": 0},
        {"object_bytes": 0},
        {"archive_bytes": 0},
        {"bundle_digest": "bad"},
        {"bundle_digest": "0" * 64},
        {"state": replace(result.state, head_digest="0" * 64)},
        {"state": replace(result.state, workflow_id="foreign")},
    ):
        with pytest.raises(ValidationError):
            replace(result, **fields)


def test_builder_freezes_source_mapping_and_relative_path_binding_before_io(scenario, monkeypatch):
    monkeypatch.chdir(scenario.root)
    sources = {key: Path(value.name) for key, value in scenario.sources.items()}
    elsewhere = scenario.root / "elsewhere"
    elsewhere.mkdir()
    original = artifacts.staged_output

    @contextmanager
    def mutate_caller_state(*args, **kwargs):
        with original(*args, **kwargs) as staging:
            sources.clear()
            monkeypatch.chdir(elsewhere)
            yield staging

    monkeypatch.setattr(artifacts, "staged_output", mutate_caller_state)
    result = build_artifact_bundle(
        scenario.path, scenario.workflow, sources, authority=scenario.policy
    )
    assert result.object_bytes == len(scenario.content)
    assert read_parts(scenario.path)[-1][1] == scenario.content


@pytest.mark.parametrize(
    "primary", [ValidationError("original"), KeyboardInterrupt(), SystemExit(7)]
)
@pytest.mark.parametrize("resource", ["archive", "member"])
def test_primary_source_error_survives_ordinary_zip_close_failure(
    scenario, monkeypatch, primary, resource
):
    def fail_source(*args, **kwargs):
        raise primary

    monkeypatch.setattr(artifacts, "_copy_source", fail_source)
    if resource == "archive":
        original = artifacts.zipfile.ZipFile.close

        def close_then_fail(archive):
            was_open = archive.fp is not None
            original(archive)
            if was_open:
                raise OSError("secondary archive close error")

        monkeypatch.setattr(artifacts.zipfile.ZipFile, "close", close_then_fail)
    else:
        original_open = artifacts.zipfile.ZipFile.open

        class FailingMember:
            def __init__(self, member):
                self.member = member

            def write(self, raw):
                return self.member.write(raw)

            def close(self):
                self.member.close()
                raise OSError("secondary member close error")

        def opened(archive, *args, **kwargs):
            member = original_open(archive, *args, **kwargs)
            if kwargs.get("mode") == "w" and args[0].filename.startswith("objects/"):
                return FailingMember(member)
            return member

        monkeypatch.setattr(artifacts.zipfile.ZipFile, "open", opened)
    with pytest.raises(type(primary)) as error:
        build(scenario)
    assert error.value is primary
    assert "artifact archive resource cleanup also failed" in error.value.__notes__
    assert not scenario.path.exists() and not list(scenario.root.glob(".evidence-*.tmp"))


def test_genuine_close_interrupt_is_not_swallowed_by_primary_error():
    class InterruptedClose:
        def close(self):
            raise KeyboardInterrupt()

    with pytest.raises(KeyboardInterrupt), artifacts._closing(InterruptedClose()):
        raise ValidationError("primary validation failure")


def test_ordinary_close_failure_without_primary_surfaces_as_io_failure(scenario, monkeypatch):
    original = artifacts.zipfile.ZipFile.close

    def broken_close(archive):
        opened = archive.fp is not None
        original(archive)
        if opened:
            raise OSError("ordinary close failed")

    monkeypatch.setattr(artifacts.zipfile.ZipFile, "close", broken_close)
    with pytest.raises(InputFormatError):
        build(scenario)
    assert not scenario.path.exists()


@pytest.mark.parametrize("fault", ["non-ascii-name", "overlapping-data"])
def test_directory_preflight_rejects_invalid_raw_name_and_overlapping_size(scenario, fault):
    build(scenario)
    raw = bytearray(scenario.path.read_bytes())
    central = struct.unpack_from("<I", raw, len(raw) - 6)[0]
    if fault == "non-ascii-name":
        raw[central + 46] = 255
    else:
        struct.pack_into("<II", raw, central + 20, central + 1, central + 1)
    scenario.path.write_bytes(raw)
    with pytest.raises(InputFormatError, match=r"ASCII|overlap"):
        verify(scenario)


def test_object_size_must_match_reference_even_with_valid_zip_crc(scenario):
    build(scenario)
    parts = read_parts(scenario.path)
    parts[-1] = parts[-1][0], parts[-1][1] + b"x"
    write_parts(scenario.path, parts)
    with pytest.raises(ValidationError, match="object size"):
        verify(scenario)


def test_manifest_boolean_cannot_substitute_for_equal_zero_integer(scenario):
    source = scenario.root / "empty-object"
    source.write_bytes(b"")
    reference = ArtifactReference(
        "empty", "lab", "stable", hashlib.sha256(b"").hexdigest(), 0, "text/plain"
    )
    workflow = build_workflow(
        "empty-reference",
        authority=scenario.policy,
        evidence=build_ledger([]),
        artifacts=(reference,),
    )
    build_artifact_bundle(scenario.path, workflow, {"empty": source}, authority=scenario.policy)
    parts = read_parts(scenario.path)
    manifest = json.loads(parts[0][1])
    manifest["artifacts"][0]["size_bytes"] = False
    parts[0] = "manifest.json", canonical_json(manifest, pretty=False).encode()
    write_parts(scenario.path, parts)
    with pytest.raises(ValidationError, match="exact canonical"):
        verify_artifact_bundle(
            scenario.path,
            authority=scenario.policy,
            expected_head=workflow.head_digest,
            expected_evidence_head=workflow.evidence.head_digest,
        )


def test_unexpected_eof_from_source_read_prevents_publication(scenario, monkeypatch):
    original = artifacts._open_regular

    class EarlyEOF:
        def __init__(self, handle):
            self.handle = handle

        def fileno(self):
            return self.handle.fileno()

        def read(self, count):
            return b""

        def close(self):
            self.handle.close()

    monkeypatch.setattr(artifacts, "_open_regular", lambda path: EarlyEOF(original(path)))
    with pytest.raises(InputFormatError, match="shorter"):
        build(scenario)
    assert not scenario.path.exists()


def test_deduplication_does_not_hide_total_source_work(scenario):
    unique_limit = replace(ArtifactBundleLimits(), max_total_object_bytes=len(scenario.content))
    assert build(scenario, limits=unique_limit).object_bytes == len(scenario.content)
    work_limit = replace(unique_limit, max_total_source_bytes=len(scenario.content))
    with pytest.raises(ValidationError, match="source bytes"):
        verify(scenario, limits=work_limit)
    with pytest.raises(ValidationError, match="source bytes"):
        build_artifact_bundle(
            scenario.root / "too-much-source.zip",
            scenario.workflow,
            scenario.sources,
            authority=scenario.policy,
            limits=work_limit,
        )


def test_reader_binds_relative_archive_before_cwd_changes(scenario, monkeypatch):
    build(scenario)
    monkeypatch.chdir(scenario.root)
    elsewhere = scenario.root / "reader-cwd"
    elsewhere.mkdir()
    original = artifacts._preflight

    def change_cwd(*args):
        result = original(*args)
        monkeypatch.chdir(elsewhere)
        return result

    monkeypatch.setattr(artifacts, "_preflight", change_cwd)
    result = verify_artifact_bundle(
        scenario.path.name,
        authority=scenario.policy,
        expected_head=scenario.workflow.head_digest,
        expected_evidence_head=scenario.workflow.evidence.head_digest,
    )
    assert result.object_bytes == len(scenario.content)
