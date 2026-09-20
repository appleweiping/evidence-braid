"""Closed content-addressed artifact archives with anchored offline verification.

This is a deliberately restrictive ZIP32 profile, not a general ZIP reader.
Metadata is materialized under byte/count limits; object bytes are streamed.
No archive member is extracted, executed or interpreted as a filesystem path.
"""

from __future__ import annotations

import hashlib
import io
import os
import re
import stat
import struct
import zipfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any, BinaryIO, Protocol, TypeVar, cast

from ._atomic import staged_output
from .authority import ArtifactReference, AuthorityPolicy, _integer
from .epistemic_case import (
    CaseAuthority,
    CaseJournal,
    CaseObservation,
    CaseObservationStatus,
    CasePlan,
)
from .errors import InputFormatError, ValidationError
from .io import _loads, canonical_json
from .ledger import _hash
from .workflow import WorkflowBundle, WorkflowState, replay_workflow

_CHUNK = 1024 * 1024
_CENTRAL = struct.Struct("<4s6H3I5H2I")
_LOCAL = struct.Struct("<4s5H3I2H")
_END = struct.Struct("<4s4H2IH")
_NAMES = ("manifest.json", "workflow.json", "state.json")
_MODE = (stat.S_IFREG | 0o600) << 16


class _Closeable(Protocol):
    def close(self) -> None: ...


_ResourceT = TypeVar("_ResourceT", bound=_Closeable)


@contextmanager
def _closing(resource: _ResourceT) -> Iterator[_ResourceT]:
    """Preserve the active operation/interrupt if ordinary resource cleanup fails."""
    primary: BaseException | None = None
    try:
        yield resource
    except BaseException as exc:
        primary = exc
        raise
    finally:
        try:
            resource.close()
        except Exception:
            if primary is None:
                raise
            primary.add_note("artifact archive resource cleanup also failed")


@dataclass(frozen=True, slots=True)
class ArtifactBundleLimits:
    max_artifacts: int = 1024
    max_artifact_bytes: int = 64 * 1024 * 1024
    max_total_object_bytes: int = 512 * 1024 * 1024
    max_total_source_bytes: int = 512 * 1024 * 1024
    max_manifest_bytes: int = 4 * 1024 * 1024
    max_workflow_bytes: int = 64 * 1024 * 1024
    max_state_bytes: int = 64 * 1024 * 1024
    max_central_bytes: int = 256 * 1024
    max_archive_bytes: int = 1024 * 1024 * 1024

    def __post_init__(self) -> None:
        for name, ceiling in (
            ("max_artifacts", 1024),
            ("max_artifact_bytes", 64 * 1024 * 1024),
            ("max_total_object_bytes", 512 * 1024 * 1024),
            ("max_total_source_bytes", 512 * 1024 * 1024),
            ("max_manifest_bytes", 4 * 1024 * 1024),
            ("max_workflow_bytes", 64 * 1024 * 1024),
            ("max_state_bytes", 64 * 1024 * 1024),
            ("max_central_bytes", 256 * 1024),
            ("max_archive_bytes", 1024 * 1024 * 1024),
        ):
            _integer(getattr(self, name), name, ceiling, 1)

    def entry_limit(self, name: str) -> int:
        return {
            "manifest.json": self.max_manifest_bytes,
            "workflow.json": self.max_workflow_bytes,
            "state.json": self.max_state_bytes,
        }.get(name, self.max_artifact_bytes)


@dataclass(frozen=True, slots=True)
class VerifiedArtifactBundle:
    """Detached verified metadata, not a live archive handle or an authenticity proof."""

    bundle_digest: str
    workflow: WorkflowBundle
    state: WorkflowState
    object_count: int
    object_bytes: int
    archive_bytes: int

    def __post_init__(self) -> None:
        _hash(self.bundle_digest, "bundle_digest")
        if type(self.workflow) is not WorkflowBundle or type(self.state) is not WorkflowState:
            raise ValidationError("verified bundle requires immutable workflow and state")
        if (
            self.state.head_digest != self.workflow.head_digest
            or self.state.workflow_id != self.workflow.workflow_id
            or self.state.record_count != len(self.workflow.records)
        ):
            raise ValidationError("verified state and workflow bindings differ")
        _integer(self.object_count, "object_count", 1024)
        _integer(self.object_bytes, "object_bytes", 512 * 1024 * 1024)
        _integer(self.archive_bytes, "archive_bytes", 1024 * 1024 * 1024)
        objects = _objects(self.workflow, ArtifactBundleLimits())
        if self.object_count != len(objects) or self.object_bytes != sum(objects.values()):
            raise ValidationError("verified object counts must match unique workflow commitments")
        workflow_raw = canonical_json(self.workflow.to_dict(), pretty=False).encode("utf-8")
        state_raw = canonical_json(self.state.to_dict(), pretty=False).encode("utf-8")
        manifest = _manifest(self.workflow, workflow_raw, state_raw, objects)
        manifest_raw = canonical_json(manifest, pretty=False).encode("utf-8")
        sizes = {
            "manifest.json": len(manifest_raw),
            "workflow.json": len(workflow_raw),
            "state.json": len(state_raw),
        }
        sizes.update({"objects/" + digest: size for digest, size in objects.items()})
        if self.bundle_digest != manifest["bundle_digest"] or self.archive_bytes != _archive_size(
            sizes
        ):
            raise ValidationError("verified digest/size must match the canonical archive metadata")

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": "evidence-braid-verified-artifact-bundle",
            "schema_version": "1.0",
            "bundle_digest": self.bundle_digest,
            "workflow_head": self.workflow.head_digest,
            "evidence_head": self.workflow.evidence.head_digest,
            "authority_digest": self.workflow.authority_digest,
            "artifact_count": len(self.workflow.artifacts),
            "object_count": self.object_count,
            "object_bytes": self.object_bytes,
            "archive_bytes": self.archive_bytes,
            "state": self.state.to_dict(),
        }


def _limits(value: ArtifactBundleLimits | None) -> ArtifactBundleLimits:
    if value is None:
        return ArtifactBundleLimits()
    if type(value) is not ArtifactBundleLimits:
        raise ValidationError("limits must be ArtifactBundleLimits")
    return value


def _json_bytes(value: Any, maximum: int, name: str) -> bytes:
    raw = canonical_json(value, pretty=False).encode("utf-8")
    if len(raw) > maximum:
        raise ValidationError(f"{name} exceeds its metadata byte limit")
    return raw


def _parse(raw: bytes, name: str) -> Any:
    try:
        result = _loads(raw.decode("utf-8"))
        if canonical_json(result, pretty=False).encode("utf-8") != raw:
            raise ValueError("noncanonical metadata")
        return result
    except (ValueError, RecursionError) as exc:
        raise InputFormatError(f"invalid canonical {name}") from exc


def _objects(bundle: WorkflowBundle, limits: ArtifactBundleLimits) -> dict[str, int]:
    if len(bundle.artifacts) > limits.max_artifacts:
        raise ValidationError("artifact reference count exceeds limit")
    if sum(artifact.size_bytes for artifact in bundle.artifacts) > limits.max_total_source_bytes:
        raise ValidationError(
            "artifact source bytes including duplicate mappings exceed total limit"
        )
    objects: dict[str, int] = {}
    for artifact in bundle.artifacts:
        if artifact.size_bytes > limits.max_artifact_bytes:
            raise ValidationError("artifact exceeds file byte limit")
        if objects.setdefault(artifact.sha256, artifact.size_bytes) != artifact.size_bytes:
            raise ValidationError("one object digest has conflicting declared sizes")
    if sum(objects.values()) > limits.max_total_object_bytes:
        raise ValidationError("object bytes exceed total limit")
    return dict(sorted(objects.items()))


def _manifest(
    bundle: WorkflowBundle, workflow_raw: bytes, state_raw: bytes, objects: Mapping[str, int]
) -> dict[str, Any]:
    files = [
        {"path": name, "size_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        for name, raw in (("workflow.json", workflow_raw), ("state.json", state_raw))
    ]
    files.extend(
        {"path": "objects/" + digest, "size_bytes": size, "sha256": digest}
        for digest, size in objects.items()
    )
    result = {
        "kind": "evidence-braid-artifact-bundle",
        "schema_version": "1.0",
        "workflow_head": bundle.head_digest,
        "evidence_head": bundle.evidence.head_digest,
        "authority_digest": bundle.authority_digest,
        "files": files,
        "artifacts": [
            {**artifact.to_dict(), "object_path": "objects/" + artifact.sha256}
            for artifact in bundle.artifacts
        ],
    }
    return {
        **result,
        "bundle_digest": hashlib.sha256(
            canonical_json(result, pretty=False).encode("utf-8")
        ).hexdigest(),
    }


def _archive_size(sizes: Mapping[str, int]) -> int:
    return _END.size + sum(
        _CENTRAL.size + _LOCAL.size + 2 * len(name) + size for name, size in sizes.items()
    )


def _fingerprint(info: os.stat_result) -> tuple[int, int, int, int]:
    if not stat.S_ISREG(info.st_mode):
        raise InputFormatError("artifact/archive source must be a regular file")
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def _open_regular(path: Path) -> BinaryIO:
    if path.is_symlink():
        raise InputFormatError("artifact/archive source must not be a symbolic link")
    _fingerprint(path.stat())
    return path.open("rb")


def _exact(handle: BinaryIO, size: int) -> bytes:
    value = handle.read(size)
    if len(value) != size:
        raise InputFormatError("truncated artifact archive")
    return value


class _ArchiveView:
    """Serve the preflight-validated immutable central directory to ZipFile.

    This also prevents a changed EOCD from expanding ZipFile's metadata read
    after preflight. Object/local-header reads still use the same source file.
    """

    def __init__(self, handle: BinaryIO, offset: int, footer: bytes) -> None:
        self.handle, self.offset, self.footer = handle, offset, footer
        self.position = 0

    def seek(self, offset: int, whence: int = 0) -> int:
        position = (
            offset
            if whence == 0
            else self.position + offset
            if whence == 1
            else self.offset + len(self.footer) + offset
            if whence == 2
            else -1
        )
        if position < 0:
            raise OSError("invalid archive seek")
        self.position = position
        return position

    def tell(self) -> int:
        return self.position

    def seekable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        size = self.offset + len(self.footer) - self.position if size < 0 else size
        size = min(size, max(0, self.offset + len(self.footer) - self.position))
        result = b""
        if self.position < self.offset:
            self.handle.seek(self.position)
            result = self.handle.read(min(size, self.offset - self.position))
        remaining = size - len(result)
        if remaining:
            start = max(0, self.position + len(result) - self.offset)
            result += self.footer[start : start + remaining]
        self.position += len(result)
        return result


def _preflight(
    handle: BinaryIO, archive_size: int, limits: ArtifactBundleLimits
) -> tuple[_ArchiveView, dict[str, int]]:
    if not _END.size <= archive_size <= limits.max_archive_bytes:
        raise InputFormatError("archive byte size exceeds bounds")
    handle.seek(archive_size - _END.size)
    end_raw = _exact(handle, _END.size)
    signature, disk, cd_disk, disk_count, count, cd_size, cd_offset, comment = _END.unpack(end_raw)
    if (
        signature != b"PK\x05\x06"
        or disk != 0
        or cd_disk != 0
        or disk_count != count
        or not 3 <= count <= limits.max_artifacts + 3
        or comment != 0
        or not 0 < cd_size <= limits.max_central_bytes
        or cd_offset + cd_size != archive_size - _END.size
    ):
        raise InputFormatError("unsupported or unbounded ZIP32 directory")
    handle.seek(cd_offset)
    central_raw = _exact(handle, cd_size)
    central = io.BytesIO(central_raw)
    entries: dict[str, int] = {}
    next_local = 0
    object_bytes = 0
    for _ in range(count):
        values = _CENTRAL.unpack(_exact(central, _CENTRAL.size))
        (
            magic,
            made,
            needed,
            flags,
            method,
            time,
            date,
            crc,
            compressed,
            size,
            name_len,
            extra_len,
            comment_len,
            entry_disk,
            internal,
            external,
            local_offset,
        ) = values
        if (
            magic != b"PK\x01\x02"
            or made != 788
            or needed != 20
            or flags != 0
            or method != 0
            or time != 0
            or date != 33
            or compressed != size
            or not 1 <= name_len <= 72
            or extra_len != 0
            or comment_len != 0
            or entry_disk != 0
            or internal != 0
            or external != _MODE
            or local_offset != next_local
        ):
            raise InputFormatError("noncanonical ZIP32 entry")
        name_raw = _exact(central, name_len)
        try:
            name = name_raw.decode("ascii")
        except UnicodeError as exc:
            raise InputFormatError("archive member names must be ASCII") from exc
        if name not in _NAMES and re.fullmatch(r"objects/[0-9a-f]{64}", name) is None:
            raise InputFormatError("unsafe or unknown archive member")
        if name in entries or size > limits.entry_limit(name):
            raise InputFormatError("duplicate or oversized archive member")
        entries[name] = size
        if name.startswith("objects/"):
            object_bytes += size
            if object_bytes > limits.max_total_object_bytes:
                raise InputFormatError("archive object bytes exceed total limit")
        next_local = local_offset + _LOCAL.size + name_len + size
        if next_local > cd_offset:
            raise InputFormatError("archive members overlap the central directory")
        handle.seek(local_offset)
        local = _LOCAL.unpack(_exact(handle, _LOCAL.size))
        if (
            local
            != (
                b"PK\x03\x04",
                needed,
                flags,
                method,
                time,
                date,
                crc,
                compressed,
                size,
                name_len,
                0,
            )
            or _exact(handle, name_len) != name_raw
        ):
            raise InputFormatError("local and central archive headers disagree")
    names = list(entries)
    if (
        names[:3] != list(_NAMES)
        or names[3:] != sorted(names[3:])
        or next_local != cd_offset
        or central.tell() != cd_size
    ):
        raise InputFormatError("archive inventory/order is not canonical")
    return _ArchiveView(handle, cd_offset, central_raw + end_raw), entries


def _verify_artifact_bundle_internal(
    path: str | Path,
    *,
    authority: AuthorityPolicy,
    expected_head: str,
    expected_evidence_head: str,
    expected_bundle_digest: str | None = None,
    limits: ArtifactBundleLimits | None = None,
    case_journal_artifact_id: str | None = None,
    case_authority: CaseAuthority | None = None,
    expected_case_head: str | None = None,
) -> tuple[VerifiedArtifactBundle, CaseJournal | None, dict[str, bytes]]:
    """Verify every byte and replay using independently supplied policy/head anchors.

    Reads metadata into bounded memory, streams all artifact bytes, extracts
    nothing. Do not concurrently modify the archive or treat this as a sandbox.
    """
    config = _limits(limits)
    _hash(expected_head, "expected_head")
    _hash(expected_evidence_head, "expected_evidence_head")
    if expected_bundle_digest is not None:
        _hash(expected_bundle_digest, "expected_bundle_digest")
    source = Path(path).absolute()
    try:
        with _closing(_open_regular(source)) as handle:
            before = _fingerprint(os.fstat(handle.fileno()))
            view, entries = _preflight(handle, before[2], config)
            with _closing(zipfile.ZipFile(view, mode="r", allowZip64=False)) as archive:
                raw: dict[str, bytes] = {}
                for name in _NAMES:
                    with _closing(archive.open(name)) as member:
                        raw[name] = member.read(config.entry_limit(name) + 1)
                manifest = _parse(raw["manifest.json"], "manifest.json")
                workflow = WorkflowBundle.from_dict(
                    _parse(raw["workflow.json"], "workflow.json"),
                    authority=authority,
                    expected_head=expected_head,
                    expected_evidence_head=expected_evidence_head,
                )
                state = replay_workflow(workflow, authority=authority, expected_head=expected_head)
                _parse(raw["state.json"], "state.json")
                if raw["state.json"] != _json_bytes(
                    state.to_dict(), config.max_state_bytes, "state"
                ):
                    raise ValidationError("stored state differs from independent workflow replay")
                objects = _objects(workflow, config)
                case_journal: CaseJournal | None = None
                captured: dict[str, bytes] = {}
                capture_refs: dict[str, ArtifactReference] = {}
                if case_journal_artifact_id is not None:
                    if case_authority is None or expected_case_head is None:
                        raise ValidationError("case archive anchors are required")
                    references = {ref.artifact_id: ref for ref in workflow.artifacts}
                    journal_ref = references.get(case_journal_artifact_id)
                    if (
                        journal_ref is None
                        or journal_ref.size_bytes > 2 * 1024 * 1024
                        or "objects/" + journal_ref.sha256 not in entries
                    ):
                        raise ValidationError("case journal artifact is missing or oversized")
                    with _closing(archive.open("objects/" + journal_ref.sha256)) as member:
                        journal_raw = member.read(journal_ref.size_bytes + 1)
                    if not journal_ref.matches(journal_raw):
                        raise ValidationError("case journal artifact bytes differ")
                    case_journal = CaseJournal.from_bytes(
                        journal_raw, authority=case_authority, expected_head=expected_case_head
                    )
                    if (
                        len(case_journal.receipts) != 3
                        or type(case_journal.receipts[0].record) is not CasePlan
                        or type(case_journal.receipts[1].record) is not CaseObservation
                        or case_journal.receipts[1].record.status
                        is not CaseObservationStatus.OBSERVED
                    ):
                        raise ValidationError("case archive requires an observed three-record case")
                    plan = case_journal.receipts[0].record
                    observation = case_journal.receipts[1].record
                    required_ids = (
                        case_journal_artifact_id,
                        plan.assertion_artifact_id,
                        plan.input_artifact_id,
                        observation.artifact_id,
                    )
                    if None in required_ids or len(set(required_ids)) != 4:
                        raise ValidationError("case archive artifact identities overlap")
                    for identifier, maximum in zip(
                        required_ids,
                        (2 * 1024 * 1024, 64 * 1024, 256 * 1024, 4096),
                        strict=True,
                    ):
                        reference = references.get(cast(str, identifier))
                        if reference is None or reference.size_bytes > maximum:
                            raise ValidationError("case archive artifact is missing or oversized")
                        capture_refs[cast(str, identifier)] = reference
                    captured[case_journal_artifact_id] = journal_raw
                expected_manifest = _manifest(
                    workflow, raw["workflow.json"], raw["state.json"], objects
                )
                if manifest != expected_manifest:
                    raise ValidationError(
                        "manifest does not exactly bind workflow and object inventory"
                    )
                if raw["manifest.json"] != _json_bytes(
                    expected_manifest, config.max_manifest_bytes, "manifest"
                ):
                    raise ValidationError("manifest is not the exact canonical representation")
                if list(entries) != [*_NAMES, *("objects/" + digest for digest in objects)]:
                    raise ValidationError(
                        "archive must contain exactly the committed object inventory"
                    )
                for digest, size in objects.items():
                    name = "objects/" + digest
                    if entries[name] != size:
                        raise ValidationError("object size differs from artifact commitment")
                    observed = hashlib.sha256()
                    payload = (
                        bytearray()
                        if any(ref.sha256 == digest for ref in capture_refs.values())
                        else None
                    )
                    with _closing(archive.open(name)) as member:
                        while chunk := member.read(_CHUNK):
                            observed.update(chunk)
                            if payload is not None:
                                payload.extend(chunk)
                    if observed.hexdigest() != digest:
                        raise ValidationError("object bytes differ from artifact commitment")
                    if payload is not None:
                        for identifier, reference in capture_refs.items():
                            if reference.sha256 == digest:
                                captured[identifier] = bytes(payload)
                if (
                    expected_bundle_digest is not None
                    and manifest["bundle_digest"] != expected_bundle_digest
                ):
                    raise ValidationError("bundle does not match the independently retained digest")
            if before != _fingerprint(os.fstat(handle.fileno())) or before != _fingerprint(
                source.stat()
            ):
                raise InputFormatError("archive changed during verification")
            verified = VerifiedArtifactBundle(
                manifest["bundle_digest"],
                workflow,
                state,
                len(objects),
                sum(objects.values()),
                before[2],
            )
            return verified, case_journal, captured
    except (OSError, zipfile.BadZipFile) as exc:
        raise InputFormatError("cannot read or verify artifact archive") from exc


def verify_artifact_bundle(
    path: str | Path,
    *,
    authority: AuthorityPolicy,
    expected_head: str,
    expected_evidence_head: str,
    expected_bundle_digest: str | None = None,
    limits: ArtifactBundleLimits | None = None,
) -> VerifiedArtifactBundle:
    """Verify every archive byte and replay under independent policy/head anchors."""
    verified, _, _ = _verify_artifact_bundle_internal(
        path,
        authority=authority,
        expected_head=expected_head,
        expected_evidence_head=expected_evidence_head,
        expected_bundle_digest=expected_bundle_digest,
        limits=limits,
    )
    return verified


def _info(name: str, size: int) -> zipfile.ZipInfo:
    result = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    result.compress_type = zipfile.ZIP_STORED
    result.create_system = 3
    result.create_version = result.extract_version = 20
    result.external_attr = _MODE
    result.file_size = size
    return result


def _copy_source(path: Path, reference: ArtifactReference, destination: IO[bytes] | None) -> None:
    with _closing(_open_regular(path)) as source:
        before = _fingerprint(os.fstat(source.fileno()))
        if before[2] != reference.size_bytes:
            raise ValidationError("artifact source length differs from its commitment")
        digest = hashlib.sha256()
        remaining = reference.size_bytes
        while remaining:
            chunk = source.read(min(_CHUNK, remaining))
            if not chunk:
                raise InputFormatError("artifact source became shorter during copying")
            digest.update(chunk)
            if destination is not None:
                destination.write(chunk)
            remaining -= len(chunk)
        if (
            source.read(1)
            or before != _fingerprint(os.fstat(source.fileno()))
            or before != _fingerprint(path.stat())
        ):
            raise InputFormatError("artifact source changed during copying")
        if digest.hexdigest() != reference.sha256:
            raise ValidationError("artifact source digest differs from its commitment")


def build_artifact_bundle(
    path: str | Path,
    workflow: WorkflowBundle,
    sources: Mapping[str, str | Path],
    *,
    authority: AuthorityPolicy,
    limits: ArtifactBundleLimits | None = None,
) -> VerifiedArtifactBundle:
    """Stream exact ID-to-file mappings into a new, independently verified archive.

    IDs are never archive/file paths. Every supplied source is checked even when
    identical content is deduplicated. Publication never replaces a destination.
    """
    config = _limits(limits)
    state = replay_workflow(workflow, authority=authority)
    objects = _objects(workflow, config)
    if (
        not isinstance(sources, Mapping)
        or len(sources) != len(workflow.artifacts)
        or set(sources) != {reference.artifact_id for reference in workflow.artifacts}
        or any(not isinstance(value, (str, Path)) for value in sources.values())
    ):
        raise ValidationError("sources must map every artifact ID exactly once to a file path")
    # Freeze both mapping membership and relative-path interpretation before I/O.
    bound_sources = {identifier: Path(source).absolute() for identifier, source in sources.items()}
    workflow_raw = _json_bytes(workflow.to_dict(), config.max_workflow_bytes, "workflow")
    state_raw = _json_bytes(state.to_dict(), config.max_state_bytes, "state")
    manifest = _manifest(workflow, workflow_raw, state_raw, objects)
    manifest_raw = _json_bytes(manifest, config.max_manifest_bytes, "manifest")
    sizes = {
        "manifest.json": len(manifest_raw),
        "workflow.json": len(workflow_raw),
        "state.json": len(state_raw),
    }
    sizes.update({"objects/" + digest: size for digest, size in objects.items()})
    central_size = sum(_CENTRAL.size + len(name) for name in sizes)
    archive_size = _archive_size(sizes)
    if central_size > config.max_central_bytes or archive_size > config.max_archive_bytes:
        raise ValidationError("planned archive exceeds directory or archive byte limit")
    by_digest: dict[str, list[ArtifactReference]] = {digest: [] for digest in objects}
    for reference in workflow.artifacts:
        by_digest[reference.sha256].append(reference)
    try:
        with staged_output(path, replace=False) as staging:
            with _closing(
                zipfile.ZipFile(staging, mode="w", compression=zipfile.ZIP_STORED, allowZip64=False)
            ) as archive:
                for name, raw in zip(_NAMES, (manifest_raw, workflow_raw, state_raw), strict=True):
                    with _closing(archive.open(_info(name, len(raw)), mode="w")) as member:
                        member.write(raw)
                for digest, references in by_digest.items():
                    first, *duplicates = references
                    with _closing(
                        archive.open(_info("objects/" + digest, first.size_bytes), mode="w")
                    ) as member:
                        _copy_source(bound_sources[first.artifact_id], first, member)
                    for reference in duplicates:
                        _copy_source(bound_sources[reference.artifact_id], reference, None)
            staging.flush()
            verified = verify_artifact_bundle(
                staging.name,
                authority=authority,
                expected_head=workflow.head_digest,
                expected_evidence_head=workflow.evidence.head_digest,
                expected_bundle_digest=manifest["bundle_digest"],
                limits=config,
            )
        return verified
    except OSError as exc:
        raise InputFormatError("cannot assemble artifact archive") from exc
