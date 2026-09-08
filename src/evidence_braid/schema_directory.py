"""Atomic no-replace directories containing only the pinned schema publication.

Observed inode/type checks refuse links and unexpected entries. They are not a
hostile-filesystem sandbox or directory-metadata power-loss guarantee.
"""

from __future__ import annotations

import ctypes
import os
import stat
import sys
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from .errors import InputFormatError, ValidationError
from .ledger import _hash
from .schema_catalog import (
    MAX_SCHEMA_FILE_BYTES,
    MAX_SCHEMA_PUBLICATION_BYTES,
    SCHEMA_PUBLICATION_LINE,
    _publication,
)

PublicationState = Literal["unpublished", "published", "unknown"]
_SYSTEM = sys.platform


@dataclass(frozen=True, slots=True)
class SchemaDirectoryExport:
    """Output metadata, not a manually constructible verification certificate."""

    destination: Path
    catalog_digest: str
    size_bytes: int

    def __post_init__(self) -> None:
        if not isinstance(self.destination, Path) or not self.destination.is_absolute():
            raise ValidationError("schema directory destination must be an absolute Path")
        _hash(self.catalog_digest, "schema catalog digest")
        if (
            type(self.size_bytes) is not int
            or not 1 <= self.size_bytes <= MAX_SCHEMA_PUBLICATION_BYTES
        ):
            raise ValidationError("schema directory size is outside the compiled bound")

    @property
    def resource_count(self) -> int:
        return 10

    def to_dict(self) -> dict[str, Any]:
        return {
            "publication_line": SCHEMA_PUBLICATION_LINE,
            "destination": str(self.destination),
            "catalog_digest": self.catalog_digest,
            "resource_count": self.resource_count,
            "size_bytes": self.size_bytes,
        }


class SchemaDirectoryPublicationError(InputFormatError):
    """Publication failed or its acknowledgement is uncertain; do not blindly retry.

    ``published`` means the rename acknowledged success or its owned inode was
    subsequently observed at the destination. It does not claim power-loss
    durability or that a later filesystem actor cannot modify the directory.
    """

    def __init__(self, destination: Path, staging: Path, state: PublicationState) -> None:
        self.destination = destination
        self.staging_path = staging
        self.publication_state = state
        super().__init__(
            f"schema directory publication failed; publication state: {state}; "
            f"staging path: {staging}"
        )


def _path(value: str | Path) -> Path:
    if not isinstance(value, (str, Path)) or not str(value) or "\x00" in str(value):
        raise InputFormatError("schema directory path must be a nonempty path without NUL")
    return Path(value).absolute()


def _plain(value: os.stat_result, directory: bool) -> os.stat_result:
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not expected(value.st_mode)
        or getattr(value, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
        or value.st_ino <= 0
    ):
        raise InputFormatError("schema publication requires ordinary non-reparse files/directories")
    return value


def _identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


def _version(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (*_identity(value), value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _binding(value: os.stat_result) -> tuple[int, int, int, int, int | None]:
    # Windows lstat and fstat can report different ctime meanings (creation
    # versus change time). Compare compatible fields across APIs; each API's
    # before/after observation still retains its full ctime in _version.
    timestamp = getattr(value, "st_birthtime_ns", None) if os.name == "nt" else value.st_ctime_ns
    return (*_identity(value), value.st_size, value.st_mtime_ns, timestamp)


def _lstat(path: Path, directory: bool) -> os.stat_result:
    return _plain(path.lstat(), directory)


def _failure(primary: BaseException | None, secondary: BaseException, phase: str) -> BaseException:
    if primary is None:
        return secondary
    if isinstance(primary, Exception) and not isinstance(secondary, Exception):
        secondary.add_note(f"prior {phase} failure: {type(primary).__name__}")
        return secondary
    primary.add_note(f"additional {phase} failure: {type(secondary).__name__}")
    return primary


@contextmanager
def _descriptor(descriptor: int) -> Iterator[int]:
    problem: BaseException | None = None
    try:
        yield descriptor
    except BaseException as exc:
        problem = exc
    try:
        os.close(descriptor)
    except BaseException as exc:
        problem = _failure(problem, exc, "descriptor cleanup")
    if problem is not None:
        raise problem


def _inventory(path: Path, expected: set[str]) -> os.stat_result:
    before = _lstat(path, True)
    found: set[str] = set()
    iterator = os.scandir(path)
    problem: BaseException | None = None
    try:
        for entry in iterator:
            if len(found) == len(expected) or entry.name not in expected or entry.name in found:
                raise InputFormatError("schema directory has extra or unexpected entries")
            found.add(entry.name)
        if found != expected or _version(_lstat(path, True)) != _version(before):
            raise InputFormatError("schema directory is incomplete or changed during enumeration")
    except BaseException as exc:
        problem = exc
    try:
        iterator.close()
    except BaseException as exc:
        problem = _failure(problem, exc, "directory enumeration cleanup")
    if problem is not None:
        raise problem
    return before


def _read_file(path: Path, expected: bytes, maximum: int) -> os.stat_result:
    before = _lstat(path, False)
    if len(expected) > maximum or before.st_size != len(expected):
        raise InputFormatError("schema file size differs or exceeds its byte bound")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    with _descriptor(os.open(path, flags)) as descriptor:
        opened = _plain(os.fstat(descriptor), False)
        if _binding(opened) != _binding(before):
            raise InputFormatError("schema file changed before opening")
        raw = os.read(descriptor, len(expected) + 1)
        if raw != expected or _version(os.fstat(descriptor)) != _version(opened):
            raise InputFormatError("schema file differs from its fixed publication or changed")
        if _version(_lstat(path, False)) != _version(before):
            raise InputFormatError("schema file path changed during verification")
    return before


def verify_schema_directory(
    path: str | Path, *, expected_catalog_digest: str
) -> SchemaDirectoryExport:
    """Compare exactly one wire directory and ten files with the installed bytes.

    Enumeration and reads are bounded before materialization. Observed root,
    version-directory and resource entries reject symbolic/reparse links;
    arbitrary ancestors remain trusted. No files are extracted, imported or repaired.
    The expected catalog must come from the caller's separately selected source.
    """
    _hash(expected_catalog_digest, "expected catalog digest")
    destination = _path(path)
    catalog, resources, _ = _publication()
    if catalog.digest != expected_catalog_digest:
        raise InputFormatError("expected catalog is not the installed publication")
    version_path = destination / SCHEMA_PUBLICATION_LINE
    try:
        root = _inventory(destination, {SCHEMA_PUBLICATION_LINE})
        names = {Path(relative).name for relative in resources}
        version = _inventory(version_path, names)
        checked = []
        total = 0
        for relative, expected in sorted(resources.items()):
            source = destination / relative
            observed = _read_file(
                source, expected, min(MAX_SCHEMA_FILE_BYTES, MAX_SCHEMA_PUBLICATION_BYTES - total)
            )
            total += len(expected)
            checked.append((source, observed))
        for source, observed in checked:
            if _version(_lstat(source, False)) != _version(observed):
                raise InputFormatError("schema publication changed after a file was checked")
        if _version(_inventory(destination, {SCHEMA_PUBLICATION_LINE})) != _version(
            root
        ) or _version(_inventory(version_path, names)) != _version(version):
            raise InputFormatError("schema directory changed during verification")
    except OSError as exc:
        raise InputFormatError("cannot verify schema directory") from exc
    return SchemaDirectoryExport(destination, catalog.digest, total)


@dataclass(slots=True)
class _Owned:
    path: Path
    directory: bool
    parent: _Owned | None = None
    identity: tuple[int, int] | None = None

    def matches(self) -> bool:
        return (
            self.identity is not None
            and (self.parent is None or self.parent.matches())
            and _identity(_lstat(self.path, self.directory)) == self.identity
        )


def _require_owned(item: _Owned) -> None:
    if not item.matches():
        raise InputFormatError("schema staging ownership changed")


def _make_directory(item: _Owned) -> None:
    if item.parent is not None:
        _require_owned(item.parent)
    # The tracking record exists before the external write. If identity capture
    # fails, cleanup refuses to guess ownership and reports the residue.
    item.path.mkdir(mode=0o700)
    item.identity = _identity(_lstat(item.path, True))


def _write_file(item: _Owned, raw: bytes) -> None:
    if item.parent is not None:
        _require_owned(item.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    with _descriptor(os.open(item.path, flags, 0o600)) as descriptor:
        item.identity = _identity(_plain(os.fstat(descriptor), False))
        _require_owned(item)
        # os.write is unbuffered: no Python buffered flush remains before fsync.
        if os.write(descriptor, raw) != len(raw):
            raise InputFormatError("schema staging write was incomplete")
        os.fsync(descriptor)


def _rename_noreplace(source: Path, destination: Path) -> None:
    if _SYSTEM == "win32":
        # Unlike Unix rename, Windows os.rename refuses even an empty target.
        os.rename(source, destination)
        return
    if _SYSTEM != "linux":
        raise InputFormatError("atomic directory no-replace is unsupported on this platform")
    try:
        library = ctypes.CDLL(None, use_errno=True)
        operation = library.renameat2
    except (OSError, AttributeError) as exc:
        raise InputFormatError("native renameat2 is unavailable; no fallback is permitted") from exc
    operation.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    operation.restype = ctypes.c_int
    # Absolute source/destination ignore AT_FDCWD (-100); RENAME_NOREPLACE is 1.
    if operation(-100, os.fsencode(source), -100, os.fsencode(destination), 1) != 0:
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number), str(destination))


def _observe_publication(stage: _Owned, destination: Path) -> PublicationState:
    def identity(path: Path) -> tuple[int, int] | None:
        try:
            return _identity(_lstat(path, True))
        except FileNotFoundError:
            return None

    old = identity(stage.path)
    try:
        new = identity(destination)
    except InputFormatError:
        new = None  # A foreign ordinary file/link cannot be the staged directory.
    if old == stage.identity and new != stage.identity:
        return "unpublished"
    if old is None and new == stage.identity:
        return "published"
    return "unknown"


def _cleanup(owned: list[_Owned], primary: BaseException | None) -> BaseException | None:
    for item in reversed(owned):
        try:
            item.path.lstat()  # An uncreated/missing reserved name needs no cleanup.
            if not item.matches():
                raise InputFormatError(f"unowned or replaced staging residue retained: {item.path}")
            if item.directory:
                item.path.rmdir()  # Never recursive: unknown entries prevent removal.
            else:
                item.path.unlink()
        except FileNotFoundError:
            continue
        except BaseException as exc:
            primary = _failure(primary, exc, f"staging cleanup ({item.path})")
    return primary


def export_schema_directory(path: str | Path) -> SchemaDirectoryExport:
    """Publish the complete known tree in one no-replace directory rename.

    The parent must already exist. Only observed owned staging paths are ever
    cleaned; unknown/replaced residue is retained and reported. On a control
    exception, publication acknowledgement is attached as an exception note.
    """
    destination = _path(path)
    catalog, resources, _ = _publication()
    result = SchemaDirectoryExport(destination, catalog.digest, sum(map(len, resources.values())))
    staging = destination.parent / f".evidence-schema-{uuid.uuid4().hex}"
    parent = _Owned(destination.parent, True)
    stage = _Owned(staging, True, parent)
    version = _Owned(staging / SCHEMA_PUBLICATION_LINE, True, stage)
    members = [_Owned(staging / relative, False, version) for relative in sorted(resources)]
    owned = [stage, version, *members]
    state: PublicationState = "unpublished"
    problem: BaseException | None = None
    attempted = False
    try:
        parent.identity = _identity(_lstat(parent.path, True))
        _make_directory(stage)
        _make_directory(version)
        for item, relative in zip(members, sorted(resources), strict=True):
            _write_file(item, resources[relative])
        verify_schema_directory(staging, expected_catalog_digest=catalog.digest)
        _require_owned(version)
        attempted = True
        _rename_noreplace(staging, destination)
        state = "published"
        if _identity(_lstat(destination, True)) != stage.identity:
            state = "unknown"
            raise InputFormatError("published directory identity changed before acknowledgement")
    except BaseException as exc:
        problem = exc
        if attempted and state == "unpublished":
            try:
                state = _observe_publication(stage, destination)
            except BaseException as observed:
                state = "unknown"
                problem = _failure(problem, observed, "publication acknowledgement")
    if state == "unpublished":
        problem = _cleanup(owned, problem)
    if problem is not None:
        problem.add_note(f"schema directory publication state: {state}; staging path: {staging}")
        if isinstance(problem, Exception):
            raise SchemaDirectoryPublicationError(destination, staging, state) from problem
        raise problem
    return result


__all__ = [
    "SchemaDirectoryExport",
    "SchemaDirectoryPublicationError",
    "export_schema_directory",
    "verify_schema_directory",
]
