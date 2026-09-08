"""Closed offline schema resources and deterministic no-replace ZIP publication.

Schema acceptance is structural, never an authorization, replay or proof verdict.
Only the fixed packaged publication line is supported; no URI is downloaded.
"""

from __future__ import annotations

import hashlib
import json
import struct
import zlib
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from types import MappingProxyType
from typing import Any

from ._atomic import staged_output
from ._schema_shapes import DIALECT, ID_PREFIX, PUBLIC_SCHEMAS, PUBLICATION_LINE
from .errors import InputFormatError, ValidationError
from .io import _loads
from .ledger import _fields, _hash

SCHEMA_PUBLICATION_LINE = PUBLICATION_LINE
MAX_SCHEMA_FILE_BYTES = 64 * 1024
MAX_SCHEMA_PUBLICATION_BYTES = 256 * 1024
MAX_SCHEMA_ARCHIVE_BYTES = MAX_SCHEMA_PUBLICATION_BYTES + 4096
_CATALOG_SHA256 = "1b71c9ba213b7547b190ba6cf351dedc26821cd6becf010a53d0bb11994a5434"
_NAMES = tuple(sorted((*PUBLIC_SCHEMAS, "common")))
_CATALOG_PATH = f"{PUBLICATION_LINE}/catalog.json"
_SUMS_PATH = f"{PUBLICATION_LINE}/SHA256SUMS"


def _name(value: Any) -> str:
    if type(value) is not str or value not in _NAMES:
        raise ValidationError("unknown packaged schema name")
    return value


def _encode(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


@dataclass(frozen=True, slots=True)
class PublishedSchema:
    """Immutable resource metadata; constructing it does not verify a file."""

    name: str
    size_bytes: int
    sha256: str

    def __post_init__(self) -> None:
        _name(self.name)
        if type(self.size_bytes) is not int or not 1 <= self.size_bytes <= MAX_SCHEMA_FILE_BYTES:
            raise ValidationError("schema size must be within the compiled file bound")
        _hash(self.sha256, "schema digest")

    @property
    def schema_id(self) -> str:
        return f"{ID_PREFIX}{self.name}"

    @property
    def path(self) -> str:
        return f"{PUBLICATION_LINE}/{self.name}.schema.json"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": self.path,
            "schema_id": self.schema_id,
            "title": f"Evidence Braid {self.name} structural wire profile",
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "public": self.name in PUBLIC_SCHEMAS,
        }


@dataclass(frozen=True, slots=True)
class SchemaCatalog:
    """A closed metadata inventory, not publisher authentication or file proof."""

    schemas: tuple[PublishedSchema, ...]

    def __post_init__(self) -> None:
        if (
            type(self.schemas) is not tuple
            or len(self.schemas) != len(_NAMES)
            or any(type(item) is not PublishedSchema for item in self.schemas)
            or tuple(item.name for item in self.schemas) != _NAMES
            or self.total_schema_bytes > MAX_SCHEMA_PUBLICATION_BYTES
        ):
            raise ValidationError("catalog must contain the exact ordered bounded schema inventory")

    @property
    def total_schema_bytes(self) -> int:
        return sum(item.size_bytes for item in self.schemas)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": "evidence-braid-schema-catalog",
            "schema_version": "1.0",
            "publication_line": PUBLICATION_LINE,
            "dialect": DIALECT,
            "schemas": [item.to_dict() for item in self.schemas],
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(_encode(self.to_dict())).hexdigest()


@dataclass(frozen=True, slots=True)
class SchemaExport:
    """Output metadata; manual construction is not a verification certificate."""

    destination: Path
    catalog_digest: str
    archive_sha256: str
    size_bytes: int

    def __post_init__(self) -> None:
        if not isinstance(self.destination, Path) or not self.destination.is_absolute():
            raise ValidationError("schema archive destination must be an absolute Path")
        for value in (self.catalog_digest, self.archive_sha256):
            _hash(value, "schema export digest")
        if type(self.size_bytes) is not int or not 1 <= self.size_bytes <= MAX_SCHEMA_ARCHIVE_BYTES:
            raise ValidationError("schema archive size is outside the compiled bound")

    def to_dict(self) -> dict[str, Any]:
        return {
            "publication_line": PUBLICATION_LINE,
            "destination": str(self.destination),
            "catalog_digest": self.catalog_digest,
            "archive_sha256": self.archive_sha256,
            "size_bytes": self.size_bytes,
        }


def _resource(path: str, maximum: int) -> bytes:
    if maximum < 0:
        raise InputFormatError("packaged schema publication exceeds its total byte bound")
    try:
        with files("evidence_braid").joinpath("schemas", *path.split("/")).open("rb") as handle:
            raw = handle.read(maximum + 1)
    except OSError as exc:
        raise InputFormatError("cannot read packaged schema resource") from exc
    if len(raw) > maximum:
        raise InputFormatError("packaged schema resource exceeds its byte bound")
    return raw


def _json(raw: bytes) -> dict[str, Any]:
    try:
        value = _loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise InputFormatError("packaged schema resource is not strict JSON") from exc
    if type(value) is not dict:
        raise InputFormatError("packaged schema resource must be an object")
    return value


def _references(value: Any) -> Iterator[str]:
    pending = [value]
    while pending:
        current = pending.pop()
        if type(current) is dict:
            if "$ref" in current:
                yield current["$ref"]
            pending.extend(current.values())
        elif type(current) is list:
            pending.extend(current)


def _publication() -> tuple[SchemaCatalog, dict[str, bytes], dict[str, dict[str, Any]]]:
    catalog_raw = _resource(_CATALOG_PATH, 8192)
    if hashlib.sha256(catalog_raw).hexdigest() != _CATALOG_SHA256:
        raise InputFormatError("packaged catalog differs from its publication commitment")
    data = _json(catalog_raw)
    rows = data.get("schemas")
    if type(rows) is not list or len(rows) != len(_NAMES):
        raise InputFormatError("packaged catalog inventory is not closed")
    descriptors = []
    for row in rows:
        _fields(
            row, {"name", "path", "schema_id", "title", "size_bytes", "sha256", "public"}, "schema"
        )
        descriptor = PublishedSchema(row["name"], row["size_bytes"], row["sha256"])
        if type(row["public"]) is not bool or row != descriptor.to_dict():
            raise InputFormatError("packaged schema descriptor differs from its fixed identity")
        descriptors.append(descriptor)
    catalog = SchemaCatalog(tuple(descriptors))
    if _encode(catalog.to_dict()) != catalog_raw:
        raise InputFormatError("packaged catalog is not the canonical supported profile")
    resources = {_CATALOG_PATH: catalog_raw}
    documents = {}
    total = len(catalog_raw)
    for descriptor in catalog.schemas:
        raw = _resource(
            descriptor.path, min(MAX_SCHEMA_FILE_BYTES, MAX_SCHEMA_PUBLICATION_BYTES - total)
        )
        total += len(raw)
        if (
            len(raw) != descriptor.size_bytes
            or hashlib.sha256(raw).hexdigest() != descriptor.sha256
        ):
            raise InputFormatError("packaged schema bytes differ from their catalog commitment")
        document = _json(raw)
        if document.get("$id") != descriptor.schema_id or document.get("$schema") != DIALECT:
            raise InputFormatError("packaged schema identity or dialect differs")
        resources[descriptor.path] = raw
        documents[descriptor.schema_id] = document
    allowed = set(documents)
    for schema_id, document in documents.items():
        definitions = document.get("$defs", {})
        if type(definitions) is not dict:
            raise InputFormatError("packaged schema definitions must be an object")
        allowed.update(f"{schema_id}#/$defs/{name}" for name in definitions)
    if any(
        type(ref) is not str or ref not in allowed
        for doc in documents.values()
        for ref in _references(doc)
    ):
        raise InputFormatError("schema reference leaves the closed offline registry")
    expected_sums = "".join(
        f"{hashlib.sha256(raw).hexdigest()}  {path}\n" for path, raw in sorted(resources.items())
    ).encode("ascii")
    sums = _resource(_SUMS_PATH, min(4096, MAX_SCHEMA_PUBLICATION_BYTES - total))
    if sums != expected_sums:
        raise InputFormatError("packaged schema checksum inventory differs")
    resources[_SUMS_PATH] = sums
    return catalog, resources, documents


def load_schema_catalog() -> SchemaCatalog:
    """Check the entire fixed publication and return immutable resource metadata."""
    return _publication()[0]


def schema_bytes(name: str) -> bytes:
    """Return exact packaged schema bytes; names are IDs, never file paths/URLs."""
    name = _name(name)
    return _publication()[1][f"{PUBLICATION_LINE}/{name}.schema.json"]


def schema_registry() -> Mapping[str, dict[str, Any]]:
    """Return a closed URI map of fresh caller-owned parsed schema documents.

    The outer map is read-only; nested JSON is a fresh copy on every call. A
    validator must preload these resources and refuse every unknown URI.
    """
    return MappingProxyType(_publication()[2])


def _archive(resources: Mapping[str, bytes]) -> bytes:
    """Encode the one fixed STORED ZIP32 profile without a general ZIP parser."""
    local: list[bytes] = []
    central: list[bytes] = []
    offset = 0
    for path, raw in sorted(resources.items()):
        name = path.encode("ascii")
        crc, size = zlib.crc32(raw), len(raw)
        header = struct.pack(
            "<IHHHHHIIIHH", 0x04034B50, 20, 0, 0, 0, 33, crc, size, size, len(name), 0
        )
        local.extend((header, name, raw))
        central.extend(
            (
                struct.pack(
                    "<IHHHHHHIIIHHHHHII",
                    0x02014B50,
                    20,
                    20,
                    0,
                    0,
                    0,
                    33,
                    crc,
                    size,
                    size,
                    len(name),
                    0,
                    0,
                    0,
                    0,
                    0,
                    offset,
                ),
                name,
            )
        )
        offset += len(header) + len(name) + size
    directory = b"".join(central)
    end = struct.pack(
        "<IHHHHIIH", 0x06054B50, 0, 0, len(resources), len(resources), len(directory), offset, 0
    )
    result = b"".join((*local, directory, end))
    if len(result) > MAX_SCHEMA_ARCHIVE_BYTES:
        raise InputFormatError("schema archive exceeds its compiled byte bound")
    return result


def verify_schema_archive(path: str | Path, *, expected_catalog_digest: str) -> SchemaExport:
    """Verify the exact known canonical ZIP against a separately selected catalog.

    This is not an arbitrary ZIP/schema import API. The bounded file is compared
    with the complete supported publication, including every ZIP header byte;
    untrusted central-directory counts are never materialized by ZipFile.
    """
    _hash(expected_catalog_digest, "expected catalog digest")
    destination = Path(path).absolute()
    catalog, resources, _ = _publication()
    if catalog.digest != expected_catalog_digest:
        raise InputFormatError("expected catalog is not the installed publication")
    try:
        with destination.open("rb") as handle:
            raw = handle.read(MAX_SCHEMA_ARCHIVE_BYTES + 1)
    except OSError as exc:
        raise InputFormatError("cannot read schema archive") from exc
    if len(raw) > MAX_SCHEMA_ARCHIVE_BYTES or raw != _archive(resources):
        raise InputFormatError("schema archive differs from the complete canonical publication")
    return SchemaExport(destination, catalog.digest, hashlib.sha256(raw).hexdigest(), len(raw))


def export_schemas(path: str | Path) -> SchemaExport:
    """Publish one canonical ZIP atomically without replacing any destination.

    The containing directory must exist. This is single-file publication, not
    atomic directory export; filesystem metadata power-loss durability and a
    hostile-filesystem/process-RSS sandbox are not promised.
    """
    destination = Path(path).absolute()
    catalog, resources, _ = _publication()
    raw = _archive(resources)
    with staged_output(destination, replace=False) as handle:
        if handle.write(raw) != len(raw):
            raise InputFormatError("schema archive staging write was incomplete")
        handle.flush()
        verify_schema_archive(handle.name, expected_catalog_digest=catalog.digest)
    return SchemaExport(destination, catalog.digest, hashlib.sha256(raw).hexdigest(), len(raw))


__all__ = [
    "SCHEMA_PUBLICATION_LINE",
    "PublishedSchema",
    "SchemaCatalog",
    "SchemaExport",
    "export_schemas",
    "load_schema_catalog",
    "schema_bytes",
    "schema_registry",
    "verify_schema_archive",
]
