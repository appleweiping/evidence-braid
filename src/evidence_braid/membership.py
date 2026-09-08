"""Detached receipt membership under a separately retained Merkle commitment.

Membership is neither source authentication nor proof that a query is complete.
The existing ledger head is not interchangeable with the commitment digest.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from math import isfinite
from typing import Any

from .errors import ValidationError
from .io import _parse_finite_float, _reject_constant, _reject_duplicate_keys, canonical_json
from .ledger import _VERSIONS, MAX_LEDGER_ENTRIES, LedgerEntry, _digest, _hash
from .models import MAX_ATTRIBUTE_INTEGER_DIGITS, EvidenceEvent
from .query import LedgerIndex, LedgerPage

_DOMAIN = b"evidence-braid:ledger-membership:v1\x00"
_KIND = "evidence-braid-ledger-commitment"
_BUNDLE_KIND = "evidence-braid-ledger-membership"
_VERSION = "1.0"
_MAX_MEMBERS = 1000
_MAX_SIBLINGS = 17
_MAX_RECEIPT_BYTES = 16 * 1024 * 1024
_MAX_BUNDLE_BYTES = 20 * 1024 * 1024
_MAX_JSON_DEPTH = 72
_MAX_JSON_NODES = 1_000_000
_MAX_INTEGER = 10**MAX_ATTRIBUTE_INTEGER_DIGITS - 1
_HEADER_FIELDS = {
    "kind",
    "schema_version",
    "ledger_version",
    "genesis",
    "head_digest",
    "entry_count",
    "root_hash",
    "commitment_digest",
}


def _count(value: Any, name: str, maximum: int, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValidationError(f"{name} must be an integer in {minimum}..{maximum}")
    return value


def _object(value: Any, fields: set[str], name: str) -> dict[str, Any]:
    if (
        type(value) is not dict
        or any(type(key) is not str for key in value)
        or set(value) != fields
    ):
        raise ValidationError(f"{name} has an invalid field set")
    return value


def _canonical(value: Any) -> bytes:
    return canonical_json(value, pretty=False).encode("utf-8")


def _hash_bytes(tag: bytes, value: bytes = b"") -> str:
    return hashlib.sha256(_DOMAIN + tag + value).hexdigest()


def _node_hash(left: str, right: str) -> str:
    return _hash_bytes(b"N", bytes.fromhex(left) + bytes.fromhex(right))


def _leaf_hash(version: str, entry: LedgerEntry) -> str:
    return _hash_bytes(b"L", _canonical({"ledger_version": version, "receipt": entry.to_dict()}))


def _receipt_bytes(entry: LedgerEntry) -> bytes:
    if type(entry) is not LedgerEntry:
        raise ValidationError("membership requires an immutable LedgerEntry")
    data = entry.to_dict()
    _preflight(data)
    raw = _canonical(data)
    if len(raw) > _MAX_RECEIPT_BYTES:
        raise ValidationError("selected receipt bytes exceed 16 MiB")
    parsed = LedgerEntry.from_dict(data)
    if _canonical(parsed.to_dict()) != raw:
        raise ValidationError("membership receipt is not canonical")
    return raw


def _route(position: int, count: int) -> tuple[bool, ...]:
    """Bottom-up sibling orientation; True means the sibling goes on the left."""
    _count(position, "sequence", count - 1)
    directions: list[bool] = []
    while count > 1:
        split = 1 << ((count - 1).bit_length() - 1)
        right = position >= split
        directions.append(right)
        if right:
            position -= split
            count -= split
        else:
            count = split
    return tuple(reversed(directions))


def _parse_integer(literal: str) -> int:
    if len(literal.removeprefix("-")) > MAX_ATTRIBUTE_INTEGER_DIGITS:
        raise ValueError("membership integer exceeds the attribute digit limit")
    return int(literal)


def _text_size(value: str, remaining: int) -> int:
    if len(value) > remaining:
        raise ValidationError("membership scalar data exceeds 20 MiB")
    try:
        return len(value.encode("utf-8"))
    except UnicodeError as exc:
        raise ValidationError("membership text must contain Unicode scalar values") from exc


def _raw_depth(raw: bytes) -> None:
    """Depth admission before json.loads; JSON grammar is still the decoder's job."""
    depth = 0
    quoted = escaped = False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > _MAX_JSON_DEPTH:
                raise ValidationError("membership JSON nesting exceeds 72 containers")
        elif byte in (93, 125):
            depth -= 1


def _preflight(value: Any) -> None:
    """Bound an already-parsed JSON graph before constructing receipt objects."""
    # Iterator frames retain O(depth) work, never one queued tuple per child.
    stack: list[tuple[Iterator[Any], int, int | None]] = [(iter((value,)), 0, None)]
    ancestors: set[int] = set()
    nodes = 0
    scalar_bytes = 0
    while stack:
        children, depth, identity = stack[-1]
        try:
            item = next(children)
        except StopIteration:
            stack.pop()
            if identity is not None:
                ancestors.remove(identity)
            continue
        nodes += 1
        if nodes > _MAX_JSON_NODES or depth > _MAX_JSON_DEPTH:
            raise ValidationError("membership JSON graph exceeds node/depth bounds")
        if type(item) in (dict, list):
            if id(item) in ancestors:
                raise ValidationError("membership JSON graph contains a cycle")
            child_work = len(item) * (2 if type(item) is dict else 1)
            if child_work > _MAX_JSON_NODES - nodes:
                raise ValidationError("membership JSON graph exceeds node bounds")
            ancestors.add(id(item))
            if type(item) is dict:
                nodes += len(item)  # Object keys also cost graph work.
                if any(type(key) is not str for key in item):
                    raise ValidationError("membership JSON keys must be strings")
                for key in item:
                    scalar_bytes += _text_size(key, _MAX_BUNDLE_BYTES - scalar_bytes)
                stack.append((iter(item.values()), depth + 1, id(item)))
            else:
                stack.append((iter(item), depth + 1, id(item)))
        elif type(item) is str:
            scalar_bytes += _text_size(item, _MAX_BUNDLE_BYTES - scalar_bytes)
        elif item is None or type(item) is bool:
            scalar_bytes += 5
        elif type(item) is int:
            if abs(item) > _MAX_INTEGER:
                raise ValidationError("membership JSON integer exceeds attribute bounds")
            scalar_bytes += len(str(item))
        elif type(item) is float:
            if not isfinite(item):
                raise ValidationError("membership JSON numbers must be finite")
            scalar_bytes += len(str(item))
        else:
            raise ValidationError("membership JSON requires exact built-in types")
        if scalar_bytes > _MAX_BUNDLE_BYTES:
            raise ValidationError("membership scalar data exceeds 20 MiB")


@dataclass(frozen=True, slots=True)
class LedgerCommitment:
    """Header consistency, not authentication; retain digest out of band."""

    ledger_version: str
    genesis: str
    head_digest: str
    entry_count: int
    root_hash: str

    def __post_init__(self) -> None:
        if type(self.ledger_version) is not str or self.ledger_version not in _VERSIONS:
            raise ValidationError("unsupported commitment ledger version")
        for name in ("genesis", "head_digest", "root_hash"):
            _hash(getattr(self, name), name)
        if self.genesis != _VERSIONS[self.ledger_version]:
            raise ValidationError("commitment genesis does not match ledger version")
        _count(self.entry_count, "entry_count", MAX_LEDGER_ENTRIES)
        if self.entry_count == 0 and (
            self.head_digest != self.genesis or self.root_hash != _hash_bytes(b"E")
        ):
            raise ValidationError("empty commitment must use genesis and the empty-tree root")

    def _body(self) -> dict[str, Any]:
        return {
            "kind": _KIND,
            "schema_version": _VERSION,
            "ledger_version": self.ledger_version,
            "genesis": self.genesis,
            "head_digest": self.head_digest,
            "entry_count": self.entry_count,
            "root_hash": self.root_hash,
        }

    @property
    def digest(self) -> str:
        return _hash_bytes(b"C", _canonical(self._body()))

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "commitment_digest": self.digest}

    @classmethod
    def from_dict(cls, value: Any) -> LedgerCommitment:
        data = _object(value, _HEADER_FIELDS, "commitment")
        if (
            type(data["kind"]) is not str
            or data["kind"] != _KIND
            or type(data["schema_version"]) is not str
            or data["schema_version"] != _VERSION
        ):
            raise ValidationError("unsupported commitment format")
        result = cls(
            data["ledger_version"],
            data["genesis"],
            data["head_digest"],
            data["entry_count"],
            data["root_hash"],
        )
        _hash(data["commitment_digest"], "commitment_digest")
        if data["commitment_digest"] != result.digest:
            raise ValidationError("commitment digest does not match its header")
        return result


@dataclass(frozen=True, slots=True)
class LedgerMemberProof:
    """A complete receipt and bottom-up sibling hashes, without a trust verdict."""

    entry: LedgerEntry = field(repr=False)
    siblings: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.siblings) is not tuple or len(self.siblings) > _MAX_SIBLINGS:
            raise ValidationError("membership siblings require a tuple of at most 17 hashes")
        for sibling in self.siblings:
            _hash(sibling, "sibling")
        _receipt_bytes(self.entry)

    def to_dict(self) -> dict[str, Any]:
        return {"entry": self.entry.to_dict(), "siblings": list(self.siblings)}

    @classmethod
    def from_dict(cls, value: Any) -> LedgerMemberProof:
        data = _object(value, {"entry", "siblings"}, "member")
        siblings = data["siblings"]
        if type(siblings) is not list or len(siblings) > _MAX_SIBLINGS:
            raise ValidationError("membership siblings must be a bounded array")
        for sibling in siblings:
            _hash(sibling, "sibling")
        _preflight(data)
        return cls(LedgerEntry.from_dict(data["entry"]), tuple(siblings))


@dataclass(frozen=True, slots=True)
class LedgerMembershipBundle:
    """Nonempty detached membership proofs sharing one commitment header."""

    commitment: LedgerCommitment
    members: tuple[LedgerMemberProof, ...] = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.commitment) is not LedgerCommitment:
            raise ValidationError("membership requires a LedgerCommitment")
        if type(self.members) is not tuple or not 1 <= len(self.members) <= _MAX_MEMBERS:
            raise ValidationError("membership requires 1..1000 immutable member proofs")
        previous = -1
        size = 0
        for member in self.members:
            if type(member) is not LedgerMemberProof:
                raise ValidationError("membership contains an invalid member proof")
            sequence = member.entry.sequence
            if sequence <= previous:
                raise ValidationError("membership positions must strictly increase")
            route = _route(sequence, self.commitment.entry_count)
            if len(member.siblings) != len(route):
                raise ValidationError("membership sibling count disagrees with tree shape")
            size += len(_receipt_bytes(member.entry))
            if size > _MAX_RECEIPT_BYTES:
                raise ValidationError("selected receipt bytes exceed 16 MiB")
            previous = sequence

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": _BUNDLE_KIND,
            "schema_version": _VERSION,
            "commitment": self.commitment.to_dict(),
            "members": [member.to_dict() for member in self.members],
        }

    def to_bytes(self) -> bytes:
        data = self.to_dict()
        _preflight(data)
        raw = _canonical(data)
        if len(raw) > _MAX_BUNDLE_BYTES:
            raise ValidationError("membership bundle exceeds 20 MiB")
        return raw

    @classmethod
    def from_dict(cls, value: Any) -> LedgerMembershipBundle:
        data = _object(value, {"kind", "schema_version", "commitment", "members"}, "bundle")
        if (
            type(data["kind"]) is not str
            or data["kind"] != _BUNDLE_KIND
            or type(data["schema_version"]) is not str
            or data["schema_version"] != _VERSION
        ):
            raise ValidationError("unsupported membership bundle format")
        members = data["members"]
        if type(members) is not list or not 1 <= len(members) <= _MAX_MEMBERS:
            raise ValidationError("membership requires 1..1000 members")
        # Inspect every path count before parsing/copying the first event graph.
        for member in members:
            fields = _object(member, {"entry", "siblings"}, "member")
            if type(fields["siblings"]) is not list or len(fields["siblings"]) > _MAX_SIBLINGS:
                raise ValidationError("membership siblings must be a bounded array")
        _preflight(data)
        size = 0
        for member in members:
            size += len(_canonical(member["entry"]))
            if size > _MAX_RECEIPT_BYTES:
                raise ValidationError("selected receipt bytes exceed 16 MiB")
        result = cls(
            LedgerCommitment.from_dict(data["commitment"]),
            tuple(LedgerMemberProof.from_dict(member) for member in members),
        )
        result.to_bytes()
        return result

    @classmethod
    def from_bytes(cls, raw: bytes) -> LedgerMembershipBundle:
        if type(raw) is not bytes or len(raw) > _MAX_BUNDLE_BYTES:
            raise ValidationError("membership input must be bytes within 20 MiB")
        _raw_depth(raw)
        try:
            data = json.loads(
                raw.decode("utf-8"),
                parse_int=_parse_integer,
                parse_float=_parse_finite_float,
                parse_constant=_reject_constant,
                object_pairs_hook=_reject_duplicate_keys,
            )
            result = cls.from_dict(data)
            if result.to_bytes() != raw:
                raise ValidationError("membership input is not canonical UTF-8 JSON")
            return result
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise ValidationError("invalid canonical membership JSON") from exc


def verify_ledger_membership(
    bundle: LedgerMembershipBundle, *, expected_commitment_digest: str
) -> tuple[LedgerEntry, ...]:
    """Verify selected receipts, requiring an independently retained commitment.

    This cannot establish query completeness, durable storage or source identity.
    No default anchor is copied from the bundle or derived from an old chain head.
    """
    _hash(expected_commitment_digest, "expected_commitment_digest")
    if type(bundle) is not LedgerMembershipBundle:
        raise ValidationError("verification requires LedgerMembershipBundle")
    header = bundle.commitment
    if header.digest != expected_commitment_digest:
        raise ValidationError("membership commitment differs from the expected anchor")
    for member in bundle.members:
        entry = member.entry
        event = EvidenceEvent.from_dict(entry.to_dict()["event"])
        if (
            _digest(entry.previous_digest, event, entry.sequence, header.ledger_version)
            != entry.digest
        ):
            raise ValidationError("membership receipt chain digest does not match")
        if entry.sequence == 0 and entry.previous_digest != header.genesis:
            raise ValidationError("first membership receipt does not follow genesis")
        if entry.sequence == header.entry_count - 1 and entry.digest != header.head_digest:
            raise ValidationError("last membership receipt differs from the prefix head")
        digest = _leaf_hash(header.ledger_version, entry)
        for left, sibling in zip(
            _route(entry.sequence, header.entry_count), member.siblings, strict=True
        ):
            digest = _node_hash(sibling, digest) if left else _node_hash(digest, sibling)
        if digest != header.root_hash:
            raise ValidationError("membership proof does not reproduce the committed root")
    return tuple(member.entry for member in bundle.members)


@dataclass(frozen=True, slots=True)
class _Node:
    digest: str
    count: int
    left: _Node | None = None
    right: _Node | None = None


def _build(index: LedgerIndex, start: int, count: int) -> _Node:
    if count == 1:
        return _Node(_leaf_hash(index.ledger.schema_version, index.ledger.entries[start]), 1)
    split = 1 << ((count - 1).bit_length() - 1)
    left = _build(index, start, split)
    right = _build(index, start + split, count - split)
    return _Node(_node_hash(left.digest, right.digest), count, left, right)


@dataclass(frozen=True, slots=True, init=False)
class LedgerProofIndex:
    """Cached tree over an already verified immutable LedgerIndex prefix."""

    index: LedgerIndex = field(repr=False)
    commitment: LedgerCommitment
    _tree: _Node | None = field(repr=False)

    def __init__(self, index: LedgerIndex) -> None:
        if type(index) is not LedgerIndex:
            raise ValidationError("proof index requires a verified LedgerIndex")
        ledger = index.ledger
        tree = _build(index, 0, len(ledger.entries)) if ledger.entries else None
        object.__setattr__(self, "index", index)
        object.__setattr__(self, "_tree", tree)
        object.__setattr__(
            self,
            "commitment",
            LedgerCommitment(
                ledger.schema_version,
                ledger.genesis,
                ledger.head_digest,
                len(ledger.entries),
                tree.digest if tree is not None else _hash_bytes(b"E"),
            ),
        )

    def _member(self, sequence: int) -> LedgerMemberProof:
        _count(sequence, "sequence", self.commitment.entry_count - 1)
        tree = self._tree
        siblings: list[str] = []
        offset = sequence
        while tree is not None and tree.count > 1:
            left, right = tree.left, tree.right
            if left is None or right is None:  # Private cached-tree invariant.
                raise RuntimeError("membership tree has an incomplete internal node")
            if offset < left.count:
                siblings.append(right.digest)
                tree = left
            else:
                siblings.append(left.digest)
                offset -= left.count
                tree = right
        return LedgerMemberProof(self.index.ledger.entries[sequence], tuple(reversed(siblings)))

    def prove(self, sequence: int) -> LedgerMembershipBundle:
        return LedgerMembershipBundle(self.commitment, (self._member(sequence),))

    def prove_page(self, page: LedgerPage) -> LedgerMembershipBundle:
        """Prove only exact page receipts, not its predicate or completeness metadata."""
        if type(page) is not LedgerPage:
            raise ValidationError("page proof requires LedgerPage")
        if (page.head_digest, page.snapshot_entries) != (
            self.commitment.head_digest,
            self.commitment.entry_count,
        ):
            raise ValidationError("page and proof index refer to different prefixes")
        if not page.entries:
            raise ValidationError("empty pages have no membership proof")
        for entry in page.entries:
            _count(entry.sequence, "page sequence", self.commitment.entry_count - 1)
            if _receipt_bytes(entry) != _receipt_bytes(self.index.ledger.entries[entry.sequence]):
                raise ValidationError("page receipt differs from the verified prefix")
        return LedgerMembershipBundle(
            self.commitment, tuple(self._member(entry.sequence) for entry in page.entries)
        )


__all__ = [
    "LedgerCommitment",
    "LedgerMemberProof",
    "LedgerMembershipBundle",
    "LedgerProofIndex",
    "verify_ledger_membership",
]
