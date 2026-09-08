"""Detached prefix consistency between two independently retained commitments.

This proves receipt-tree prefix equality, not source identity, durable storage,
or independent validation of every undisclosed newly appended chain link.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from .errors import ValidationError
from .io import _reject_constant, _reject_duplicate_keys
from .ledger import MAX_LEDGER_ENTRIES, _hash
from .membership import (
    _HEADER_FIELDS,
    LedgerCommitment,
    LedgerProofIndex,
    _canonical,
    _Node,
    _node_hash,
)

_KIND = "evidence-braid-ledger-consistency"
_VERSION = "1.0"
_FIELDS = {"kind", "schema_version", "old_commitment", "new_commitment", "path"}
_MAX_PATH = 18
_MAX_BYTES = 4096


def _object(value: Any, fields: set[str]) -> dict[str, Any]:
    # Exact cardinality first: do not traverse a caller-owned huge/wide graph.
    if (
        type(value) is not dict
        or len(value) != len(fields)
        or any(type(key) is not str for key in value)
        or set(value) != fields
    ):
        raise ValidationError("consistency object has an invalid field set")
    return value


def _shape(value: Any) -> dict[str, Any]:
    """Closed shape admission before header construction or serialization.

    The exact grammar permits at most 61 graph nodes, counting object keys,
    and two containers of depth. No arbitrary receipt graphs are present.
    """
    data = _object(value, _FIELDS)
    if (
        type(data["kind"]) is not str
        or data["kind"] != _KIND
        or type(data["schema_version"]) is not str
        or data["schema_version"] != _VERSION
    ):
        raise ValidationError("unsupported consistency proof format")
    path = data["path"]
    if type(path) is not list or len(path) > _MAX_PATH:
        raise ValidationError("consistency path must contain at most 18 hashes")
    for item in path:
        _hash(item, "consistency path hash")
    for name in ("old_commitment", "new_commitment"):
        header = _object(data[name], _HEADER_FIELDS)
        for key, item in header.items():
            if key == "entry_count":
                if type(item) is not int or not 0 <= item <= MAX_LEDGER_ENTRIES:
                    raise ValidationError("consistency count exceeds ledger bounds")
            elif type(item) is not str or len(item) > 64:
                raise ValidationError("consistency header fields must be bounded text")
    return data


def _admit_bytes(raw: bytes) -> None:
    if type(raw) is not bytes or len(raw) > _MAX_BYTES:
        raise ValidationError("consistency input must be bytes within 4096 bytes")
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
            if depth > 2:
                raise ValidationError("consistency JSON exceeds two container levels")
        elif byte in (93, 125):
            depth -= 1


def _integer(literal: str) -> int:
    if len(literal.removeprefix("-")) > 6:
        raise ValueError("consistency count exceeds six decimal digits")
    return int(literal)


def _headers(old: LedgerCommitment, new: LedgerCommitment) -> None:
    if type(old) is not LedgerCommitment or type(new) is not LedgerCommitment:
        raise ValidationError("consistency requires two immutable LedgerCommitment headers")
    if (old.ledger_version, old.genesis) != (new.ledger_version, new.genesis):
        raise ValidationError("consistency headers use different ledger versions or genesis")
    if old.entry_count > new.entry_count:
        raise ValidationError("consistency cannot decrease the committed count")
    if old.entry_count == new.entry_count and old != new:
        raise ValidationError("equal counts require identical complete commitment headers")


def _path_size(old: int, new: int, known: bool = True) -> int:
    if old == 0:
        return 0
    if old == new:
        return 0 if known else 1
    split = 1 << ((new - 1).bit_length() - 1)
    return 1 + (
        _path_size(old, split, known)
        if old <= split
        else _path_size(old - split, new - split, False)
    )


@dataclass(frozen=True, slots=True)
class LedgerConsistencyProof:
    """Bounded structure only; verification requires two separate expected digests."""

    old_commitment: LedgerCommitment
    new_commitment: LedgerCommitment
    path: tuple[str, ...]

    def __post_init__(self) -> None:
        _headers(self.old_commitment, self.new_commitment)
        if type(self.path) is not tuple or len(self.path) > _MAX_PATH:
            raise ValidationError(
                "consistency path requires an immutable tuple of at most 18 hashes"
            )
        if len(self.path) != _path_size(
            self.old_commitment.entry_count, self.new_commitment.entry_count
        ):
            raise ValidationError("consistency path length disagrees with committed tree sizes")
        for item in self.path:
            _hash(item, "consistency path hash")

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": _KIND,
            "schema_version": _VERSION,
            "old_commitment": self.old_commitment.to_dict(),
            "new_commitment": self.new_commitment.to_dict(),
            "path": list(self.path),
        }

    def to_bytes(self) -> bytes:
        data = _shape(self.to_dict())
        raw = _canonical(data)
        if len(raw) > _MAX_BYTES:
            raise ValidationError("consistency proof exceeds 4096 bytes")
        return raw

    @classmethod
    def from_dict(cls, value: Any) -> LedgerConsistencyProof:
        data = _shape(value)
        result = cls(
            LedgerCommitment.from_dict(data["old_commitment"]),
            LedgerCommitment.from_dict(data["new_commitment"]),
            tuple(data["path"]),
        )
        result.to_bytes()
        return result

    @classmethod
    def from_bytes(cls, raw: bytes) -> LedgerConsistencyProof:
        _admit_bytes(raw)
        try:
            data = json.loads(
                raw.decode("utf-8"),
                parse_int=_integer,
                parse_float=_reject_constant,
                parse_constant=_reject_constant,
                object_pairs_hook=_reject_duplicate_keys,
            )
            result = cls.from_dict(data)
            if result.to_bytes() != raw:
                raise ValidationError("consistency proof is not canonical UTF-8 JSON")
            return result
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise ValidationError("invalid canonical consistency JSON") from exc


def _children(tree: _Node) -> tuple[_Node, _Node]:
    if tree.left is None or tree.right is None:  # Private cached-tree invariant.
        raise RuntimeError("consistency tree has an incomplete internal node")
    return tree.left, tree.right


def _prefix_root(tree: _Node, count: int) -> str:
    if count == tree.count:
        return tree.digest
    left, right = _children(tree)
    if count <= left.count:
        return _prefix_root(left, count)
    return _node_hash(left.digest, _prefix_root(right, count - left.count))


def _subproof(tree: _Node, count: int, known: bool, path: list[str]) -> None:
    if count == tree.count:
        if not known:
            path.append(tree.digest)
        return
    left, right = _children(tree)
    if count <= left.count:
        _subproof(left, count, known, path)
        path.append(right.digest)
    else:
        _subproof(right, count - left.count, False, path)
        path.append(left.digest)


def prove_ledger_consistency(
    new_index: LedgerProofIndex, old_commitment: LedgerCommitment
) -> LedgerConsistencyProof:
    """Prove a retained prefix after checking its real head/root in a verified index."""
    if type(new_index) is not LedgerProofIndex:
        raise ValidationError("consistency generation requires a verified LedgerProofIndex")
    _headers(old_commitment, new_index.commitment)
    count = old_commitment.entry_count
    path: list[str] = []
    if count:
        tree = new_index._tree
        if tree is None:  # Private cached-tree invariant.
            raise RuntimeError("nonempty consistency index has no tree")
        if new_index.index.ledger.entries[count - 1].digest != old_commitment.head_digest:
            raise ValidationError("old commitment head differs from the actual indexed prefix")
        if _prefix_root(tree, count) != old_commitment.root_hash:
            raise ValidationError("old commitment root differs from the actual indexed prefix")
        _subproof(tree, count, True, path)
    return LedgerConsistencyProof(old_commitment, new_index.commitment, tuple(path))


def _recover(
    old: int, new: int, known: bool, old_root: str, hashes: Iterator[str]
) -> tuple[str, str]:
    if old == new:
        root = old_root if known else next(hashes)
        return root, root
    split = 1 << ((new - 1).bit_length() - 1)
    if old <= split:
        before, after = _recover(old, split, known, old_root, hashes)
        return before, _node_hash(after, next(hashes))
    before, after = _recover(old - split, new - split, False, old_root, hashes)
    sibling = next(hashes)
    return _node_hash(sibling, before), _node_hash(sibling, after)


def verify_ledger_consistency(
    proof: LedgerConsistencyProof,
    *,
    expected_old_commitment_digest: str,
    expected_new_commitment_digest: str,
) -> None:
    """Verify receipt-tree prefix equality under two separately retained anchors.

    Empty-prefix consistency is vacuous. No hidden new chain links, durable
    commits, authenticated identities or global non-equivocation are attested.
    """
    _hash(expected_old_commitment_digest, "expected_old_commitment_digest")
    _hash(expected_new_commitment_digest, "expected_new_commitment_digest")
    if type(proof) is not LedgerConsistencyProof:
        raise ValidationError("consistency verification requires LedgerConsistencyProof")
    old, new = proof.old_commitment, proof.new_commitment
    if old.digest != expected_old_commitment_digest or new.digest != expected_new_commitment_digest:
        raise ValidationError("consistency commitment differs from an expected external anchor")
    if old.entry_count == 0 or old.entry_count == new.entry_count:
        return
    hashes = iter(proof.path)
    recovered = _recover(old.entry_count, new.entry_count, True, old.root_hash, hashes)
    if recovered != (old.root_hash, new.root_hash) or next(hashes, None) is not None:
        raise ValidationError("consistency path does not reproduce both committed roots")


__all__ = ["LedgerConsistencyProof", "prove_ledger_consistency", "verify_ledger_consistency"]
