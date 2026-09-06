"""Ordered, explicit upgrades between policy schema versions.

A stored policy outlives the release that wrote it. Refusing an older document
would make every schema change a coordinated rewrite of every operator's files,
and quietly reinterpreting one would change decisions without saying so. This
module does the third thing: it upgrades a document one version at a time and
reports every field it added.

Two rules keep that honest.

A migration only ever writes down, explicitly, the behaviour the older version
already had. It never guesses what an operator would have wanted from a
capability that did not exist when they wrote the file. When schema 1 had no way
to require a modality, the faithful reading of a schema 1 policy is "no modality
is required", so that is what the upgrade writes.

A migration is therefore decision-preserving by construction, and
``tests/test_migrations.py`` checks it rather than trusting it: evaluating a
migrated policy must produce the byte-identical result the original produced.
Any future migration that cannot make that promise belongs in a major release
with a migration note, not here.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .errors import ValidationError

# The schema this build reads and writes. `Policy` objects always carry this
# version; `Policy.source_schema_version` records where the document came from.
CURRENT_POLICY_SCHEMA_VERSION = 2

# The oldest document this build can still upgrade.
EARLIEST_POLICY_SCHEMA_VERSION = 1


@dataclass(frozen=True, slots=True)
class MigrationNote:
    """One field an upgrade added, and the reading that justified it."""

    path: str
    change: str

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "change": self.change}


@dataclass(frozen=True, slots=True)
class MigrationReport:
    """What an upgrade did, in enough detail to review before adopting it."""

    from_version: int
    to_version: int
    notes: tuple[MigrationNote, ...] = ()

    @property
    def migrated(self) -> bool:
        """Whether the document needed any change at all."""

        return self.from_version != self.to_version

    def to_dict(self) -> dict[str, Any]:
        return {
            "from_version": self.from_version,
            "to_version": self.to_version,
            "migrated": self.migrated,
            "notes": [note.to_dict() for note in self.notes],
        }


def policy_schema_version(raw: Any) -> int:
    """Read and bound a policy document's declared schema version.

    The version is read before anything else in the document is trusted, because
    which fields are even allowed depends on it.
    """

    if not isinstance(raw, Mapping):
        raise ValidationError("policy must be a JSON object")
    version = raw.get("schema_version")
    if type(version) is not int:
        raise ValidationError("policy.schema_version must be an integer")
    if version < EARLIEST_POLICY_SCHEMA_VERSION:
        raise ValidationError(
            f"policy.schema_version {version} is older than the earliest supported "
            f"version {EARLIEST_POLICY_SCHEMA_VERSION}"
        )
    if version > CURRENT_POLICY_SCHEMA_VERSION:
        raise ValidationError(
            f"policy.schema_version {version} is newer than this build understands "
            f"(schema {CURRENT_POLICY_SCHEMA_VERSION}); upgrade evidence-braid rather "
            f"than downgrading the policy"
        )
    return version


def _claims(document: Mapping[str, Any]) -> Mapping[str, Any]:
    claims = document.get("claims")
    if not isinstance(claims, Mapping):
        raise ValidationError("policy.claims must be a JSON object")
    return claims


def _upgrade_1_to_2(document: dict[str, Any]) -> tuple[dict[str, Any], list[MigrationNote]]:
    """Add the modality requirement schema 1 could not express.

    Schema 1 counted distinct modalities with ``min_modalities`` but could not
    say *which* ones, so a claim needing corroboration from a camera could only
    ask for two of anything. Schema 2 adds ``required_modalities``. An empty list
    is the only faithful upgrade of a schema 1 claim: the older document made no
    such demand, and inventing one here would change a decision.
    """

    notes: list[MigrationNote] = []
    claims = dict(_claims(document))
    for name in sorted(claims):
        rule = claims[name]
        if not isinstance(rule, Mapping):
            raise ValidationError(f"policy.claims.{name} must be a JSON object")
        if "required_modalities" in rule:
            raise ValidationError(
                f"policy.claims.{name}.required_modalities is not part of schema 1; "
                f"declare schema_version 2 to use it"
            )
        upgraded = dict(rule)
        upgraded["required_modalities"] = []
        claims[name] = upgraded
        notes.append(
            MigrationNote(
                path=f"policy.claims.{name}.required_modalities",
                change="added [] because schema 1 could not require a modality",
            )
        )
    document["claims"] = claims
    document["schema_version"] = 2
    return document, notes


_UPGRADES: Mapping[int, Callable[[dict[str, Any]], tuple[dict[str, Any], list[MigrationNote]]]] = {
    1: _upgrade_1_to_2,
}


def migrate_policy_document(raw: Any) -> tuple[dict[str, Any], MigrationReport]:
    """Upgrade a policy document to the current schema and report every change.

    The input is not modified. The returned document is a plain JSON structure,
    ready to be validated by :meth:`Policy.from_dict` or written back to disk.
    """

    if not isinstance(raw, Mapping):
        raise ValidationError("policy must be a JSON object")
    from_version = policy_schema_version(raw)
    document: dict[str, Any] = dict(raw)
    notes: list[MigrationNote] = []
    version = from_version
    while version < CURRENT_POLICY_SCHEMA_VERSION:
        upgrade = _UPGRADES.get(version)
        if upgrade is None:  # pragma: no cover - a gap would be a packaging error
            raise ValidationError(f"no upgrade is registered from policy schema {version}")
        document, step_notes = upgrade(document)
        notes.extend(step_notes)
        version += 1
    return document, MigrationReport(
        from_version=from_version, to_version=version, notes=tuple(notes)
    )


__all__ = [
    "CURRENT_POLICY_SCHEMA_VERSION",
    "EARLIEST_POLICY_SCHEMA_VERSION",
    "MigrationNote",
    "MigrationReport",
    "migrate_policy_document",
    "policy_schema_version",
]
