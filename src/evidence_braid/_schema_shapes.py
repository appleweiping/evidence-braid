"""Original structural wire profiles; native semantic validators remain separate.

The compact definitions below generate packaged static resources. Enum values
and established count bounds come from the existing models, not example data.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .authority import (
    MAX_WORKFLOW_ARTIFACTS,
    MAX_WORKFLOW_RECORDS,
    ActorKind,
    AuthorityRole,
    WorkflowAction,
)
from .consistency import _MAX_PATH
from .ledger import MAX_LEDGER_ENTRIES
from .membership import _MAX_MEMBERS, _MAX_SIBLINGS
from .models import Modality, Signal

PUBLICATION_LINE = "wire-1"
DIALECT = "https://json-schema.org/draft/2020-12/schema"
ID_PREFIX = f"urn:evidence-braid:schemas:{PUBLICATION_LINE}:"
PUBLIC_SCHEMAS = {
    "evidence-event": "EvidenceEvent",
    "evidence-ledger": "EvidenceLedger",
    "authority-policy": "AuthorityPolicy",
    "workflow-bundle": "WorkflowBundle",
    "ledger-commitment": "LedgerCommitment",
    "ledger-membership": "LedgerMembershipBundle",
    "ledger-consistency": "LedgerConsistencyProof",
}


def _ref(name: str) -> dict[str, Any]:
    return {"$ref": f"{ID_PREFIX}common#/$defs/{name}"}


def _object(properties: dict[str, Any], *, optional: tuple[str, ...] = ()) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": sorted(set(properties) - set(optional)),
        "additionalProperties": False,
    }


def _array(item: dict[str, Any], maximum: int, minimum: int = 0) -> dict[str, Any]:
    return {"type": "array", "items": item, "minItems": minimum, "maxItems": maximum}


def _count(maximum: int, minimum: int = 0) -> dict[str, Any]:
    return {"type": "integer", "minimum": minimum, "maximum": maximum}


def definitions() -> dict[str, Any]:
    """Return fresh shared shapes, not validators for hashes, authority or replay."""
    text = {"type": "string", "minLength": 1}
    identifier = {
        "type": "string",
        "minLength": 1,
        "maxLength": 128,
        "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$",
    }
    digest = {"type": "string", "minLength": 64, "maxLength": 64, "pattern": "^[0-9a-f]+$"}
    version = {"const": "1.0"}
    timestamp = {
        "type": "string",
        "pattern": r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{6})?Z$",
        "format": "date-time",
    }
    result: dict[str, Any] = {
        "JsonValue": {
            "anyOf": [
                {"type": ["string", "number", "boolean", "null"]},
                {"type": "array", "items": _ref("JsonValue")},
                {"type": "object", "additionalProperties": _ref("JsonValue")},
            ],
            "$comment": (
                "Native parsing separately bounds depth/nodes/integer digits "
                "and rejects nonfinite numbers."
            ),
        },
        "EvidenceEvent": _object(
            {
                "event_id": text,
                "claim": text,
                "modality": {"enum": [item.value for item in Modality]},
                "source": text,
                "signal": {"enum": [item.value for item in Signal]},
                "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                "observed_at": timestamp,
                "ingested_at": timestamp,
                "correlation_group": text,
                "attributes": {
                    "type": "object",
                    "minProperties": 1,
                    "additionalProperties": _ref("JsonValue"),
                },
            },
            optional=("correlation_group", "attributes"),
        ),
        "LedgerEntry": _object(
            {
                "sequence": _count(MAX_LEDGER_ENTRIES - 1),
                "event_id": text,
                "event": _ref("EvidenceEvent"),
                "previous_digest": digest,
                "digest": digest,
            }
        ),
        "EvidenceLedger": _object(
            {
                "schema_version": {"enum": ["1.0", "2.0"]},
                "kind": {"const": "evidence-braid-ledger"},
                "genesis": digest,
                "head_digest": digest,
                "entry_count": _count(MAX_LEDGER_ENTRIES),
                "entries": _array(_ref("LedgerEntry"), MAX_LEDGER_ENTRIES),
                "verified": {"const": True},
            }
        ),
        "ScopeGrant": _object(
            {"scope": identifier, "role": {"enum": [item.value for item in AuthorityRole]}}
        ),
        "WorkflowActor": _object(
            {
                "actor_id": identifier,
                "kind": {"enum": [item.value for item in ActorKind]},
                "grants": {**_array(_ref("ScopeGrant"), 128, 1), "uniqueItems": True},
            }
        ),
        "AuthorityPolicy": _object(
            {
                "schema_version": version,
                "kind": {"const": "evidence-braid-authority"},
                "policy_id": identifier,
                "approval_quorum": _count(16, 1),
                "actors": _array(_ref("WorkflowActor"), 256, 1),
            }
        ),
        "ArtifactReference": _object(
            {
                "artifact_id": identifier,
                "scope": identifier,
                "claim_id": identifier,
                "sha256": digest,
                "size_bytes": _count(64 * 1024 * 1024),
                "media_type": {**text, "maxLength": 128},
            }
        ),
        "WorkflowTransition": _object(
            {
                "transition_id": identifier,
                "action": {"enum": [item.value for item in WorkflowAction]},
                "actor_id": identifier,
                "scope": identifier,
                "claim_id": identifier,
                "expected_revision": _count(MAX_WORKFLOW_RECORDS),
                "statement": {"type": ["string", "null"], "minLength": 1, "maxLength": 8192},
                "reference_id": {"anyOf": [identifier, {"type": "null"}]},
                "reference_digest": {"anyOf": [digest, {"type": "null"}]},
                "reason": {"type": ["string", "null"], "minLength": 1, "maxLength": 8192},
            }
        ),
        "WorkflowReceipt": _object(
            {
                "schema_version": version,
                "sequence": _count(MAX_WORKFLOW_RECORDS - 1),
                "context_digest": digest,
                "previous_digest": digest,
                "transition": _ref("WorkflowTransition"),
                "digest": digest,
            }
        ),
        "WorkflowBundle": _object(
            {
                "kind": {"const": "evidence-braid-workflow-bundle"},
                "schema_version": version,
                "workflow_id": identifier,
                "authority_digest": digest,
                "evidence": _ref("EvidenceLedger"),
                "artifacts": _array(_ref("ArtifactReference"), MAX_WORKFLOW_ARTIFACTS),
                "context_digest": digest,
                "head_digest": digest,
                "record_count": _count(MAX_WORKFLOW_RECORDS),
                "records": _array(_ref("WorkflowReceipt"), MAX_WORKFLOW_RECORDS),
            }
        ),
        "LedgerCommitment": _object(
            {
                "kind": {"const": "evidence-braid-ledger-commitment"},
                "schema_version": version,
                "ledger_version": {"enum": ["1.0", "2.0"]},
                "genesis": digest,
                "head_digest": digest,
                "entry_count": _count(MAX_LEDGER_ENTRIES),
                "root_hash": digest,
                "commitment_digest": digest,
            }
        ),
        "LedgerMemberProof": _object(
            {"entry": _ref("LedgerEntry"), "siblings": _array(digest, _MAX_SIBLINGS)}
        ),
        "LedgerMembershipBundle": _object(
            {
                "kind": {"const": "evidence-braid-ledger-membership"},
                "schema_version": version,
                "commitment": _ref("LedgerCommitment"),
                "members": _array(_ref("LedgerMemberProof"), _MAX_MEMBERS, 1),
            }
        ),
        "LedgerConsistencyProof": _object(
            {
                "kind": {"const": "evidence-braid-ledger-consistency"},
                "schema_version": version,
                "old_commitment": _ref("LedgerCommitment"),
                "new_commitment": _ref("LedgerCommitment"),
                "path": _array(digest, _MAX_PATH),
            }
        ),
    }
    conditions = []
    for action in WorkflowAction:
        properties: dict[str, Any] = {
            "statement": {"type": "string"}
            if action is WorkflowAction.CREATE
            else {"type": "null"},
            "reason": {"type": "string"}
            if action in (WorkflowAction.REJECT, WorkflowAction.REVOKE)
            else {"type": "null"},
        }
        binding = action in (WorkflowAction.BIND_EVIDENCE, WorkflowAction.BIND_ARTIFACT)
        properties["reference_id"] = identifier if binding else {"type": "null"}
        properties["reference_digest"] = digest if binding else {"type": "null"}
        conditions.append(
            {
                "if": {"properties": {"action": {"const": action.value}}},
                "then": {"properties": properties},
            }
        )
    result["WorkflowTransition"]["allOf"] = conditions
    return result


def _encode(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def generated_resources() -> dict[str, bytes]:
    """Produce the complete deterministic publication tree for drift checking."""
    schemas = {"common": {"$defs": definitions()}}
    schemas.update({name: _ref(definition) for name, definition in PUBLIC_SCHEMAS.items()})
    files: dict[str, bytes] = {}
    inventory = []
    for name, shape in sorted(schemas.items()):
        path = f"{PUBLICATION_LINE}/{name}.schema.json"
        schema_id = f"{ID_PREFIX}{name}"
        title = f"Evidence Braid {name} structural wire profile"
        raw = _encode({"$schema": DIALECT, "$id": schema_id, "title": title, **shape})
        files[path] = raw
        inventory.append(
            {
                "name": name,
                "path": path,
                "schema_id": schema_id,
                "title": title,
                "size_bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "public": name in PUBLIC_SCHEMAS,
            }
        )
    files[f"{PUBLICATION_LINE}/catalog.json"] = _encode(
        {
            "kind": "evidence-braid-schema-catalog",
            "schema_version": "1.0",
            "publication_line": PUBLICATION_LINE,
            "dialect": DIALECT,
            "schemas": inventory,
        }
    )
    files[f"{PUBLICATION_LINE}/SHA256SUMS"] = "".join(
        f"{hashlib.sha256(raw).hexdigest()}  {path}\n" for path, raw in sorted(files.items())
    ).encode("ascii")
    return files
