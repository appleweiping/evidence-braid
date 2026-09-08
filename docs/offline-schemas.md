# Offline structural schema catalog

The `wire-1` publication contains seven **structural wire profiles**, one shared
definitions resource, `catalog.json` and `SHA256SUMS`. The files ship in both the
wheel and source distribution; no package index, HTTP request or validator
dependency is needed to inspect or export them. This is an original Evidence
Braid format, not a claim of another protocol's wire compatibility.

## Published entry points

| Schema name | Existing canonical wire producer |
|---|---|
| `evidence-event` | `EvidenceEvent.to_dict()` |
| `evidence-ledger` | `EvidenceLedger.to_dict()`; strict v1 and v2 ledgers |
| `authority-policy` | `AuthorityPolicy.to_dict()` |
| `workflow-bundle` | `WorkflowBundle.to_dict()` |
| `ledger-commitment` | `LedgerCommitment.to_dict()` |
| `ledger-membership` | `LedgerMembershipBundle.to_dict()` |
| `ledger-consistency` | `LedgerConsistencyProof.to_dict()` |

Each `$id` is `urn:evidence-braid:schemas:wire-1:<name>`. The `common` resource
contains reusable records and recursive JSON attribute definitions; it is not
a separate application envelope. These IDs are opaque names, not downloadable
URLs. Every reference resolves inside this exact eight-resource registry.
The dialect is JSON Schema Draft 2020-12. Empty event attributes and absent
correlation groups follow the canonical serializer's omitted-field form.
Other native inputs, policy migrations, reports and artifact ZIP manifests are
not covered by these seven profiles.

These are canonical **serialized output** profiles, not the complete set of
inputs accepted by each native parser. For example, the event parser accepts
empty `attributes: {}` but its serializer omits that field. A valid serialized
ledger has `verified: true`; the schema checks this literal output marker only,
not the cryptographic relationship it describes. An attacker can write the same
marker, so independent ledger verification is still mandatory.

The catalog records exact relative paths, `$id`s, titles, public/support status,
byte sizes and lowercase SHA-256 digests. Its own digest is pinned in the library;
`SHA256SUMS` covers the catalog and all eight schemas without a self-referential
hash. Loading any resource verifies the **whole** publication, strict JSON,
identities, reference closure and checksums. Hand-constructing `PublishedSchema`,
`SchemaCatalog` or `SchemaExport` creates validated metadata, not a verification
certificate or authenticated publisher identity.

## API and CLI

```python
from evidence_braid import (
    export_schemas,
    load_schema_catalog,
    schema_bytes,
    schema_registry,
    verify_schema_archive,
)

catalog = load_schema_catalog()
event_schema_bytes = schema_bytes("evidence-event")
registry_documents = schema_registry()
published = export_schemas("schemas.zip")  # parent directory must already exist
checked = verify_schema_archive(
    "schemas.zip",
    expected_catalog_digest=catalog.digest,
)
assert checked.archive_sha256 == published.archive_sha256
```

In a real exchange, select the expected catalog digest from a **separately
trusted publication**, not from the archive being checked. The example above
demonstrates matching the installed release, not independent trust. A compromised
installation can change both code and pins; the catalog is not a signature.

```sh
evidence-braid schema catalog
evidence-braid schema show ledger-consistency
evidence-braid schema export schemas.zip
evidence-braid schema verify schemas.zip --expected-catalog-digest <trusted-digest>
python examples/offline_schemas.py
```

The executable example exports a real archive, renames it and verifies it in a
fresh process outside the checkout. Names passed to `schema_bytes` are from the
closed inventory: arbitrary paths and URLs are rejected. The registry's outer
mapping is read-only; each call owns fresh nested JSON dictionaries that a caller
may adapt without modifying the next call or the installed publication.

## Independent validator, fully offline

`jsonschema` is a development/test extra, **not** a runtime dependency. With that
extra installed, preload every resource and explicitly refuse retrieval:

```python
import json
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.exceptions import NoSuchResource
from evidence_braid import schema_bytes, schema_registry


def refuse(uri):
    raise NoSuchResource(ref=uri)


registry = Registry(retrieve=refuse).with_resources(
    (uri, Resource.from_contents(document)) for uri, document in schema_registry().items()
)
validator = Draft202012Validator(
    json.loads(schema_bytes("workflow-bundle")),
    registry=registry,
)
# validator.validate(bundle.to_dict()) performs structural checks only.
```

The independent tests validate real native event, authority, receipt and proof
outputs, v1/v2 ledgers, Unicode, large integers and optional fields. Missing,
extra, mistyped and action-inappropriate fields fail structural validation.
Serializer-field and generated-byte checks catch drift in shared definitions.
The library itself does not implement or silently invoke a JSON Schema engine.

## Structure is not a semantic verdict

A structurally valid document may still be invalid or unauthorized. Always run
the native parser and the corresponding externally anchored verifier/replay:

- `EvidenceEvent.from_dict` enforces canonical text, timestamp semantics and
  bounded finite attributes; ledger parsing checks chain/count/event bindings.
- `WorkflowBundle.from_dict(..., authority=trusted_policy)` checks authority,
  exact scopes, revision order, state preconditions and evidence/artifact binds.
- Membership and consistency verification require separately selected commitment
  digests and recompute the relevant Merkle relationships.

Tests deliberately rehash unauthorized or cross-scope workflow receipts:
they pass schema validation and fail native authorization. Altered derived
counts and proof siblings also pass structure but fail native verification.
Actor declarations, procedural approval and hashes never establish claim truth.

JSON Schema operates on parsed values. It cannot reject duplicate JSON fields
already discarded by a permissive parser or enforce raw canonical spelling.
Its `integer` means a mathematical integer, so a decoded `1.0` can validate even
where the native API requires an exact integer. `format` is an annotation unless
the consumer opts into a compatible format checker; timestamp calendar validity
still needs native parsing. Unicode XML/text canonicalization, finite-number
handling, attribute depth/node/number-digit limits and byte limits remain native
responsibilities. A schema-valid array count is not proof of cross-record counts,
uniqueness of IDs, replay permission or valid digests.

## Bounded single-file publication

Export uses one deterministic **STORED ZIP32** profile: ten fixed sorted ASCII
file names, fixed 1980 timestamp, CRC32 and sizes, no compression, data
descriptors, encryption, directories, extra fields, comments, trailing bytes or
ZIP64. It writes through the existing same-directory staged-output helper,
checks the complete staging file independently, flushes/fsyncs/closes, then
publishes with an atomic no-replace hard link. An existing destination is never
overwritten; competing writers have exactly one winner. Unsupported hard links
fail closed without a copy/overwrite fallback. Ordinary prepublication failure
or interruption cleans staging and preserves the destination. Rare cleanup
failure after publication is reported truthfully by the atomic helper.

Verification supports **only the installed, pinned publication**. It reads at
most 266,241 bytes and compares against the complete expected ZIP byte sequence;
it never asks a general ZIP parser to materialize untrusted central-directory
counts or extracts files. Independent tests use the standard ZIP reader to check
interoperability, including every member's CRC and content. Valid but differently
encoded ZIPs, unknown schemas and future publication lines are refused, not
silently imported. The exported ZIP's current size is reported by the example;
the limits are 64 KiB per schema, 8 KiB catalog, 4 KiB checksum inventory,
256 KiB for all resources together, and 260 KiB for the complete archive.

These are payload/file bounds, not a process-RSS or CPU sandbox: JSON objects and
multiple bounded byte buffers are materialized. A caller-supplied pathological
schema or unbounded application document is not evaluated by this API. Filesystem
I/O, native filesystem behavior and process interruption are not hard real-time
guarantees; hostile same-user filesystem mutation is outside the trust model.
Directory metadata power-loss durability is not promised. **Atomic directory
export remains open**; this single-file exchange does not implement it.

## Publication and maintenance

`_schema_shapes.generated_resources()` deterministically derives compact static
files from shared definitions, existing enum values and established count
constants. Tests compare all generated bytes with committed package resources;
do not hand-edit generated schemas or relax a drift test to conceal disagreement.
An intentional new publication requires reviewed source definitions, regenerated
resources, a reviewed catalog pin and fresh independent positive/negative
fixtures. Published `wire-1` bytes and IDs must remain immutable; an incompatible
or otherwise byte-changing revision needs a new publication line alongside its
own digests. Loading archived older lines or extending this initial registry is
not implemented merely by retaining an old ZIP. The containing package version
is separate from schema publication and wire-record versions.

CI builds both distributions, inspects their complete schema resource sets and
runs the ZIP example from an isolated installed wheel without `jsonschema`.
The unit suite independently validates all schemas with `Draft202012Validator`.
Neither source line counts nor these schema profiles close the broader
[whole-repository parity ledger](parity-ledger.md).
