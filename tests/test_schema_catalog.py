"""Offline structural interoperability, distinct from native semantic verdicts."""

from __future__ import annotations

import hashlib
import io
import json
import socket
import subprocess
import sys
import tarfile
import zipfile
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from pathlib import Path
from threading import Barrier

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.exceptions import NoSuchResource

from evidence_braid import (
    ActorKind,
    ArtifactReference,
    AuthorityPolicy,
    AuthorityRole,
    EvidenceEvent,
    EvidenceLedger,
    InputFormatError,
    LedgerCommitment,
    LedgerConsistencyProof,
    LedgerEntry,
    LedgerIndex,
    LedgerMembershipBundle,
    LedgerProofIndex,
    Modality,
    PublishedSchema,
    SchemaCatalog,
    SchemaExport,
    ScopeGrant,
    Signal,
    ValidationError,
    WorkflowAction,
    WorkflowActor,
    WorkflowBundle,
    WorkflowTransition,
    build_ledger,
    build_workflow,
    export_schemas,
    load_schema_catalog,
    prove_ledger_consistency,
    schema_bytes,
    schema_registry,
    verify_ledger_consistency,
    verify_ledger_membership,
    verify_schema_archive,
)
from evidence_braid import schema_catalog as module
from evidence_braid._schema_shapes import PUBLIC_SCHEMAS, definitions, generated_resources
from evidence_braid.cli import run

BASE = datetime(2026, 9, 7, tzinfo=UTC)
ZERO = "0" * 64


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def event(number=0, **extra):
    return EvidenceEvent(
        str(number),
        "incident",
        Modality.TEXT,
        "instrument",
        Signal.SUPPORT,
        0.7,
        BASE,
        BASE,
        attributes={"workflow_scope": "lab", **extra},
    )


def proof_index(ledger):
    return LedgerProofIndex(LedgerIndex(ledger, expected_head=ledger.head_digest))


def workflow():
    authority = AuthorityPolicy(
        "review",
        (
            WorkflowActor("alice", ActorKind.HUMAN, (ScopeGrant("lab", AuthorityRole.AUTHOR),)),
            WorkflowActor("bob", ActorKind.HUMAN, (ScopeGrant("lab", AuthorityRole.REVIEWER),)),
        ),
    )
    ledger = build_ledger([event(integer=10**300, text="来源🔬", float=1e-20)])
    artifact = ArtifactReference(
        "report", "lab", "incident", hashlib.sha256(b"proof").hexdigest(), 5, "text/plain"
    )
    base = build_workflow("workflow", authority=authority, evidence=ledger, artifacts=(artifact,))
    steps = (
        WorkflowTransition(
            "create",
            WorkflowAction.CREATE,
            "alice",
            "lab",
            "incident",
            0,
            statement="Observed problem",
        ),
        WorkflowTransition(
            "evidence",
            WorkflowAction.BIND_EVIDENCE,
            "alice",
            "lab",
            "incident",
            1,
            reference_id="0",
            reference_digest=ledger.head_digest,
        ),
        WorkflowTransition(
            "artifact",
            WorkflowAction.BIND_ARTIFACT,
            "alice",
            "lab",
            "incident",
            2,
            reference_id="report",
            reference_digest=artifact.sha256,
        ),
        WorkflowTransition("submit", WorkflowAction.SUBMIT, "alice", "lab", "incident", 3),
        WorkflowTransition("approve", WorkflowAction.APPROVE, "bob", "lab", "incident", 4),
    )
    return authority, base.append(steps, authority=authority)


def examples():
    authority, bundle = workflow()
    ledger = bundle.evidence
    index = proof_index(ledger)
    old = proof_index(build_ledger([]))
    return {
        "evidence-event": ledger.entries[0].to_dict()["event"],
        "evidence-ledger": ledger.to_dict(),
        "authority-policy": authority.to_dict(),
        "workflow-bundle": bundle.to_dict(),
        "ledger-commitment": index.commitment.to_dict(),
        "ledger-membership": index.prove(0).to_dict(),
        "ledger-consistency": prove_ledger_consistency(index, old.commitment).to_dict(),
    }


def validator(name):
    documents = schema_registry()

    def refuse(uri):
        raise NoSuchResource(ref=uri)

    registry = Registry(retrieve=refuse).with_resources(
        (uri, Resource.from_contents(document)) for uri, document in documents.items()
    )
    return Draft202012Validator(json.loads(schema_bytes(name)), registry=registry)


def test_catalog_is_closed_pinned_immutable_and_generated_bytes_do_not_drift():
    catalog = load_schema_catalog()
    resources = generated_resources()
    assert (
        len(catalog.schemas) == 8 and sum(item.to_dict()["public"] for item in catalog.schemas) == 7
    )
    assert catalog.digest == module._CATALOG_SHA256
    assert catalog.total_schema_bytes == sum(item.size_bytes for item in catalog.schemas)
    for path, expected in resources.items():
        assert module._resource(path, module.MAX_SCHEMA_FILE_BYTES) == expected
    assert len(resources) == 10
    with pytest.raises(FrozenInstanceError):
        catalog.schemas = ()
    with pytest.raises(FrozenInstanceError):
        catalog.schemas[0].sha256 = ZERO


def test_all_schemas_compile_and_real_profiles_validate_with_no_network(monkeypatch):
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: pytest.fail("network used"))
    for document in schema_registry().values():
        Draft202012Validator.check_schema(document)
    for name, document in examples().items():
        validator(name).validate(document)


def test_schema_fields_track_actual_serializers_including_shared_nested_contracts():
    authority, bundle = workflow()
    shapes = definitions()
    outputs = {PUBLIC_SCHEMAS[name]: value for name, value in examples().items()}
    outputs.update(
        {
            "ScopeGrant": authority.actors[0].grants[0].to_dict(),
            "WorkflowActor": authority.actors[0].to_dict(),
            "WorkflowTransition": bundle.records[0].transition.to_dict(),
            "WorkflowReceipt": bundle.records[0].to_dict(),
            "ArtifactReference": bundle.artifacts[0].to_dict(),
            "LedgerEntry": bundle.evidence.entries[0].to_dict(),
            "LedgerMemberProof": proof_index(bundle.evidence).prove(0).members[0].to_dict(),
        }
    )
    for name, output in outputs.items():
        optional = {"correlation_group", "attributes"} if name == "EvidenceEvent" else set()
        assert set(output) <= set(shapes[name]["properties"])
        assert set(output) | optional == set(shapes[name]["properties"])


@pytest.mark.parametrize("name", sorted(PUBLIC_SCHEMAS))
def test_independent_structure_mutations_reject_unknown_missing_and_wrong_types(name):
    value = examples()[name]
    check = validator(name)
    assert not check.is_valid({**value, "typo": None})
    required = definitions()[PUBLIC_SCHEMAS[name]]["required"]
    for field in required:
        changed = {key: item for key, item in value.items() if key != field}
        assert not check.is_valid(changed), (name, field)
        changed = {**value, field: {"wrong": "type"}}
        assert not check.is_valid(changed), (name, field)


@pytest.mark.parametrize(
    "correlation,attributes",
    [(None, {}), ("group", {}), (None, {"binary": False}), ("group", {"nested": [None, 1, 2.5]})],
)
def test_event_optional_canonical_forms(correlation, attributes):
    value = EvidenceEvent(
        "id",
        "claim",
        Modality.VISION,
        "source",
        Signal.CONTRADICT,
        1,
        BASE,
        BASE,
        correlation_group=correlation,
        attributes=attributes,
    ).to_dict()
    validator("evidence-event").validate(value)
    if correlation is None:
        assert "correlation_group" not in value
        assert not validator("evidence-event").is_valid({**value, "correlation_group": None})
    if not attributes:
        assert "attributes" not in value
        assert not validator("evidence-event").is_valid({**value, "attributes": {}})


def test_real_v1_and_v2_ledgers_share_structure_not_digest_algorithms():
    events = [event(0), event(1)]
    genesis = hashlib.sha256(b"evidence-braid-ledger:v1").hexdigest()
    previous, entries = genesis, []
    for sequence, observation in enumerate(events):
        digest = hashlib.sha256(
            previous.encode() + b"\n" + canonical(observation.to_dict())
        ).hexdigest()
        entries.append(
            LedgerEntry(sequence, observation.event_id, observation.to_dict(), previous, digest)
        )
        previous = digest
    v1 = EvidenceLedger(tuple(entries), genesis, "1.0")
    assert v1.verify()
    for ledger in (v1, build_ledger(events), build_ledger([])):
        validator("evidence-ledger").validate(ledger.to_dict())
        validator("ledger-commitment").validate(proof_index(ledger).commitment.to_dict())


@pytest.mark.parametrize("name", ["evidence-ledger", "workflow-bundle", "ledger-commitment"])
def test_schema_does_not_certify_derived_counts_or_digest_integrity(name):
    value = examples()[name]
    if name == "workflow-bundle":
        value["record_count"] += 1
    elif name == "evidence-ledger":
        value["entry_count"] += 1
    else:
        value["commitment_digest"] = ZERO
    validator(name).validate(value)
    with pytest.raises(ValidationError):
        if name == "workflow-bundle":
            WorkflowBundle.from_dict(value, authority=workflow()[0])
        elif name == "evidence-ledger":
            EvidenceLedger.from_dict(value)
        else:
            LedgerCommitment.from_dict(value)


@pytest.mark.parametrize("change", ["unauthorized_actor", "other_scope", "stale_revision"])
def test_hash_valid_schema_valid_workflow_can_still_fail_authorized_replay(change):
    authority, bundle = workflow()
    value = bundle.to_dict()
    command = value["records"][0]["transition"]
    if change == "unauthorized_actor":
        command["actor_id"] = "bob"
    elif change == "other_scope":
        command["scope"] = "elsewhere"
    else:
        command["expected_revision"] = 1
    previous = value["context_digest"]
    for record in value["records"]:
        record["previous_digest"] = previous
        content = {key: item for key, item in record.items() if key != "digest"}
        record["digest"] = hashlib.sha256(canonical(content)).hexdigest()
        previous = record["digest"]
    value["head_digest"] = previous
    validator("workflow-bundle").validate(value)
    with pytest.raises(ValidationError, match=r"scoped role|revision zero"):
        WorkflowBundle.from_dict(value, authority=authority)


def test_schema_valid_membership_and_consistency_still_need_external_native_verification():
    ledger = build_ledger([event(i) for i in range(7)])
    index = proof_index(ledger)
    value = index.prove(2).to_dict()
    value["members"][0]["siblings"][0] = ZERO
    validator("ledger-membership").validate(value)
    with pytest.raises(ValidationError):
        verify_ledger_membership(
            LedgerMembershipBundle.from_dict(value),
            expected_commitment_digest=index.commitment.digest,
        )
    old = proof_index(build_ledger([event(i) for i in range(3)]))
    proof = prove_ledger_consistency(index, old.commitment).to_dict()
    proof["path"][0] = ZERO
    validator("ledger-consistency").validate(proof)
    with pytest.raises(ValidationError):
        verify_ledger_consistency(
            LedgerConsistencyProof.from_dict(proof),
            expected_old_commitment_digest=old.commitment.digest,
            expected_new_commitment_digest=index.commitment.digest,
        )


def test_raw_canonical_spelling_is_not_a_json_schema_guarantee():
    index = proof_index(build_ledger([event()]))
    proof = prove_ledger_consistency(index, proof_index(build_ledger([])).commitment)
    raw = proof.to_bytes() + b"\n"
    validator("ledger-consistency").validate(json.loads(raw))
    with pytest.raises(ValidationError, match="canonical"):
        LedgerConsistencyProof.from_bytes(raw)


def test_registry_is_fresh_and_unknown_references_never_fetch():
    registry = schema_registry()
    uri = next(iter(registry))
    with pytest.raises(TypeError):
        registry[uri] = {}
    registry[uri].clear()
    assert schema_registry()[uri]
    check = validator("evidence-event")
    with pytest.raises(Exception, match="Unresolvable"):
        check.evolve(schema={"$ref": "https://should-never-resolve.invalid/schema"}).validate({})


@pytest.mark.parametrize(
    "name", ["", "../common", "wire-1/common.schema.json", "https://invalid/schema", None, True]
)
def test_schema_names_are_closed_not_paths(name):
    with pytest.raises(ValidationError):
        schema_bytes(name)


def test_real_export_is_canonical_stored_zip_and_independent_reader_checks_every_byte(tmp_path):
    first = export_schemas(tmp_path / "first.zip")
    second = export_schemas(tmp_path / "second.zip")
    raw = first.destination.read_bytes()
    assert raw == second.destination.read_bytes()
    assert first.size_bytes == len(raw) and first.archive_sha256 == hashlib.sha256(raw).hexdigest()
    expected = generated_resources()
    with zipfile.ZipFile(io.BytesIO(raw)) as reader:
        assert reader.namelist() == sorted(expected)
        assert reader.testzip() is None and reader.comment == b""
        for entry in reader.infolist():
            assert entry.compress_type == zipfile.ZIP_STORED and entry.flag_bits == 0
            assert entry.extra == entry.comment == b"" and not entry.is_dir()
            assert entry.date_time == (1980, 1, 1, 0, 0, 0)
            assert reader.read(entry) == expected[entry.filename]
    checked = verify_schema_archive(first.destination, expected_catalog_digest=first.catalog_digest)
    assert checked == first
    assert not list(tmp_path.glob(".evidence-*"))


def test_no_replace_preserves_foreign_file_and_exactly_one_concurrent_publisher_wins(tmp_path):
    path = tmp_path / "competing.zip"
    barrier = Barrier(2)

    def publish():
        barrier.wait()
        try:
            return export_schemas(path)
        except InputFormatError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        answers = list(pool.map(lambda _: publish(), range(2)))
    assert sum(answer is not None for answer in answers) == 1
    before = path.read_bytes()
    with pytest.raises(InputFormatError):
        export_schemas(path)
    assert path.read_bytes() == before
    foreign = tmp_path / "foreign"
    foreign.write_bytes(b"unrelated user content")
    with pytest.raises(InputFormatError):
        export_schemas(foreign)
    assert foreign.read_bytes() == b"unrelated user content"
    assert not list(tmp_path.glob(".evidence-*"))


def test_archive_relocation_new_process_and_cli_work_without_checkout_or_network(tmp_path):
    original = export_schemas(tmp_path / "original.zip")
    moved = tmp_path / "moved.zip"
    original.destination.rename(moved)
    code = """
import json, socket, sys
from evidence_braid import verify_schema_archive, schema_registry
socket.create_connection = lambda *a, **k: (_ for _ in ()).throw(AssertionError('network'))
checked = verify_schema_archive(sys.argv[1], expected_catalog_digest=sys.argv[2])
assert len(schema_registry()) == 8
print(json.dumps(checked.to_dict()))
"""
    process = subprocess.run(
        [sys.executable, "-c", code, str(moved), original.catalog_digest],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    assert json.loads(process.stdout)["archive_sha256"] == original.archive_sha256
    assert process.stderr == ""


def test_cli_catalog_show_export_verify_and_failure(tmp_path, capsys):
    assert run(["schema", "catalog"]) == 0
    assert json.loads(capsys.readouterr().out) == load_schema_catalog().to_dict()
    assert run(["schema", "show", "ledger-consistency"]) == 0
    assert capsys.readouterr().out.encode() == schema_bytes("ledger-consistency")
    path = tmp_path / "schemas.zip"
    assert run(["schema", "export", str(path)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert (
        run(["schema", "verify", str(path), "--expected-catalog-digest", result["catalog_digest"]])
        == 0
    )
    assert json.loads(capsys.readouterr().out) == result
    assert run(["schema", "export", str(path)]) == 2
    assert "cannot publish" in capsys.readouterr().err


@pytest.mark.parametrize(
    "change", ["prefix", "suffix", "truncate", "central_count", "compression", "content"]
)
def test_complete_zip_profile_refuses_malformed_or_alternate_archive_bytes(tmp_path, change):
    exported = export_schemas(tmp_path / "valid.zip")
    raw = bytearray(exported.destination.read_bytes())
    if change == "prefix":
        raw = b"x" + raw
    elif change == "suffix":
        raw += b"x"
    elif change == "truncate":
        raw = raw[:-1]
    elif change == "central_count":
        raw[-12:-10] = b"\xff\xff"
    elif change == "compression":
        raw[8] = 8
    else:
        raw[100] ^= 1
    altered = tmp_path / "bad.zip"
    altered.write_bytes(raw)
    with pytest.raises(InputFormatError):
        verify_schema_archive(altered, expected_catalog_digest=exported.catalog_digest)


def test_archive_bounds_wrong_anchor_and_io_failure(tmp_path, monkeypatch):
    result = export_schemas(tmp_path / "valid.zip")
    with pytest.raises(InputFormatError, match="expected catalog"):
        verify_schema_archive(result.destination, expected_catalog_digest=ZERO)
    with pytest.raises(InputFormatError, match="cannot read"):
        verify_schema_archive(tmp_path / "absent", expected_catalog_digest=result.catalog_digest)
    monkeypatch.setattr(module, "MAX_SCHEMA_ARCHIVE_BYTES", 10)
    with pytest.raises(InputFormatError):
        verify_schema_archive(result.destination, expected_catalog_digest=result.catalog_digest)
    with pytest.raises(InputFormatError, match="compiled byte bound"):
        export_schemas(tmp_path / "too-small.zip")


def test_export_checks_short_write_and_failed_verification_before_publication(
    tmp_path, monkeypatch
):
    real = module.staged_output

    @contextmanager
    def short_output(*args, **kwargs):
        with real(*args, **kwargs) as handle:

            class Short:
                def write(self, value):
                    return handle.write(value[:-1])

            yield Short()

    monkeypatch.setattr(module, "staged_output", short_output)
    with pytest.raises(InputFormatError, match="incomplete"):
        export_schemas(tmp_path / "short.zip")
    assert not (tmp_path / "short.zip").exists() and not list(tmp_path.glob(".evidence-*"))
    monkeypatch.setattr(module, "staged_output", real)
    monkeypatch.setattr(
        module, "verify_schema_archive", lambda *a, **k: (_ for _ in ()).throw(KeyboardInterrupt())
    )
    with pytest.raises(KeyboardInterrupt):
        export_schemas(tmp_path / "interrupted.zip")
    assert not (tmp_path / "interrupted.zip").exists() and not list(tmp_path.glob(".evidence-*"))


@pytest.mark.parametrize("value", [True, 0, -1, 65537, 1.2])
def test_metadata_size_bounds_are_not_boolean_or_unbounded(value):
    with pytest.raises(ValidationError):
        PublishedSchema("common", value, ZERO)


def test_metadata_derived_identity_and_invalid_catalogs(tmp_path):
    first = PublishedSchema("common", 1, ZERO)
    assert first.schema_id.endswith(":common") and first.path == "wire-1/common.schema.json"
    with pytest.raises(ValidationError):
        SchemaCatalog((first,))
    with pytest.raises(ValidationError):
        SchemaCatalog([])
    with pytest.raises(ValidationError):
        SchemaExport(Path("relative"), ZERO, ZERO, 1)
    with pytest.raises(ValidationError):
        SchemaExport(tmp_path, ZERO, ZERO, True)


def test_packaged_resource_tampering_and_read_bounds(monkeypatch):
    original = module._resource
    monkeypatch.setattr(module, "_resource", lambda *a: b"bad")
    with pytest.raises(InputFormatError, match="catalog differs"):
        load_schema_catalog()
    monkeypatch.setattr(
        module,
        "_resource",
        lambda path, cap: (
            b"changed" if path.endswith("common.schema.json") else original(path, cap)
        ),
    )
    with pytest.raises(InputFormatError, match="schema bytes"):
        load_schema_catalog()
    monkeypatch.setattr(
        module,
        "_resource",
        lambda path, cap: b"changed" if path.endswith("SHA256SUMS") else original(path, cap),
    )
    with pytest.raises(InputFormatError, match="checksum inventory"):
        load_schema_catalog()
    monkeypatch.setattr(module, "_resource", original)
    with pytest.raises(InputFormatError, match="byte bound"):
        original("wire-1/common.schema.json", 10)
    with pytest.raises(InputFormatError, match="total byte bound"):
        original("wire-1/common.schema.json", -1)
    with pytest.raises(InputFormatError, match="cannot read"):
        original("wire-1/absent", 10)


def install_test_publication(monkeypatch, resources):
    """Simulate a publisher mistake, not an attacker who can change a trusted pin."""
    catalog_raw = resources[module._CATALOG_PATH]
    monkeypatch.setattr(module, "_CATALOG_SHA256", hashlib.sha256(catalog_raw).hexdigest())

    def bounded(path, maximum):
        raw = resources[path]
        if len(raw) > maximum:
            raise InputFormatError("test publisher exceeded requested resource bound")
        return raw

    monkeypatch.setattr(module, "_resource", bounded)


@pytest.mark.parametrize(
    "change",
    [
        "kind",
        "version",
        "line",
        "extra",
        "rows_type",
        "rows_count",
        "order",
        "row_extra",
        "path",
        "uri",
        "title",
        "public",
        "size_bool",
        "size_zero",
        "name",
        "sha",
    ],
)
def test_mistaken_publisher_cannot_expand_the_closed_catalog(monkeypatch, change):
    resources = generated_resources()
    data = json.loads(resources[module._CATALOG_PATH])
    if change in ("kind", "version", "line", "extra"):
        key = {"version": "schema_version", "line": "publication_line"}.get(change, change)
        data[key] = "unsupported"
    elif change == "rows_type":
        data["schemas"] = {}
    elif change == "rows_count":
        data["schemas"].pop()
    elif change == "order":
        data["schemas"].reverse()
    else:
        key, value = {
            "row_extra": ("extra", None),
            "path": ("path", "../escape"),
            "uri": ("schema_id", "https://invalid/schema"),
            "title": ("title", "Other"),
            "public": ("public", 1),
            "size_bool": ("size_bytes", True),
            "size_zero": ("size_bytes", 0),
            "name": ("name", "not-a-schema"),
            "sha": ("sha256", "ABC"),
        }[change]
        data["schemas"][0][key] = value
    resources[module._CATALOG_PATH] = module._encode(data)
    install_test_publication(monkeypatch, resources)
    with pytest.raises((InputFormatError, ValidationError)):
        load_schema_catalog()


@pytest.mark.parametrize(
    "raw", [b"[]", b"{", b'{"x":0,"x":1}', b'{"x":1e999}', b"\xff", b"[" * 2000 + b"]" * 2000]
)
def test_strict_packaged_json_rejects_malformed_bytes_even_under_a_publisher_pin(monkeypatch, raw):
    resources = generated_resources()
    resources[module._CATALOG_PATH] = raw
    install_test_publication(monkeypatch, resources)
    with pytest.raises(InputFormatError):
        load_schema_catalog()


@pytest.mark.parametrize("change", ["id", "dialect", "reference", "numeric_ref", "defs", "json"])
def test_schema_identity_and_offline_reference_closure_survive_rehashed_publisher_error(
    monkeypatch, change
):
    resources = generated_resources()
    path = "wire-1/common.schema.json"
    value = json.loads(resources[path])
    if change == "id":
        value["$id"] = "urn:other:common"
    elif change == "dialect":
        value["$schema"] = "https://json-schema.org/draft-07/schema"
    elif change in ("reference", "numeric_ref"):
        value["$defs"]["Other"] = {
            "$ref": "https://never-fetch.invalid/schema" if change == "reference" else 1
        }
    elif change == "defs":
        value["$defs"] = []
    raw = b"null" if change == "json" else module._encode(value)
    resources[path] = raw
    catalog = json.loads(resources[module._CATALOG_PATH])
    row = next(row for row in catalog["schemas"] if row["path"] == path)
    row.update(size_bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    resources[module._CATALOG_PATH] = module._encode(catalog)
    install_test_publication(monkeypatch, resources)
    with pytest.raises(InputFormatError):
        load_schema_catalog()


def test_aggregate_bounds_include_catalog_schemas_and_checksum_inventory(monkeypatch):
    resources = generated_resources()
    schema_total = load_schema_catalog().total_schema_bytes
    monkeypatch.setattr(module, "MAX_SCHEMA_PUBLICATION_BYTES", schema_total - 1)
    with pytest.raises(ValidationError, match="bounded schema inventory"):
        load_schema_catalog()
    # All schema bytes fit; the final checksum file must still fit the same budget.
    ceiling = sum(len(raw) for path, raw in resources.items() if path != module._SUMS_PATH) + 1
    monkeypatch.setattr(module, "MAX_SCHEMA_PUBLICATION_BYTES", ceiling)
    with pytest.raises(InputFormatError, match="byte bound"):
        load_schema_catalog()


@pytest.mark.parametrize("action", list(WorkflowAction))
def test_action_specific_structural_contract_matches_native_transition(action):
    optional = {"statement": "claim"} if action is WorkflowAction.CREATE else {}
    if action in (WorkflowAction.BIND_EVIDENCE, WorkflowAction.BIND_ARTIFACT):
        optional.update(reference_id="artifact", reference_digest=ZERO)
    if action in (WorkflowAction.REJECT, WorkflowAction.REVOKE):
        optional["reason"] = "reason"
    command = WorkflowTransition("transition", action, "alice", "lab", "claim", 0, **optional)
    value = command.to_dict()
    check = validator("workflow-bundle").evolve(
        schema={"$ref": f"{module.ID_PREFIX}common#/$defs/WorkflowTransition"}
    )
    check.validate(value)
    for key in ("statement", "reference_id", "reference_digest", "reason"):
        wrong = None if value[key] is not None else ZERO
        assert not check.is_valid({**value, key: wrong}), (action, key)
    assert not check.is_valid({**value, "expected_revision": True})
    assert not check.is_valid({**value, "expected_revision": 10001})


def test_json_schema_integer_and_format_annotations_are_not_native_parsing_guarantees():
    policy = examples()["authority-policy"]
    policy["approval_quorum"] = 1.0
    validator("authority-policy").validate(policy)  # JSON Schema integer is mathematical.
    with pytest.raises(ValidationError, match="integer"):
        AuthorityPolicy.from_dict(policy)
    observation = examples()["evidence-event"]
    observation["observed_at"] = "2026-02-31T00:00:00Z"
    validator("evidence-event").validate(observation)  # Format is an annotation by default.
    with pytest.raises(ValidationError):
        EvidenceEvent.from_dict(observation)


def test_schema_publication_change_during_staging_cannot_publish(tmp_path, monkeypatch):
    real = module.verify_schema_archive

    def changed(*args, **kwargs):
        monkeypatch.setattr(module, "_CATALOG_SHA256", ZERO)
        return real(*args, **kwargs)

    monkeypatch.setattr(module, "verify_schema_archive", changed)
    with pytest.raises(InputFormatError, match="publication commitment"):
        export_schemas(tmp_path / "stale.zip")
    assert not (tmp_path / "stale.zip").exists() and not list(tmp_path.glob(".evidence-*"))


def test_real_wheel_and_sdist_ship_exact_resources_and_zip_import_needs_no_dependencies(tmp_path):
    project = Path(__file__).resolve().parents[1]
    built = tmp_path / "distributions"
    result = subprocess.run(
        [sys.executable, "-m", "build", "--no-isolation", "--outdir", str(built), str(project)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
    )
    assert "Successfully built" in result.stdout
    (wheel,) = built.glob("*.whl")
    (sdist,) = built.glob("*.tar.gz")
    expected = generated_resources()
    with zipfile.ZipFile(wheel) as reader:
        prefix = "evidence_braid/schemas/"
        members = {name[len(prefix) :] for name in reader.namelist() if name.startswith(prefix)}
        assert members == set(expected)
        for path, raw in expected.items():
            assert reader.read(prefix + path) == raw
        metadata = reader.read(
            next(name for name in reader.namelist() if name.endswith("/METADATA"))
        )
        requirements = [
            row for row in metadata.decode().splitlines() if row.startswith("Requires-Dist:")
        ]
        assert requirements and all("extra == 'dev'" in row for row in requirements)
    with tarfile.open(sdist) as reader:
        prefix = f"{sdist.name.removesuffix('.tar.gz')}/src/evidence_braid/schemas/"
        members = {item.name[len(prefix) :] for item in reader if item.name.startswith(prefix)}
        assert members == set(expected)
        for path, raw in expected.items():
            handle = reader.extractfile(prefix + path)
            assert handle is not None
            with handle:
                assert handle.read() == raw
    code = """
import json, socket, sys
sys.path.insert(0, sys.argv[1])
socket.create_connection = lambda *a, **k: (_ for _ in ()).throw(AssertionError('network'))
import evidence_braid
from evidence_braid import export_schemas, verify_schema_archive, schema_registry
assert sys.argv[1] in evidence_braid.__file__
assert 'jsonschema' not in sys.modules and len(schema_registry()) == 8
result = export_schemas(sys.argv[2])
assert verify_schema_archive(sys.argv[2], expected_catalog_digest=result.catalog_digest) == result
print(json.dumps(result.to_dict()))
"""
    isolated = subprocess.run(
        [sys.executable, "-I", "-S", "-c", code, str(wheel), str(tmp_path / "installed.zip")],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    assert isolated.stderr == ""
    assert json.loads(isolated.stdout)["catalog_digest"] == load_schema_catalog().digest


def test_offline_schema_example_verifies_real_relocated_archive_in_new_process(tmp_path):
    example = Path(__file__).resolve().parents[1] / "examples" / "offline_schemas.py"
    result = subprocess.run(
        [sys.executable, "-I", str(example)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
        timeout=90,
    )
    report = json.loads(result.stdout)
    assert report["public_schemas"] == 7 and report["schema_resources"] == 8
    assert report["relocated_process_verified"] is True
    assert report["semantic_authorization_provided"] is False
    assert report["catalog_digest"] == load_schema_catalog().digest
