from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

from evidence_braid import (
    ActorKind,
    ArtifactReference,
    AuthorityPolicy,
    AuthorityRole,
    ClaimStatus,
    ClaimWorkflow,
    EvidenceEvent,
    ScopeGrant,
    SQLiteLedger,
    WorkflowAction,
    WorkflowActor,
    WorkflowBundle,
    WorkflowReceipt,
    WorkflowState,
    WorkflowTransition,
    build_ledger,
    build_workflow,
    load_workflow_bundle,
    replay_workflow,
    write_workflow_bundle,
)
from evidence_braid.cli import run
from evidence_braid.errors import InputFormatError, ValidationError

FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "workflow-cases.json").read_text())
ABC_DIGEST = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def authority():
    def actor(name, roles, scope="site/a", kind=ActorKind.HUMAN):
        return WorkflowActor(name, kind, tuple(ScopeGrant(scope, role) for role in roles))

    return AuthorityPolicy(
        "review-v1",
        (
            actor("alice", tuple(AuthorityRole)),
            actor("bob", tuple(AuthorityRole)),
            actor("carol", (AuthorityRole.REVIEWER, AuthorityRole.REVOKER)),
            actor("ellen", (AuthorityRole.REVIEWER,)),
            actor("dana", (AuthorityRole.REVOKER,)),
            actor("robot", tuple(AuthorityRole), kind=ActorKind.AUTOMATION),
            actor("outsider", tuple(AuthorityRole), scope="site/b"),
        ),
        approval_quorum=2,
    )


def evidence_event(**changes):
    document = {
        "event_id": "observation-1",
        "claim": "incident",
        "modality": "sensor",
        "source": "instrument-1",
        "signal": "support",
        "confidence": 0.8,
        "observed_at": "2026-09-07T00:00:00Z",
        "ingested_at": "2026-09-07T00:00:01Z",
        "attributes": {"workflow_scope": "site/a"},
    }
    return EvidenceEvent.from_dict({**document, **changes})


def artifact(**changes):
    return ArtifactReference.from_dict(
        {
            "artifact_id": "analysis-1",
            "scope": "site/a",
            "claim_id": "incident",
            "sha256": ABC_DIGEST,
            "size_bytes": 3,
            "media_type": "text/plain",
            **changes,
        }
    )


def empty_bundle(*, evidence=None, artifacts=None, policy=None):
    return build_workflow(
        "workflow-1",
        authority=policy or authority(),
        evidence=evidence if evidence is not None else build_ledger([evidence_event()]),
        artifacts=artifacts if artifacts is not None else (artifact(),),
    )


def steps(bundle, descriptions):
    result = []
    for item in descriptions:
        reference = item.get("reference")
        result.append(
            WorkflowTransition(
                item["id"],
                WorkflowAction(item["action"]),
                item["actor"],
                item.get("scope", "site/a"),
                item.get("claim", "incident"),
                item["revision"],
                statement=item.get("statement"),
                reference_id=(
                    bundle.evidence.entries[0].event_id
                    if reference == "evidence"
                    else bundle.artifacts[0].artifact_id
                    if reference == "artifact"
                    else None
                ),
                reference_digest=(
                    bundle.evidence.entries[0].digest
                    if reference == "evidence"
                    else bundle.artifacts[0].sha256
                    if reference == "artifact"
                    else None
                ),
                reason=item.get("reason"),
            )
        )
    return result


def submitted_bundle():
    bundle = empty_bundle()
    return bundle.append(steps(bundle, FIXTURE["draft_to_submitted"]), authority=authority())


def approved_bundle():
    bundle = submitted_bundle()
    return bundle.append(steps(bundle, FIXTURE["cases"][0]["steps"]), authority=authority())


@pytest.mark.parametrize("case", FIXTURE["cases"], ids=lambda case: case["name"])
def test_independent_lifecycle_conformance_fixture(case):
    bundle = empty_bundle()
    before = bundle.to_dict()
    commands = steps(bundle, FIXTURE["draft_to_submitted"][: case["prefix"]] + case["steps"])
    if "error" in case:
        with pytest.raises(ValidationError, match=case["error"]):
            bundle.append(commands, authority=authority())
    else:
        updated = bundle.append(commands, authority=authority())
        state = replay_workflow(updated, authority=authority())
        assert state.to_dict()["claims"]["incident"] == {
            "claim_id": "incident",
            "scope": "site/a",
            "statement": "The incident has reviewed supporting material.",
            "status": case["status"],
            "revision": len(commands),
            "authors": ["alice", "bob"],
            "evidence_ids": ["observation-1"],
            "artifact_ids": ["analysis-1"],
            "approvals": case["approvals"],
        }
        assert WorkflowBundle.from_dict(updated.to_dict(), authority=authority()) == updated
    assert bundle.to_dict() == before


def oracle_digest(document):
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def test_receipt_hash_oracle_binds_context_sequence_and_complete_intent():
    bundle = approved_bundle()
    raw = bundle.to_dict()
    context = oracle_digest(
        {
            "kind": "evidence-braid-workflow-context",
            "schema_version": "1.0",
            "workflow_id": "workflow-1",
            "authority_digest": authority().digest,
            "evidence_head": bundle.evidence.head_digest,
            "artifacts": [artifact().to_dict()],
        }
    )
    assert context == raw["context_digest"]
    previous = context
    for number, record in enumerate(raw["records"]):
        assert record["sequence"] == number
        assert record["previous_digest"] == previous
        assert record["context_digest"] == context
        body = {key: value for key, value in record.items() if key != "digest"}
        assert record["digest"] == oracle_digest(body)
        previous = record["digest"]
    assert previous == raw["head_digest"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("actor_id", "mallory"),
        ("scope", "site/b"),
        ("claim_id", "another"),
        ("expected_revision", 1),
        ("transition_id", "forged"),
        ("statement", "Forged."),
    ],
)
def test_payload_tampering_is_rejected_before_replay(field, value):
    raw = approved_bundle().to_dict()
    raw["records"][0]["transition"][field] = value
    with pytest.raises(ValidationError):
        WorkflowBundle.from_dict(raw, authority=authority())


@pytest.mark.parametrize(
    "field,value",
    [
        ("sequence", True),
        ("sequence", 9),
        ("previous_digest", "0" * 64),
        ("context_digest", "0" * 64),
        ("digest", "0" * 64),
        ("schema_version", "2.0"),
    ],
)
def test_receipt_metadata_tampering_is_rejected(field, value):
    raw = approved_bundle().to_dict()
    raw["records"][2][field] = value
    with pytest.raises(ValidationError):
        WorkflowBundle.from_dict(raw, authority=authority())


def resign(raw):
    """An adversary may recompute public hashes; authorization must still reject."""
    previous = raw["context_digest"]
    for number, record in enumerate(raw["records"]):
        record["sequence"] = number
        record["previous_digest"] = previous
        record["digest"] = oracle_digest({k: v for k, v in record.items() if k != "digest"})
        previous = record["digest"]
    raw["head_digest"] = previous
    raw["record_count"] = len(raw["records"])
    return raw


@pytest.mark.parametrize("actor,match", [("mallory", "scoped role"), ("alice", "independent")])
def test_rehashed_forged_permission_does_not_bypass_authority(actor, match):
    raw = approved_bundle().to_dict()
    raw["records"][4]["transition"]["actor_id"] = actor
    with pytest.raises(ValidationError, match=match):
        WorkflowBundle.from_dict(resign(raw), authority=authority())


def test_hashes_are_not_authentication_or_rollback_prevention():
    bundle = approved_bundle()
    raw = bundle.to_dict()
    raw["records"][4]["transition"]["actor_id"] = "ellen"
    raw["records"][5]["transition"]["actor_id"] = "carol"
    replacement = resign(raw)
    # Permitted names with recomputed hashes are valid declarations, not signatures.
    assert (
        WorkflowBundle.from_dict(replacement, authority=authority()).head_digest
        != bundle.head_digest
    )
    with pytest.raises(ValidationError, match="expected head"):
        WorkflowBundle.from_dict(
            replacement, authority=authority(), expected_head=bundle.head_digest
        )
    prefix = replace(bundle, records=bundle.records[:4])
    assert (
        replay_workflow(prefix, authority=authority()).claims["incident"].status
        is ClaimStatus.SUBMITTED
    )
    with pytest.raises(ValidationError, match="expected head"):
        replay_workflow(prefix, authority=authority(), expected_head=bundle.head_digest)


def test_policy_replacement_requires_independent_caller_trust():
    bundle = approved_bundle()
    changed_policy = replace(authority(), approval_quorum=1)
    with pytest.raises(ValidationError, match="trusted policy"):
        replay_workflow(bundle, authority=changed_policy)
    with pytest.raises(ValidationError, match="integrity"):
        replace(bundle, authority_digest=changed_policy.digest)


def test_reordered_replayed_and_cross_workflow_records_fail():
    bundle = approved_bundle()
    with pytest.raises(ValidationError, match="integrity"):
        replace(bundle, records=(bundle.records[1], bundle.records[0], *bundle.records[2:]))
    with pytest.raises(ValidationError, match="integrity"):
        replace(bundle, workflow_id="another-workflow")
    with pytest.raises(ValidationError, match="integrity"):
        bundle.append([bundle.records[0].transition], authority=authority())
    raw = bundle.to_dict()
    raw["records"][0], raw["records"][1] = raw["records"][1], raw["records"][0]
    with pytest.raises(ValidationError, match="missing"):
        WorkflowBundle.from_dict(resign(raw), authority=authority())


@pytest.mark.parametrize(
    "event_changes",
    [
        {"claim": "other"},
        {"attributes": {}},
        {"attributes": {"workflow_scope": "site/b"}},
        {"attributes": {"workflow_scope": True}},
    ],
)
def test_evidence_claim_and_producer_scope_are_bound(event_changes):
    bundle = empty_bundle(evidence=build_ledger([evidence_event(**event_changes)]))
    with pytest.raises(ValidationError, match="evidence reference"):
        bundle.append(steps(bundle, FIXTURE["draft_to_submitted"]), authority=authority())


@pytest.mark.parametrize("changes", [{"claim_id": "other"}, {"scope": "site/b"}])
def test_artifact_claim_and_scope_are_bound(changes):
    bundle = empty_bundle(artifacts=(artifact(**changes),))
    with pytest.raises(ValidationError, match="artifact reference"):
        bundle.append(steps(bundle, FIXTURE["draft_to_submitted"]), authority=authority())


@pytest.mark.parametrize("index", [1, 2])
@pytest.mark.parametrize(
    "field,value", [("reference_id", "missing"), ("reference_digest", "0" * 64)]
)
def test_reference_identity_and_digest_both_required(index, field, value):
    bundle = empty_bundle()
    commands = steps(bundle, FIXTURE["draft_to_submitted"])
    commands[index] = replace(commands[index], **{field: value})
    with pytest.raises(ValidationError, match="reference"):
        bundle.append(commands, authority=authority())


@pytest.mark.parametrize("index", [1, 2])
def test_duplicate_reference_cannot_be_counted_twice(index):
    bundle = empty_bundle()
    commands = steps(bundle, FIXTURE["draft_to_submitted"][: index + 1])
    commands.append(replace(commands[-1], transition_id="duplicate", expected_revision=index + 1))
    with pytest.raises(ValidationError, match="duplicated"):
        bundle.append(commands, authority=authority())


def test_existing_claim_identity_cannot_move_scope_or_be_recreated():
    bundle = empty_bundle()
    created = bundle.append(steps(bundle, FIXTURE["draft_to_submitted"][:1]), authority=authority())
    create_again = replace(created.records[0].transition, transition_id="again")
    with pytest.raises(ValidationError, match="new claim"):
        created.append([create_again], authority=authority())
    wrong_scope = WorkflowTransition(
        "scope", WorkflowAction.SUBMIT, "outsider", "site/b", "incident", 1
    )
    with pytest.raises(ValidationError, match="another scope"):
        created.append([wrong_scope], authority=authority())
    with pytest.raises(ValidationError, match="revision zero"):
        bundle.append([replace(create_again, expected_revision=1)], authority=authority())


@pytest.mark.parametrize("actor", ["alice", "bob", "carol"])
def test_revoker_is_not_author_or_approver(actor):
    bundle = approved_bundle()
    with pytest.raises(ValidationError, match="independent"):
        bundle.append(
            [
                WorkflowTransition(
                    "revoke",
                    WorkflowAction.REVOKE,
                    actor,
                    "site/a",
                    "incident",
                    6,
                    reason="Withdrawn.",
                )
            ],
            authority=authority(),
        )


def test_terminal_states_do_not_accept_reviews():
    bundle = approved_bundle()
    with pytest.raises(ValidationError, match="only submitted"):
        bundle.append(
            [
                WorkflowTransition(
                    "extra", WorkflowAction.REJECT, "ellen", "site/a", "incident", 6, reason="No."
                )
            ],
            authority=authority(),
        )


def test_detached_documents_and_immutable_state():
    bundle = approved_bundle()
    raw = bundle.to_dict()
    raw["evidence"]["entries"][0]["event"]["attributes"]["workflow_scope"] = "site/b"
    raw["records"].clear()
    state = replay_workflow(bundle, authority=authority())
    output = state.to_dict()
    output["claims"]["incident"]["authors"].clear()
    assert state.claims["incident"].authors == ("alice", "bob")
    with pytest.raises(TypeError):
        state.claims["other"] = state.claims["incident"]
    with pytest.raises(FrozenInstanceError):
        bundle.workflow_id = "other"
    assert len(bundle.records) == 6


def test_content_manifest_verification_is_explicit_and_exact():
    bundle = approved_bundle()
    assert bundle.verify_artifacts({"analysis-1": b"abc"})
    assert not bundle.verify_artifacts({"analysis-1": b"abd"})
    assert not bundle.verify_artifacts({"analysis-1": b"abc", "extra": b""})
    assert not bundle.verify_artifacts({})
    assert not bundle.verify_artifacts(None)
    assert not artifact().matches(bytearray(b"abc"))


def test_durable_evidence_and_bundle_roundtrip_across_process(tmp_path):
    store = SQLiteLedger(tmp_path / "evidence.db")
    ledger = store.append([evidence_event()])
    bundle = empty_bundle(evidence=ledger)
    bundle = bundle.append(steps(bundle, FIXTURE["draft_to_submitted"]), authority=authority())
    policy_path = tmp_path / "authority.json"
    policy_path.write_text(json.dumps(authority().to_dict()), encoding="utf-8")
    path = tmp_path / "workflow.json"
    write_workflow_bundle(path, bundle, authority=authority())
    loaded = load_workflow_bundle(
        path,
        authority=authority(),
        expected_head=bundle.head_digest,
        expected_evidence_head=ledger.head_digest,
    )
    assert loaded == bundle
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "evidence_braid",
            "workflow-replay",
            str(policy_path),
            str(path),
            "--expected-head",
            bundle.head_digest,
            "--expected-evidence-head",
            ledger.head_digest,
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    assert json.loads(result.stdout) == replay_workflow(bundle, authority=authority()).to_dict()
    assert SQLiteLedger(store.path, create=False).snapshot() == ledger


def test_atomic_export_failure_preserves_prior_file(tmp_path, monkeypatch):
    import evidence_braid.workflow as workflow

    path = tmp_path / "workflow.json"
    path.write_bytes(b"prior-content")

    def fail_replace(*args):
        raise OSError("simulated publish error")

    monkeypatch.setattr(workflow.os, "replace", fail_replace)
    with pytest.raises(InputFormatError, match="cannot publish"):
        write_workflow_bundle(path, approved_bundle(), authority=authority())
    assert path.read_bytes() == b"prior-content"
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.parametrize("payload", [b'{"x":1,"x":2}', b'{"x":1e999}', b"\xff", b"{", b"[" * 2000])
def test_strict_portable_json_rejection(tmp_path, payload):
    path = tmp_path / "input.json"
    path.write_bytes(payload)
    with pytest.raises(InputFormatError):
        load_workflow_bundle(path, authority=authority())


def test_load_and_build_resource_limits(tmp_path, monkeypatch):
    import evidence_braid.workflow as workflow

    path = tmp_path / "input.json"
    path.write_bytes(b"12345")
    monkeypatch.setattr(workflow, "MAX_WORKFLOW_BYTES", 4)
    with pytest.raises(InputFormatError, match="limit"):
        load_workflow_bundle(path, authority=authority())
    with pytest.raises(ValidationError, match="limit"):
        empty_bundle()


def test_cli_failure_does_not_emit_partial_state(tmp_path, capsys):
    policy_path = tmp_path / "authority.json"
    policy_path.write_text(json.dumps(authority().to_dict()), encoding="utf-8")
    path = tmp_path / "bundle.json"
    write_workflow_bundle(path, approved_bundle(), authority=authority())
    assert run(["workflow-replay", str(policy_path), str(path), "--expected-head", "0" * 64]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "expected head" in output.err


def test_cli_success_reports_exact_replayed_state(tmp_path, capsys):
    policy_path = tmp_path / "authority.json"
    policy_path.write_text(json.dumps(authority().to_dict()), encoding="utf-8")
    path = tmp_path / "bundle.json"
    bundle = approved_bundle()
    write_workflow_bundle(path, bundle, authority=authority())
    assert run(["workflow-replay", str(policy_path), str(path)]) == 0
    output = capsys.readouterr()
    assert not output.err
    assert json.loads(output.out) == replay_workflow(bundle, authority=authority()).to_dict()


@pytest.mark.parametrize(
    "field,value",
    [
        ("kind", "other"),
        ("schema_version", "2.0"),
        ("record_count", True),
        ("record_count", 9),
        ("records", None),
        ("artifacts", None),
        ("context_digest", "0" * 64),
        ("head_digest", "0" * 64),
    ],
)
def test_bundle_document_is_exact_and_derived_metadata_is_checked(field, value):
    raw = approved_bundle().to_dict()
    raw[field] = value
    with pytest.raises(ValidationError):
        WorkflowBundle.from_dict(raw, authority=authority())


@pytest.mark.parametrize(
    "changes",
    [
        {"evidence": None},
        {"artifacts": []},
        {"artifacts": (None,)},
        {"artifacts": (artifact(), artifact())},
        {"records": []},
        {"records": (None,)},
    ],
)
def test_bundle_constructor_refuses_nonimmutable_or_invalid_components(changes):
    with pytest.raises(ValidationError):
        replace(empty_bundle(), **changes)


def test_receipt_constructor_requires_transition_type():
    with pytest.raises(ValidationError, match="WorkflowTransition"):
        WorkflowReceipt(0, "0" * 64, "0" * 64, {}, "0" * 64)


def test_runtime_entrypoints_fail_closed_on_wrong_types_and_bounds(monkeypatch):
    import evidence_braid.workflow as workflow

    bundle = empty_bundle()
    with pytest.raises(ValidationError, match="trusted AuthorityPolicy"):
        build_workflow("workflow", authority=None, evidence=bundle.evidence)
    with pytest.raises(ValidationError, match="trusted AuthorityPolicy"):
        replay_workflow(bundle, authority=None)
    with pytest.raises(ValidationError, match="WorkflowBundle"):
        replay_workflow(None, authority=authority())
    with pytest.raises(ValidationError, match="digest"):
        replay_workflow(bundle, authority=authority(), expected_head="bad")
    with pytest.raises(ValidationError, match="WorkflowTransition"):
        bundle.append([None], authority=authority())
    monkeypatch.setattr(workflow, "MAX_WORKFLOW_RECORDS", 1)
    with pytest.raises(ValidationError, match="bounded"):
        bundle.append(steps(bundle, FIXTURE["draft_to_submitted"][:2]), authority=authority())
    with pytest.raises(ValidationError, match="bounded"):
        replace(bundle, records=(None, None))


def test_manifest_limits_and_canonical_order(monkeypatch):
    import evidence_braid.workflow as workflow

    manifest = (artifact(artifact_id="z"), artifact())
    bundle = empty_bundle(artifacts=manifest)
    assert [a.artifact_id for a in bundle.artifacts] == ["analysis-1", "z"]
    raw = bundle.to_dict()
    raw["artifacts"].reverse()
    with pytest.raises(ValidationError, match="canonical"):
        WorkflowBundle.from_dict(raw, authority=authority())
    monkeypatch.setattr(workflow, "MAX_WORKFLOW_ARTIFACTS", 1)
    with pytest.raises(ValidationError, match="bounded"):
        empty_bundle(artifacts=manifest)


@pytest.mark.parametrize(
    "changes",
    [
        {"status": "draft"},
        {"authors": []},
        {"authors": ()},
        {"authors": ("alice", "alice")},
        {"evidence_ids": ["e1"]},
        {"artifact_ids": ("bad key",)},
        {"approvals": ("alice",)},
    ],
)
def test_public_claim_snapshot_cannot_contain_mutable_or_inconsistent_identity_sets(changes):
    claim = ClaimWorkflow("claim", "site/a", "A claim.", ClaimStatus.DRAFT, 1, ("alice",))
    with pytest.raises(ValidationError):
        replace(claim, **changes)


def test_public_state_snapshot_copies_and_checks_claim_inventory():
    claim = ClaimWorkflow("claim", "site/a", "A claim.", ClaimStatus.DRAFT, 1, ("alice",))
    claims = {"claim": claim}
    state = WorkflowState("workflow", "0" * 64, 1, claims)
    claims.clear()
    assert state.claims["claim"] == claim
    for inventory in (None, {"wrong-key": claim}, {"claim": {}}):
        with pytest.raises(ValidationError, match="matching IDs"):
            replace(state, claims=inventory)
    with pytest.raises(ValidationError, match="account for every"):
        replace(state, record_count=2)


def test_empty_workflow_and_empty_append_are_deterministic():
    bundle = empty_bundle()
    assert bundle.head_digest == bundle.context_digest
    assert bundle.append([], authority=authority()) == bundle
    assert replay_workflow(bundle, authority=authority()).to_dict()["claims"] == {}


def test_interleaved_claim_revisions_are_independent_and_automation_can_author():
    bundle = empty_bundle()
    commands = [
        WorkflowTransition(
            "create-a", WorkflowAction.CREATE, "alice", "site/a", "a", 0, statement="First."
        ),
        WorkflowTransition(
            "create-b", WorkflowAction.CREATE, "robot", "site/a", "b", 0, statement="Second."
        ),
    ]
    updated = bundle.append(commands, authority=authority())
    state = replay_workflow(updated, authority=authority())
    assert state.claims["a"].revision == state.claims["b"].revision == 1
    assert state.claims["b"].authors == ("robot",)
    assert list(state.to_dict()["claims"]) == ["a", "b"]
    with pytest.raises(ValidationError, match="evidence reference"):
        updated.append(
            [
                WorkflowTransition(
                    "bind",
                    WorkflowAction.BIND_EVIDENCE,
                    "alice",
                    "site/a",
                    "a",
                    1,
                    reference_id="observation-1",
                    reference_digest=bundle.evidence.entries[0].digest,
                )
            ],
            authority=authority(),
        )
