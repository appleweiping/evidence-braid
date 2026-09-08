"""Procedural approvals are not a substitute for retained-content verification."""

import hashlib
import json
from dataclasses import replace

import pytest
from test_workflow import authority, evidence_event

import evidence_braid as api
from evidence_braid.errors import InputFormatError, ValidationError


def committed(identifier, raw):
    return api.ArtifactReference(
        identifier,
        "site/a",
        "incident",
        hashlib.sha256(raw).hexdigest(),
        len(raw),
        "application/json",
    )


def case(raw=b'{"ok":true}', *, reported=None, approve=True):
    trusted = authority()
    evidence = api.build_ledger([evidence_event()])
    statement = "Retained analysis meets the explicit check plan."
    plan = api.CheckPlan(
        "plan-1",
        "workflow-1",
        "site/a",
        "incident",
        hashlib.sha256(statement.encode()).hexdigest(),
        trusted.digest,
        evidence.head_digest,
        (committed("analysis", raw),),
        (api.CheckRule("ok", api.CheckOperator.EQUALS, "analysis", ("ok",), expected=True),),
    )
    result = api.evaluate_checks(plan, {"analysis": raw})
    contents = {
        "analysis": raw,
        "plan": plan.to_bytes(),
        "evaluation": result.to_bytes() if reported is None else reported,
    }
    artifacts = tuple(committed(name, value) for name, value in contents.items())
    commands = [
        api.WorkflowTransition(
            "create",
            api.WorkflowAction.CREATE,
            "alice",
            "site/a",
            "incident",
            0,
            statement=statement,
        ),
        api.WorkflowTransition(
            "evidence",
            api.WorkflowAction.BIND_EVIDENCE,
            "alice",
            "site/a",
            "incident",
            1,
            reference_id=evidence.entries[0].event_id,
            reference_digest=evidence.entries[0].digest,
        ),
    ]
    for item in artifacts:
        commands.append(
            api.WorkflowTransition(
                f"bind-{item.artifact_id}",
                api.WorkflowAction.BIND_ARTIFACT,
                "alice",
                "site/a",
                "incident",
                len(commands),
                reference_id=item.artifact_id,
                reference_digest=item.sha256,
            )
        )
    commands.append(
        api.WorkflowTransition(
            "submit", api.WorkflowAction.SUBMIT, "alice", "site/a", "incident", len(commands)
        )
    )
    if approve:
        for name in ("carol", "ellen"):
            commands.append(
                api.WorkflowTransition(
                    f"approve-{name}",
                    api.WorkflowAction.APPROVE,
                    name,
                    "site/a",
                    "incident",
                    len(commands),
                )
            )
    bundle = api.build_workflow(
        "workflow-1",
        authority=trusted,
        evidence=evidence,
        artifacts=artifacts,
        transitions=commands,
    )
    return bundle, trusted, plan, result, contents


def policy_for(plan):
    return api.CheckPolicy(
        "gate-1",
        plan.workflow_id,
        plan.scope,
        plan.claim_id,
        plan.authority_digest,
        "plan",
        plan.digest,
        "evaluation",
    )


def check(bundle, trusted, plan, contents):
    return api.verify_claim_checks(
        bundle,
        authority=trusted,
        policy=policy_for(plan),
        contents=contents,
        expected_head=bundle.head_digest,
        expected_evidence_head=bundle.evidence.head_digest,
    )


def test_approved_humans_do_not_turn_actual_failed_data_into_semantic_pass():
    bundle, trusted, plan, result, contents = case(b'{"ok":false,"passed":true}')
    assert (
        api.replay_workflow(bundle, authority=trusted).claims["incident"].status
        is api.ClaimStatus.APPROVED
    )
    assert result.outcome is api.CheckOutcome.FAIL
    checked = check(bundle, trusted, plan, contents)
    assert checked.procedural_status is api.ClaimStatus.APPROVED
    assert checked.evaluation.outcome is api.CheckOutcome.FAIL
    assert checked.accepted is False


def test_gate_recomputes_even_a_forged_report_bound_by_real_approvals():
    _, _, _, success, _ = case()
    bundle, trusted, plan, _, contents = case(b'{"ok":false}', reported=success.to_bytes())
    with pytest.raises(ValidationError):
        check(bundle, trusted, plan, contents)


def test_success_needs_both_content_pass_and_procedural_approval():
    for approve in (False, True):
        bundle, trusted, plan, _, contents = case(approve=approve)
        checked = check(bundle, trusted, plan, contents)
        assert checked.evaluation.outcome is api.CheckOutcome.PASS
        assert checked.accepted is approve


def rebind(bundle, trusted, contents):
    """Rebuild genuine commitments/receipts; attacks are not merely stale hashes."""
    artifacts = tuple(committed(name, raw) for name, raw in contents.items())
    references = {item.artifact_id: item for item in artifacts}
    transitions = tuple(
        replace(
            receipt.transition, reference_digest=references[receipt.transition.reference_id].sha256
        )
        if receipt.transition.action is api.WorkflowAction.BIND_ARTIFACT
        else receipt.transition
        for receipt in bundle.records
    )
    return api.build_workflow(
        bundle.workflow_id,
        authority=trusted,
        evidence=bundle.evidence,
        artifacts=artifacts,
        transitions=transitions,
    )


def test_claimed_pass_with_same_plan_and_rehashed_report_is_not_trusted():
    bundle, trusted, plan, failed, contents = case(b'{"ok":false}')
    forged = api.CheckEvaluation(
        plan.digest, (api.CheckResult("ok", api.CheckOutcome.PASS, api.CheckReason.PASSED),)
    )
    assert forged.plan_digest == failed.plan_digest
    contents["evaluation"] = forged.to_bytes()
    rebuilt = rebind(bundle, trusted, contents)
    assert (
        api.replay_workflow(rebuilt, authority=trusted).claims["incident"].status
        is api.ClaimStatus.APPROVED
    )
    with pytest.raises(ValidationError, match="independent recomputation"):
        check(rebuilt, trusted, plan, contents)


@pytest.mark.parametrize("raw", [b"{}", b'{"ok":null}', b'{"ok":[]}', b'{"ok":{}}'])
def test_unknown_is_never_accepted_even_with_true_quorum(raw):
    bundle, trusted, plan, _, contents = case(raw)
    result = check(bundle, trusted, plan, contents)
    assert result.procedural_status is api.ClaimStatus.APPROVED
    assert result.evaluation.outcome is (
        api.CheckOutcome.FAIL if raw == b'{"ok":null}' else api.CheckOutcome.UNKNOWN
    )
    assert not result.accepted


@pytest.mark.parametrize(
    "field,value",
    [
        ("workflow_id", "another"),
        ("scope", "site/b"),
        ("claim_id", "other"),
        ("authority_digest", "d" * 64),
        ("plan_digest", "e" * 64),
        ("plan_artifact_id", "unknown"),
        ("evaluation_artifact_id", "unknown"),
    ],
)
def test_externally_pinned_policy_bindings_are_not_taken_from_the_bundle(field, value):
    bundle, trusted, plan, _, contents = case()
    with pytest.raises(ValidationError):
        api.verify_claim_checks(
            bundle,
            authority=trusted,
            policy=replace(policy_for(plan), **{field: value}),
            contents=contents,
            expected_head=bundle.head_digest,
            expected_evidence_head=bundle.evidence.head_digest,
        )


@pytest.mark.parametrize("field", ["expected_head", "expected_evidence_head"])
@pytest.mark.parametrize("value", [None, True, "f" * 64, "G" * 64])
def test_both_external_heads_are_mandatory_exact_and_current(field, value):
    bundle, trusted, plan, _, contents = case()
    args = {
        "expected_head": bundle.head_digest,
        "expected_evidence_head": bundle.evidence.head_digest,
    }
    args[field] = value
    with pytest.raises(ValidationError):
        api.verify_claim_checks(
            bundle, authority=trusted, policy=policy_for(plan), contents=contents, **args
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("workflow_id", "other"),
        ("statement_digest", "d" * 64),
        ("authority_digest", "e" * 64),
        ("evidence_head", "f" * 64),
    ],
)
def test_coherent_rehashed_plan_cannot_escape_claim_context(field, value):
    bundle, trusted, plan, _, contents = case()
    changed = replace(plan, **{field: value})
    contents["plan"] = changed.to_bytes()
    rebuilt = rebind(bundle, trusted, contents)
    with pytest.raises(ValidationError, match="plan context"):
        api.verify_claim_checks(
            rebuilt,
            authority=trusted,
            policy=replace(policy_for(plan), plan_digest=changed.digest),
            contents=contents,
            expected_head=rebuilt.head_digest,
            expected_evidence_head=rebuilt.evidence.head_digest,
        )


def test_rehashed_reordered_rules_report_is_not_an_interchangeable_result():
    bundle, trusted, plan, _, contents = case()
    plan = replace(
        plan, rules=(*plan.rules, api.CheckRule("exists", api.CheckOperator.EXISTS, "analysis"))
    )
    actual = api.evaluate_checks(plan, {"analysis": contents["analysis"]})
    reordered = api.CheckEvaluation(plan.digest, tuple(reversed(actual.results)))
    contents.update(plan=plan.to_bytes(), evaluation=reordered.to_bytes())
    rebuilt = rebind(bundle, trusted, contents)
    with pytest.raises(ValidationError, match="independent recomputation"):
        check(rebuilt, trusted, plan, contents)


@pytest.mark.parametrize("identifier", ["plan", "evaluation", "analysis"])
def test_metadata_and_input_bytes_are_checked_against_the_same_retained_snapshot(identifier):
    bundle, trusted, plan, _, contents = case()
    contents[identifier] += b" "
    with pytest.raises(ValidationError, match="commitment"):
        check(bundle, trusted, plan, contents)


@pytest.mark.parametrize("identifier", ["plan", "evaluation", "analysis"])
def test_every_retained_input_is_required(identifier):
    bundle, trusted, plan, _, contents = case()
    del contents[identifier]
    with pytest.raises(ValidationError):
        check(bundle, trusted, plan, contents)


def test_extra_retained_data_is_not_silently_ignored():
    bundle, trusted, plan, _, contents = case()
    contents["extra"] = b"null"
    with pytest.raises(ValidationError, match="inventory"):
        check(bundle, trusted, plan, contents)


def test_revocation_changes_gate_status_without_redefining_original_approvals():
    bundle, trusted, plan, _, contents = case()
    old_head = bundle.head_digest
    bundle = bundle.append(
        (
            api.WorkflowTransition(
                "revoke",
                api.WorkflowAction.REVOKE,
                "dana",
                "site/a",
                "incident",
                len(bundle.records),
                reason="Separate retained-head lifecycle probe.",
            ),
        ),
        authority=trusted,
    )
    checked = check(bundle, trusted, plan, contents)
    assert checked.procedural_status is api.ClaimStatus.REVOKED
    assert checked.evaluation.outcome is api.CheckOutcome.PASS
    assert not checked.accepted
    with pytest.raises(ValidationError):
        api.verify_claim_checks(
            bundle,
            authority=trusted,
            policy=policy_for(plan),
            contents=contents,
            expected_head=old_head,
            expected_evidence_head=bundle.evidence.head_digest,
        )


def test_new_gate_replays_authority_not_just_a_serialized_status():
    bundle, trusted, plan, _, contents = case()
    # A fresh policy which removes reviewers cannot inherit an old authority pin.
    unauthorized = replace(
        trusted, actors=tuple(actor for actor in trusted.actors if actor.actor_id != "carol")
    )
    with pytest.raises(ValidationError):
        api.verify_claim_checks(
            bundle,
            authority=unauthorized,
            policy=policy_for(plan),
            contents=contents,
            expected_head=bundle.head_digest,
            expected_evidence_head=bundle.evidence.head_digest,
        )


def test_policy_wire_profile_and_output_metadata_have_no_implicit_authentication():
    bundle, trusted, plan, evaluation, contents = case()
    policy = policy_for(plan)
    assert api.CheckPolicy.from_dict(policy.to_dict()) == policy
    assert api.parse_check_policy(policy.to_bytes()) == policy
    assert policy.digest == hashlib.sha256(policy.to_bytes()).hexdigest()
    checked = check(bundle, trusted, plan, contents)
    raw = checked.to_dict()
    assert raw["accepted"] is True
    assert raw["evaluation_digest"] == evaluation.digest
    assert raw["policy_digest"] == policy.digest
    assert json.loads(checked.to_bytes()) == raw
    with pytest.raises(InputFormatError):
        api.parse_check_policy(policy.to_bytes() + b"\n")
    for changes in ({"plan_artifact_id": "evaluation"}, {"plan_digest": False}):
        with pytest.raises(ValidationError):
            replace(policy, **changes)
    for changes in (
        {"procedural_status": "approved"},
        {"evaluation": None},
        {"plan_digest": "d" * 64},
        {"workflow_head": True},
    ):
        with pytest.raises(ValidationError):
            replace(checked, **changes)


def test_gate_shares_all_byte_node_and_output_work_without_partial_acceptance():
    bundle, trusted, plan, _, contents = case()
    for changes in (
        {"max_work_units": 1},
        {"max_json_nodes": 2},
        {"max_output_bytes": 1},
        {"max_input_bytes": 1},
        {"max_plan_bytes": 1},
        {"max_total_input_bytes": 1},
    ):
        with pytest.raises(api.CheckLimitError):
            api.verify_claim_checks(
                bundle,
                authority=trusted,
                policy=policy_for(plan),
                contents=contents,
                expected_head=bundle.head_digest,
                expected_evidence_head=bundle.evidence.head_digest,
                limits=api.CheckLimits(**changes),
            )
    original = contents.copy()
    assert check(bundle, trusted, plan, contents).accepted
    assert contents == original


def test_gate_rejects_wrong_model_types_and_noncanonical_but_correctly_rehashed_plan():
    bundle, trusted, plan, _, contents = case()
    args = {
        "bundle": bundle,
        "authority": trusted,
        "policy": policy_for(plan),
        "contents": contents,
        "expected_head": bundle.head_digest,
        "expected_evidence_head": bundle.evidence.head_digest,
    }
    for name in ("bundle", "authority", "policy"):
        with pytest.raises(ValidationError):
            api.verify_claim_checks(**{**args, name: None})
    with pytest.raises(ValidationError):
        api.CheckPolicy.from_dict([])
    contents["plan"] += b"\n"
    changed = rebind(bundle, trusted, contents)
    with pytest.raises(InputFormatError, match="canonical"):
        api.verify_claim_checks(
            changed,
            authority=trusted,
            policy=replace(
                policy_for(plan), plan_digest=hashlib.sha256(contents["plan"]).hexdigest()
            ),
            contents=contents,
            expected_head=changed.head_digest,
            expected_evidence_head=changed.evidence.head_digest,
        )


@pytest.mark.parametrize("identifier", ["plan", "evaluation"])
def test_metadata_as_plan_input_is_rejected_before_attempting_a_hash_cycle(identifier):
    bundle, trusted, plan, _, contents = case()
    changed = replace(
        plan,
        inputs=(committed(identifier, b"null"),),
        rules=(api.CheckRule("r", api.CheckOperator.EXISTS, identifier),),
    )
    contents["plan"] = changed.to_bytes()
    rebuilt = rebind(bundle, trusted, contents)
    with pytest.raises(ValidationError, match="cannot include"):
        check(rebuilt, trusted, changed, contents)


def test_plan_input_commitment_must_equal_bound_reference_before_evaluation():
    bundle, trusted, plan, _, contents = case()
    changed = replace(
        plan,
        inputs=(replace(plan.inputs[0], size_bytes=0, sha256=hashlib.sha256(b"").hexdigest()),),
    )
    contents["plan"] = changed.to_bytes()
    rebuilt = rebind(bundle, trusted, contents)
    with pytest.raises(ValidationError, match="exact bound"):
        check(rebuilt, trusted, changed, contents)


def test_complete_gate_output_has_independent_bound_after_valid_evaluation():
    bundle, trusted, plan, evaluation, contents = case()
    bound = len(evaluation.to_bytes())
    with pytest.raises(api.CheckLimitError, match="checked-claim output"):
        api.verify_claim_checks(
            bundle,
            authority=trusted,
            policy=policy_for(plan),
            contents=contents,
            expected_head=bundle.head_digest,
            expected_evidence_head=bundle.evidence.head_digest,
            limits=api.CheckLimits(max_output_bytes=bound),
        )


@pytest.mark.parametrize("identifier", ["analysis", "plan", "evaluation"])
def test_artifact_in_global_context_but_unbound_to_claim_does_not_count(identifier):
    bundle, trusted, plan, _, contents = case()
    transitions = []
    for receipt in bundle.records:
        item = receipt.transition
        if item.action is api.WorkflowAction.BIND_ARTIFACT and item.reference_id == identifier:
            continue
        transitions.append(replace(item, expected_revision=len(transitions)))
    changed = api.build_workflow(
        bundle.workflow_id,
        authority=trusted,
        evidence=bundle.evidence,
        artifacts=bundle.artifacts,
        transitions=transitions,
    )
    assert (
        api.replay_workflow(changed, authority=trusted).claims["incident"].status
        is api.ClaimStatus.APPROVED
    )
    with pytest.raises(ValidationError, match="bound"):
        check(changed, trusted, plan, contents)


@pytest.mark.parametrize("field", ["kind", "schema_version"])
def test_check_policy_does_not_admit_unknown_wire_versions(field):
    _, _, plan, _, _ = case()
    with pytest.raises(ValidationError):
        api.CheckPolicy.from_dict({**policy_for(plan).to_dict(), field: "other"})


def test_gate_rejects_cross_claim_and_scope_even_in_a_self_consistent_plan():
    bundle, trusted, plan, _, contents = case()
    for changes in ({"scope": "site/b"}, {"claim_id": "other"}):
        changed = replace(
            plan, **changes, inputs=tuple(replace(item, **changes) for item in plan.inputs)
        )
        updated = {**contents, "plan": changed.to_bytes()}
        rebuilt = rebind(bundle, trusted, updated)
        with pytest.raises(ValidationError, match="plan context"):
            api.verify_claim_checks(
                rebuilt,
                authority=trusted,
                policy=replace(policy_for(plan), plan_digest=changed.digest),
                contents=updated,
                expected_head=rebuilt.head_digest,
                expected_evidence_head=rebuilt.evidence.head_digest,
            )
