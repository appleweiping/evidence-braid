"""The case core keeps model assertions separate from evidence-backed decisions."""

import hashlib
import json
from copy import deepcopy
from dataclasses import replace

import pytest

import evidence_braid as api
from evidence_braid.errors import InputFormatError, ValidationError


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def authority():
    return api.CaseAuthority(
        "case-policy",
        (
            api.CaseActor(
                "model", api.CaseActorKind.MODEL, (api.CaseGrant("site/a", api.CaseRole.PROPOSE),)
            ),
            api.CaseActor(
                "probe", api.CaseActorKind.TOOL, (api.CaseGrant("site/a", api.CaseRole.OBSERVE),)
            ),
            api.CaseActor(
                "judge", api.CaseActorKind.TOOL, (api.CaseGrant("site/a", api.CaseRole.EVALUATE),)
            ),
            api.CaseActor(
                "owner", api.CaseActorKind.HUMAN, (api.CaseGrant("site/a", api.CaseRole.DECIDE),)
            ),
        ),
    )


def planned(trusted=None):
    trusted = authority() if trusted is None else trusted
    plan = api.CasePlan(
        case_id="case-1",
        workflow_id="workflow-1",
        claim_id="incident",
        scope="site/a",
        proposer_id="model",
        assertion_artifact_id="assertion-1",
        assertion_sha256=sha(b"model proposes cache hypothesis"),
        hypothesis="A stale report is caused by the cache path.",
        prediction="Bypassing the cache will return revision-B.",
        expected_observation_text="revision-B",
        input_artifact_id="incident-input",
        input_sha256=sha(b"cached revision-A; source revision-B"),
        prediction_sha256=sha(b"revision-B"),
        test_id="bypass-cache",
        adapter_id="fixture-cache",
        adapter_version="1",
        comparator_profile="sha256-equality-v1",
        authority_digest=trusted.digest,
    )
    return trusted, plan


def observed(plan, *, value=b"revision-B", status=None):
    status = api.CaseObservationStatus.OBSERVED if status is None else status
    return api.CaseObservation(
        plan_digest=plan.digest,
        request_id="request-1",
        observer_id="probe",
        status=status,
        input_sha256=plan.input_sha256,
        observed_sha256=sha(value) if status is api.CaseObservationStatus.OBSERVED else None,
        artifact_id="observation-1" if status is api.CaseObservationStatus.OBSERVED else None,
        error_code=None if status is api.CaseObservationStatus.OBSERVED else "tool_unavailable",
    )


def verdict(plan, observation, *, evaluator="judge", outcome=None):
    if outcome is None:
        outcome = (
            api.CaseVerdictOutcome.INCONCLUSIVE
            if observation.status is not api.CaseObservationStatus.OBSERVED
            else api.CaseVerdictOutcome.SUPPORTED
            if observation.observed_sha256 == plan.prediction_sha256
            else api.CaseVerdictOutcome.REFUTED
        )
    return api.CaseVerdict(
        plan_digest=plan.digest,
        observation_digest=observation.digest,
        evaluator_id=evaluator,
        outcome=outcome,
    )


def decision(result, disposition=None):
    if disposition is None:
        disposition = (
            api.CaseDisposition.APPROVE
            if result.outcome is api.CaseVerdictOutcome.SUPPORTED
            else api.CaseDisposition.DEFER
        )
    return api.CaseDecision(
        verdict_digest=result.digest,
        decider_id="owner",
        disposition=disposition,
        reason="Bounded decision for this case",
    )


def complete(*, value=b"revision-B", status=None):
    trusted, plan = planned()
    observation = observed(plan, value=value, status=status)
    result = verdict(plan, observation)
    action = decision(result)
    journal = api.CaseJournal.empty(trusted).append(
        (plan, observation, result, action), authority=trusted
    )
    return trusted, plan, observation, result, action, journal


@pytest.mark.parametrize(
    ("value", "status", "expected"),
    [
        (b"revision-B", None, "supported"),
        (b"revision-A", None, "refuted"),
        (b"", "unavailable", "inconclusive"),
        (b"", "error", "inconclusive"),
    ],
)
def test_ordered_replay_and_roundtrip(value, status, expected):
    typed = None if status is None else api.CaseObservationStatus(status)
    trusted, plan, observation, result, action, journal = complete(value=value, status=typed)
    state = api.replay_case(journal, authority=trusted, expected_head=journal.head_digest)
    assert state.phase is api.CasePhase.DECIDED
    assert state.outcome.value == expected
    assert state.case_id == plan.case_id
    assert state.checkpoint.record_count == 4
    assert state.decision == action
    assert api.CasePlan.from_bytes(plan.to_bytes()) == plan
    assert api.CaseObservation.from_bytes(observation.to_bytes()) == observation
    assert api.CaseVerdict.from_bytes(result.to_bytes()) == result
    assert api.CaseDecision.from_bytes(action.to_bytes()) == action
    assert (
        api.CaseJournal.from_bytes(
            journal.to_bytes(), authority=trusted, expected_head=journal.head_digest
        )
        == journal
    )
    assert (
        journal.to_bytes()
        == json.dumps(
            journal.to_dict(),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )


def test_plan_is_persisted_first_and_append_does_not_mutate_prior_journal():
    trusted, plan = planned()
    empty = api.CaseJournal.empty(trusted)
    first = empty.append((plan,), authority=trusted)
    assert empty.checkpoint.record_count == 0
    assert first.checkpoint.record_count == 1
    assert api.replay_case(first, authority=trusted).phase is api.CasePhase.PLANNED
    observation = observed(plan)
    second = first.append((observation,), authority=trusted, expected=first.checkpoint)
    assert first.checkpoint.record_count == 1
    assert second.checkpoint.record_count == 2
    with pytest.raises(ValidationError):
        first.append((observation,), authority=trusted, expected=empty.checkpoint)


def test_independent_authority_genesis_and_first_receipt_formula():
    trusted, plan = planned()
    canonical = lambda value: json.dumps(  # noqa: E731 - local independent wire oracle
        value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode()
    domain = b"evidence-braid:epistemic-case:v1\x00"
    authority_digest = sha(domain + b"A" + canonical(trusted.to_dict()))
    genesis = sha(domain + b"G" + bytes.fromhex(authority_digest))
    expected = sha(domain + b"R" + bytes(4) + bytes.fromhex(genesis) + canonical(plan.to_dict()))
    journal = api.CaseJournal.empty(trusted).append((plan,), authority=trusted)
    assert trusted.digest == authority_digest
    assert journal.receipts[0].previous_digest == genesis
    assert journal.receipts[0].digest == expected


def test_case_record_input_dict_is_not_mutated_by_import():
    trusted, _, _, _, _, journal = complete()
    document = journal.to_dict()
    before = deepcopy(document)
    assert api.CaseJournal.from_dict(document, authority=trusted) == journal
    assert document == before


def test_observation_and_verdict_require_separate_tool_actors():
    trusted, plan = planned()
    observation = observed(plan)
    first = api.CaseJournal.empty(trusted).append((plan, observation), authority=trusted)
    powerful = api.CaseAuthority(
        "new-policy",
        tuple(
            replace(
                actor,
                grants=(
                    api.CaseGrant("site/a", api.CaseRole.OBSERVE),
                    api.CaseGrant("site/a", api.CaseRole.EVALUATE),
                ),
            )
            if actor.actor_id == "probe"
            else actor
            for actor in trusted.actors
        ),
    )
    shifted = replace(plan, authority_digest=powerful.digest)
    shifted_observation = replace(observation, plan_digest=shifted.digest)
    shifted_journal = api.CaseJournal.empty(powerful).append(
        (shifted, shifted_observation), authority=powerful
    )
    with pytest.raises(ValidationError):
        shifted_journal.append(
            (verdict(shifted, shifted_observation, evaluator="probe"),),
            authority=powerful,
        )
    assert first.checkpoint.record_count == 2


@pytest.mark.parametrize("records", ["observation_first", "verdict_first", "duplicate_plan"])
def test_order_or_duplicate_rejected_without_partial_result(records):
    trusted, plan = planned()
    observation = observed(plan)
    result = verdict(plan, observation)
    supplied = {
        "observation_first": (observation, plan),
        "verdict_first": (plan, result),
        "duplicate_plan": (plan, plan),
    }[records]
    empty = api.CaseJournal.empty(trusted)
    with pytest.raises(ValidationError):
        empty.append(supplied, authority=trusted)
    assert empty.checkpoint.record_count == 0


def test_model_cannot_self_observe_or_evaluate_and_cross_scope_fails():
    trusted, plan = planned()
    observation = observed(plan)
    first = api.CaseJournal.empty(trusted).append((plan,), authority=trusted)
    for wrong in (
        replace(observation, observer_id="model"),
        replace(observation, observer_id="owner"),
    ):
        with pytest.raises(ValidationError):
            first.append((wrong,), authority=trusted)
    second = first.append((observation,), authority=trusted)
    with pytest.raises(ValidationError):
        second.append((verdict(plan, observation, evaluator="model"),), authority=trusted)
    with pytest.raises(ValidationError):
        api.CaseJournal.empty(trusted).append((replace(plan, scope="site/b"),), authority=trusted)


def test_forged_verdict_and_approval_of_refutation_rejected():
    trusted, plan = planned()
    observation = observed(plan, value=b"revision-A")
    first = api.CaseJournal.empty(trusted).append((plan, observation), authority=trusted)
    with pytest.raises(ValidationError):
        first.append(
            (verdict(plan, observation, outcome=api.CaseVerdictOutcome.SUPPORTED),),
            authority=trusted,
        )
    second = first.append((verdict(plan, observation),), authority=trusted)
    with pytest.raises(ValidationError):
        second.append(
            (decision(verdict(plan, observation), api.CaseDisposition.APPROVE),),
            authority=trusted,
        )


def test_wrong_authority_or_head_and_changed_receipt_rejected():
    trusted, _, _, _, _, journal = complete()
    with pytest.raises(ValidationError):
        api.replay_case(journal, authority=trusted, expected_head=sha(b"other"))
    changed = api.CaseAuthority("different", trusted.actors)
    with pytest.raises(ValidationError):
        api.replay_case(journal, authority=changed)
    document = journal.to_dict()
    document["receipts"][1]["digest"] = sha(b"forged")
    with pytest.raises(ValidationError):
        api.CaseJournal.from_dict(document, authority=trusted)


def test_noncanonical_and_unknown_wire_fields_rejected():
    trusted, plan = planned()
    with pytest.raises(InputFormatError):
        api.CasePlan.from_bytes(plan.to_bytes() + b"\n")
    with pytest.raises(InputFormatError):
        api.CasePlan.from_bytes(json.dumps(plan.to_dict()).encode())
    plan_dict = plan.to_dict()
    plan_dict["unrecognized"] = "surprise"
    with pytest.raises(ValidationError):
        api.CasePlan.from_dict(plan_dict)
    authority_dict = trusted.to_dict()
    authority_dict["actors"][0]["grants"].append(authority_dict["actors"][0]["grants"][0])
    with pytest.raises(ValidationError):
        api.CaseAuthority.from_dict(authority_dict)


def test_journal_count_and_wire_depth_bounds():
    trusted, plan = planned()
    first = api.CaseJournal.empty(trusted).append((plan,), authority=trusted)
    oversized = first.to_dict()
    oversized["receipts"] = [oversized["receipts"][0]] * 513
    with pytest.raises(ValidationError):
        api.CaseJournal.from_dict(oversized, authority=trusted)
    raw = b"[" * 17 + b"0" + b"]" * 17
    with pytest.raises(InputFormatError):
        api.CaseJournal.from_bytes(raw, authority=trusted)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"kind":"evidence-braid-case-plan","kind":"evidence-braid-case-plan"}',
        b"\xff",
        b"{" + b" " * 20_000 + b"}",
        b'{"floating":NaN}',
    ],
)
def test_strict_wire_rejects_ambiguous_or_oversized_input(raw):
    with pytest.raises((ValidationError, InputFormatError)):
        api.CasePlan.from_bytes(raw)


def test_immutable_nested_grants_and_exact_status_fields():
    trusted, plan = planned()
    assert trusted.actors[0].grants == (api.CaseGrant("site/a", api.CaseRole.PROPOSE),)
    with pytest.raises(ValidationError):
        api.CaseObservation(
            plan.digest,
            "request-1",
            "probe",
            api.CaseObservationStatus.UNAVAILABLE,
            plan.input_sha256,
            sha(b"fabricated"),
            "observation-1",
            "tool_unavailable",
        )
    with pytest.raises(ValidationError):
        replace(plan, input_artifact_id=plan.assertion_artifact_id)
    journal = api.CaseJournal.empty(trusted).append((plan,), authority=trusted)
    with pytest.raises(ValidationError):
        journal.append(
            (replace(observed(plan), artifact_id=plan.assertion_artifact_id),),
            authority=trusted,
        )


def test_unsupported_comparator_and_unbounded_hypothesis_rejected():
    _, plan = planned()
    with pytest.raises(ValidationError):
        replace(plan, comparator_profile="python-eval")
    with pytest.raises(ValidationError):
        replace(plan, hypothesis="x" * 2049)


def test_expected_observation_cannot_silently_diverge_from_pinned_digest():
    _, plan = planned()
    assert plan.prediction == "Bypassing the cache will return revision-B."
    assert plan.expected_observation_text == "revision-B"
    assert plan.prediction_sha256 == sha(b"revision-B")
    # Old code accepted this changed digest while leaving the readable prediction
    # about revision-B untouched; replay would then support revision-A.
    with pytest.raises(ValidationError):
        replace(plan, prediction_sha256=sha(b"revision-A"))
    with pytest.raises(ValidationError):
        replace(plan, expected_observation_text="revision-A")


def test_expected_observation_is_exact_utf8_without_normalization_or_trimming():
    _, plan = planned()
    exact = " e\u0301\n"
    precise = replace(
        plan,
        expected_observation_text=exact,
        prediction_sha256=sha(exact.encode("utf-8")),
    )
    assert api.CasePlan.from_bytes(precise.to_bytes()) == precise
    with pytest.raises(ValidationError):
        replace(precise, expected_observation_text=" \u00e9\n")
    with pytest.raises(ValidationError):
        replace(plan, expected_observation_text="x" * 4097)


@pytest.mark.parametrize("length", [2048, 2049, 3000, 4096])
def test_accepted_expected_observation_text_roundtrips_at_parser_boundary(length):
    _, plan = planned()
    exact = "x" * length
    bounded = replace(
        plan,
        expected_observation_text=exact,
        prediction_sha256=sha(exact.encode("utf-8")),
    )
    assert api.CasePlan.from_bytes(bounded.to_bytes()) == bounded


def test_expected_observation_utf8_byte_limit_is_independent_of_codepoint_count():
    _, plan = planned()
    exact = "é" * 2048  # 2048 codepoints, exactly 4096 UTF-8 bytes.
    bounded = replace(
        plan,
        expected_observation_text=exact,
        prediction_sha256=sha(exact.encode("utf-8")),
    )
    assert api.CasePlan.from_bytes(bounded.to_bytes()) == bounded
    with pytest.raises(ValidationError):
        replace(
            plan,
            expected_observation_text=exact + "é",
            prediction_sha256=sha((exact + "é").encode("utf-8")),
        )


def canonical_bytes(value):
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


@pytest.mark.parametrize(("field", "replacement"), [("kind", "other"), ("schema_version", "2.0")])
def test_canonical_plan_rejects_unsupported_profile_without_mutating_input(field, replacement):
    _, plan = planned()
    document = plan.to_dict()
    document[field] = replacement
    before = deepcopy(document)
    raw = canonical_bytes(document)
    with pytest.raises(ValidationError, match="unsupported epistemic case wire profile"):
        api.CasePlan.from_bytes(raw)
    assert document == before
    assert raw == canonical_bytes(before)


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("float", "invalid epistemic case JSON"),
        ("long_integer", "invalid epistemic case JSON"),
        ("node_count", "case JSON node count exceeds"),
        ("long_key", "case JSON key is outside"),
        ("long_text", "case JSON text is outside"),
        ("invalid_text", "case JSON text is outside"),
    ],
)
def test_bounded_journal_parser_rejects_hostile_canonical_data(case, message):
    trusted = authority()
    raw = {
        "float": b'{"x":1.0}',
        "long_integer": b'{"x":12345678901}',
        "node_count": canonical_bytes({"x": [None] * 8192}),
        "long_key": canonical_bytes({"x" * 4097: None}),
        "long_text": canonical_bytes({"x": "x" * 4097}),
        "invalid_text": canonical_bytes({"x": "\x01"}),
    }[case]
    before = raw
    with pytest.raises(InputFormatError, match=message):
        api.CaseJournal.from_bytes(raw, authority=trusted)
    assert raw == before


def test_authority_rejects_untyped_or_forbidden_grants_and_duplicate_actors():
    scoped = api.CaseGrant("site/a", api.CaseRole.PROPOSE)
    with pytest.raises(ValidationError, match="typed role"):
        api.CaseGrant("site/a", "propose")
    with pytest.raises(ValidationError, match="typed kind"):
        api.CaseActor("model", "model", (scoped,))
    with pytest.raises(ValidationError, match="cannot hold"):
        api.CaseActor(
            "model", api.CaseActorKind.MODEL, (api.CaseGrant("site/a", api.CaseRole.OBSERVE),)
        )
    first = authority().actors[0]
    with pytest.raises(ValidationError, match="unique bounded actors"):
        api.CaseAuthority("policy", ())
    with pytest.raises(ValidationError, match="unique bounded actors"):
        api.CaseAuthority("policy", (first, first))


def test_observation_and_outcome_fields_require_typed_consistent_values():
    _, plan = planned()
    observation = observed(plan)
    with pytest.raises(ValidationError, match="typed status"):
        replace(observation, status="observed")
    with pytest.raises(ValidationError, match="cannot also report an error"):
        replace(observation, error_code="unexpected_error")
    with pytest.raises(ValidationError, match="failed observation needs"):
        replace(
            observation,
            status=api.CaseObservationStatus.UNAVAILABLE,
            observed_sha256=None,
            artifact_id=None,
        )
    result = verdict(plan, observation)
    with pytest.raises(ValidationError, match="typed outcome"):
        replace(result, outcome="supported")
    with pytest.raises(ValidationError, match="typed disposition"):
        replace(decision(result), disposition="approve")


@pytest.mark.parametrize("mutation", ["previous", "sequence"])
def test_self_consistent_forged_receipt_cannot_break_journal_chain(mutation):
    trusted, plan = planned()
    first = api.CaseJournal.empty(trusted).append((plan,), authority=trusted)
    original = first.receipts[0]
    sequence = 1 if mutation == "sequence" else original.sequence
    previous = sha(b"foreign predecessor") if mutation == "previous" else original.previous_digest
    digest = sha(
        b"evidence-braid:epistemic-case:v1\x00"
        + b"R"
        + sequence.to_bytes(4, "big")
        + bytes.fromhex(previous)
        + plan.to_bytes()
    )
    forged = api.CaseReceipt(sequence, previous, plan, digest)
    with pytest.raises(ValidationError, match="chain is not contiguous"):
        api.CaseJournal(trusted.digest, (forged,))
    assert first.checkpoint.record_count == 1
    assert first.receipts[0] == original


def test_unknown_record_kind_and_premature_decision_leave_plan_unchanged():
    trusted, plan = planned()
    first = api.CaseJournal.empty(trusted).append((plan,), authority=trusted)
    altered = first.to_dict()
    altered["receipts"][0]["record"]["kind"] = "evidence-braid-case-future"
    before = deepcopy(altered)
    with pytest.raises(ValidationError, match="record kind is unsupported"):
        api.CaseJournal.from_dict(altered, authority=trusted)
    assert altered == before
    observation = observed(plan)
    premature = decision(verdict(plan, observation))
    checkpoint = first.checkpoint
    with pytest.raises(ValidationError, match="decision needs one preceding verdict"):
        first.append((premature,), authority=trusted, expected=checkpoint)
    assert first.checkpoint == checkpoint


@pytest.mark.parametrize("invalid", [(), [], (object(),)])
def test_append_rejects_empty_mutable_or_unsupported_records_without_partial_history(invalid):
    trusted, plan = planned()
    first = api.CaseJournal.empty(trusted).append((plan,), authority=trusted)
    checkpoint = first.checkpoint
    with pytest.raises(ValidationError, match="case append"):
        first.append(invalid, authority=trusted, expected=checkpoint)
    assert first.checkpoint == checkpoint


def test_authority_wire_and_decision_digest_have_independent_oracles():
    trusted, _, _, _, action, journal = complete()
    authority_wire = canonical_bytes(trusted.to_dict())
    decision_wire = canonical_bytes(action.to_dict())
    assert trusted.to_bytes() == authority_wire
    assert api.CaseAuthority.from_bytes(authority_wire) == trusted
    assert action.to_bytes() == decision_wire
    assert action.digest == sha(b"evidence-braid:epistemic-case:v1\x00D" + decision_wire)
    assert (
        api.replay_case(journal, authority=trusted, expected_head=journal.head_digest).decision
        == action
    )


@pytest.mark.parametrize("role", [None, "unsupported-role"])
def test_grant_wire_rejects_unknown_or_untyped_role(role):
    document = {"scope": "site/a", "role": role}
    before = deepcopy(document)
    with pytest.raises(ValidationError, match="known enum string"):
        api.CaseGrant.from_dict(document)
    assert document == before


def test_exact_expected_observation_rejects_wrong_type_and_disallowed_character():
    _, plan = planned()
    with pytest.raises(ValidationError, match="exact UTF-8 text"):
        replace(plan, expected_observation_text=b"revision-B")
    with pytest.raises(ValidationError, match="unsupported text"):
        replace(plan, expected_observation_text="\x01", prediction_sha256=sha(b"\x01"))


def test_authority_rejects_valid_but_oversized_actor_inventory():
    actors = tuple(
        api.CaseActor(
            f"probe-{actor_index}",
            api.CaseActorKind.TOOL,
            tuple(
                api.CaseGrant(
                    f"site/{actor_index}/{grant_index}/" + "x" * 110,
                    api.CaseRole.OBSERVE,
                )
                for grant_index in range(64)
            ),
        )
        for actor_index in range(8)
    )
    with pytest.raises(ValidationError, match="case authority exceeds its byte bound"):
        api.CaseAuthority("oversized", actors)
    assert len(actors) == 8
    assert all(len(actor.grants) == 64 for actor in actors)


def test_journal_boundary_rejects_untyped_records_and_callers():
    trusted, plan = planned()
    first = api.CaseJournal.empty(trusted).append((plan,), authority=trusted)
    document = first.to_dict()
    document["receipts"][0]["record"] = {"kind": 7}
    before = deepcopy(document)
    with pytest.raises(ValidationError, match="record needs a known kind"):
        api.CaseJournal.from_dict(document, authority=trusted)
    assert document == before
    with pytest.raises(ValidationError, match="unsupported type"):
        api.CaseReceipt(0, first.receipts[0].previous_digest, object(), sha(b"invalid"))
    with pytest.raises(ValidationError, match="bounded immutable receipts"):
        api.CaseJournal(trusted.digest, [])
    with pytest.raises(ValidationError, match="trusted authority"):
        api.CaseJournal.empty(object())
    with pytest.raises(ValidationError, match="typed journal and authority"):
        api.replay_case(object(), authority=trusted)
    with pytest.raises(ValidationError, match="typed journal and authority"):
        api.replay_case(first, authority=object())
    assert first.checkpoint.record_count == 1


def test_decider_must_have_separate_exact_scope_authority():
    trusted, plan = planned()
    observation = observed(plan)
    result = verdict(plan, observation)
    evaluated = api.CaseJournal.empty(trusted).append(
        (plan, observation, result), authority=trusted
    )
    checkpoint = evaluated.checkpoint
    with pytest.raises(ValidationError, match="decision lacks verdict binding"):
        evaluated.append(
            (replace(decision(result), decider_id="probe"),),
            authority=trusted,
            expected=checkpoint,
        )
    assert evaluated.checkpoint == checkpoint
