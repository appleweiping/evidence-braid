"""Offline observation must bind actual adapter bytes, not a declared digest."""

import hashlib
import json
import sys
from copy import copy
from dataclasses import replace
from threading import Barrier, Event, Thread

import pytest

import evidence_braid as api
from evidence_braid import case_observation as observation_runtime
from evidence_braid.errors import ValidationError
from evidence_braid.examples.cache_bypass_case import (
    INCIDENT,
    ReportEnvironment,
    _parse_incident,
    make_cache_bypass_adapter,
    run_fixture,
)
from evidence_braid.examples.cache_bypass_case import main as cache_bypass_main

ASSERTION = b"The cache is stale."
INPUT = b'{"incident":"cache","revision":"B"}'


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def case(*, expected: bytes = b"revision-B", input_bytes: bytes = INPUT):
    authority = api.CaseAuthority(
        "offline-policy",
        (
            api.CaseActor(
                "model", api.CaseActorKind.MODEL, (api.CaseGrant("site/a", api.CaseRole.PROPOSE),)
            ),
            api.CaseActor(
                "observer", api.CaseActorKind.TOOL, (api.CaseGrant("site/a", api.CaseRole.OBSERVE),)
            ),
            api.CaseActor(
                "evaluator",
                api.CaseActorKind.TOOL,
                (api.CaseGrant("site/a", api.CaseRole.EVALUATE),),
            ),
        ),
    )
    plan = api.CasePlan(
        case_id="case-1",
        workflow_id="workflow-1",
        claim_id="claim-1",
        scope="site/a",
        proposer_id="model",
        assertion_artifact_id="assertion-1",
        assertion_sha256=digest(ASSERTION),
        hypothesis="The report cache is stale.",
        prediction="A bypass should return the current revision.",
        expected_observation_text=expected.decode("utf-8"),
        input_artifact_id="input-1",
        input_sha256=digest(input_bytes),
        prediction_sha256=digest(expected),
        test_id="cache-bypass",
        adapter_id="fixture-cache",
        adapter_version="1",
        comparator_profile="sha256-equality-v1",
        authority_digest=authority.digest,
    )
    journal = api.CaseJournal.empty(authority).append((plan,), authority=authority)
    return authority, plan, journal


def registry(callback, *, observer="observer", version="1", limits=None):
    adapter = api.ObservationAdapter("cache-bypass", "fixture-cache", version, observer, callback)
    return api.ObservationRegistry((adapter,), limits=limits)


def prepared(callback, *, expected=b"revision-B", limits=None):
    authority, plan, journal = case(expected=expected)
    selected = registry(callback, limits=limits)
    intent = api.prepare_observation(
        journal,
        authority,
        selected,
        ASSERTION,
        INPUT,
        expected_plan_head=journal.head_digest,
        request_id="request-1",
    )
    return authority, plan, journal, selected, intent


def checked(authority, journal, retained):
    return api.verify_observed_bytes(
        retained.journal,
        authority,
        retained,
        expected_plan_head=journal.head_digest,
        expected_observation_head=retained.journal.head_digest,
        evaluator_id="evaluator",
    )


def test_missing_stage_b_api_is_genuine_red_then_exact_bytes_are_checked():
    calls = []

    def adapter(raw: bytes) -> bytes:
        calls.append(raw)
        return b"revision-B"

    authority, plan, journal, selected, intent = prepared(adapter)
    assert calls == []
    retained = api.run_observation(intent, registry=selected)
    result = checked(authority, journal, retained)
    assert calls == [INPUT]
    assert retained.observation.status is api.CaseObservationStatus.OBSERVED
    assert retained.observation.observed_sha256 == digest(b"revision-B")
    assert result.verdict.outcome is api.CaseVerdictOutcome.SUPPORTED
    assert result.journal.checkpoint.record_count == 3
    assert result.observed_bytes == b"revision-B"
    assert plan.to_bytes() == retained.journal.receipts[0].record.to_bytes()
    with pytest.raises(ValidationError, match="consumed"):
        api.run_observation(intent, registry=selected)


@pytest.mark.parametrize(
    ("actual", "expected_outcome"),
    [(b"revision-C", api.CaseVerdictOutcome.REFUTED), (b"", api.CaseVerdictOutcome.REFUTED)],
)
def test_independent_oracle_for_refuted_and_empty_output(actual, expected_outcome):
    authority, plan, journal, selected, intent = prepared(lambda _: actual)
    retained = api.run_observation(intent, registry=selected)
    result = checked(authority, journal, retained)
    assert result.verdict.outcome is expected_outcome
    assert retained.observation.observed_sha256 == hashlib.sha256(actual).hexdigest()
    assert retained.observation.observed_sha256 != plan.prediction_sha256


@pytest.mark.parametrize("actual", [b" \n", b" e\xcc\x81\n", b"x" * 4096])
def test_exact_utf8_text_and_output_boundary(actual):
    authority, _, journal, selected, intent = prepared(lambda _: actual, expected=actual)
    retained = api.run_observation(intent, registry=selected)
    assert checked(authority, journal, retained).verdict.outcome is api.CaseVerdictOutcome.SUPPORTED
    assert retained.observed_bytes == actual


@pytest.mark.parametrize(
    "actual", [b"x" * 4097, b"\xff", b"\x01", bytearray(b"revision-B"), "revision-B"]
)
def test_invalid_adapter_output_is_error_not_support(actual):
    authority, _, journal, selected, intent = prepared(lambda _: actual)
    retained = api.run_observation(intent, registry=selected)
    assert retained.observation.status is api.CaseObservationStatus.ERROR
    assert retained.observed_bytes is None
    assert (
        checked(authority, journal, retained).verdict.outcome is api.CaseVerdictOutcome.INCONCLUSIVE
    )


def test_unavailable_and_unexpected_exception_are_inconclusive_without_secret_leak():
    def unavailable(_: bytes) -> bytes:
        raise api.ObservationUnavailable("secret")

    def broken(_: bytes) -> bytes:
        raise RuntimeError("secret")

    for adapter, status in (
        (unavailable, api.CaseObservationStatus.UNAVAILABLE),
        (broken, api.CaseObservationStatus.ERROR),
    ):
        authority, _, journal, selected, intent = prepared(adapter)
        retained = api.run_observation(intent, registry=selected)
        assert retained.observation.status is status
        assert "secret" not in retained.observation.to_bytes().decode()
        assert (
            checked(authority, journal, retained).verdict.outcome
            is api.CaseVerdictOutcome.INCONCLUSIVE
        )


def test_preflight_rejects_all_bad_commitments_without_invocation():
    calls = []

    def adapter(raw):
        calls.append(raw)
        return b"revision-B"

    authority, plan, journal = case()
    selected = registry(adapter)
    for bad_assertion, bad_input, bad_head, bad_registry, bad_authority in (
        (b"tamper", INPUT, journal.head_digest, selected, authority),
        (ASSERTION, b"tamper", journal.head_digest, selected, authority),
        (ASSERTION, INPUT, digest(b"stale"), selected, authority),
        (ASSERTION, INPUT, journal.head_digest, registry(adapter, version="2"), authority),
        (ASSERTION, INPUT, journal.head_digest, registry(adapter, observer="wrong"), authority),
        (ASSERTION, INPUT, None, selected, authority),
        (
            ASSERTION,
            INPUT,
            journal.head_digest,
            selected,
            api.CaseAuthority("other", authority.actors),
        ),
    ):
        with pytest.raises(ValidationError):
            api.prepare_observation(
                journal,
                bad_authority,
                bad_registry,
                bad_assertion,
                bad_input,
                expected_plan_head=bad_head,
                request_id="request-1",
            )
    assert calls == []
    assert journal.checkpoint.record_count == 1
    assert plan.digest == journal.receipts[0].record.digest


def test_duplicate_registry_and_limits_rejected():
    adapter = api.ObservationAdapter(
        "cache-bypass", "fixture-cache", "1", "observer", lambda _: b"ok"
    )
    with pytest.raises(ValidationError):
        api.ObservationRegistry((adapter, adapter))
    with pytest.raises(ValidationError):
        api.ObservationLimits(output_bytes=4097)
    with pytest.raises(ValidationError):
        api.ObservationLimits(input_bytes=True)
    authority, _, journal = case()
    selected = api.ObservationRegistry((adapter,), limits=api.ObservationLimits(input_bytes=2))
    with pytest.raises(ValidationError):
        api.prepare_observation(
            journal,
            authority,
            selected,
            ASSERTION,
            INPUT,
            expected_plan_head=journal.head_digest,
            request_id="request-1",
        )


def test_forged_retention_and_wrong_anchor_never_support():
    authority, _, journal, selected, intent = prepared(lambda _: b"revision-B")
    retained = api.run_observation(intent, registry=selected)
    with pytest.raises(ValidationError, match="issued by the runner"):
        checked(authority, journal, copy(retained))
    with pytest.raises(ValidationError):
        checked(authority, journal, replace(retained, observed_bytes=b"revision-C"))
    with pytest.raises(ValidationError):
        checked(authority, journal, replace(retained, assertion_bytes=b"changed"))
    with pytest.raises(ValidationError):
        checked(
            authority,
            journal,
            replace(retained, artifact_inventory=retained.artifact_inventory[:-1]),
        )
    with pytest.raises(ValidationError):
        checked(authority, journal, replace(retained, limits=api.ObservationLimits(output_bytes=1)))
    with pytest.raises(ValidationError):
        checked(
            authority,
            journal,
            replace(
                retained,
                artifact_inventory=(
                    *retained.artifact_inventory,
                    api.ObservationArtifact("unexpected", digest(b"extra")),
                ),
            ),
        )
    with pytest.raises(ValidationError):
        checked(
            authority,
            journal,
            replace(
                retained,
                artifact_inventory=(
                    *retained.artifact_inventory[:-1],
                    api.ObservationArtifact("swapped", digest(b"revision-B")),
                ),
            ),
        )
    with pytest.raises(ValidationError):
        api.verify_observed_bytes(
            retained.journal,
            authority,
            retained,
            expected_plan_head=journal.head_digest,
            expected_observation_head=digest(b"wrong"),
            evaluator_id="evaluator",
        )
    with pytest.raises(ValidationError):
        api.verify_observed_bytes(
            retained.journal,
            authority,
            retained,
            expected_plan_head=journal.head_digest,
            expected_observation_head=retained.journal.head_digest,
            evaluator_id="observer",
        )


def test_caller_cannot_mint_supported_retention_without_running_adapter():
    calls = []
    authority, plan, journal, _, _ = prepared(lambda raw: calls.append(raw) or b"revision-B")
    output = b"revision-B"
    observation = api.CaseObservation(
        plan.digest,
        "request-1",
        "observer",
        api.CaseObservationStatus.OBSERVED,
        plan.input_sha256,
        digest(output),
        "fabricated-output",
        None,
    )
    observed = journal.append((observation,), authority=authority)
    with pytest.raises(ValidationError, match="runner"):
        api.RetainedObservation(
            observed,
            journal.checkpoint,
            observed.checkpoint,
            observation,
            (plan.test_id, plan.adapter_id, plan.adapter_version, "observer"),
            "request-1",
            ASSERTION,
            INPUT,
            output,
            (
                api.ObservationArtifact(plan.assertion_artifact_id, digest(ASSERTION)),
                api.ObservationArtifact(plan.input_artifact_id, digest(INPUT)),
                api.ObservationArtifact("fabricated-output", digest(output)),
            ),
            api.ObservationLimits(),
        )
    assert calls == []


def test_single_prepared_intent_is_claimed_before_callback_with_racing_threads():
    entered = Barrier(2)
    release = Barrier(2)
    calls = []

    def adapter(raw):
        calls.append(raw)
        entered.wait(timeout=5)
        release.wait(timeout=5)
        return b"revision-B"

    _, _, _, selected, intent = prepared(adapter)
    results = []

    def worker():
        try:
            results.append(api.run_observation(intent, registry=selected))
        except ValidationError as error:
            results.append(error)

    first = Thread(target=worker)
    first.start()
    entered.wait(timeout=5)
    second = Thread(target=worker)
    second.start()
    second.join(timeout=5)
    release.wait(timeout=5)
    first.join(timeout=5)
    assert not first.is_alive() and not second.is_alive()
    assert len(calls) == 1
    assert len(results) == 2
    assert sum(isinstance(item, api.RetainedObservation) for item in results) == 1
    assert sum(isinstance(item, ValidationError) for item in results) == 1


def test_cancellation_before_and_during_callback_does_not_publish_false_success():
    token = api.ObservationCancelToken()
    assert token.cancel() is True
    calls = []
    _, _, journal, selected, intent = prepared(lambda raw: calls.append(raw) or b"revision-B")
    with pytest.raises(api.ObservationCancelled):
        api.run_observation(intent, registry=selected, cancel=token)
    assert calls == []
    assert journal.checkpoint.record_count == 1
    with pytest.raises(ValidationError, match="consumed"):
        api.run_observation(intent, registry=selected)

    during = api.ObservationCancelToken()

    def callback(raw):
        assert during.cancel() is True
        return b"revision-B"

    _, _, journal, selected, intent = prepared(callback)
    with pytest.raises(api.ObservationInterrupted) as raised:
        api.run_observation(intent, registry=selected, cancel=during)
    assert raised.value.observed_bytes == b"revision-B"
    assert journal.checkpoint.record_count == 1


def test_same_thread_cancel_during_publication_is_diagnostic(monkeypatch):
    token = api.ObservationCancelToken()
    _, _, journal, selected, intent = prepared(lambda _: b"revision-B")
    original_append = api.CaseJournal.append
    attempted = []

    def append_with_reentrant_cancel(self, records, *, authority, expected=None):
        if self is journal:
            with pytest.raises(ValidationError, match="publication"):
                token.cancel()
            attempted.append(True)
        return original_append(self, records, authority=authority, expected=expected)

    monkeypatch.setattr(api.CaseJournal, "append", append_with_reentrant_cancel)
    retained = api.run_observation(intent, registry=selected, cancel=token)
    assert attempted == [True]
    assert retained.observation.status is api.CaseObservationStatus.OBSERVED
    assert token.cancelled is False
    assert token.cancel() is False


def test_other_thread_cancel_cannot_mark_published_result_cancelled(monkeypatch):
    token = api.ObservationCancelToken()
    _, _, journal, selected, intent = prepared(lambda _: b"revision-B")
    original_append = api.CaseJournal.append
    entered = Event()
    release = Event()
    attempting = Event()
    results = []
    cancellation = []

    def paused_append(self, records, *, authority, expected=None):
        if self is journal:
            entered.set()
            assert release.wait(timeout=5)
        return original_append(self, records, authority=authority, expected=expected)

    def worker():
        results.append(api.run_observation(intent, registry=selected, cancel=token))

    def cancel_worker():
        attempting.set()
        cancellation.append(token.cancel())

    monkeypatch.setattr(api.CaseJournal, "append", paused_append)
    runner = Thread(target=worker)
    canceller = Thread(target=cancel_worker)
    runner.start()
    try:
        assert entered.wait(timeout=5)
        canceller.start()
        assert attempting.wait(timeout=5)
    finally:
        release.set()
        runner.join(timeout=5)
        if canceller.ident is not None:
            canceller.join(timeout=5)
    assert not runner.is_alive() and not canceller.is_alive()
    assert len(results) == 1
    assert results[0].observation.status is api.CaseObservationStatus.OBSERVED
    assert cancellation == [False]
    assert token.cancelled is False


def test_accepted_cancel_before_publication_prevents_append(monkeypatch):
    token = api.ObservationCancelToken()
    _, _, journal, selected, intent = prepared(lambda _: b"revision-B")
    original_retained = observation_runtime._retained
    entered = Event()
    release = Event()
    results = []

    def paused_retention(*args):
        entered.set()
        assert release.wait(timeout=5)
        return original_retained(*args)

    def worker():
        try:
            results.append(api.run_observation(intent, registry=selected, cancel=token))
        except api.ObservationInterrupted as error:
            results.append(error)

    monkeypatch.setattr(observation_runtime, "_retained", paused_retention)
    runner = Thread(target=worker)
    runner.start()
    try:
        assert entered.wait(timeout=5)
        assert token.cancel() is True
    finally:
        release.set()
        runner.join(timeout=5)
    assert not runner.is_alive()
    assert len(results) == 1
    assert isinstance(results[0], api.ObservationInterrupted)
    assert results[0].observed_bytes == b"revision-B"
    assert journal.checkpoint.record_count == 1


def test_registry_replacement_and_stale_append_leave_original_journal():
    authority, _, journal, selected, intent = prepared(lambda _: b"revision-B")
    other = registry(lambda _: b"revision-C")
    with pytest.raises(ValidationError):
        api.run_observation(intent, registry=other)
    assert journal.checkpoint.record_count == 1
    retained = api.run_observation(intent, registry=selected)
    assert checked(authority, journal, retained).verdict.outcome is api.CaseVerdictOutcome.SUPPORTED


@pytest.mark.parametrize(
    ("source", "outcome", "observed"),
    [
        ("revision-B", api.CaseVerdictOutcome.SUPPORTED, b"revision-B"),
        ("revision-C", api.CaseVerdictOutcome.REFUTED, b"revision-C"),
        (None, api.CaseVerdictOutcome.INCONCLUSIVE, None),
    ],
)
def test_real_offline_cache_bypass_fixture(source, outcome, observed):
    result = run_fixture(source)
    assert result.reads == (False, True)
    assert result.outcome is outcome
    assert result.observed_bytes == observed
    assert result.observed_sha256 == (digest(observed) if observed is not None else None)
    assert len({result.plan_head, result.observation_head, result.verdict_head}) == 3


@pytest.mark.parametrize(
    "argument, outcome, observed",
    [
        (None, "supported", "revision-B"),
        ("C", "refuted", "revision-C"),
        ("unavailable", "inconclusive", None),
    ],
)
def test_cache_bypass_example_cli_reports_checked_result(
    monkeypatch, capsys, argument, outcome, observed
):
    monkeypatch.setattr(sys, "argv", ["cache-bypass"] + ([] if argument is None else [argument]))
    assert cache_bypass_main() == 0
    report = json.loads(capsys.readouterr().out)
    assert report["outcome"] == outcome
    assert report["observed_text"] == observed
    assert report["observed_sha256"] == (
        digest(observed.encode("utf-8")) if observed is not None else None
    )
    assert report["read_sequence"] == [False, True]


def test_cache_bypass_example_cli_rejects_unrecognized_selection(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["cache-bypass", "C", "extra"])
    assert cache_bypass_main() == 2
    assert "usage:" in capsys.readouterr().err


@pytest.mark.parametrize(
    "raw",
    [
        b"{" + b'"x":[' * 5 + b"0" + b"]}" * 5,
        b'{"incident":"stale-report","incident":"stale-report","requested_field":"revision"}',
        b'{"incident":"stale-report","requested_field":"revision","url":"https://example.org"}',
        b'{"incident":"stale-report","requested_field":"revision","command":"echo"}',
        b'{"incident":"stale-report","requested_field":"revision","expected":"revision-B"}',
        b"{" + b" " * 4096 + b"}",
    ],
)
def test_fixture_rejects_noncanonical_or_executable_selections(raw):
    environment = ReportEnvironment()
    adapter = make_cache_bypass_adapter(environment)
    with pytest.raises(ValidationError):
        adapter(raw)
    assert environment.reads == []
    assert _parse_incident(INCIDENT) == {"incident": "stale-report", "requested_field": "revision"}


def test_registry_entries_are_immutable_and_direct_callback_returns_cannot_alias_mutable_buffer():
    mutable = bytearray(b"revision-B")
    selected = registry(lambda _: mutable)
    with pytest.raises(AttributeError):
        selected._entries = ()
    authority, _, journal = case()
    intent = api.prepare_observation(
        journal,
        authority,
        selected,
        ASSERTION,
        INPUT,
        expected_plan_head=journal.head_digest,
        request_id="request-1",
    )
    retained = api.run_observation(intent, registry=selected)
    mutable[:] = b"revision-C"
    assert retained.observed_bytes is None
    assert (
        checked(authority, journal, retained).verdict.outcome is api.CaseVerdictOutcome.INCONCLUSIVE
    )


def test_prepared_identity_cannot_be_replaced_and_preflight_never_accepts_mutable_inputs():
    calls = []
    authority, _, journal, selected, intent = prepared(
        lambda raw: calls.append(raw) or b"revision-B"
    )
    with pytest.raises(AttributeError):
        intent._input = b"changed"
    with pytest.raises(AttributeError):
        intent._adapter = selected.entries[0]
    for assertion, source in (
        (bytearray(ASSERTION), INPUT),
        (ASSERTION, memoryview(INPUT)),
        (b"x" * (64 * 1024 + 1), INPUT),
        (ASSERTION, b"x" * (256 * 1024 + 1)),
    ):
        with pytest.raises(ValidationError):
            api.prepare_observation(
                journal,
                authority,
                selected,
                assertion,
                source,
                expected_plan_head=journal.head_digest,
                request_id="request-2",
            )
    assert calls == []
    assert api.run_observation(intent, registry=selected).observed_bytes == b"revision-B"


def test_post_return_append_failure_keeps_old_head_and_retains_measured_bytes(monkeypatch):
    _, _, journal, selected, intent = prepared(lambda _: b"revision-B")
    original_append = api.CaseJournal.append

    def failing_append(self, records, *, authority, expected=None):
        if self is journal:
            raise ValidationError("private append detail")
        return original_append(self, records, authority=authority, expected=expected)

    monkeypatch.setattr(api.CaseJournal, "append", failing_append)
    with pytest.raises(api.ObservationPublicationError) as raised:
        api.run_observation(intent, registry=selected)
    assert raised.value.observed_bytes == b"revision-B"
    assert "private append detail" not in str(raised.value)
    assert journal.checkpoint.record_count == 1
    with pytest.raises(ValidationError, match="consumed"):
        api.run_observation(intent, registry=selected)


def test_total_limit_is_checked_before_and_after_callback():
    calls = []
    authority, _, journal = case()
    too_small = registry(
        lambda raw: calls.append(raw) or b"revision-B",
        limits=api.ObservationLimits(total_bytes=len(ASSERTION) + len(INPUT) - 1),
    )
    with pytest.raises(ValidationError):
        api.prepare_observation(
            journal,
            authority,
            too_small,
            ASSERTION,
            INPUT,
            expected_plan_head=journal.head_digest,
            request_id="request-3",
        )
    assert calls == []
    after_return = registry(
        lambda raw: calls.append(raw) or b"revision-B",
        limits=api.ObservationLimits(total_bytes=len(ASSERTION) + len(INPUT) + 9),
    )
    intent = api.prepare_observation(
        journal,
        authority,
        after_return,
        ASSERTION,
        INPUT,
        expected_plan_head=journal.head_digest,
        request_id="request-4",
    )
    retained = api.run_observation(intent, registry=after_return)
    assert calls == [INPUT]
    assert retained.observation.status is api.CaseObservationStatus.ERROR
    assert retained.observed_bytes is None
