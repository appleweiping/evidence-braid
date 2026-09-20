"""Offline, installed-package smoke for durable case claim and byte verification."""

from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

from evidence_braid import (
    CaseActor,
    CaseActorKind,
    CaseAuthority,
    CaseGrant,
    CaseJournal,
    CasePlan,
    CaseRole,
    CaseVerdict,
    CaseVerdictOutcome,
    ObservationAdapter,
    ObservationRegistry,
    SQLiteCaseStore,
    create_case_store,
)


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def run_fixture() -> tuple[str, str, str]:
    assertion = b"The cache is stale."
    test_input = b'{"incident":"cache","revision":"B"}'
    observed = b"revision-B"
    authority = CaseAuthority(
        "offline-case-policy",
        (
            CaseActor("model", CaseActorKind.MODEL, (CaseGrant("site/a", CaseRole.PROPOSE),)),
            CaseActor("observer", CaseActorKind.TOOL, (CaseGrant("site/a", CaseRole.OBSERVE),)),
            CaseActor("evaluator", CaseActorKind.TOOL, (CaseGrant("site/a", CaseRole.EVALUATE),)),
        ),
    )
    plan = CasePlan(
        "case-1",
        "workflow-1",
        "claim-1",
        "site/a",
        "model",
        "assertion-1",
        _sha(assertion),
        "The report cache is stale.",
        "A bypass should show the source revision.",
        "revision-B",
        "input-1",
        _sha(test_input),
        _sha(observed),
        "cache-bypass",
        "fixture-cache",
        "1",
        "sha256-equality-v1",
        authority.digest,
    )
    planned = CaseJournal.empty(authority).append((plan,), authority=authority)

    def adapter(raw: bytes) -> bytes:
        if raw != test_input:
            raise ValueError("unexpected committed fixture input")
        return observed

    registry = ObservationRegistry(
        (
            ObservationAdapter(
                "cache-bypass",
                "fixture-cache",
                "1",
                "observer",
                adapter,
            ),
        )
    )
    with tempfile.TemporaryDirectory(prefix="evidence-case-") as temporary:
        path = Path(temporary) / "case.db"
        store = create_case_store(
            path,
            planned,
            authority=authority,
            expected_plan_head=planned.head_digest,
            assertion_bytes=assertion,
            input_bytes=test_input,
        )
        before = store.snapshot().checkpoint
        claim_digest = store.claim_request_digest(registry, request_id="run-1", expected=before)
        finished = store.execute_observation(
            registry,
            request_id="run-1",
            finish_id="finish-1",
            expected=before,
        )
        reopened = SQLiteCaseStore(
            path,
            authority=authority,
            expected_plan_head=planned.head_digest,
            expected=finished.result.checkpoint,
        )
        claimed = reopened.lookup("run-1", expected_request_digest=claim_digest)
        if claimed is None or claimed.result.pending_request_id != "run-1":
            raise RuntimeError("durable claim lookup failed")
        snapshot = reopened.snapshot(expected=finished.result.checkpoint)
        if snapshot.observed_bytes != observed or _sha(snapshot.observed_bytes) != _sha(observed):
            raise RuntimeError("durable measured output differs")
        verdict = reopened.append_checked_verdict(
            operation_id="verdict-1",
            evaluator_id="evaluator",
            expected=finished.result.checkpoint,
        )
        final = verdict.result.journal.receipts[2].record
        if type(final) is not CaseVerdict or final.outcome is not CaseVerdictOutcome.SUPPORTED:
            raise RuntimeError("reopened checked verdict differs")
        return planned.head_digest, snapshot.journal.head_digest, verdict.result.journal.head_digest


def main() -> None:
    plan_head, observation_head, verdict_head = run_fixture()
    print(f"plan={plan_head}")
    print(f"observation={observation_head}")
    print(f"verdict={verdict_head}")
    print("outcome=supported")


if __name__ == "__main__":
    main()
