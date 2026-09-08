from __future__ import annotations

import base64
import json
import random
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from evidence_braid import (
    EvidenceEvent,
    EvidenceLedger,
    Modality,
    Signal,
    SQLiteLedger,
    build_ledger,
)
from evidence_braid.errors import ValidationError
from evidence_braid.query import LedgerIndex, LedgerPage, LedgerQuery, LedgerSelection

BASE = datetime(2026, 9, 1, tzinfo=UTC)


def event(number: int, **overrides: Any) -> EvidenceEvent:
    return EvidenceEvent(
        event_id=f"event-{number}",
        claim=f"claim-{number % 3}",
        source=f"source-{number % 4}",
        modality=tuple(Modality)[number % 4],
        signal=tuple(Signal)[number % 2],
        confidence=0.75,
        observed_at=BASE + timedelta(seconds=number % 5),
        ingested_at=BASE + timedelta(seconds=number),
        correlation_group=f"group-{number % 2}",
        attributes=overrides,
    )


def index(count: int = 20) -> LedgerIndex:
    ledger = build_ledger(event(number) for number in range(count))
    return LedgerIndex(ledger, expected_head=ledger.head_digest)


def collect(selection: LedgerSelection, **kwargs: Any) -> list[int]:
    result = []
    cursor = None
    while True:
        page = selection.page(cursor=cursor, **kwargs)
        result.extend(entry.sequence for entry in page.entries)
        cursor = page.next_cursor
        if cursor is None:
            return result


def test_exact_or_and_filters_and_chronology_are_independent() -> None:
    snapshot = index()
    query = LedgerQuery(
        claims=("claim-2", "claim-0"),
        sources=("source-0", "source-2"),
        modalities=(Modality.VISION, Modality.TEXT),
        signals=(Signal.SUPPORT,),
        correlation_groups=("group-0",),
        observed_start=BASE + timedelta(seconds=1),
        observed_end=BASE + timedelta(seconds=4),
    )
    expected = [n for n in range(20) if n % 3 in (0, 2) and n % 4 in (0, 2) and 1 <= n % 5 < 4]
    chosen = snapshot.select(query)
    assert collect(chosen, limit=2) == expected
    assert chosen.page().total_matches == len(expected)
    assert snapshot.select(LedgerQuery(event_ids=("event-13",))).positions == (13,)
    assert snapshot.select(LedgerQuery(claims=("absent",))).page().entries == ()
    assert snapshot.select(
        LedgerQuery(
            ingested_start=BASE + timedelta(seconds=5), ingested_end=BASE + timedelta(seconds=8)
        )
    ).positions == (5, 6, 7)


def test_seeded_query_oracle_matches_independent_linear_scan() -> None:
    snapshot = index(101)
    rng = random.Random(741)
    for _ in range(120):
        claims = tuple(f"claim-{n}" for n in rng.sample(range(3), rng.randrange(4)))
        sources = tuple(f"source-{n}" for n in rng.sample(range(4), rng.randrange(5)))
        lower, upper = sorted(rng.sample(range(102), 2))
        query = LedgerQuery(
            claims=claims,
            sources=sources,
            ingested_start=BASE + timedelta(seconds=lower),
            ingested_end=BASE + timedelta(seconds=upper),
        )
        expected = [
            n
            for n in range(101)
            if (not claims or f"claim-{n % 3}" in claims)
            and (not sources or f"source-{n % 4}" in sources)
            and lower <= n < upper
        ]
        assert collect(snapshot.select(query), limit=rng.randint(1, 13)) == expected


def test_timezones_canonical_query_and_immutable_storage() -> None:
    first = LedgerQuery(claims=("b", "a"), ingested_start=BASE)
    second = LedgerQuery(
        claims=("a", "b"), ingested_start=BASE.astimezone(timezone(timedelta(hours=5)))
    )
    assert first == second
    assert first.identity == second.identity
    copied = first.to_dict()
    copied["claims"].clear()
    assert first.claims == ("a", "b")
    snapshot = index()
    with pytest.raises(FrozenInstanceError):
        snapshot.ledger = build_ledger([])
    with pytest.raises(TypeError):
        snapshot._postings["claim"]["new"] = (0,)
    page = snapshot.select().page(limit=1)
    detached = page.to_dict()
    detached["entries"][0]["event"]["claim"] = "changed"
    assert page.entries[0].event["claim"] == "claim-0"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"claims": ["a"]},
        {"claims": ("",)},
        {"claims": (" a",)},
        {"claims": ("a", "a")},
        {"claims": (1,)},
        {"claims": ("x" * 4097,)},
        {"claims": ("中" * 1366,)},
        {"claims": ("\ud800",)},
        {"sources": tuple(str(n) for n in range(129))},
        {"signals": ("support",)},
        {"signals": (Signal.SUPPORT, Signal.SUPPORT)},
        {"modalities": [Modality.TEXT]},
        {"modalities": (Signal.SUPPORT,)},
        {"observed_start": "2026-09-01"},
        {"observed_end": BASE.replace(tzinfo=None)},
        {"observed_start": BASE, "observed_end": BASE},
        {"ingested_start": BASE, "ingested_end": BASE - timedelta(seconds=1)},
        {"claims": tuple(str(n) + "x" * 4090 for n in range(17))},
    ],
)
def test_query_rejects_malformed_and_excessive_filters(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        LedgerQuery(**kwargs)


def test_byte_budget_is_exact_utf8_and_never_skips_large_receipt() -> None:
    ledger = build_ledger([event(0, note="中文"), event(1, note="🙂")])
    selected = LedgerIndex(ledger, expected_head=ledger.head_digest).select()
    first_size = len(
        json.dumps(
            ledger.entries[0].to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode()
    )
    page = selected.page(max_entry_bytes=first_size)
    assert page.entry_bytes == first_size
    assert len(page.entries) == 1
    assert collect(selected, max_entry_bytes=first_size) == [0, 1]
    with pytest.raises(ValidationError, match="next receipt"):
        selected.page(max_entry_bytes=first_size - 1)
    assert selected.page(cursor=page.next_cursor).entries == (ledger.entries[1],)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"limit": True},
        {"limit": 0},
        {"limit": 1001},
        {"limit": 2.0},
        {"max_entry_bytes": 0},
        {"max_entry_bytes": True},
        {"max_entry_bytes": 16 * 1024 * 1024 + 1},
    ],
)
def test_page_limits(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        index().select().page(**kwargs)


def test_cursor_is_bound_to_head_query_count_and_version() -> None:
    snapshot = index()
    selected = snapshot.select()
    cursor = selected.page(limit=3).next_cursor
    assert cursor is not None
    assert selected.page(cursor=cursor, limit=1).entries[0].sequence == 3
    assert LedgerIndex(snapshot.ledger, expected_head=snapshot.ledger.head_digest).select().page(
        cursor=cursor, limit=1
    ) == selected.page(cursor=cursor, limit=1)
    with pytest.raises(ValidationError):
        snapshot.select(LedgerQuery(sources=("source-0",))).page(cursor=cursor)
    with pytest.raises(ValidationError):
        index(21).select().page(cursor=cursor)
    document = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
    for key, value in [
        ("head", "0" * 64),
        ("entries", 19),
        ("query", "0" * 64),
        ("ledger_version", "1.0"),
        ("schema_version", "2.0"),
        ("next_sequence", True),
        ("next_sequence", -1),
        ("next_sequence", 21),
        ("extra", None),
    ]:
        altered = {**document, key: value}
        token = (
            base64.urlsafe_b64encode(
                json.dumps(altered, sort_keys=True, separators=(",", ":")).encode()
            )
            .decode()
            .rstrip("=")
        )
        with pytest.raises(ValidationError):
            selected.page(cursor=token)


@pytest.mark.parametrize(
    "token",
    ["", "=", "bad!", "a", "x" * 2049, "中文", 42, True, "W10", "eyJhIjoxLCJhIjoyfQ", "////"],
)
def test_bad_cursor_is_domain_error(token: Any) -> None:
    with pytest.raises(ValidationError):
        index().select().page(cursor=token)


def test_snapshot_pagination_survives_backdated_append_and_restart(tmp_path: Path) -> None:
    store = SQLiteLedger(tmp_path / "events.sqlite")
    original = store.append(event(n) for n in range(8))
    selected = LedgerIndex(original, expected_head=original.head_digest).select()
    cursor = selected.page(limit=3).next_cursor
    store.append([replace(event(8), ingested_at=BASE - timedelta(days=1))])
    assert collect(selected, limit=2) == list(range(8))
    latest = SQLiteLedger(store.path, create=False).snapshot()
    restored = LedgerIndex(latest, expected_head=original.head_digest, prefix_count=8).select()
    assert restored.page(cursor=cursor) == selected.page(cursor=cursor)
    assert LedgerIndex(latest, expected_head=latest.head_digest).select().positions == tuple(
        range(9)
    )
    with pytest.raises(ValidationError):
        LedgerIndex(latest, expected_head=original.head_digest)
    with pytest.raises(ValidationError):
        LedgerIndex(latest, expected_head=original.head_digest, prefix_count=7)
    corrupted = replace(
        latest, entries=(*latest.entries[:-1], replace(latest.entries[-1], digest="0" * 64))
    )
    with pytest.raises(ValidationError):
        LedgerIndex(corrupted, expected_head=original.head_digest, prefix_count=8)


def test_empty_snapshot_and_invalid_index_inputs(monkeypatch: pytest.MonkeyPatch) -> None:
    empty = index(0)
    page = empty.select().page(limit=1)
    assert page.entries == () and page.next_cursor is None and page.entry_bytes == 0
    assert page.to_dict()["total_matches"] == 0
    for value in (True, -1, 1, 1.0):
        with pytest.raises(ValidationError):
            LedgerIndex(empty.ledger, expected_head=empty.ledger.head_digest, prefix_count=value)
    for ledger in (None, replace(empty.ledger, genesis="0" * 64)):
        with pytest.raises(ValidationError):
            LedgerIndex(ledger, expected_head=empty.ledger.head_digest)
    with pytest.raises(ValidationError):
        LedgerIndex(empty.ledger, expected_head="invalid")
    with pytest.raises(ValidationError):
        LedgerSelection(empty, {})
    with pytest.raises(ValidationError):
        LedgerSelection(None, LedgerQuery())
    monkeypatch.setattr("evidence_braid.query._MAX_INDEX_BYTES", 1)
    with pytest.raises(ValidationError, match="indexed receipt bytes"):
        index(1)


@pytest.mark.parametrize(
    "change",
    [
        {"head_digest": "bad"},
        {"snapshot_entries": True},
        {"total_matches": 1000},
        {"entry_bytes": 0},
        {"next_cursor": ""},
        {"next_cursor": 42},
        {"entries": []},
        {"entries": (None,)},
    ],
)
def test_direct_page_consistency(change: dict[str, Any]) -> None:
    page = index(2).select().page(limit=1)
    with pytest.raises(ValidationError):
        replace(page, **change)


def test_page_rejects_decreasing_or_outside_receipts() -> None:
    page = index(2).select().page()
    with pytest.raises(ValidationError):
        replace(page, entries=tuple(reversed(page.entries)))
    with pytest.raises(ValidationError):
        LedgerPage(
            page.entries, page.head_digest, 1, 1, page.entry_bytes, None, page.query_identity
        )


def test_v1_prefix_remains_a_v1_chain() -> None:
    import hashlib

    from evidence_braid import LedgerEntry
    from evidence_braid.io import canonical_json

    item = event(0)
    genesis = hashlib.sha256(b"evidence-braid-ledger:v1").hexdigest()
    digest = hashlib.sha256(
        (genesis + "\n" + canonical_json(item.to_dict(), pretty=False)).encode()
    ).hexdigest()
    ledger = EvidenceLedger((LedgerEntry(0, item.event_id, item.to_dict(), genesis, digest),))
    selected = LedgerIndex(ledger, expected_head=digest).select()
    assert selected.index.ledger.schema_version == "1.0"
    assert selected.page().entries == ledger.entries


def test_cli_fixed_prefix_filters_cursor_and_failures(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from evidence_braid.cli import run

    store = SQLiteLedger(tmp_path / "ledger.sqlite")
    ledger = store.append(event(n) for n in range(12))
    arguments = [
        "ledger-query",
        str(store.path),
        "--expected-head",
        ledger.head_digest,
        "--source",
        "source-0",
        "--modality",
        "vision",
        "--signal",
        "support",
        "--correlation-group",
        "group-0",
        "--claim",
        "claim-0",
        "--limit",
        "1",
        "--observed-start",
        BASE.isoformat(),
        "--observed-end",
        (BASE + timedelta(days=1)).isoformat(),
        "--ingested-start",
        BASE.isoformat(),
        "--ingested-end",
        (BASE + timedelta(days=1)).isoformat(),
    ]
    assert run(arguments) == 0
    first = json.loads(capsys.readouterr().out)
    assert first["entries"][0]["event_id"] == "event-0" and first["total_matches"] == 1
    basic = ["ledger-query", str(store.path), "--expected-head", ledger.head_digest, "--limit", "2"]
    assert run(basic) == 0
    first = json.loads(capsys.readouterr().out)
    store.append([event(12)])
    assert run([*basic, "--prefix-count", "12", "--cursor", first["next_cursor"]]) == 0
    assert json.loads(capsys.readouterr().out)["entries"][0]["sequence"] == 2
    assert run([*basic, "--cursor", first["next_cursor"]]) == 2
    assert not capsys.readouterr().out
    assert run([*basic, "--prefix-count", "12", "--event-id", "event-11"]) == 0
    assert json.loads(capsys.readouterr().out)["total_matches"] == 1
    assert run([*basic, "--observed-start", "not-time"]) == 2
    assert not capsys.readouterr().out
    absent = tmp_path / "absent.sqlite"
    assert run(["ledger-query", str(absent), "--expected-head", ledger.head_digest]) == 2
    assert not absent.exists()


def test_receipt_limit_covers_tail_even_when_reopening_small_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    small = index(2).ledger
    monkeypatch.setattr(
        "evidence_braid.query._MAX_INDEX_BYTES",
        len(json.dumps(small.entries[0].to_dict()).encode()) + 1,
    )
    with pytest.raises(ValidationError, match="indexed receipt bytes"):
        LedgerIndex(small, expected_head=small.entries[0].digest, prefix_count=1)
    with pytest.raises(ValidationError):
        LedgerIndex(replace(small, entries=(None,)), expected_head=small.head_digest)


def test_absent_groups_and_parallel_reads_do_not_block_writer(tmp_path: Path) -> None:
    from concurrent.futures import ThreadPoolExecutor

    store = SQLiteLedger(tmp_path / "history.sqlite")
    snapshot = store.append([replace(event(n), correlation_group=None) for n in range(20)])
    selected = LedgerIndex(snapshot, expected_head=snapshot.head_digest).select()
    assert selected.index.select(LedgerQuery(correlation_groups=("group-0",))).positions == ()
    with ThreadPoolExecutor(max_workers=3) as pool:
        reading = pool.submit(collect, selected, limit=2)
        writing = pool.submit(store.append, [event(20)])
        assert writing.result(timeout=10).entries[-1].sequence == 20
        assert reading.result(timeout=10) == list(range(20))
    assert selected.index.ledger.head_digest == snapshot.head_digest
