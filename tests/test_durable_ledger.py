from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from evidence_braid import (
    EvidenceEvent,
    EvidenceLedger,
    LedgerEntry,
    SQLiteLedger,
    build_ledger,
    load_ledger,
    write_ledger,
)
from evidence_braid.cli import run
from evidence_braid.errors import InputFormatError, ValidationError
from evidence_braid.io import canonical_json


def event(identifier: str = "e1", **overrides: Any) -> EvidenceEvent:
    data = {
        "event_id": identifier,
        "claim": "door-open",
        "source": "door-camera",
        "modality": "vision",
        "signal": "support",
        "confidence": 0.85,
        "observed_at": "2026-09-01T10:00:00Z",
        "ingested_at": "2026-09-01T10:01:00Z",
        "attributes": {"images": [{"id": "frame-1"}]},
    }
    return EvidenceEvent.from_dict({**data, **overrides})


def test_v2_hash_matches_independent_definition_and_receipt_is_immutable() -> None:
    observed = event()
    ledger = build_ledger([observed])
    genesis = hashlib.sha256(b"evidence-braid-ledger:v2").hexdigest()
    envelope = {
        "schema_version": "2.0",
        "sequence": 0,
        "previous_digest": genesis,
        "event": observed.to_dict(),
    }
    encoded = json.dumps(
        envelope, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    )
    assert ledger.head_digest == hashlib.sha256(encoded.encode()).hexdigest()
    assert EvidenceLedger.from_dict(json.loads(json.dumps(ledger.to_dict()))) == ledger
    with pytest.raises(TypeError):
        ledger.entries[0].event["attributes"]["images"][0]["id"] = "changed"
    detached = ledger.to_dict()
    detached["entries"][0]["event"]["attributes"]["images"][0]["id"] = "changed"
    assert ledger.verify()
    assert ledger.entries[0].event["attributes"]["images"][0]["id"] == "frame-1"


def test_v1_receipts_remain_readable_without_silently_rehashing() -> None:
    observed = event()
    genesis = hashlib.sha256(b"evidence-braid-ledger:v1").hexdigest()
    digest = hashlib.sha256(
        (genesis + "\n" + canonical_json(observed.to_dict(), pretty=False)).encode()
    ).hexdigest()
    old = EvidenceLedger((LedgerEntry(0, observed.event_id, observed.to_dict(), genesis, digest),))
    restored = EvidenceLedger.from_dict(old.to_dict(), expected_head=digest)
    assert restored.schema_version == "1.0"
    assert restored.head_digest == digest


@pytest.mark.parametrize(
    "path,value",
    [
        (("schema_version",), "3.0"),
        (("schema_version",), []),
        (("kind",), "other"),
        (("genesis",), "0" * 64),
        (("entry_count",), True),
        (("entry_count",), 2),
        (("entries",), {}),
        (("verified",), False),
        (("verified",), 1),
        (("head_digest",), "f" * 64),
        (("extra",), "unexpected"),
        (("entries", 0, "sequence"), True),
        (("entries", 0, "sequence"), -1),
        (("entries", 0, "sequence"), 1),
        (("entries", 0, "event_id"), "other"),
        (("entries", 0, "digest"), "ABC"),
        (("entries", 0, "previous_digest"), "a" * 64),
        (("entries", 0, "digest"), "b" * 64),
        (("entries", 0, "event", "source"), " door-camera "),
        (("entries", 0, "event", "confidence"), 0.2),
        (("entries", 0, "event", "observed_at"), "2026-09-01T10:00:00+00:00"),
        (("entries", 0, "event", "unknown"), True),
    ],
)
def test_reader_rejects_malformed_and_mutated_documents(path: tuple[Any, ...], value: Any) -> None:
    document = build_ledger([event()]).to_dict()
    target = document
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value
    with pytest.raises(ValidationError):
        EvidenceLedger.from_dict(document)


def test_chain_removal_reorder_and_replacement_anchor() -> None:
    full = build_ledger([event("a"), event("b")])
    document = full.to_dict()
    document["entries"].reverse()
    with pytest.raises(ValidationError):
        EvidenceLedger.from_dict(document)
    prefix = build_ledger([event("a")])
    # A valid prefix verifies internally; a trusted retained head detects rollback.
    assert prefix.verify()
    assert not prefix.verify(expected_head=full.head_digest)
    with pytest.raises(ValidationError):
        EvidenceLedger.from_dict(prefix.to_dict(), expected_head=full.head_digest)
    replacement = build_ledger([event("a", confidence=0.01), event("b")])
    assert replacement.verify()
    assert not replacement.verify(expected_head=full.head_digest)


def test_empty_ledger_round_trip_and_snapshot_alias_isolation(tmp_path: Path) -> None:
    path = tmp_path / "empty.json"
    empty = build_ledger([])
    write_ledger(path, empty)
    assert load_ledger(path) == empty
    document = event().to_dict()
    entry = LedgerEntry(0, "e1", document, "0" * 64, "0" * 64)
    document["attributes"]["images"].append({"id": "second"})
    assert len(entry.event["attributes"]["images"]) == 1
    entries = [entry]
    snapshot = EvidenceLedger(entries)  # type: ignore[arg-type]
    entries.clear()
    assert len(snapshot.entries) == 1


def test_reopen_append_order_and_portable_import(tmp_path: Path) -> None:
    path = tmp_path / "records.db"
    store = SQLiteLedger(path)
    first = store.append([event("z")])
    second = SQLiteLedger(path, create=False).append([event("a")], expected_head=first.head_digest)
    assert [item.event_id for item in second.entries] == ["z", "a"]
    assert second.entries[:1] == first.entries
    assert SQLiteLedger(path).snapshot(expected_head=second.head_digest) == second
    exported = tmp_path / "receipt.json"
    write_ledger(exported, second)
    restored = SQLiteLedger(tmp_path / "restored.db").import_snapshot(load_ledger(exported))
    assert restored.to_dict() == second.to_dict()
    assert store.append([]) == second
    with pytest.raises(ValidationError, match="empty"):
        store.import_snapshot(second)


def test_multiple_writers_serialize_without_losing_events(tmp_path: Path) -> None:
    path = tmp_path / "concurrent.db"
    SQLiteLedger(path)

    def append_one(index: int) -> None:
        SQLiteLedger(path, create=False).append([event(str(index))])

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(append_one, range(16)))
    result = SQLiteLedger(path).snapshot()
    assert {entry.event_id for entry in result.entries} == {str(index) for index in range(16)}
    assert [entry.sequence for entry in result.entries] == list(range(16))
    assert result.verify()


def test_independent_processes_commit_and_reopen(tmp_path: Path) -> None:
    path = tmp_path / "processes.db"
    SQLiteLedger(path)
    code = (
        "import json,sys; from evidence_braid import SQLiteLedger,EvidenceEvent; "
        "SQLiteLedger(sys.argv[1],create=False).append([EvidenceEvent.from_dict(json.loads(sys.argv[2]))])"
    )
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", code, str(path), json.dumps(event(str(i)).to_dict())],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for i in range(4)
    ]
    for process in processes:
        stdout, stderr = process.communicate(timeout=30)
        assert process.returncode == 0, (stdout, stderr)
    assert {entry.event_id for entry in SQLiteLedger(path).snapshot().entries} == {
        "0",
        "1",
        "2",
        "3",
    }


def test_duplicate_batch_rolls_back_inserted_prefix_and_metadata(tmp_path: Path) -> None:
    store = SQLiteLedger(tmp_path / "rollback.db")
    before = store.append([event("original")])
    with pytest.raises(InputFormatError, match="UNIQUE"):
        store.append([event("new"), event("original")])
    assert store.snapshot() == before
    with pytest.raises(InputFormatError, match="UNIQUE"):
        store.append([event("same"), event("same")])
    assert store.snapshot() == before
    assert store.append([event("new")]).entries[-1].sequence == 1


def test_process_death_before_commit_rolls_back(tmp_path: Path) -> None:
    path = tmp_path / "crash.db"
    original = SQLiteLedger(path).append([event()])
    code = (
        "import sqlite3,sys,os; c=sqlite3.connect(sys.argv[1]); c.execute('BEGIN IMMEDIATE'); "
        'c.execute("UPDATE ledger_meta SET entries=999"); os._exit(23)'
    )
    process = subprocess.run([sys.executable, "-c", code, str(path)], check=False, timeout=30)
    assert process.returncode == 23
    assert SQLiteLedger(path, create=False).snapshot() == original


def test_stale_head_and_invalid_batch_never_write(tmp_path: Path) -> None:
    store = SQLiteLedger(tmp_path / "conflict.db")
    empty = store.snapshot()
    original = store.append([event()])
    with pytest.raises(ValidationError, match="stale"):
        store.append([event("new")], expected_head=empty.head_digest)
    with pytest.raises(ValidationError, match="expected head"):
        store.snapshot(expected_head=empty.head_digest)
    with pytest.raises(ValidationError):
        store.append([event("new"), object()])  # type: ignore[list-item]
    with pytest.raises(ValidationError):
        store.snapshot(expected_head="bad")
    assert store.snapshot() == original


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE ledger_entries SET digest='bad'",
        "DELETE FROM ledger_entries",
    ],
)
def test_regular_sql_update_and_delete_are_refused(tmp_path: Path, sql: str) -> None:
    path = tmp_path / "protected.db"
    store = SQLiteLedger(path)
    before = store.append([event()])
    with (
        closing(sqlite3.connect(path)) as connection,
        connection,
        pytest.raises(sqlite3.IntegrityError, match="append-only"),
    ):
        connection.execute(sql)
    assert store.snapshot() == before


@pytest.mark.parametrize(
    "mutation",
    [
        "UPDATE ledger_entries SET event='not-json'",
        'UPDATE ledger_entries SET event=\'{"event_id":"e1","event_id":"e1"}\'',
        "UPDATE ledger_entries SET digest='" + "f" * 64 + "'",
        "UPDATE ledger_meta SET entries=0",
        "UPDATE ledger_meta SET version='99.0'",
        "DELETE FROM ledger_entries",
        "DELETE FROM ledger_meta",
    ],
)
def test_tampering_is_detected_before_further_append(tmp_path: Path, mutation: str) -> None:
    path = tmp_path / "tampered.db"
    store = SQLiteLedger(path)
    store.append([event()])
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute("DROP TRIGGER ledger_no_update")
        connection.execute("DROP TRIGGER ledger_no_delete")
        connection.execute(mutation)
    with pytest.raises((ValidationError, InputFormatError)):
        store.snapshot()
    with pytest.raises((ValidationError, InputFormatError)):
        store.append([event("new")])


def test_writer_lock_timeout_is_a_domain_error(tmp_path: Path) -> None:
    path = tmp_path / "busy.db"
    store = SQLiteLedger(path, timeout=0.01)
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        with pytest.raises(InputFormatError, match="locked"):
            store.append([event()])
    assert not store.snapshot().entries


@pytest.mark.parametrize(
    "kwargs",
    [
        {"create": 1},
        {"timeout": -1},
        {"timeout": True},
        {"timeout": float("inf")},
        {"timeout": float("nan")},
        {"timeout": 10**1000},
        {"timeout": 61},
    ],
)
def test_invalid_store_options_do_not_create_files(tmp_path: Path, kwargs: dict[str, Any]) -> None:
    path = tmp_path / "absent.db"
    with pytest.raises(ValidationError):
        SQLiteLedger(path, **kwargs)
    assert not path.exists()


def test_missing_and_unrelated_databases_are_refused(tmp_path: Path) -> None:
    path = tmp_path / "absent.db"
    with pytest.raises(InputFormatError):
        SQLiteLedger(path, create=False)
    assert not path.exists()
    unrelated = tmp_path / "unrelated.db"
    with closing(sqlite3.connect(unrelated)) as connection, connection:
        connection.execute("CREATE TABLE important (value TEXT)")
        connection.execute("INSERT INTO important VALUES ('keep')")
    before = unrelated.read_bytes()
    with pytest.raises(ValidationError, match="not an Evidence"):
        SQLiteLedger(unrelated)
    assert unrelated.read_bytes() == before
    views = tmp_path / "views.db"
    with closing(sqlite3.connect(views)) as connection, connection:
        connection.execute("CREATE VIEW settings AS SELECT 'keep' AS value")
    before = views.read_bytes()
    with pytest.raises(ValidationError, match="not an Evidence"):
        SQLiteLedger(views)
    assert views.read_bytes() == before


def test_interchange_rejects_invalid_json_and_invalid_chains(tmp_path: Path) -> None:
    path = tmp_path / "input.json"
    for content in ('{"entries":[],"entries":[]}', '{"number":NaN}', "not-json"):
        path.write_text(content, encoding="utf-8")
        with pytest.raises(InputFormatError):
            load_ledger(path)
    invalid = EvidenceLedger((), "bad")
    with pytest.raises(ValidationError):
        write_ledger(path, invalid)
    store = SQLiteLedger(tmp_path / "import.db")
    with pytest.raises(ValidationError):
        store.import_snapshot(invalid)


def test_cli_append_verify_export_import_and_failures(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "events.jsonl"
    source.write_text(json.dumps(event().to_dict()) + "\n", encoding="utf-8")
    database = tmp_path / "cli.db"
    assert run(["ledger", "append", str(database), str(source)]) == 0
    head = json.loads(capsys.readouterr().out)["head_digest"]
    assert run(["ledger", "verify", str(database), "--expected-head", head]) == 0
    assert json.loads(capsys.readouterr().out)["entry_count"] == 1
    exported = tmp_path / "export.json"
    assert run(["ledger", "export", str(database), "--output", str(exported)]) == 0
    imported = tmp_path / "import.db"
    assert run(["ledger", "import", str(imported), str(exported), "--expected-head", head]) == 0
    assert json.loads(capsys.readouterr().out)["head_digest"] == head
    assert run(["ledger", "export", str(database), "--output", str(database)]) == 2
    assert "must not overwrite" in capsys.readouterr().err
    assert run(["ledger", "verify", str(tmp_path / "missing.db")]) == 2
    assert "operation failed" in capsys.readouterr().err
    assert run(["ledger", "append", str(database), str(source)]) == 2
    assert "UNIQUE" in capsys.readouterr().err
    assert SQLiteLedger(database).snapshot().head_digest == head


def test_limits_roll_back_oversized_import_and_preserve_existing_export(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from evidence_braid import storage

    ledger = build_ledger([event()])
    store = SQLiteLedger(tmp_path / "bounds.db")
    monkeypatch.setattr(storage, "MAX_ENTRY_BYTES", 5)
    with pytest.raises(ValidationError, match="limits"):
        store.append([event()])
    with pytest.raises(ValidationError, match="limits"):
        store.import_snapshot(ledger)
    assert not store.snapshot().entries
    monkeypatch.setattr(storage, "MAX_LEDGER_BYTES", 5)
    destination = tmp_path / "preserve.json"
    destination.write_text("preserve", encoding="utf-8")
    with pytest.raises(ValidationError, match="limit"):
        write_ledger(destination, ledger)
    assert destination.read_text(encoding="utf-8") == "preserve"
    with pytest.raises(InputFormatError, match="limit"):
        load_ledger(destination)


def test_duplicate_chain_rejected_even_with_recomputed_hashes() -> None:
    document = build_ledger([event("a"), event("b")]).to_dict()
    document["entries"][1]["event"] = deepcopy(document["entries"][0]["event"])
    document["entries"][1]["event_id"] = "a"
    with pytest.raises(ValidationError):
        EvidenceLedger.from_dict(document)


def test_direct_receipt_verification_fails_closed() -> None:
    original = build_ledger([event()])
    assert not replace(original, entries=(object(),)).verify()  # type: ignore[arg-type]
    assert not replace(original, schema_version=[]).verify()  # type: ignore[arg-type]
    assert not replace(original, entries=(replace(original.entries[0], event={}),)).verify()
    assert not replace(original, entries=(replace(original.entries[0], sequence=True),)).verify()


def test_count_and_cumulative_byte_limits_are_enforced_before_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from evidence_braid import ledger, storage

    store = SQLiteLedger(tmp_path / "counts.db")
    before = store.append([event("first")])
    monkeypatch.setattr(storage, "MAX_LEDGER_ENTRIES", 1)
    with pytest.raises(ValidationError, match="entry limit"):
        store.append([event("second")])
    assert store.snapshot() == before
    monkeypatch.setattr(storage, "MAX_LEDGER_ENTRIES", 100_000)
    monkeypatch.setattr(storage, "MAX_APPEND_ENTRIES", 1)
    with pytest.raises(ValidationError, match="limits"):
        store.append([event("second"), event("third")])
    size = len(canonical_json(event("first").to_dict(), pretty=False).encode())
    monkeypatch.setattr(storage, "MAX_LEDGER_BYTES", size + 1)
    with pytest.raises(ValidationError, match="byte limit"):
        store.append([event("second")])
    assert store.snapshot() == before
    monkeypatch.setattr(ledger, "MAX_LEDGER_ENTRIES", 0)
    assert not before.verify()
    with pytest.raises(ValidationError, match="maximum"):
        build_ledger([event()])


def test_cli_refuses_oversized_export_without_replacing_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from evidence_braid import cli

    database = tmp_path / "large.db"
    SQLiteLedger(database).append([event()])
    destination = tmp_path / "output.json"
    destination.write_text("keep", encoding="utf-8")
    monkeypatch.setattr(cli, "MAX_LEDGER_BYTES", 5)
    assert run(["ledger", "export", str(database), "--output", str(destination)]) == 2
    assert "limit" in capsys.readouterr().err
    assert destination.read_text(encoding="utf-8") == "keep"
