"""Closed filesystem publication with real no-replace and ownership checks."""

import ctypes
import errno
import json
import os
import stat
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from pathlib import Path
from threading import Barrier
from types import SimpleNamespace

import pytest

import evidence_braid as api
from evidence_braid import schema_directory as module
from evidence_braid._schema_shapes import generated_resources
from evidence_braid.cli import run
from evidence_braid.errors import InputFormatError


def exported(tmp_path):
    return api.export_schema_directory(tmp_path / "publication")


def check(result):
    return api.verify_schema_directory(
        result.destination, expected_catalog_digest=result.catalog_digest
    )


def stat_copy(value, **changes):
    fields = {name: getattr(value, name) for name in dir(value) if name.startswith("st_")}
    return SimpleNamespace(**(fields | changes))


def test_real_directory_export_matches_unchanged_resource_bytes_and_verifies(tmp_path):
    result = api.export_schema_directory(tmp_path / "publication")
    assert result.resource_count == 10
    expected = generated_resources()
    assert result.size_bytes == sum(map(len, expected.values()))
    assert [item.name for item in result.destination.iterdir()] == ["wire-1"]
    for relative, raw in expected.items():
        assert (result.destination / relative).read_bytes() == raw
    verified = api.verify_schema_directory(
        result.destination, expected_catalog_digest=result.catalog_digest
    )
    assert verified == result
    assert json.loads(json.dumps(result.to_dict()))["resource_count"] == 10
    assert not list(tmp_path.glob(".evidence-schema-*"))


def test_directory_export_never_replaces_existing_empty_or_foreign_targets(tmp_path):
    for name, directory in (("empty", True), ("file", False), ("populated", True)):
        target = tmp_path / name
        if directory:
            target.mkdir()
            if name == "populated":
                (target / "user.txt").write_bytes(b"preserve")
        else:
            target.write_bytes(b"preserve")
        before = target.stat()
        with pytest.raises(InputFormatError):
            api.export_schema_directory(target)
        assert target.stat().st_ino == before.st_ino
        if name == "populated":
            assert (target / "user.txt").read_bytes() == b"preserve"
        elif not directory:
            assert target.read_bytes() == b"preserve"
    assert not list(tmp_path.glob(".evidence-schema-*"))


def test_two_real_directory_publishers_have_exactly_one_winner(tmp_path):
    barrier = Barrier(2)
    target = tmp_path / "race"

    def publish():
        barrier.wait()
        try:
            return api.export_schema_directory(target)
        except InputFormatError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: publish(), range(2)))
    winners = [item for item in results if item is not None]
    assert len(winners) == 1
    assert (
        api.verify_schema_directory(target, expected_catalog_digest=winners[0].catalog_digest)
        == winners[0]
    )
    assert not list(tmp_path.glob(".evidence-schema-*"))


@pytest.mark.parametrize(
    "change", ["missing", "extra_root", "extra_wire", "wrong_line", "bytes", "large", "directory"]
)
def test_strict_directory_inventory_and_complete_bytes_reject_changes(tmp_path, change):
    result = exported(tmp_path)
    root = result.destination
    file = root / "wire-1/SHA256SUMS"
    if change == "missing":
        file.unlink()
    elif change == "extra_root":
        (root / "unexpected").write_bytes(b"user")
    elif change == "extra_wire":
        (root / "wire-1/.hidden").write_bytes(b"user")
    elif change == "wrong_line":
        (root / "wire-1").rename(root / "wire-2")
    elif change == "bytes":
        raw = bytearray(file.read_bytes())
        raw[0] ^= 1
        file.write_bytes(raw)
    elif change == "large":
        with file.open("ab") as handle:
            handle.truncate(module.MAX_SCHEMA_FILE_BYTES + 1)
    else:
        file.unlink()
        file.mkdir()
    with pytest.raises(InputFormatError):
        check(result)


def test_missing_parent_is_not_created_and_wrong_anchor_fails_before_filesystem_read(
    tmp_path, monkeypatch
):
    parent = tmp_path / "not-created"
    with pytest.raises(InputFormatError):
        api.export_schema_directory(parent / "publication")
    assert not parent.exists()
    monkeypatch.setattr(module, "_inventory", lambda *a: pytest.fail("filesystem enumerated"))
    with pytest.raises(InputFormatError, match="expected catalog"):
        api.verify_schema_directory(tmp_path / "absent", expected_catalog_digest="0" * 64)


@pytest.mark.parametrize("level", ["root", "wire", "file"])
def test_symlink_at_each_named_level_is_never_followed(tmp_path, level):
    result = exported(tmp_path)
    root = result.destination
    target = (
        root
        if level == "root"
        else root / "wire-1"
        if level == "wire"
        else root / "wire-1/SHA256SUMS"
    )
    moved = tmp_path / "retained"
    target.rename(moved)
    try:
        target.symlink_to(moved, target_is_directory=level != "file")
    except OSError:
        moved.rename(target)
        pytest.skip("host does not grant symbolic-link creation")
    with pytest.raises(InputFormatError, match="ordinary"):
        check(result)
    assert moved.exists()


def test_reparse_attribute_is_rejected_even_with_regular_mode(tmp_path, monkeypatch):
    result = exported(tmp_path)
    real = Path.lstat

    def reparse(path, *args, **kwargs):
        value = real(path, *args, **kwargs)
        return (
            stat_copy(value, st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT)
            if path == result.destination
            else value
        )

    monkeypatch.setattr(Path, "lstat", reparse)
    with pytest.raises(InputFormatError, match="non-reparse"):
        check(result)


def test_read_bounds_are_checked_before_os_read(tmp_path, monkeypatch):
    result = exported(tmp_path)
    monkeypatch.setattr(module, "MAX_SCHEMA_FILE_BYTES", 1)
    monkeypatch.setattr(module.os, "read", lambda *a: pytest.fail("oversized source read"))
    with pytest.raises(InputFormatError, match="byte bound"):
        check(result)


def test_enumeration_stops_on_first_extra_entry_and_closes_iterator(tmp_path, monkeypatch):
    result = exported(tmp_path)
    calls = []

    class Inventory:
        def __iter__(self):
            return self

        def __next__(self):
            calls.append("next")
            assert calls.count("next") <= 2
            return SimpleNamespace(name="wire-1")

        def close(self):
            calls.append("close")

    monkeypatch.setattr(module.os, "scandir", lambda *a: Inventory())
    with pytest.raises(InputFormatError, match="extra"):
        check(result)
    assert calls == ["next", "next", "close"]


def test_reader_compares_same_opened_file_identity_and_change_observations(tmp_path, monkeypatch):
    result = exported(tmp_path)
    real = os.fstat
    monkeypatch.setattr(
        module.os, "fstat", lambda fd: stat_copy(real(fd), st_ino=real(fd).st_ino + 1)
    )
    with pytest.raises(InputFormatError, match="before opening"):
        check(result)


def test_same_file_mutation_during_read_and_after_earlier_read_is_detected(tmp_path, monkeypatch):
    result = exported(tmp_path)
    first = result.destination / "wire-1/SHA256SUMS"
    real = os.read

    def mutate(descriptor, size):
        raw = real(descriptor, size)
        observed = first.stat()
        os.utime(first, ns=(observed.st_atime_ns, observed.st_mtime_ns + 1_000_000_000))
        return raw

    with monkeypatch.context() as scoped:
        scoped.setattr(module.os, "read", mutate)
        with pytest.raises(InputFormatError, match="changed"):
            check(result)
    real_file = module._read_file
    count = 0

    def later(*args):
        nonlocal count
        observed = real_file(*args)
        count += 1
        if count == 10:
            first.write_bytes(b"altered")
        return observed

    monkeypatch.setattr(module, "_read_file", later)
    with pytest.raises(InputFormatError, match="after a file"):
        check(result)


@pytest.mark.parametrize(
    "problem", [OSError("disk failure"), KeyboardInterrupt("stop"), SystemExit("stop")]
)
def test_write_failure_or_control_preserves_target_and_cleans_only_owned_staging(
    tmp_path, monkeypatch, problem
):
    def fail(*args):
        raise problem

    monkeypatch.setattr(module, "_write_file", fail)
    with pytest.raises(
        type(problem) if not isinstance(problem, Exception) else InputFormatError
    ) as caught:
        api.export_schema_directory(tmp_path / "out")
    if not isinstance(problem, Exception):
        assert caught.value is problem
        assert any("unpublished" in note for note in problem.__notes__)
    assert not (tmp_path / "out").exists()
    assert not list(tmp_path.glob(".evidence-schema-*"))


def test_short_write_and_fsync_failure_close_descriptors_and_do_not_publish(tmp_path, monkeypatch):
    real_write, real_close = os.write, os.close
    closed = []

    def close(descriptor):
        real_close(descriptor)
        closed.append(descriptor)

    monkeypatch.setattr(module.os, "close", close)
    with monkeypatch.context() as scoped:
        scoped.setattr(module.os, "write", lambda descriptor, raw: real_write(descriptor, raw[:-1]))
        with pytest.raises(api.SchemaDirectoryPublicationError) as caught:
            api.export_schema_directory(tmp_path / "short")
        assert "incomplete" in str(caught.value.__cause__)
    monkeypatch.setattr(module.os, "fsync", lambda *a: (_ for _ in ()).throw(OSError("fsync")))
    with pytest.raises(api.SchemaDirectoryPublicationError) as caught:
        api.export_schema_directory(tmp_path / "sync")
    assert caught.value.publication_state == "unpublished"
    assert len(closed) == 2 and not list(tmp_path.glob(".evidence-schema-*"))


@pytest.mark.parametrize("control", [KeyboardInterrupt, SystemExit])
def test_primary_control_survives_ordinary_descriptor_close_failure(tmp_path, monkeypatch, control):
    expected = control("primary")
    real_close = os.close

    def write(*args):
        raise expected

    def close(descriptor):
        real_close(descriptor)
        raise OSError("secondary close failure")

    monkeypatch.setattr(module.os, "write", write)
    monkeypatch.setattr(module.os, "close", close)
    with pytest.raises(control) as caught:
        api.export_schema_directory(tmp_path / "out")
    assert caught.value is expected
    assert any("descriptor cleanup" in note for note in expected.__notes__)
    assert not list(tmp_path.glob(".evidence-schema-*"))


def test_unknown_and_replaced_files_are_retained_not_recursively_deleted(tmp_path, monkeypatch):
    def fail(stage, **kwargs):
        first = stage / "wire-1/SHA256SUMS"
        first.rename(stage / "original-checksums")
        first.write_bytes(b"foreign replacement")
        (stage / "wire-1/user.txt").write_bytes(b"unknown content")
        raise InputFormatError("injected verification failure")

    monkeypatch.setattr(module, "verify_schema_directory", fail)
    with pytest.raises(api.SchemaDirectoryPublicationError) as caught:
        api.export_schema_directory(tmp_path / "out")
    stage = caught.value.staging_path
    assert (stage / "wire-1/SHA256SUMS").read_bytes() == b"foreign replacement"
    assert (stage / "wire-1/user.txt").read_bytes() == b"unknown content"
    assert (stage / "original-checksums").read_bytes() == generated_resources()["wire-1/SHA256SUMS"]
    assert sorted(path.name for path in (stage / "wire-1").iterdir()) == ["SHA256SUMS", "user.txt"]
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("problem", [OSError("lost ack"), KeyboardInterrupt("lost ack")])
def test_successful_rename_followed_by_error_reports_publication_without_deleting_it(
    tmp_path, monkeypatch, problem
):
    real = module._rename_noreplace

    def rename(source, destination):
        real(source, destination)
        raise problem

    monkeypatch.setattr(module, "_rename_noreplace", rename)
    with pytest.raises(
        InputFormatError if isinstance(problem, Exception) else KeyboardInterrupt
    ) as caught:
        api.export_schema_directory(tmp_path / "out")
    if isinstance(problem, Exception):
        assert caught.value.publication_state == "published"
    else:
        assert caught.value is problem and any("published" in note for note in problem.__notes__)
    api.verify_schema_directory(
        tmp_path / "out", expected_catalog_digest=api.load_schema_catalog().digest
    )
    assert not list(tmp_path.glob(".evidence-schema-*"))


def test_lost_source_and_destination_reports_unknown_ack_without_deleting_moved_tree(
    tmp_path, monkeypatch
):
    moved = tmp_path / "elsewhere"

    def rename(source, destination):
        source.rename(moved)
        raise OSError("ack lost")

    monkeypatch.setattr(module, "_rename_noreplace", rename)
    with pytest.raises(api.SchemaDirectoryPublicationError) as caught:
        api.export_schema_directory(tmp_path / "out")
    assert caught.value.publication_state == "unknown"
    api.verify_schema_directory(moved, expected_catalog_digest=api.load_schema_catalog().digest)


def test_cli_metadata_relocation_and_independent_process_reopen(tmp_path, capsys):
    destination = tmp_path / "cli"
    assert run(["schema", "export-directory", str(destination)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert (
        run(
            [
                "schema",
                "verify-directory",
                str(destination),
                "--expected-catalog-digest",
                result["catalog_digest"],
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == result
    assert run(["schema", "export-directory", str(destination)]) == 2
    assert "unpublished" in capsys.readouterr().err
    moved = tmp_path / "moved"
    destination.rename(moved)
    code = """
from evidence_braid import verify_schema_directory
import json, sys
result = verify_schema_directory(sys.argv[1], expected_catalog_digest=sys.argv[2])
print(json.dumps(result.to_dict()))
"""
    process = subprocess.run(
        [sys.executable, "-I", "-c", code, str(moved), result["catalog_digest"]],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    assert json.loads(process.stdout) == {**result, "destination": str(moved)}
    assert process.stderr == ""


def test_metadata_is_immutable_and_manual_construction_is_only_bounded_metadata(tmp_path):
    result = exported(tmp_path)
    with pytest.raises(FrozenInstanceError):
        result.size_bytes = 0
    for size in (True, 0, -1, 1.0, module.MAX_SCHEMA_PUBLICATION_BYTES + 1):
        with pytest.raises(ValueError):
            api.SchemaDirectoryExport(result.destination, result.catalog_digest, size)
    with pytest.raises(ValueError):
        api.SchemaDirectoryExport(Path("relative"), result.catalog_digest, 1)


def test_linux_renameat2_uses_exact_noreplace_flags_and_no_fallback(tmp_path, monkeypatch):
    calls = []

    class Operation:
        def __call__(self, *args):
            calls.append(args)
            return 0

    operation = Operation()
    monkeypatch.setattr(module, "_SYSTEM", "linux")
    monkeypatch.setattr(module.ctypes, "CDLL", lambda *a, **k: SimpleNamespace(renameat2=operation))
    source, destination = tmp_path / "stage", tmp_path / "out"
    module._rename_noreplace(source, destination)
    assert calls == [(-100, os.fsencode(source), -100, os.fsencode(destination), 1)]
    assert operation.restype is ctypes.c_int
    assert operation.argtypes == [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    monkeypatch.setattr(module.ctypes, "CDLL", lambda *a, **k: SimpleNamespace())
    with pytest.raises(InputFormatError, match="unavailable"):
        module._rename_noreplace(source, destination)
    monkeypatch.setattr(module, "_SYSTEM", "darwin")
    with pytest.raises(InputFormatError, match="unsupported"):
        module._rename_noreplace(source, destination)


def test_linux_unsupported_filesystem_error_is_not_retried_with_plain_rename(tmp_path, monkeypatch):
    class Operation:
        def __call__(self, *args):
            ctypes.set_errno(errno.EINVAL)
            return -1

    monkeypatch.setattr(module, "_SYSTEM", "linux")
    monkeypatch.setattr(
        module.ctypes, "CDLL", lambda *a, **k: SimpleNamespace(renameat2=Operation())
    )
    monkeypatch.setattr(module.os, "rename", lambda *a: pytest.fail("unsafe fallback rename"))
    with pytest.raises(OSError) as caught:
        module._rename_noreplace(tmp_path / "source", tmp_path / "destination")
    assert caught.value.errno == errno.EINVAL


def test_successful_mkdir_with_failed_identity_capture_retains_unknown_residue(
    tmp_path, monkeypatch
):
    real = module._lstat
    failed = False

    def observe(path, directory):
        nonlocal failed
        if path.name.startswith(".evidence-schema-") and not failed:
            failed = True
            raise OSError("identity lookup failed after mkdir")
        return real(path, directory)

    monkeypatch.setattr(module, "_lstat", observe)
    with pytest.raises(api.SchemaDirectoryPublicationError) as caught:
        api.export_schema_directory(tmp_path / "out")
    assert failed and caught.value.publication_state == "unpublished"
    assert caught.value.staging_path.is_dir()
    assert list(caught.value.staging_path.iterdir()) == []
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("early_failure", [False, True])
def test_replaced_staging_ancestor_blocks_cleanup_of_every_descendant(
    tmp_path, monkeypatch, early_failure
):
    retained = tmp_path / "retained-original"

    def fail(stage, **kwargs):
        stage.rename(retained)
        (stage / "wire-1").mkdir(parents=True)
        (stage / "wire-1/SHA256SUMS").write_bytes(b"foreign content")
        if early_failure:
            raise InputFormatError("staging was replaced")

    monkeypatch.setattr(module, "verify_schema_directory", fail)
    with pytest.raises(api.SchemaDirectoryPublicationError) as caught:
        api.export_schema_directory(tmp_path / "out")
    assert (caught.value.staging_path / "wire-1/SHA256SUMS").read_bytes() == b"foreign content"
    assert len(list((retained / "wire-1").iterdir())) == 10
    assert not (tmp_path / "out").exists()


def test_path_observation_after_read_refuses_a_replaced_identity(tmp_path, monkeypatch):
    result = exported(tmp_path)
    first = result.destination / "wire-1/SHA256SUMS"
    real = module._lstat
    calls = 0

    def changed(path, directory):
        nonlocal calls
        value = real(path, directory)
        if path == first:
            calls += 1
            if calls == 2:
                return stat_copy(value, st_ino=value.st_ino + 1)
        return value

    monkeypatch.setattr(module, "_lstat", changed)
    with pytest.raises(InputFormatError, match="path changed"):
        check(result)


def test_final_directory_change_is_checked_even_when_names_stay_the_same(tmp_path, monkeypatch):
    result = exported(tmp_path)
    real = module._read_file
    count = 0

    def touch(*args):
        nonlocal count
        value = real(*args)
        count += 1
        if count == 10:
            observed = result.destination.stat()
            os.utime(
                result.destination, ns=(observed.st_atime_ns, observed.st_mtime_ns + 1_000_000_000)
            )
        return value

    monkeypatch.setattr(module, "_read_file", touch)
    with pytest.raises(InputFormatError, match="directory changed"):
        check(result)


def test_changed_identity_after_ack_reports_unknown_and_never_cleans_published_target(
    tmp_path, monkeypatch
):
    destination = tmp_path / "out"
    real = module._lstat

    def changed(path, directory):
        value = real(path, directory)
        return stat_copy(value, st_ino=value.st_ino + 1) if path == destination else value

    with monkeypatch.context() as scoped:
        scoped.setattr(module, "_lstat", changed)
        with pytest.raises(api.SchemaDirectoryPublicationError) as caught:
            api.export_schema_directory(destination)
        assert caught.value.publication_state == "unknown"
    api.verify_schema_directory(
        destination, expected_catalog_digest=api.load_schema_catalog().digest
    )


def test_rename_and_ack_observation_failures_produce_unknown_and_retain_stage(
    tmp_path, monkeypatch
):
    expected = KeyboardInterrupt("primary rename interrupt")

    def rename(*args):
        raise expected

    monkeypatch.setattr(module, "_rename_noreplace", rename)
    monkeypatch.setattr(
        module, "_observe_publication", lambda *a: (_ for _ in ()).throw(OSError("ack lookup"))
    )
    with pytest.raises(KeyboardInterrupt) as caught:
        api.export_schema_directory(tmp_path / "out")
    assert caught.value is expected
    assert any("state: unknown" in note for note in expected.__notes__)
    retained = list(tmp_path.glob(".evidence-schema-*"))
    assert len(retained) == 1 and len(list((retained[0] / "wire-1").iterdir())) == 10


@pytest.mark.parametrize("primary_is_control", [False, True])
def test_cleanup_attempts_remaining_owned_files_and_prioritizes_controls(
    tmp_path, monkeypatch, primary_is_control
):
    primary = KeyboardInterrupt("primary") if primary_is_control else InputFormatError("primary")
    cleanup = SystemExit("cleanup control")
    real_unlink = Path.unlink
    attempted = []

    def fail(*args, **kwargs):
        raise primary

    def unlink(path, *args, **kwargs):
        attempted.append(path.name)
        if len(attempted) == 1:
            raise cleanup
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(module, "verify_schema_directory", fail)
    monkeypatch.setattr(Path, "unlink", unlink)
    expected = primary if primary_is_control else cleanup
    with pytest.raises(type(expected)) as caught:
        api.export_schema_directory(tmp_path / "out")
    assert caught.value is expected
    assert len(attempted) == 10
    stage = next(tmp_path.glob(".evidence-schema-*"))
    assert [p.name for p in (stage / "wire-1").iterdir()] == [attempted[0]]
    assert not (tmp_path / "out").exists()


def test_close_control_takes_precedence_over_ordinary_write_failure(tmp_path, monkeypatch):
    expected = KeyboardInterrupt("close control")
    real_close = os.close

    def close(descriptor):
        real_close(descriptor)
        raise expected

    monkeypatch.setattr(module.os, "close", close)
    monkeypatch.setattr(module.os, "write", lambda *a: (_ for _ in ()).throw(OSError("write")))
    with pytest.raises(KeyboardInterrupt) as caught:
        api.export_schema_directory(tmp_path / "out")
    assert caught.value is expected
    assert not list(tmp_path.glob(".evidence-schema-*"))


@pytest.mark.parametrize("control", [False, True])
def test_inventory_close_failure_is_not_silenced_and_control_is_not_wrapped(
    tmp_path, monkeypatch, control
):
    result = exported(tmp_path)
    expected = KeyboardInterrupt("iterator close") if control else OSError("iterator close")
    real = os.scandir
    closed = []

    class Closing:
        def __init__(self, path):
            self.iterator = real(path)

        def __iter__(self):
            return iter(self.iterator)

        def close(self):
            self.iterator.close()
            closed.append(1)
            raise expected

    monkeypatch.setattr(module.os, "scandir", Closing)
    with pytest.raises(KeyboardInterrupt if control else InputFormatError) as caught:
        check(result)
    assert closed == [1]
    if control:
        assert caught.value is expected


def test_compatible_cross_api_timestamp_binding_still_checks_each_api_changes(
    tmp_path, monkeypatch
):
    result = exported(tmp_path)
    real = os.fstat

    def different_creation_vs_change(descriptor):
        value = real(descriptor)
        return stat_copy(value, st_ctime_ns=value.st_ctime_ns + 1234)

    monkeypatch.setattr(module.os, "fstat", different_creation_vs_change)
    if os.name == "nt":
        assert check(result) == result
    else:
        with pytest.raises(InputFormatError, match="before opening"):
            check(result)
    calls = 0

    def changing(descriptor):
        nonlocal calls
        calls += 1
        value = real(descriptor)
        return stat_copy(value, st_ctime_ns=value.st_ctime_ns + (calls > 1))

    monkeypatch.setattr(module.os, "fstat", changing)
    with pytest.raises(InputFormatError, match="changed"):
        check(result)


def test_relative_destination_is_bound_before_work_that_changes_process_cwd(tmp_path, monkeypatch):
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()
    real = module._write_file

    def change(item, raw):
        os.chdir(second)
        real(item, raw)

    monkeypatch.chdir(first)
    monkeypatch.setattr(module, "_write_file", change)
    result = api.export_schema_directory("out")
    assert result.destination == first / "out"
    assert check(result) == result
    assert not (second / "out").exists()


@pytest.mark.parametrize("control", [False, True])
def test_cli_output_failure_explicitly_reports_already_published_directory(
    tmp_path, monkeypatch, capsys, control
):
    from evidence_braid import cli

    problem = KeyboardInterrupt("report interrupted") if control else OSError("stdout broke")

    def fail(*args):
        raise problem

    monkeypatch.setattr(cli, "_emit", fail)
    destination = tmp_path / "out"
    if control:
        with pytest.raises(KeyboardInterrupt) as caught:
            cli.run(["schema", "export-directory", str(destination)])
        assert caught.value is problem
        assert any("directory published" in note for note in problem.__notes__)
    else:
        assert cli.run(["schema", "export-directory", str(destination)]) == 2
        assert "directory published" in capsys.readouterr().err
    api.verify_schema_directory(
        destination, expected_catalog_digest=api.load_schema_catalog().digest
    )


@pytest.mark.parametrize("path", ["", "bad\x00path", None, True, 1])
def test_malformed_paths_fail_before_publication(tmp_path, path):
    with pytest.raises(InputFormatError, match="nonempty path"):
        api.export_schema_directory(path)
    with pytest.raises(InputFormatError, match="nonempty path"):
        api.verify_schema_directory(path, expected_catalog_digest=api.load_schema_catalog().digest)


def test_offline_directory_example_executes_real_relocation_and_child_verification(capsys):
    from examples.offline_schema_directory import main

    main()
    result = json.loads(capsys.readouterr().out)
    assert result["resource_count"] == 10 and result["size_bytes"] == 26961
    assert result["relocated_process_verified"]
    assert not result["semantic_authorization_provided"]
