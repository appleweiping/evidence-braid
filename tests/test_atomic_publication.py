from __future__ import annotations

import os
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import evidence_braid._atomic as module
from evidence_braid import build_ledger, load_ledger, write_ledger
from evidence_braid._atomic import staged_output
from evidence_braid.errors import InputFormatError, ValidationError


def test_export_stages_verifiable_ledger_and_preserves_parent_creation(tmp_path, monkeypatch):
    destination = tmp_path / "new" / "ledger.json"
    ledger = build_ledger([])
    observed = []
    real_replace = os.replace

    def replace(source, target):
        assert not destination.exists()
        assert load_ledger(source) == ledger
        observed.append(True)
        real_replace(source, target)

    monkeypatch.setattr(module.os, "replace", replace)
    write_ledger(destination, ledger)
    assert observed == [True]
    assert load_ledger(destination) == ledger
    assert list(destination.parent.iterdir()) == [destination]


@pytest.mark.parametrize("failure", ["write", "fsync", "replace"])
@pytest.mark.parametrize("exists", [False, True])
def test_partial_failure_never_changes_destination(tmp_path, monkeypatch, failure, exists):
    destination = tmp_path / "published"
    if exists:
        destination.write_bytes(b"old")

    def fail(*args):
        raise OSError("injected failure")

    if failure != "write":
        monkeypatch.setattr(module.os, failure, fail)
    with (
        pytest.raises(InputFormatError, match="cannot publish"),
        staged_output(destination, replace=True) as handle,
    ):
        handle.write(b"partial")
        if failure == "write":
            fail()
    assert destination.read_bytes() == b"old" if exists else not destination.exists()
    assert list(tmp_path.iterdir()) == ([destination] if exists else [])


def test_ledger_export_fsync_failure_preserves_previous_valid_receipt(tmp_path, monkeypatch):
    destination = tmp_path / "receipt.json"
    write_ledger(destination, build_ledger([]))
    before = destination.read_bytes()

    def fail(*args):
        raise OSError("disk flush failed")

    monkeypatch.setattr(module.os, "fsync", fail)
    with pytest.raises(InputFormatError):
        write_ledger(destination, build_ledger([]))
    assert destination.read_bytes() == before
    assert list(tmp_path.iterdir()) == [destination]


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_body_failure_keeps_original_exception_and_removes_stage(tmp_path, error):
    original = error("verification refused")
    with (
        pytest.raises(error) as caught,
        staged_output(tmp_path / "target", replace=False) as handle,
    ):
        handle.write(b"unverified")
        raise original
    assert caught.value is original
    assert list(tmp_path.iterdir()) == []


def test_no_replace_uses_atomic_competing_publishers(tmp_path):
    destination = tmp_path / "bundle"
    barrier = threading.Barrier(2)

    def publish(content):
        try:
            with staged_output(destination, replace=False) as handle:
                handle.write(content)
                barrier.wait(timeout=10)
            return "published", content
        except InputFormatError:
            return "conflict", content

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(publish, [b"one" * 1000, b"two" * 1000]))
    assert sorted(result[0] for result in outcomes) == ["conflict", "published"]
    assert destination.read_bytes() == next(
        value for status, value in outcomes if status == "published"
    )
    assert list(tmp_path.iterdir()) == [destination]


def test_no_replace_refuses_existing_directory_and_unsupported_filesystem(tmp_path, monkeypatch):
    destination = tmp_path / "existing"
    destination.mkdir()
    with pytest.raises(InputFormatError), staged_output(destination, replace=False) as handle:
        handle.write(b"content")
    assert destination.is_dir()

    def unsupported(*args):
        raise OSError("hard links unsupported")

    monkeypatch.setattr(module.os, "link", unsupported)
    with pytest.raises(InputFormatError), staged_output(tmp_path / "unpublished", replace=False):
        pass
    assert list(tmp_path.iterdir()) == [destination]


@pytest.mark.parametrize("published", [False, True])
def test_staging_cleanup_failure_has_truthful_publication_outcome(tmp_path, monkeypatch, published):
    destination = tmp_path / "target"
    real_unlink = Path.unlink

    def fail_unlink(path, *args, **kwargs):
        raise OSError("cannot remove temporary file")

    original = KeyboardInterrupt("caller interrupted")
    with monkeypatch.context() as patch:
        patch.setattr(Path, "unlink", fail_unlink)
        with (
            pytest.raises(InputFormatError if published else KeyboardInterrupt) as caught,
            staged_output(destination, replace=False) as handle,
        ):
            handle.write(b"complete")
            if not published:
                raise original
    if published:
        assert "output published, but" in str(caught.value)
        assert destination.read_bytes() == b"complete"
    else:
        assert caught.value is original
        assert "unpublished staging" in caught.value.__notes__[0]
        assert not destination.exists()
    leftovers = list(tmp_path.glob(".evidence-*.tmp"))
    assert len(leftovers) == 1
    real_unlink(leftovers[0])


@pytest.mark.parametrize("replace,parents", [(1, False), (False, 1)])
def test_publication_flags_are_strict(tmp_path, replace, parents):
    with (
        pytest.raises(ValidationError),
        staged_output(tmp_path / "file", replace=replace, create_parents=parents),
    ):
        pass


def test_empty_or_missing_parent_destination_is_refused(tmp_path):
    for destination in ("", tmp_path / "absent" / "file"):
        with pytest.raises(InputFormatError), staged_output(destination, replace=False):
            pass
    assert list(tmp_path.iterdir()) == []


def test_cleanup_error_is_not_attached_to_an_unrelated_handled_exception(tmp_path, monkeypatch):
    def fail_unlink(path, *args, **kwargs):
        raise OSError("staging cleanup failure")

    destination = tmp_path / "published"
    try:
        raise LookupError("unrelated caller exception")
    except LookupError as ambient:
        with monkeypatch.context() as patch:
            patch.setattr(Path, "unlink", fail_unlink)
            with (
                pytest.raises(InputFormatError, match="output published, but"),
                staged_output(destination, replace=False) as handle,
            ):
                handle.write(b"content")
        assert not hasattr(ambient, "__notes__")
    assert destination.read_bytes() == b"content"
    for staging in tmp_path.glob(".evidence-*.tmp"):
        staging.unlink()


@pytest.mark.parametrize("replace", [False, True])
def test_destination_is_bound_before_caller_changes_working_directory(
    tmp_path, monkeypatch, replace
):
    requested = tmp_path / "requested"
    elsewhere = tmp_path / "elsewhere"
    requested.mkdir()
    elsewhere.mkdir()
    monkeypatch.chdir(requested)
    with staged_output("receipt.json", replace=replace) as handle:
        handle.write(b"verified content")
        monkeypatch.chdir(elsewhere)
    assert (requested / "receipt.json").read_bytes() == b"verified content"
    assert list(elsewhere.iterdir()) == []
    assert list(requested.iterdir()) == [requested / "receipt.json"]


@pytest.mark.parametrize("body_error", [None, RuntimeError, KeyboardInterrupt])
def test_close_failure_does_not_replace_primary_verification_error(
    tmp_path, monkeypatch, body_error
):
    real_create = module.tempfile.NamedTemporaryFile

    class CloseFailure:
        def __init__(self, wrapped):
            self.wrapped = wrapped

        def __getattr__(self, name):
            return getattr(self.wrapped, name)

        def close(self):
            self.wrapped.close()
            raise OSError("injected close failure")

    monkeypatch.setattr(
        module.tempfile, "NamedTemporaryFile", lambda **kwargs: CloseFailure(real_create(**kwargs))
    )
    original = None if body_error is None else body_error("body failure")
    with (
        pytest.raises(InputFormatError if body_error is None else body_error) as caught,
        staged_output(tmp_path / "target", replace=False) as handle,
    ):
        handle.write(b"contents")
        if original is not None:
            raise original
    if original is not None:
        assert caught.value is original
        assert "staging file close failed" in caught.value.__notes__[0]
    assert list(tmp_path.iterdir()) == []
