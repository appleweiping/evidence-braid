"""Private same-directory file publication, with explicit replacement policy.

Only a fully written, flushed and fsynced file is published. No-replace uses an
atomic hard link and fails closed on filesystems that do not support it. This is
not directory-metadata power-loss durability or a hostile-filesystem sandbox.
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO, cast

from .errors import InputFormatError, ValidationError


@contextmanager
def staged_output(
    path: str | Path, *, replace: bool, create_parents: bool = False
) -> Iterator[BinaryIO]:
    """Yield a seekable staging file; publish only after the context succeeds.

    The caller may flush and independently reopen ``handle.name`` to verify
    before leaving the context. Existing destinations are never removed first.
    A rare staging-unlink failure after no-replace publication explicitly reports
    that publication succeeded; callers must not blindly retry that result.
    """
    if type(replace) is not bool or type(create_parents) is not bool:
        raise ValidationError("publication flags must be boolean")
    if not str(path):
        raise InputFormatError("cannot publish output: destination path is empty")
    # Bind before yielding: cwd is process-global and may change in caller code
    # or another thread while the temporary file is being filled.
    destination = Path(path).absolute()
    temporary: Path | None = None
    published = False
    failure: BaseException | None = None
    try:
        if create_parents:
            destination.parent.mkdir(parents=True, exist_ok=True)
        # This function is the owning context manager. A nested file context
        # would let its close error mask a primary verification/interrupt error.
        handle = tempfile.NamedTemporaryFile(  # noqa: SIM115
            mode="w+b", prefix=".evidence-", suffix=".tmp", dir=destination.parent, delete=False
        )
        temporary = Path(handle.name)
        try:
            try:
                # tempfile forwards this binary file interface but its typeshed
                # wrapper class does not nominally subclass BinaryIO.
                yield cast(BinaryIO, handle)
                handle.flush()
                os.fsync(handle.fileno())
            except BaseException as exc:
                failure = exc
                raise
        finally:
            try:
                handle.close()
            except Exception as exc:
                if failure is None:
                    raise
                # An ordinary cleanup error must not replace an earlier
                # verification failure or interrupt. New interrupts propagate.
                failure.add_note(f"staging file close failed: {type(exc).__name__}")
        if replace:
            os.replace(temporary, destination)
            temporary = None
        else:
            # No exists()/rename gap: hard-link creation refuses every existing
            # destination, including another publisher's concurrently won name.
            os.link(temporary, destination)
        published = True
    except OSError as exc:
        failure = InputFormatError("cannot publish output")
        raise failure from exc
    except BaseException as exc:
        failure = exc
        raise
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError as exc:
                detail = (
                    f"output published, but staging file cleanup failed: {temporary}"
                    if published
                    else f"unpublished staging file cleanup failed: {temporary}"
                )
                if failure is not None:
                    failure.add_note(detail)
                else:
                    raise InputFormatError(detail) from exc
