"""Cross-platform advisory file locks for PIKA journals."""
from __future__ import annotations

from contextlib import contextmanager
import errno
import os
import threading
import time
from typing import Iterator

try:
    import fcntl as _native_fcntl
except ImportError:  # Windows uses msvcrt byte-range locks.
    _native_fcntl = None

_registry_guard = threading.Lock()
_thread_locks: dict[tuple[int, int], threading.Lock] = {}
_held_guard = threading.Lock()
_held_contexts: dict[tuple[int, int], object] = {}


def _file_key(fd: int) -> tuple[int, int]:
    metadata = os.fstat(fd)
    return int(metadata.st_dev), int(metadata.st_ino)


@contextmanager
def _windows_locked_fd(fd: int, *, blocking: bool = True) -> Iterator[None]:
    """Lock byte zero across processes and serialize same-process threads.

    Windows byte-range locks are exclusive, so LOCK_SH is conservatively
    implemented as an exclusive lock. The descriptor cursor is preserved.
    """
    if isinstance(fd, bool) or not isinstance(fd, int):
        raise TypeError("file lock requires an integer file descriptor")
    os.fstat(fd)
    try:
        import msvcrt
    except ImportError as exc:
        raise OSError("Windows byte-range locking is unavailable.") from exc

    key = _file_key(fd)
    with _registry_guard:
        local_lock = _thread_locks.setdefault(key, threading.Lock())
    if not local_lock.acquire(blocking=blocking):
        raise BlockingIOError(errno.EAGAIN, "file is already locked in this process")
    acquired = False
    original_position = None
    release_position = None
    try:
        original_position = os.lseek(fd, 0, os.SEEK_CUR)
        os.lseek(fd, 0, os.SEEK_SET)
        retry_errnos = {
            errno.EACCES,
            errno.EAGAIN,
            getattr(errno, "EDEADLK", errno.EACCES),
        }
        while True:
            try:
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                acquired = True
                break
            except OSError as exc:
                if exc.errno not in retry_errnos:
                    raise
                if not blocking:
                    raise BlockingIOError(exc.errno or errno.EACCES, str(exc)) from exc
                time.sleep(0.05)

        os.lseek(fd, original_position, os.SEEK_SET)
        yield
    finally:
        try:
            if acquired:
                try:
                    release_position = os.lseek(fd, 0, os.SEEK_CUR)
                except OSError:
                    release_position = original_position
                try:
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                finally:
                    if release_position is not None:
                        os.lseek(fd, release_position, os.SEEK_SET)
        finally:
            local_lock.release()


class _WindowsFcntlCompat:
    LOCK_SH = 1
    LOCK_EX = 2
    LOCK_NB = 4
    LOCK_UN = 8

    def flock(self, fd: int, operation: int) -> None:
        if isinstance(operation, bool) or not isinstance(operation, int):
            raise TypeError("flock operation must be an integer")
        key = (threading.get_ident(), int(fd))
        if operation == self.LOCK_UN:
            with _held_guard:
                context = _held_contexts.pop(key, None)
            if context is not None:
                context.__exit__(None, None, None)
            return

        nonblocking = bool(operation & self.LOCK_NB)
        mode = operation & ~self.LOCK_NB
        if mode not in (self.LOCK_SH, self.LOCK_EX):
            raise ValueError("Unsupported Windows flock operation")
        with _held_guard:
            if key in _held_contexts:
                raise RuntimeError("file descriptor already has an active lock")
            _held_contexts[key] = None

        context = _windows_locked_fd(fd, blocking=not nonblocking)
        try:
            context.__enter__()
        except Exception:
            with _held_guard:
                _held_contexts.pop(key, None)
            raise
        with _held_guard:
            _held_contexts[key] = context


@contextmanager
def locked_fd(fd: int, *, exclusive: bool = True) -> Iterator[None]:
    """Context manager for an already-open regular-file descriptor."""
    if isinstance(fd, bool) or not isinstance(fd, int):
        raise TypeError("file lock requires an integer file descriptor")
    os.fstat(fd)
    if _native_fcntl is not None:
        operation = _native_fcntl.LOCK_EX if exclusive else _native_fcntl.LOCK_SH
        _native_fcntl.flock(fd, operation)
        try:
            yield
        finally:
            _native_fcntl.flock(fd, _native_fcntl.LOCK_UN)
    else:
        with _windows_locked_fd(fd):
            yield


fcntl = _native_fcntl if _native_fcntl is not None else _WindowsFcntlCompat()
