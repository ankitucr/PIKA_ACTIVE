"""Portable process locks for POSIX and Windows hosts.

Windows msvcrt exposes exclusive byte-range locks only; shared requests are
serialized as exclusive locks there. POSIX retains shared/exclusive flock.
"""
from __future__ import annotations

import os

try:
    import fcntl
except ImportError:  # Windows
    fcntl = None
try:
    import msvcrt
except ImportError:  # POSIX
    msvcrt = None


def lock_fd(fd: int, *, exclusive: bool = True) -> None:
    if fcntl is not None:
        fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        return
    if msvcrt is not None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
        return
    raise OSError("No supported inter-process lock backend is available.")


def unlock_fd(fd: int) -> None:
    if fcntl is not None:
        fcntl.flock(fd, fcntl.LOCK_UN)
        return
    if msvcrt is not None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        return
    raise OSError("No supported inter-process lock backend is available.")
