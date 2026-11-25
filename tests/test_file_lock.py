from __future__ import annotations

import multiprocessing
import os
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor

import pytest
from pathlib import Path

from core.file_lock import fcntl


def _increment_in_process(path_text: str, count: int) -> int:
    path = Path(path_text)
    for _ in range(count):
        fd = os.open(path, os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                os.lseek(fd, 0, os.SEEK_SET)
                raw = os.read(fd, 64)
                value = int(raw.decode("ascii") or "0") + 1
                encoded = str(value).encode("ascii")
                os.lseek(fd, 0, os.SEEK_SET)
                os.ftruncate(fd, 0)
                if os.write(fd, encoded) != len(encoded):
                    raise OSError("short counter write")
                os.fsync(fd)
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
    return count


def test_flock_compatibility_lock_unlock(tmp_path):
    path = tmp_path / "compat.lock"
    path.write_bytes(b"0")
    fd = os.open(path, os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        os.lseek(fd, 0, os.SEEK_SET)
        assert os.read(fd, 1) == b"0"
        fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def test_lock_preserves_descriptor_position(tmp_path):
    path = tmp_path / "position.lock"
    path.write_bytes(b"0123")
    fd = os.open(path, os.O_RDWR)
    try:
        os.lseek(fd, 2, os.SEEK_SET)
        fcntl.flock(fd, fcntl.LOCK_EX)
        assert os.lseek(fd, 0, os.SEEK_CUR) == 2
        os.lseek(fd, 3, os.SEEK_SET)
        fcntl.flock(fd, fcntl.LOCK_UN)
        assert os.lseek(fd, 0, os.SEEK_CUR) == 3
    finally:
        os.close(fd)


def test_flock_nonblocking_reports_contention(tmp_path):
    path = tmp_path / "nonblocking.lock"
    path.write_bytes(b"0")
    first = os.open(path, os.O_RDWR)
    second = os.open(path, os.O_RDWR)
    try:
        fcntl.flock(first, fcntl.LOCK_EX)
        with pytest.raises(BlockingIOError):
            fcntl.flock(second, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(first, fcntl.LOCK_UN)
    finally:
        os.close(first)
        os.close(second)


def test_threaded_file_lock_serializes_updates(tmp_path):
    path = tmp_path / "thread-counter.txt"
    path.write_text("0", encoding="ascii")
    workers, repetitions = 8, 15
    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(lambda _: _increment_in_process(str(path), repetitions), range(workers)))
    assert path.read_text(encoding="ascii") == str(workers * repetitions)


def test_cross_process_file_lock_serializes_updates(tmp_path):
    path = tmp_path / "process-counter.txt"
    path.write_text("0", encoding="ascii")
    workers, repetitions = 4, 12
    context = multiprocessing.get_context("spawn")
    with ProcessPoolExecutor(max_workers=workers, mp_context=context) as pool:
        results = list(pool.map(_increment_in_process, [str(path)] * workers, [repetitions] * workers))
    assert results == [repetitions] * workers
