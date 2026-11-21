from __future__ import annotations

import hashlib
import os
import re
import traceback as traceback_module
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA = "pika.phase37.source-context.v1"
_MAX_FRAMES = 8
_MAX_SOURCE_BYTES = 1_000_000
_MAX_SNIPPET_LINES = 7
_MAX_LINE_CHARS = 240
_DENIED_PARTS = frozenset({
    ".git", ".venv", ".sandbox_venv", "venv", "env", "site-packages",
    "dist-packages", "node_modules", "__pycache__", "data", "PIKA_KNOWLEDGE",
})
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_TRACE_FRAME = re.compile(
    r'''^\s*File "([^"\n]{1,1024})", line ([1-9][0-9]{0,8}), in ([^\r\n]{1,120})\s*$'''
)
_SECRET_ASSIGNMENT = re.compile(
    r"""(?i)((?:api[_-]?key|access[_-]?token|password|secret)\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;]+)"""
)
_BEARER = re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+")


def _safe_function(value: Any) -> str:
    if not isinstance(value, str):
        return "<unknown>"
    return re.sub(r"[^A-Za-z0-9_.<>-]", "_", value)[:80] or "<unknown>"


def _redact_line(value: Any) -> str:
    text = str(value)[:_MAX_LINE_CHARS]
    text = _SECRET_ASSIGNMENT.sub(r"\1[REDACTED]", text)
    text = _BEARER.sub("Bearer [REDACTED]", text)
    return text


def _relative_path(value: Any, root: Path) -> PurePosixPath | None:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        return None
    try:
        candidate = Path(value)
        if not candidate.is_absolute():
            candidate = root / candidate
        absolute = Path(os.path.abspath(str(candidate)))
        relative = absolute.relative_to(root)
    except (OSError, ValueError):
        return None
    rel = PurePosixPath(relative.as_posix())
    if (
        rel.is_absolute()
        or rel.as_posix() in {"", "."}
        or any(part in {"", ".", ".."} or part in _DENIED_PARTS for part in rel.parts)
        or rel.suffix != ".py"
    ):
        return None
    return rel


def _current_frame(
    root: Path, relative: PurePosixPath, line_number: int, function: Any
) -> dict[str, Any] | None:
    cursor = root
    try:
        for part in relative.parts:
            if cursor.is_symlink():
                return None
            cursor = cursor / part
            if cursor.is_symlink():
                return None
        resolved = cursor.resolve(strict=True)
        resolved.relative_to(root)
        if not resolved.is_file() or resolved.stat().st_size > _MAX_SOURCE_BYTES:
            return None
        raw = resolved.read_bytes()
        text = raw.decode("utf-8")
    except (OSError, UnicodeError, ValueError):
        return None

    lines = text.splitlines()
    if isinstance(line_number, bool) or not isinstance(line_number, int):
        return None
    if line_number < 1 or line_number > max(1, len(lines)):
        return None

    start = max(1, line_number - 3)
    end = min(len(lines), line_number + 3)
    snippet = [_redact_line(line) for line in lines[start - 1:end]]
    source_kind = "test" if (
        relative.parts[0] == "tests"
        and (relative.name.startswith("test_") or relative.name.endswith("_test.py"))
    ) else "project"
    return {
        "path": relative.as_posix(),
        "line": line_number,
        "function": _safe_function(function),
        "line_start": start,
        "line_end": end,
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "snippet": snippet[:_MAX_SNIPPET_LINES],
        "source_kind": source_kind,
        "current_source_matches": True,
    }


def capture_traceback_text_source_context(
    traceback_text: Any, project_root: str | Path
) -> dict[str, Any] | None:
    """Extract bounded source frames from a returned Python traceback string.

    Only canonical Python traceback frame lines are accepted. Arbitrary error
    text, file-like names outside the project, and stale/unsafe source paths
    cannot create a source binding.
    """
    if not isinstance(traceback_text, str) or not traceback_text:
        return None
    bounded = traceback_text[:32_768]
    try:
        root = Path(project_root).expanduser().resolve(strict=True)
        if not root.is_dir():
            return None
    except (OSError, RuntimeError, TypeError, ValueError):
        return None

    extracted: list[tuple[str, int, str]] = []
    for line in bounded.splitlines():
        match = _TRACE_FRAME.fullmatch(line[:1400])
        if match is None:
            continue
        extracted.append((match.group(1), int(match.group(2)), match.group(3)))

    frames: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for filename, line_number, function in extracted[-(_MAX_FRAMES * 2):]:
        relative = _relative_path(filename, root)
        if relative is None:
            continue
        record = _current_frame(root, relative, line_number, function)
        if record is None:
            continue
        identity = (record["path"], record["line"])
        if identity in seen:
            continue
        seen.add(identity)
        frames.append(record)
        if len(frames) >= _MAX_FRAMES:
            break

    if not frames:
        return None
    return {
        "schema": SCHEMA,
        "capture_mode": "PYTHON_TRACEBACK_TEXT",
        "frames": frames,
        "root_cause_verified": False,
        "source_execution_authorized": False,
        "candidate_execution_authorized": False,
    }


def capture_exception_source_context(
    exception: BaseException | None, project_root: str | Path
) -> dict[str, Any] | None:
    """Capture bounded, redacted frames that resolve inside the PIKA project.

    This is traceback evidence only. It does not prove causality, authorize
    execution, or make a candidate eligible for learning or promotion.
    """
    if not isinstance(exception, BaseException) or exception.__traceback__ is None:
        return None
    try:
        root = Path(project_root).expanduser().resolve(strict=True)
        if not root.is_dir():
            return None
        extracted = traceback_module.extract_tb(exception.__traceback__)
    except (OSError, RuntimeError, TypeError, ValueError):
        return None

    frames: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for frame in extracted[-(_MAX_FRAMES * 2):]:
        relative = _relative_path(frame.filename, root)
        if relative is None:
            continue
        record = _current_frame(root, relative, frame.lineno, frame.name)
        if record is None:
            continue
        identity = (record["path"], record["line"])
        if identity in seen:
            continue
        seen.add(identity)
        frames.append(record)
        if len(frames) >= _MAX_FRAMES:
            break

    if not frames:
        return None
    return {
        "schema": SCHEMA,
        "capture_mode": capture_mode,
        "frames": frames,
        "root_cause_verified": False,
        "source_execution_authorized": False,
        "candidate_execution_authorized": False,
    }


def validate_source_context(
    context: Any, project_root: str | Path
) -> dict[str, Any] | None:
    """Validate stored traceback evidence and re-check current source bindings.

    Historical snippets remain visibly historical when the current file has
    changed. A current binding is reported only when the present file hash
    exactly matches the hash captured with the traceback.
    """
    if not isinstance(context, dict) or context.get("schema") != SCHEMA:
        return None
    capture_mode = context.get("capture_mode")
    if capture_mode not in {"PYTHON_EXCEPTION_TRACEBACK", "PYTHON_TRACEBACK_TEXT"}:
        return None
    raw_frames = context.get("frames")
    if not isinstance(raw_frames, list) or not raw_frames or len(raw_frames) > _MAX_FRAMES:
        return None
    if (
        context.get("root_cause_verified") is not False
        or context.get("source_execution_authorized") is not False
        or context.get("candidate_execution_authorized") is not False
    ):
        return None
    try:
        root = Path(project_root).expanduser().resolve(strict=True)
        if not root.is_dir():
            return None
    except (OSError, RuntimeError):
        return None

    frames: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for raw in raw_frames:
        if not isinstance(raw, dict):
            continue
        relative = _relative_path(raw.get("path"), root)
        line_number = raw.get("line")
        source_sha256 = raw.get("source_sha256")
        function = raw.get("function")
        snippet = raw.get("snippet")
        if (
            relative is None
            or isinstance(line_number, bool)
            or not isinstance(line_number, int)
            or line_number < 1
            or not isinstance(source_sha256, str)
            or _DIGEST.fullmatch(source_sha256) is None
            or not isinstance(snippet, list)
            or not 1 <= len(snippet) <= _MAX_SNIPPET_LINES
            or any(not isinstance(line, str) or len(line) > _MAX_LINE_CHARS for line in snippet)
        ):
            continue

        current = _current_frame(root, relative, line_number, function)
        current_matches = bool(
            current is not None and current["source_sha256"] == source_sha256
        )
        if current_matches:
            clean_snippet = current["snippet"]
            line_start = current["line_start"]
            line_end = current["line_end"]
            source_kind = current["source_kind"]
        else:
            clean_snippet = [_redact_line(line) for line in snippet]
            line_start = raw.get("line_start")
            line_end = raw.get("line_end")
            source_kind = (
                "test" if relative.parts[0] == "tests"
                and (relative.name.startswith("test_") or relative.name.endswith("_test.py"))
                else "project"
            )
            if (
                isinstance(line_start, bool) or not isinstance(line_start, int)
                or isinstance(line_end, bool) or not isinstance(line_end, int)
                or line_start < 1 or line_end < line_start
                or line_end - line_start + 1 > _MAX_SNIPPET_LINES
            ):
                continue

        identity = (relative.as_posix(), line_number)
        if identity in seen:
            continue
        seen.add(identity)
        frames.append({
            "path": relative.as_posix(),
            "line": line_number,
            "function": _safe_function(function),
            "line_start": line_start,
            "line_end": line_end,
            "source_sha256": source_sha256,
            "snippet": clean_snippet,
            "source_kind": source_kind,
            "current_source_matches": current_matches,
        })

    if not frames:
        return None
    return {
        "schema": SCHEMA,
        "capture_mode": "PYTHON_EXCEPTION_TRACEBACK",
        "frames": frames,
        "root_cause_verified": False,
        "source_execution_authorized": False,
        "candidate_execution_authorized": False,
    }

)
_SECRET_ASSIGNMENT = re.compile(
    r"""(?i)((?:api[_-]?key|access[_-]?token|password|secret)\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;]+)"""
)
_BEARER = re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+")


def _safe_function(value: Any) -> str:
    if not isinstance(value, str):
        return "<unknown>"
    return re.sub(r"[^A-Za-z0-9_.<>-]", "_", value)[:80] or "<unknown>"


def _redact_line(value: Any) -> str:
    text = str(value)[:_MAX_LINE_CHARS]
    text = _SECRET_ASSIGNMENT.sub(r"\1[REDACTED]", text)
    text = _BEARER.sub("Bearer [REDACTED]", text)
    return text


def _relative_path(value: Any, root: Path) -> PurePosixPath | None:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        return None
    try:
        candidate = Path(value)
        if not candidate.is_absolute():
            candidate = root / candidate
        absolute = Path(os.path.abspath(str(candidate)))
        relative = absolute.relative_to(root)
    except (OSError, ValueError):
        return None
    rel = PurePosixPath(relative.as_posix())
    if (
        rel.is_absolute()
        or rel.as_posix() in {"", "."}
        or any(part in {"", ".", ".."} or part in _DENIED_PARTS for part in rel.parts)
        or rel.suffix != ".py"
    ):
        return None
    return rel


def _current_frame(
    root: Path, relative: PurePosixPath, line_number: int, function: Any
) -> dict[str, Any] | None:
    cursor = root
    try:
        for part in relative.parts:
            if cursor.is_symlink():
                return None
            cursor = cursor / part
            if cursor.is_symlink():
                return None
        resolved = cursor.resolve(strict=True)
        resolved.relative_to(root)
        if not resolved.is_file() or resolved.stat().st_size > _MAX_SOURCE_BYTES:
            return None
        raw = resolved.read_bytes()
        text = raw.decode("utf-8")
    except (OSError, UnicodeError, ValueError):
        return None

    lines = text.splitlines()
    if isinstance(line_number, bool) or not isinstance(line_number, int):
        return None
    if line_number < 1 or line_number > max(1, len(lines)):
        return None

    start = max(1, line_number - 3)
    end = min(len(lines), line_number + 3)
    snippet = [_redact_line(line) for line in lines[start - 1:end]]
    source_kind = "test" if (
        relative.parts[0] == "tests"
        and (relative.name.startswith("test_") or relative.name.endswith("_test.py"))
    ) else "project"
    return {
        "path": relative.as_posix(),
        "line": line_number,
        "function": _safe_function(function),
        "line_start": start,
        "line_end": end,
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "snippet": snippet[:_MAX_SNIPPET_LINES],
        "source_kind": source_kind,
        "current_source_matches": True,
    }


def capture_exception_source_context(
    exception: BaseException | None, project_root: str | Path
) -> dict[str, Any] | None:
    """Capture bounded, redacted frames that resolve inside the PIKA project.

    This is traceback evidence only. It does not prove causality, authorize
    execution, or make a candidate eligible for learning or promotion.
    """
    if not isinstance(exception, BaseException) or exception.__traceback__ is None:
        return None
    try:
        root = Path(project_root).expanduser().resolve(strict=True)
        if not root.is_dir():
            return None
        extracted = traceback_module.extract_tb(exception.__traceback__)
    except (OSError, RuntimeError, TypeError, ValueError):
        return None

    frames: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for frame in extracted[-(_MAX_FRAMES * 2):]:
        relative = _relative_path(frame.filename, root)
        if relative is None:
            continue
        record = _current_frame(root, relative, frame.lineno, frame.name)
        if record is None:
            continue
        identity = (record["path"], record["line"])
        if identity in seen:
            continue
        seen.add(identity)
        frames.append(record)
        if len(frames) >= _MAX_FRAMES:
            break

    if not frames:
        return None
    return {
        "schema": SCHEMA,
        "capture_mode": "PYTHON_EXCEPTION_TRACEBACK",
        "frames": frames,
        "root_cause_verified": False,
        "source_execution_authorized": False,
        "candidate_execution_authorized": False,
    }


def validate_source_context(
    context: Any, project_root: str | Path
) -> dict[str, Any] | None:
    """Validate stored traceback evidence and re-check current source bindings.

    Historical snippets remain visibly historical when the current file has
    changed. A current binding is reported only when the present file hash
    exactly matches the hash captured with the traceback.
    """
    if not isinstance(context, dict) or context.get("schema") != SCHEMA:
        return None
    raw_frames = context.get("frames")
    if not isinstance(raw_frames, list) or not raw_frames or len(raw_frames) > _MAX_FRAMES:
        return None
    if (
        context.get("root_cause_verified") is not False
        or context.get("source_execution_authorized") is not False
        or context.get("candidate_execution_authorized") is not False
    ):
        return None
    try:
        root = Path(project_root).expanduser().resolve(strict=True)
        if not root.is_dir():
            return None
    except (OSError, RuntimeError):
        return None

    frames: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for raw in raw_frames:
        if not isinstance(raw, dict):
            continue
        relative = _relative_path(raw.get("path"), root)
        line_number = raw.get("line")
        source_sha256 = raw.get("source_sha256")
        function = raw.get("function")
        snippet = raw.get("snippet")
        if (
            relative is None
            or isinstance(line_number, bool)
            or not isinstance(line_number, int)
            or line_number < 1
            or not isinstance(source_sha256, str)
            or _DIGEST.fullmatch(source_sha256) is None
            or not isinstance(snippet, list)
            or not 1 <= len(snippet) <= _MAX_SNIPPET_LINES
            or any(not isinstance(line, str) or len(line) > _MAX_LINE_CHARS for line in snippet)
        ):
            continue

        current = _current_frame(root, relative, line_number, function)
        current_matches = bool(
            current is not None and current["source_sha256"] == source_sha256
        )
        if current_matches:
            clean_snippet = current["snippet"]
            line_start = current["line_start"]
            line_end = current["line_end"]
            source_kind = current["source_kind"]
        else:
            clean_snippet = [_redact_line(line) for line in snippet]
            line_start = raw.get("line_start")
            line_end = raw.get("line_end")
            source_kind = (
                "test" if relative.parts[0] == "tests"
                and (relative.name.startswith("test_") or relative.name.endswith("_test.py"))
                else "project"
            )
            if (
                isinstance(line_start, bool) or not isinstance(line_start, int)
                or isinstance(line_end, bool) or not isinstance(line_end, int)
                or line_start < 1 or line_end < line_start
                or line_end - line_start + 1 > _MAX_SNIPPET_LINES
            ):
                continue

        identity = (relative.as_posix(), line_number)
        if identity in seen:
            continue
        seen.add(identity)
        frames.append({
            "path": relative.as_posix(),
            "line": line_number,
            "function": _safe_function(function),
            "line_start": line_start,
            "line_end": line_end,
            "source_sha256": source_sha256,
            "snippet": clean_snippet,
            "source_kind": source_kind,
            "current_source_matches": current_matches,
        })

    if not frames:
        return None
    return {
        "schema": SCHEMA,
        "capture_mode": "PYTHON_EXCEPTION_TRACEBACK",
        "frames": frames,
        "root_cause_verified": False,
        "source_execution_authorized": False,
        "candidate_execution_authorized": False,
    }
