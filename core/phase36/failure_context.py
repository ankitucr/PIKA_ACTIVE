"""Bounded, path-safe source context for local failure diagnostics.

Reads Python source as data. It never imports/evaluates project code or claims
that a traceback location is a proven root cause.
"""
from __future__ import annotations

import ast
import hashlib
import re
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

MAX_SOURCE_FILE_BYTES = 1_000_000
MAX_CONTEXT_BYTES = 64 * 1024
MAX_CONTEXT_FILES = 8
DEFAULT_RADIUS = 5

_ALLOWED_ROOTS = {
    "agents", "config", "core", "evaluation", "learning", "models",
    "skills", "tests", "tools", "workspace",
}
_ALLOWED_ROOT_FILES = {"main.py", "pika.py", "pika_live.py"}
_DENIED_PARTS = {
    ".git", ".venv", ".sandbox_venv", ".pika", "__pycache__",
    ".pytest_cache", "data", "memory", "storage", "PIKA_KNOWLEDGE",
    "backups", "logs", "node_modules", "site-packages",
}
_FRAME = re.compile(
    r"""File\s+["'](?P<path>[^"']+?\.py)["']\s*,\s*line\s+(?P<line>\d+)(?:,\s*in\s+(?P<function>[^\r\n]+))?"""
)
_LOCATION = re.compile(
    r"""(?P<path>(?:[A-Za-z]:)?[^\s:'"]+?\.py):(?P<line>\d+)(?::\d+)?"""
)
_FAILED = re.compile(r"""(?m)^FAILED\s+(?P<node>[^\s]+\.py)(?:::\S+)?""")
_SECRET_PATTERNS = (
    re.compile(r"(?i)\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|password|passwd|secret)\b\s*[:=]\s*[^\s,;]+"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
)


def _redact(value: str) -> str:
    result = value
    for pattern in _SECRET_PATTERNS:
        result = pattern.sub("[REDACTED]", result)
    return result


def _map_runner_path(raw: str) -> str | None:
    value = str(raw or "").strip().replace("\\", "/")
    if not value or "\x00" in value:
        return None
    for marker in ("/work/", "/project/"):
        if marker in value:
            value = value.rsplit(marker, 1)[1]
            break
    while value.startswith("./"):
        value = value[2:]
    rel = PurePosixPath(value)
    if rel.is_absolute() or not rel.parts or ".." in rel.parts:
        return None
    if rel.suffix.lower() != ".py":
        return None
    if any(part in _DENIED_PARTS for part in rel.parts):
        return None
    if rel.parts[0] not in _ALLOWED_ROOTS and rel.as_posix() not in _ALLOWED_ROOT_FILES:
        return None
    if any(part.startswith(".") for part in rel.parts):
        return None
    return rel.as_posix()



def _call_target(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_target(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _ast_context(source_text: str, line_number: int | None) -> dict[str, Any]:
    """Describe enclosing symbols and static calls without executing source."""
    if line_number is None:
        return {
            "parse_status": "not_attempted",
            "reason": "no_traceback_line",
            "enclosing_symbols": [],
            "imports": [],
            "calls": [],
        }
    try:
        tree = ast.parse(source_text, type_comments=True)
    except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
        return {
            "parse_status": "syntax_error" if isinstance(exc, SyntaxError) else "parse_unavailable",
            "parse_error": getattr(exc, "msg", type(exc).__name__)[:200],
            "parse_error_line": getattr(exc, "lineno", None),
            "enclosing_symbols": [],
            "imports": [],
            "calls": [],
        }

    symbol_nodes = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        start = getattr(node, "lineno", None)
        end = getattr(node, "end_lineno", start)
        if isinstance(start, int) and isinstance(end, int) and start <= line_number <= end:
            symbol_nodes.append(node)
    symbol_nodes.sort(
        key=lambda node: (
            -(getattr(node, "end_lineno", node.lineno) - node.lineno),
            node.lineno,
            node.name,
        )
    )

    enclosing_symbols = []
    for node in symbol_nodes[-8:]:
        kind = "class" if isinstance(node, ast.ClassDef) else (
            "async_function" if isinstance(node, ast.AsyncFunctionDef) else "function"
        )
        enclosing_symbols.append({
            "kind": kind,
            "name": node.name,
            "start_line": node.lineno,
            "end_line": getattr(node, "end_lineno", node.lineno),
        })

    classes = [node for node in symbol_nodes if isinstance(node, ast.ClassDef)]
    functions = [
        node for node in symbol_nodes
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    nearest_class = min(
        classes,
        key=lambda node: getattr(node, "end_lineno", node.lineno) - node.lineno,
        default=None,
    )
    nearest_function = min(
        functions,
        key=lambda node: getattr(node, "end_lineno", node.lineno) - node.lineno,
        default=None,
    )

    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            imports.extend(
                f"{module}.{alias.name}" if module else alias.name
                for alias in node.names
            )
    imports = list(dict.fromkeys(imports))

    calls = []
    call_count = 0
    call_scope = nearest_function or nearest_class or tree
    for node in ast.walk(call_scope):
        if not isinstance(node, ast.Call):
            continue
        call_line = getattr(node, "lineno", None)
        if nearest_function is None and isinstance(call_line, int):
            if abs(call_line - line_number) > 5:
                continue
        call_count += 1
        name = _call_target(node.func)
        if name and name not in calls:
            calls.append(name)

    class_name = nearest_class.name if nearest_class is not None else None
    function_name = nearest_function.name if nearest_function is not None else None
    qualified = ".".join(x for x in (class_name, function_name) if x) or None
    parameters = []
    if nearest_function is not None:
        args = nearest_function.args
        parameters = [
            item.arg for item in (
                list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs)
            )
        ]
        if args.vararg is not None:
            parameters.append("*" + args.vararg.arg)
        if args.kwarg is not None:
            parameters.append("**" + args.kwarg.arg)

    return {
        "parse_status": "parsed",
        "enclosing_symbols": enclosing_symbols,
        "enclosing_class": class_name,
        "enclosing_function": function_name,
        "qualified_symbol": qualified,
        "parameters": parameters[:32],
        "imports": imports[:32],
        "import_count": len(imports),
        "calls": calls[:32],
        "call_count": call_count,
        "call_scope": qualified or "local_module_region",
        "calls_truncated": len(calls) > 32,
    }


class FailureContextExtractor:
    """Collect small, redacted snippets referenced by a diagnostic traceback."""

    def __init__(self, project_root: str | Path, *, max_files: int = MAX_CONTEXT_FILES,
                 max_bytes: int = MAX_CONTEXT_BYTES, radius: int = DEFAULT_RADIUS):
        self.root = Path(project_root).expanduser().resolve()
        if not self.root.is_dir():
            raise ValueError("project_root must be an existing directory.")
        if isinstance(max_files, bool) or not 1 <= int(max_files) <= MAX_CONTEXT_FILES:
            raise ValueError(f"max_files must be between 1 and {MAX_CONTEXT_FILES}.")
        if isinstance(max_bytes, bool) or not 1024 <= int(max_bytes) <= MAX_CONTEXT_BYTES:
            raise ValueError(f"max_bytes must be between 1024 and {MAX_CONTEXT_BYTES}.")
        if isinstance(radius, bool) or not 0 <= int(radius) <= 20:
            raise ValueError("radius must be between 0 and 20.")
        self.max_files = int(max_files)
        self.max_bytes = int(max_bytes)
        self.radius = int(radius)

    def _select_file(self, rel_text: str, overlay_root: Path | None,
                     overlay_paths: set[str]) -> tuple[Path | None, str, str]:
        rel = PurePosixPath(rel_text)
        if overlay_root is not None and rel_text in overlay_paths:
            cursor = overlay_root
            for part in rel.parts:
                cursor = cursor / part
                if cursor.is_symlink():
                    return None, "candidate_symlink_rejected", "candidate_overlay"
            try:
                candidate = cursor.resolve(strict=True)
                candidate.relative_to(overlay_root)
            except (OSError, ValueError):
                candidate = None
            if candidate is not None and candidate.is_file():
                try:
                    if candidate.stat().st_size > MAX_SOURCE_FILE_BYTES:
                        return None, "source_file_too_large", "candidate_overlay"
                except OSError:
                    return None, "candidate_source_unavailable", "candidate_overlay"
                return candidate, "ok", "candidate_overlay"

        cursor = self.root
        for part in rel.parts:
            cursor = cursor / part
            if cursor.is_symlink():
                return None, "symlink_rejected", "project_baseline"
        try:
            source = cursor.resolve(strict=True)
            source.relative_to(self.root)
        except (OSError, ValueError):
            return None, "source_unavailable", "project_baseline"
        if not source.is_file():
            return None, "not_a_regular_file", "project_baseline"
        try:
            if source.stat().st_size > MAX_SOURCE_FILE_BYTES:
                return None, "source_file_too_large", "project_baseline"
        except OSError:
            return None, "source_unavailable", "project_baseline"
        return source, "ok", "project_baseline"

    def collect(self, output: Any, *, test_path: str = "",
                overlay_root: str | Path | None = None,
                overlay_paths: Iterable[str] | None = None) -> dict[str, Any]:
        text = output if isinstance(output, str) else ""
        text = text[-MAX_CONTEXT_BYTES:]
        overlay = Path(overlay_root).expanduser().resolve() if overlay_root is not None else None
        allowed_overlay = {
            rel for item in (overlay_paths or ())
            if (rel := _map_runner_path(str(item))) is not None
        }
        locations: list[dict[str, Any]] = []

        def add(raw_path: str, line: int | None, function: str | None, source: str) -> None:
            rel = _map_runner_path(raw_path)
            if not rel or (line is not None and (isinstance(line, bool) or line < 1)):
                return
            key = (rel, line, function)
            if any((x["path"], x.get("line"), x.get("function")) == key for x in locations):
                return
            locations.append({"path": rel, "line": line, "function": function, "source": source})

        for match in _FRAME.finditer(text):
            try:
                line = int(match.group("line"))
            except (TypeError, ValueError):
                continue
            add(match.group("path"), line,
                (match.group("function") or "").strip() or None, "traceback_frame")
        for match in _LOCATION.finditer(text):
            try:
                line = int(match.group("line"))
            except (TypeError, ValueError):
                continue
            add(match.group("path"), line, None, "pytest_location")
        for match in _FAILED.finditer(text):
            add(match.group("node"), None, None, "failed_test")
        if test_path:
            add(test_path, None, None, "requested_test")

        locations = list(reversed(locations))[:self.max_files]
        snippets: list[dict[str, Any]] = []
        omitted: list[dict[str, str]] = []
        total_bytes = 0

        for location in locations:
            path, status, view = self._select_file(location["path"], overlay, allowed_overlay)
            if path is None:
                omitted.append({"path": location["path"], "reason": status})
                continue
            try:
                raw = path.read_bytes()
                source_text = raw.decode("utf-8")
            except (OSError, UnicodeError):
                omitted.append({"path": location["path"], "reason": "source_unreadable"})
                continue
            lines = source_text.splitlines()
            if not lines:
                omitted.append({"path": location["path"], "reason": "empty_source"})
                continue
            line_number = location.get("line")
            start = max(1, line_number - self.radius) if line_number else 1
            end = min(len(lines), line_number + self.radius) if line_number else min(len(lines), self.radius * 2 + 1)
            rendered = "\n".join(
                f"{index}: {_redact(lines[index - 1])[:1000]}"
                for index in range(start, end + 1)
            )
            used = len(rendered.encode("utf-8"))
            if total_bytes + used > self.max_bytes:
                omitted.append({"path": location["path"], "reason": "context_budget_exhausted"})
                continue
            total_bytes += used
            snippets.append({
                **location,
                "start_line": start,
                "end_line": end,
                "source_sha256": hashlib.sha256(raw).hexdigest(),
                "content": rendered,
                "ast_context": _ast_context(source_text, line_number),
                "source_view": view,
            })

        return {
            "schema": "pika.failure_context.v1",
            "context_kind": "traceback_referenced_static_source",
            "snippets": snippets,
            "omitted": omitted,
            "limits": {
                "max_files": self.max_files,
                "max_context_bytes": self.max_bytes,
                "max_source_file_bytes": MAX_SOURCE_FILE_BYTES,
                "source_executed": False,
                "source_imported": False,
                "causal_claim": False,
                "interpretation": "Source context helps explain a failure; it does not establish root cause or authorize repair.",
            },
        }
