from __future__ import annotations

import ast
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


DEFAULT_EXCLUDED_DIRS = {
    ".git", ".venv", "venv", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", "node_modules", "dist", "build",
    ".idea", ".gradle", "backups", "logs", "data", ".pika",
}


@dataclass(frozen=True)
class SourceFile:
    path: str
    size_bytes: int
    line_count: int
    sha256: str
    syntax_ok: bool
    syntax_error: str | None
    classes: tuple[str, ...]
    functions: tuple[str, ...]
    imports: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ProjectSnapshot:
    project_root: str
    scanned_at: str
    files: list[SourceFile]
    skipped_files: list[dict[str, str]]

    def summary(self) -> dict[str, int]:
        return {
            "python_files": len(self.files),
            "syntax_pass": sum(x.syntax_ok for x in self.files),
            "syntax_fail": sum(not x.syntax_ok for x in self.files),
            "skipped_files": len(self.skipped_files),
            "classes": sum(len(x.classes) for x in self.files),
            "functions": sum(len(x.functions) for x in self.files),
            "lines": sum(x.line_count for x in self.files),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_root": self.project_root,
            "scanned_at": self.scanned_at,
            "summary": self.summary(),
            "files": [item.to_dict() for item in self.files],
            "skipped_files": self.skipped_files,
        }


class SourceScanner:
    """Read-only Python source inventory. Symlinks are never followed."""

    def __init__(
        self,
        project_root: str | Path,
        *,
        excluded_dirs: set[str] | None = None,
        max_file_bytes: int = 2 * 1024 * 1024,
    ) -> None:
        self.root = Path(project_root).expanduser().resolve()
        self.excluded_dirs = set(excluded_dirs or DEFAULT_EXCLUDED_DIRS)
        self.max_file_bytes = max(1, int(max_file_bytes))

    def scan(self) -> ProjectSnapshot:
        from datetime import datetime, timezone

        if not self.root.is_dir():
            raise NotADirectoryError(f"Project root does not exist: {self.root}")

        records: list[SourceFile] = []
        skipped: list[dict[str, str]] = []

        for path in sorted(self.root.rglob("*.py")):
            try:
                rel = path.relative_to(self.root)
            except ValueError:
                continue

            if path.is_symlink() or any(part in self.excluded_dirs for part in rel.parts):
                continue

            try:
                stat = path.stat()
                if stat.st_size > self.max_file_bytes:
                    skipped.append({"path": rel.as_posix(), "reason": "file_too_large"})
                    continue
                raw = path.read_bytes()
                source = raw.decode("utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                skipped.append({"path": rel.as_posix(), "reason": type(exc).__name__})
                continue

            try:
                tree = ast.parse(source, filename=rel.as_posix())
                syntax_ok, syntax_error = True, None
                classes = tuple(sorted({n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)}))
                functions = tuple(sorted({n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}))
                imports: set[str] = set()
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        imports.update(alias.name for alias in node.names)
                    elif isinstance(node, ast.ImportFrom):
                        imports.add("." * node.level + (node.module or ""))
            except SyntaxError as exc:
                syntax_ok = False
                syntax_error = f"{exc.msg} at line {exc.lineno}, column {exc.offset}"
                classes, functions, imports = (), (), set()

            import hashlib
            records.append(SourceFile(
                path=rel.as_posix(),
                size_bytes=len(raw),
                line_count=len(source.splitlines()),
                sha256=hashlib.sha256(raw).hexdigest(),
                syntax_ok=syntax_ok,
                syntax_error=syntax_error,
                classes=classes,
                functions=functions,
                imports=tuple(sorted(imports)),
            ))

        return ProjectSnapshot(
            project_root=str(self.root),
            scanned_at=datetime.now(timezone.utc).isoformat(),
            files=records,
            skipped_files=skipped,
        )
