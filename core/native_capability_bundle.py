"""Multi-file capability bundle intake and immutable staging.

Source is treated strictly as data. This module parses Python ASTs and copies
hash-bound files into a review workspace; it never imports, executes, tests,
installs, trusts, or promotes the acquired code.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shutil
import tempfile
import uuid
from pathlib import Path, PurePosixPath
from typing import Any


SCHEMA = "pika.native_capability_bundle.v1"
MAX_FILES = 200
MAX_FILE_BYTES = 500_000
MAX_TOTAL_BYTES = 5_000_000
MAX_AST_NODES_PER_FILE = 100_000
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}")
_IGNORED_PARTS = {".git", ".venv", "venv", "__pycache__", "node_modules", ".pytest_cache"}
_FORBIDDEN_NAMES = {".env", ".env.local", ".env.production", "id_rsa", "id_ed25519"}


class CapabilityBundleError(ValueError):
    """A capability bundle failed intake or staging validation."""


def _relative(value: Any) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise CapabilityBundleError("Bundle paths must be non-empty relative POSIX paths.")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or any(
        part in {"", ".", ".."} or part.startswith(".") for part in path.parts
    ):
        raise CapabilityBundleError("Absolute, hidden, traversal, and ambiguous paths are rejected.")
    if path.suffix != ".py":
        raise CapabilityBundleError("Only Python source and test files are accepted in this phase.")
    return path


def _module_name(path: PurePosixPath) -> str:
    parts = list(path.parts)
    if parts[-1] == "__init__.py":
        parts.pop()
    else:
        parts[-1] = path.stem
    return ".".join(parts)


def _imports(tree: ast.AST, current_module: str) -> tuple[list[str], list[str]]:
    internal: set[str] = set()
    external: set[str] = set()
    package = current_module.split(".")[:-1]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                (internal if alias.name.split(".")[0] == "core" else external).add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                keep = max(0, len(package) - node.level + 1)
                base = package[:keep]
                if node.module:
                    base.extend(node.module.split("."))
                name = ".".join(base)
            else:
                name = node.module or ""
            if name:
                (internal if name.split(".")[0] == "core" else external).add(name)
    return sorted(internal), sorted(external)


def _source_flags(tree: ast.AST) -> list[str]:
    flags: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in {"eval", "exec", "compile", "__import__"}:
                flags.add("DYNAMIC_CODE_OR_IMPORT_PRIMITIVE")
            elif isinstance(func, ast.Attribute) and func.attr in {"system", "popen"}:
                flags.add("PROCESS_EXECUTION_SURFACE")
            elif isinstance(func, ast.Name) and func.id == "__import__":
                flags.add("DYNAMIC_CODE_OR_IMPORT_PRIMITIVE")
        if isinstance(node, ast.Import):
            if any(alias.name.split(".")[0] in {"subprocess", "ctypes", "socket"} for alias in node.names):
                flags.add("SENSITIVE_RUNTIME_IMPORT")
        if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] in {"subprocess", "ctypes", "socket"}:
            flags.add("SENSITIVE_RUNTIME_IMPORT")
    return sorted(flags)


class NativeCapabilityBundleEngine:
    """Stage bounded multi-file Python capabilities as untrusted review artifacts."""

    def __init__(self, knowledge_root: str | Path) -> None:
        requested = Path(knowledge_root).expanduser()
        if requested.is_symlink():
            raise CapabilityBundleError("Knowledge root must not be a symlink.")
        self.knowledge = requested.resolve()
        self.staging = self.knowledge / "CAPABILITY_STAGING"
        self.staging.mkdir(parents=True, exist_ok=True)
        if self.staging.is_symlink():
            raise CapabilityBundleError("Capability staging root must not be a symlink.")

    def stage_bundle(
        self,
        source_root: str | Path,
        *,
        name: str,
        include_paths: list[str],
        test_paths: list[str] | None = None,
    ) -> dict[str, Any]:
        if not isinstance(name, str) or not _NAME.fullmatch(name):
            raise CapabilityBundleError("Bundle name must be a short identifier.")
        root_requested = Path(source_root).expanduser()
        if root_requested.is_symlink():
            raise CapabilityBundleError("Source root must not be a symlink.")
        root = root_requested.resolve(strict=True)
        if not root.is_dir():
            raise CapabilityBundleError("Source root must be a directory.")
        if not isinstance(include_paths, list) or not include_paths or len(include_paths) > MAX_FILES:
            raise CapabilityBundleError(f"Provide 1 to {MAX_FILES} explicit Python paths.")
        if test_paths is None:
            test_paths = []
        if not isinstance(test_paths, list) or len(test_paths) > MAX_FILES:
            raise CapabilityBundleError("test_paths must be a bounded list.")
        normalized = [_relative(item).as_posix() for item in include_paths]
        if len(set(normalized)) != len(normalized):
            raise CapabilityBundleError("Duplicate bundle paths are rejected.")
        tests = [_relative(item).as_posix() for item in test_paths]
        if len(set(tests)) != len(tests) or not set(tests).issubset(set(normalized)):
            raise CapabilityBundleError("Every test path must be unique and included in the bundle.")

        rows: list[dict[str, Any]] = []
        total_bytes = 0
        modules: dict[str, str] = {}
        for relative in sorted(normalized):
            rel = PurePosixPath(relative)
            if any(part in _IGNORED_PARTS or part in _FORBIDDEN_NAMES for part in rel.parts):
                raise CapabilityBundleError("Ignored, secret-like, or dependency-cache paths are forbidden.")
            current = root
            for part in rel.parts:
                current = current / part
                if current.is_symlink():
                    raise CapabilityBundleError(f"Symlink source rejected: {relative}")
            path = current.resolve(strict=True)
            try:
                path.relative_to(root)
            except ValueError as exc:
                raise CapabilityBundleError("Source path escapes the selected root.") from exc
            if not path.is_file():
                raise CapabilityBundleError(f"Source path is not a regular file: {relative}")
            raw = path.read_bytes()
            if not raw or len(raw) > MAX_FILE_BYTES or b"\x00" in raw:
                raise CapabilityBundleError(f"Empty, oversized, or binary source rejected: {relative}")
            total_bytes += len(raw)
            if total_bytes > MAX_TOTAL_BYTES:
                raise CapabilityBundleError("Bundle exceeds the total source-byte budget.")
            try:
                source = raw.decode("utf-8")
                tree = ast.parse(source, filename=relative)
            except (UnicodeError, SyntaxError) as exc:
                raise CapabilityBundleError(f"Python source cannot be parsed: {relative}") from exc
            node_count = sum(1 for _ in ast.walk(tree))
            if node_count > MAX_AST_NODES_PER_FILE:
                raise CapabilityBundleError(f"AST node budget exceeded: {relative}")
            module = _module_name(rel)
            if module in modules:
                raise CapabilityBundleError(f"Duplicate Python module identity: {module}")
            modules[module] = relative
            internal, external = _imports(tree, module)
            rows.append({
                "path": relative,
                "module": module,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size_bytes": len(raw),
                "ast_node_count": node_count,
                "internal_imports": internal,
                "external_imports": external,
                "static_risk_flags": _source_flags(tree),
                "is_test": relative in tests,
            })

        module_names = set(modules)
        unresolved_internal = sorted({
            dependency
            for row in rows
            for dependency in row["internal_imports"]
            if dependency.startswith("core.") and dependency not in module_names
            and not any(candidate.startswith(dependency + ".") for candidate in module_names)
        })
        manifest_core = {
            "schema": SCHEMA,
            "bundle_id": uuid.uuid4().hex,
            "name": name,
            "files": rows,
            "test_paths": sorted(tests),
            "file_count": len(rows),
            "total_bytes": total_bytes,
            "internal_dependency_gaps": unresolved_internal,
            "external_dependencies": sorted({dep for row in rows for dep in row["external_imports"]}),
            "source_root_label": root.name[:120],
            "trust": "UNTRUSTED_SOURCE_OBSERVATION",
            "review_status": "NEEDS_HUMAN_REVIEW",
            "execution_performed": False,
            "tests_executed": False,
            "source_imported": False,
            "live_source_modified": False,
            "trusted_learning_admission": False,
            "production_promotion_allowed": False,
        }
        canonical = json.dumps(manifest_core, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        manifest_core["manifest_sha256"] = hashlib.sha256(canonical).hexdigest()

        destination = self.staging / manifest_core["bundle_id"]
        temp = Path(tempfile.mkdtemp(prefix=".bundle-", dir=self.staging))
        try:
            for row in rows:
                relative = PurePosixPath(row["path"])
                source = root
                for part in relative.parts:
                    source = source / part
                    if source.is_symlink():
                        raise CapabilityBundleError(f"Symlink source appeared during staging: {row['path']}")
                source = source.resolve(strict=True)
                try:
                    source.relative_to(root)
                except ValueError as exc:
                    raise CapabilityBundleError("Source path escaped its root during staging.") from exc
                target = temp.joinpath(*relative.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                raw = source.read_bytes()
                rechecked = root
                for part in relative.parts:
                    rechecked = rechecked / part
                    if rechecked.is_symlink():
                        raise CapabilityBundleError(f"Symlink source appeared during staging: {row['path']}")
                if rechecked.resolve(strict=True) != source or hashlib.sha256(raw).hexdigest() != row["sha256"]:
                    raise CapabilityBundleError(f"Source changed during staging: {row['path']}")
                with target.open("xb") as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
            manifest_path = temp / "bundle.json"
            with manifest_path.open("x", encoding="utf-8") as stream:
                json.dump(manifest_core, stream, indent=2, ensure_ascii=False, allow_nan=False)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, destination)
        except Exception:
            shutil.rmtree(temp, ignore_errors=True)
            raise

        return {
            "success": True,
            "schema": SCHEMA,
            "bundle_id": manifest_core["bundle_id"],
            "bundle_name": name,
            "bundle_path": str(destination),
            "manifest_sha256": manifest_core["manifest_sha256"],
            "file_count": len(rows),
            "total_bytes": total_bytes,
            "test_count": len(tests),
            "internal_dependency_gaps": unresolved_internal,
            "external_dependencies": manifest_core["external_dependencies"],
            "risk_flag_count": sum(len(row["static_risk_flags"]) for row in rows),
            "trust": manifest_core["trust"],
            "review_status": manifest_core["review_status"],
            "execution_performed": False,
            "tests_executed": False,
            "source_imported": False,
            "live_source_modified": False,
            "trusted_learning_admission": False,
            "production_promotion_allowed": False,
            "next_required_step": "dependency_and_capability_review_then_disposable_isolated_evaluation",
        }
