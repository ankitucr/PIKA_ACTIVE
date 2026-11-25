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
import sys
import tempfile
import uuid
from pathlib import Path, PurePosixPath
from typing import Any


SCHEMA = "pika.native_capability_bundle.v1"
MAX_FILES = 1000
MAX_FILE_BYTES = 2_000_000
MAX_TOTAL_BYTES = 25_000_000
MAX_AST_NODES_PER_FILE = 500_000
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


def _imports(tree: ast.AST, current_module: str) -> list[str]:
    imports: set[str] = set()
    package = current_module.split(".")[:-1]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
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
                imports.add(name)
    return sorted(imports)


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

    def __init__(self, knowledge_root: str | Path, *, project_root: str | Path | None = None) -> None:
        requested = Path(knowledge_root).expanduser()
        if requested.is_symlink():
            raise CapabilityBundleError("Knowledge root must not be a symlink.")
        self.knowledge = requested.resolve()
        self.project_root = Path(project_root).expanduser().resolve() if project_root is not None else self.knowledge.parent
        self.staging = self.knowledge / "CAPABILITY_STAGING"
        self.staging.mkdir(parents=True, exist_ok=True)
        if self.staging.is_symlink():
            raise CapabilityBundleError("Capability staging root must not be a symlink.")

    def evaluate_bundle(
        self,
        bundle_id: str,
        *,
        acknowledge_untrusted_sandbox: bool,
        timeout: int = 120,
    ) -> dict[str, Any]:
        """Run an explicitly acknowledged bundle test set in the PC Docker sandbox."""
        if not isinstance(bundle_id, str) or not re.fullmatch(r"[0-9a-f]{32}", bundle_id):
            raise CapabilityBundleError("A valid staged bundle ID is required.")
        if acknowledge_untrusted_sandbox is not True:
            raise CapabilityBundleError("Explicit acknowledgement of untrusted local sandbox evidence is required.")
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 600:
            raise CapabilityBundleError("Evaluation timeout must be between 1 and 600 seconds.")
        bundle_root = self.staging / bundle_id
        if bundle_root.is_symlink() or not bundle_root.is_dir():
            raise CapabilityBundleError("Staged capability bundle was not found or is unsafe.")
        manifest_path = bundle_root / "bundle.json"
        if manifest_path.is_symlink() or not manifest_path.is_file():
            raise CapabilityBundleError("Bundle manifest is missing or unsafe.")
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CapabilityBundleError("Bundle manifest is unreadable.") from exc
        if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA or manifest.get("bundle_id") != bundle_id:
            raise CapabilityBundleError("Bundle manifest identity or schema mismatch.")
        expected_manifest_sha = manifest.get("manifest_sha256")
        canonical_payload = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
        actual_manifest_sha = hashlib.sha256(
            json.dumps(canonical_payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        ).hexdigest()
        if not isinstance(expected_manifest_sha, str) or expected_manifest_sha != actual_manifest_sha:
            raise CapabilityBundleError("Bundle manifest digest mismatch.")
        rows = manifest.get("files")
        tests = manifest.get("test_paths")
        if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_FILES:
            raise CapabilityBundleError("Bundle file inventory is invalid.")
        if not isinstance(tests, list) or not 1 <= len(tests) <= 20:
            raise CapabilityBundleError("At least one explicitly included test file is required.")
        paths: list[str] = []
        source_hashes: dict[str, str] = {}
        for row in rows:
            if not isinstance(row, dict):
                raise CapabilityBundleError("Bundle file inventory contains an invalid row.")
            relative = _relative(row.get("path")).as_posix()
            expected = row.get("sha256")
            if relative in source_hashes or not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
                raise CapabilityBundleError("Bundle source hash inventory is invalid.")
            current = bundle_root
            for part in PurePosixPath(relative).parts:
                current = current / part
                if current.is_symlink():
                    raise CapabilityBundleError(f"Staged bundle symlink rejected: {relative}")
            source = current.resolve(strict=True)
            try:
                source.relative_to(bundle_root.resolve(strict=True))
            except ValueError as exc:
                raise CapabilityBundleError("Staged bundle source escaped its root.") from exc
            raw = source.read_bytes()
            if hashlib.sha256(raw).hexdigest() != expected:
                raise CapabilityBundleError(f"Staged bundle file digest mismatch: {relative}")
            paths.append(relative)
            source_hashes[relative] = expected
        normalized_tests = [_relative(item).as_posix() for item in tests]
        if len(set(normalized_tests)) != len(normalized_tests) or not set(normalized_tests).issubset(set(paths)):
            raise CapabilityBundleError("Bundle tests are not a unique subset of its hash-bound files.")

        workspace = self.project_root / "workspace"
        if workspace.is_symlink():
            raise CapabilityBundleError("Project workspace must not be a symlink.")
        workspace.mkdir(parents=True, exist_ok=True)
        evaluation_name = "pika_capability_eval_" + uuid.uuid4().hex
        evaluation_root = workspace / evaluation_name
        evaluation_root.mkdir(mode=0o700)
        try:
            for relative in paths:
                pure = PurePosixPath(relative)
                source = bundle_root.joinpath(*pure.parts)
                target = evaluation_root.joinpath(*pure.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                raw = source.read_bytes()
                if hashlib.sha256(raw).hexdigest() != source_hashes[relative]:
                    raise CapabilityBundleError(f"Staged bundle changed during evaluation preparation: {relative}")
                with target.open("xb") as stream:
                    stream.write(raw)
            source_paths = [f"workspace/{evaluation_name}/{item}" for item in paths]
            test_paths = [f"workspace/{evaluation_name}/{item}" for item in normalized_tests]
            from core.host.pc_body import PCBodyRuntime
            result = PCBodyRuntime(self.project_root).run_tests(
                source_paths=source_paths,
                test_paths=test_paths,
                timeout=timeout,
                acknowledge_untrusted_sandbox=True,
            )
        finally:
            shutil.rmtree(evaluation_root, ignore_errors=True)

        success = result.get("success") is True
        return {
            "success": success,
            "schema": "pika.native_capability_evaluation.v1",
            "bundle_id": bundle_id,
            "bundle_manifest_sha256": expected_manifest_sha,
            "file_count": len(paths),
            "test_count": len(normalized_tests),
            "sandbox_result": result,
            "execution_performed": bool(result.get("execution_started", False)),
            "sandboxed": result.get("sandboxed") is True,
            "attested": False,
            "trust": "UNVERIFIED_LOCAL",
            "trusted_learning_admission": False,
            "production_promotion_allowed": False,
            "next_required_step": "independent_result_attestation_and_capability_delta_review",
        }

    def verify_staged_bundle(self, bundle_id: str) -> dict[str, Any]:
        """Re-hash a staged multi-file bundle before it can enter evaluation."""
        if not isinstance(bundle_id, str) or re.fullmatch(r"[0-9a-f]{32}", bundle_id) is None:
            return {"success": False, "verified": False, "error": "INVALID_BUNDLE_ID"}
        bundle_root = self.staging / bundle_id
        manifest_path = bundle_root / "bundle.json"
        try:
            if bundle_root.is_symlink() or not bundle_root.is_dir():
                raise CapabilityBundleError("Bundle directory is missing or unsafe.")
            if manifest_path.is_symlink() or not manifest_path.is_file():
                raise CapabilityBundleError("Bundle manifest is missing or unsafe.")
            if manifest_path.stat().st_size > 2_000_000:
                raise CapabilityBundleError("Bundle manifest exceeds the verification limit.")

            def reject_duplicates(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise CapabilityBundleError("Duplicate manifest key.")
                    result[key] = value
                return result

            manifest = json.loads(
                manifest_path.read_text(encoding="utf-8"),
                object_pairs_hook=reject_duplicates,
            )
            if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA or manifest.get("bundle_id") != bundle_id:
                raise CapabilityBundleError("Bundle manifest identity or schema mismatch.")
            expected_manifest_sha = manifest.get("manifest_sha256")
            canonical_payload = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
            actual_manifest_sha = hashlib.sha256(
                json.dumps(canonical_payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
            ).hexdigest()
            if expected_manifest_sha != actual_manifest_sha:
                raise CapabilityBundleError("Bundle manifest digest mismatch.")

            rows = manifest.get("files")
            if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_FILES:
                raise CapabilityBundleError("Bundle file inventory is invalid.")
            seen: set[str] = set()
            total_bytes = 0
            for row in rows:
                if not isinstance(row, dict):
                    raise CapabilityBundleError("Bundle inventory contains an invalid row.")
                relative = _relative(row.get("path")).as_posix()
                digest = row.get("sha256")
                if relative in seen or not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                    raise CapabilityBundleError("Bundle path or digest inventory is invalid.")
                seen.add(relative)
                current = bundle_root
                for part in PurePosixPath(relative).parts:
                    current = current / part
                    if current.is_symlink():
                        raise CapabilityBundleError(f"Staged bundle symlink rejected: {relative}")
                resolved = current.resolve(strict=True)
                resolved.relative_to(bundle_root.resolve(strict=True))
                if not resolved.is_file() or resolved.stat().st_size > MAX_FILE_BYTES:
                    raise CapabilityBundleError(f"Staged bundle entry is not regular or exceeds the size limit: {relative}")
                raw = resolved.read_bytes()
                if hashlib.sha256(raw).hexdigest() != digest:
                    raise CapabilityBundleError(f"Staged bundle file digest mismatch: {relative}")
                if row.get("size_bytes") != len(raw):
                    raise CapabilityBundleError(f"Staged bundle file size metadata mismatch: {relative}")
                try:
                    ast.parse(raw.decode("utf-8"), filename=relative)
                except (UnicodeError, SyntaxError) as exc:
                    raise CapabilityBundleError(f"Staged bundle Python source no longer parses: {relative}") from exc
                total_bytes += len(raw)
                if total_bytes > MAX_TOTAL_BYTES:
                    raise CapabilityBundleError("Staged bundle exceeds the total source-byte limit.")

            tests = manifest.get("test_paths")
            if (
                not isinstance(tests, list)
                or len(tests) > MAX_FILES
                or len(set(tests)) != len(tests)
                or any(_relative(item).as_posix() not in seen for item in tests)
            ):
                raise CapabilityBundleError("Bundle test path inventory is invalid.")
            internal_gaps = manifest.get("internal_dependency_gaps")
            external = manifest.get("external_dependencies")
            if not isinstance(internal_gaps, list) or not isinstance(external, list):
                raise CapabilityBundleError("Bundle dependency inventory is malformed.")
            return {
                "success": True,
                "verified": True,
                "bundle_id": bundle_id,
                "manifest_sha256": actual_manifest_sha,
                "file_count": len(rows),
                "total_bytes": total_bytes,
                "test_paths": list(tests),
                "internal_dependency_gaps": list(internal_gaps),
                "external_dependencies": list(external),
                "risk_flag_count": sum(
                    len(row.get("static_risk_flags", []))
                    for row in rows if isinstance(row, dict)
                    and isinstance(row.get("static_risk_flags", []), list)
                ),
                "source_executed": False,
                "trusted_learning_admission": False,
                "production_promotion_allowed": False,
            }
        except (OSError, ValueError, TypeError, RecursionError) as exc:
            return {
                "success": False,
                "verified": False,
                "bundle_id": bundle_id,
                "error": f"BUNDLE_INTEGRITY_REJECTED:{type(exc).__name__}",
            }

    def list_staged_bundles(self, *, limit: int = 50) -> dict[str, Any]:
        """Return a bounded, hash-verified inventory without executing source."""
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
            raise CapabilityBundleError("Bundle listing limit must be between 1 and 200.")
        if self.staging.is_symlink() or not self.staging.is_dir():
            raise CapabilityBundleError("Capability staging directory is missing or unsafe.")
        directories = [
            item for item in self.staging.iterdir()
            if item.is_dir() and not item.is_symlink()
            and re.fullmatch(r"[0-9a-f]{32}", item.name)
        ]
        directories.sort(key=lambda item: item.stat().st_mtime_ns, reverse=True)
        items = [self.verify_staged_bundle(item.name) for item in directories[:limit]]
        return {
            "success": True,
            "schema": "pika.native_capability_bundle_inventory.v1",
            "item_count": len(items),
            "verified_count": sum(item.get("verified") is True for item in items),
            "items": items,
        }

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
            if len(raw) > MAX_FILE_BYTES or b"\x00" in raw:
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
            imports = _imports(tree, module)
            rows.append({
                "path": relative,
                "module": module,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size_bytes": len(raw),
                "ast_node_count": node_count,
                "imports": imports,
                "static_risk_flags": _source_flags(tree),
                "is_test": relative in tests,
            })

        module_names = set(modules)
        stdlib_names = set(sys.stdlib_module_names)
        for row in rows:
            internal: set[str] = set()
            standard_library: set[str] = set()
            external: set[str] = set()
            for dependency in row.pop("imports"):
                top_level = dependency.split(".")[0]
                is_internal = (
                    dependency in module_names
                    or any(candidate.startswith(dependency + ".") for candidate in module_names)
                    or any(dependency.startswith(candidate + ".") for candidate in module_names)
                )
                if is_internal:
                    internal.add(dependency)
                elif top_level in stdlib_names:
                    standard_library.add(dependency)
                else:
                    external.add(dependency)
            row["internal_imports"] = sorted(internal)
            row["standard_library_imports"] = sorted(standard_library)
            row["external_imports"] = sorted(external)
        unresolved_internal = sorted({
            dependency
            for row in rows
            for dependency in row["internal_imports"]
            if dependency not in module_names
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
