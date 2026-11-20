"""Deterministic source-code learning for PIKA.

This module uses Python's built-in AST parser and structural feature extraction.
It does not use an LLM, import downloaded code, or execute downloaded code.
Its output is structural evidence, not a claim of human-like semantic understanding.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = 1
SKIP_PARTS = {
    ".git", ".venv", ".sandbox_venv", "venv", "node_modules", "vendor",
    "dist", "build", "__pycache__", "site-packages", "__pypackages__",
    ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".cache",
    "coverage", "htmlcov", "backups", "data", "logs", "workspace",
    "PIKA_KNOWLEDGE",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _unparse(node: ast.AST | None) -> str:
    if node is None:
        return ""
    try:
        return ast.unparse(node)
    except Exception:
        return type(node).__name__


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    return ""


def _ancestor_name(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> str:
    parts: list[str] = []
    current = node
    while current in parents:
        current = parents[current]
        if isinstance(current, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            parts.append(current.name)
    return ".".join(reversed(parts))


class NativeCodeAnalyzer:
    """Extract symbol maps, structural patterns, and source evidence."""

    def analyze_python_source(
        self,
        source: str,
        *,
        relative_path: str,
        repository: str = "local",
        commit: str = "",
        license_id: str = "NOASSERTION",
        untrusted_source: bool | None = None,
    ) -> dict[str, Any]:
        raw = source.encode("utf-8", errors="replace")
        base = {
            "path": relative_path,
            "repository": repository,
            "commit": commit,
            "sha256": _sha256(raw),
            "bytes": len(raw),
            "license": license_id or "NOASSERTION",
            "untrusted_source": (repository != "local") if untrusted_source is None else bool(untrusted_source),
            "executed": False,
        }
        try:
            tree = ast.parse(source, filename=relative_path)
        except (SyntaxError, ValueError) as exc:
            return {
                **base,
                "parse_status": "syntax_error",
                "parse_error": str(exc),
                "module_docstring": "",
                "imports": [],
                "symbols": [],
                "patterns": [],
                "metrics": {"classes": 0, "functions": 0, "async_functions": 0},
            }

        parents: dict[ast.AST, ast.AST] = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parents[child] = parent

        imports: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.append("." * (node.level or 0) + (node.module or ""))

        functions = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        classes = [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
        symbols: list[dict[str, Any]] = []
        total_branches = 0
        total_calls = 0
        all_names: list[str] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                total_calls += 1
                call = _call_name(node.func)
                if call:
                    all_names.append(call)

        for node in sorted([*classes, *functions], key=lambda x: (getattr(x, "lineno", 0), type(x).__name__)):
            parent = _ancestor_name(node, parents)
            qualified = f"{parent}.{node.name}" if parent else node.name
            if isinstance(node, ast.ClassDef):
                kind = "class"
                signature = "class " + node.name + "(" + ", ".join(_unparse(x) for x in node.bases) + ")"
                decorators = [_unparse(x) for x in node.decorator_list]
                annotations: list[str] = []
            else:
                kind = "async_function" if isinstance(node, ast.AsyncFunctionDef) else "function"
                args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
                arg_specs = []
                for arg in args:
                    spec = arg.arg
                    if arg.annotation is not None:
                        spec += ": " + _unparse(arg.annotation)
                    arg_specs.append(spec)
                if node.args.vararg:
                    arg_specs.append("*" + node.args.vararg.arg)
                if node.args.kwarg:
                    arg_specs.append("**" + node.args.kwarg.arg)
                signature = f"{node.name}({', '.join(arg_specs)})"
                if node.returns is not None:
                    signature += " -> " + _unparse(node.returns)
                decorators = [_unparse(x) for x in node.decorator_list]
                annotations = [a.arg for a in args if a.annotation is not None]
                total_branches += sum(
                    isinstance(x, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler,
                                   ast.IfExp, ast.Assert, ast.Match))
                    for x in ast.walk(node)
                )
            symbols.append({
                "kind": kind,
                "name": node.name,
                "qualified_name": qualified,
                "signature": signature,
                "lineno": getattr(node, "lineno", None),
                "end_lineno": getattr(node, "end_lineno", None),
                "docstring": (ast.get_docstring(node) or "")[:1200],
                "decorators": decorators[:12],
                "argument_annotations": annotations[:20],
            })

        names_lower = " ".join([relative_path, *[s["qualified_name"] for s in symbols], *all_names]).lower()
        path_lower = relative_path.lower()
        nodes = list(ast.walk(tree))
        node_types = Counter(type(n).__name__ for n in nodes)
        calls_lower = " ".join(all_names).lower()
        patterns: list[str] = []

        def add(condition: bool, pattern: str) -> None:
            if condition and pattern not in patterns:
                patterns.append(pattern)

        add(any(isinstance(n, (ast.With, ast.AsyncWith)) for n in nodes), "resource_context_management")
        add(any(isinstance(n, ast.Try) for n in nodes), "exception_boundary")
        add(any(isinstance(n, ast.AsyncFunctionDef) for n in functions) or any(isinstance(n, ast.Await) for n in nodes), "async_concurrency_structure")
        add(any(isinstance(n, ast.If) and any(isinstance(x, ast.Raise) for x in ast.walk(n)) for n in nodes), "guard_or_validation_branch")
        add(any(isinstance(n, ast.Raise) for n in nodes), "explicit_error_contract")
        add(any(isinstance(n, (ast.For, ast.While)) for n in nodes) and any(k in names_lower for k in ("retry", "attempt", "backoff", "sleep")), "retry_control_structure")
        add(any(k in names_lower for k in ("rollback", "transaction", "restore_snapshot")) or "rollback" in calls_lower, "transaction_or_rollback_naming")
        add(any(isinstance(n, ast.Assert) for n in nodes) or "test_" in Path(relative_path).name.lower() or Path(relative_path).name.lower().endswith("_test.py"), "test_or_assertion_evidence")
        add(any(s["argument_annotations"] for s in symbols) or any(isinstance(n, ast.AnnAssign) for n in nodes), "type_annotation_contracts")
        add(any(isinstance(n, ast.ClassDef) and any(_unparse(d).split("(")[0].endswith("dataclass") for d in n.decorator_list) for n in nodes), "dataclass_model_structure")
        add(any(k in calls_lower for k in ("register", "dispatch", "select", "route")) or any(k in names_lower for k in ("registry", "router")), "registry_or_routing_structure")
        add(any(k in calls_lower for k in ("write_text", "write_bytes", "json.dump", "replace", "commit")) or any(k in names_lower for k in ("save", "persist", "store")), "persistence_operation")
        add(any(isinstance(n, ast.ImportFrom) and (n.module or "").endswith("protocol") for n in nodes) or any(s["name"] == "Protocol" for s in symbols), "protocol_or_interface_structure")
        add("rollback" in names_lower and "test" in path_lower, "rollback_test_cooccurrence")

        findings: list[dict[str, Any]] = []
        for function in functions:
            start_line = getattr(function, "lineno", 0) or 0
            end_line = getattr(function, "end_lineno", start_line) or start_line
            span = max(1, end_line - start_line + 1)
            branch_count = sum(
                isinstance(n, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler, ast.IfExp, ast.Assert, ast.Match))
                for n in ast.walk(function)
            )
            qualified = f"{_ancestor_name(function, parents)}.{function.name}".lstrip(".")
            if span >= 80:
                findings.append({
                    "rule": "long_function",
                    "severity": "medium",
                    "symbol": qualified,
                    "line": start_line,
                    "evidence": f"Function spans {span} source lines.",
                    "recommendation": "Review whether the function can be split into independently testable responsibilities.",
                })
            if branch_count >= 12:
                findings.append({
                    "rule": "high_branch_density",
                    "severity": "medium",
                    "symbol": qualified,
                    "line": start_line,
                    "evidence": f"Function contains {branch_count} branch-like AST nodes.",
                    "recommendation": "Review decision paths and add branch-focused regression tests before refactoring.",
                })

        for handler in (n for n in nodes if isinstance(n, ast.ExceptHandler)):
            exception_name = _unparse(handler.type) if handler.type is not None else "bare-except"
            if exception_name in {"bare-except", "Exception", "BaseException"}:
                findings.append({
                    "rule": "broad_exception_handler",
                    "severity": "low",
                    "symbol": _ancestor_name(handler, parents),
                    "line": getattr(handler, "lineno", None),
                    "evidence": f"Handler catches {exception_name}.",
                    "recommendation": "Check whether narrower exception types preserve useful failure signals.",
                })

        for call in (n for n in nodes if isinstance(n, ast.Call)):
            call_name = _call_name(call.func)
            if call_name in {"eval", "exec", "compile"}:
                findings.append({
                    "rule": "dynamic_code_execution_surface",
                    "severity": "high",
                    "symbol": _ancestor_name(call, parents),
                    "line": getattr(call, "lineno", None),
                    "evidence": f"Call to {call_name}().",
                    "recommendation": "Verify that input is trusted and constrained; prefer a non-executing parser where possible.",
                })
            if call_name.startswith("subprocess.") and any(
                keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True
                for keyword in call.keywords
            ):
                findings.append({
                    "rule": "shell_true_execution_surface",
                    "severity": "high",
                    "symbol": _ancestor_name(call, parents),
                    "line": getattr(call, "lineno", None),
                    "evidence": "subprocess call sets shell=True.",
                    "recommendation": "Prefer argument-list execution with shell=False and a fixed executable allowlist.",
                })

        return {
            **base,
            "parse_status": "parsed",
            "module_docstring": (ast.get_docstring(tree) or "")[:2000],
            "imports": sorted(set(imports))[:150],
            "symbols": symbols[:500],
            "patterns": patterns,
            "findings": findings,
            "metrics": {
                "classes": len(classes),
                "functions": len([f for f in functions if isinstance(f, ast.FunctionDef)]),
                "async_functions": len([f for f in functions if isinstance(f, ast.AsyncFunctionDef)]),
                "imports": len(set(imports)),
                "calls": total_calls,
                "branch_nodes": total_branches,
                "try_blocks": node_types.get("Try", 0),
                "assertions": node_types.get("Assert", 0),
                "with_blocks": node_types.get("With", 0) + node_types.get("AsyncWith", 0),
            },
        }

    def analyze_corpus(
        self,
        corpus_root: str | Path,
        *,
        repository_metadata: dict[str, dict[str, Any]] | None = None,
        repository_override: str | None = None,
        include_dirs: Iterable[str] | None = None,
        untrusted_source: bool | None = None,
    ) -> dict[str, Any]:
        root = Path(corpus_root).expanduser().resolve()
        repository_metadata = repository_metadata or {}
        files: list[dict[str, Any]] = []
        errors: list[str] = []
        pattern_files: dict[str, set[str]] = defaultdict(set)
        pattern_repos: dict[str, set[str]] = defaultdict(set)
        graph_nodes: dict[str, dict[str, Any]] = {}
        graph_edges: list[dict[str, str]] = []
        total_bytes = 0
        def walk_python_files(base: Path):
            if not base.is_dir():
                return
            for current, directories, filenames in os.walk(base, followlinks=False):
                directories[:] = [
                    name for name in directories
                    if name.lower() not in SKIP_PARTS
                    and not (Path(current) / name).is_symlink()
                ]
                for filename in filenames:
                    if filename.lower().endswith(".py"):
                        yield Path(current) / filename

        if include_dirs is None:
            candidate_paths = walk_python_files(root)
        else:
            candidate_paths = (
                path
                for directory in include_dirs
                for path in walk_python_files(root / directory)
            )
        if root.exists():
            for path in sorted(candidate_paths):
                try:
                    relative = path.relative_to(root)
                    if any(part.lower() in SKIP_PARTS for part in relative.parts) or path.is_symlink():
                        continue
                    raw = path.read_bytes()
                    if not raw or len(raw) > 300_000 or b"\x00" in raw:
                        continue
                    text = raw.decode("utf-8", errors="replace")
                    parts = relative.parts
                    repo = repository_override or ("/".join(parts[:2]) if len(parts) >= 2 else "local")
                    metadata = repository_metadata.get(repo, {})
                    record = self.analyze_python_source(
                        text,
                        relative_path=relative.as_posix(),
                        repository=repo,
                        commit=str(metadata.get("commit", "")),
                        license_id=str(metadata.get("license_id", "NOASSERTION")),
                        untrusted_source=untrusted_source,
                    )
                    files.append(record)
                    total_bytes += len(raw)
                    module_id = "module:" + relative.as_posix()
                    graph_nodes[module_id] = {"id": module_id, "kind": "module", "path": relative.as_posix()}
                    for symbol in record.get("symbols", []):
                        symbol_id = module_id + "::" + symbol["qualified_name"]
                        graph_nodes[symbol_id] = {
                            "id": symbol_id,
                            "kind": symbol["kind"],
                            "name": symbol["qualified_name"],
                            "path": relative.as_posix(),
                        }
                        graph_edges.append({"from": module_id, "relation": "defines", "to": symbol_id})
                    for imported in record.get("imports", []):
                        import_id = "import:" + imported
                        graph_nodes.setdefault(import_id, {"id": import_id, "kind": "import", "name": imported})
                        graph_edges.append({"from": module_id, "relation": "imports", "to": import_id})
                    for pattern in record.get("patterns", []):
                        pattern_files[pattern].add(relative.as_posix())
                        if repo != "local":
                            pattern_repos[pattern].add(repo)
                        pattern_id = "pattern:" + pattern
                        graph_nodes.setdefault(pattern_id, {"id": pattern_id, "kind": "pattern", "name": pattern})
                        graph_edges.append({"from": module_id, "relation": "exhibits", "to": pattern_id})
                except (OSError, ValueError) as exc:
                    errors.append(f"{path}: {exc}")

        findings: list[dict[str, Any]] = []
        for record in files:
            for finding in record.get("findings", []):
                findings.append({
                    **finding,
                    "path": record.get("path"),
                    "repository": record.get("repository"),
                    "source_sha256": record.get("sha256"),
                    "status": "PROPOSED_REVIEW",
                    "auto_fixed": False,
                })

        pattern_summary = []
        for pattern, paths in sorted(pattern_files.items()):
            repos = sorted(pattern_repos.get(pattern, set()))
            count = len(paths)
            strength = "single-source" if len(repos) <= 1 else ("cross-repository" if len(repos) >= 2 else "local-only")
            pattern_summary.append({
                "pattern": pattern,
                "file_evidence_count": count,
                "repository_evidence_count": len(repos),
                "repositories": repos[:50],
                "evidence_strength": strength,
                "evidence_paths": sorted(paths)[:100],
                "interpretation": "structural AST signature only; requires task-specific validation before reuse",
            })

        return {
            "schema": "pika.native_code_knowledge.v1",
            "generated_at": _utc_now(),
            "learning_method": "deterministic_python_ast_structural_analysis",
            "uses_llm": False,
            "uses_external_model_api": False,
            "executes_source_code": False,
            "corpus_root": str(root),
            "metrics": {
                "python_files_analyzed": len(files),
                "bytes_analyzed": total_bytes,
                "parsed_files": sum(x.get("parse_status") == "parsed" for x in files),
                "syntax_error_files": sum(x.get("parse_status") != "parsed" for x in files),
                "graph_nodes": len(graph_nodes),
                "graph_edges": len(graph_edges),
                "structural_patterns": len(pattern_summary),
                "static_findings": len(findings),
                "high_severity_findings": sum(x.get("severity") == "high" for x in findings),
                "classes": sum(x.get("metrics", {}).get("classes", 0) for x in files),
                "functions": sum(x.get("metrics", {}).get("functions", 0) for x in files),
                "async_functions": sum(x.get("metrics", {}).get("async_functions", 0) for x in files),
                "imports": sum(x.get("metrics", {}).get("imports", 0) for x in files),
                "calls": sum(x.get("metrics", {}).get("calls", 0) for x in files),
                "branch_nodes": sum(x.get("metrics", {}).get("branch_nodes", 0) for x in files),
                "try_blocks": sum(x.get("metrics", {}).get("try_blocks", 0) for x in files),
                "assertions": sum(x.get("metrics", {}).get("assertions", 0) for x in files),
                "with_blocks": sum(x.get("metrics", {}).get("with_blocks", 0) for x in files),
            },
            "patterns": pattern_summary,
            "improvement_findings": findings,
            "files": files,
            "graph": {
                "nodes": list(graph_nodes.values()),
                "edges": graph_edges,
            },
            "errors": errors[:100],
            "limits": [
                "AST structure is not full semantic understanding.",
                "Pattern frequency is evidence of code shape, not proof of correctness.",
                "Third-party source is untrusted data and is never executed by this analyzer.",
            ],
        }

    def analyze_project(self, project_root: str | Path) -> dict[str, Any]:
        """Analyze PIKA's own source directories without executing project code."""
        # Scan all first-party project source once. Generated workspaces, caches,
        # data, backups, logs, virtualenvs and vendor trees are excluded by SKIP_PARTS.
        return self.analyze_corpus(
            project_root,
            repository_override="PIKA_ACTIVE",
            include_dirs=(".",),
            untrusted_source=False,
        )

    @staticmethod
    def save(knowledge: dict[str, Any], path: str | Path) -> Path:
        destination = Path(path).expanduser().resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_suffix(destination.suffix + ".tmp")
        temporary.write_text(json.dumps(knowledge, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(temporary, destination)
        return destination
