"""Build an unverified native knowledge graph from acquired GitHub source.

Only bounded Python AST structure is inspected. Repository code is never imported,
executed, modified, or persisted by this adapter. Every emitted edge carries a
stable source identifier whose detailed evidence is returned alongside reasoning.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any

from core.native_reasoning import NativeReasoningEngine

SCHEMA = "pika.native_code_graph_adapter.v1"
REASONING_SCHEMA = "pika.native_code_graph_reasoning.v1"
MAX_FILES = 300
MAX_FILE_BYTES = 200_000
MAX_FACTS = 500
MAX_CANDIDATE_FACTS = 20_000
MAX_AST_NODES_PER_FILE = 20_000
MAX_AST_NODES_TOTAL = 60_000
MAX_PATH_LENGTH = 500
MAX_REPOSITORY_LENGTH = 200
_REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_COMMIT_RE = re.compile(r"[A-Fa-f0-9]{6,64}\Z")
_SKIP_PARTS = {
    ".git", ".venv", ".sandbox_venv", "venv", "node_modules", "vendor",
    "site-packages", "__pycache__", "build", "dist", "target", ".tox",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", "coverage", "htmlcov",
}


class _GraphLimitExceeded(ValueError):
    pass


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _safe_path(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_PATH_LENGTH:
        raise ValueError("invalid or oversized repository path")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts:
        raise ValueError("absolute or empty repository path is not allowed")
    if any(part in {"", ".", ".."} or part.lower() in _SKIP_PARTS for part in path.parts):
        raise ValueError("unsafe or excluded repository path")
    return path.as_posix()


def _module_name(relative_path: str) -> str:
    parts = list(PurePosixPath(relative_path).with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts) if parts else "__root__"


def _dotted_name(node: ast.AST) -> str:
    """Resolve only a syntactic name/attribute chain without recursive descent."""
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        return ""
    parts.append(current.id)
    return ".".join(reversed(parts))


def _entity_id(kind: str, repository: str, commit: str, path: str, label: str) -> str:
    identity = "\0".join((kind, repository, commit, path, label))
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]
    readable = re.sub(r"[^A-Za-z0-9_.-]+", "_", label).strip("_")[:160] or "unnamed"
    return f"{kind}:{repository}@{commit[:12]}:{readable}:{digest}"


def _source_id(
    repository: str,
    commit: str,
    path: str,
    file_sha: str,
    line_start: int,
    line_end: int,
    node_type: str,
    observation: str,
) -> str:
    value = "\0".join((
        repository, commit, path, file_sha, str(line_start), str(line_end),
        node_type, observation,
    ))
    return "github-source:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _relative_import_name(module_name: str, path: str, level: int, module: str | None) -> str:
    if level <= 0:
        return module or ""
    current = module_name.split(".") if module_name != "__root__" else []
    if PurePosixPath(path).name != "__init__.py" and current:
        current = current[:-1]
    keep = max(0, len(current) - (level - 1))
    parts = current[:keep]
    if module:
        parts.extend(module.split("."))
    return ".".join(parts)


class NativeKnowledgeGraphAdapter:
    """Convert exact acquired-source structure into Phase 39's bounded fact format."""

    def __init__(
        self,
        root: str | Path | None = None,
        reasoning_engine: NativeReasoningEngine | None = None,
    ) -> None:
        self.root = Path(root or Path(__file__).resolve().parents[1]).expanduser().resolve()
        self.data = self.root / "data"
        self.corpus = self.data / "github_code_corpus"
        self.registry_path = self.data / "pika_native_git_registry.json"
        self.reasoning = reasoning_engine or NativeReasoningEngine()

    def _load_registry(self) -> dict[str, Any]:
        try:
            value = json.loads(self.registry_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return {}
        return value if isinstance(value, dict) else {}

    def build_repository_facts(self, repository: str) -> dict[str, Any]:
        """Read registered, hash-bound Python source and emit AST-only graph facts."""
        repo = repository.strip().strip("/") if isinstance(repository, str) else ""
        if (
            len(repo) > MAX_REPOSITORY_LENGTH
            or not _REPOSITORY_RE.fullmatch(repo)
            or any(part in {"", ".", ".."} for part in repo.split("/"))
        ):
            return self._failure("INVALID_REPOSITORY", "Repository must be a safe owner/name identifier.")

        registry = self._load_registry().get("repositories", {})
        metadata = registry.get(repo) if isinstance(registry, dict) else None
        if not isinstance(metadata, dict):
            return self._failure("REPOSITORY_NOT_IN_PIKA_REGISTRY", "Acquire the GitHub repository through PIKA first.")

        commit = str(metadata.get("commit", ""))
        if not _COMMIT_RE.fullmatch(commit):
            return self._failure("INVALID_REGISTERED_COMMIT", "The registered commit identifier is missing or malformed.")
        entries = metadata.get("files")
        if not isinstance(entries, list) or not entries:
            return self._failure("REGISTERED_SOURCE_FILES_REQUIRED", "The repository has no registered source-file manifest.")
        if len(entries) > MAX_FILES:
            return self._failure("REPOSITORY_FILE_LIMIT_EXCEEDED", f"At most {MAX_FILES} registered files are accepted.")

        if self.corpus.is_symlink():
            return self._failure(
                "INVALID_SOURCE_CORPUS_ROOT",
                "The acquired source corpus root must not be a symlink.",
            )
        repo_dir = self.corpus.joinpath(*repo.split("/"))
        current = self.corpus
        for part in repo.split("/"):
            current = current / part
            if current.is_symlink():
                return self._failure(
                    "INVALID_REGISTERED_REPOSITORY_PATH",
                    "Symlinked repository or owner directories are not accepted.",
                )
        try:
            repo_dir.resolve().relative_to(self.corpus.resolve())
        except (OSError, ValueError):
            return self._failure(
                "INVALID_REGISTERED_REPOSITORY_PATH",
                "Registered repository resolves outside the acquired source corpus.",
            )
        parsed: list[dict[str, Any]] = []
        errors: list[str] = []
        skipped_non_python = 0
        syntax_errors = 0
        ast_nodes_total = 0
        seen_paths: set[str] = set()

        for item in sorted(entries, key=lambda row: str(row.get("path", "")) if isinstance(row, dict) else ""):
            if not isinstance(item, dict):
                errors.append("manifest contains a non-object entry")
                continue
            try:
                relative_path = _safe_path(item.get("path"))
                if relative_path in seen_paths:
                    raise ValueError("duplicate repository path in source manifest")
                seen_paths.add(relative_path)
                if not relative_path.lower().endswith(".py"):
                    skipped_non_python += 1
                    continue
                source_path = repo_dir.joinpath(*PurePosixPath(relative_path).parts)
                current = repo_dir
                for part in PurePosixPath(relative_path).parts:
                    current = current / part
                    if current.is_symlink():
                        raise ValueError("symlinked source paths are not accepted")
                source_path.resolve().relative_to(repo_dir.resolve())
                if not source_path.is_file():
                    raise FileNotFoundError("registered source file is missing")
                raw = source_path.read_bytes()
                if not raw or len(raw) > MAX_FILE_BYTES or b"\x00" in raw:
                    raise ValueError("source is empty, oversized, or binary")
                expected_sha = str(item.get("sha256", ""))
                actual_sha = _sha256(raw)
                if not re.fullmatch(r"[A-Fa-f0-9]{64}", expected_sha) or actual_sha != expected_sha:
                    raise ValueError("source SHA-256 does not match the Git learning manifest")
                source = raw.decode("utf-8", errors="replace")
                try:
                    tree = ast.parse(source, filename=relative_path)
                except (SyntaxError, ValueError, RecursionError) as exc:
                    syntax_errors += 1
                    errors.append(f"{relative_path}: syntax error: {str(exc)[:180]}")
                    continue
                ast_node_count = 0
                for _node in ast.walk(tree):
                    ast_node_count += 1
                    if ast_node_count > MAX_AST_NODES_PER_FILE:
                        break
                if ast_node_count > MAX_AST_NODES_PER_FILE:
                    errors.append(
                        f"{relative_path}: AST node budget exceeded ({MAX_AST_NODES_PER_FILE})"
                    )
                    continue
                if ast_nodes_total + ast_node_count > MAX_AST_NODES_TOTAL:
                    errors.append(
                        f"{relative_path}: repository AST node budget would exceed {MAX_AST_NODES_TOTAL}"
                    )
                    continue
                ast_nodes_total += ast_node_count
                parsed.append({
                    "path": relative_path,
                    "sha256": actual_sha,
                    "source": source,
                    "tree": tree,
                    "module_name": _module_name(relative_path),
                    "line_count": len(source.splitlines()),
                })
            except (OSError, ValueError) as exc:
                errors.append(f"{item.get('path', '?')}: {type(exc).__name__}: {exc}")

        if not parsed:
            return self._failure(
                "NO_HASH_VERIFIED_PYTHON_SOURCE",
                "No registered Python source file passed path, size, hash, and AST validation.",
                errors=errors[:80],
                syntax_errors=syntax_errors,
                skipped_non_python=skipped_non_python,
            )

        module_nodes: dict[str, str] = {}
        module_name_paths: dict[str, list[str]] = {}
        for record in parsed:
            module_id = _entity_id("module", repo, commit, record["path"], record["module_name"])
            module_nodes[record["path"]] = module_id
            module_name_paths.setdefault(record["module_name"], []).append(record["path"])

        class_records: list[dict[str, Any]] = []
        symbol_records: list[dict[str, Any]] = []
        for record in parsed:
            tree = record["tree"]
            parents: dict[ast.AST, ast.AST] = {}
            for parent in ast.walk(tree):
                for child in ast.iter_child_nodes(parent):
                    parents[child] = parent

            nodes = [
                node for node in ast.walk(tree)
                if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
            ]
            node_ids: dict[int, str] = {}
            for node in sorted(nodes, key=lambda value: (
                getattr(value, "lineno", 0),
                getattr(value, "col_offset", 0),
                type(value).__name__,
            )):
                ancestors: list[str] = []
                current = parents.get(node)
                while current is not None:
                    if isinstance(current, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                        ancestors.append(current.name)
                    current = parents.get(current)
                qualified = ".".join([*reversed(ancestors), node.name])
                source_identity = (
                    f"{qualified}@{getattr(node, 'lineno', 0)}:"
                    f"{getattr(node, 'col_offset', 0)}:"
                    f"{getattr(node, 'end_lineno', 0)}:"
                    f"{getattr(node, 'end_col_offset', 0)}:{type(node).__name__}"
                )
                node_ids[id(node)] = _entity_id(
                    "symbol", repo, commit, record["path"], source_identity
                )
                symbol_records.append({
                    "record": record,
                    "node": node,
                    "parents": parents,
                    "node_ids": node_ids,
                    "qualified": qualified,
                })
                if isinstance(node, ast.ClassDef):
                    class_records.append({
                        "record": record,
                        "node": node,
                        "node_id": node_ids[id(node)],
                        "name": node.name,
                        "qualified": qualified,
                    })

        simple_class_ids: dict[str, list[str]] = {}
        qualified_class_ids: dict[str, list[str]] = {}
        for item in class_records:
            simple_class_ids.setdefault(item["name"], []).append(item["node_id"])
            qualified_name = f"{_module_name(item['record']['path'])}.{item['qualified']}"
            qualified_class_ids.setdefault(qualified_name, []).append(item["node_id"])

        fact_groups: dict[str, list[dict[str, str]]] = {
            "module": [],
            "dependency": [],
            "inheritance": [],
            "containment": [],
        }
        evidence: dict[str, dict[str, Any]] = {}
        candidate_fact_count = 0

        def add_fact(
            subject: str,
            predicate: str,
            obj: str,
            record: dict[str, Any],
            node: ast.AST,
            category: str,
            observation: str,
        ) -> None:
            nonlocal candidate_fact_count
            if category not in fact_groups:
                raise ValueError(f"unsupported graph fact category: {category}")
            candidate_fact_count += 1
            if candidate_fact_count > MAX_CANDIDATE_FACTS:
                raise _GraphLimitExceeded(
                    f"source graph candidate generation exceeds {MAX_CANDIDATE_FACTS} relationships"
                )
            line_start = int(getattr(node, "lineno", 1) or 1)
            line_end = int(getattr(node, "end_lineno", line_start) or line_start)
            if isinstance(node, ast.Module):
                line_start = 1
                line_end = max(1, int(record.get("line_count", 1)))
            source = _source_id(
                repo, commit, record["path"], record["sha256"],
                line_start, line_end, type(node).__name__, observation,
            )
            fact_groups[category].append({
                "subject": subject,
                "predicate": predicate,
                "object": obj,
                "source": source,
            })
            evidence[source] = {
                "source_id": source,
                "repository": repo,
                "commit": commit,
                "path": record["path"],
                "sha256": record["sha256"],
                "line_start": line_start,
                "line_end": line_end,
                "ast_node_type": type(node).__name__,
                "observation": observation,
                "license_id": str(metadata.get("license_id", "NOASSERTION")),
                "source_executed": False,
                "trust": "OBSERVED_NOT_YET_VERIFIED_FOR_REUSE",
            }

        repository_node = _entity_id("repository", repo, commit, "", repo)
        try:
            # Module existence and containment are directly observed from parsed AST files.
            for record in parsed:
                module_id = module_nodes[record["path"]]
                add_fact(
                    module_id, "part_of", repository_node, record, record["tree"],
                    "module", "python_module_is_part_of_repository",
                )

            # Import statements create dependency edges. No import is loaded or executed.
            for record in parsed:
                tree = record["tree"]
                for node in ast.walk(tree):
                    imported: list[str] = []
                    if isinstance(node, ast.Import):
                        imported.extend(alias.name for alias in node.names)
                    elif isinstance(node, ast.ImportFrom):
                        target = _relative_import_name(
                            record["module_name"], record["path"], node.level, node.module
                        )
                        if target:
                            imported.append(target)
                    for import_name in imported:
                        if not import_name or len(import_name) > 300:
                            continue
                        matches = module_name_paths.get(import_name, [])
                        if len(matches) == 1:
                            target_id = module_nodes[matches[0]]
                        else:
                            target_id = _entity_id(
                                "external_module", repo, commit, "", import_name
                            )
                        add_fact(
                            module_nodes[record["path"]], "depends_on", target_id,
                            record, node, "dependency", "python_import_statement",
                        )

            # Definitions are contained by their nearest enclosing definition or module.
            for item in symbol_records:
                record = item["record"]
                node = item["node"]
                current = item["parents"].get(node)
                parent_id = module_nodes[record["path"]]
                while current is not None:
                    if id(current) in item["node_ids"]:
                        parent_id = item["node_ids"][id(current)]
                        break
                    current = item["parents"].get(current)
                add_fact(
                    item["node_ids"][id(node)], "part_of", parent_id,
                    record, node, "containment", "python_ast_definition_containment",
                )

            # Inheritance is recorded only for simple/dotted syntactic base expressions.
            # Ambiguous local names remain unresolved symbolic references.
            for item in class_records:
                record = item["record"]
                node = item["node"]
                for base in node.bases:
                    base_name = _dotted_name(base)
                    if not base_name or len(base_name) > 300:
                        continue
                    qualified_candidates = qualified_class_ids.get(base_name, [])
                    target_id = qualified_candidates[0] if len(qualified_candidates) == 1 else None
                    if target_id is None and "." not in base_name:
                        local_candidates = simple_class_ids.get(base_name, [])
                        if len(local_candidates) == 1:
                            target_id = local_candidates[0]
                    if target_id is None:
                        target_id = _entity_id(
                            "unresolved_class_reference", repo, commit, "", base_name
                        )
                    add_fact(
                        item["node_id"], "is_a", target_id,
                        record, node, "inheritance", "python_class_base_declaration",
                    )
        except _GraphLimitExceeded as exc:
            return self._failure(
                "SOURCE_GRAPH_CANDIDATE_LIMIT_EXCEEDED",
                str(exc),
                repository=repo,
                commit=commit,
                parsed_files=len(parsed),
                errors=errors[:80],
            )

        core_facts = [
            *fact_groups["module"],
            *fact_groups["dependency"],
            *fact_groups["inheritance"],
        ]
        if len(core_facts) > MAX_FACTS:
            return self._failure(
                "SOURCE_GRAPH_CORE_FACT_LIMIT_EXCEEDED",
                f"Core module, dependency, and inheritance relationships exceed the {MAX_FACTS}-fact reasoning budget.",
                repository=repo,
                commit=commit,
                core_relationships=len(core_facts),
                errors=errors[:80],
            )
        remaining_containment_budget = MAX_FACTS - len(core_facts)
        containment_facts = fact_groups["containment"]
        selected_containment = containment_facts[:remaining_containment_budget]
        omitted_containment = len(containment_facts) - len(selected_containment)
        facts = [*core_facts, *selected_containment]
        used_source_ids = {row["source"] for row in facts}
        evidence = {key: value for key, value in evidence.items() if key in used_source_ids}
        facts.sort(key=lambda row: (
            row["subject"], row["predicate"], row["object"], row["source"]
        ))
        coverage_flags: list[str] = []
        if errors:
            coverage_flags.append("REJECTED_OR_UNPARSEABLE_FILES")
        if omitted_containment:
            coverage_flags.append("CONTAINMENT_FACTS_OMITTED_FOR_REASONING_BUDGET")
        coverage_status = (
            "COMPLETE_REGISTERED_SOURCE_SET"
            if not coverage_flags else (
                "PARTIAL_MULTIPLE_LIMITS"
                if len(coverage_flags) > 1 else (
                    "PARTIAL_GRAPH_FACT_BUDGET"
                    if omitted_containment else "PARTIAL_REJECTED_OR_UNPARSEABLE_FILES"
                )
            )
        )
        return {
            "success": True,
            "schema": SCHEMA,
            "repository": repo,
            "commit": commit,
            "coverage_status": coverage_status,
            "coverage_flags": coverage_flags,
            "facts": facts,
            "source_evidence": [evidence[key] for key in sorted(evidence)],
            "metrics": {
                "registered_files": len(entries),
                "python_files_parsed": len(parsed),
                "ast_nodes_analyzed": ast_nodes_total,
                "syntax_errors": syntax_errors,
                "non_python_files_skipped": skipped_non_python,
                "input_relationship_records": len(facts),
                "unique_source_records": len(evidence),
                "modules": len(parsed),
                "classes": len(class_records),
                "definitions": len(symbol_records),
                "dependency_edges": sum(row["predicate"] == "depends_on" for row in facts),
                "inheritance_edges": sum(row["predicate"] == "is_a" for row in facts),
                "containment_edges": len(fact_groups["module"]) + len(selected_containment),
                "module_containment_edges": len(fact_groups["module"]),
                "definition_containment_edges": len(selected_containment),
                "candidate_containment_edges": len(containment_facts),
                "candidate_module_containment_edges": len(fact_groups["module"]),
                "relationships_omitted": omitted_containment,
                "containment_relationships_omitted": omitted_containment,
            },
            "errors": errors[:80],
            "trust": "UNVERIFIED_SOURCE_STRUCTURE",
            "source_executed": False,
            "source_modified": False,
            "source_persisted": False,
            "memory_updated": False,
            "knowledge_admitted": False,
            "promotion_allowed": False,
            "limits": [
                "Only Python import, class-base, and AST definition-containment structure is represented.",
                "The 500-fact reasoning budget prioritizes module, import, and inheritance edges; excess containment edges are deterministically omitted and reported.",
                f"AST limits: {MAX_AST_NODES_PER_FILE} nodes per file and {MAX_AST_NODES_TOTAL} nodes per repository.",
                "Imports are not resolved at runtime; ambiguous names remain external symbolic references.",
                "Calls, dynamic imports, reflection, runtime behavior, and test outcomes are not inferred.",
                "AST observations and all transitive conclusions remain unverified hypotheses.",
            ],
        }

    def reason_repository(self, repository: str) -> dict[str, Any]:
        """Build and reason over one registered repository without persisting the graph."""
        graph = self.build_repository_facts(repository)
        if not graph.get("success"):
            return graph
        result = self.reasoning.reason(graph["facts"])
        if not result.get("success"):
            return {
                "success": False,
                "error": result.get("error", "NATIVE_REASONING_FAILED"),
                "message": result.get("message", "The bounded reasoning engine rejected the source graph."),
                "source_graph": {
                    "schema": graph["schema"],
                    "repository": graph["repository"],
                    "commit": graph["commit"],
                    "metrics": graph["metrics"],
                },
                "source_executed": False,
                "source_modified": False,
                "source_persisted": False,
                "memory_updated": False,
                "knowledge_admitted": False,
                "promotion_allowed": False,
            }
        # Preserve the exact Phase 39 result shape for Brain's independent safety checks.
        return {
            **result,
            "success": True,
            "source_graph": {
                "schema": graph["schema"],
                "repository": graph["repository"],
                "commit": graph["commit"],
                "coverage_status": graph["coverage_status"],
                "coverage_flags": graph["coverage_flags"],
                "metrics": graph["metrics"],
                "trust": graph["trust"],
                "errors": graph["errors"],
            },
            "source_evidence": graph["source_evidence"],
            "source_graph_limits": graph["limits"],
            "source_executed": False,
            "source_modified": False,
            "source_persisted": False,
            "memory_updated": False,
            "knowledge_admitted": False,
            "promotion_allowed": False,
        }

    @staticmethod
    def _failure(error: str, message: str, **extra: Any) -> dict[str, Any]:
        return {
            "success": False,
            "error": error,
            "message": message,
            "facts": [],
            "source_evidence": [],
            "source_executed": False,
            "source_modified": False,
            "source_persisted": False,
            "memory_updated": False,
            "knowledge_admitted": False,
            "promotion_allowed": False,
            **extra,
        }
