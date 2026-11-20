"""PIKA native engineering-knowledge extraction (no LLM/API/source execution).

Converts acquired repository source into provenance-backed observations.
It deliberately avoids claiming semantic understanding or test success.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA = "pika.native_engineering_knowledge.v1"
SKIP_PARTS = {
    ".git", ".venv", ".sandbox_venv", "venv", "node_modules", "vendor",
    "site-packages", "__pycache__", "build", "dist", "target", ".tox",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", "coverage", "htmlcov",
}
MAX_SOURCE_BYTES = 300_000
MAX_FILES = 500
MAX_EVIDENCE_PER_FACT = 12


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _safe_rel(value: str) -> str:
    p = PurePosixPath(value)
    if p.is_absolute() or not p.parts or any(x in {"", ".", ".."} for x in p.parts):
        raise ValueError(f"unsafe repository path: {value!r}")
    if any(part.lower() in SKIP_PARTS for part in p.parts):
        raise ValueError(f"excluded repository path: {value!r}")
    return p.as_posix()


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _symbol_record(node: ast.AST, source: str) -> dict[str, Any] | None:
    if not isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    segment = ast.get_source_segment(source, node) or ""
    if isinstance(node, ast.ClassDef):
        kind = "class"
        signature = f"class {node.name}"
        if node.bases:
            signature += "(" + ", ".join(ast.unparse(x) for x in node.bases) + ")"
    else:
        kind = "async_function" if isinstance(node, ast.AsyncFunctionDef) else "function"
        args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
        parts = []
        for arg in args:
            item = arg.arg
            if arg.annotation is not None:
                item += ": " + ast.unparse(arg.annotation)
            parts.append(item)
        if node.args.vararg:
            parts.append("*" + node.args.vararg.arg)
        if node.args.kwarg:
            parts.append("**" + node.args.kwarg.arg)
        signature = f"{node.name}({', '.join(parts)})"
        if node.returns is not None:
            signature += " -> " + ast.unparse(node.returns)
    return {
        "kind": kind,
        "name": node.name,
        "signature": signature[:500],
        "line_start": getattr(node, "lineno", None),
        "line_end": getattr(node, "end_lineno", None),
        "docstring": (ast.get_docstring(node) or "")[:1600],
        "decorators": [ast.unparse(d)[:180] for d in getattr(node, "decorator_list", [])[:8]],
        "bases": [ast.unparse(b)[:180] for b in getattr(node, "bases", [])[:8]] if isinstance(node, ast.ClassDef) else [],
        "source_excerpt": segment[:900],
    }


def _analyze_file(path: Path, rel: str, repo: str, commit: str, license_id: str) -> dict[str, Any]:
    raw = path.read_bytes()
    if not raw or len(raw) > MAX_SOURCE_BYTES or b"\x00" in raw:
        raise ValueError("empty, oversized, or binary source file")
    source = raw.decode("utf-8", errors="replace")
    record: dict[str, Any] = {
        "path": rel,
        "repository": repo,
        "commit": commit,
        "sha256": _sha(raw),
        "bytes": len(raw),
        "license_id": license_id or "NOASSERTION",
        "source_executed": False,
    }
    if not rel.lower().endswith(".py"):
        return {**record, "language": Path(rel).suffix.lower().lstrip("."), "parse_status": "not_python", "symbols": [], "imports": [], "metrics": {}}
    try:
        tree = ast.parse(source, filename=rel)
    except (SyntaxError, ValueError) as exc:
        return {**record, "language": "python", "parse_status": "syntax_error", "parse_error": str(exc)[:300], "symbols": [], "imports": [], "metrics": {}}

    nodes = list(ast.walk(tree))
    imports: list[str] = []
    for node in nodes:
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.append("." * (node.level or 0) + (node.module or ""))

    symbol_nodes = [n for n in nodes if isinstance(n, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))]
    symbols = [_symbol_record(node, source) for node in sorted(symbol_nodes, key=lambda n: (n.lineno, type(n).__name__))]
    symbols = [x for x in symbols if x is not None]
    assertions = []
    for node in nodes:
        if isinstance(node, ast.Assert):
            assertions.append({
                "line": node.lineno,
                "expression": ast.unparse(node.test)[:500],
            })
    test_path = bool(re.search(r"(^|/)(tests?|testing)(/|$)|(^|/)test_[^/]+\.py$|_test\.py$", rel, re.I))
    calls = [_call_name(n.func) for n in nodes if isinstance(n, ast.Call)]
    raised = [ast.unparse(n.exc)[:220] for n in nodes if isinstance(n, ast.Raise) and n.exc is not None]
    exception_classes = []
    for n in nodes:
        if isinstance(n, ast.ClassDef):
            bases = [ast.unparse(b).split(".")[-1] for b in n.bases]
            if any("Exception" in b or b == "Error" for b in bases):
                exception_classes.append({"name": n.name, "bases": bases, "line": n.lineno})
    module_doc = ast.get_docstring(tree) or ""
    return {
        **record,
        "language": "python",
        "parse_status": "parsed",
        "module_docstring": module_doc[:1600],
        "imports": sorted(set(imports))[:200],
        "symbols": symbols[:500],
        "assertions": assertions[:500],
        "metrics": {
            "classes": sum(isinstance(n, ast.ClassDef) for n in nodes),
            "functions": sum(isinstance(n, ast.FunctionDef) for n in nodes),
            "async_functions": sum(isinstance(n, ast.AsyncFunctionDef) for n in nodes),
            "assertions": len(assertions),
            "try_blocks": sum(isinstance(n, ast.Try) for n in nodes),
            "with_blocks": sum(isinstance(n, (ast.With, ast.AsyncWith)) for n in nodes),
            "raise_statements": sum(isinstance(n, ast.Raise) for n in nodes),
            "calls": len(calls),
        },
        "test_file": test_path,
        "exception_classes": exception_classes[:100],
        "call_names": sorted(set(x for x in calls if x))[:300],
        "raised_expressions": raised[:100],
        "module_line_count": len(source.splitlines()),
    }


def _evidence(file_record: dict[str, Any], *, symbol: dict[str, Any] | None = None, note: str = "") -> dict[str, Any]:
    item = {
        "repository": file_record["repository"],
        "commit": file_record["commit"],
        "path": file_record["path"],
        "sha256": file_record["sha256"],
        "license_id": file_record["license_id"],
        "source_executed": False,
    }
    if symbol:
        item.update({k: symbol.get(k) for k in ("kind", "name", "signature", "line_start", "line_end", "docstring", "source_excerpt") if symbol.get(k) is not None})
    if note:
        item["note"] = note
    return item


def _make_fact(repo: str, commit: str, concept: str, statement: str, evidence: list[dict[str, Any]], *, fact_type: str = "observed_structure", caveat: str = "") -> dict[str, Any]:
    # Confidence refers only to fidelity of the observation, not correctness or quality.
    confidence = "high" if evidence else "none"
    return {
        "id": hashlib.sha256((repo + "\0" + commit + "\0" + concept + "\0" + statement).encode()).hexdigest()[:20],
        "concept": concept,
        "fact_type": fact_type,
        "statement": statement,
        "confidence": confidence,
        "confidence_scope": "source observation only; not proof of correctness or best practice",
        "evidence_count": len(evidence),
        "evidence": evidence[:MAX_EVIDENCE_PER_FACT],
        "caveat": caveat or "Observed from source structure/docstrings; behavior was not executed or independently verified.",
        "status": "OBSERVED_NOT_YET_VERIFIED_FOR_REUSE",
    }


class NativeEngineeringKnowledgeExtractor:
    """Extracts repository-specific engineering observations with provenance."""

    def __init__(self, root: str | Path | None = None) -> None:
        self.root = Path(root or Path(__file__).resolve().parents[1]).expanduser().resolve()
        self.data = self.root / "data"
        self.corpus = self.data / "github_code_corpus"
        self.registry_path = self.data / "pika_native_git_registry.json"
        self.output_path = self.data / "pika_native_engineering_knowledge.json"

    def _load_registry(self) -> dict[str, Any]:
        try:
            payload = json.loads(self.registry_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return {}
        return payload if isinstance(payload, dict) else {}

    def extract_repository(self, repository: str, *, max_files: int = MAX_FILES) -> dict[str, Any]:
        repo = repository.strip().strip("/")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
            return {"success": False, "error": "INVALID_REPOSITORY", "repository": repository}
        registry = self._load_registry().get("repositories", {})
        meta = registry.get(repo)
        if not isinstance(meta, dict):
            return {"success": False, "error": "REPOSITORY_NOT_IN_PIKA_REGISTRY", "repository": repo, "hint": "Run python -m core.git_learning_loop --repo owner/repo first."}
        commit = str(meta.get("commit", ""))
        files_meta = meta.get("files", [])
        if not isinstance(files_meta, list) or not files_meta:
            return {"success": False, "error": "REPOSITORY_HAS_NO_REGISTERED_FILES", "repository": repo}

        repo_dir = self.corpus.joinpath(*repo.split("/"))
        records: list[dict[str, Any]] = []
        errors: list[str] = []
        for item in files_meta[: max(1, min(int(max_files), MAX_FILES))]:
            if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                continue
            try:
                rel = _safe_rel(item["path"])
                source_path = repo_dir.joinpath(*PurePosixPath(rel).parts)
                source_path.resolve().relative_to(repo_dir.resolve())
                if not source_path.is_file() or source_path.is_symlink():
                    raise FileNotFoundError("registered source file missing or symlink")
                record = _analyze_file(source_path, rel, repo, commit, str(meta.get("license_id", "NOASSERTION")))
                # Require the corpus bytes to match the acquisition manifest. Never silently analyze stale content.
                expected = str(item.get("sha256", ""))
                if expected and record["sha256"] != expected:
                    raise ValueError("source SHA-256 does not match Git learning manifest")
                records.append(record)
            except Exception as exc:
                errors.append(f"{item.get('path', '?')}: {type(exc).__name__}: {exc}")

        python_files = [x for x in records if x.get("language") == "python" and x.get("parse_status") == "parsed"]
        tests = [x for x in python_files if x.get("test_file")]
        facts: list[dict[str, Any]] = []

        # Evidence-backed symbol inventory. This is factual indexing, not semantic inference.
        symbol_evidence: list[dict[str, Any]] = []
        for file_record in python_files:
            for symbol in file_record.get("symbols", []):
                if symbol.get("docstring") or symbol.get("kind") == "class":
                    symbol_evidence.append(_evidence(file_record, symbol=symbol))
        if symbol_evidence:
            facts.append(_make_fact(
                repo, commit, "public_and_internal_symbols",
                f"The acquired Python source for {repo} contains {sum(len(x.get('symbols', [])) for x in python_files)} class/function symbols across {len(python_files)} parsed Python files.",
                symbol_evidence[:MAX_EVIDENCE_PER_FACT],
                caveat="Symbol counts and signatures are AST observations; visibility/API stability are not inferred.",
            ))

        # Deterministic, narrow concept recognizers. Each output cites the exact matching files/symbols.
        all_symbols = [(f, s) for f in python_files for s in f.get("symbols", [])]
        all_text = "\n".join(
            [f.get("path", "") + " " + f.get("module_docstring", "") for f in python_files]
            + [s.get("name", "") + " " + s.get("signature", "") + " " + s.get("docstring", "") for _, s in all_symbols]
        ).lower()
        file_by_name = {Path(f["path"]).name.lower(): f for f in python_files}

        # Adapter/transport abstraction.
        adapter_matches = [(f, s) for f, s in all_symbols if s.get("kind") == "class" and ("adapter" in s.get("name", "").lower() or "transport adapter" in s.get("docstring", "").lower())]
        if adapter_matches or "transport adapter" in all_text:
            evidence = [_evidence(f, symbol=s) for f, s in adapter_matches[:8]]
            for f in python_files:
                if "adapter" in Path(f["path"]).name.lower() and len(evidence) < MAX_EVIDENCE_PER_FACT:
                    evidence.append(_evidence(f, note="Adapter-related module; AST and module documentation inspected."))
            if evidence:
                facts.append(_make_fact(
                    repo, commit, "adapter_transport_abstraction",
                    "The repository contains adapter-named classes or modules documenting/implementing a transport-adapter boundary.", evidence,
                    caveat="The observation identifies an abstraction boundary; it does not establish that the design is optimal or universally reusable.",
                ))

        # Connection/session pooling.
        pooling_terms = ("pool_connections", "pool_maxsize", "connection-pooling", "connection pooling", "poolmanager")
        pooling_matches = [(f, s) for f, s in all_symbols if any(t in (s.get("name", "") + " " + s.get("signature", "") + " " + s.get("docstring", "")).lower() for t in pooling_terms)]
        pooling_files = [f for f in python_files if any(t in (f.get("path", "") + " " + f.get("module_docstring", "")).lower() for t in pooling_terms)]
        if pooling_matches or pooling_files:
            evidence = [_evidence(f, symbol=s) for f, s in pooling_matches[:8]]
            known = {e["path"] for e in evidence}
            for f in pooling_files:
                if f["path"] not in known and len(evidence) < MAX_EVIDENCE_PER_FACT:
                    evidence.append(_evidence(f, note="Module/path contains explicit connection-pooling or pool-manager terminology."))
            facts.append(_make_fact(
                repo, commit, "session_and_connection_pooling",
                "The source explicitly exposes or documents session/connection-pool concepts, including pool-related configuration or pool-manager references.", evidence,
                caveat="This is a description of names/documentation and source structure; performance behavior was not benchmarked.",
            ))

        # Retry policy.
        retry_matches = [(f, s) for f, s in all_symbols if any(t in (s.get("name", "") + " " + s.get("signature", "") + " " + s.get("docstring", "")).lower() for t in ("retry", "backoff", "max_retries"))]
        retry_files = [f for f in python_files if any(t in (" ".join(f.get("imports", [])) + " " + " ".join(f.get("call_names", [])) + " " + f.get("path", "")).lower() for t in ("retry", "backoff", "max_retries"))]
        if retry_matches or retry_files:
            evidence = [_evidence(f, symbol=s) for f, s in retry_matches[:8]]
            known = {e["path"] for e in evidence}
            for f in retry_files:
                if f["path"] not in known and len(evidence) < MAX_EVIDENCE_PER_FACT:
                    evidence.append(_evidence(f, note="Retry/backoff identifier appears in import, call, or module path."))
            facts.append(_make_fact(
                repo, commit, "retry_policy_structure",
                "The source includes retry/backoff identifiers, imports, configuration, or documented retry-related symbols.", evidence,
                caveat="Retry semantics and idempotency guarantees require line-level behavioral analysis and tests; identifiers alone are not proof.",
            ))

        # Exception hierarchy.
        exception_evidence = []
        for f in python_files:
            for c in f.get("exception_classes", []):
                exception_evidence.append(_evidence(f, note=f"Exception subclass: {c['name']} bases={c['bases']} line={c['line']}"))
        exception_files = [f for f in python_files if "exception" in Path(f["path"]).name.lower()]
        for f in exception_files:
            if len(exception_evidence) < MAX_EVIDENCE_PER_FACT:
                exception_evidence.append(_evidence(f, note="Exception-related module."))
        if exception_evidence:
            facts.append(_make_fact(
                repo, commit, "exception_taxonomy",
                "The repository defines exception-named modules and/or custom exception subclasses that form an explicit error taxonomy.", exception_evidence,
                caveat="The extracted hierarchy is structural; catch/raise behavior and public compatibility were not executed.",
            ))

        # Test evidence and correlation; never claim tests pass because they were not run.
        test_evidence = []
        test_assertions = 0
        for f in tests:
            count = int(f.get("metrics", {}).get("assertions", 0))
            test_assertions += count
            if count or Path(f["path"]).name.startswith("test_"):
                test_evidence.append(_evidence(f, note=f"Test-like Python file; AST assertions={count}; tests were not executed."))
        if test_evidence:
            facts.append(_make_fact(
                repo, commit, "test_contract_evidence",
                f"The acquired repository contains {len(test_evidence)} test-like Python files with {test_assertions} AST assert statements.", test_evidence,
                fact_type="test_evidence_not_test_result",
                caveat="Assertion presence does not mean the tests pass, cover all behavior, or are independent. No repository test code was executed.",
            ))

        # Test/source correlation by symbol-name occurrence in test source. Explicitly weak evidence.
        correlation = []
        test_sources: list[tuple[str, str]] = []
        for f in tests:
            try:
                p = repo_dir.joinpath(*PurePosixPath(f["path"]).parts)
                test_sources.append((f["path"], p.read_text(encoding="utf-8", errors="replace")))
            except OSError:
                continue
        for file_record, symbol in all_symbols:
            if symbol.get("kind") != "class" or len(correlation) >= 40:
                continue
            name = symbol.get("name", "")
            if len(name) < 4:
                continue
            matched_tests = [p for p, text in test_sources if name in text]
            if matched_tests:
                correlation.append({"symbol": name, "source_path": file_record["path"], "test_paths": matched_tests[:8], "relationship": "name_occurs_in_test_source_only"})
        if correlation:
            facts.append(_make_fact(
                repo, commit, "source_test_name_correlation",
                f"Found {len(correlation)} class-name occurrences in test source files; this is a navigation hint, not proof of coverage.",
                [_evidence(next(f for f, s in all_symbols if s.get("name") == item["symbol"]), note=f"Name-only test correlation: {item['test_paths']}") for item in correlation[:MAX_EVIDENCE_PER_FACT]],
                fact_type="weak_test_navigation_evidence",
                caveat="A matching name in a test file does not prove the class is exercised, nor that assertions validate its behavior.",
            ))

        metrics = {
            "registered_files": len(files_meta),
            "files_read": len(records),
            "python_files_parsed": len(python_files),
            "python_syntax_errors": sum(x.get("parse_status") == "syntax_error" for x in records),
            "classes": sum(x.get("metrics", {}).get("classes", 0) for x in python_files),
            "functions": sum(x.get("metrics", {}).get("functions", 0) + x.get("metrics", {}).get("async_functions", 0) for x in python_files),
            "test_files": len(tests),
            "assertions_in_test_files": test_assertions,
            "knowledge_facts": len(facts),
        }
        license_id = str(meta.get("license_id", "NOASSERTION"))
        recognized_licenses = {"Apache-2.0", "MIT", "BSD-2-Clause", "BSD-3-Clause", "MPL-2.0", "GPL-2.0-only", "GPL-3.0-only", "Unlicense", "CC0-1.0"}
        reuse_policy = (
            "LICENSE_IDENTIFIED_BUT_COMPATIBILITY_REVIEW_REQUIRED"
            if license_id in recognized_licenses
            else "NO_CODE_REUSE_UNTIL_LICENSE_IS_CLASSIFIED_AND_REVIEWED"
        )
        report = {
            "schema": SCHEMA,
            "generated_at": _now(),
            "success": bool(records) and bool(python_files),
            "repository": repo,
            "url": meta.get("url"),
            "commit": commit,
            "license": {
                "id": license_id,
                "file": meta.get("license_file"),
                "reuse_policy": reuse_policy,
            },
            "method": "deterministic_ast_docstring_test_evidence_extraction",
            "llm_used": False,
            "model_api_used": False,
            "source_executed": False,
            "metrics": metrics,
            "facts": facts,
            "files": [{k: x.get(k) for k in ("path", "sha256", "parse_status", "metrics", "test_file") if x.get(k) is not None} for x in records],
            "errors": errors[:100],
            "limits": [
                "This creates source-backed observations, not human-like semantic understanding.",
                "Docstrings and identifiers may be incomplete or misleading.",
                "Test assertions were counted, not executed; test correlation is not test coverage proof.",
                "No third-party source was imported or executed.",
                "An unclassified license blocks code-reuse recommendations until separately reviewed.",
            ],
        }
        self._merge_and_save(report)
        self._append_event({"type": "engineering_knowledge_extracted", "repository": repo, "commit": commit, "facts": len(facts), "files": len(records), "errors": len(errors)})
        return report

    def _merge_and_save(self, report: dict[str, Any]) -> None:
        existing: dict[str, Any] = {"schema": SCHEMA, "repositories": {}}
        try:
            value = json.loads(self.output_path.read_text(encoding="utf-8"))
            if isinstance(value, dict) and isinstance(value.get("repositories"), dict):
                existing = value
        except (OSError, ValueError, TypeError):
            pass
        repos = existing.setdefault("repositories", {})
        repos[report["repository"]] = report
        payload = {"schema": SCHEMA, "updated_at": _now(), "repositories": repos}
        tmp = self.output_path.with_suffix(".json.tmp")
        tmp.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.output_path)

    def _append_event(self, event: dict[str, Any]) -> None:
        path = self.data / "pika_native_knowledge_events.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"timestamp": _now(), **event}, ensure_ascii=False) + "\n")

    def search_facts(self, query: str, *, repository: str | None = None, limit: int = 8) -> list[dict[str, Any]]:
        q = {x.lower() for x in re.findall(r"[a-zA-Z][a-zA-Z0-9_]{2,}", query)}
        if not q:
            return []
        try:
            payload = json.loads(self.output_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return []
        matches = []
        for repo, record in payload.get("repositories", {}).items():
            if repository and repo != repository:
                continue
            for fact in record.get("facts", []):
                text = " ".join((fact.get("concept", ""), fact.get("statement", ""), fact.get("fact_type", ""))).lower()
                terms = set(re.findall(r"[a-zA-Z][a-zA-Z0-9_]{2,}", text))
                overlap = len(q & terms)
                if overlap:
                    matches.append((overlap, fact))
        matches.sort(key=lambda x: (x[0], x[1].get("evidence_count", 0)), reverse=True)
        return [fact for _, fact in matches[: max(1, min(int(limit), 20))]]


    # PIKA_NATIVE_KNOWLEDGE_BRAIN_V2
    def record_outcome(
        self,
        task: str,
        facts: list[dict[str, Any]],
        *,
        success: bool,
        surfaced_to_worker: bool,
        worker_reported_consumed: bool = False,
        evaluation: dict[str, Any] | None = None,
        attempt: int | None = None,
    ) -> None:
        """Record retrieval/outcome telemetry without upgrading fact trust.

        A surfaced or consumed fact remains OBSERVED_NOT_YET_VERIFIED_FOR_REUSE.
        Only a separate independent verification/governance flow may change trust.
        """
        evaluation = evaluation if isinstance(evaluation, dict) else {}
        fact_ids = [str(x.get("id")) for x in facts if isinstance(x, dict) and x.get("id")]
        sources = sorted({
            str(ev.get("repository", "")) + ":" + str(ev.get("path", ""))
            for fact in facts if isinstance(fact, dict)
            for ev in fact.get("evidence", []) if isinstance(ev, dict)
        })
        self._append_event({
            "type": "engineering_knowledge_outcome",
            "task": str(task)[:1000],
            "fact_ids": fact_ids[:40],
            "sources": sources[:80],
            "success": bool(success),
            "surfaced_to_worker": bool(surfaced_to_worker),
            "worker_reported_consumed": bool(worker_reported_consumed),
            "evaluation_passed": evaluation.get("passed"),
            "evaluation_score": evaluation.get("score"),
            "attempt": attempt,
            "trust_changed": False,
        })


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Extract provenance-backed engineering observations from PIKA's GitHub corpus.")
    parser.add_argument("--repo", required=True, help="Repository already acquired by PIKA, e.g. psf/requests")
    parser.add_argument("--root", default=".", help="PIKA project root")
    parser.add_argument("--max-files", type=int, default=MAX_FILES)
    parser.add_argument("--search", default=None, help="Search extracted facts after extraction")
    parser.add_argument("--json", action="store_true", help="Print the full provenance-backed JSON report")
    args = parser.parse_args(argv)
    engine = NativeEngineeringKnowledgeExtractor(args.root)
    report = engine.extract_repository(args.repo, max_files=args.max_files)
    if not report.get("success"):
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 1
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        summary = {
            "success": report["success"],
            "repository": report["repository"],
            "commit": report["commit"],
            "license": report["license"],
            "metrics": report["metrics"],
            "facts": [{"concept": x["concept"], "statement": x["statement"], "evidence_count": x["evidence_count"], "status": x["status"]} for x in report["facts"]],
            "errors": report["errors"],
            "llm_used": report["llm_used"],
            "model_api_used": report["model_api_used"],
            "source_executed": report["source_executed"],
            "saved_to": str(engine.output_path),
        }
        print(json.dumps(summary, indent=2, ensure_ascii=False))
    if args.search:
        print("\nFACT SEARCH:")
        print(json.dumps(engine.search_facts(args.search, repository=args.repo), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
