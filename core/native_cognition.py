"""PIKA's native, non-LLM cognition entrypoint.

This module orchestrates deterministic source analysis, GitHub source acquisition,
structural knowledge and the existing Brain's memory/evaluation layers. It does not
call an inference provider or execute downloaded repository code.
"""
from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from core.native_code_analyzer import NativeCodeAnalyzer


_REPO_URL = re.compile(r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:[/?#\s]|$)", re.I)
_OWNER_REPO = re.compile(r"(?<![A-Za-z0-9_.-])([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)(?:\.git)?(?![A-Za-z0-9_.-])")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class NativeCognitionEngine:
    """One native task interface for PIKA's existing Brain."""

    def __init__(self, root: str | Path | None = None) -> None:
        self.root = Path(root or Path(__file__).resolve().parents[1]).expanduser().resolve()
        self.data = self.root / "data"
        self.data.mkdir(parents=True, exist_ok=True)
        self.analyzer = NativeCodeAnalyzer()
        self.learning = None
        try:
            from core.pika_code_learning import PikaCodeLearning
            self.learning = PikaCodeLearning(self.root)
        except Exception:
            # The source analyzer is independently usable during bootstrap/tests.
            self.learning = None

        # PIKA_NATIVE_KNOWLEDGE_BRAIN_V2: same Brain, second evidence source.
        self.engineering_knowledge = None
        try:
            from core.native_knowledge_extractor import NativeEngineeringKnowledgeExtractor
            self.engineering_knowledge = NativeEngineeringKnowledgeExtractor(self.root)
        except Exception as exc:
            self._append_event({
                "type": "engineering_knowledge_unavailable",
                "error": f"{type(exc).__name__}: {exc}"[:300],
            })

    def _append_event(self, event: dict[str, Any]) -> None:
        path = self.data / "pika_native_learning_events.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"timestamp": _now(), **event}, ensure_ascii=False) + "\n")

    def analyze_self(self) -> dict[str, Any]:
        """Analyze PIKA's own source using AST only; never imports or executes it."""
        result = self.analyzer.analyze_project(self.root)
        self_path = self.data / "pika_self_code_analysis.json"
        NativeCodeAnalyzer.save(result, self_path)
        queue = {
            "schema": "pika.native_improvement_queue.v1",
            "generated_at": _now(),
            "source": "native_static_self_analysis",
            "items": result.get("improvement_findings", []),
            "policy": "proposals_only; no source files modified; static findings require review",
        }
        queue_path = self.data / "pika_native_improvement_queue.json"
        NativeCodeAnalyzer.save(queue, queue_path)
        self._append_event({
            "type": "self_code_analysis",
            "files": result.get("metrics", {}).get("python_files_analyzed", 0),
            "findings": len(queue["items"]),
            "source_modified": False,
        })
        return {
            "success": True,
            "mode": "native_static_self_analysis",
            "llm_used": False,
            "model_api_used": False,
            "source_executed": False,
            "source_modified": False,
            "analysis_path": str(self_path),
            "improvement_queue_path": str(queue_path),
            "metrics": result.get("metrics", {}),
            "findings": queue["items"][:30],
            "limits": result.get("limits", []),
        }

    def learn_repositories(self, repositories: Iterable[str], *, max_files: int = 80) -> dict[str, Any]:
        """Fetch GitHub repositories through Git transport and analyze them as data."""
        repo_list = [str(x).strip() for x in repositories if str(x).strip()]
        if not repo_list:
            return {
                "success": False,
                "error": "GITHUB_REPOSITORY_REQUIRED",
                "message": "Provide one or more GitHub repositories as owner/repo or https://github.com/owner/repo.",
            }
        from core.git_learning_loop import run_cycle
        result = run_cycle(repo_list, max_files=max_files)
        self._append_event({
            "type": "github_learning_cycle",
            "repositories": repo_list,
            "scanned": result.get("repositories_scanned", 0),
            "llm_used": False,
            "model_api_used": False,
            "source_executed": False,
        })
        return {
            "success": bool(result.get("repositories_scanned")),
            "mode": "git_transport_plus_native_static_analysis",
            "llm_used": False,
            "model_api_used": False,
            "source_executed": False,
            **result,
        }

    def search_code(self, query: str, *, limit: int = 5) -> dict[str, Any]:
        """Search lexical source snippets and structured engineering observations."""
        retrieval: dict[str, Any] = {"query": str(query), "items": [], "method": "unavailable"}
        if self.learning is not None:
            value = self.learning.retrieve(query, limit=limit)
            if isinstance(value, dict):
                retrieval = value
        facts: list[dict[str, Any]] = []
        if self.engineering_knowledge is not None:
            facts = self.engineering_knowledge.search_facts(query, limit=limit)
        items = retrieval.get("items", []) if isinstance(retrieval, dict) else []
        items = items if isinstance(items, list) else []
        self._append_event({
            "type": "native_knowledge_retrieval_combined",
            "query": str(query)[:500],
            "lexical_hits": len(items),
            "engineering_fact_hits": len(facts),
            "lexical_method": retrieval.get("method", "unavailable"),
            "llm_used": False,
            "model_api_used": False,
        })
        return {
            "success": bool(items or facts),
            "query": str(query),
            "items": items[: max(0, min(int(limit), 10))],
            "engineering_facts": facts,
            "methods": {
                "source_retrieval": retrieval.get("method", "unavailable"),
                "engineering_facts": "source_backed_observation_search",
            },
            "llm_used": False,
            "model_api_used": False,
            "trust_note": "Engineering facts are source observations, not verified best practices or proof of behavior.",
        }

    def status(self) -> dict[str, Any]:
        def load(path: Path) -> dict[str, Any]:
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                return data if isinstance(data, dict) else {}
            except (OSError, ValueError, TypeError):
                return {}

        registry = load(self.data / "pika_native_git_registry.json")
        knowledge = load(self.data / "pika_native_code_knowledge.json")
        self_report = load(self.data / "pika_self_code_analysis.json")
        eng_doc = load(self.data / "pika_native_engineering_knowledge.json")
        return {
            "brain": "PIKABrain",
            "cognition": "native_deterministic_code_cognition",
            "external_llm": False,
            "model_api": False,
            "github_transport": "git",
            "repositories_learned": len(registry.get("repositories", {})),
            "github_python_files_analyzed": knowledge.get("metrics", {}).get("python_files_analyzed", 0),
            "self_python_files_analyzed": self_report.get("metrics", {}).get("python_files_analyzed", 0),
            "self_improvement_proposals": len(load(self.data / "pika_native_improvement_queue.json").get("items", [])),
            "knowledge_index": str(self.data / "pika_learning_index.json"),
            "engineering_knowledge_repositories": len(eng_doc.get("repositories", {})),
            "engineering_knowledge_facts": sum(
                len(record.get("facts", []))
                for record in eng_doc.get("repositories", {}).values()
                if isinstance(record, dict)
            ),
            "engineering_knowledge_file": str(self.data / "pika_native_engineering_knowledge.json"),
        }

    @staticmethod
    def _repositories_from_task(task: str) -> list[str]:
        found: list[str] = []
        for owner, name in _REPO_URL.findall(task):
            value = f"{owner}/{name.removesuffix('.git')}"
            if value not in found:
                found.append(value)
        if not found and "github" in task.lower():
            # Only accept owner/repo tokens when the task explicitly says GitHub.
            for owner, name in _OWNER_REPO.findall(task):
                value = f"{owner}/{name.removesuffix('.git')}"
                if value not in found and value.lower() not in {"github/repo", "git/hub"}:
                    found.append(value)
        return found

    async def execute(self, task: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        context = context if isinstance(context, dict) else {}
        text = str(task or "").strip()
        lower = text.lower()

        if not text:
            return self._failure("EMPTY_TASK", "A task is required.")

        if isinstance(context.get("workspace"), dict):
            return self._failure(
                "NATIVE_CODE_GENERATION_NOT_YET_SUPPORTED",
                "This native Brain build does not yet synthesize arbitrary workspace applications. No model/API fallback is enabled; no workspace files were generated.",
            )

        github_action = any(word in lower for word in ("learn", "acquire", "clone", "index", "scan", "study")) and "github" in lower
        if github_action:
            repositories = self._repositories_from_task(text)
            if not repositories:
                return self._failure(
                    "GITHUB_REPOSITORY_REQUIRED",
                    "Name the repository explicitly, for example: learn GitHub repo owner/project. The loop uses Git transport, not an inference API.",
                )
            result = await asyncio.to_thread(self.learn_repositories, repositories)
            output = self._format_learning_report(result)
            return self._response(result.get("success", False), output, knowledge_consumed=False, raw=result)

        self_markers = ("self analyze", "self-analyze", "analyze yourself", "analyze your own code", "analyse your own code", "inspect your own code", "review your own architecture", "self code analysis", "improve yourself", "inspect pika")
        if any(marker in lower for marker in self_markers):
            result = await asyncio.to_thread(self.analyze_self)
            output = self._format_self_report(result)
            return self._response(result.get("success", False), output, knowledge_consumed=False, raw=result)

        if any(marker in lower for marker in ("learning status", "native brain status", "github learning status", "knowledge status")):
            result = self.status()
            return self._response(True, json.dumps(result, indent=2, ensure_ascii=False), knowledge_consumed=False, raw=result)

        # PIKA_NATIVE_KNOWLEDGE_BRAIN_V2: expose both evidence stores to native tasks.
        knowledge = context.get("github_code_knowledge", {})
        items = knowledge.get("items", []) if isinstance(knowledge, dict) else []
        engineering_facts = context.get("native_engineering_knowledge", [])
        if not isinstance(engineering_facts, list):
            engineering_facts = []
        search_markers = ("search", "find", "show", "retrieve", "github", "code example", "pattern", "knowledge")
        is_search_task = any(marker in lower for marker in search_markers) and any(
            marker in lower for marker in ("code", "github", "knowledge", "pattern", "adapter", "memory", "retry", "testing", "architecture")
        )
        if is_search_task and (items or engineering_facts):
            safe_items = []
            for item in items[:5]:
                if not isinstance(item, dict):
                    continue
                safe_items.append({key: item.get(key) for key in ("repository", "source", "language", "sha256", "matched_terms", "summary", "snippet", "warning") if item.get(key) is not None})
            safe_facts = []
            for fact in engineering_facts[:8]:
                if not isinstance(fact, dict):
                    continue
                safe_facts.append({key: fact.get(key) for key in ("id", "concept", "fact_type", "statement", "confidence", "confidence_scope", "evidence_count", "evidence", "caveat", "status") if fact.get(key) is not None})
            output = (
                "NATIVE SOURCE EVIDENCE (lexical matches; not semantic proof):\n"
                + json.dumps({"lexical_items": safe_items, "engineering_facts": safe_facts}, indent=2, ensure_ascii=False)
                + "\nTrust: OBSERVED_NOT_YET_VERIFIED_FOR_REUSE facts are observations only. No code reuse or self-modification is authorized by retrieval."
            )
            return self._response(
                True, output, knowledge_consumed=bool(safe_items or safe_facts),
                raw={"items": safe_items, "engineering_facts": safe_facts, "method": "combined_native_evidence"},
            )

        if any(marker in lower for marker in ("search code", "find code", "search github", "find github code", "code knowledge", "search knowledge", "find knowledge")):
            result = await asyncio.to_thread(self.search_code, text, limit=5)
            output = json.dumps(result, indent=2, ensure_ascii=False)
            return self._response(
                result.get("success", False), output,
                knowledge_consumed=bool(result.get("items") or result.get("engineering_facts")), raw=result,
            )

        if any(marker in lower for marker in ("architecture", "module map", "dependency map", "inspect", "analyze", "analyse", "review")) and any(marker in lower for marker in ("pika", "project", "code", "module", "system", "architecture")):
            result = await asyncio.to_thread(self.analyze_self)
            output = self._format_self_report(result)
            return self._response(result.get("success", False), output, knowledge_consumed=False, raw=result)

        return self._failure(
            "UNSUPPORTED_NATIVE_OPERATION",
            "This request is outside the current verified native capability set. Current supported operations: GitHub repository learning, PIKA source AST analysis, static improvement-queue generation, and lexical code-evidence retrieval. No LLM/API fallback is enabled.",
        )

    @staticmethod
    def _failure(code: str, message: str) -> dict[str, Any]:
        return {
            "success": False,
            "agent": "native",
            "provider": "pika-native",
            "model": None,
            "error": code,
            "output": message,
            "knowledge_consumed": False,
            "raw": {"error": code},
        }

    @staticmethod
    def _response(success: bool, output: str, *, knowledge_consumed: bool, raw: dict[str, Any]) -> dict[str, Any]:
        return {
            "success": bool(success),
            "agent": "native",
            "provider": "pika-native",
            "model": None,
            "output": output,
            "error": None if success else "NATIVE_OPERATION_INCOMPLETE",
            "knowledge_consumed": bool(knowledge_consumed),
            "raw": raw,
        }

    @staticmethod
    def _format_self_report(result: dict[str, Any]) -> str:
        metrics = result.get("metrics", {})
        findings = result.get("findings", [])
        lines = [
            "PIKA NATIVE SELF-CODE ANALYSIS",
            f"Python files: {metrics.get('python_files_analyzed', 0)} | parsed: {metrics.get('parsed_files', 0)} | syntax errors: {metrics.get('syntax_error_files', 0)}",
            f"Classes: {metrics.get('classes', 0)} | functions: {metrics.get('functions', 0)} | structural patterns: {metrics.get('structural_patterns', 0)}",
            f"Static findings: {metrics.get('static_findings', 0)} | high severity: {metrics.get('high_severity_findings', 0)}",
            f"Improvement proposals saved: {len(findings)}",
            f"Report: {result.get('analysis_path')}",
            f"Queue: {result.get('improvement_queue_path')}",
            "Policy: source was parsed as data; no project code was executed or modified.",
        ]
        for item in findings[:12]:
            lines.append(f"- [{item.get('severity', 'unknown')}] {item.get('rule')} | {item.get('path')}:{item.get('line')} | {item.get('evidence')}")
        return "\n".join(lines)

    @staticmethod
    def _format_learning_report(result: dict[str, Any]) -> str:
        metrics = result.get("github_code_analysis", {})
        lines = [
            "PIKA NATIVE GITHUB LEARNING CYCLE",
            f"Repositories scanned: {result.get('repositories_scanned', 0)}",
            f"Python files structurally analyzed: {metrics.get('python_files_analyzed', 0)}",
            f"AST patterns found: {metrics.get('structural_patterns', 0)}",
            f"Errors: {len(result.get('errors', []))}",
            f"Knowledge: {result.get('knowledge_file')}",
            f"Self analysis: {result.get('self_analysis_file')}",
            "Transport: Git clone/fetch. No inference model, LLM API, or downloaded-code execution.",
        ]
        for repo in result.get("repositories", [])[:10]:
            lines.append(f"- {repo.get('repository')} | {repo.get('files_copied')} files | commit {str(repo.get('commit', ''))[:12]} | license {repo.get('license_id')}")
        return "\n".join(lines)
