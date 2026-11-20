from __future__ import annotations

"""PIKA Verified Self-Improvement, Phase 1.

Builds source-backed improvement hypotheses and reproducible experiment plans.
It does NOT execute downloaded source, generate patches, or modify PIKA source.
Every proposal remains pending until a later isolated experiment and independent
verification stage supplies evidence.
"""

import argparse
import ast
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "pika.verified_self_improvement_plan.v1"
MARKER = "PIKA_VERIFIED_SELF_IMPROVEMENT_V2"
VERSION = "2.0.0"
SKIP_PARTS = {
    ".git", ".venv", "venv", ".sandbox_venv", "site-packages",
    "__pycache__", "node_modules", "workspace", "build", "dist",
    "target", "coverage", "data", "PIKA_KNOWLEDGE",
}
SCAN_DIRS = ("core", "agents", "memory", "evaluation", "tests")
MAX_SOURCE_BYTES = 600_000
MAX_SCAN_FILES = 1800
MAX_TARGETS_PER_FACT = 3

CONCEPT_TERMS: dict[str, tuple[str, ...]] = {
    "session_and_connection_pooling": ("session", "pool", "connection", "transport", "http"),
    "retry_policy_structure": ("retry", "backoff", "timeout", "failure", "recovery"),
    "adapter_transport_abstraction": ("adapter", "router", "worker", "agent", "interface"),
    "exception_taxonomy": ("exception", "error", "failure", "recovery"),
    "test_contract_evidence": ("test", "assert", "evaluation", "verification"),
    "source_test_name_correlation": ("test", "coverage", "assertion", "verification"),
    "public_and_internal_symbols": ("brain", "planner", "memory", "agent", "router"),
}

CONCEPT_QUESTIONS: dict[str, str] = {
    "session_and_connection_pooling": "Does the selected PIKA subsystem reuse bounded resources safely, and are lifecycle/cleanup invariants tested?",
    "retry_policy_structure": "Does the selected PIKA subsystem use bounded, failure-aware retries without repeating unsafe non-idempotent actions?",
    "adapter_transport_abstraction": "Would a stable adapter boundary reduce coupling while preserving the current worker/router contract?",
    "exception_taxonomy": "Are failures classified precisely enough to select safe, observable recovery actions?",
    "test_contract_evidence": "Do the selected PIKA interfaces have independent tests for success, failure, boundary and regression behavior?",
    "source_test_name_correlation": "Can a traceable mapping be established between the selected implementation symbols and PIKA regression tests?",
    "public_and_internal_symbols": "Are the selected PIKA module boundaries and public/internal interfaces explicit and consistently tested?",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}
    return value if isinstance(value, dict) else {}


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temp.replace(path)


def _tokens(value: str) -> set[str]:
    """Tokenize paths and Python identifiers across snake_case/camelCase."""
    text = str(value)
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    text = text.replace("_", " ").replace("-", " ")
    return {
        token.lower()
        for token in re.findall(r"[A-Za-z][A-Za-z0-9]{1,}", text)
    }


def _relative_inside(root: Path, raw: str) -> Path | None:
    try:
        candidate = (root / raw).resolve()
        candidate.relative_to(root.resolve())
        return candidate
    except (OSError, ValueError, RuntimeError):
        return None


class VerifiedSelfImprovement:
    """Evidence-gated proposal builder for the existing PIKA project."""

    def __init__(self, root: str | Path | None = None) -> None:
        self.root = Path(root or Path(__file__).resolve().parents[1]).expanduser().resolve()
        self.data = self.root / "data"
        self.engineering_path = self.data / "pika_native_engineering_knowledge.json"
        self.self_analysis_path = self.data / "pika_self_code_analysis.json"
        self.plan_path = self.data / "pika_verified_improvement_plan.json"
        self.events_path = self.data / "pika_verified_improvement_events.jsonl"
        self.corpus = self.data / "github_code_corpus"

    def _event(self, event: dict[str, Any]) -> None:
        self.events_path.parent.mkdir(parents=True, exist_ok=True)
        with self.events_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"timestamp": _now(), **event}, ensure_ascii=False) + "\n")

    def _facts(self) -> list[dict[str, Any]]:
        payload = _safe_json(self.engineering_path)
        out: list[dict[str, Any]] = []
        for repo, report in payload.get("repositories", {}).items():
            if not isinstance(report, dict):
                continue
            commit = str(report.get("commit", ""))
            license_meta = report.get("license", {}) if isinstance(report.get("license"), dict) else {}
            license_id = str(license_meta.get("id", "NOASSERTION"))
            reuse_policy = str(license_meta.get("reuse_policy", "UNKNOWN"))
            for fact in report.get("facts", []):
                if not isinstance(fact, dict):
                    continue
                evidence = [x for x in fact.get("evidence", []) if isinstance(x, dict)]
                if not evidence:
                    continue
                out.append({
                    "repository": str(repo),
                    "commit": commit,
                    "license_id": license_id,
                    "reuse_policy": reuse_policy,
                    "fact": fact,
                })
        return out

    def _self_findings(self) -> list[dict[str, Any]]:
        report = _safe_json(self.self_analysis_path)
        candidates: list[Any] = []
        for key in ("findings", "improvement_findings", "items"):
            value = report.get(key)
            if isinstance(value, list):
                candidates.extend(value)
        result = []
        for item in candidates:
            if not isinstance(item, dict):
                continue
            path = str(item.get("path", ""))
            if not path:
                continue
            result.append({
                "rule": str(item.get("rule", item.get("id", "unknown"))),
                "severity": str(item.get("severity", "unknown")),
                "path": path,
                "symbol": str(item.get("symbol", "")),
                "recommendation": str(item.get("recommendation", item.get("message", "Review this finding."))),
                "source_sha256": str(item.get("source_sha256", "")),
            })
        return result

    def _scan_local_targets(self) -> list[dict[str, Any]]:
        targets: list[dict[str, Any]] = []
        scanned = 0
        for directory in SCAN_DIRS:
            base = self.root / directory
            if not base.is_dir() or base.is_symlink():
                continue
            for path in base.rglob("*.py"):
                if scanned >= MAX_SCAN_FILES:
                    return targets
                # Check project-relative parts only. Checking path.parts here
                # also sees the Android prefix /data/data/... and incorrectly
                # excludes every file because "data" is in SKIP_PARTS.
                try:
                    rel_parts = path.relative_to(self.root).parts
                except ValueError:
                    continue
                if path.is_symlink() or any(part in SKIP_PARTS for part in rel_parts):
                    continue
                try:
                    resolved = path.resolve()
                    resolved.relative_to(self.root)
                    raw = path.read_bytes()
                    if not raw or len(raw) > MAX_SOURCE_BYTES:
                        continue
                    text = raw.decode("utf-8", errors="replace")
                    tree = ast.parse(text, filename=str(path))
                except (OSError, ValueError, SyntaxError, RuntimeError):
                    continue
                scanned += 1
                symbols: set[str] = set()
                imports: set[str] = set()
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        symbols.add(node.name)
                    elif isinstance(node, ast.Name):
                        symbols.add(node.id)
                    elif isinstance(node, ast.Import):
                        imports.update(alias.name for alias in node.names)
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        imports.add(node.module)
                rel = str(path.relative_to(self.root))
                targets.append({
                    "path": rel,
                    "sha256": _sha(raw),
                    "bytes": len(raw),
                    "symbols": sorted(symbols),
                    "imports": sorted(imports),
                    "line_count": len(text.splitlines()),
                })
        return targets

    @staticmethod
    def _evidence_is_valid(repo: str, commit: str, evidence: dict[str, Any]) -> bool:
        return (
            evidence.get("repository") == repo
            and evidence.get("commit") == commit
            and isinstance(evidence.get("path"), str)
            and bool(evidence.get("sha256"))
        )

    def _source_evidence_matches_corpus(self, repo: str, evidence: dict[str, Any]) -> bool:
        raw_path = evidence.get("path")
        if not isinstance(raw_path, str) or not raw_path or Path(raw_path).is_absolute() or ".." in Path(raw_path).parts:
            return False
        repo_dir = self.corpus.joinpath(*repo.split("/"))
        path = repo_dir.joinpath(*Path(raw_path).parts)
        try:
            resolved = path.resolve()
            resolved.relative_to(repo_dir.resolve())
            if path.is_symlink() or not path.is_file():
                return False
            return _sha(path.read_bytes()) == evidence.get("sha256")
        except (OSError, ValueError, RuntimeError):
            return False

    def build_plan(self) -> dict[str, Any]:
        facts = self._facts()
        local_targets = self._scan_local_targets()
        self_findings = self._self_findings()
        proposals: list[dict[str, Any]] = []
        skipped: list[dict[str, str]] = []

        for entry in facts:
            repo, commit, fact = entry["repository"], entry["commit"], entry["fact"]
            concept = str(fact.get("concept", "unknown"))
            evidence = [
                x for x in fact.get("evidence", [])
                if self._evidence_is_valid(repo, commit, x)
                and self._source_evidence_matches_corpus(repo, x)
            ]
            if not evidence:
                skipped.append({"repository": repo, "concept": concept, "reason": "missing_stale_or_inconsistent_source_provenance"})
                continue
            terms = set(CONCEPT_TERMS.get(concept, ()))
            if not terms:
                terms = _tokens(concept + " " + str(fact.get("statement", "")))
            ranked: list[tuple[int, dict[str, Any]]] = []
            for target in local_targets:
                haystack = _tokens(target["path"] + " " + " ".join(target["symbols"]) + " " + " ".join(target["imports"]))
                overlap = terms & haystack
                if overlap:
                    ranked.append((len(overlap), {**target, "matched_terms": sorted(overlap)}))
            ranked.sort(key=lambda pair: (pair[0], pair[1]["path"]), reverse=True)
            selected = [target for _, target in ranked[:MAX_TARGETS_PER_FACT]]
            if not selected:
                skipped.append({"repository": repo, "concept": concept, "reason": "no_local_architecture_target_found"})
                continue

            matching_findings = []
            target_paths = {x["path"] for x in selected}
            for finding in self_findings:
                if finding["path"] in target_paths:
                    matching_findings.append(finding)

            license_id = entry["license_id"]
            reuse_allowed = entry["reuse_policy"].upper() in {"ALLOW", "ALLOWED", "CODE_REUSE_ALLOWED"}
            question = CONCEPT_QUESTIONS.get(concept, f"Can the observed {concept} structure improve a corresponding PIKA subsystem?")
            stable = json.dumps({"repo": repo, "commit": commit, "concept": concept, "targets": [(x["path"], x["sha256"]) for x in selected]}, sort_keys=True)
            proposal_id = hashlib.sha256(stable.encode()).hexdigest()[:20]
            proposals.append({
                "id": proposal_id,
                "concept": concept,
                "status": "HYPOTHESIS_PENDING_EXPERIMENT",
                "hypothesis": question,
                "source": {
                    "repository": repo,
                    "commit": commit,
                    "license_id": license_id,
                    "reuse_policy": entry["reuse_policy"],
                    "code_reuse_allowed": reuse_allowed,
                    "source_executed": False,
                    "fact_status": str(fact.get("status", "unknown")),
                    "fact_statement": str(fact.get("statement", "")),
                    "evidence": [{k: ev.get(k) for k in ("repository", "commit", "path", "sha256", "kind", "name", "line_start", "line_end", "license_id", "source_executed") if ev.get(k) is not None} for ev in evidence[:12]],
                },
                "pika_targets": selected,
                "related_self_findings": matching_findings[:10],
                "experiment": {
                    "mode": "DESIGN_ONLY_NO_SOURCE_WRITES",
                    "question": question,
                    "steps": [
                        "Inspect the exact PIKA target interfaces and current regression tests.",
                        "Write a disposable experiment in a separate scratch workspace; do not edit live PIKA files.",
                        "Define positive, negative, boundary and regression cases before implementation.",
                        "Run only trusted project tests in an explicitly isolated environment; downloaded source remains data and is never executed.",
                        "Compare baseline and candidate behavior, resource use and failure handling.",
                        "Require independent evaluation and a complete rollback diff before considering promotion.",
                    ],
                    "acceptance_criteria": [
                        "The hypothesis is supported by line-level PIKA evidence, not keyword overlap alone.",
                        "All relevant baseline tests pass before and after the experiment.",
                        "New tests demonstrate the intended behavior and reject unsafe edge cases.",
                        "No unreviewed source from an unclassified license is copied or translated.",
                        "The live source tree remains unchanged until explicit promotion approval.",
                    ],
                    "required_measurements": ["baseline_test_result", "candidate_test_result", "behavioral_diff", "resource_measurement", "rollback_verification"],
                },
                "confidence": "LOW_TO_MODERATE_CANDIDATE_MATCH_ONLY",
                "caveats": [
                    "This is a deterministic hypothesis, not semantic proof.",
                    "Lexical/AST overlap only selects a review target; it does not prove the source design fits PIKA.",
                    "Observed facts are not approved for reuse.",
                    "Unclassified or unknown licenses prohibit copying/adapting source code until reviewed.",
                ],
            })

        plan = {
            "schema": SCHEMA,
            "generated_at": _now(),
            "mission": "True Evolution through Verified Self-Improvement",
            "phase": "PHASE_1_EVIDENCE_GATED_HYPOTHESIS_AND_EXPERIMENT_PLANNING",
            "llm_used": False,
            "model_api_used": False,
            "downloaded_source_executed": False,
            "live_source_modified": False,
            "automatic_promotion": False,
            "metrics": {
                "engineering_facts_seen": len(facts),
                "local_python_targets_scanned": len(local_targets),
                "self_findings_seen": len(self_findings),
                "proposals_created": len(proposals),
                "facts_skipped": len(skipped),
            },
            "proposals": proposals,
            "skipped": skipped,
            "plan_status": "HYPOTHESES_CREATED" if proposals else "NO_ELIGIBLE_PROPOSALS",
            "policy": "proposals_only; experiment design only; no source execution, source writes, code reuse, or automatic promotion",
        }
        _atomic_json(self.plan_path, plan)
        self._event({"type": "verified_improvement_plan_built", "proposals": len(proposals), "facts": len(facts), "targets": len(local_targets), "source_modified": False})
        return {"success": True, "plan_path": str(self.plan_path), **plan}

    def verify_plan(self) -> dict[str, Any]:
        plan = _safe_json(self.plan_path)
        if plan.get("schema") != SCHEMA:
            return {"success": False, "valid": False, "error": "PLAN_MISSING_OR_SCHEMA_MISMATCH", "plan_path": str(self.plan_path)}
        errors: list[str] = []
        checked_sources = checked_targets = 0
        proposals = plan.get("proposals", [])
        if not isinstance(proposals, list) or not proposals:
            errors.append("empty_plan_no_evidence_to_verify")
            proposals = []
        for proposal in proposals:
            if not isinstance(proposal, dict):
                errors.append("invalid_proposal_record")
                continue
            source = proposal.get("source", {})
            if not isinstance(source, dict):
                errors.append("invalid_source_record")
                continue
            repo = str(source.get("repository", ""))
            commit = str(source.get("commit", ""))
            source_evidence = source.get("evidence", [])
            target_records = proposal.get("pika_targets", [])
            if not isinstance(source_evidence, list) or not source_evidence:
                errors.append(f"proposal_has_no_source_evidence:{proposal.get('id', '?')}")
                source_evidence = []
            if not isinstance(target_records, list) or not target_records:
                errors.append(f"proposal_has_no_pika_targets:{proposal.get('id', '?')}")
                target_records = []
            for evidence in source_evidence:
                if not isinstance(evidence, dict):
                    errors.append(f"invalid_source_evidence_record:{proposal.get('id', '?')}")
                    continue
                if evidence.get("repository") != repo or evidence.get("commit") != commit:
                    errors.append(f"source_provenance_mismatch:{repo}:{evidence.get('path', '?')}")
                    continue
                raw_path = str(evidence.get("path", ""))
                if not raw_path or Path(raw_path).is_absolute() or ".." in Path(raw_path).parts:
                    errors.append(f"unsafe_source_path:{repo}:{raw_path}")
                    continue
                path = self.corpus.joinpath(*repo.split("/"), *Path(raw_path).parts)
                try:
                    resolved = path.resolve()
                    resolved.relative_to(self.corpus.resolve())
                    if path.is_symlink() or not path.is_file():
                        raise FileNotFoundError
                    if _sha(path.read_bytes()) != evidence.get("sha256"):
                        raise ValueError("sha256_mismatch")
                    checked_sources += 1
                except (OSError, ValueError, RuntimeError) as exc:
                    errors.append(f"source_evidence_invalid:{repo}:{raw_path}:{exc}")
            for target in target_records:
                if not isinstance(target, dict):
                    errors.append(f"invalid_pika_target_record:{proposal.get('id', '?')}")
                    continue
                raw_target_path = str(target.get("path", ""))
                if not raw_target_path or Path(raw_target_path).is_absolute() or ".." in Path(raw_target_path).parts:
                    errors.append(f"unsafe_pika_target_path:{raw_target_path}")
                    continue
                path = _relative_inside(self.root, raw_target_path)
                try:
                    if path is None or path.is_symlink() or not path.is_file():
                        raise FileNotFoundError
                    if _sha(path.read_bytes()) != target.get("sha256"):
                        raise ValueError("target_sha256_changed")
                    checked_targets += 1
                except (OSError, ValueError, RuntimeError) as exc:
                    errors.append(f"pika_target_invalid:{target.get('path')}:{exc}")
        # A verification pass is never valid unless it checked at least one
        # real source record and one real PIKA target. Prevent vacuous success.
        if checked_sources == 0:
            errors.append("no_source_evidence_was_checked")
        if checked_targets == 0:
            errors.append("no_pika_target_hashes_were_checked")
        valid = not errors and bool(proposals) and checked_sources > 0 and checked_targets > 0
        result = {
            "success": valid,
            "valid": valid,
            "schema": SCHEMA,
            "proposals": len(proposals),
            "source_evidence_checked": checked_sources,
            "pika_targets_checked": checked_targets,
            "errors": errors[:100],
            "source_executed": False,
            "live_source_modified": False,
            "automatic_promotion": False,
        }
        self._event({"type": "verified_improvement_plan_verified", **result})
        return result

    def status(self) -> dict[str, Any]:
        plan = _safe_json(self.plan_path)
        return {
            "success": True,
            "plan_exists": plan.get("schema") == SCHEMA,
            "plan_path": str(self.plan_path),
            "proposals": len(plan.get("proposals", [])),
            "generated_at": plan.get("generated_at"),
            "phase": plan.get("phase"),
            "source_execution": False,
            "live_source_writes": False,
            "automatic_promotion": False,
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PIKA evidence-gated self-improvement planning")
    parser.add_argument("command", choices=("build", "verify", "status"))
    parser.add_argument("--root", default=None)
    args = parser.parse_args(argv)
    engine = VerifiedSelfImprovement(args.root)
    if args.command == "build":
        result = engine.build_plan()
    elif args.command == "verify":
        result = engine.verify_plan()
    else:
        result = engine.status()
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result.get("success", False) else 1


if __name__ == "__main__":
    raise SystemExit(main())
