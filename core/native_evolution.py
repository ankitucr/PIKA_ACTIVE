"""Native, reversible self-evolution proposal staging.

Only explicitly named deterministic transformations are allowed. Candidates are
staged through the existing Phase 37 experiment engine; live source is never
modified and no candidate is executed by this module.
"""
from __future__ import annotations

import ast
import difflib
import hashlib
import io
import tokenize
from pathlib import Path, PurePosixPath
from typing import Any

from core.evolution.experiments import CandidateExperimentEngine

MAX_SOURCE_BYTES = 500_000
ALLOWED_RULES = {"none_comparison_identity_v1"}


class NativeSelfEvolutionError(ValueError):
    """A native evolution request is invalid or not supported by a rule."""


def _safe_source_path(root: Path, value: str) -> tuple[str, Path]:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise NativeSelfEvolutionError("Target must be a relative POSIX Python path.")
    rel = PurePosixPath(value)
    if rel.is_absolute() or rel.as_posix() != value or rel.suffix != ".py" or any(p in {"", ".", ".."} or p.startswith(".") for p in rel.parts):
        raise NativeSelfEvolutionError("Target must be a clean relative Python path.")
    cursor = root
    for part in rel.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise NativeSelfEvolutionError("Symlink source paths are forbidden.")
    resolved = cursor.resolve(strict=True)
    resolved.relative_to(root)
    if not resolved.is_file() or resolved.stat().st_size > MAX_SOURCE_BYTES:
        raise NativeSelfEvolutionError("Target must be a regular Python file within the size limit.")
    return rel.as_posix(), resolved


def _offset(source: str, position: tuple[int, int]) -> int:
    lines = source.splitlines(keepends=True)
    return sum(len(line) for line in lines[: position[0] - 1]) + position[1]


def _replace_none_comparison(source: str) -> tuple[str, int]:
    """Replace exactly one tokenized equality/inequality comparison to None."""
    try:
        ast.parse(source)
    except SyntaxError as exc:
        raise NativeSelfEvolutionError(f"Baseline source must parse before this rule: {exc.msg}") from exc
    tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    matches = []
    significant = [token for token in tokens if token.type not in {tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT, tokenize.COMMENT, tokenize.ENCODING}]
    for index, token in enumerate(significant):
        if token.type != tokenize.NAME or token.string != "None" or index == 0:
            continue
        previous = significant[index - 1]
        if previous.type == tokenize.OP and previous.string in {"==", "!="}:
            matches.append(previous)
    if len(matches) != 1:
        raise NativeSelfEvolutionError("Rule requires exactly one unambiguous comparison to None.")
    operator = matches[0]
    start = _offset(source, operator.start)
    end = _offset(source, operator.end)
    replacement = "is" if operator.string == "==" else "is not"
    candidate = source[:start] + replacement + source[end:]
    try:
        ast.parse(candidate)
    except SyntaxError as exc:
        raise NativeSelfEvolutionError(f"Transformed candidate did not parse: {exc.msg}") from exc
    return candidate, 1


class NativeSelfEvolutionEngine:
    """Create an evidence-bound candidate using a fixed native transformation."""

    def __init__(self, root: str | Path, knowledge_root: str | Path | None = None) -> None:
        requested = Path(root).expanduser()
        if requested.is_symlink():
            raise NativeSelfEvolutionError("Project root must not be a symlink.")
        self.root = requested.resolve(strict=True)
        self.knowledge = Path(knowledge_root).expanduser().resolve() if knowledge_root else self.root / "PIKA_KNOWLEDGE"
        self.experiments = CandidateExperimentEngine(self.knowledge)

    def propose_and_stage(
        self,
        target: str,
        *,
        test_paths: list[str],
        rule_id: str,
        evidence: list[dict[str, Any]],
        rationale: str,
    ) -> dict[str, Any]:
        if rule_id not in ALLOWED_RULES:
            raise NativeSelfEvolutionError("No approved deterministic transformation matches this rule ID.")
        if not isinstance(evidence, list) or not evidence or len(evidence) > 8 or any(not isinstance(item, dict) for item in evidence):
            raise NativeSelfEvolutionError("One to eight structured evidence records are required.")
        if not isinstance(rationale, str) or not rationale.strip() or len(rationale) > 2000:
            raise NativeSelfEvolutionError("A bounded rationale is required.")
        target_key, source_path = _safe_source_path(self.root, target)
        baseline = source_path.read_text(encoding="utf-8")
        baseline_sha = hashlib.sha256(baseline.encode("utf-8")).hexdigest()
        candidate, edits = _replace_none_comparison(baseline)
        candidate_sha = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
        diff = "".join(difflib.unified_diff(
            baseline.splitlines(keepends=True),
            candidate.splitlines(keepends=True),
            fromfile=f"baseline/{target_key}",
            tofile=f"candidate/{target_key}",
        ))
        staged = self.experiments.stage_candidate(
            self.root,
            target_key,
            candidate,
            test_paths=test_paths,
            expected_base_sha256=baseline_sha,
            rationale=rationale,
            provenance={
                "provider": "pika-native",
                "generation_mode": "native_deterministic_rule",
                "diagnostic_classification": rule_id,
            },
        )
        return {
            "success": True,
            "schema": "pika.native_self_evolution_proposal.v1",
            "candidate_id": staged["candidate_id"],
            "target": target_key,
            "rule_id": rule_id,
            "edit_count": edits,
            "baseline_sha256": baseline_sha,
            "candidate_sha256": candidate_sha,
            "diff": diff[:12_000],
            "evidence": evidence,
            "test_paths": list(test_paths),
            "stage": "ISOLATED_CANDIDATE_STAGED",
            "candidate_trust": "UNVERIFIED_LOCAL",
            "execution": "NOT_EXECUTED",
            "source_executed": False,
            "live_source_modified": False,
            "trusted_learning_admission": False,
            "promotion_allowed": False,
            "rollback": "BASELINE_SNAPSHOT_RECORDED_BY_EXPERIMENT_ENGINE",
            "next_required_step": "independent_candidate_evaluation_and_result_attestation",
            "experiment": staged,
        }
