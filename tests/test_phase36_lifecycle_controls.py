from __future__ import annotations

import ast
from pathlib import Path

import pytest

from core.phase32_controller import Phase32Controller
from core.package_manager import PackageManager
from core.pika_code_learning import PikaCodeLearning
from core.repair_candidate_generator import RepairCandidateGenerator
from core.self_healing import SelfHealingEngine
from core.phase36.scanner import SourceScanner
from core.phase36.weaknesses import WeaknessAnalyzer


class PackageInstallSpy:
    def __init__(self):
        self.calls = []

    def install(self, package):
        self.calls.append(package)
        return {
            "success": True,
            "available_after": True,
            "already_available": False,
        }


class ExplicitWorker:
    async def ask(self, *args, **kwargs):
        return {"success": False, "error": "test worker not invoked"}


def make_phase32(*, allowlist=(), approval=None, package_manager=None):
    controller = object.__new__(Phase32Controller)
    controller.dependency_allowlist = frozenset(
        controller._normalize_package_name(item)
        for item in allowlist
        if PackageManager.validate_package_name(item)
    )
    controller.dependency_approval = approval
    controller.package_manager = package_manager or PackageInstallSpy()
    return controller


def test_dependency_install_requires_allowlist_and_explicit_true_approval():
    spy = PackageInstallSpy()

    no_allowlist = make_phase32(
        approval=lambda package, diagnosis: True,
        package_manager=spy,
    )
    result = no_allowlist._install_dependency({"package": "pytest"})
    assert result["success"] is False
    assert "allowlist" in result["error"].lower()
    assert spy.calls == []

    no_approval = make_phase32(
        allowlist=("pytest",),
        approval=None,
        package_manager=spy,
    )
    result = no_approval._install_dependency({"package": "pytest"})
    assert result["success"] is False
    assert spy.calls == []

    denied = make_phase32(
        allowlist=("pytest",),
        approval=lambda package, diagnosis: 1,
        package_manager=spy,
    )
    result = denied._install_dependency({"package": "pytest"})
    assert result["success"] is False
    assert spy.calls == []

    approved = make_phase32(
        allowlist=("Py_Test",),
        approval=lambda package, diagnosis: True,
        package_manager=spy,
    )
    # Normalization treats case, underscore and hyphen consistently.
    approved.dependency_allowlist = frozenset({"py-test"})
    result = approved._install_dependency({"package": "py-test"})
    assert result["success"] is True
    assert spy.calls == ["py-test"]


def test_repair_worker_adapter_never_selects_an_external_provider_implicitly(tmp_path):
    with pytest.raises(ValueError, match="explicit repair worker"):
        RepairCandidateGenerator(workspace_root=tmp_path)

    generator = RepairCandidateGenerator(
        worker=ExplicitWorker(),
        workspace_root=tmp_path,
    )
    assert generator.worker.__class__ is ExplicitWorker


def test_native_repair_generator_is_the_active_brain_default():
    source = (Path(__file__).resolve().parents[1] / "core" / "brain.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    imports = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        and node.module == "core.native_repair_generator"
    ]
    assert imports, "PIKABrain must use the native-only candidate generator"
    aliases = {
        alias.asname or alias.name
        for node in imports
        for alias in node.names
    }
    assert "RepairCandidateGenerator" in aliases
    assert "core.repair_candidate_generator" not in source


def test_code_knowledge_retrieval_does_not_index_implicitly(tmp_path):
    corpus = tmp_path / "data" / "github_code_corpus" / "sample"
    corpus.mkdir(parents=True)
    (corpus / "example.py").write_text(
        "def deterministic_repair(value):\n    return value\n",
        encoding="utf-8",
    )

    knowledge = PikaCodeLearning(tmp_path, auto_index_on_retrieve=False)
    result = knowledge.retrieve("deterministic repair")

    assert result["items"] == []
    assert result["reason"] == "index_not_ready"
    assert not knowledge.index_path.exists()

    indexed = knowledge.index_corpus()
    assert indexed["indexed"] == 1
    result = knowledge.retrieve("deterministic repair")
    assert result["items"]
    assert knowledge.index_path.exists()


def test_brain_exposes_indexing_as_an_explicit_lifecycle_action():
    source = (Path(__file__).resolve().parents[1] / "core" / "brain.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    brain_class = next(
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "PIKABrain"
    )
    init = next(
        node for node in brain_class.body
        if isinstance(node, ast.FunctionDef) and node.name == "__init__"
    )
    init_source = ast.get_source_segment(source, init) or ""
    assert "index_corpus(" not in init_source
    assert "auto_index_on_retrieve=False" in init_source
    assert any(
        isinstance(node, ast.FunctionDef) and node.name == "index_code_knowledge"
        for node in brain_class.body
    )


def test_self_healing_has_no_unenforced_retry_setting():
    source = (Path(__file__).resolve().parents[1] / "core" / "self_healing.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    engine = next(
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "SelfHealingEngine"
    )
    source_segment = ast.get_source_segment(source, engine) or ""
    assert "self.max_retries" not in source_segment
    assert "max_retries" not in source_segment


def test_readiness_audit_recognizes_lifecycle_and_provider_controls():
    root = Path(__file__).resolve().parents[1]
    snapshot = SourceScanner(root).scan()
    findings = WeaknessAnalyzer(snapshot).analyze()
    ids = {item.finding_id for item in findings}

    assert "repair_generation_provider_coupling" not in ids
    assert "automatic_dependency_installation" not in ids
    assert "brain_startup_indexing_side_effect" not in ids
    assert "self_healing_retry_setting_unused" not in ids
