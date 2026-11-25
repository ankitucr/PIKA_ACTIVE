from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.native_capability_bundle import CapabilityBundleError, NativeCapabilityBundleEngine


def make_source(root: Path):
    (root / "core").mkdir()
    (root / "tests").mkdir()
    (root / "core" / "__init__.py").write_text("", encoding="utf-8")
    (root / "core" / "engine.py").write_text(
        "from core.helpers import normalize\n\ndef run(value):\n    return normalize(value)\n",
        encoding="utf-8",
    )
    (root / "core" / "helpers.py").write_text(
        "def normalize(value):\n    return str(value).strip()\n",
        encoding="utf-8",
    )
    (root / "tests" / "test_engine.py").write_text(
        "from core.engine import run\n\ndef test_run():\n    assert run(' x ') == 'x'\n",
        encoding="utf-8",
    )


def test_stages_multi_file_capability_with_hash_bound_manifest(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    make_source(source)
    engine = NativeCapabilityBundleEngine(tmp_path / "knowledge")
    result = engine.stage_bundle(
        source,
        name="sample-engine",
        include_paths=["core/__init__.py", "core/engine.py", "core/helpers.py", "tests/test_engine.py"],
        test_paths=["tests/test_engine.py"],
    )
    assert result["success"] is True
    assert result["file_count"] == 4
    assert result["test_count"] == 1
    assert result["trust"] == "UNTRUSTED_SOURCE_OBSERVATION"
    assert result["execution_performed"] is False
    assert result["production_promotion_allowed"] is False
    manifest = json.loads((Path(result["bundle_path"]) / "bundle.json").read_text())
    assert manifest["manifest_sha256"] == result["manifest_sha256"]
    assert len({row["sha256"] for row in manifest["files"]}) == 4
    assert manifest["internal_dependency_gaps"] == []


def test_flags_risky_runtime_surfaces_without_executing_them(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "danger.py").write_text("def run(value):\n    return eval(value)\n", encoding="utf-8")
    result = NativeCapabilityBundleEngine(tmp_path / "knowledge").stage_bundle(
        source, name="risk-review", include_paths=["danger.py"]
    )
    manifest = json.loads((Path(result["bundle_path"]) / "bundle.json").read_text())
    assert "DYNAMIC_CODE_OR_IMPORT_PRIMITIVE" in manifest["files"][0]["static_risk_flags"]
    assert result["execution_performed"] is False


@pytest.mark.parametrize("paths", [
    ["../escape.py"],
    ["/absolute.py"],
    ["../.env.py"],
])
def test_rejects_unsafe_paths(tmp_path, paths):
    source = tmp_path / "source"
    source.mkdir()
    engine = NativeCapabilityBundleEngine(tmp_path / "knowledge")
    with pytest.raises(CapabilityBundleError):
        engine.stage_bundle(source, name="unsafe", include_paths=paths)


def test_rejects_missing_tests_and_duplicate_paths(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    engine = NativeCapabilityBundleEngine(tmp_path / "knowledge")
    with pytest.raises(CapabilityBundleError):
        engine.stage_bundle(source, name="bad", include_paths=["module.py"], test_paths=["tests/missing.py"])
    with pytest.raises(CapabilityBundleError):
        engine.stage_bundle(source, name="bad", include_paths=["module.py", "module.py"])


def test_source_mutation_during_copy_is_detected(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    file = source / "module.py"
    file.write_text("VALUE = 1\n", encoding="utf-8")
    engine = NativeCapabilityBundleEngine(tmp_path / "knowledge")
    original = Path.read_bytes
    changed = False

    def racing_read(path):
        nonlocal changed
        if path == file and not changed:
            changed = True
            value = original(path)
            file.write_text("VALUE = 2\n", encoding="utf-8")
            return value
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", racing_read)
    with pytest.raises(CapabilityBundleError):
        engine.stage_bundle(source, name="racing", include_paths=["module.py"])


def test_native_cognition_routes_capability_staging_and_reports_status(tmp_path):
    import asyncio
    from core.native_cognition import NativeCognitionEngine

    source = tmp_path / "external"
    source.mkdir()
    (source / "feature.py").write_text("def feature():\n    return 42\n", encoding="utf-8")
    engine = NativeCognitionEngine(tmp_path / "pika")
    result = asyncio.run(engine.execute(
        "stage capability bundle",
        context={
            "source_root": str(source),
            "bundle_name": "external-feature",
            "include_paths": ["feature.py"],
            "test_paths": [],
        },
    ))
    assert result["success"] is True
    assert result["raw"]["file_count"] == 1
    assert result["raw"]["live_source_modified"] is False
    status = engine.status()
    assert status["staged_capability_bundles"] == 1
    assert "hash_bound_multi_file_capability_intake" in status["native_capabilities"]
