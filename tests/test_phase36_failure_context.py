from __future__ import annotations

from core.phase36.failure_context import FailureContextExtractor


def test_extracts_traceback_frame_and_test_context(tmp_path):
    (tmp_path / "core").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "core" / "service.py").write_text(
        "def outer():\n    return inner()\n\ndef inner():\n    value = 1\n    raise ValueError('bad')\n",
        encoding="utf-8",
    )
    (tmp_path / "tests" / "test_service.py").write_text(
        "from core.service import outer\n\ndef test_outer():\n    outer()\n",
        encoding="utf-8",
    )
    output = (
        'File "/tmp/pika_local_run_123/work/core/service.py", line 6, in inner\n'
        'File "/tmp/pika_local_run_123/work/tests/test_service.py", line 4, in test_outer\n'
        "FAILED tests/test_service.py::test_outer - ValueError\n"
    )
    result = FailureContextExtractor(tmp_path).collect(output, test_path="tests/test_service.py")
    assert result["schema"] == "pika.failure_context.v1"
    assert result["limits"]["source_executed"] is False
    assert result["limits"]["causal_claim"] is False
    assert any(x["path"] == "core/service.py" and x["line"] == 6 for x in result["snippets"])
    assert any(x["path"] == "tests/test_service.py" for x in result["snippets"])


def test_candidate_overlay_supports_changed_and_new_files(tmp_path):
    project, overlay = tmp_path / "project", tmp_path / "candidate"
    (project / "core").mkdir(parents=True)
    (overlay / "core").mkdir(parents=True)
    (project / "core" / "service.py").write_text("VALUE = 1\n", encoding="utf-8")
    (overlay / "core" / "service.py").write_text("VALUE = 2\n", encoding="utf-8")
    (overlay / "core" / "new_module.py").write_text("VALUE = 3\n", encoding="utf-8")
    extractor = FailureContextExtractor(project)
    changed = extractor.collect(
        'File "/tmp/run/work/core/service.py", line 1, in <module>\n',
        overlay_root=overlay, overlay_paths=["core/service.py"],
    )
    added = extractor.collect(
        'File "/tmp/run/work/core/new_module.py", line 1, in <module>\n',
        overlay_root=overlay, overlay_paths=["core/new_module.py"],
    )
    assert "VALUE = 2" in changed["snippets"][0]["content"]
    assert changed["snippets"][0]["source_view"] == "candidate_overlay"
    assert "VALUE = 3" in added["snippets"][0]["content"]


def test_rejects_traversal_private_and_external_paths(tmp_path):
    (tmp_path / "core").mkdir()
    (tmp_path / "core" / "safe.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "secret.py").write_text("TOKEN = 'should-not-read'\n", encoding="utf-8")
    output = (
        'File "/tmp/run/work/../../etc/passwd.py", line 1, in x\n'
        'File "/tmp/run/work/data/secret.py", line 1, in x\n'
        'File "/outside/core/evil.py", line 1, in x\n'
        'File "/tmp/run/work/core/safe.py", line 1, in x\n'
    )
    result = FailureContextExtractor(tmp_path).collect(output)
    assert [x["path"] for x in result["snippets"]] == ["core/safe.py"]


def test_redacts_secrets_from_source_context(tmp_path):
    (tmp_path / "core").mkdir()
    (tmp_path / "core" / "config.py").write_text(
        "API_KEY = 'abcdefghijklmnop-secret-value'\n"
        "AUTHORIZATION = 'Bearer abcdefghijklmnop'\n",
        encoding="utf-8",
    )
    result = FailureContextExtractor(tmp_path, radius=1).collect(
        'File "/tmp/run/work/core/config.py", line 1, in load\n'
    )
    content = result["snippets"][0]["content"]
    assert "abcdefghijklmnop-secret-value" not in content
    assert "Bearer abcdefghijklmnop" not in content
    assert "[REDACTED]" in content


def test_rejects_symlink_source_and_overlay(tmp_path):
    (tmp_path / "core").mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("VALUE = 1\n", encoding="utf-8")
    (tmp_path / "core" / "link.py").symlink_to(outside)
    result = FailureContextExtractor(tmp_path).collect(
        'File "/tmp/run/work/core/link.py", line 1, in x\n'
    )
    assert result["snippets"] == []
    assert result["omitted"][0]["reason"] == "symlink_rejected"

    project, overlay = tmp_path / "project", tmp_path / "candidate"
    (project / "core").mkdir(parents=True)
    (project / "core" / "link.py").write_text("BASE = True\n", encoding="utf-8")
    (overlay / "core").mkdir(parents=True)
    (overlay / "core" / "link.py").symlink_to(outside)
    result = FailureContextExtractor(project).collect(
        'File "/tmp/run/work/core/link.py", line 1, in x\n',
        overlay_root=overlay, overlay_paths=["core/link.py"],
    )
    assert result["snippets"] == []
    assert result["omitted"][0]["reason"] == "candidate_symlink_rejected"


def test_bounds_source_file_and_reports_missing_source(tmp_path):
    (tmp_path / "core").mkdir()
    (tmp_path / "core" / "large.py").write_text("X = 1\n" * 200000, encoding="utf-8")
    extractor = FailureContextExtractor(tmp_path)
    large = extractor.collect('File "/tmp/run/work/core/large.py", line 1, in x\n')
    assert large["snippets"] == []
    assert large["omitted"][0]["reason"] == "source_file_too_large"
    missing = extractor.collect('File "/tmp/run/work/core/missing.py", line 1, in x\n')
    assert missing["snippets"] == []
    assert missing["omitted"][0]["reason"] == "source_unavailable"


def test_total_context_budget_is_enforced(tmp_path):
    (tmp_path / "core").mkdir()
    for index in range(8):
        (tmp_path / "core" / f"module_{index}.py").write_text(
            "\n".join(f"VALUE_{line} = {line}" for line in range(80)),
            encoding="utf-8",
        )
    output = "".join(
        f'File "/tmp/run/work/core/module_{index}.py", line 40, in run\n'
        for index in range(8)
    )
    result = FailureContextExtractor(tmp_path, max_bytes=1024, radius=20).collect(output)
    total = sum(len(item["content"].encode("utf-8")) for item in result["snippets"])
    assert total <= 1024
    assert result["omitted"]


def test_invalid_limits_are_rejected(tmp_path):
    import pytest
    with pytest.raises(ValueError):
        FailureContextExtractor(tmp_path, max_files=0)
    with pytest.raises(ValueError):
        FailureContextExtractor(tmp_path, max_bytes=0)
    with pytest.raises(ValueError):
        FailureContextExtractor(tmp_path, radius=21)



def test_ast_context_identifies_enclosing_class_function_imports_and_calls(tmp_path):
    (tmp_path / "core").mkdir()
    (tmp_path / "core" / "calculator.py").write_text(
        "import math\n"
        "class Calculator:\n"
        "    def multiply(self, left, right):\n"
        "        result = math.prod([left, right])\n"
        "        return result\n",
        encoding="utf-8",
    )
    result = FailureContextExtractor(tmp_path).collect(
        'File "/tmp/run/work/core/calculator.py", line 4, in multiply\n'
    )
    context = result["snippets"][0]["ast_context"]
    assert context["parse_status"] == "parsed"
    assert context["enclosing_class"] == "Calculator"
    assert context["enclosing_function"] == "multiply"
    assert context["qualified_symbol"] == "Calculator.multiply"
    assert context["parameters"] == ["self", "left", "right"]
    assert "math" in context["imports"]
    assert "math.prod" in context["calls"]


def test_ast_context_reports_syntax_error_without_guessing(tmp_path):
    (tmp_path / "core").mkdir()
    (tmp_path / "core" / "broken.py").write_text(
        "def broken(:\n    return missing()\n",
        encoding="utf-8",
    )
    result = FailureContextExtractor(tmp_path).collect(
        'File "/tmp/run/work/core/broken.py", line 2, in broken\n'
    )
    context = result["snippets"][0]["ast_context"]
    assert context["parse_status"] == "syntax_error"
    assert context["parse_error"] == "invalid syntax"
    assert context["calls"] == []


def test_ast_context_does_not_claim_function_for_module_level_failure(tmp_path):
    (tmp_path / "core").mkdir()
    (tmp_path / "core" / "module.py").write_text(
        "import json\nVALUE = json.loads('{}')\n",
        encoding="utf-8",
    )
    result = FailureContextExtractor(tmp_path).collect(
        'File "/tmp/run/work/core/module.py", line 2, in <module>\n'
    )
    context = result["snippets"][0]["ast_context"]
    assert context["parse_status"] == "parsed"
    assert context["enclosing_function"] is None
    assert context["calls"] == ["json.loads"]
    assert context["call_scope"] == "local_module_region"
    assert "json" in context["imports"]


def test_ast_context_marks_missing_line_as_not_attempted(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_sample.py").write_text(
        "def test_sample():\n    assert True\n",
        encoding="utf-8",
    )
    result = FailureContextExtractor(tmp_path).collect(
        "FAILED tests/test_sample.py::test_sample - AssertionError\n"
    )
    context = result["snippets"][0]["ast_context"]
    assert context["parse_status"] == "not_attempted"
    assert context["reason"] == "no_traceback_line"
