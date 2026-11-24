"""Bounded multi-language structural source analysis for PIKA.

This module uses conservative regular-expression recognizers over source text.
It does not claim a compiler-grade parse, resolve dependencies, or execute code.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import PurePosixPath
from typing import Any

MAX_BYTES = 300_000
MAX_SYMBOLS = 500
MAX_IMPORTS = 300
MAX_LINES = 20_000

LANGUAGE_BY_SUFFIX = {
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".dart": "dart", ".go": "go", ".rs": "rust",
    ".java": "java", ".kt": "kotlin", ".kts": "kotlin",
    ".swift": "swift", ".cs": "csharp", ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp",
    ".h": "c", ".hpp": "cpp", ".rb": "ruby", ".php": "php",
    ".sql": "sql", ".html": "html", ".htm": "html", ".css": "css",
}


def _unique(values: list[str], limit: int) -> list[str]:
    seen: set[str] = set()
    result = []
    for value in values:
        value = value.strip()[:500]
        if value and value not in seen:
            seen.add(value)
            result.append(value)
            if len(result) >= limit:
                break
    return result


def _patterns(language: str) -> tuple[list[re.Pattern[str]], list[re.Pattern[str]]]:
    declaration: list[str] = []
    imports: list[str] = []
    if language in {"javascript", "typescript"}:
        declaration = [
            r"\b(?:export\s+)?(?:default\s+)?class\s+([A-Za-z_$][\w$]*)",
            r"\b(?:export\s+)?interface\s+([A-Za-z_$][\w$]*)",
            r"\b(?:export\s+)?type\s+([A-Za-z_$][\w$]*)\s*=",
            r"\b(?:export\s+)?enum\s+([A-Za-z_$][\w$]*)",
            r"\b(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(",
            r"\b(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(",
        ]
        imports = [r"\bimport\s+(?:[^;]*?\s+from\s+)?[\"']([^\"']+)[\"']", r"\brequire\(\s*[\"']([^\"']+)[\"']\s*\)"]
    elif language == "dart":
        declaration = [r"\b(?:abstract\s+)?class\s+(\w+)", r"\bmixin\s+(\w+)", r"\benum\s+(\w+)", r"\bextension\s+(\w+)"]
        imports = [r"\b(?:import|export|part)\s+[\"']([^\"']+)[\"']"]
    elif language == "go":
        declaration = [r"\bfunc\s+(?:\([^)]*\)\s*)?(\w+)\s*\(", r"\btype\s+(\w+)\s+(?:struct|interface)\b"]
        imports = [r"\bimport\s+(?:\w+\s+)?[\"']([^\"']+)[\"']"]
    elif language == "rust":
        declaration = [r"\b(?:pub\s+)?(?:async\s+)?fn\s+(\w+)\s*\(", r"\b(?:pub\s+)?(?:struct|enum|trait|union|mod)\s+(\w+)"]
        imports = [r"\buse\s+([^;]+);"]
    elif language in {"java", "kotlin", "csharp", "swift"}:
        declaration = [
            r"\b(?:(?:public|private|protected|internal|open|final|abstract|sealed|static|partial|data|record|actor)\s+)*(?:class|interface|enum|record|struct|protocol|object|trait|extension|annotation)\s+([A-Za-z_]\w*)",
            r"\b(?:fun|func)\s+([A-Za-z_]\w*)\s*\(",
        ]
        imports = [r"^\s*import\s+(?:static\s+)?([A-Za-z_][\w.*]+)", r"^\s*using\s+([A-Za-z_][\w.]+)\s*;"]
    elif language == "ruby":
        declaration = [r"^\s*class\s+([A-Z]\w*)", r"^\s*module\s+([A-Z]\w*)", r"^\s*def\s+(\w+[!?=]?)"]
        imports = [r"^\s*require(?:_relative)?\s+[\"']([^\"']+)[\"']"]
    elif language == "php":
        declaration = [r"\b(?:class|interface|trait|enum)\s+(\w+)", r"\bfunction\s+([A-Za-z_]\w*)\s*\("]
        imports = [r"\buse\s+([A-Za-z_\\][\w\\]*)\s*;"]
    elif language in {"cpp", "c"}:
        declaration = [r"\b(?:class|struct|enum)\s+(\w+)", r"\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:const\s*)?\{"]
        imports = [r"^\s*#\s*include\s*[<\"]([^>\"]+)[>\"]"]
    elif language == "sql":
        declaration = [r"\b(?:create\s+(?:or\s+replace\s+)?(?:table|view|index|function|procedure|trigger))\s+([A-Za-z_][\w.]*)"]
    elif language == "html":
        declaration = [r"\bid\s*=\s*[\"']([^\"']+)[\"']"]
    elif language == "css":
        declaration = [r"(?:^|})\s*([.#][A-Za-z_][\w-]*)\s*\{"]
    return [re.compile(x, re.I | re.M) for x in declaration], [re.compile(x, re.I | re.M) for x in imports]


def analyze_source(source: str, relative_path: str, *, repository: str = "", commit: str = "", expected_sha256: str | None = None) -> dict[str, Any]:
    if not isinstance(source, str) or not source:
        raise ValueError("source must be non-empty text")
    raw = source.encode("utf-8", errors="replace")
    if len(raw) > MAX_BYTES:
        raise ValueError("source exceeds the multi-language analysis size limit")
    lines = source.splitlines()
    if len(lines) > MAX_LINES:
        raise ValueError("source exceeds the multi-language line limit")
    digest = hashlib.sha256(raw).hexdigest()
    if expected_sha256 and digest != expected_sha256:
        raise ValueError("source SHA-256 does not match acquisition manifest")
    suffix = PurePosixPath(relative_path).suffix.lower()
    language = LANGUAGE_BY_SUFFIX.get(suffix)
    if not language:
        return {
            "path": relative_path, "repository": repository, "commit": commit,
            "language": suffix.lstrip(".") or "unknown", "parse_status": "unsupported_language",
            "sha256": digest, "bytes": len(raw), "source_executed": False,
            "symbols": [], "imports": [], "metrics": {},
        }
    declarations, import_patterns = _patterns(language)
    symbols: list[dict[str, Any]] = []
    for pattern in declarations:
        for match in pattern.finditer(source):
            name = match.group(1) if match.lastindex else match.group(0)
            line = source.count("\n", 0, match.start()) + 1
            symbols.append({"name": name, "kind": "declaration", "line": line, "evidence": match.group(0)[:300]})
            if len(symbols) >= MAX_SYMBOLS:
                break
        if len(symbols) >= MAX_SYMBOLS:
            break
    imports = []
    for pattern in import_patterns:
        imports.extend(match.group(1) for match in pattern.finditer(source))
    test_file = bool(re.search(r"(^|/)(tests?|spec|specs|testing)(/|$)|(^|/)(test|spec)[^/]*\.[^.]+$|_test\.[^.]+$", relative_path, re.I))
    assertion_patterns = {
        "javascript": r"\b(?:expect|assert|it|test)\s*\(",
        "typescript": r"\b(?:expect|assert|it|test)\s*\(",
        "dart": r"\b(?:expect|test|group)\s*\(",
        "go": r"\bt\.(?:Error|Fatal|Errorf|Fatalf)\s*\(",
        "rust": r"\bassert!?\s*!?\s*\(",
        "java": r"\bassert(?:Equals|True|False|Throws|NotNull)?\s*\(",
        "kotlin": r"\bassert(?:Equals|True|False|Fails)?\s*\(",
        "csharp": r"\bAssert\.(?:That|Equal|True|False|Throws)\s*\(",
        "swift": r"\bXCTAssert\w*\s*\(",
        "ruby": r"\b(?:assert|expect)\s*\(",
        "php": r"\bassert\s*\(",
        "cpp": r"\b(?:assert|EXPECT_[A-Z]+|ASSERT_[A-Z]+)\s*\(",
        "c": r"\bassert\s*\(",
    }
    assertion_count = len(re.findall(assertion_patterns.get(language, r"(?!)"), source))
    return {
        "path": relative_path, "repository": repository, "commit": commit,
        "language": language, "parse_status": "structural_scan_complete",
        "sha256": digest, "bytes": len(raw), "source_executed": False,
        "symbols": _unique([item["name"] for item in symbols], MAX_SYMBOLS),
        "symbol_evidence": symbols,
        "imports": _unique(imports, MAX_IMPORTS),
        "test_file": test_file,
        "metrics": {
            "lines": len(lines),
            "declarations": len(symbols),
            "imports": len(imports),
            "assertion_like_calls": assertion_count,
            "test_file": test_file,
        },
        "limits": [
            "Conservative text recognizers only; not a compiler-grade parser.",
            "Declaration and import matches may include false positives or miss syntax variants.",
            "No dependency resolution, type checking, build, tests, import, or execution was performed.",
        ],
    }
