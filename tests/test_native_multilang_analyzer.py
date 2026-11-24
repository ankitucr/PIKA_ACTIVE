from __future__ import annotations

import hashlib

import pytest

from core.native_multilang_analyzer import analyze_source


@pytest.mark.parametrize(
    ("path", "language", "expected_symbol", "expected_import"),
    [
        ("src/app.ts", "typescript", "ChatService", "socket.io"),
        ("lib/main.dart", "dart", "ChatRepository", "package:flutter/material.dart"),
        ("src/server.go", "go", "StartServer", "net/http"),
        ("src/lib.rs", "rust", "MessageStore", "std::collections::HashMap"),
        ("src/App.java", "java", "MessageController", "java.util.List"),
        ("src/app.kt", "kotlin", "ChatViewModel", "kotlinx.coroutines.launch"),
        ("src/style.css", "css", ".chat-panel", None),
    ],
)
def test_extracts_conservative_multilanguage_structure(path, language, expected_symbol, expected_import):
    samples = {
        "typescript": 'import { Server } from "socket.io";\nexport class ChatService {}\n',
        "dart": "import 'package:flutter/material.dart';\nclass ChatRepository {}\n",
        "go": 'package server\nimport "net/http"\nfunc StartServer() {}\n',
        "rust": "use std::collections::HashMap;\npub struct MessageStore {}\n",
        "java": "import java.util.List;\npublic class MessageController {}\n",
        "kotlin": "import kotlinx.coroutines.launch\nclass ChatViewModel {}\n",
        "css": ".chat-panel { display: flex; }\n",
    }
    source = samples[language]
    result = analyze_source(source, path, repository="sample/app", commit="abc123")
    assert result["language"] == language
    assert result["parse_status"] == "structural_scan_complete"
    assert expected_symbol in result["symbols"]
    if expected_import:
        assert expected_import in result["imports"]
    assert result["source_executed"] is False
    assert result["sha256"] == hashlib.sha256(source.encode()).hexdigest()


def test_rejects_stale_source_manifest_hash():
    with pytest.raises(ValueError, match="SHA-256"):
        analyze_source("class Current {}", "src/current.ts", expected_sha256="0" * 64)


def test_rejects_oversized_source():
    with pytest.raises(ValueError, match="size limit"):
        analyze_source("x" * 300_001, "src/large.js")


def test_java_modifiers_do_not_become_fake_type_names():
    result = analyze_source(
        "public class RealService {}\npublic static void execute() {}\n",
        "src/RealService.java",
    )
    assert "RealService" in result["symbols"]
    assert "void" not in result["symbols"]
