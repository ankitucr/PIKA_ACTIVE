# Phase 40: Deep GitHub Learning

## Purpose

Phase 40 expands PIKA's GitHub learning path beyond Python-only structural extraction. Acquired repositories remain data: PIKA reads bounded source files, verifies each file against the Git acquisition manifest, and extracts conservative language-specific structure without importing, building, or executing downloaded code.

## Language coverage

Python continues to use the built-in AST analyzer. Non-Python files use bounded static recognizers for JavaScript, TypeScript, Dart, Go, Rust, Java, Kotlin, Swift, C#, C/C++, Ruby, PHP, SQL, HTML, and CSS.

The multi-language analyzer records:
- detected language and source SHA-256;
- declaration names and exact source-line evidence;
- import/include/use references;
- test-like paths and assertion-like call matches;
- bounded file/line/symbol/import metrics.

## Provenance

Every acquired file is checked against its registered SHA-256 before analysis. Each resulting knowledge observation carries repository, commit, path, source hash, license identifier, and `source_executed=false`. Stale or modified corpus files are rejected instead of being silently analyzed.

Cross-language observations are explicitly labelled `OBSERVED_NOT_YET_VERIFIED_FOR_REUSE`. Test-like paths and assertion-like matches are navigation evidence only; they do not prove tests pass or provide behavioral coverage.

## License boundary

The existing repository license classification remains in force. An unclassified license blocks code-reuse recommendations until separately classified and reviewed. Structural learning does not grant permission to copy third-party code.

## Safety boundary

- No LLM, local model, Ollama, or external inference API.
- No downloaded code execution, import, build, dependency installation, or test execution.
- No source modification, trusted-learning admission, or production promotion.
- Regex recognizers are not compiler-grade parsers and can produce false positives or miss syntax variants.

## Validation

`tests/test_native_multilang_analyzer.py` covers representative language declarations/imports, stale hash rejection, size bounds, and recognizer false-positive protection. `tests/test_native_knowledge_extractor.py` verifies that cross-language facts retain source provenance and unverified status.
