"""Independent validation for native source-code proof-query results.

The validator checks that every returned edge, root premise and source
sidecar is bound to the underlying Phase 39 input facts and the acquired
source evidence. It never promotes or verifies the truth of source claims.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

ALLOWED_PREDICATES = {"depends_on", "is_a", "part_of", "requires"}
ALLOWED_STATUSES = {
    "DIRECT_SOURCE_RELATION",
    "DIRECT_AND_ALTERNATE_SOURCE_PATHS",
    "TRANSITIVE_SOURCE_PATH",
    "SOURCE_PATH_WITHOUT_ENGINE_CLOSURE",
    "UNRESOLVED_EXPLICIT_CONTRADICTION",
    "EXPLICIT_NEGATION_UNVERIFIED",
    "NOT_ESTABLISHED_BY_REGISTERED_SOURCE_GRAPH",
    "QUERY_RESOURCE_LIMIT",
    "QUERY_RESOURCE_LIMIT_WITH_PARTIAL_PATHS",
}


def _digest(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_native_code_proof_query(result: Any) -> bool:
    """Validate a complete proof-query result; malformed shapes fail closed."""
    try:
        if not isinstance(result, dict):
            return False
        query = result.get("proof_query")
        source_graph = result.get("source_graph")
        facts = result.get("facts")
        derived_facts = result.get("derived_facts")
        evidence = result.get("source_evidence")
        if not all(isinstance(value, dict) for value in (query, source_graph)):
            return False
        if not all(isinstance(value, list) for value in (facts, derived_facts, evidence)):
            return False
        if query.get("schema") != "pika.native_code_proof_query.v1":
            return False
        if query.get("trust") != "UNVERIFIED_PROOF_EXPLANATION":
            return False
        if not isinstance(query.get("query_id"), str) or query.get("status") not in ALLOWED_STATUSES:
            return False

        repository = source_graph.get("repository")
        commit = source_graph.get("commit")
        subject = query.get("subject")
        predicate = query.get("predicate")
        object_name = query.get("object")
        if not all(isinstance(value, str) and value for value in (repository, commit, subject, object_name)):
            return False
        if predicate not in ALLOWED_PREDICATES:
            return False
        if query.get("repository") != repository or query.get("commit") != commit:
            return False
        if query.get("reasoning_id") != result.get("reasoning_id"):
            return False
        if query.get("coverage_status") != source_graph.get("coverage_status"):
            return False
        if query.get("coverage_flags") != source_graph.get("coverage_flags"):
            return False

        input_by_id: dict[str, dict[str, Any]] = {}
        all_fact_ids: set[str] = set()
        for fact in facts:
            if not isinstance(fact, dict) or not isinstance(fact.get("id"), str):
                return False
            fact_id = fact["id"]
            if fact_id in all_fact_ids:
                return False
            all_fact_ids.add(fact_id)
            if fact.get("kind") == "OBSERVED_INPUT":
                if fact.get("trust") != "UNVERIFIED_INPUT":
                    return False
                if fact.get("polarity") not in {"positive", "negative"}:
                    return False
                if not isinstance(fact.get("provenance"), list):
                    return False
                input_by_id[fact_id] = fact

        derived_by_id: dict[str, dict[str, Any]] = {}
        for fact in derived_facts:
            if not isinstance(fact, dict) or not isinstance(fact.get("id"), str):
                return False
            if fact["id"] in derived_by_id:
                return False
            derived_by_id[fact["id"]] = fact
        evidence_by_id: dict[str, dict[str, Any]] = {}
        for item in evidence:
            if not isinstance(item, dict) or not isinstance(item.get("source_id"), str):
                return False
            source_id = item["source_id"]
            if source_id in evidence_by_id:
                return False
            if (
                item.get("repository") != repository
                or item.get("commit") != commit
                or item.get("trust") != "OBSERVED_NOT_YET_VERIFIED_FOR_REUSE"
                or item.get("source_executed") is not False
                or not isinstance(item.get("sha256"), str)
                or len(item.get("sha256", "")) != 64
                or not isinstance(item.get("path"), str)
                or not isinstance(item.get("line_start"), int)
                or not isinstance(item.get("line_end"), int)
            ):
                return False
            evidence_by_id[source_id] = item

        paths = query.get("paths")
        path_count = query.get("path_count")
        direct_fact_ids = query.get("direct_source_fact_ids")
        negative_evidence = query.get("negative_source_evidence")
        search = query.get("path_search")
        if (
            not isinstance(paths, list)
            or len(paths) > 8
            or path_count != len(paths)
            or not isinstance(direct_fact_ids, list)
            or not isinstance(negative_evidence, list)
            or not isinstance(search, dict)
        ):
            return False
        max_depth = search.get("max_depth")
        max_paths = search.get("max_paths")
        expansions = search.get("expansions")
        if (
            not isinstance(max_depth, int) or isinstance(max_depth, bool) or not 1 <= max_depth <= 12
            or not isinstance(max_paths, int) or isinstance(max_paths, bool) or not 1 <= max_paths <= 8
            or not isinstance(expansions, int) or isinstance(expansions, bool) or not 0 <= expansions <= 10_001
            or search.get("expansion_limit") != 10_000
            or not isinstance(search.get("resource_limited"), bool)
            or search["resource_limited"] != (expansions > 10_000)
            or len(paths) > max_paths
        ):
            return False

        expected_path_ids: list[str] = []
        root_sets: set[tuple[str, ...]] = set()
        for path in paths:
            if not isinstance(path, dict) or path.get("trust") != "UNVERIFIED_SOURCE_PATH":
                return False
            length = path.get("length")
            labels = path.get("node_labels")
            steps = path.get("steps")
            root_ids = path.get("root_premise_fact_ids")
            if (
                not isinstance(length, int) or isinstance(length, bool) or not 1 <= length <= max_depth
                or not isinstance(labels, list) or len(labels) != length + 1
                or not isinstance(steps, list) or len(steps) != length
                or labels[0] != subject or labels[-1] != object_name
                or not isinstance(root_ids, list) or len(root_ids) != length
                or len(set(root_ids)) != length
            ):
                return False
            step_ids: list[str] = []
            for index, step in enumerate(steps):
                if not isinstance(step, dict):
                    return False
                fact_id = step.get("fact_id")
                source_fact = input_by_id.get(fact_id)
                if source_fact is None:
                    return False
                if (
                    step.get("subject") != labels[index]
                    or step.get("object") != labels[index + 1]
                    or step.get("predicate") != predicate
                    or step.get("trust") != "UNVERIFIED_INPUT"
                    or source_fact.get("subject") != step.get("subject")
                    or source_fact.get("predicate") != step.get("predicate")
                    or source_fact.get("object") != step.get("object")
                    or source_fact.get("polarity") != "positive"
                ):
                    return False
                sources = step.get("source_ids")
                sidecars = step.get("source_evidence")
                if not isinstance(sources, list) or not isinstance(sidecars, list):
                    return False
                expected_sources = set(source_fact.get("provenance", []))
                if (
                    set(sources) != expected_sources
                    or len(sources) != len(expected_sources)
                    or {item.get("source_id") for item in sidecars if isinstance(item, dict)} != expected_sources
                    or len(sidecars) != len(expected_sources)
                    or any(
                        not isinstance(item, dict)
                        or item.get("source_id") not in evidence_by_id
                        or item != evidence_by_id[item["source_id"]]
                        for item in sidecars
                    )
                ):
                    return False
                step_ids.append(fact_id)
            if root_ids != step_ids:
                return False
            roots = tuple(sorted(root_ids))
            root_sets.add(roots)
            expected_path_id = _digest({
                "repository": repository,
                "predicate": predicate,
                "fact_ids": step_ids,
            })
            if path.get("path_id") != expected_path_id:
                return False
            expected_path_ids.append(expected_path_id)

        if len(set(expected_path_ids)) != len(expected_path_ids):
            return False
        negative_fact_ids: list[str] = []
        for item in negative_evidence:
            if not isinstance(item, dict) or item.get("trust") != "UNVERIFIED_INPUT_NEGATION":
                return False
            fact_id = item.get("fact_id")
            source_fact = input_by_id.get(fact_id)
            if source_fact is None:
                return False
            if (
                source_fact.get("polarity") != "negative"
                or source_fact.get("subject") != subject
                or source_fact.get("predicate") != predicate
                or source_fact.get("object") != object_name
                or item.get("subject") != subject
                or item.get("predicate") != predicate
                or item.get("object") != object_name
                or item.get("polarity") != "negative"
            ):
                return False
            sources = item.get("source_ids")
            sidecars = item.get("source_evidence")
            expected_sources = set(source_fact.get("provenance", []))
            if (
                not isinstance(sources, list)
                or set(sources) != expected_sources
                or not isinstance(sidecars, list)
                or {entry.get("source_id") for entry in sidecars if isinstance(entry, dict)} != expected_sources
                or any(
                    not isinstance(entry, dict)
                    or entry.get("source_id") not in evidence_by_id
                    or entry != evidence_by_id[entry["source_id"]]
                    for entry in sidecars
                )
            ):
                return False
            negative_fact_ids.append(fact_id)

        if not isinstance(direct_fact_ids, list) or len(set(direct_fact_ids)) != len(direct_fact_ids):
            return False
        for fact_id in direct_fact_ids:
            fact = input_by_id.get(fact_id)
            if not fact or (
                fact.get("subject") != subject
                or fact.get("predicate") != predicate
                or fact.get("object") != object_name
                or fact.get("polarity") != "positive"
            ):
                return False

        derived_report = query.get("derived_hypothesis")
        if derived_report is not None:
            if not isinstance(derived_report, dict):
                return False
            derived = derived_by_id.get(derived_report.get("fact_id"))
            if derived is None or (
                derived.get("kind") != "DERIVED_HYPOTHESIS"
                or derived.get("trust") != "UNVERIFIED_DERIVATION"
                or derived.get("subject") != subject
                or derived.get("predicate") != predicate
                or derived.get("object") != object_name
                or derived.get("polarity") != "positive"
            ):
                return False
            supports = derived.get("derivation_supports")
            if not isinstance(supports, list) or not 1 <= len(supports) <= 8:
                return False
            matching = [
                support for support in supports
                if isinstance(support, dict)
                and tuple(sorted(support.get("root_premise_fact_ids", []))) in root_sets
            ]
            if (
                derived_report.get("trust") != "UNVERIFIED_DERIVATION"
                or derived_report.get("derivation_supports") != supports[:8]
                or derived_report.get("matching_path_support_count") != len(matching)
            ):
                return False

        payload = {
            "schema": query["schema"],
            "repository": repository,
            "commit": commit,
            "subject": subject,
            "predicate": predicate,
            "object": object_name,
            "status": query.get("status"),
            "path_ids": expected_path_ids,
            "negative_fact_ids": negative_fact_ids,
            "reasoning_id": result.get("reasoning_id"),
        }
        if query.get("query_id") != _digest(payload):
            return False

        return all(
            result.get(field) is False
            for field in (
                "source_executed",
                "source_modified",
                "source_persisted",
                "memory_updated",
                "knowledge_admitted",
                "promotion_allowed",
            )
        ) and result.get("memory_admission") == "BLOCKED_UNVERIFIED_HYPOTHESES"
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


def validate_native_code_impact_analysis(result: Any) -> bool:
    """Validate every nested impact proof against the original source facts."""
    try:
        if not isinstance(result, dict):
            return False
        analysis = result.get("impact_analysis")
        source_graph = result.get("source_graph")
        if not isinstance(analysis, dict) or not isinstance(source_graph, dict):
            return False
        if (
            analysis.get("schema") != "pika.native_code_impact_analysis.v1"
            or analysis.get("trust") != "UNVERIFIED_IMPACT_ANALYSIS"
            or analysis.get("repository") != source_graph.get("repository")
            or analysis.get("commit") != source_graph.get("commit")
            or analysis.get("reasoning_id") != result.get("reasoning_id")
            or analysis.get("coverage_status") != source_graph.get("coverage_status")
            or analysis.get("coverage_flags") != source_graph.get("coverage_flags")
            or analysis.get("predicate") not in {"depends_on", "is_a"}
            or not isinstance(analysis.get("target"), str)
            or not analysis.get("target")
        ):
            return False
        impacts = analysis.get("impacts")
        search = analysis.get("search")
        if not isinstance(impacts, list) or not isinstance(search, dict):
            return False
        max_results = search.get("max_results")
        max_paths = search.get("max_paths_per_impact")
        max_depth = search.get("max_depth")
        expansions = search.get("expansions")
        if (
            not isinstance(max_results, int) or isinstance(max_results, bool) or not 1 <= max_results <= 50
            or not isinstance(max_paths, int) or isinstance(max_paths, bool) or not 1 <= max_paths <= 3
            or not isinstance(max_depth, int) or isinstance(max_depth, bool) or not 1 <= max_depth <= 12
            or not isinstance(expansions, int) or isinstance(expansions, bool) or not 0 <= expansions <= 10_001
            or search.get("expansion_limit") != 10_000
            or search.get("resource_limited") != (expansions > 10_000)
            or not isinstance(search.get("results_truncated"), bool)
            or len(impacts) > max_results
            or analysis.get("impact_count") != len(impacts)
        ):
            return False
        total_count = analysis.get("total_impact_count")
        if (
            not isinstance(total_count, int)
            or isinstance(total_count, bool)
            or total_count < len(impacts)
            or search.get("results_truncated") != (total_count > len(impacts))
        ):
            return False
        status = analysis.get("status")
        if status not in {
            "IMPACT_PATHS_FOUND",
            "PARTIAL_IMPACT_ANALYSIS",
            "NO_RECORDED_IMPACT",
            "NO_RECORDED_IMPACT_WITH_PARTIAL_COVERAGE",
        }:
            return False
        partial = (
            analysis.get("coverage_status") != "COMPLETE_REGISTERED_SOURCE_SET"
            or search.get("resource_limited") is True
            or search.get("results_truncated") is True
        )
        if impacts:
            expected_status = "PARTIAL_IMPACT_ANALYSIS" if partial else "IMPACT_PATHS_FOUND"
        else:
            expected_status = (
                "NO_RECORDED_IMPACT_WITH_PARTIAL_COVERAGE"
                if partial else "NO_RECORDED_IMPACT"
            )
        if status != expected_status:
            return False

        seen_entities: set[str] = set()
        expected_impact_ids: list[str] = []
        previous_rank: tuple[int, str] | None = None
        for impact in impacts:
            if not isinstance(impact, dict):
                return False
            entity = impact.get("entity")
            proof = impact.get("proof_query")
            if not isinstance(entity, str) or not entity or entity in seen_entities:
                return False
            seen_entities.add(entity)
            if not isinstance(proof, dict):
                return False
            if (
                proof.get("subject") != entity
                or proof.get("object") != analysis.get("target")
                or proof.get("predicate") != analysis.get("predicate")
            ):
                return False
            synthetic = dict(result)
            synthetic["proof_query"] = proof
            if not validate_native_code_proof_query(synthetic):
                return False
            paths = proof.get("paths", [])
            if not paths:
                return False
            shortest = min(path.get("length", 0) for path in paths)
            expected_type = (
                "DIRECT_CONSUMER"
                if any(path.get("length") == 1 for path in paths)
                else "TRANSITIVE_CONSUMER"
            )
            if (
                impact.get("path_count") != len(paths)
                or impact.get("shortest_path_length") != shortest
                or impact.get("impact_type") != expected_type
                or any(path.get("length", 0) > max_depth for path in paths)
            ):
                return False
            rank = (shortest, entity)
            if previous_rank is not None and rank < previous_rank:
                return False
            previous_rank = rank
            expected_impact_ids.append(_digest({
                "repository": analysis["repository"],
                "target": analysis["target"],
                "predicate": analysis["predicate"],
                "entity": entity,
                "path_ids": proof.get("path_ids", []),
            }))
        if analysis.get("impact_ids") != expected_impact_ids:
            return False
        expected_analysis_payload = {
            "schema": analysis["schema"],
            "repository": analysis["repository"],
            "commit": analysis["commit"],
            "target": analysis["target"],
            "predicate": analysis["predicate"],
            "status": analysis["status"],
            "impact_ids": expected_impact_ids,
            "reasoning_id": analysis["reasoning_id"],
        }
        if analysis.get("analysis_id") != _digest(expected_analysis_payload):
            return False
        if not isinstance(analysis.get("claim_scope"), str) or not analysis.get("claim_scope"):
            return False
        return all(
            result.get(field) is False
            for field in (
                "source_executed",
                "source_modified",
                "source_persisted",
                "memory_updated",
                "knowledge_admitted",
                "promotion_allowed",
            )
        ) and result.get("memory_admission") == "BLOCKED_UNVERIFIED_HYPOTHESES"
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


def validate_native_test_selection(result: Any) -> bool:
    """Validate statically discovered test cases against impacted modules and file evidence."""
    try:
        if not validate_native_code_impact_analysis(result):
            return False
        selection = result.get("test_selection")
        impact = result.get("impact_analysis")
        source_evidence = result.get("source_evidence")
        if not isinstance(selection, dict) or not isinstance(impact, dict) or not isinstance(source_evidence, list):
            return False
        if (
            selection.get("schema") != "pika.native_test_selection.v1"
            or selection.get("trust") != "UNVERIFIED_STATIC_TEST_SELECTION"
            or selection.get("repository") != impact.get("repository")
            or selection.get("commit") != impact.get("commit")
            or selection.get("target") != impact.get("target")
            or selection.get("predicate") != impact.get("predicate")
            or selection.get("impact_analysis_status") != impact.get("status")
            or selection.get("execution_performed") is not False
            or result.get("test_execution_performed") is not False
            or result.get("memory_admission") != "BLOCKED_UNVERIFIED_HYPOTHESES"
        ):
            return False

        modules = selection.get("modules")
        errors = selection.get("errors")
        flags = selection.get("coverage_flags")
        limits = selection.get("limits")
        if (
            not isinstance(modules, list)
            or len(modules) > 50
            or not isinstance(errors, list)
            or not all(isinstance(error, str) for error in errors)
            or not isinstance(flags, list)
            or not isinstance(limits, dict)
            or limits.get("max_test_modules") != 50
            or limits.get("max_test_cases") != 500
            or limits.get("max_file_bytes") != 200_000
            or limits.get("max_ast_nodes_per_file") != 20_000
        ):
            return False

        impact_by_entity = {
            item.get("entity"): item
            for item in impact.get("impacts", [])
            if isinstance(item, dict) and isinstance(item.get("entity"), str)
        }
        evidence_by_id = {
            item.get("source_id"): item
            for item in source_evidence
            if isinstance(item, dict) and isinstance(item.get("source_id"), str)
        }
        seen_modules: set[str] = set()
        seen_paths: set[str] = set()
        expected_module_ids: list[str] = []
        expected_test_ids: list[str] = []
        total_cases = 0
        previous_path = ""
        for module in modules:
            if not isinstance(module, dict):
                return False
            entity = module.get("module_entity")
            path = module.get("path")
            file_sha = module.get("sha256")
            proof = module.get("proof_query")
            if (
                not isinstance(entity, str)
                or entity in seen_modules
                or entity not in impact_by_entity
                or not isinstance(path, str)
                or not (
                    (path.rsplit("/", 1)[-1].lower().startswith("test_")
                     and path.rsplit("/", 1)[-1].lower().endswith(".py"))
                    or path.rsplit("/", 1)[-1].lower().endswith("_test.py")
                )
                or path in seen_paths
                or path < previous_path
                or not isinstance(file_sha, str)
                or len(file_sha) != 64
                or not isinstance(proof, dict)
                or proof != impact_by_entity[entity].get("proof_query")
                or module.get("trust") != "UNVERIFIED_STATIC_TEST_CANDIDATE"
                or not isinstance(module.get("source_encoding"), str)
                or not isinstance(module.get("ast_node_count"), int)
                or not 0 <= module.get("ast_node_count", -1) <= 20_000
            ):
                return False
            seen_modules.add(entity)
            seen_paths.add(path)
            previous_path = path
            expected_module_ids.append(entity)

            import_evidence = module.get("import_evidence")
            if not isinstance(import_evidence, list) or not import_evidence:
                return False
            proof_first_steps = [
                path_item.get("steps", [{}])[0]
                for path_item in proof.get("paths", [])
                if isinstance(path_item, dict) and path_item.get("steps")
            ]
            allowed_import_ids = {
                source_id
                for step in proof_first_steps
                for source_id in step.get("source_ids", [])
            }
            if (
                any(
                    not isinstance(item, dict)
                    or item.get("source_id") not in evidence_by_id
                    or item != evidence_by_id[item["source_id"]]
                    or item.get("path") != path
                    or item.get("sha256") != file_sha
                    or item.get("source_id") not in allowed_import_ids
                    for item in import_evidence
                )
            ):
                return False

            cases = module.get("test_cases")
            case_count = module.get("test_case_count")
            if not isinstance(cases, list) or case_count != len(cases):
                return False
            previous_line = 0
            for case in cases:
                if not isinstance(case, dict):
                    return False
                name = case.get("name")
                line_start = case.get("line_start")
                line_end = case.get("line_end")
                node_type = case.get("ast_node_type")
                evidence = case.get("source_evidence")
                if (
                    not isinstance(name, str)
                    or not (
                        name.startswith("test_")
                        or (".test_" in name and name.split(".", 1)[0].startswith("Test"))
                    )
                    or not isinstance(line_start, int)
                    or isinstance(line_start, bool)
                    or not isinstance(line_end, int)
                    or isinstance(line_end, bool)
                    or line_start < 1
                    or line_end < line_start
                    or line_start < previous_line
                    or node_type not in {"FunctionDef", "AsyncFunctionDef"}
                    or case.get("status") != "DISCOVERED_NOT_EXECUTED"
                    or not isinstance(evidence, dict)
                ):
                    return False
                previous_line = line_start
                source_identity = "\0".join((
                    selection["repository"], selection["commit"], path, file_sha,
                    name, str(line_start), str(line_end), node_type,
                ))
                expected_source_id = "github-test-source:" + hashlib.sha256(
                    source_identity.encode("utf-8")
                ).hexdigest()
                expected_test_id = "pytest-case:" + _digest({
                    "repository": selection["repository"],
                    "commit": selection["commit"],
                    "path": path,
                    "sha256": file_sha,
                    "qualified_name": name,
                    "line_start": line_start,
                    "line_end": line_end,
                    "ast_node_type": node_type,
                })
                if (
                    case.get("test_id") != expected_test_id
                    or evidence.get("source_id") != expected_source_id
                    or evidence.get("repository") != selection["repository"]
                    or evidence.get("commit") != selection["commit"]
                    or evidence.get("path") != path
                    or evidence.get("sha256") != file_sha
                    or evidence.get("line_start") != line_start
                    or evidence.get("line_end") != line_end
                    or evidence.get("ast_node_type") != node_type
                    or evidence.get("source_encoding") != module.get("source_encoding")
                    or evidence.get("observation") != "pytest_style_test_function_definition"
                    or evidence.get("source_executed") is not False
                    or evidence.get("trust") != "OBSERVED_NOT_YET_VERIFIED_FOR_REUSE"
                ):
                    return False
                expected_test_ids.append(expected_test_id)
            total_cases += len(cases)

        if (
            selection.get("test_module_count") != len(modules)
            or selection.get("test_case_count") != total_cases
            or total_cases > 500
            or selection.get("module_ids") != expected_module_ids
            or selection.get("test_ids") != expected_test_ids
        ):
            return False

        partial = (
            impact.get("status") == "PARTIAL_IMPACT_ANALYSIS"
            or bool(errors)
        )
        if total_cases:
            expected_status = "PARTIAL_TEST_CANDIDATES" if partial else "TEST_CANDIDATES_FOUND"
        elif partial:
            expected_status = "NO_TEST_CANDIDATES_WITH_PARTIAL_COVERAGE"
        else:
            expected_status = "NO_TEST_CANDIDATES_FOUND"
        if selection.get("status") != expected_status:
            return False
        expected_flags = list(impact.get("coverage_flags", []))
        if errors:
            expected_flags.append("TEST_SOURCE_OR_SELECTION_LIMITS")
        if flags != expected_flags:
            return False

        payload = {
            "schema": selection["schema"],
            "repository": selection["repository"],
            "commit": selection["commit"],
            "target": selection["target"],
            "predicate": selection["predicate"],
            "status": selection["status"],
            "module_ids": expected_module_ids,
            "test_ids": expected_test_ids,
            "impact_analysis_id": impact.get("analysis_id"),
        }
        if selection.get("selection_id") != _digest(payload):
            return False
        return all(
            result.get(field) is False
            for field in (
                "source_executed",
                "source_modified",
                "source_persisted",
                "test_execution_performed",
                "memory_updated",
                "knowledge_admitted",
                "promotion_allowed",
            )
        )
    except (KeyError, TypeError, ValueError, AttributeError):
        return False

