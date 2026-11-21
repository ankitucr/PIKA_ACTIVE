from __future__ import annotations

import argparse
import json
from pathlib import Path

from .controller import EvolutionController
from core.phase36.result_attestation import load_result_attestation_trust_policy


def main() -> int:
    parser = argparse.ArgumentParser(description="PIKA Integrated Evolution Core")
    parser.add_argument(
        "command",
        choices=(
            "cycle",
            "status",
            "observe",
            "verify-ledger",
            "remember",
            "candidate-stage",
            "candidate-evaluate",
            "discover-candidates",
            "review-discoveries",
            "candidate-stage-native",
            "record-experiment-memory",
            "verify-experiment-memory",
            "verify-attested-learning",
            "prepare-learning-approval",
            "admit-learning",
            "promotion-plan",
            "promote-candidate",
            "rollback-candidate",
        ),
    )
    parser.add_argument("--root", default=".")
    parser.add_argument("--category", default="observation")
    parser.add_argument("--message", default="")
    parser.add_argument("--target")
    parser.add_argument("--candidate-file")
    parser.add_argument("--candidate-id")
    parser.add_argument("--discovery-id")
    parser.add_argument("--proposal-file")
    parser.add_argument("--report-file")
    parser.add_argument("--attestor-config")
    parser.add_argument("--operator-approval-file")
    parser.add_argument("--operator-trust-config")
    parser.add_argument("--plan-file")
    parser.add_argument("--rollback-root")
    parser.add_argument("--attestor-url")
    parser.add_argument("--attestor-token-file")
    parser.add_argument("--attestor-backend-id")
    parser.add_argument("--replay-journal")
    parser.add_argument("--baseline-root")
    parser.add_argument("--test-path", action="append", default=[])
    parser.add_argument("--expected-base-sha256")
    parser.add_argument("--rationale", default="")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--python")
    args = parser.parse_args()
    evolution = EvolutionController(args.root)

    if args.command == "cycle":
        result = evolution.cycle()
    elif args.command == "status":
        result = evolution.status()
    elif args.command == "observe":
        inventory, resources = evolution.observe()
        result = {
            "success": True,
            "inventory": {
                "python_files": inventory["python_file_count"],
                "files": inventory["file_count"],
                "scan_errors": len(inventory["scan_errors"]),
            },
            "resources": resources,
        }
    elif args.command == "verify-ledger":
        result = evolution.ledger.verify()
    elif args.command == "remember":
        result = evolution.memory.add(args.category, {"message": args.message})
        evolution.ledger.append("experience_recorded", {"category": args.category})
    elif args.command == "discover-candidates":
        result = evolution.refresh_candidate_discovery()
    elif args.command == "review-discoveries":
        result = evolution.review_candidate_discoveries()
    elif args.command == "record-experiment-memory":
        if not args.report_file:
            parser.error("record-experiment-memory requires --report-file")
        result = evolution.record_experiment_memory(args.report_file)
    elif args.command == "verify-experiment-memory":
        result = evolution.verify_experiment_memory()
    elif args.command == "verify-attested-learning":
        if not args.report_file or not args.attestor_config:
            parser.error("verify-attested-learning requires --report-file and --attestor-config")
        report_path = Path(args.report_file).expanduser()
        if report_path.is_symlink() or not report_path.is_file():
            parser.error("report file must be a regular non-symlink file")
        if report_path.stat().st_size > 20_000_000:
            parser.error("attested report exceeds the 20 MB limit")
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            parser.error(f"invalid attested report: {type(exc).__name__}")
        trust_policy = load_result_attestation_trust_policy(
            args.attestor_config, project_root=args.root
        )
        result = evolution.verify_attested_learning_report(
            report, trust_policy=trust_policy
        )
    elif args.command == "prepare-learning-approval":
        if not args.report_file or not args.attestor_config:
            parser.error("prepare-learning-approval requires --report-file and --attestor-config")
        result = evolution.prepare_learning_approval(
            args.report_file, result_attestor_config=args.attestor_config
        )
    elif args.command == "admit-learning":
        if not all((args.report_file, args.attestor_config, args.operator_approval_file, args.operator_trust_config)):
            parser.error("admit-learning requires --report-file, --attestor-config, --operator-approval-file and --operator-trust-config")
        result = evolution.admit_attested_learning(
            args.report_file,
            result_attestor_config=args.attestor_config,
            operator_approval_file=args.operator_approval_file,
            operator_trust_config=args.operator_trust_config,
        )
    elif args.command == "promotion-plan":
        if not all((args.candidate_id, args.report_file, args.attestor_config, args.rollback_root)):
            parser.error("promotion-plan requires --candidate-id, --report-file, --attestor-config and --rollback-root")
        result = evolution.prepare_production_promotion(
            args.candidate_id,
            report_path=args.report_file,
            result_attestor_config=args.attestor_config,
            rollback_root=args.rollback_root,
        )
    elif args.command == "promote-candidate":
        required = (
            args.plan_file, args.operator_approval_file, args.operator_trust_config,
            args.attestor_config, args.attestor_url, args.attestor_token_file,
            args.attestor_backend_id, args.replay_journal, args.rollback_root,
        )
        if not all(required):
            parser.error("promote-candidate requires --plan-file, operator approval/config, attestor config/url/token/backend, replay journal and rollback root")
        result = evolution.promote_candidate(
            plan_file=args.plan_file,
            approval_file=args.operator_approval_file,
            approval_trust_config=args.operator_trust_config,
            result_attestor_config=args.attestor_config,
            attestor_url=args.attestor_url,
            attestor_token_file=args.attestor_token_file,
            attestor_backend_id=args.attestor_backend_id,
            replay_journal=args.replay_journal,
            rollback_root=args.rollback_root,
        )
    elif args.command == "rollback-candidate":
        if not args.plan_file or not args.rollback_root:
            parser.error("rollback-candidate requires --plan-file and --rollback-root")
        result = evolution.rollback_candidate(
            plan_file=args.plan_file, rollback_root=args.rollback_root
        )
    elif args.command == "candidate-stage-native":
        if not args.discovery_id or not args.proposal_file:
            parser.error(
                "candidate-stage-native requires --discovery-id and --proposal-file"
            )
        proposal_path = Path(args.proposal_file).expanduser()
        if proposal_path.is_symlink() or not proposal_path.is_file():
            parser.error("proposal file must be a regular non-symlink file")
        if proposal_path.stat().st_size > 1_500_000:
            parser.error("proposal file exceeds the 1.5 MB limit")
        try:
            proposal = json.loads(proposal_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            parser.error(f"invalid proposal JSON: {type(exc).__name__}")
        result = evolution.stage_native_proposal(
            args.discovery_id,
            proposal,
            test_paths=args.test_path or None,
        )
    elif args.command == "candidate-stage":
        if not args.target or not args.candidate_file or not args.test_path:
            parser.error(
                "candidate-stage requires --target, --candidate-file, "
                "and at least one --test-path"
            )
        result = evolution.stage_candidate(
            args.target,
            args.candidate_file,
            test_paths=args.test_path,
            expected_base_sha256=args.expected_base_sha256,
            rationale=args.rationale,
            baseline_root=args.baseline_root,
        )
    else:
        if not args.candidate_id:
            parser.error("candidate-evaluate requires --candidate-id")
        result = evolution.evaluate_candidate(
            args.candidate_id,
            timeout=args.timeout,
            python=args.python,
            repetitions=args.repetitions,
        )

    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
    return 0 if result.get("success", result.get("valid", True)) else 1


if __name__ == "__main__":
    raise SystemExit(main())
