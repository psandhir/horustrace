"""Fail-closed Wave B pilot engineering closeout, not security release GO.

The source-only pilot dossier is complete on this scanner tree. A passed
workflow attests evidence integrity and bounded scope only; it cannot turn
original model-reviewed source assertions into independent V2 negatives or
source-only unknowns into observed runtime security claims.
"""
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any

from scripts.audit_wave_b540_v2_oracle_eligibility import oracle_eligibility
from scripts.verify_wave_b540_unresolved_claims import acceptance_check

VALIDATED_SCANNER_TREE = "7c1ce9fb257f85b7de1c4dc10bd7475fc96cdd16"
VALIDATED_SCANNER_HEAD = "3b3aca87eb6e27859b4708d5564bc64513670841"
CASE_IDS = {
    "gen-pyd-001", "ff60-microsoft-04", "gen-mcp-003", "ff60-amazon-04"
}


def closeout(
    *, scanner_tree: str, ledger: dict[str, Any],
    oracle: dict[str, Any], claims: dict[str, Any], ruleset: dict[str, Any],
) -> dict[str, Any]:
    if scanner_tree != VALIDATED_SCANNER_TREE:
        raise ValueError("scanner has changed since 15/15 validated framework/cohort gates")
    cases = ledger.get("cases")
    if not isinstance(cases, dict) or set(cases) != CASE_IDS:
        raise ValueError("five-pilot source ledger changed or incomplete")
    required = {
        "gen-pyd-001": ("tool_edges", 22),
        "ff60-microsoft-04": ("server_edges", 2),
        "gen-mcp-003": ("tool_edges", 53),
        "ff60-amazon-04": ("constructor_sites", 10),
    }
    for name, (key, count) in required.items():
        if len(cases[name].get(key, [])) != count:
            raise ValueError(f"pinned source-positive ledger drift: {name}/{key}")
    amazon = cases["ff60-amazon-04"]
    if len(amazon.get("orchestrator_tool_membership", [])) != 9:
        raise ValueError("Amazon wrapper/deferred membership source ledger drift")
    if claims.get("total_historical_claims") != 73 or len(
        claims.get("unresolved", [])
    ) != 12:
        raise ValueError("twelve external tool/effect/control unknowns disappeared")
    distribution = oracle.get("legacy_completeness_v2_disposition", {})
    if distribution != {
        "historical_agent_ontology_incompatible": 1,
        "historical_agent_reference_incomplete": 89,
        "historically_complete_v2_not_yet_adjudicated": 55,
    } or oracle.get("independent_v2_negative_label_complete_cases") != 0:
        raise ValueError("independent V2 negative reference status drift")
    if oracle.get("active_cases") != 145 or oracle.get("langgraph_active") is not False:
        raise ValueError("original source scope changed")
    if oracle.get("independently_certified_v2_agent_precision") is not None:
        raise ValueError("unsupported V2 precision promoted")
    if ruleset.get("enforcement") != "active":
        raise ValueError("protected main ruleset not active")
    status_rule = next(
        (entry for entry in ruleset.get("rules", [])
         if entry.get("type") == "required_status_checks"), None
    )
    if not isinstance(status_rule, dict):
        raise ValueError("missing ruleset required status check contract")
    required_checks = {
        x.get("context")
        for x in status_rule.get("parameters", {}).get("required_status_checks", [])
    }
    if not {"package", "test (3.11)", "test (3.12)",
            "self-scan", "analyze"}.issubset(required_checks):
        raise ValueError("existing protected main required checks were weakened")
    accurate_gate_enforced = "accuracy-regression-gate" in required_checks
    return {
        "schema_version": 1,
        "scope": "wave_b540_source_pilot_engineering_closeout_not_release_certification",
        "scanner_src_tree_sha": scanner_tree,
        "most_recent_matching_full_framework_validation_head": VALIDATED_SCANNER_HEAD,
        "scanner_source_tree_matches_frozen_cohort_validated_head": True,
        "source_pilot_positive_contracts": {
            "pharmiq_tool_exposures": 22,
            "microsoft_declared_dynamic_servers": 2,
            "couchbase_conditional_registered_tools": 53,
            "amazon_constructor_sites": 10,
            "amazon_orchestrator_membership": 9,
            "linkedin_source_contexts": 124,
            "linkedin_test_source_contexts": 121,
            "linkedin_runtime_source_contexts": 3,
        },
        "source_pilot_evidence_work_completed": True,
        "source_pilot_independent_runtime_authority_certified": False,
        "historical_model_review_claims": 73,
        "historical_unresolved_runtime_claims": 12,
        "reference_agent_legacy_incomplete": 89,
        "reference_agent_legacy_complete_but_v2_not_reviewed": 55,
        "reference_agent_known_ontology_conflicts": 1,
        "v2_exhaustive_independent_negative_cases_certified": 0,
        "accuracy_required_status_enforced": accurate_gate_enforced,
        "admin_followup": (
            None if accurate_gate_enforced
            else "Add accuracy-regression-gate to active Protect main ruleset "
                 "23823545; verify red/stale scanner-PR blocking"
        ),
        "source_accuracy_precision": None,
        "source_accuracy_recall": None,
        "authority_and_path_accuracy_certified": False,
        "engineering_pilot_closeout_supported": True,
        "security_release_go": False,
        "wave_c_production_cutover_go": False,
        "remaining_evidence_actions": [
            "Independently labelled V2 positive/negative agent, relationship and path truth",
            "Same environment dependency/MCP/identity and permission evidence for 12 Amazon claims",
            "Require and adversarially test protected main accuracy-regression-gate",
            "Controlled Wave C Graph/ADG/authority feature flag cutover with rollout and rollback",
        ],
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--repo-root", type=Path, default=Path("."))
    p.add_argument("--source-ledger", type=Path, required=True)
    p.add_argument("--cohort", type=Path, required=True)
    p.add_argument("--truth-root", type=Path, required=True)
    p.add_argument("--claim-high", type=Path, required=True)
    p.add_argument("--claim-medium", type=Path, required=True)
    p.add_argument("--ruleset", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    scanner_tree = subprocess.check_output(
        ["git", "rev-parse", "HEAD:src/horustrace"],
        cwd=args.repo_root, text=True,
    ).strip()
    truth: dict[str, dict[str, Any]] = {}
    for f in sorted(args.truth_root.glob("rw-*.json")):
        row = json.loads(f.read_text())
        if row["case_id"] in truth:
            raise ValueError("duplicate immutable source reference")
        truth[row["case_id"]] = row
    report = closeout(
        scanner_tree=scanner_tree,
        ledger=json.loads(args.source_ledger.read_text()),
        oracle=oracle_eligibility(
            json.loads(args.cohort.read_text()), truth
        ),
        claims=acceptance_check([
            json.loads(args.claim_high.read_text()),
            json.loads(args.claim_medium.read_text()),
        ]),
        ruleset=json.loads(args.ruleset.read_text()),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "pilot_work_complete": report["source_pilot_evidence_work_completed"],
        "security_release_go": report["security_release_go"],
        "independent_negative_cases": report[
            "v2_exhaustive_independent_negative_cases_certified"
        ],
        "runtime_unknown_claims": report["historical_unresolved_runtime_claims"],
    }))


if __name__ == "__main__":
    main()
