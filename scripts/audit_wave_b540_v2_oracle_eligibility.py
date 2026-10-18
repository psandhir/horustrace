"""Source-truth eligibility gate: historical completeness is NOT a V2 oracle.

Do not modify Frozen-180 source labels. Post-hoc diagnostics mark known
incompatibility separately from 55 still-unadjudicated historically complete
cases; none qualify as independently blind V2 negative-labelled truth.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from scripts.audit_wave_b540_active_truth_coverage import audit

RW001 = "rw-001"
RW001_REPO = "Klavis-AI/klavis"
RW001_SHA = "45c9f7da83d1cf43f7429b96f9c8e8153542ea1e"
RW001_ROOT = "mcp_servers/hugging_face/packages/e2e-python/"
# Six recorded frozen source-positive agent records refer to application
# factory assignments, not individual @fast.agent declarations. Independently
# inspected immutable source and tests are tracked by the merged #600 proof.
RW001_FACTORY_COUNT = 6
POSTHOC_SOURCE_WITNESSES: dict[str, str] = {
    "rw-001": "scripts/verify_wave_b540_rw001_fastagent_negatives.py",
    "rw-002": "scripts/verify_wave_b540_rw002_fastagent_negatives.py",
    "rw-003": "scripts/verify_wave_b540_rw003_fastagent_ontology.py",
}


def oracle_eligibility(
    cohort: dict[str, Any], truth: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    reference = audit(cohort, truth)
    rows = reference["case_rows"]
    indexed = {r["case_id"]: r for r in rows}
    if not all(k in indexed for k in POSTHOC_SOURCE_WITNESSES):
        raise ValueError("missing post-hoc source review scope")
    for key in POSTHOC_SOURCE_WITNESSES:
        if indexed[key]["framework"] != "fastagent":
            raise ValueError(f"source review framework stratum changed: {key}")

    original = truth[RW001]
    if (original["source_reference"]["repo"] != RW001_REPO
        or original["source_reference"]["sha"] != RW001_SHA
        or indexed[RW001]["reference_completeness"]["agent_entities"] is not True):
        raise ValueError("historically complete rw-001 source reference drift")
    original_claims = [
        claim for claim in original["assertions"]
        if claim.get("predicate") == "explicit_agent_entity"
        and claim.get("subject") == "fast"
        and claim.get("expected_state") == "present"
        and isinstance(claim.get("evidence"), list)
        and claim["evidence"]
        and str(claim["evidence"][0].get("path", "")).startswith(RW001_ROOT)
    ]
    if len(original_claims) != RW001_FACTORY_COUNT:
        raise ValueError("rw-001 known factory-as-agent source conflicts changed")

    statuses = Counter()
    per_framework: dict[str, Counter[str]] = {}
    for row in rows:
        key = row["case_id"]
        complete = row["reference_completeness"]["agent_entities"]
        status = (
            "historical_agent_ontology_incompatible"
            if key == RW001 else
            "historical_agent_reference_incomplete"
            if not complete else
            "historically_complete_v2_not_yet_adjudicated"
        )
        if key == RW001 and not complete:
            raise ValueError("known incompatible reference must stay historically complete")
        row["v2_agent_reference_status"] = status
        row["v2_agent_negative_universe_certified"] = False
        row["v2_agent_precision_recall_eligible"] = False
        row["historical_agent_complete_flag_only"] = complete
        row["posthoc_source_review"] = POSTHOC_SOURCE_WITNESSES.get(key)
        row["v2_accuracy_eligibility_reason"] = (
            "known_factory_as_agent_source_ontology_conflict"
            if key == RW001 else
            "incomplete_source_reference"
            if not complete else
            "not_independently_v2_adjudicated_and_no_exhaustive_negatives"
        )
        statuses[status] += 1
        per_framework.setdefault(row["framework"], Counter())[status] += 1

    if statuses != {
        "historical_agent_ontology_incompatible": 1,
        "historical_agent_reference_incomplete": 89,
        "historically_complete_v2_not_yet_adjudicated": 55,
    }:
        raise ValueError(f"historical complete/incomplete V2 status drift: {statuses}")

    active_claims = Counter()
    for row in rows:
        active_claims.update(row["locked_assertions"])
    if (active_claims.get("absent", 0) != 0
        or active_claims.get("unresolved", 0) != 0):
        raise ValueError("original source-negative assertion universe changed")

    return {
        "schema_version": 1,
        "scope": "active145_legacy_truth_vs_independent_v2_oracle_eligibility",
        "active_cases": len(rows),
        "legacy_agent_complete": 56,
        "legacy_agent_incomplete": 89,
        "known_complete_flag_ontology_conflicts": {
            RW001: {
                "case_id": RW001,
                "source_sha": RW001_SHA,
                "historical_factory_as_agent_positives": RW001_FACTORY_COUNT,
                "proof": POSTHOC_SOURCE_WITNESSES[RW001],
                "source_review_method": "posthoc_not_independent_blind",
            }
        },
        "original_locked_active_assertions": dict(sorted(active_claims.items())),
        "legacy_completeness_v2_disposition": dict(sorted(statuses.items())),
        "framework_status_counts": {
            f: dict(sorted(counts.items()))
            for f, counts in sorted(per_framework.items())
        },
        "case_rows": rows,
        "independent_v2_negative_label_complete_cases": 0,
        "independently_certified_v2_agent_precision": None,
        "independently_certified_v2_agent_recall": None,
        "frozen_180_truth_rewritten": False,
        "langgraph_active": False,
        "methodologically_independent_new_v2_oracle": False,
        "wave_b_go": False,
        "wave_c_go": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cohort", type=Path, required=True)
    parser.add_argument("--truth-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    cohort = json.loads(args.cohort.read_text(encoding="utf-8"))
    truth: dict[str, dict[str, Any]] = {}
    for path in sorted(args.truth_root.glob("rw-*.json")):
        entry = json.loads(path.read_text(encoding="utf-8"))
        key = entry.get("case_id")
        if key in truth or not isinstance(key, str):
            raise ValueError("duplicate/missing frozen source reference")
        truth[key] = entry
    result = oracle_eligibility(cohort, truth)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({
        "historically_complete": result["legacy_agent_complete"],
        "known_invalid": result["legacy_completeness_v2_disposition"][
            "historical_agent_ontology_incompatible"
        ],
        "not_yet_v2_reviewed": result["legacy_completeness_v2_disposition"][
            "historically_complete_v2_not_yet_adjudicated"
        ],
        "incomplete": result["legacy_agent_incomplete"],
        "v2_eligible": result["independent_v2_negative_label_complete_cases"],
        "wave_b_go": False,
    }))


if __name__ == "__main__":
    main()
