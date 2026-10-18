"""Active-145 source-truth coverage audit; never score missing truth as TN/FN.

The frozen 180-case reference and SHA pins are immutable inputs. This review
reports the independent automated source truth's coverage limitations, not
a new blind/hand-labelled oracle for V2 agent topology or effective authority.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

STUDY = "real-world-agent-security-2026"
DIMENSIONS = ("agent_entities", "tools", "mcp_servers", "delegation_edges")


def audit(cohort: dict[str, Any], truth: dict[str, dict[str, Any]]) -> dict[str, Any]:
    pins = cohort.get("cases")
    if (cohort.get("cohort_frozen") is not True
        or cohort.get("ground_truth_locked") is not True
        or not isinstance(pins, list) or len(pins) != 180):
        raise ValueError("immutable frozen-180 reference contract broken")
    original = {p["case_id"]: p for p in pins}
    if len(original) != 180 or set(truth) != set(original):
        raise ValueError("missing or duplicate original case/source reference")
    active = [p for p in pins if p.get("framework_stratum") != "langgraph"]
    archived = [p for p in pins if p.get("framework_stratum") == "langgraph"]
    if len(active) != 145 or len(archived) != 35:
        raise ValueError("active 145/archived LangGraph 35 scope drift")
    metrics = {k: Counter() for k in DIMENSIONS}
    strata: dict[str, dict[str, int]] = {}
    rows = []
    for pin in pins:
        case_id = pin["case_id"]
        row = truth[case_id]
        if (row.get("study") != STUDY
            or row.get("case_id") != case_id
            or row.get("truth_lock", {}).get("reviewed") is not True
            or row["truth_lock"].get("horustrace_output_seen") is not False):
            raise ValueError(f"source truth lock invalid: {case_id}")
        ref = row.get("source_reference") or {}
        if (ref.get("repo"), ref.get("sha"),
            ref.get("framework_stratum")) != (
            pin.get("repo"), pin.get("sha"), pin.get("framework_stratum")
        ):
            raise ValueError(f"source revision/stratum drift: {case_id}")
        completeness = (row.get("tier_a") or {}).get("reference_completeness")
        if (not isinstance(completeness, dict)
            or any(type(completeness.get(k)) is not bool for k in DIMENSIONS)):
            raise ValueError(f"missing explicit per-dimension completeness: {case_id}")
        assertions = row.get("assertions")
        if not isinstance(assertions, list):
            raise ValueError(f"missing source assertions: {case_id}")
        states = Counter()
        for claim in assertions:
            status = claim.get("expected_state")
            if status not in {"present", "absent", "unresolved"}:
                raise ValueError(f"unrecognized source label in {case_id}")
            if not isinstance(claim.get("evidence"), list) or not claim["evidence"]:
                raise ValueError(f"unsupported source label in {case_id}")
            states[status] += 1
        if pin in archived:
            continue
        framework = pin["framework_stratum"]
        per = strata.setdefault(framework, {"cases": 0, "agent_complete": 0})
        per["cases"] += 1
        per["agent_complete"] += int(completeness["agent_entities"])
        for key in DIMENSIONS:
            metrics[key]["complete" if completeness[key] else "incomplete"] += 1
        rows.append({
            "case_id": case_id, "framework": framework,
            "repo": pin["repo"], "sha": pin["sha"],
            "reference_completeness": {
                k: completeness[k] for k in DIMENSIONS
            },
            "locked_assertions": dict(sorted(states.items())),
            "source_reference_automated": ref.get("automated_reference") is True,
            "source_reference_human_dual_review": ref.get("human_dual_review") is True,
            "eligible_for_closed_world_negative_scoring": {
                k: bool(completeness[k]) for k in DIMENSIONS
            },
            "new_independent_v2_review_done": False,
        })
    return {
        "schema_version": 1,
        "study": STUDY,
        "scope": "active_145_nonlanggraph_coverage_not_v2_precision",
        "original_frozen_cases_unchanged": len(pins),
        "active_cases": len(rows),
        "archived_langgraph_cases_excluded_only_from_active": len(archived),
        "reference_completeness": {
            k: dict(sorted(v.items())) for k, v in metrics.items()
        },
        "frameworks": dict(sorted(strata.items())),
        "case_rows": sorted(rows, key=lambda x: x["case_id"]),
        "no_blank_negative_universe_auto_scored": True,
        "v2_bounded_negative_truth_complete": False,
        "independent_blind_v2_truth": False,
        "agent_precision": None,
        "agent_recall": None,
        "graph_precision": None,
        "graph_recall": None,
        "wave_b_go": False,
        "wave_c_go": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cohort", type=Path, required=True)
    parser.add_argument("--truth-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    cohort = json.loads(args.cohort.read_text())
    truth: dict[str, dict[str, Any]] = {}
    for path in sorted(args.truth_root.glob("rw-*.json")):
        data = json.loads(path.read_text())
        key = data.get("case_id")
        if key in truth or not isinstance(key, str):
            raise ValueError("duplicate/invalid locked reference case")
        truth[key] = data
    summary = audit(cohort, truth)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps({
        "active": summary["active_cases"],
        "agent_complete": summary["reference_completeness"]["agent_entities"]["complete"],
        "agent_incomplete": summary["reference_completeness"]["agent_entities"]["incomplete"],
        "wave_b_go": summary["wave_b_go"],
    }))


if __name__ == "__main__":
    main()
