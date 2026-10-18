"""Source-witness diagnostic: original precision intact, post-hoc review separate.

Never edit the frozen reference or silently reinterpret an accuracy gate.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def witness(case_id, node):
    loc = node.get("location") or {}
    if not isinstance(loc.get("line"), int) or not isinstance(loc.get("path"), str):
        raise ValueError("missing graph source location")
    return (case_id, node.get("kind"), node.get("name"), loc["path"], loc["line"])


def evaluate(candidate, cohort, overlay):
    if candidate.get("study") != "real-world-agent-security-2026" or candidate.get("cohort_cases") != 145:
        raise ValueError("requires source-locked non-LangGraph 145 scan")
    if (cohort.get("cohort_frozen") is not True or cohort.get("ground_truth_locked") is not True
            or len(cohort.get("cases", [])) != 180):
        raise ValueError("original frozen truth/cohort drift")
    by_id = {c["case_id"]: c for c in cohort["cases"]}
    included = {cid for cid, c in by_id.items() if c["framework_stratum"] != "langgraph"}
    if len(by_id) != 180 or len(included) != 145:
        raise ValueError("unexpected LangGraph exclusion / duplicate case")
    if (overlay.get("scope") != "non-langgraph-145"
            or overlay.get("reference_type") != "posthoc_source_adjudication_overlay"
            or overlay.get("original_locked_truth_preserved") is not True):
        raise ValueError("invalid overlay provenance")
    classification = {}
    valid_classes = {"workflow_step_not_agent", "source_supported_agent", "taxonomy_unresolved"}
    for item in overlay.get("classifications", []):
        cid = item["case_id"]
        if cid not in included or item.get("repository") != by_id[cid]["repo"] or item.get("source_sha") != by_id[cid]["sha"]:
            raise ValueError("overlay source pin mismatch")
        if not item.get("source_basis") or item.get("adjudication_method") != "posthoc_source_inspection_not_independent_blind":
            raise ValueError("missing source rationale/posthoc disclosure")
        cls = item.get("classification")
        if cls not in valid_classes or (cls == "workflow_step_not_agent") != (item["node_kind"] == "workflow_node"):
            raise ValueError("invalid overlay agent/workflow ontology")
        nodekey = (cid, item["node_kind"], item["node_name"], item["source_path"], item["source_line"])
        if nodekey in classification:
            raise ValueError("duplicate overlay witness")
        classification[nodekey] = cls
    if len(classification) != 31:
        raise ValueError("must classify all 31 pinned unmatched candidates")
    cases = candidate.get("cases", [])
    if len(cases) != 145:
        raise ValueError("missing candidate cases")
    case_ids = set()
    unmatched = set()
    matched = fp = matched_workflows = eligible = success = 0
    for case in cases:
        cid = case["case_id"]
        if cid not in included or cid in case_ids or case.get("repo") != by_id[cid]["repo"] or case.get("framework") != by_id[cid]["framework_stratum"]:
            raise ValueError("scanner case/source mismatch")
        if case.get("sha") is not None and case["sha"] != by_id[cid]["sha"]:
            raise ValueError("scanner source SHA drift")
        case_ids.add(cid)
        if case.get("status") != "success":
            continue
        success += 1
        a = case["comparisons"]["agent_entities"]
        if not a.get("precision_eligible"):
            continue
        eligible += 1
        matched += a["precision_tp"]
        fp += a["fp"]
        nodes = case.get("agent_node_audit")
        if not isinstance(nodes, list) or len(nodes) != a["predicted"]:
            raise ValueError("all complete-case Graph witnesses required; enable --audit-agent-nodes")
        matched_case = fp_case = 0
        for node in nodes:
            if node.get("matched_locked_reference") is True:
                matched_case += 1
                if node["kind"] == "workflow_node":
                    matched_workflows += 1
                elif node["kind"] != "agent":
                    raise ValueError("unexpected Graph matched kind")
            else:
                fp_case += 1
                k = witness(cid, node)
                if k in unmatched:
                    raise ValueError("duplicate unmatched Graph witness")
                unmatched.add(k)
        if matched_case != a["precision_tp"] or fp_case != a["fp"]:
            raise ValueError("Graph matcher counts and witness counts disagree")
    if case_ids != included or unmatched != set(classification):
        raise ValueError("unreviewed or stale unmatched candidates; fail closed")
    counts = Counter(classification.values())
    if counts != Counter({"workflow_step_not_agent": 12, "source_supported_agent": 17, "taxonomy_unresolved": 2}) or fp != 31:
        raise ValueError("unknown source-adjudication drift")
    agent_tp = matched - matched_workflows
    agent_fp = fp - counts["workflow_step_not_agent"]
    supported = agent_tp + counts["source_supported_agent"]
    return {
        "scope": "non-langgraph-145", "scanner_sha": candidate["scanner_sha"],
        "source_method": "posthoc_not_independent_blind",
        "original_locked_truth_preserved": True,
        "successful_cases": success, "precision_eligible_cases": eligible,
        "original_precision": {"tp": matched, "fp": fp, "ratio": round(matched/(matched+fp), 4)},
        "classifications": dict(counts), "matched_workflow_nodes": matched_workflows,
        "agent_kind_only_sensitivity": {"tp": agent_tp, "unmatched": agent_fp, "ratio": round(agent_tp/(agent_tp+agent_fp), 4)},
        "posthoc_support_sensitivity": {
            "supported_if_prior_matches_valid": supported, "ambiguous": counts["taxonomy_unresolved"],
            "lower_if_both_ambiguous_invalid": round(supported/(supported+counts["taxonomy_unresolved"]), 4),
            "upper_if_both_ambiguous_valid": 1.0, "certified_precision": False,
        },
        "limitations": overlay["limitations"],
    }


def render(report):
    original = report["original_precision"]
    kinds = report["agent_kind_only_sensitivity"]
    sensitivity = report["posthoc_support_sensitivity"]
    cls = report["classifications"]
    lines = [
        "# Wave B non-LangGraph 145: agent precision source audit",
        "",
        "Scanner SHA: " + report["scanner_sha"],
        "Original benchmark precision: " + str(original["tp"]) + "/(" + str(original["tp"]) + "+" + str(original["fp"]) + ") = " + str(original["ratio"]),
        "Source-witness breakdown: workflow-only " + str(cls["workflow_step_not_agent"]) + "; supported agents " + str(cls["source_supported_agent"]) + "; unresolved custom clients " + str(cls["taxonomy_unresolved"]),
        "Additional matched workflow nodes: " + str(report["matched_workflow_nodes"]),
        "Agent-kind-only apparent ratio (uncorrected source truth): " + str(kinds["ratio"]),
        "Source-overlay conditional sensitivity: " + str(sensitivity["lower_if_both_ambiguous_invalid"]) + " to " + str(sensitivity["upper_if_both_ambiguous_valid"]),
        "",
        "NOT certified accuracy. Post-hoc source review is not blinded; previously matched nodes are not independently adjudicated.",
        "The historical scanner must be rescored with the same ontology and common-success subset before claiming a corrected before/after precision delta.",
        "Original 180-case frozen truth and six active non-LangGraph release thresholds remain unchanged.",
        "",
    ]
    return "\n".join(lines)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("candidate", "cohort", "overlay", "output-json", "output-markdown"):
        p.add_argument("--" + name, type=Path, required=True)
    args = p.parse_args()
    result = evaluate(read(args.candidate), read(args.cohort), read(args.overlay))
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    args.output_markdown.write_text(render(result))
    print(render(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
