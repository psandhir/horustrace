"""Conservative source-qualified agent-precision contract (Wave B, non-LangGraph).

This is a *new*, opt-in evaluator. It does not modify the Frozen-180 source
reference, the historical scoreboard, or any production scanner/ADG behaviour.
A corrected release score requires a separately reviewed exhaustive V2
reference and per-node witnesses from BOTH historical and current scanners.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


def _norm(text: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(text or "").lower())


def _anchor(record: dict[str, Any]) -> tuple[str, int]:
    loc = record.get("location")
    if not isinstance(loc, dict):
        raise ValueError("agent witness missing source location")
    path = loc.get("path")
    line = loc.get("line")
    if not isinstance(path, str) or not path or not isinstance(line, int) or line <= 0:
        raise ValueError("agent witness requires a source path and positive line")
    return (path.replace("\\", "/").removeprefix("./"), line)


def _identity(node: dict[str, Any]) -> tuple[str, str, int]:
    path, line = _anchor(node)
    name = _norm(node.get("name"))
    if not name:
        raise ValueError("agent witness requires a canonical name")
    return (name, path, line)


def _reference_identity(item: dict[str, Any]) -> tuple[str, str, int]:
    path, line = _anchor(item)
    return (_norm(item.get("name")), path, line)


def _adjudicate(
    nodes: list[dict[str, Any]], truth: list[dict[str, Any]],
) -> tuple[int, int, int, int]:
    """Score exact positive/negative source witnesses, never use guessed aliases.

    Every source-qualified node matches at most one independently reviewed
    positive record. Source-backed negatives are the ONLY source of confirmed
    false positives. Any remaining agent candidate is unresolved, not FP.
    """
    truth_positive = [x for x in truth if x.get("expected") is True]
    truth_negative = [x for x in truth if x.get("expected") is False]
    if len(truth_positive) + len(truth_negative) != len(truth):
        raise ValueError("reference records must be explicit positive or negative")
    keys = [_reference_identity(x) for x in truth]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate source-qualified reference identity")
    positives = {_reference_identity(x) for x in truth_positive}
    negatives = {_reference_identity(x) for x in truth_negative}
    found: set[tuple[str, str, int]] = set()
    tp = fp = unresolved = 0
    for node in nodes:
        key = _identity(node)
        if key in found:
            # Multiple source sites or distinct binding identities require a
            # V2 declaration; do not quietly collapse identical source anchors.
            raise ValueError(f"ambiguous duplicate scanner identity: {key}")
        found.add(key)
        if key in positives:
            tp += 1
        elif key in negatives:
            fp += 1
        else:
            unresolved += 1
    return tp, fp, len(positives - found), unresolved


def score_one(
    case: dict[str, Any],
    reference: dict[str, Any],
) -> dict[str, Any]:
    """Score one source-pinned case under a deliberately strict ontology."""
    if case.get("status") != "success":
        return {"status": "scanner_failure", "reason": case.get("status")}
    witnesses = case.get("agent_node_audit")
    if not isinstance(witnesses, list):
        raise ValueError("every successful case requires per-node Graph witnesses")
    if not isinstance(reference.get("agent_sites"), list):
        raise ValueError("V2 reference needs explicit source-qualified agent sites")
    agents = [x for x in witnesses if x.get("kind") == "agent"]
    workflows = [x for x in witnesses if x.get("kind") == "workflow_node"]
    unknown = [x for x in witnesses if x.get("kind") not in {"agent", "workflow_node"}]
    if unknown:
        raise ValueError("unexpected Graph node kinds in agent audit")
    tp, fp, fn, unresolved = _adjudicate(agents, reference["agent_sites"])
    complete = reference.get("agent_inventory_exhaustive") is True
    independent = reference.get("independent_review") is True
    # Precisions cannot be certified from our post-hoc 31-node overlay.
    precision = round(tp / (tp + fp), 4) if complete and independent and not unresolved and tp + fp else None
    recall = round(tp / (tp + fn), 4) if complete and independent and not unresolved and tp + fn else None
    return {
        "status": "scored", "tp": tp, "fp": fp, "fn": fn,
        "unresolved_agent_candidates": unresolved,
        "workflow_nodes_excluded_from_agent_precision": len(workflows),
        "reference_complete": complete, "independent_review": independent,
        "precision": precision, "recall": recall,
        "certified": bool(complete and independent and not unresolved),
        "source_witnesses": len(agents),
    }


def score_pair(
    cohort: dict[str, Any],
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    reference_v2: dict[str, Any],
) -> dict[str, Any]:
    """Require the same exact pinned 145-case panel and review on both sides."""
    if cohort.get("cohort_frozen") is not True or cohort.get("ground_truth_locked") is not True:
        raise ValueError("original source truth not locked")
    source = cohort.get("cases")
    if not isinstance(source, list) or len(source) != 180:
        raise ValueError("expected original 180 source pins")
    active = {str(c["case_id"]): c for c in source if c.get("framework_stratum") != "langgraph"}
    if len(active) != 145:
        raise ValueError("active non-LangGraph 145 scope drift")
    if reference_v2.get("scope") != "non-langgraph-145":
        raise ValueError("V2 reference scope mismatch")
    reference = reference_v2.get("cases")
    if not isinstance(reference, list) or {x.get("case_id") for x in reference} != set(active):
        raise ValueError("V2 reference must cover all 145 pinned case IDs")
    refs = {x["case_id"]: x for x in reference}
    for case_id, row in refs.items():
        pinned = active[case_id]
        if row.get("repo") != pinned["repo"] or row.get("sha") != pinned["sha"]:
            raise ValueError(f"V2 source reference pin changed: {case_id}")
        if not isinstance(row.get("agent_inventory_exhaustive"), bool):
            raise ValueError("review completeness must be explicit")
        if not isinstance(row.get("independent_review"), bool):
            raise ValueError("review independence must be explicit")
    def rows(report: dict[str, Any], label: str) -> dict[str, dict[str, Any]]:
        if report.get("cohort_cases") != 145:
            raise ValueError(f"{label}: report is not exactly 145 cases")
        values = report.get("cases")
        if not isinstance(values, list) or len(values) != 145:
            raise ValueError(f"{label}: missing case-level evidence")
        result: dict[str, dict[str, Any]] = {}
        for row in values:
            cid = row.get("case_id")
            if cid not in active or cid in result:
                raise ValueError(f"{label}: unexpected/duplicate case ID")
            pin = active[cid]
            if row.get("repo") != pin["repo"] or row.get("framework") != pin["framework_stratum"] or row.get("sha") != pin["sha"]:
                raise ValueError(f"{label}: source pin changed for {cid}")
            result[cid] = row
        return result
    old = rows(baseline, "baseline")
    new = rows(candidate, "candidate")
    common = [cid for cid in sorted(active) if old[cid].get("status") == new[cid].get("status") == "success"]
    per_case: list[dict[str, Any]] = []
    for cid in common:
        before = score_one(old[cid], refs[cid])
        after = score_one(new[cid], refs[cid])
        per_case.append({"case_id": cid, "baseline": before, "candidate": after})
    # Do not quietly remove failed scans; record exact common-success count.
    def total(side: str) -> dict[str, Any]:
        used = [row[side] for row in per_case]
        sums = Counter()
        for row in used:
            for key in ("tp", "fp", "fn", "unresolved_agent_candidates", "workflow_nodes_excluded_from_agent_precision"):
                sums[key] += row[key]
        certified = len(common) == 145 and all(row["certified"] for row in used)
        return {
            **dict(sums), "certified": certified,
            "precision": round(sums["tp"]/(sums["tp"] + sums["fp"]), 4) if certified and sums["tp"] + sums["fp"] else None,
            "recall": round(sums["tp"]/(sums["tp"] + sums["fn"]), 4) if certified and sums["tp"] + sums["fn"] else None,
        }
    return {
        "scope": "non-langgraph-145", "common_success_cases": len(common),
        "baseline_sha": baseline.get("scanner_sha"), "candidate_sha": candidate.get("scanner_sha"),
        "baseline": total("baseline"), "candidate": total("candidate"),
        "cases": per_case, "original_source_reference_unchanged": True,
        "release_precision_not_established_without_blinded_exhaustive_labels": True,
    }


def main() -> None:
    import argparse
    p = argparse.ArgumentParser(description=__doc__)
    for key in ("cohort", "baseline", "candidate", "reference-v2", "output"):
        p.add_argument("--" + key, required=True, type=Path)
    args = p.parse_args()
    result = score_pair(
        json.loads(args.cohort.read_text()),
        json.loads(args.baseline.read_text()),
        json.loads(args.candidate.read_text()),
        json.loads(args.reference_v2.read_text()),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: result[k] for k in ("scope", "common_success_cases", "baseline", "candidate")}, indent=2))


if __name__ == "__main__":
    main()
