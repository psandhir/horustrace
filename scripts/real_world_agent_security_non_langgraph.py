"""Derive an auditable non-LangGraph evaluation from the immutable Frozen-180.

The excluded source stratum is never deleted or silently re-labelled. Both
scanner reports are reaggregated from the same 145 case IDs; totals and
completeness-aware precision denominators are recomputed, not subtracted from
rounded whole-cohort scores.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from real_world_agent_security_compare import compare, render_markdown
from real_world_agent_security_execute import aggregate
from real_world_semantic_benchmark import score

EXCLUDED_FRAMEWORK = "langgraph"
EXPECTED_ORIGINAL = 180
EXPECTED_EXCLUDED = 35


def load(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected an object")
    return data


def scope_cases(
    cohort: dict[str, Any],
    baseline: dict[str, Any],
    candidate: dict[str, Any],
) -> tuple[dict[str, Any], list[str], dict[str, Any], dict[str, Any]]:
    if cohort.get("cohort_frozen") is not True or cohort.get("ground_truth_locked") is not True:
        raise ValueError("frozen original truth/cohort locks must remain intact")
    original = cohort.get("cases")
    if not isinstance(original, list) or len(original) != EXPECTED_ORIGINAL:
        raise ValueError("expected exact original Frozen-180 cohort")
    by_id: dict[str, dict[str, Any]] = {}
    for item in original:
        if not isinstance(item, dict) or not item.get("case_id"):
            raise ValueError("invalid original case")
        case_id = str(item["case_id"])
        if case_id in by_id:
            raise ValueError(f"duplicate original case {case_id}")
        if not item.get("sha") or len(str(item["sha"])) != 40:
            raise ValueError(f"unpinned original case {case_id}")
        by_id[case_id] = item

    excluded = sorted(
        case_id for case_id, item in by_id.items()
        if item.get("framework_stratum") == EXCLUDED_FRAMEWORK
    )
    if len(excluded) != EXPECTED_EXCLUDED:
        raise ValueError("LangGraph cohort composition drift")
    selected = set(by_id) - set(excluded)
    if len(selected) != EXPECTED_ORIGINAL - EXPECTED_EXCLUDED:
        raise ValueError("non-LangGraph cohort count drift")

    views: list[dict[str, Any]] = []
    for label, report in (("baseline", baseline), ("candidate", candidate)):
        if report.get("study") != "real-world-agent-security-2026":
            raise ValueError(f"{label}: wrong reference study")
        report_count = report.get("cohort_cases")
        valid_counts = {EXPECTED_ORIGINAL} if label == "baseline" else {
            EXPECTED_ORIGINAL, EXPECTED_ORIGINAL - EXPECTED_EXCLUDED
        }
        if report_count not in valid_counts:
            raise ValueError(f"{label}: unexpected report cohort count")
        cases = report.get("cases")
        if not isinstance(cases, list) or len(cases) != report_count:
            raise ValueError(f"{label}: missing report case")
        results: dict[str, dict[str, Any]] = {}
        for row in cases:
            if not isinstance(row, dict):
                raise ValueError(f"{label}: invalid report case")
            case_id = str(row.get("case_id") or "")
            expected = by_id.get(case_id)
            if expected is None or case_id in results:
                raise ValueError(f"{label}: unexpected or duplicate case {case_id}")
            if row.get("framework") != expected.get("framework_stratum"):
                raise ValueError(f"{label}: source framework drift for {case_id}")
            if row.get("repo") != expected.get("repo"):
                raise ValueError(f"{label}: source repository drift for {case_id}")
            if row.get("sha") is not None and row.get("sha") != expected.get("sha"):
                raise ValueError(f"{label}: source SHA drift for {case_id}")
            results[case_id] = row
        expected_ids = (
            selected
            if label == "candidate" and report_count == EXPECTED_ORIGINAL - EXPECTED_EXCLUDED
            else set(by_id)
        )
        if set(results) != expected_ids:
            raise ValueError(f"{label}: report doesn't cover expected source-pinned cases")
        selection = [results[case_id] for case_id in sorted(selected)]
        scoped_cohort = {
            **cohort,
            "cases": [by_id[case_id] for case_id in sorted(selected)],
            "tier_c_case_ids": [
                case_id for case_id in cohort.get("tier_c_case_ids", [])
                if case_id in selected
            ],
        }
        derived = aggregate(
            selection,
            str(report["scanner_sha"]),
            scoped_cohort,
            execution_mode=str(report.get("execution_mode") or "baseline"),
        )
        derived["evaluation_scope"] = {
            "name": "non-langgraph-145",
            "original_cases": EXPECTED_ORIGINAL,
            "active_cases": len(selection),
            "excluded_framework": EXCLUDED_FRAMEWORK,
            "excluded_case_ids": excluded,
            "source_locked_180_preserved": True,
            "derivation": "same-case filtered reaggregation, no source edits or rescans",
        }
        views.append(derived)
    return scoped_cohort, excluded, views[0], views[1]


def analyze(
    cohort: dict[str, Any],
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    benchmark: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    scoped_cohort, excluded, before, after = scope_cases(cohort, baseline, candidate)
    comparison = compare(before, after)
    # The historical v0.9 gate policy includes two LangGraph-specific gates.
    # Under the explicitly user-selected non-LangGraph product scope, those
    # gates are NOT evaluated; all other six thresholds are unchanged.
    all_gates = comparison.pop("v09_gates")
    comparison.pop("v09_gates_met")
    lg_gates = {"langgraph_agent_recall", "langgraph_tool_recall"}
    if {g["name"] for g in all_gates if g["name"] in lg_gates} != lg_gates:
        raise ValueError("expected exactly two excluded LangGraph-specific gates")
    comparison["active_non_langgraph_gates"] = [
        gate for gate in all_gates if gate["name"] not in lg_gates
    ]
    if len(comparison["active_non_langgraph_gates"]) != 6:
        raise ValueError("must retain all six applicable thresholds")
    comparison["active_non_langgraph_gates_met"] = all(
        gate["meets"] for gate in comparison["active_non_langgraph_gates"]
    )
    comparison["evaluation_scope"] = after["evaluation_scope"]
    comparison["excluded_release_gates"] = sorted(lg_gates)
    comparison["excluded_framework"] = EXCLUDED_FRAMEWORK

    semantic_cases = benchmark.get("cases")
    if not isinstance(semantic_cases, list):
        raise ValueError("invalid locked semantic benchmark")
    active_ids = {case["case_id"] for case in scoped_cohort["cases"]}
    remaining = [case for case in semantic_cases if case.get("case_id") in active_ids]
    benchmark_excluded = sorted(
        str(case.get("case_id")) for case in semantic_cases
        if case.get("case_id") not in active_ids
    )
    if any(case_id not in excluded for case_id in benchmark_excluded):
        raise ValueError("semantic benchmark has missing non-LangGraph cases")
    if not remaining:
        raise ValueError("no semantic benchmark cases remain")
    scoped_benchmark = {
        **benchmark,
        "methodology": {**benchmark["methodology"], "case_count": len(remaining)},
        "cases": remaining,
    }
    semantic = score(after, scoped_benchmark)
    semantic["evaluation_scope"] = "non-langgraph-145"
    semantic["excluded_semantic_case_ids"] = benchmark_excluded
    return before, after, comparison, semantic


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cohort", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--semantic-benchmark", type=Path, required=True)
    parser.add_argument("--output-prefix", type=Path, required=True)
    args = parser.parse_args()

    before, after, delta, semantic = analyze(
        load(args.cohort),
        load(args.baseline),
        load(args.candidate),
        load(args.semantic_benchmark),
    )
    prefix = args.output_prefix
    prefix.parent.mkdir(parents=True, exist_ok=True)
    for suffix, content in (
        ("baseline", before),
        ("candidate", after),
        ("delta", delta),
        ("semantic-parity", semantic),
    ):
        Path(f"{prefix}-{suffix}.json").write_text(
            json.dumps(content, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    rendered = render_markdown({
        **delta,
        "v09_gates": delta["active_non_langgraph_gates"],
    }).replace(
        "# HorusTrace v0.9 Frozen-Cohort Delta",
        "# Wave B — active non-LangGraph source-locked 145-case delta",
    ).replace("## v0.9 release gates", "## Active non-LangGraph gates (six unchanged thresholds)")
    header = (
        "Scope: 145/180 original exact-source cases; 35 LangGraph cases excluded. "
        "Historical 180-case reports unchanged. "
        f"Active gates met: {delta['active_non_langgraph_gates_met']}. "
        f"Semantic assertions passed: {semantic['passed']}/{semantic['assertions']}.\n\n"
    )
    Path(f"{prefix}-delta.md").write_text(header + rendered, encoding="utf-8")
    print(header + rendered)
    # Diagnostic study generation succeeds even if accuracy fails; the
    # machine-readable active_non_langgraph_gates_met remains explicit.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
