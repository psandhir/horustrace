"""Compare exact source identities across historical/current scanner Graph inventories.

This intentionally reports topology/entity deltas, *not* measured precision:
the archived Frozen-180 reference is not an exhaustive independent V2 label.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

HISTORICAL_SHA = "418db4e29798a7d25df686dd7bccfd9fefa225bd"
STUDY = "real-world-agent-security-2026"


def read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object at {path}")
    return value


def normal(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def source_id(node: dict[str, Any]) -> tuple[str, str, str, int]:
    kind = node.get("kind")
    if kind not in {"agent", "workflow_node"}:
        raise ValueError(f"unexpected node kind in agent audit: {kind}")
    name = node.get("name")
    loc = node.get("location")
    if not isinstance(name, str) or not name or not isinstance(loc, dict):
        raise ValueError("Graph agent witness missing source name/location")
    path, line = loc.get("path"), loc.get("line")
    if not isinstance(path, str) or not path or not isinstance(line, int) or line <= 0:
        raise ValueError("Graph agent witness missing source path/line")
    return (kind, normal(name), path.replace("\\", "/").removeprefix("./"), line)


def identities(row: dict[str, Any]) -> dict[tuple[str, str, str, int], dict[str, Any]]:
    a = row.get("agent_node_audit")
    if not isinstance(a, list):
        raise ValueError(f"{row.get('case_id')}: scanner did not emit per-node witnesses")
    dimension = (row.get("comparisons") or {}).get("agent_entities") or {}
    if len(a) != dimension.get("predicted"):
        raise ValueError(f"{row.get('case_id')}: Graph witness count and scanner count disagree")
    result = {}
    for node in a:
        key = source_id(node)
        if key in result:
            raise ValueError(f"{row.get('case_id')}: duplicate Graph source identity: {key}")
        result[key] = node
    return result


def case_rows(
    report: dict[str, Any], cohort: dict[str, dict[str, Any]], label: str, scanner_sha: str,
) -> dict[str, dict[str, Any]]:
    if report.get("study") != STUDY or report.get("scanner_sha") != scanner_sha:
        raise ValueError(f"{label}: study or exact scanner SHA changed")
    if report.get("cohort_cases") != 145:
        raise ValueError(f"{label}: active scope must be 145 non-LangGraph repositories")
    rows = report.get("cases")
    if not isinstance(rows, list) or len(rows) != 145:
        raise ValueError(f"{label}: exactly 145 source-pinned rows required")
    result = {}
    for row in rows:
        cid = row.get("case_id")
        pin = cohort.get(cid)
        if pin is None or cid in result:
            raise ValueError(f"{label}: unknown or duplicate case {cid}")
        if row.get("repo") != pin["repo"] or row.get("framework") != pin["framework_stratum"]:
            raise ValueError(f"{label}: source pin drift for {cid}")
        status = row.get("status")
        # The source-pinned execution harness emits a SHA only after a successful
        # checkout+scan. Failure rows still preserve cohort ID/repo/framework
        # but may omit sha. Never interpret an execution failure as source drift.
        if status == "success":
            if row.get("sha") != pin["sha"]:
                raise ValueError(f"{label}: source pin drift for {cid}")
        elif status in {"fetch_error", "scanner_error", "timeout"}:
            if row.get("sha") not in {None, pin["sha"]}:
                raise ValueError(f"{label}: source pin drift for {cid}")
            if not isinstance(row.get("error"), str) or not row["error"].strip():
                raise ValueError(f"{label}: failed case missing execution evidence for {cid}")
        else:
            raise ValueError(f"{label}: unknown execution status for {cid}: {status}")
        result[cid] = row
    if set(result) != set(cohort):
        raise ValueError(f"{label}: omitted non-LangGraph case(s)")
    return result


def analyze(cohort: dict[str, Any], historical: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    frozen = cohort.get("cases")
    if (cohort.get("cohort_frozen") is not True or cohort.get("ground_truth_locked") is not True
            or not isinstance(frozen, list) or len(frozen) != 180):
        raise ValueError("Frozen-180 source lock missing")
    if len({x["case_id"] for x in frozen}) != 180:
        raise ValueError("duplicate locked case ID")
    active = {x["case_id"]: x for x in frozen if x["framework_stratum"] != "langgraph"}
    if len(active) != 145 or len(frozen) - len(active) != 35:
        raise ValueError("LangGraph exclusion drift")
    old = case_rows(historical, active, "historical", HISTORICAL_SHA)
    candidate_sha = current.get("scanner_sha")
    if not isinstance(candidate_sha, str) or not re.fullmatch("[0-9a-f]{40}", candidate_sha):
        raise ValueError("candidate scanner SHA must be pinned")
    new = case_rows(current, active, "current", candidate_sha)
    totals: Counter[str] = Counter()
    by_framework: dict[str, Counter[str]] = {}
    cases = []
    for cid in sorted(active):
        left, right = old[cid], new[cid]
        framework = active[cid]["framework_stratum"]
        scope = by_framework.setdefault(framework, Counter())
        if left.get("status") != "success" or right.get("status") != "success":
            failures = {
                "case_id": cid, "repo": active[cid]["repo"], "framework": framework,
                "historical_status": left.get("status"), "current_status": right.get("status"),
                "historical_error": left.get("error"), "current_error": right.get("error"),
            }
            cases.append(failures)
            totals["not_common_success"] += 1
            scope["not_common_success"] += 1
            continue
        a, b = identities(left), identities(right)
        removed = sorted(set(a) - set(b))
        added = sorted(set(b) - set(a))
        matched = len(set(a) & set(b))
        totals["common_success"] += 1
        scope["common_success"] += 1
        totals["historical_agent_nodes"] += sum(k[0] == "agent" for k in a)
        totals["current_agent_nodes"] += sum(k[0] == "agent" for k in b)
        totals["historical_workflow_nodes"] += sum(k[0] == "workflow_node" for k in a)
        totals["current_workflow_nodes"] += sum(k[0] == "workflow_node" for k in b)
        for k in removed:
            totals["removed_" + k[0]] += 1
            scope["removed_" + k[0]] += 1
        for k in added:
            totals["added_" + k[0]] += 1
            scope["added_" + k[0]] += 1
        cases.append({
            "case_id": cid, "repo": active[cid]["repo"], "framework": framework,
            "historical_status": "success", "current_status": "success",
            "matched_source_identities": matched, "historical_node_count": len(a),
            "current_node_count": len(b),
            "added_nodes": [{"kind": k[0], "name": b[k]["name"], "path": k[2], "line": k[3]} for k in added],
            "removed_nodes": [{"kind": k[0], "name": a[k]["name"], "path": k[2], "line": k[3]} for k in removed],
        })
    return {
        "study": STUDY, "scope": "non-langgraph-145",
        "historical_scanner_sha": HISTORICAL_SHA, "current_scanner_sha": candidate_sha,
        "frozen_source_truth_preserved": True,
        "summary": dict(totals), "per_framework": {k: dict(v) for k, v in sorted(by_framework.items())},
        "cases": cases,
        "accuracy_certified": False,
        "release_eligible": totals["common_success"] == 145,
        "limitations": [
            "Exact Graph name/kind/source-site comparison is a structural delta, not ground-truth agent precision.",
            "Historical/new scanner may normalize names and source spans differently; independently adjudicate removals/additions.",
            "Unreviewed agent source candidates are not automatic false positives.",
            "The 145-case historical scanner must run with current study harness at the pinned source SHAs.",
            "Both scanner binaries use source-only inspection; neither proves runtime deployment or effective authority.",
        ],
    }



def assess_source_study_completion(report: dict[str, Any]) -> str:
    """Evidence completion != paired release reliability or certified accuracy.

    A frozen historical scanner version cannot be retroactively patched. Permit
    only its one *independently observed* rw-177 Bazel symlink exception to
    produce a complete research artifact. All 145 CURRENT scanner cases must
    succeed. The original 145/145 paired reliability flag remains FALSE.
    """
    if report.get("accuracy_certified") is not False:
        raise ValueError("source study cannot assert certified accuracy")
    if report.get("frozen_source_truth_preserved") is not True:
        raise ValueError("frozen historical source truth must be retained")
    cases = report.get("cases")
    if not isinstance(cases, list) or len(cases) != 145:
        raise ValueError("must account for exactly 145 source-pinned cases")
    not_current = [row["case_id"] for row in cases if row.get("current_status") != "success"]
    if not_current:
        raise ValueError(f"current 145/145 reliability NOT MET: {not_current}")
    old_failed = [row for row in cases if row.get("historical_status") != "success"]
    if not old_failed:
        if report.get("release_eligible") is not True:
            raise ValueError("fully paired 145 source cases must be release-eligible")
        if report["summary"].get("common_success") != 145:
            raise ValueError("paired successes do not reconcile")
        return "paired_145_complete"
    if len(old_failed) != 1:
        raise ValueError("unrecognized historical reliability failures")
    historic = old_failed[0]
    error = historic.get("historical_error") or ""
    if not (
        historic.get("case_id") == "rw-177"
        and historic.get("repo") == "JUN176/exp-agent"
        and historic.get("historical_status") == "scanner_error"
        and "PermissionError" in error
        and "bazel-testlogs" in error
        and report.get("historical_scanner_sha") == HISTORICAL_SHA
        and report["summary"].get("common_success") == 144
        and report.get("release_eligible") is False
    ):
        raise ValueError("historical failure is not the exact documented immutable rw-177 defect")
    return "legacy_144_only_not_paired_release_eligible"


def render(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Wave B: historical/current source-pinned agent-identity differential", "",
        f"- Historical scanner: `{report['historical_scanner_sha']}`",
        f"- Current scanner: `{report['current_scanner_sha']}`",
        f"- Exact active cases: 145; historical LangGraph stratum excluded: 35",
        f"- Common successful scans: {summary.get('common_success', 0)}/145",
        f"- Failures/unequal-success cases: {summary.get('not_common_success', 0)}",
        f"- Agent sites historical/current: {summary.get('historical_agent_nodes', 0)} / {summary.get('current_agent_nodes', 0)}",
        f"- Workflow steps historical/current: {summary.get('historical_workflow_nodes', 0)} / {summary.get('current_workflow_nodes', 0)}",
        f"- Added agent-kind identities: {summary.get('added_agent', 0)}; removed agent-kind identities: {summary.get('removed_agent', 0)}",
        f"- Added workflow steps: {summary.get('added_workflow_node', 0)}; removed workflow steps: {summary.get('removed_workflow_node', 0)}",
        "",
        "| Case | Framework | Historical | Current | Matched | Added agents | Removed agents |",
        "| --- | --- | --- | --- | ---: | ---: | ---: |",
    ]
    for row in report["cases"]:
        added = len([x for x in row.get("added_nodes", []) if x["kind"] == "agent"])
        removed = len([x for x in row.get("removed_nodes", []) if x["kind"] == "agent"])
        lines.append(f"| {row['case_id']} | {row['framework']} | {row['historical_status']} | {row['current_status']} | {row.get('matched_source_identities', '—')} | {added} | {removed} |")
    lines.extend(["", "**Not a release-certified precision/recall study.** Entity additions, removals, and source-name changes require V2 source adjudication; unreviewed predictions remain unresolved."])
    return "\n".join(lines) + "\n"


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    for key in ("cohort", "historical", "current", "output-json", "output-markdown"):
        p.add_argument("--" + key, required=True, type=Path)
    args = p.parse_args()
    result = analyze(read(args.cohort), read(args.historical), read(args.current))
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.output_markdown.write_text(render(result), encoding="utf-8")
    print(render(result))


if __name__ == "__main__":
    main()
