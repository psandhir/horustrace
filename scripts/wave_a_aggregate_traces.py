"""Fail-closed Wave-A passive semantic tracing study aggregate.

Outputs observed stage transition volumes, not precision, recall or root cause.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from scripts.verify_accuracy_wave_a_baseline import ROOT, audit

COHORT = ROOT / "research/accuracy-wave-a-retrospective-20261014/cohort.json"


class TraceStudyError(ValueError):
    pass


def aggregate(inputs: Path, cohort_path: Path = COHORT) -> dict:
    audit(cohort_path, ROOT)
    expected = {
        c["case_id"]: c
        for c in json.loads(cohort_path.read_text(encoding="utf-8"))["cases"]
    }
    data = {}
    failures = []
    for path in inputs.rglob("result.json"):
        try:
            result = json.loads(path.read_text(encoding="utf-8"))
            case_id = result["case_id"]
            if case_id not in expected or case_id in data:
                raise TraceStudyError(f"unknown or duplicate case {case_id}")
            case = expected[case_id]
            for field in ("repo", "sha", "framework", "application_path"):
                if result.get(field) != case[field]:
                    raise TraceStudyError(f"{case_id}: {field} frozen source mismatch")
            if result.get("trace_truncated") or result.get("trace_stage_count") != 11:
                raise TraceStudyError(f"{case_id}: trace incomplete")
            trace = json.loads(path.with_name("trace.json").read_text(encoding="utf-8"))
            stages = trace.get("stages", [])
            if len(stages) != 11 or trace.get("events_truncated"):
                raise TraceStudyError(f"{case_id}: missing stage evidence")
            if stages[-1]["stage"] != "findings":
                raise TraceStudyError(f"{case_id}: final stage missing")
            if sum(x.get("added", 0) for x in stages) < 1 and result["entities"] > 0:
                raise TraceStudyError(f"{case_id}: nonempty scan has no trace observations")
            data[case_id] = (result, trace)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            failures.append(f"{path}: {exc}")
    missing = sorted(set(expected) - set(data))
    if missing:
        failures.append("Missing expected pinned cases: " + ", ".join(missing))
    if failures:
        raise TraceStudyError("; ".join(failures))
    by_framework: dict[str, Counter[str]] = {}
    by_stage: dict[str, Counter[str]] = {}
    for result, trace in data.values():
        group = by_framework.setdefault(result["framework"], Counter())
        group["repositories"] += 1
        for count in ("entities", "tools", "mcp_servers", "skills", "findings", "attack_paths"):
            group[count] += result[count]
        for stage in trace["stages"]:
            current = by_stage.setdefault(stage["stage"], Counter())
            current["added"] += stage["added"]
            current["removed"] += stage["removed"]
            current["observations"] += stage["entities"]
    return {
        "schema_version": 1,
        "study": "accuracy-wave-a-retrospective-20261014",
        "cases_expected": len(expected),
        "cases_completed": len(data),
        "frameworks": {k: dict(v) for k, v in sorted(by_framework.items())},
        "stages": {k: dict(v) for k, v in sorted(by_stage.items())},
        "case_results": [data[k][0] for k in sorted(data)],
        "independent_source_adjudication": False,
        "precision_recall": None,
        "interpretation": "Stage transition counts localize *intervals* only, never a confirmed error.",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("aggregate-wave-a"))
    args = parser.parse_args()
    result = aggregate(args.inputs)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "summary.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    lines = [
        "# Wave A — retrospective semantic stage survival",
        "",
        f"Pinned cases: {result['cases_completed']}/{result['cases_expected']}",
        "",
        "| Stage | Added observations | Removed observations | Observations after stage |",
        "|---|---:|---:|---:|",
    ]
    for stage, counts in result["stages"].items():
        lines.append(
            f"| {stage} | {counts['added']} | {counts['removed']} | {counts['observations']} |"
        )
    lines += [
        "", "This report is a **retrospective diagnostic**, not independent truth.",
        "Added/removed observations do not imply correct/incorrect security detections.",
        "Complete source-blind adjudication remains outstanding.",
    ]
    (args.output_dir / "summary.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
