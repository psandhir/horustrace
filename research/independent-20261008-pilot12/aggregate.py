from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    results = []
    errors = []
    for path in sorted(args.input.rglob("result.json")):
        try:
            results.append(json.loads(path.read_text(encoding="utf-8")))
        except Exception as exc:
            errors.append({"path": str(path), "error": f"result parse: {exc}"})
    for path in sorted(args.input.rglob("error.json")):
        try:
            errors.append(json.loads(path.read_text(encoding="utf-8")))
        except Exception as exc:
            errors.append({"path": str(path), "error": f"error parse: {exc}"})

    by_framework = defaultdict(lambda: {
        "completed": 0, "agents": 0, "findings": 0, "attack_paths": 0,
        "authority_relationships": 0, "partially_resolved_authority": 0,
        "unknown_authority": 0, "diagnostics": 0, "zero_agent_cases": [],
        "repos": [],
    })
    cases = []
    for item in results:
        fw = item.get("framework") or "unknown"
        counts = item.get("counts") or {}
        row = by_framework[fw]
        row["completed"] += 1
        row["repos"].append(item.get("repo"))
        for key in (
            "agents", "findings", "attack_paths", "authority_relationships",
            "partially_resolved_authority", "unknown_authority", "diagnostics",
        ):
            row[key] += int(counts.get(key) or 0)
        if int(counts.get("agents") or 0) == 0:
            row["zero_agent_cases"].append(item.get("case_id"))
        cases.append({
            "case_id": item.get("case_id"),
            "framework": fw,
            "repo": item.get("repo"),
            "sha": item.get("sha"),
            "counts": counts,
        })

    error_by_framework = defaultdict(int)
    for item in errors:
        error_by_framework[item.get("framework") or "unknown"] += 1

    framework_summary = {}
    for fw in sorted(set(by_framework) | set(error_by_framework)):
        row = dict(by_framework[fw])
        row["errors"] = error_by_framework[fw]
        row["expected"] = 10 if fw != "unknown" else 0
        framework_summary[fw] = row

    summary = {
        "schema_version": 1,
        "study": "full-framework-60-20261005",
        "completed": len(results),
        "errors": len(errors),
        "frameworks": framework_summary,
        "cases": sorted(cases, key=lambda x: x["case_id"] or ""),
        "error_cases": errors,
    }
    (args.output / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )

    lines = [
        "# Full-framework 60 current-main scan summary",
        "",
        f"- completed: **{len(results)}/60**",
        f"- errors: **{len(errors)}**",
        "",
        "| Framework | Complete | Errors | Agents | Findings | Paths | Authority rels | Partial | Unknown | Diagnostics | Zero-agent |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for fw, row in framework_summary.items():
        lines.append(
            f"| {fw} | {row['completed']}/10 | {row['errors']} | {row['agents']} | "
            f"{row['findings']} | {row['attack_paths']} | {row['authority_relationships']} | "
            f"{row['partially_resolved_authority']} | {row['unknown_authority']} | "
            f"{row['diagnostics']} | {len(row['zero_agent_cases'])} |"
        )
    if errors:
        lines += ["", "## Errors", ""]
        for item in errors:
            lines.append(
                f"- **{item.get('case_id', item.get('path', 'unknown'))}** "
                f"({item.get('framework', 'unknown')}): {item.get('error', 'unknown error')}"
            )
    lines += ["", "## Zero-agent cases", ""]
    any_zero = False
    for fw, row in framework_summary.items():
        for case_id in row["zero_agent_cases"]:
            any_zero = True
            lines.append(f"- {fw}: {case_id}")
    if not any_zero:
        lines.append("- none")

    (args.output / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
