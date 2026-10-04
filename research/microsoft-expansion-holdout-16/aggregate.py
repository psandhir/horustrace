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

    rows = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(args.input.rglob("result.json"))
    ]
    groups: dict[str, dict[str, int]] = defaultdict(
        lambda: {
            "cases": 0,
            "agents": 0,
            "findings": 0,
            "attack_paths": 0,
            "authority_relationships": 0,
        }
    )
    for row in rows:
        group = groups[row["surface"]]
        group["cases"] += 1
        for key in (
            "agents",
            "findings",
            "attack_paths",
            "authority_relationships",
        ):
            group[key] += int((row.get("counts") or {}).get(key, 0))

    zero_agent_cases = [
        row["case_id"]
        for row in rows
        if int((row.get("counts") or {}).get("agents", 0)) == 0
    ]

    summary = {
        "schema_version": 1,
        "study": "microsoft-expansion-holdout-16",
        "cases_completed": len(rows),
        "target_cases": 16,
        "zero_agent_cases": zero_agent_cases,
        "groups": [
            {"surface": key, **groups[key]}
            for key in sorted(groups)
        ],
        "results": rows,
    }

    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n",
        encoding="utf-8",
    )

    lines = [
        "# Microsoft expansion holdout 16",
        "",
        "| Surface | Cases | Agents | Authority relationships | Findings | Attack paths |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for group in summary["groups"]:
        lines.append(
            f"| {group['surface']} | {group['cases']} | {group['agents']} | "
            f"{group['authority_relationships']} | {group['findings']} | "
            f"{group['attack_paths']} |"
        )

    lines += [
        "",
        f"- Cases completed: {len(rows)}/16",
        f"- Zero-agent cases: {', '.join(zero_agent_cases) if zero_agent_cases else 'none'}",
        f"- Findings: {sum((row.get('counts') or {}).get('findings', 0) for row in rows)}",
        f"- Attack paths: {sum((row.get('counts') or {}).get('attack_paths', 0) for row in rows)}",
        f"- Authority relationships: {sum((row.get('counts') or {}).get('authority_relationships', 0) for row in rows)}",
        "",
        "Raw counts are not accuracy scores. Zero-agent cases are an immediate structural warning; all detected authority, findings and attack paths require source adjudication against the frozen source signal.",
    ]

    (args.output / "summary.md").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
