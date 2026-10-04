from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

STUDY = "google-adk-unseen-holdout-10"
TARGET = 10


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
            "partially_resolved_authority": 0,
            "unknown_authority": 0,
        }
    )
    for row in rows:
        group = groups[row["surface"]]
        group["cases"] += 1
        for key in (
            "agents", "findings", "attack_paths", "authority_relationships",
            "partially_resolved_authority", "unknown_authority",
        ):
            group[key] += int((row.get("counts") or {}).get(key, 0))

    zero_agent_cases = [
        row["case_id"] for row in rows
        if int((row.get("counts") or {}).get("agents", 0)) == 0
    ]
    totals = {
        key: sum(int((row.get("counts") or {}).get(key, 0)) for row in rows)
        for key in (
            "agents", "findings", "attack_paths", "authority_relationships",
            "partially_resolved_authority", "unknown_authority",
        )
    }

    summary = {
        "schema_version": 1,
        "study": STUDY,
        "cases_completed": len(rows),
        "target_cases": TARGET,
        "zero_agent_cases": zero_agent_cases,
        "groups": [{"surface": key, **groups[key]} for key in sorted(groups)],
        "totals": totals,
        "results": rows,
    }

    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )

    lines = [
        "# Google ADK unseen holdout 10",
        "",
        "| Surface | Cases | Agents | Authority rels | Partial | Unknown | Findings | Attack paths |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for group in summary["groups"]:
        lines.append(
            f"| {group['surface']} | {group['cases']} | {group['agents']} | "
            f"{group['authority_relationships']} | {group['partially_resolved_authority']} | "
            f"{group['unknown_authority']} | {group['findings']} | {group['attack_paths']} |"
        )

    lines += [
        "",
        f"- Cases completed: {len(rows)}/{TARGET}",
        f"- Zero-agent cases: {', '.join(zero_agent_cases) if zero_agent_cases else 'none'}",
        f"- Agents: {totals['agents']}",
        f"- Authority relationships: {totals['authority_relationships']}",
        f"- Partially resolved authority: {totals['partially_resolved_authority']}",
        f"- Unknown authority: {totals['unknown_authority']}",
        f"- Findings: {totals['findings']}",
        f"- Attack paths: {totals['attack_paths']}",
        "",
        "Raw counts are not accuracy scores. Source adjudication against the frozen source signals is required before changing scanner behavior.",
    ]
    (args.output / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
