from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

STUDY = "pydantic-unseen-holdout-8"
TARGET = 8


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
            "framework_agents": 0,
            "tools": 0,
            "mcp_servers": 0,
            "authority_relationships": 0,
            "findings": 0,
        }
    )
    for row in rows:
        group = groups[row["surface"]]
        group["cases"] += 1
        for key in ("framework_agents", "tools", "mcp_servers", "authority_relationships", "findings"):
            group[key] += int((row.get("counts") or {}).get(key, 0))

    zero_agent = [
        row["case_id"] for row in rows
        if int((row.get("counts") or {}).get("framework_agents", 0)) == 0
    ]
    totals = {
        key: sum(int((row.get("counts") or {}).get(key, 0)) for row in rows)
        for key in ("framework_agents", "tools", "mcp_servers", "authority_relationships", "findings")
    }
    summary = {
        "schema_version": 1,
        "study": STUDY,
        "research_status": "execution_complete_source_adjudication_required",
        "cases_completed": len(rows),
        "target_cases": TARGET,
        "zero_agent_cases": zero_agent,
        "groups": [{"surface": name, **groups[name]} for name in sorted(groups)],
        "totals": totals,
        "results": rows,
    }

    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# Pydantic unseen holdout 8 — raw research output",
        "",
        "> Workflow success means the eight pinned scans executed and aggregated. It is not a depth-parity pass. Source adjudication is required.",
        "",
        "| Surface | Cases | Agents | Tools | MCP | Authority rels | Findings |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for group in summary["groups"]:
        lines.append(
            f"| {group['surface']} | {group['cases']} | {group['framework_agents']} | "
            f"{group['tools']} | {group['mcp_servers']} | {group['authority_relationships']} | "
            f"{group['findings']} |"
        )
    lines += [
        "",
        f"- Cases completed: {len(rows)}/{TARGET}",
        f"- Zero-agent cases: {', '.join(zero_agent) if zero_agent else 'none'}",
        f"- Framework agents: {totals['framework_agents']}",
        f"- Tools: {totals['tools']}",
        f"- MCP servers: {totals['mcp_servers']}",
        f"- Authority relationships: {totals['authority_relationships']}",
        f"- Findings: {totals['findings']}",
        "",
        "**Do not treat these counts as accuracy metrics.** Compare each frozen source signal and emitted security assertion against pinned source before changing scanner semantics.",
    ]
    (args.output / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
