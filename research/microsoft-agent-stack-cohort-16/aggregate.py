from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


def load_rows(root: Path) -> list[dict[str, Any]]:
    return [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(root.rglob("result.json"))
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    rows = load_rows(args.input)
    args.output.mkdir(parents=True, exist_ok=True)

    groups: dict[str, dict[str, int]] = defaultdict(
        lambda: {
            "repos": 0,
            "scan_ok": 0,
            "agents": 0,
            "expected_framework_agents": 0,
            "tools": 0,
            "bound_mcp_servers": 0,
            "findings": 0,
            "attack_paths": 0,
        }
    )
    for row in rows:
        group = groups[row["stack"]]
        group["repos"] += 1
        group["scan_ok"] += int(row.get("scan") == "ok")
        counts = row.get("counts") or {}
        for key in (
            "agents",
            "expected_framework_agents",
            "tools",
            "bound_mcp_servers",
            "findings",
            "attack_paths",
        ):
            group[key] += int(counts.get(key, 0) or 0)

    scored = [row for row in rows if row.get("scored_p0")]
    discovery = [row for row in rows if not row.get("scored_p0")]
    scored_ok = [row for row in scored if row.get("scan") == "ok"]
    structural_passes = [
        row for row in scored
        if row.get("structural_p0_detection_pass") is True
    ]

    summary = {
        "schema_version": 1,
        "study": "microsoft-agent-stack-cohort-16",
        "cases_completed": len(rows),
        "scored_p0_cases": len(scored),
        "discovery_cases": len(discovery),
        "scored_scan_ok": len(scored_ok),
        "scored_structural_detection_passes": len(structural_passes),
        "scored_structural_detection_rate": (
            len(structural_passes) / len(scored) if scored else None
        ),
        "groups": [
            {"stack": stack, **groups[stack]} for stack in sorted(groups)
        ],
        "results": rows,
        "interpretation_guardrail": (
            "Structural detection is only an initial gate. It is not precision, "
            "recall, or effective-authority accuracy. Source adjudication of "
            "agents, tools, MCP bindings, destinations, identities and authority "
            "is required before making accuracy claims."
        ),
    }
    (args.output / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n",
        encoding="utf-8",
    )

    lines = [
        "# Microsoft agent stack cohort 16 — scanner reveal",
        "",
        "## Structural gate",
        "",
        f"- Cases completed: {len(rows)}/16",
        f"- Scored P0 cases: {len(scored)}",
        f"- Scored scans completed: {len(scored_ok)}/{len(scored)}",
        (
            "- Scored cases with at least the frozen minimum number of "
            f"expected-framework agents: {len(structural_passes)}/{len(scored)}"
        ),
        "",
        "| Case | Stack | Scope | Scan | Expected-framework agents | Tools | Bound MCP | Findings | Paths |",
        "|---|---|---|---|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        counts = row.get("counts") or {}
        scope = "P0 scored" if row.get("scored_p0") else "discovery"
        lines.append(
            f"| {row['case_id']} | {row['stack']} | {scope} | "
            f"{row.get('scan', 'unknown')} | "
            f"{counts.get('expected_framework_agents', 0)} | "
            f"{counts.get('tools', 0)} | "
            f"{counts.get('bound_mcp_servers', 0)} | "
            f"{counts.get('findings', 0)} | "
            f"{counts.get('attack_paths', 0)} |"
        )

    lines += [
        "",
        "## Stack totals",
        "",
        "| Stack | Repos | Scan OK | Agents | Expected-framework agents | Tools | Bound MCP | Findings | Paths |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for group in summary["groups"]:
        lines.append(
            f"| {group['stack']} | {group['repos']} | {group['scan_ok']} | "
            f"{group['agents']} | {group['expected_framework_agents']} | "
            f"{group['tools']} | {group['bound_mcp_servers']} | "
            f"{group['findings']} | {group['attack_paths']} |"
        )

    lines += [
        "",
        "## Interpretation",
        "",
        "This reveal answers whether HorusTrace can structurally discover the frozen Microsoft P0 cohort and what it emits. It does **not** establish precision/recall or effective-authority correctness. The next step is source adjudication against the frozen evidence and source packs, including false positives, missed tools/MCP, delegation, hosted/provider authority, identity, and destinations.",
    ]
    markdown = "\n".join(lines) + "\n"
    (args.output / "summary.md").write_text(markdown, encoding="utf-8")
    print(markdown)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
