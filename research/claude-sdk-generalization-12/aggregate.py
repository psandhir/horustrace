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

    rows = [json.loads(path.read_text(encoding="utf-8")) for path in sorted(args.input.rglob("result.json"))]
    groups: dict[str, dict[str, int]] = defaultdict(lambda: {"cases": 0, "passes": 0, "agents": 0, "mcp_cases": 0, "delegation_cases": 0, "hooks_cases": 0})
    for row in rows:
        group = groups[row["surface"]]
        group["cases"] += 1
        group["passes"] += int(row.get("coarse_status") == "pass")
        group["agents"] += int((row.get("observed") or {}).get("framework_agents") or 0)
        group["mcp_cases"] += int(bool((row.get("observed") or {}).get("mcp")))
        group["delegation_cases"] += int(bool((row.get("observed") or {}).get("delegation")))
        group["hooks_cases"] += int(bool((row.get("observed") or {}).get("hooks")))

    missed = [row for row in rows if row.get("coarse_status") != "pass"]
    summary = {
        "schema_version": 1,
        "study": "claude-sdk-generalization-12",
        "cases_completed": len(rows),
        "target_cases": 12,
        "coarse_passes": len(rows) - len(missed),
        "coarse_misses": len(missed),
        "zero_framework_agent_cases": [row["case_id"] for row in rows if not (row.get("observed") or {}).get("root")],
        "results": rows,
    }

    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# Claude Agent SDK generalisation 12",
        "",
        "| Case | Repository | Surface | Root | Tools | MCP | Delegation | Hooks | Permission modes | Coarse result | Misses |",
        "|---|---|---|:---:|---:|:---:|:---:|:---:|---|:---:|---|",
    ]
    for row in rows:
        obs = row.get("observed") or {}
        lines.append(
            f"| {row['case_id']} | {row['repo']} | {row['surface']} | "
            f"{'yes' if obs.get('root') else 'NO'} | {obs.get('tool_count', 0)} | "
            f"{'yes' if obs.get('mcp') else 'no'} | {'yes' if obs.get('delegation') else 'no'} | "
            f"{'yes' if obs.get('hooks') else 'no'} | {', '.join(obs.get('permission_modes') or []) or '-'} | "
            f"{row.get('coarse_status')} | {', '.join(row.get('misses') or []) or '-'} |"
        )

    lines += [
        "",
        f"- Cases completed: {len(rows)}/12",
        f"- Coarse structural passes: {len(rows) - len(missed)}/12",
        f"- Zero Claude-framework agent cases: {', '.join(summary['zero_framework_agent_cases']) if summary['zero_framework_agent_cases'] else 'none'}",
        "",
        "## Misses",
        "",
    ]
    if missed:
        for row in missed:
            lines.append(f"- **{row['case_id']} — {row['repo']}**: {', '.join(row.get('misses') or [])}")
    else:
        lines.append("- none")

    lines += [
        "",
        "The coarse result checks only source-derived structural requirements. It is deliberately not a precision/recall score. A pass can still contain partial authority, over-projection, or incorrect findings; source adjudication is still required before changing scanner semantics.",
    ]

    text = "\n".join(lines) + "\n"
    (args.output / "summary.md").write_text(text, encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
