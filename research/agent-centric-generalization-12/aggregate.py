from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()

    rows = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(args.input.rglob("result.json"))]
    groups: dict[str, dict[str, int]] = defaultdict(lambda: {"repos": 0, "agents": 0, "findings": 0, "attack_paths": 0})
    for row in rows:
        g = groups[row["framework"]]
        g["repos"] += 1
        for key in ("agents", "findings", "attack_paths"):
            g[key] += int((row.get("counts") or {}).get(key, 0))

    summary = {
        "schema_version": 1,
        "study": "agent-centric-generalization-12",
        "cases": len(rows),
        "groups": [{"framework": k, **groups[k]} for k in sorted(groups)],
        "results": rows,
    }
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# Agent-centric generalization 12",
        "",
        "| Framework | Repos | Agents | Findings | Attack paths |",
        "|---|---:|---:|---:|---:|",
    ]
    for g in summary["groups"]:
        lines.append(f"| {g['framework']} | {g['repos']} | {g['agents']} | {g['findings']} | {g['attack_paths']} |")
    lines += [
        "",
        f"- Cases completed: {len(rows)}/12",
        f"- Findings: {sum((r.get('counts') or {}).get('findings', 0) for r in rows)}",
        f"- Attack paths: {sum((r.get('counts') or {}).get('attack_paths', 0) for r in rows)}",
        "",
        "Precision is evaluated against the persisted #290 claim adjudication for the same frozen cases, then any changed/new claims are source-reviewed separately.",
    ]
    (args.output / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
