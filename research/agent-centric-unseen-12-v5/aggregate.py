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
    groups: dict[str, dict[str, int]] = defaultdict(
        lambda: {"repos": 0, "agents": 0, "findings": 0, "attack_paths": 0, "authority_relationships": 0}
    )
    for row in rows:
        g = groups[row["framework"]]
        g["repos"] += 1
        for key in ("agents", "findings", "attack_paths", "authority_relationships"):
            g[key] += int((row.get("counts") or {}).get(key, 0))

    summary = {
        "schema_version": 1,
        "study": "agent-centric-unseen-12-v5",
        "cases": len(rows),
        "groups": [{"framework": k, **groups[k]} for k in sorted(groups)],
        "results": rows,
    }
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# Agent-centric unseen 12 v5",
        "",
        "| Framework | Repos | Agents | Authority relationships | Findings | Attack paths |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for g in summary["groups"]:
        lines.append(
            f"| {g['framework']} | {g['repos']} | {g['agents']} | {g['authority_relationships']} | {g['findings']} | {g['attack_paths']} |"
        )
    lines += [
        "",
        f"- Cases completed: {len(rows)}/12",
        f"- Findings: {sum((r.get('counts') or {}).get('findings', 0) for r in rows)}",
        f"- Attack paths: {sum((r.get('counts') or {}).get('attack_paths', 0) for r in rows)}",
        f"- Authority relationships: {sum((r.get('counts') or {}).get('authority_relationships', 0) for r in rows)}",
        "",
        "Fresh blind cohort. Findings and attack paths require source adjudication; recall is reviewed separately against source-visible authority.",
    ]
    (args.output / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
