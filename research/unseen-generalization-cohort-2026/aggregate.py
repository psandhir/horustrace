from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path


def ratio(num: int, den: int):
    return round(num / den, 4) if den else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--adjudication", type=Path, default=Path(__file__).with_name("adjudication-summary.json"))
    args = ap.parse_args()

    rows = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(args.input.rglob("result.json"))]
    families = defaultdict(lambda: {"repos": 0, "findings": 0, "paths": 0, "nodes": 0})
    for row in rows:
        g = families[row["family"]]
        g["repos"] += 1
        g["findings"] += row["finding_count"]
        g["paths"] += row["path_count"]
        g["nodes"] += row["node_count"]

    adjudication = None
    if args.adjudication.exists():
        adjudication = json.loads(args.adjudication.read_text(encoding="utf-8"))
        c = adjudication.get("finding_verdicts", {})
        tp, partial, fp, unresolved = (int(c.get(k, 0)) for k in ("true_positive", "partial", "false_positive", "unresolved"))
        resolved = tp + partial + fp
        adjudication["finding_precision_strict"] = ratio(tp, resolved)
        adjudication["finding_precision_supported"] = ratio(tp + partial, resolved)
        adjudication["finding_fp_rate"] = ratio(fp, resolved)

    output = {
        "schema_version": 1,
        "study": "unseen-generalization-cohort-2026",
        "cases": len(rows),
        "families": dict(sorted(families.items())),
        "totals": {
            "findings": sum(r["finding_count"] for r in rows),
            "paths": sum(r["path_count"] for r in rows),
            "nodes": sum(r["node_count"] for r in rows),
        },
        "adjudication": adjudication,
        "results": rows,
    }
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "summary.json").write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")

    lines = ["# Unseen generalization cohort", "", "| Family | Repos | Findings | Paths | Nodes |", "|---|---:|---:|---:|---:|"]
    for family, g in sorted(families.items()):
        lines.append(f"| {family} | {g['repos']} | {g['findings']} | {g['paths']} | {g['nodes']} |")
    lines += ["", f"Total cases: **{len(rows)}**.", f"Total findings: **{output['totals']['findings']}**.", f"Total attack paths: **{output['totals']['paths']}**."]
    if adjudication:
        lines += ["", "## Source adjudication", "", f"- Strict precision: {adjudication['finding_precision_strict']:.1%}", f"- Materially-supported precision: {adjudication['finding_precision_supported']:.1%}", f"- Explicit FP rate: {adjudication['finding_fp_rate']:.1%}"]
    else:
        lines += ["", "Source adjudication: **pending**."]
    (args.output / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
