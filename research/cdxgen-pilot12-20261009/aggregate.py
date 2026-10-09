"""Aggregate paired inventory results without inventing precision or recall."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    results = []
    for path in sorted(args.input.rglob("result.json")):
        try:
            results.append(json.loads(path.read_text(encoding="utf-8")))
        except Exception as exc:
            results.append({"case_id": str(path.parent.name), "status": "unreadable", "error": str(exc)})
    states = Counter(str(x.get("status")) for x in results)
    cases = []
    for result in sorted(results, key=lambda x: str(x.get("case_id") or "")):
        horus = result.get("horusscan") or {}
        cx = result.get("cdxgen") or {}
        counts = horus.get("counts") or {}
        cases.append({
            "case_id": result.get("case_id"),
            "framework": result.get("framework"),
            "repo": result.get("repo"),
            "sha": result.get("sha"),
            "application_path": result.get("application_path"),
            "status": result.get("status"),
            "horusscan_status": horus.get("status", "missing"),
            "horusscan_counts": counts,
            "cdxgen": {m: {
                "status": (cx.get(m) or {}).get("status", "missing"),
                "components": (cx.get(m) or {}).get("components"),
                "services": (cx.get(m) or {}).get("services"),
                "dependencies": (cx.get(m) or {}).get("dependencies"),
                "component_types": (cx.get(m) or {}).get("component_types") or {},
            } for m in ("ai", "mcp", "ai-skill")},
            "error": result.get("error") or horus.get("error"),
        })
    summary = {
        "study": "cdxgen-pilot12-20261009",
        "expected": 12,
        "collected": len(results),
        "status_counts": dict(states),
        "cases": cases,
        "comparison_status": "inventory quantities only; source-backed adjudication required",
        "critical_limits": [
            "BOM components across project modes may duplicate or overlap.",
            "HorusScan entities/edges and cdxgen component types are not directly interchangeable.",
            "Raw per-mode observations and scanner graph must be adjudicated at source lines before FP/FN.",
            "Scanning uses fixed repository SHAs but whichever HorusScan revision is checked out in the workflow.",
            "No AI runtime exploitability or control effectiveness is claimed.",
        ],
    }
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# cdxgen vs HorusScan — pinned 12-repository pilot",
        "",
        f"- Cases collected: **{len(results)}/12**",
        f"- Fully complete: **{states.get('complete', 0)}/12**",
        "- cdxgen version: **13.3.0**; three source-only project modes: ai, mcp, ai-skill",
        "- Source roots and SHAs: inherited without changes from the independent pilot cohort manifest",
        "",
        "## Unadjudicated inventory-level outputs",
        "",
        "| Case | Framework | Horus agents | Tools | MCP bindings | Skill bindings | Findings | Paths | cdxgen AI components | MCP components | Skill-mode components | State |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for case in cases:
        hc = case["horusscan_counts"]
        cx = case["cdxgen"]
        def fmt(mode: str) -> str:
            return str(cx[mode]["components"]) if cx[mode]["status"] == "ok" else "ERR"
        lines.append(
            f"| {case['case_id']} | {case['framework']} | {hc.get('agents', '—')} | "
            f"{hc.get('tools', '—')} | {hc.get('mcp_bindings', '—')} | "
            f"{hc.get('skill_bindings', '—')} | {hc.get('findings', '—')} | "
            f"{hc.get('attack_paths', '—')} | {fmt('ai')} | {fmt('mcp')} | "
            f"{fmt('ai-skill')} | {case['status']} |"
        )
    lines += [
        "",
        "These numbers are NOT detection accuracy or an entity-by-entity comparison. "
        "cdxgen columns count CycloneDX components in each scan mode, not agent, "
        "MCP or skill bindings. The full BOMs, observations and HorusScan graph "
        "are retained in case artifacts for source adjudication.",
        "",
        "## Execution issues",
        "",
    ]
    problems = [x for x in cases if x["status"] != "complete"]
    lines += [
        f"- {x['case_id']}: {x.get('error') or 'See case logs and per-mode statuses'}"
        for x in problems
    ] or ["- None"]
    lines += [
        "",
        "## Follow-on matching",
        "",
        "Perform source-backed identity and relationship matching across agents, models, "
        "tools, MCP servers, skills, capabilities, identities, resources, destinations "
        "and controls. Findings and attack paths are HorusScan security assessments, "
        "not expected cdxgen BOM fields. Classify each difference as supported, "
        "unsupported, ambiguous or scope-excluded before proposing fixes.",
        "",
    ]
    (args.output / "summary.md").write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines[:6]))
    return 0 if len(results) == 12 and states.get("complete", 0) == 12 else 1


if __name__ == "__main__":
    raise SystemExit(main())
