"""Locked Fresh-16 paired deterministic / optional-LLM scanner comparison.

This is a *differential scan*, NOT an independently source-adjudicated TP/FP/FN study.
Any novel claims are candidates for manual source inspection, not ground truth.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import tempfile
import time
from collections import Counter
from pathlib import Path

from horustrace.config import load_config
from horustrace.effective_authority import effective_authority_report
from horustrace.llm_semantics import LLMSemanticConfig
from horustrace.scanner import scan

ROOT = Path(__file__).resolve().parents[2]
COHORT = ROOT / "research/fresh-unseen-generalization-20/cohort.json"
EXCLUDED = {"langgraph"}


def run(cmd: list[str], timeout: int = 300) -> str:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode:
        raise RuntimeError(f"{' '.join(cmd[:4])}: {(proc.stderr or proc.stdout)[-1500:]}")
    return proc.stdout.strip()


def cases() -> list[dict]:
    data = json.loads(COHORT.read_text(encoding="utf-8"))
    result = [item for item in data["cases"] if item["framework"] not in EXCLUDED]
    assert len(result) == 16 and len({r["case_id"] for r in result}) == 16
    return result


def location(obj, root: Path) -> dict | None:
    loc = getattr(obj, "location", None)
    if loc is None:
        return None
    path = Path(loc.path)
    try:
        rel = path.resolve().relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        rel = path.name
    return {"path": rel, "line": loc.line, "column": loc.column}


def slim_inventory(graph, root: Path) -> dict:
    agents = []
    for agent in graph.agents:
        agents.append({
            "name": agent.name,
            "framework": agent.metadata.get("framework"),
            "location": location(agent, root),
            "capabilities": sorted(agent.capabilities),
            "tools": [{
                "name": t.name, "kind": t.kind, "location": location(t, root),
                "capabilities": sorted(t.capabilities), "approval": t.approval,
                "guardrails": t.guardrails,
                "destinations": sorted({d.target for d in t.destinations}),
                "resources": sorted({str(r.selector) for r in t.resources}),
                "semantic_origin": t.metadata.get("semantic_origin"),
                "semantic_confidence": t.metadata.get("semantic_confidence"),
                "semantic_evidence": t.metadata.get("semantic_evidence", []),
            } for t in agent.tools],
            "mcp_servers": [{
                "name": m.name, "transport": m.transport, "url": m.url,
                "command": m.command, "allowed_tools": list(m.allowed_tools),
                "location": location(m, root),
                "semantic_confidence": m.metadata.get("semantic_confidence"),
            } for m in agent.mcp_servers],
            "skills": [{
                "name": s.name, "location": location(s, root),
                "capabilities": sorted(s.capabilities),
                "semantic": s.metadata.get("llm_security_semantics"),
            } for s in agent.skills],
            "identities": [{
                "name": i.name, "provider": i.provider
            } for i in agent.identities],
        })
    return {
        "agents": agents,
        "unbound_tools": sorted(t.name for t in graph.unbound_tools),
        "unbound_mcp": sorted(m.name for m in graph.unbound_mcp_servers),
        "unbound_skills": sorted(s.name for s in graph.unbound_skills),
        "identities": sorted(i.name for i in graph.all_identities()),
    }


def serialize(graph, findings, root: Path) -> dict:
    inv = slim_inventory(graph, root)
    adg = graph.adg.as_dict()
    authority = effective_authority_report(graph)
    paths = [{
        "path_id": p.path_id, "agent": p.agent,
        "title": p.title, "nodes": p.nodes,
        "severity": p.severity.label(),
        "metadata": p.metadata,
    } for p in graph.attack_paths]
    finding_items = []
    for f in findings:
        finding_items.append({
            "fingerprint": f.fingerprint,
            "rule_id": f.rule_id, "agent": f.agent, "title": f.title,
            "severity": f.severity.label(), "source_context": f.source_context,
            "location": location(f, root), "evidence": list(f.evidence),
            "provenance": [p.as_dict() for p in f.provenance],
            "limitations": list(f.limitations),
        })
    counts = {
        "agents": len(graph.agents),
        "tools_bound": sum(len(a.tools) for a in graph.agents),
        "tools_unbound": len(graph.unbound_tools),
        "mcp_bound": sum(len(a.mcp_servers) for a in graph.agents),
        "mcp_unbound": len(graph.unbound_mcp_servers),
        "skills_bound": sum(len(a.skills) for a in graph.agents),
        "skills_unbound": len(graph.unbound_skills),
        "identities": len(graph.all_identities()),
        "adg_nodes": len(adg["nodes"]),
        "adg_edges": len(adg["edges"]),
        "authority_relationships": len(authority["relationships"]),
        "findings": len(finding_items),
        "attack_paths": len(paths),
    }
    return {
        "counts": counts,
        "adg_node_kinds": adg["summary"]["node_kinds"],
        "adg_edge_kinds": adg["summary"]["edge_kinds"],
        "inventory": inv, "adg": adg,
        "authority": authority["relationships"],
        "findings": finding_items,
        "attack_paths": paths,
        "coverage": graph.coverage.as_dict(),
        "semantic_stats": {
            "tools": graph.coverage.resolution.get("semantic_llm", {}),
            "skills": graph.coverage.resolution.get("skill_semantic_llm", {}),
        },
    }


def stable_key(kind: str, item: dict) -> str:
    if kind in {"nodes", "edges"}:
        return str(item.get("id"))
    if kind == "authority":
        # Identify the same conceptual relationship even if metadata changes.
        target = item.get("target") or {}
        loc = item.get("location") or {}
        return "|".join(str(x) for x in (
            item.get("agent"), target.get("kind"), target.get("name"),
            loc.get("path"), loc.get("line"), item.get("source_context")
        ))
    if kind == "findings":
        return str(item.get("fingerprint") or (
            item.get("rule_id"), item.get("agent"), item.get("location")
        ))
    return str((item.get("agent"), item.get("path_id"), item.get("title")))


def diff_items(kind: str, before: list[dict], after: list[dict]) -> dict:
    b = {stable_key(kind, x): x for x in before}
    a = {stable_key(kind, x): x for x in after}
    added = sorted(set(a) - set(b))
    removed = sorted(set(b) - set(a))
    changed = sorted(k for k in set(a) & set(b)
                     if json.dumps(a[k], sort_keys=True, default=str)
                     != json.dumps(b[k], sort_keys=True, default=str))
    return {
        "added": [a[k] for k in added],
        "removed": [b[k] for k in removed],
        "modified": [{"before": b[k], "after": a[k]} for k in changed],
        "counts": {"added": len(added), "removed": len(removed),
                   "modified": len(changed)},
    }


def paired_diff(b: dict, h: dict) -> dict:
    return {
        "count_delta": {k: h["counts"][k] - v for k, v in b["counts"].items()},
        "adg_nodes": diff_items("nodes", b["adg"]["nodes"], h["adg"]["nodes"]),
        "adg_edges": diff_items("edges", b["adg"]["edges"], h["adg"]["edges"]),
        "authority": diff_items("authority", b["authority"], h["authority"]),
        "findings": diff_items("findings", b["findings"], h["findings"]),
        "attack_paths": diff_items("paths", b["attack_paths"], h["attack_paths"]),
    }


def compare_case(case_id: str, output_dir: Path) -> None:
    case = next(c for c in cases() if c["case_id"] == case_id)
    output_dir.mkdir(parents=True, exist_ok=True)
    record = {
        "case_id": case_id, "repository": case["repo"], "sha": case["sha"],
        "framework": case["framework"], "mode": "same SHA, baseline then hybrid",
        "evidence_path": case.get("evidence_path"), "state": "error",
    }
    started = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix="horustrace-f16-") as td:
            repo = Path(td) / "target"
            run(["git", "init", "-q", str(repo)])
            run(["git", "-C", str(repo), "remote", "add",
                 "origin", f"https://github.com/{case['repo']}.git"])
            run(["git", "-C", str(repo), "fetch", "--quiet", "--depth=1",
                 "--filter=blob:none", "origin", case["sha"]], timeout=480)
            run(["git", "-C", str(repo), "checkout", "--quiet", "--detach",
                 "FETCH_HEAD"])
            got = run(["git", "-C", str(repo), "rev-parse", "HEAD"])
            if got != case["sha"]:
                raise RuntimeError(f"SHA mismatch {got} != {case['sha']}")
            config = load_config(repo)
            baseline_graph, baseline_findings = scan(repo, config=config)
            cache = Path(td) / "llm-cache.json"
            hybrid_graph, hybrid_findings = scan(
                repo, config=config,
                llm_semantic_config=LLMSemanticConfig(
                    provider=os.environ.get("SEMANTIC_PROVIDER", "copilot"),
                    model=os.environ.get("SEMANTIC_MODEL", "auto"),
                    max_candidates=3, max_slice_chars=8000,
                    max_total_chars=24000, min_confidence=0.75,
                    max_retries=2, cache_path=cache, fail_open=True,
                ),
            )
            baseline = serialize(baseline_graph, baseline_findings, repo)
            hybrid = serialize(hybrid_graph, hybrid_findings, repo)
            record.update({
                "state": "complete", "baseline": baseline, "hybrid": hybrid,
                "diff": paired_diff(baseline, hybrid),
                "note": "TP/FP/FN cannot be inferred from these deltas alone.",
            })
    except Exception as exc:
        record["error"] = f"{type(exc).__name__}: {exc}"
    record["duration_seconds"] = round(time.monotonic() - started, 1)
    (output_dir / "result.json").write_text(
        json.dumps(record, indent=2, default=str) + "\n", encoding="utf-8"
    )
    print(json.dumps({"case": case_id, "state": record["state"],
                      "counts": record.get("diff", {}).get("count_delta"),
                      "errors": record.get("error")}, indent=2))


def aggregate(result_dir: Path, output_dir: Path) -> int:
    output_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    for case in cases():
        path = result_dir / case["case_id"] / "result.json"
        if not path.exists():
            rows.append({"case_id": case["case_id"], "state": "missing_artifact"})
        else:
            rows.append(json.loads(path.read_text(encoding="utf-8")))
    totals = {"baseline": Counter(), "hybrid": Counter()}
    llm = Counter()
    changed = Counter()
    details = []
    failures = []
    for row in rows:
        if row["state"] != "complete":
            failures.append({"case": row["case_id"], "error": row.get("error", row["state"])})
            continue
        for mode in ("baseline", "hybrid"):
            totals[mode].update(row[mode]["counts"])
        for phase in ("tools", "skills"):
            stats = row["hybrid"]["semantic_stats"][phase]
            for key in ("eligible_candidates", "eligible_skills", "selected_candidates",
                        "selected_skills", "escalated", "applied", "errors",
                        "low_confidence", "cache_hits", "input_chars", "skipped_budget"):
                llm[f"{phase}_{key}"] += int(stats.get(key, 0))
        for section in ("adg_nodes", "adg_edges", "authority", "findings", "attack_paths"):
            for k, v in row["diff"][section]["counts"].items():
                changed[f"{section}_{k}"] += v
        details.append(row)
    report = {
        "study": "Fresh16 paired deterministic versus opt-in LLM scan",
        "cohort": "research/fresh-unseen-generalization-20/cohort.json, excluding LangGraph",
        "cases_expected": 16, "cases_completed": len(details),
        "cases_failed": failures,
        "configuration": {"provider": os.environ.get("SEMANTIC_PROVIDER", "copilot"),
                          "model": os.environ.get("SEMANTIC_MODEL", "auto"),
                          "max_candidates_per_phase": 3,
                          "max_slice_chars": 8000, "max_total_chars_per_phase": 24000,
                          "min_confidence": 0.75},
        "baseline_totals": dict(totals["baseline"]),
        "hybrid_totals": dict(totals["hybrid"]),
        "delta": {k: totals["hybrid"][k] - v for k, v in totals["baseline"].items()},
        "llm": dict(llm), "claim_changes": dict(changed),
        "cases": [{k: v for k, v in row.items()
                   if k in {"case_id", "repository", "sha", "framework", "state",
                            "error", "diff", "duration_seconds", "hybrid"}}
                  for row in details],
        "accuracy_warning": ("No independent source-grounded TP/FP/FN labels; "
                             "changed finding/path counts do not establish recall or precision."),
    }
    (output_dir / "comparison.json").write_text(
        json.dumps(report, indent=2, default=str) + "\n", encoding="utf-8")
    keys = ["agents", "tools_bound", "mcp_bound", "skills_bound", "identities",
            "adg_nodes", "adg_edges", "authority_relationships", "findings", "attack_paths"]
    lines = [
        "# Fresh-16: deterministic versus hybrid LLM comparison", "",
        f"Cases: {len(details)}/16 complete; errors: {len(failures)}.",
        "Same pinned source SHA and scanner revision for both modes.",
        "Hybrid: Copilot auto, 3 candidates/phase, 8k chars/slice, 24k chars/phase, confidence ≥0.75.", "",
        "## Aggregate (detection counts, **not** accuracy metrics)", "",
        "| Dimension | Deterministic | Hybrid | Delta |",
        "|---|---:|---:|---:|",
    ]
    for k in keys:
        a, b = totals["baseline"][k], totals["hybrid"][k]
        lines.append(f"| {k} | {a} | {b} | {b-a:+} |")
    lines += ["", "## LLM execution observability", "",
              f"- Tool semantic calls: {llm['tools_escalated']}; applied: {llm['tools_applied']}; errors: {llm['tools_errors']}.",
              f"- Skill semantic calls: {llm['skills_escalated']}; applied: {llm['skills_applied']}; errors: {llm['skills_errors']}.",
              f"- Source input chars: {llm['tools_input_chars'] + llm['skills_input_chars']}.",
              "", "## Per-case counts", "",
              "| Case | Framework | Agents D→H | Tools D→H | MCP D→H | Skills D→H | Edges D→H | Findings D→H | Paths D→H | LLM calls |",
              "|---|---|---|---|---|---|---|---|---|---:|"]
    for row in details:
        b, h = row["baseline"]["counts"], row["hybrid"]["counts"]
        cell = lambda k: f"{b[k]}→{h[k]}"
        stats = row["hybrid"]["semantic_stats"]
        calls = sum(int(stats[p].get("escalated", 0)) for p in ("tools", "skills"))
        lines.append(f"| {row['case_id']} | {row['framework']} | {cell('agents')} | "
                     f"{cell('tools_bound')} | {cell('mcp_bound')} | "
                     f"{cell('skills_bound')} | {cell('adg_edges')} | "
                     f"{cell('findings')} | {cell('attack_paths')} | {calls} |")
    lines += ["", "## Source-adjudication queue (NOT confirmed true/false positives)", ""]
    for k in ("adg_nodes", "adg_edges", "authority", "findings", "attack_paths"):
        lines.append(f"- {k}: +{changed[k+'_added']} / -{changed[k+'_removed']} / "
                     f"~{changed[k+'_modified']} changed records.")
    lines += ["", "Independent adjudication of introduced, removed, and changed claims "
              "against pinned source is required before any accuracy conclusion.",
              "Full source-aligned records and model errors are in comparison.json.", ""]
    if failures:
        lines += ["## Failed cases", ""]
        lines += [f"- {x['case']}: {x['error']}" for x in failures]
    (output_dir / "COMPARISON.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    # Mark incomplete or zero-LLM studies as invalid; never imply hybrid ran.
    if failures or len(details) != 16 or (
        llm["tools_escalated"] + llm["skills_escalated"] == 0
    ):
        return 1
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    case_parser = sub.add_parser("case")
    case_parser.add_argument("--case-id", required=True)
    case_parser.add_argument("--output-dir", type=Path, required=True)
    agg_parser = sub.add_parser("aggregate")
    agg_parser.add_argument("--result-dir", type=Path, required=True)
    agg_parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "case":
        compare_case(args.case_id, args.output_dir)
    else:
        raise SystemExit(aggregate(args.result_dir, args.output_dir))
