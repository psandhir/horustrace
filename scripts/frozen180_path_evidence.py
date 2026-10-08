"""Recover exact per-path scanner records that frozen-180 replay omitted.

This is coordinator-only scanner data; NEVER present to source-blind Phase-A
judges. Original sources and source-reference truth are not modified.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import re
import shutil
import subprocess
import tempfile
from collections import Counter
from pathlib import Path

from scripts.real_world_agent_security_execute import fetch_case

ROOT = Path("research/real-world-agent-security-2026")


def collect_one(case: dict, expected_paths: int, scanner: str,
                work: Path, dest: Path, tier_c: bool) -> dict:
    cid = case["case_id"]
    result = {"case_id": cid, "repo": case["repo"], "sha": case["sha"],
              "framework": case["framework_stratum"],
              "expected_historical_attack_paths": expected_paths,
              "status": "failed", "error": None}
    try:
        scope, _authority, fetch_error = fetch_case(work, case, tier_c=tier_c)
        if fetch_error or scope is None:
            raise RuntimeError(f"source fetch failed: {fetch_error}")
        cmd = [scanner, "security-graph", str(scope)]
        if tier_c:
            cmd.extend(["--authority-source", str(work / cid)])
        proc = subprocess.run(cmd, text=True, capture_output=True, timeout=360, check=False)
        if proc.returncode not in {0, 2}:
            raise RuntimeError(f"graph exit {proc.returncode}: {proc.stderr[-1500:]}")
        graph = json.loads(proc.stdout)
        scan_cmd = [scanner, "scan", str(scope), "--format", "json", "--fail-on", "none"]
        if tier_c:
            scan_cmd.extend(["--authority-source", str(work / cid)])
        scan_proc = subprocess.run(scan_cmd, text=True, capture_output=True,
                                   timeout=360, check=False)
        if scan_proc.returncode not in {0, 2}:
            raise RuntimeError(f"scan exit {scan_proc.returncode}: {scan_proc.stderr[-1500:]}")
        scan = json.loads(scan_proc.stdout)
        out = dest / cid
        out.mkdir(parents=True, exist_ok=True)
        (out / "security-graph.json").write_text(json.dumps(graph, indent=2) + "\n")
        (out / "scan.json").write_text(json.dumps(scan, indent=2) + "\n")
        records = graph.get("attack_paths") if isinstance(graph, dict) else None
        if not isinstance(records, list):
            records = scan.get("attack_paths") if isinstance(scan, dict) else None
        if not isinstance(records, list):
            records = []
        result.update({
            "status": "ok", "recovered_path_records": len(records),
            "parity_with_historical_count": len(records) == expected_paths,
            "scanner_evidence_review_status": "not_adjudicated",
            "scanner_result_sections": sorted(scan.keys()),
            "graph_sections": sorted(graph.keys()),
        })
    except Exception as exc:
        result["error"] = str(exc)
    return result


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--historical-result", type=Path, required=True)
    p.add_argument("--scanner", default="horustrace")
    p.add_argument("--scanner-sha", required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--workers", type=int, default=4)
    args = p.parse_args()
    if re.fullmatch(r"[0-9a-f]{40}", args.scanner_sha) is None:
        raise SystemExit("scanner_sha must be a full commit SHA")
    original = json.loads(args.historical_result.read_text())
    frozen = json.loads((ROOT / "cohort.json").read_text())
    if (original.get("study") != frozen["study"] or
            original.get("scanner_sha") != args.scanner_sha or
            len(frozen["cases"]) != 180):
        raise SystemExit("historical run / scanner / cohort mismatched")
    case_by_id = {c["case_id"]: c for c in frozen["cases"]}
    targets = []
    for case in original["cases"]:
        if case["framework"] == "langgraph":
            continue
        count = case["observed"]["attack_paths"]
        if count:
            targets.append((case_by_id[case["case_id"]], count))
    if len(targets) != 17 or sum(p for _, p in targets) != 45:
        raise SystemExit("expected 17 cases containing 45 scanner attack paths")
    args.output.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="horusscan-path-review-"))
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(args.workers, 8))) as exe:
            futures = [exe.submit(collect_one, c, count, args.scanner, work, args.output,
                                  c["case_id"] in frozen["tier_c_case_ids"])
                       for c, count in targets]
            records = [future.result() for future in concurrent.futures.as_completed(futures)]
    finally:
        shutil.rmtree(work, ignore_errors=True)
    records.sort(key=lambda x: x["case_id"])
    report = {
        "schema_version": 1, "type": "coordinator_only_scanner_path_reconstruction",
        "scanner_sha": args.scanner_sha,
        "historical_cohort": frozen["study"],
        "deprecated_langgraph_excluded": 35,
        "attack_paths_in_legacy_result": sum(n for _, n in targets),
        "source_case_count": len(targets),
        "status_counts": dict(Counter(c["status"] for c in records)),
        "parity_cases": sum(c.get("parity_with_historical_count") is True for c in records),
        "llm_adjudication": "not_performed",
        "cases": records,
    }
    (args.output / "manifest.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: report[k] for k in
                      ("attack_paths_in_legacy_result", "status_counts", "parity_cases")}))
    return 0 if all(c["status"] == "ok" and c["parity_with_historical_count"]
                    for c in records) else 2


if __name__ == "__main__":
    raise SystemExit(main())
