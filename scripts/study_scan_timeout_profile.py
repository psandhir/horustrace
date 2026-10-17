"""Source-only profiling for two pinned Wave B scanner timeout regressions.

Uses exact Frozen-180 source revision and existing non-LangGraph checkout scope;
never imports or executes scanned application code. Periodic stack sampling is
diagnostic only and DOES NOT modify the scanner or the 300s release timeout.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from real_world_agent_security_execute import fetch_case, load_json

ALLOWED = {
    "rw-002": "scan",
    "rw-085": "security-graph",
}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--cohort", type=Path, required=True)
    p.add_argument("--case-id", choices=sorted(ALLOWED), required=True)
    p.add_argument("--scanner", type=Path, required=True)
    p.add_argument("--artifacts", type=Path, required=True)
    p.add_argument("--diagnostic-timeout", type=int, default=170)
    args = p.parse_args()
    if args.diagnostic_timeout <= 40 or args.diagnostic_timeout > 300:
        raise ValueError("diagnostic-only limit must be within (40, 300]")
    cohort = load_json(args.cohort)
    if cohort.get("cohort_frozen") is not True or cohort.get("ground_truth_locked") is not True:
        raise ValueError("frozen source reference changed")
    cases = cohort.get("cases", [])
    if len(cases) != 180 or sum(x["framework_stratum"] == "langgraph" for x in cases) != 35:
        raise ValueError("expected immutable Frozen-180, non-LangGraph study subset")
    case = next((c for c in cases if c["case_id"] == args.case_id), None)
    if not case or case["framework_stratum"] == "langgraph":
        raise ValueError("selected case not part of active non-LangGraph source truth")
    output = args.artifacts.resolve()
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="horustrace-wave-b-hotspot-") as work:
        base = Path(work)
        start = time.monotonic()
        primary, authority, err = fetch_case(base, case, tier_c=False)
        fetch_sec = round(time.monotonic() - start, 2)
        if err or primary is None or authority is None:
            raise RuntimeError("exact pinned source retrieval failed: " + str(err))
        root = base / args.case_id
        git_sha = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
        if git_sha != case["sha"]:
            raise ValueError("frozen source pin mismatch")
        trace_dir = base / "trace-hooks"
        trace_dir.mkdir()
        (trace_dir / "sitecustomize.py").write_text(
            "import faulthandler, sys\n"
            "faulthandler.enable(file=sys.stderr)\n"
            "faulthandler.dump_traceback_later(25, repeat=True, file=sys.stderr)\n",
            encoding="utf-8",
        )
        command = ALLOWED[args.case_id]
        scan = [str(args.scanner.resolve()), command, str(primary)]
        if command == "scan":
            scan.extend(["--format", "json", "--fail-on", "none"])
        selected_files = [f for f in primary.rglob("*") if f.is_file() and not f.is_symlink()]
        manifest = {
            "case_id": args.case_id,
            "repo": case["repo"],
            "frozen_source_sha": git_sha,
            "application_path": case["application_path"],
            "framework": case["framework_stratum"],
            "command": command,
            "primary_scope_relative": str(primary.relative_to(root)),
            "authority_scope_relative": str(authority.relative_to(root)),
            "workspace_python_files": len(list(root.rglob("*.py"))),
            "primary_regular_files": len(selected_files),
            "primary_bytes": sum(f.stat().st_size for f in selected_files),
            "pinned_fetch_seconds": fetch_sec,
            "diagnostic_timeout_seconds": args.diagnostic_timeout,
            "release_timeout_unchanged_seconds": 300,
        }
        env = dict(os.environ)
        env["PYTHONPATH"] = str(trace_dir) + os.pathsep + env.get("PYTHONPATH", "")
        stdout_path = output / (args.case_id + "-stdout.json")
        stderr_path = output / (args.case_id + "-stacks.stderr.log")
        started = time.monotonic()
        with stdout_path.open("wb") as out, stderr_path.open("wb") as stderr:
            try:
                run = subprocess.run(
                    scan, stdout=out, stderr=stderr, env=env,
                    timeout=args.diagnostic_timeout, check=False,
                )
                manifest["status"] = "completed"
                manifest["returncode"] = run.returncode
            except subprocess.TimeoutExpired:
                manifest["status"] = "diagnostic_timeout"
                manifest["returncode"] = None
        manifest["elapsed_seconds"] = round(time.monotonic() - started, 2)
        if stdout_path.exists() and stdout_path.stat().st_size > 5_000_000:
            # Never discard full results: they remain in the study workspace
            # but oversized JSON is not needed for timeout stack inspection.
            manifest["stdout_bytes"] = stdout_path.stat().st_size
        manifest["stderr_bytes"] = stderr_path.stat().st_size
        if manifest["status"] == "completed" and manifest["returncode"] in (0, 2):
            try:
                doc = json.loads(stdout_path.read_text(encoding="utf-8"))
                manifest["json_output_valid"] = isinstance(doc, dict)
                if isinstance(doc, dict):
                    topology = doc.get("topology") or {}
                    manifest["topology_node_count"] = len(topology.get("nodes", []))
                    manifest["topology_edge_count"] = len(topology.get("edges", []))
                    coverage = doc.get("coverage")
                    manifest["analysis_incomplete"] = (
                        bool(coverage.get("incomplete")) if isinstance(coverage, dict)
                        else None
                    )
            except (json.JSONDecodeError, UnicodeDecodeError, OSError):
                manifest["json_output_valid"] = False
        (output / (args.case_id + "-profiling.json")).write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(json.dumps(manifest, indent=2))
        print("Last sampled stack frames, if any:", flush=True)
        if stderr_path.exists():
            logs = stderr_path.read_text(encoding="utf-8", errors="replace")
            print(logs[-6500:])
    # Always return 0 for a diagnostic result with evidence; this does not
    # indicate a successful security scan nor alter the Wave B release gate.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
