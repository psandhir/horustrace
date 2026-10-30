"""Run a pinned Wave-A source scan with passive semantic trace, without target imports."""
from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
import time
from pathlib import Path

from horustrace.scanner import scan
from horustrace.semantic_trace import SemanticTrace
from scripts.verify_accuracy_wave_a_baseline import ROOT, audit

COHORT_PATH = ROOT / "research/accuracy-wave-a-retrospective-20261014/cohort.json"


def _git(*args: str, cwd: Path | None = None) -> str:
    result = subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True,
        text=True, timeout=1200,
    )
    return result.stdout.strip()


def run_case(case_id: str, output_root: Path) -> dict:
    audit(COHORT_PATH, ROOT)
    cohort = json.loads(COHORT_PATH.read_text(encoding="utf-8"))
    rows = [row for row in cohort["cases"] if row["case_id"] == case_id]
    if len(rows) != 1:
        raise ValueError("unknown/duplicate source-pinned case")
    case = rows[0]
    out = output_root / case_id
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="wave-a-source-") as tmp:
        target = Path(tmp) / "repo"
        _git("init", "--quiet", str(target))
        _git("-C", str(target), "remote", "add", "origin",
             f"https://github.com/{case['repo']}.git")
        _git("-C", str(target), "fetch", "--quiet", "--depth=1",
             "--filter=blob:none", "origin", case["sha"])
        _git("-C", str(target), "checkout", "--quiet", "--detach", "FETCH_HEAD")
        if _git("-C", str(target), "rev-parse", "HEAD") != case["sha"]:
            raise ValueError("source SHA checkout mismatch")
        app = (target / case["application_path"]).resolve()
        if not app.is_relative_to(target.resolve()) or not app.exists():
            raise ValueError("frozen application root missing or escapes repository")
        tracer = SemanticTrace(app if app.is_dir() else app.parent)
        start = time.monotonic()
        graph, findings = scan(app, trace=tracer)
        duration = round(time.monotonic() - start, 3)
        report = tracer.as_dict()
        if len(report["stages"]) != 11 or report["events_truncated"]:
            raise ValueError("incomplete/truncated semantic trace")
        output = {
            "schema_version": 1,
            "case_id": case_id,
            "repo": case["repo"],
            "sha": case["sha"],
            "framework": case["framework"],
            "application_path": case["application_path"],
            "duration_seconds": duration,
            "entities": len(graph.agents),
            "tools": len(graph.all_tools()),
            "mcp_servers": len(graph.all_mcp_servers()),
            "skills": len(graph.all_skills()),
            "findings": len(findings),
            "attack_paths": len(graph.attack_paths),
            "pipeline_valid": (graph.coverage.resolution.get("analysis_pipeline") or {}).get("valid"),
            "trace_stage_count": len(report["stages"]),
            "trace_events": len(report["events"]),
            "trace_truncated": report["events_truncated"],
            "diagnostics": len(graph.coverage.diagnostics),
            "assessment": "historical_source_graph_diagnostic_not_blind_accuracy",
        }
        (out / "trace.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (out / "result.json").write_text(
            json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("wave-a-artifacts"))
    args = parser.parse_args()
    print(json.dumps(run_case(args.case_id, args.output_dir), sort_keys=True))


if __name__ == "__main__":
    main()
