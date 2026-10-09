#!/usr/bin/env python3
"""Pinned historical post-Frozen-180 scanner regression; no LLM/human accuracy claims."""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "evidence" / "post180-three-cohorts-20261009"
SCANNER_SHA = "a1bbdc3a391a1377726ce9d80a8b9b80b633ea51"
RUNNER = ROOT / "research/full-framework-60-20261005/run_case.py"
SOURCES = {
    "holdout10": ROOT / "research/gpt-horustrace-differential-2026/unseen-holdout-adk-pydantic-10-v2-cohort.json",
    "fresh16": ROOT / "research/fresh-unseen-generalization-20/cohort.json",
    "full60": ROOT / "research/full-framework-60-20261005/cohort.json",
}
EXPECTED = {"holdout10": 10, "fresh16": 16, "full60": 60}
KEYS = ("agents", "findings", "attack_paths", "authority_relationships",
        "partially_resolved_authority", "unknown_authority",
        "diagnostics", "unbound_skills")


def prepare(name: str) -> tuple[list[dict], Path]:
    source = SOURCES[name]
    original = json.loads(source.read_text(encoding="utf-8"))
    assert source.exists()
    original_cases = original["cases"]
    if name == "fresh16":
        assert len(original_cases) == 20
        assert sum(x["framework"] == "langgraph" for x in original_cases) == 4
        cases = [dict(x) for x in original_cases if x["framework"] != "langgraph"]
    else:
        cases = [dict(x) for x in original_cases]
    assert len(cases) == EXPECTED[name]
    assert len({x["case_id"] for x in cases}) == len(cases)
    assert all(re.fullmatch(r"[a-f0-9]{40}", x["sha"]) for x in cases)
    assert all(x["framework"] != "langgraph" for x in cases)
    historical_refs = [{"case_id": x["case_id"], "repo": x["repo"],
                        "sha": x["sha"], "framework": x["framework"]}
                       for x in cases]
    # The original holdout and fresh-unseen scanners targeted each repository
    # root, not only its recorded evidence entrypoint.
    if name in {"holdout10", "fresh16"}:
        for case in cases:
            case["evidence_path"] = case.get("evidence_path") or case.get("application_path")
            case["application_path"] = "."
    harness = OUT / name / "_harness"
    harness.mkdir(parents=True, exist_ok=True)
    shutil.copy2(RUNNER, harness / "run_case.py")
    copy = dict(original)
    copy["cases"] = cases
    copy["study"] = "historical-post180-" + name
    (harness / "cohort.json").write_text(json.dumps(copy, indent=2) + "\n")
    (OUT / name / "selection.json").write_text(
        json.dumps({
            "cohort": name,
            "original_manifest": str(source.relative_to(ROOT)),
            "original_case_count": len(original_cases),
            "selected_case_count": len(cases),
            "excluded_langgraph": len(original_cases) - len(cases),
            "scanner_sha": SCANNER_SHA,
            "historical_refs_unchanged": True,
            "scan_scope": "repository-root" if name != "full60" else "original-application-path",
            "case_refs": historical_refs,
            "harness": "full-framework-60 rich evidence runner; derived in scratch only",
            "quality": "historical-regression-only; source-first accuracy not re-adjudicated"
        }, indent=2) + "\n")
    return cases, harness / "run_case.py"


def run_one(name: str, runner: Path, case: dict) -> tuple[str, str | None]:
    case_id = case["case_id"]
    directory = OUT / name / "cases" / case_id
    directory.mkdir(parents=True, exist_ok=True)
    try:
        proc = subprocess.run(
            [sys.executable, str(runner), "--case-id", case_id,
             "--output-dir", str(OUT / name / "cases")],
            cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=2400, check=False,
        )
        (directory / "run.log").write_text(proc.stdout[-30000:], encoding="utf-8")
        if proc.returncode != 0:
            if not (directory / "error.json").exists():
                (directory / "error.json").write_text(json.dumps({
                    "case_id": case_id, "status": "error",
                    "error": "runner exit " + str(proc.returncode),
                    "log_tail": proc.stdout[-3000:]
                }, indent=2) + "\n")
            return case_id, "runner exit " + str(proc.returncode)
        if not (directory / "result.json").exists():
            raise RuntimeError("successful command did not produce result.json")
        result = json.loads((directory / "result.json").read_text())
        assert result["sha"] == case["sha"]
        assert result["repo"] == case["repo"]
        assert result["case_id"] == case_id
        return case_id, None
    except Exception as exc:
        error = str(exc)
        (directory / "error.json").write_text(json.dumps({
            "case_id": case_id, "status": "error", "error": error
        }, indent=2) + "\n")
        return case_id, error


def historical_baseline(name: str) -> dict:
    if name == "holdout10":
        report = (ROOT / "research/gpt-horustrace-differential-2026"
                  / "UNSEEN_HOLDOUT_ADK_PYDANTIC_10_V2_REPORT.md").read_text()
        rows = {}
        for match in re.finditer(
            r"^\|\s*(hold-(?:adk|pyd)-\d{3})\s*\|[^|\n]*\|\s*(\d+)\s*\|\s*(\d+)\s*\|",
            report, re.MULTILINE,
        ):
            rows[match.group(1)] = {"findings": int(match.group(2)),
                                    "attack_paths": int(match.group(3))}
        assert len(rows) == 10, "holdout historical report no longer parsable"
        return {"per_case": rows, "source": "UNSEEN_HOLDOUT_ADK_PYDANTIC_10_V2_REPORT.md",
                "comparable_keys": ["findings", "attack_paths"]}
    if name == "fresh16":
        doc = json.loads((ROOT / "research/fresh-unseen-generalization-20"
                          / "adjudication-summary.json").read_text())
        by_framework = {k: int(v["findings"]) for k, v in doc["frameworks"].items()
                        if k != "langgraph"}
        assert sum(by_framework.values()) == 76
        return {"per_framework_findings": by_framework,
                "source": "adjudication-summary.json (20 cases minus 4 LangGraph cases)",
                "comparable_keys": ["findings"],
                "note": "Historical attack-path totals are not available for the identical 16-case subset; no path comparison claimed."}
    csv_path = ROOT / "research/full-framework-60-post-remediation-20261006/baseline.csv"
    with csv_path.open(newline="", encoding="utf-8") as handle:
        data = {row["case_id"]: {k: int(row[k]) for k in KEYS}
                for row in csv.DictReader(handle)}
    assert len(data) == 60
    return {"per_case": data, "source": str(csv_path.relative_to(ROOT)),
            "comparable_keys": list(KEYS)}


def compare(name: str, cases: list[dict], errors: dict[str, str]) -> dict:
    baseline = historical_baseline(name)
    results = {}
    for c in cases:
        path = OUT / name / "cases" / c["case_id"] / "result.json"
        if path.exists():
            results[c["case_id"]] = json.loads(path.read_text())
    counts = Counter()
    by_framework = defaultdict(Counter)
    for item in results.values():
        for key in KEYS:
            value = int(item.get("counts", {}).get(key) or 0)
            counts[key] += value
            by_framework[item["framework"]][key] += value
    rows = []
    for c in cases:
        case_id = c["case_id"]
        item = results.get(case_id)
        before = baseline.get("per_case", {}).get(case_id)
        after = (item or {}).get("counts")
        delta = ({k: int(after.get(k, 0)) - int(before[k])
                  for k in baseline["comparable_keys"]}
                 if before is not None and after is not None else None)
        rows.append({
            "case_id": case_id, "repo": c["repo"], "sha": c["sha"],
            "framework": c["framework"], "status": "ok" if item is not None else "error",
            "error": errors.get(case_id),
            "before": before, "after": after, "delta": delta
        })
    framework_deltas = {}
    if name == "fresh16":
        for framework, old in baseline["per_framework_findings"].items():
            new = by_framework[framework]["findings"]
            framework_deltas[framework] = {
                "findings_before": old, "findings_after": new,
                "delta": new - old,
            }
    elif name in {"holdout10", "full60"}:
        for metric in baseline["comparable_keys"]:
            old = sum(x[metric] for x in baseline["per_case"].values())
            counts_key = counts[metric]
            framework_deltas[metric] = {
                "before": old, "after": counts_key, "delta": counts_key - old,
            }
    report = {
        "study": "post180-three-cohorts-20261009", "cohort": name,
        "scanner_sha": SCANNER_SHA, "original_baseline": baseline["source"],
        "historical_regression": True, "new_blind_adjudication": False,
        "ground_truth_accuracy_verified": False,
        "cases_expected": len(cases), "cases_succeeded": len(results),
        "cases_failed": len(errors),
        "framework_counts": dict(sorted(Counter(c["framework"] for c in cases).items())),
        "current_totals": dict(counts), "current_by_framework": {
            k: dict(v) for k, v in sorted(by_framework.items())
        },
        "comparison": framework_deltas,
        "baseline_limitations": baseline.get("note"),
        "rows": rows
    }
    directory = OUT / name
    (directory / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    lines = [
        "# Historical post-Frozen-180 regression: " + name, "",
        "- Pinned scanner: " + SCANNER_SHA,
        f"- Successful scans: **{len(results)}/{len(cases)}**",
        "- Original reference: " + baseline["source"],
        "- New blinded precision/recall adjudication: **not performed**",
        "- Source checkouts: original repo + immutable SHA; target code not executed",
        "- LangGraph: excluded",
        "",
        "## Historical comparison", "",
    ]
    if name == "fresh16":
        lines += ["| Framework | Historical findings | Current findings | Delta |",
                  "| --- | ---: | ---: | ---: |"]
        for k, v in sorted(framework_deltas.items()):
            lines.append(f"| {k} | {v['findings_before']} | {v['findings_after']} | {v['delta']:+d} |")
        lines.append("")
        lines.append("Historical 16-case path baseline unavailable: current path count is descriptive only.")
    else:
        lines += ["| Metric | Historical | Current | Delta |",
                  "| --- | ---: | ---: | ---: |"]
        for k, v in framework_deltas.items():
            lines.append(f"| {k} | {v['before']} | {v['after']} | {v['delta']:+d} |")
    lines += ["", "## Repository-level comparison", "",
              "| Case | Repository | Findings change | Attack paths change | Status |",
              "| --- | --- | ---: | ---: | --- |"]
    for row in rows:
        d = row["delta"]
        findings_delta = (f"{d['findings']:+d}" if d and "findings" in d else "n/a")
        paths_delta = (f"{d['attack_paths']:+d}" if d and "attack_paths" in d else "n/a")
        lines.append(f"| {row['case_id']} | {row['repo']} | {findings_delta} | {paths_delta} | {row['status']} |")
    if errors:
        lines += ["", "## Failures"]
        for case_id, error in sorted(errors.items()):
            lines.append("- " + case_id + ": " + error[:400])
    lines += ["", "Volume deltas alone do not establish correctness or a regression; adjudicate changed claims and paths against pinned source before a product-quality judgment.", ""]
    (directory / "report.md").write_text("\n".join(lines), encoding="utf-8")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as handle:
            handle.write("\n".join(lines[:min(len(lines), 28)]) + "\n")
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cohort", choices=list(SOURCES), required=True)
    parser.add_argument("--workers", type=int, default=5)
    args = parser.parse_args()
    assert os.environ.get("PINNED_SCANNER_SHA") == SCANNER_SHA, "pinned scanner SHA not supplied"
    cases, runner = prepare(args.cohort)
    errors = {}
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(run_one, args.cohort, runner, c): c for c in cases}
        for future in as_completed(futures):
            case_id, error = future.result()
            if error:
                errors[case_id] = error
            print(f"{args.cohort}: {case_id}: {'ERROR '+error if error else 'ok'}", flush=True)
    report = compare(args.cohort, cases, errors)
    print(json.dumps({"cohort": args.cohort, "scanned": report["cases_succeeded"],
                      "expected": report["cases_expected"],
                      "errors": len(errors), "counts": report["current_totals"]}, indent=2))
    return 0 if not errors else 2


if __name__ == "__main__":
    raise SystemExit(main())
