"""Audit scanner stage contracts for exact-case GitHub Actions study artifacts."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

EXPECTED_STAGES = [
    "discovered",
    "normalized",
    "flows_resolved",
    "attack_paths",
    "adg",
    "findings",
]


def audit_case(scan_doc: dict, case_id: str) -> dict:
    summary = scan_doc.get("summary") or {}
    pipeline = ((scan_doc.get("coverage") or {}).get("resolution") or {}).get(
        "analysis_pipeline"
    )
    issues: list[str] = []
    if not isinstance(pipeline, dict):
        return {"case_id": case_id, "valid": False, "issues": ["missing pipeline contract"]}
    stages = pipeline.get("stages")
    if not isinstance(stages, list):
        return {"case_id": case_id, "valid": False, "issues": ["missing stage records"]}
    observed = [step.get("stage") for step in stages if isinstance(step, dict)]
    if observed != EXPECTED_STAGES:
        issues.append("stage order or completeness mismatch")
    if pipeline.get("schema_version") != 1 or pipeline.get("complete") is not True:
        issues.append("unsupported or incomplete pipeline contract")
    for step in stages:
        if not isinstance(step, dict):
            issues.append("invalid stage record")
            continue
        for error in step.get("issues") or []:
            issues.append(f"{step.get('stage')}: {error}")
    if pipeline.get("valid") is not (len(issues) == 0):
        issues.append("pipeline validity flag disagrees with stage issues")
    if stages and isinstance(stages[-1], dict):
        final = stages[-1]
        for key in ("agents", "attack_paths", "findings"):
            if final.get(key) != summary.get(key):
                issues.append(f"final {key} count differs from scan summary")
    return {"case_id": case_id, "valid": not issues, "issues": sorted(set(issues))}


def audit_study(root: Path) -> dict:
    cases = []
    found = sorted(root.rglob("scan.json"))
    for path in found:
        try:
            cases.append(
                audit_case(json.loads(path.read_text(encoding="utf-8")), path.parent.name)
            )
        except (OSError, ValueError, TypeError) as exc:
            cases.append({"case_id": path.parent.name, "valid": False, "issues": [str(exc)]})
    errors = [
        f"{item['case_id']}: {message}"
        for item in cases
        for message in item["issues"]
    ]
    if not found:
        errors.append("no scan.json files found")
    return {
        "schema_version": 1,
        "cases": sorted(cases, key=lambda item: item["case_id"]),
        "total": len(cases),
        "valid": not errors,
        "errors": errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scans", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = audit_study(args.scans)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Pipeline audit: {report['total']} scan cases, {len(report['errors'])} issues")
    for error in report["errors"]:
        print(" - " + error)
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
