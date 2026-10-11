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


def audit_study(root: Path, *, expected_cases: set[str] | None = None) -> dict:
    cases = []
    found = sorted(root.rglob("scan.json"))
    seen: set[str] = set()
    duplicates: list[str] = []
    for path in found:
        case_id = path.parent.name
        # Actions download-artifact nests case data in a named artifact directory.
        # Use exact case IDs from the pinned manifest rather than artifact labels.
        if case_id.startswith("ff60-post-case-"):
            case_id = case_id[len("ff60-post-case-"):]
        if case_id in seen:
            duplicates.append(case_id)
        seen.add(case_id)
        try:
            cases.append(
                audit_case(json.loads(path.read_text(encoding="utf-8")), case_id)
            )
        except (OSError, ValueError, TypeError) as exc:
            cases.append({"case_id": case_id, "valid": False, "issues": [str(exc)]})
    errors = [
        f"{item['case_id']}: {message}"
        for item in cases
        for message in item["issues"]
    ]
    if not found:
        errors.append("no scan.json files found")
    if duplicates:
        errors.append("duplicate case IDs: " + ", ".join(sorted(set(duplicates))))
    if expected_cases is not None:
        missing = expected_cases - seen
        extra = seen - expected_cases
        if missing:
            errors.append("missing cases: " + ", ".join(sorted(missing)))
        if extra:
            errors.append("unexpected cases: " + ", ".join(sorted(extra)))
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
    parser.add_argument("--cohort", type=Path, help="Pinned cohort.json to verify exact case IDs")
    args = parser.parse_args()
    expected = None
    if args.cohort is not None:
        manifest = json.loads(args.cohort.read_text(encoding="utf-8"))
        cases = manifest.get("cases")
        if not isinstance(cases, list) or not cases:
            parser.error("cohort must have a nonempty cases list")
        identifiers = [item.get("case_id") for item in cases]
        if any(not isinstance(value, str) or not value for value in identifiers):
            parser.error("cohort has empty or invalid case IDs")
        expected = set(identifiers)
        if len(expected) != len(identifiers):
            parser.error("cohort has duplicate case IDs")
    report = audit_study(args.scans, expected_cases=expected)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Pipeline audit: {report['total']} scan cases, {len(report['errors'])} issues")
    for error in report["errors"]:
        print(" - " + error)
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
