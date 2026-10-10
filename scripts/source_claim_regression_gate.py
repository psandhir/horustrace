"""Source-supported claim regression gate for frozen historical cohorts.

This gate compares semantic claims at the same pinned repository SHA; it does
not infer ground truth or restore counts. Missing historically supported claims
require an explicit source-backed disposition before a rerun can pass.
"""
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path


VALID_VERDICTS = {"true_positive", "partial", "false_positive", "unresolved"}
VALID_DISPOSITIONS = {
    "corrected_false_positive",
    "scope_narrowed",
    "consolidated",
    "preserved_in_inventory",
}


def _load_results(root: Path) -> dict[str, dict]:
    if not root.is_dir():
        raise ValueError(f"missing result directory: {root}")
    results: dict[str, dict] = {}
    for path in sorted(root.rglob("result.json")):
        item = json.loads(path.read_text(encoding="utf-8"))
        case_id = str(item.get("case_id") or "")
        if not case_id or case_id in results:
            raise ValueError(f"invalid or duplicate case in {path}")
        findings = item.get("findings")
        count = (item.get("counts") or {}).get("findings")
        if not isinstance(findings, list) or count != len(findings):
            raise ValueError(f"missing/inconsistent finding evidence: {case_id}")
        results[case_id] = item
    if not results:
        raise ValueError(f"no result.json files in {root}")
    return results



def _load_reference_manifest(path: Path) -> tuple[dict[str, dict], dict[tuple[str, int], dict]]:
    """Load the postmerge *unadjudicated* claim inventory as a protective floor.

    These reviews deliberately remain 'unresolved': matching a historical
    scanner output is not independent evidence that its finding was valid.
    """
    doc = json.loads(path.read_text(encoding="utf-8"))
    if (
        doc.get("schema_version") != 1
        or doc.get("reference_type") != "postmerge_unadjudicated_claim_inventory"
        or not isinstance(doc.get("cases"), list)
    ):
        raise ValueError("invalid postmerge source claim inventory")
    baseline: dict[str, dict] = {}
    reviews: dict[tuple[str, int], dict] = {}
    for case in doc["cases"]:
        case_id = str(case.get("case_id") or "")
        claims = case.get("findings")
        if (
            not case_id or case_id in baseline or
            not all(isinstance(case.get(key), str) and case[key]
                    for key in ("repo", "sha", "framework")) or
            not isinstance(claims, list) or
            (case.get("counts") or {}).get("findings") != len(claims)
        ):
            raise ValueError(f"invalid/duplicate locked case: {case_id}")
        for index, claim in enumerate(claims):
            if not isinstance(claim, dict) or not claim.get("rule_id"):
                raise ValueError(f"{case_id}/{index}: missing locked finding")
            if not isinstance(claim.get("location"), dict):
                raise ValueError(f"{case_id}/{index}: missing locked source")
            if not claim["location"].get("path") or not isinstance(
                claim["location"].get("line"), int
            ):
                raise ValueError(f"{case_id}/{index}: invalid locked source")
            reviews[(case_id, index)] = {
                "case_id": case_id,
                "finding_index": str(index),
                "rule_id": claim["rule_id"],
                "verdict": "unresolved",
                "reason_category": "unadjudicated_postmerge_reference",
            }
        baseline[case_id] = case
    if len(baseline) != 16 or sum(len(x["findings"]) for x in baseline.values()) != 49:
        raise ValueError("postmerge Fresh-16 reference cohort/claim count drift")
    return baseline, reviews


def _source_path(finding: dict) -> str:
    location = finding.get("location") or {}
    path = str(location.get("path") or "").replace("\\", "/")
    # Historical scans run in different ephemeral checkout directories.
    return path.rsplit("/target/", 1)[-1] if "/target/" in path else path


def _identity(finding: dict) -> tuple[str, str, int, str]:
    location = finding.get("location") or {}
    return (
        str(finding.get("rule_id") or ""),
        _source_path(finding),
        int(location.get("line") or 0),
        str(finding.get("agent") or ""),
    )


def _read_reviews(path: Path) -> dict[tuple[str, int], dict]:
    rows: dict[tuple[str, int], dict] = {}
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            case_id = str(row.get("case_id") or "")
            index = int(row.get("finding_index") or -1)
            verdict = row.get("verdict")
            if not case_id or index < 0 or verdict not in VALID_VERDICTS:
                raise ValueError(f"invalid adjudication row: {row}")
            key = (case_id, index)
            if key in rows:
                raise ValueError(f"duplicate adjudication: {key}")
            rows[key] = row
    return rows


def _read_decisions(path: Path) -> dict[tuple[str, int], dict]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if doc.get("schema_version") != 1 or not isinstance(doc.get("decisions"), list):
        raise ValueError("decisions must be schema_version=1 with a decisions list")
    decisions: dict[tuple[str, int], dict] = {}
    for row in doc["decisions"]:
        key = (str(row.get("case_id") or ""), int(row.get("finding_index", -1)))
        evidence = row.get("source_evidence") or {}
        if (
            not key[0]
            or key[1] < 0
            or key in decisions
            or row.get("disposition") not in VALID_DISPOSITIONS
            or not isinstance(evidence, dict)
            or not isinstance(evidence.get("path"), str)
            or not evidence["path"]
            or not isinstance(evidence.get("line"), int)
            or evidence["line"] < 1
            or len(str(row.get("rationale") or "")) < 20
        ):
            raise ValueError(f"invalid source-backed decision for {key}")
        decisions[key] = row
    return decisions


def compare(
    baseline: dict[str, dict],
    candidate: dict[str, dict],
    reviews: dict[tuple[str, int], dict],
    decisions: dict[tuple[str, int], dict],
) -> dict:
    problems: list[str] = []
    changes: list[dict] = []
    if set(baseline) != set(candidate):
        problems.append("candidate case set does not match frozen baseline")
    for case_id, before in sorted(baseline.items()):
        after = candidate.get(case_id)
        if after is None:
            continue
        for field in ("repo", "sha", "framework"):
            if before.get(field) != after.get(field):
                problems.append(f"{case_id}: frozen {field} changed")
        available = Counter(_identity(finding) for finding in after["findings"])
        for index, finding in enumerate(before["findings"]):
            review = reviews.get((case_id, index))
            if review is None or review.get("rule_id") != finding.get("rule_id"):
                problems.append(f"{case_id}/{index}: absent or mismatched source review")
                continue
            claim = _identity(finding)
            if available[claim]:
                available[claim] -= 1
                continue
            key = (case_id, index)
            decision = decisions.get(key)
            supported = review["verdict"] in {"true_positive", "partial", "unresolved"}
            changes.append({
                "case_id": case_id,
                "finding_index": index,
                "rule_id": finding.get("rule_id"),
                "source_path": claim[1],
                "source_line": claim[2],
                "prior_verdict": review["verdict"],
                "disposition": decision["disposition"] if decision else "review_required",
            })
            if supported and decision is None:
                problems.append(f"{case_id}/{index}: unadjudicated source-supported claim loss")
    known = {
        (case_id, index)
        for case_id, before in baseline.items()
        for index in range(len(before["findings"]))
    }
    if not set(reviews).issuperset(known):
        problems.append("incomplete historical source adjudication")
    if set(decisions) - known:
        problems.append("decisions refer to claims outside the baseline")
    return {
        "schema_version": 1,
        "baseline_cases": len(baseline),
        "candidate_cases": len(candidate),
        "removed_claims": changes,
        "gate_failures": sorted(set(problems)),
        "passed": not problems,
        "quality_claim": "semantic_regression_triage_only_not_blind_recall",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    reference = parser.add_mutually_exclusive_group(required=True)
    reference.add_argument("--baseline", type=Path)
    reference.add_argument("--baseline-manifest", type=Path)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--review-csv", type=Path)
    parser.add_argument("--decisions", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.baseline_manifest:
            if args.review_csv:
                raise ValueError("review-csv is not applicable to locked postmerge manifest")
            baseline, reviews = _load_reference_manifest(args.baseline_manifest)
        else:
            if not args.review_csv:
                raise ValueError("--review-csv required for historical baseline directory")
            baseline = _load_results(args.baseline)
            reviews = _read_reviews(args.review_csv)
        report = compare(
            baseline,
            _load_results(args.candidate),
            reviews,
            _read_decisions(args.decisions),
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        report = {"schema_version": 1, "passed": False, "gate_failures": [str(exc)]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
