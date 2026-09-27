"""Validate blinded human reviews for attack-path/finding accuracy studies."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml

ATTACK_VERDICTS = {"valid", "invalid", "unresolved"}
FINDING_VERDICTS = {"supported", "unsupported", "unresolved"}
SEVERITIES = {"critical", "high", "medium", "low", "informational", "unresolved"}


class ReviewPackError(ValueError):
    pass


def _load(path: Path) -> dict[str, Any]:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ReviewPackError(f"{path}: cannot load review case") from exc
    if not isinstance(value, dict):
        raise ReviewPackError(f"{path}: expected mapping")
    return value


def _validate_case_doc(case: dict[str, Any], where: str) -> dict[str, Any]:
    if case.get("schema_version") not in {None, 1}:
        raise ReviewPackError(f"{where}: schema_version must be 1")
    if case.get("study") not in {None, "attack-path-finding-validation-2026"}:
        raise ReviewPackError(f"{where}: unexpected study")
    case_type = case.get("case_type")
    if case_type not in {"attack_path", "finding"}:
        raise ReviewPackError(f"{where}: invalid case_type")

    repository = case.get("repository")
    if not isinstance(repository, dict):
        raise ReviewPackError(f"{where}: repository must be mapping")
    sha = repository.get("sha")
    if not isinstance(sha, str) or len(sha) != 40:
        raise ReviewPackError(f"{where}: repository.sha must be full SHA")

    reviewers = case.get("reviewers")
    if not isinstance(reviewers, list) or len(reviewers) != 2:
        raise ReviewPackError(f"{where}: exactly two reviewers are required")

    ids: list[str] = []
    case_where = where
    for index, review in enumerate(reviewers):
        review_where = f"{case_where}: reviewers[{index}]"
        if not isinstance(review, dict):
            raise ReviewPackError(f"{review_where}: expected mapping")
        reviewer_id = review.get("reviewer_id")
        if not isinstance(reviewer_id, str) or not reviewer_id.strip():
            raise ReviewPackError(f"{review_where}: reviewer_id is required")
        ids.append(reviewer_id.strip())
        if review.get("independent_human") is not True:
            raise ReviewPackError(f"{review_where}: independent_human must be true")
        if review.get("horustrace_output_seen") is not False:
            raise ReviewPackError(f"{review_where}: reviewer must be blinded")
        if review.get("locked") is not True:
            raise ReviewPackError(f"{review_where}: review must be locked")

        verdict = review.get("verdict")
        allowed = ATTACK_VERDICTS if case_type == "attack_path" else FINDING_VERDICTS
        if verdict not in allowed:
            raise ReviewPackError(f"{review_where}: invalid verdict {verdict!r}")
        severity = review.get("severity", "unresolved")
        if severity not in SEVERITIES:
            raise ReviewPackError(f"{review_where}: invalid severity {severity!r}")
        evidence = review.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            raise ReviewPackError(f"{review_where}: evidence must be non-empty")
        rationale = review.get("rationale")
        if not isinstance(rationale, str) or not rationale.strip():
            raise ReviewPackError(f"{review_where}: rationale is required")

    if ids[0] == ids[1]:
        raise ReviewPackError(f"{case_where}: reviewers must be different people")

    verdicts = [review["verdict"] for review in reviewers]
    severities = [review.get("severity", "unresolved") for review in reviewers]
    return {
        "case_id": case.get("case_id"),
        "case_type": case_type,
        "consensus": verdicts[0] == verdicts[1],
        "consensus_verdict": verdicts[0] if verdicts[0] == verdicts[1] else None,
        "severity_consensus": severities[0] == severities[1],
        "consensus_severity": severities[0] if severities[0] == severities[1] else None,
        "reviewers": ids,
    }




def validate_review_case(path: Path) -> dict[str, Any]:
    case = _load(path)
    if case.get("schema_version") != 1:
        raise ReviewPackError(f"{path}: schema_version must be 1")
    if case.get("study") != "attack-path-finding-validation-2026":
        raise ReviewPackError(f"{path}: unexpected study")
    return _validate_case_doc(case, str(path))


def validate_review_packet(path: Path) -> list[dict[str, Any]]:
    packet = _load(path)
    if packet.get("schema_version") != 1:
        raise ReviewPackError(f"{path}: schema_version must be 1")
    if packet.get("study") != "attack-path-finding-validation-2026":
        raise ReviewPackError(f"{path}: unexpected study")
    cases = packet.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ReviewPackError(f"{path}: packet cases must be non-empty")
    rows: list[dict[str, Any]] = []
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            raise ReviewPackError(f"{path}: cases[{index}] must be a mapping")
        rows.append(_validate_case_doc(case, f"{path}: cases[{index}]"))
    return rows

def summarize(paths: list[Path]) -> dict[str, Any]:
    rows = [validate_review_case(path) for path in paths]
    return summarize_rows(rows)


def summarize_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "study": "attack-path-finding-validation-2026",
        "cases": len(rows),
        "attack_path_cases": sum(row["case_type"] == "attack_path" for row in rows),
        "finding_cases": sum(row["case_type"] == "finding" for row in rows),
        "consensus_cases": sum(bool(row["consensus"]) for row in rows),
        "disagreement_cases": sum(not bool(row["consensus"]) for row in rows),
        "rows": rows,
        "scanner_reveal_allowed": bool(rows) and all(row["consensus"] for row in rows),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("review_input", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    if args.review_input.is_file():
        rows = validate_review_packet(args.review_input)
        report = summarize_rows(rows)
    else:
        paths = sorted(args.review_input.glob("*.yaml"))
        if not paths:
            raise ReviewPackError(f"{args.review_input}: no review cases found")
        report = summarize(paths)
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
