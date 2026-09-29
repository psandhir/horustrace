"""Build and score case-blind GPT ↔ HorusTrace differential evaluations.

GPT is a differential oracle, not ground truth.  The workflow is deliberately
two-phase:

1. export a packet containing only pinned repo identity/framework metadata;
2. lock a source-only GPT review before revealing HorusTrace output;
3. explicitly align GPT semantic claims to HorusTrace finding fingerprints;
4. source-adjudicate disagreements rather than automatically treating either side
   as correct.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

SOURCE_STUDY = "real-world-agent-security-2026"
DIFF_STUDY = "gpt-horustrace-differential-2026"
COVERAGE = {"covered", "partial", "missed"}
HT_OUTCOMES = {
    "source_supported",
    "semantic_duplicate",
    "policy_semantics_review",
    "effective_authority_review",
    "unsupported",
    "unresolved",
}


class DifferentialError(ValueError):
    pass


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DifferentialError(f"{path}: cannot load JSON") from exc
    if not isinstance(value, dict):
        raise DifferentialError(f"{path}: expected JSON object")
    return value


def build_packet(result: dict[str, Any], case_ids: list[str]) -> dict[str, Any]:
    if result.get("study") != SOURCE_STUDY:
        raise DifferentialError("scanner result belongs to a different study")
    scanner_sha = str(result.get("scanner_sha") or "")
    if len(scanner_sha) != 40:
        raise DifferentialError("scanner result must have a full scanner_sha")
    cases = {
        str(case.get("case_id")): case
        for case in result.get("cases", [])
        if isinstance(case, dict) and case.get("case_id")
    }
    selected: list[dict[str, str]] = []
    seen: set[str] = set()
    for case_id in case_ids:
        if case_id in seen:
            raise DifferentialError(f"duplicate case_id {case_id}")
        seen.add(case_id)
        case = cases.get(case_id)
        if case is None:
            raise DifferentialError(f"unknown case_id {case_id}")
        repo = str(case.get("repo") or "")
        sha = str(case.get("sha") or "")
        framework = str(case.get("framework") or "")
        if not repo or len(sha) != 40 or not framework:
            raise DifferentialError(f"{case_id}: incomplete source identity")
        selected.append(
            {
                "case_id": case_id,
                "repo": repo,
                "sha": sha,
                "framework": framework,
            }
        )

    return {
        "schema_version": 1,
        "study": DIFF_STUDY,
        "phase": "case_blind_source_review",
        "scanner_sha_withheld_until_review_lock": scanner_sha,
        "horustrace_findings_in_packet": False,
        "cases": selected,
        "review_requirements": {
            "inspect_pinned_source_independently": True,
            "do_not_use_horustrace_case_output": True,
            "distinguish_declared_from_effective_authority": True,
            "distinguish_agent_authority_from_application_only_authority": True,
            "record_source_evidence": True,
            "record_runtime_viability": True,
        },
        "semantic_dimensions": [
            "agent principals and delegation",
            "tool/MCP binding and effective authority",
            "ingress and trust/authentication controls",
            "data/process/network/file/cloud capabilities",
            "approval/guardrail boundaries",
            "source-supported attack paths",
            "runtime viability or unresolved dynamic behavior",
        ],
    }


def _scanner_findings(result: dict[str, Any]) -> tuple[str, dict[str, dict[str, Any]]]:
    if result.get("study") != SOURCE_STUDY:
        raise DifferentialError("scanner result belongs to a different study")
    scanner_sha = str(result.get("scanner_sha") or "")
    rows: dict[str, dict[str, Any]] = {}
    for case in result.get("cases", []):
        if not isinstance(case, dict):
            continue
        case_id = str(case.get("case_id") or "")
        for finding in case.get("findings", []) or []:
            if not isinstance(finding, dict):
                continue
            fingerprint = str(finding.get("fingerprint") or "")
            if not fingerprint:
                raise DifferentialError(f"{case_id}: finding missing fingerprint")
            key = f"{case_id}:{fingerprint}"
            rows[key] = {
                "case_id": case_id,
                "fingerprint": fingerprint,
                "rule_id": finding.get("rule_id"),
                "severity": finding.get("severity"),
                "agent": finding.get("agent"),
                "title": finding.get("title"),
            }
    return scanner_sha, rows


def _gpt_findings(review: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if review.get("study") != DIFF_STUDY:
        raise DifferentialError("GPT review belongs to a different study")
    result: dict[str, dict[str, Any]] = {}
    for case in review.get("cases", []):
        if not isinstance(case, dict):
            continue
        case_id = str(case.get("case_id") or "")
        for finding in case.get("findings", []) or []:
            if not isinstance(finding, dict):
                continue
            finding_id = str(finding.get("finding_id") or "")
            if not finding_id:
                raise DifferentialError(f"{case_id}: GPT finding missing finding_id")
            if finding_id in result:
                raise DifferentialError(f"duplicate GPT finding_id {finding_id}")
            result[finding_id] = {
                "case_id": case_id,
                "severity": finding.get("severity"),
                "semantic_key": finding.get("semantic_key"),
            }
    return result


def score(
    review: dict[str, Any],
    scanner: dict[str, Any],
    alignment: dict[str, Any],
) -> dict[str, Any]:
    if alignment.get("study") != DIFF_STUDY:
        raise DifferentialError("alignment belongs to a different study")

    scanner_sha, scanner_findings = _scanner_findings(scanner)
    gpt_findings = _gpt_findings(review)
    expected_sha = str(alignment.get("scanner_sha") or "")
    if expected_sha != scanner_sha:
        raise DifferentialError("alignment scanner_sha does not match scanner result")

    coverage = Counter()
    matched_scanner_keys: set[str] = set()
    severity = Counter()
    gpt_rows = alignment.get("gpt_findings")
    if not isinstance(gpt_rows, list):
        raise DifferentialError("alignment.gpt_findings must be a list")
    seen_gpt: set[str] = set()

    for row in gpt_rows:
        if not isinstance(row, dict):
            raise DifferentialError("GPT alignment row must be an object")
        finding_id = str(row.get("finding_id") or "")
        if finding_id not in gpt_findings:
            raise DifferentialError(f"unknown GPT finding_id {finding_id}")
        if finding_id in seen_gpt:
            raise DifferentialError(f"duplicate GPT alignment {finding_id}")
        seen_gpt.add(finding_id)
        status = row.get("coverage")
        if status not in COVERAGE:
            raise DifferentialError(f"{finding_id}: invalid coverage {status!r}")
        coverage[status] += 1

        matched = row.get("matched_horustrace") or []
        if not isinstance(matched, list):
            raise DifferentialError(f"{finding_id}: matched_horustrace must be a list")
        for ref in matched:
            if not isinstance(ref, dict):
                raise DifferentialError(f"{finding_id}: invalid HorusTrace reference")
            case_id = str(ref.get("case_id") or "")
            fingerprint = str(ref.get("fingerprint") or "")
            key = f"{case_id}:{fingerprint}"
            scanner_row = scanner_findings.get(key)
            if scanner_row is None:
                raise DifferentialError(f"{finding_id}: unknown scanner finding {key}")
            if case_id != gpt_findings[finding_id]["case_id"]:
                raise DifferentialError(f"{finding_id}: cross-case scanner match")
            matched_scanner_keys.add(key)
            gpt_sev = str(gpt_findings[finding_id].get("severity") or "")
            ht_sev = str(scanner_row.get("severity") or "")
            if gpt_sev and ht_sev:
                severity[
                    "same" if gpt_sev == ht_sev else f"gpt_{gpt_sev}__ht_{ht_sev}"
                ] += 1

    if seen_gpt != set(gpt_findings):
        missing = sorted(set(gpt_findings) - seen_gpt)
        raise DifferentialError(f"alignment omitted GPT findings: {missing}")

    ht_review = alignment.get("horustrace_findings") or []
    if not isinstance(ht_review, list):
        raise DifferentialError("alignment.horustrace_findings must be a list")
    ht_outcomes = Counter()
    seen_ht: set[str] = set()
    for row in ht_review:
        if not isinstance(row, dict):
            raise DifferentialError("HorusTrace alignment row must be an object")
        case_id = str(row.get("case_id") or "")
        fingerprint = str(row.get("fingerprint") or "")
        key = f"{case_id}:{fingerprint}"
        if key not in scanner_findings:
            raise DifferentialError(f"unknown scanner finding {key}")
        if key in seen_ht:
            raise DifferentialError(f"duplicate scanner adjudication {key}")
        seen_ht.add(key)
        outcome = row.get("outcome")
        if outcome not in HT_OUTCOMES:
            raise DifferentialError(f"{key}: invalid outcome {outcome!r}")
        ht_outcomes[outcome] += 1

    # Explicit adjudication may intentionally group duplicate scanner findings, but
    # every scanner finding must still be represented once so no disagreement is
    # silently lost.
    if seen_ht != set(scanner_findings):
        missing = sorted(set(scanner_findings) - seen_ht)
        raise DifferentialError(f"alignment omitted scanner findings: {missing}")

    attack = alignment.get("attack_paths") or {}
    if not isinstance(attack, dict):
        raise DifferentialError("alignment.attack_paths must be an object")

    total_gpt = len(gpt_findings)
    return {
        "schema_version": 1,
        "study": DIFF_STUDY,
        "batch_id": alignment.get("batch_id"),
        "scanner_sha": scanner_sha,
        "cases": len(review.get("cases", [])),
        "gpt_semantic_findings": {
            "total": total_gpt,
            "covered": coverage["covered"],
            "partial": coverage["partial"],
            "missed": coverage["missed"],
            "covered_or_partial_rate": round(
                (coverage["covered"] + coverage["partial"]) / total_gpt, 4
            )
            if total_gpt
            else None,
            "full_coverage_rate": round(coverage["covered"] / total_gpt, 4)
            if total_gpt
            else None,
        },
        "horustrace_finding_adjudication": dict(sorted(ht_outcomes.items())),
        "severity_alignment_on_matches": dict(sorted(severity.items())),
        "attack_paths": attack,
        "notes": [
            "These are differential coverage metrics, not product precision/recall.",
            "GPT is not treated as ground truth; disagreements require source adjudication.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    export = sub.add_parser("export")
    export.add_argument("scanner_result", type=Path)
    export.add_argument("--case", action="append", required=True, dest="cases")
    export.add_argument("--output", type=Path, required=True)

    compare = sub.add_parser("compare")
    compare.add_argument("--gpt-review", type=Path, required=True)
    compare.add_argument("--scanner-result", type=Path, required=True)
    compare.add_argument("--alignment", type=Path, required=True)
    compare.add_argument("--output", type=Path)

    args = parser.parse_args()
    if args.command == "export":
        payload = build_packet(_load(args.scanner_result), args.cases)
    else:
        payload = score(
            _load(args.gpt_review),
            _load(args.scanner_result),
            _load(args.alignment),
        )

    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if getattr(args, "output", None):
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
