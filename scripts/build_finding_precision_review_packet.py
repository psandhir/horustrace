"""Build a blinded Phase-B finding precision packet after Phase-A blinded-review lock.

This script must not run before the Phase-A review summary explicitly permits scanner
reveal. It samples HorusTrace findings by hidden rule/severity strata, then emits:

1. a reviewer packet containing neutral factual claims and source scope only;
2. a coordinator-only hidden map containing rule/severity/fingerprint metadata.

Do not distribute the hidden map to reviewers.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml

STUDY = "attack-path-finding-validation-2026"
SEVERITIES = ("critical", "high", "medium", "low", "informational", "unknown")


class PhaseBError(ValueError):
    pass


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PhaseBError(f"{path}: cannot load JSON") from exc
    if not isinstance(value, dict):
        raise PhaseBError(f"{path}: expected JSON object")
    return value


def _review_slots() -> list[dict[str, Any]]:
    return [
        {
            "reviewer_id": "",
            "independent_human": True,
            "horustrace_output_seen": False,
            "locked": False,
            "verdict": "unresolved",
            "severity": "unresolved",
            "evidence": [],
            "rationale": "",
        },
        {
            "reviewer_id": "",
            "independent_human": True,
            "horustrace_output_seen": False,
            "locked": False,
            "verdict": "unresolved",
            "severity": "unresolved",
            "evidence": [],
            "rationale": "",
        },
    ]


def _require_phase_a_lock(summary: dict[str, Any]) -> None:
    if summary.get("study") != STUDY:
        raise PhaseBError("Phase-A summary belongs to a different study")
    if summary.get("scanner_reveal_allowed") is not True:
        raise PhaseBError(
            "Phase B is blocked until Phase-A reviews are locked with scanner_reveal_allowed=true"
        )
    if int(summary.get("cases", 0)) <= 0:
        raise PhaseBError("Phase-A summary contains no reviewed cases")
    # Review disagreements are retained for escalation and excluded by the final
    # scorer. They do not prevent a separately blinded Phase-B sample once both
    # Phase-A reviews have been locked.


def _str(value: Any, fallback: str = "") -> str:
    return str(value).strip() if value is not None else fallback


def _source_paths(finding: dict[str, Any]) -> list[str]:
    paths: set[str] = set()
    location = finding.get("location")
    if isinstance(location, dict) and isinstance(location.get("path"), str):
        paths.add(location["path"])
    provenance = finding.get("provenance")
    if isinstance(provenance, list):
        for item in provenance:
            if not isinstance(item, dict):
                continue
            loc = item.get("location")
            if isinstance(loc, dict) and isinstance(loc.get("path"), str):
                paths.add(loc["path"])
    return sorted(paths)


def _finding_rows(doc: dict[str, Any]) -> list[dict[str, Any]]:
    scanner_sha = _str(doc.get("scanner_sha"))
    if len(scanner_sha) != 40:
        raise PhaseBError("findings input must contain a full scanner_sha")
    cases = doc.get("cases")
    if not isinstance(cases, list):
        raise PhaseBError("findings input cases must be a list")

    rows: list[dict[str, Any]] = []
    for case in cases:
        if not isinstance(case, dict):
            continue
        case_id = _str(case.get("case_id"))
        repo = _str(case.get("repo"))
        sha = _str(case.get("sha"))
        findings = case.get("findings")
        if not case_id or not repo or len(sha) != 40 or not isinstance(findings, list):
            continue
        for index, finding in enumerate(findings):
            if not isinstance(finding, dict):
                continue
            rule_id = _str(finding.get("rule_id"), "unknown")
            severity = _str(finding.get("severity"), "unknown").lower()
            if severity not in SEVERITIES:
                severity = "unknown"
            message = _str(finding.get("message"))
            if not message:
                continue
            paths = _source_paths(finding)
            if not paths:
                continue
            rows.append(
                {
                    "source_case_id": case_id,
                    "repo": repo,
                    "sha": sha,
                    "finding_index": index,
                    "finding": finding,
                    "rule_id": rule_id,
                    "severity": severity,
                    "source_paths": paths,
                    "scanner_sha": scanner_sha,
                }
            )
    if not rows:
        raise PhaseBError("findings input contains no reviewable findings")
    return rows


def _sample(rows: list[dict[str, Any]], target: int) -> list[dict[str, Any]]:
    if target < 1:
        raise PhaseBError("target must be positive")

    strata: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        strata[(row["rule_id"], row["severity"])].append(row)
    for values in strata.values():
        values.sort(
            key=lambda row: (
                row["sha"],
                row["source_case_id"],
                row["repo"],
                row["finding_index"],
            )
        )

    selected: list[dict[str, Any]] = []
    repo_counts: Counter[str] = Counter()
    stratum_counts: Counter[tuple[str, str]] = Counter()
    ordered_strata = sorted(
        strata,
        key=lambda key: (
            SEVERITIES.index(key[1]) if key[1] in SEVERITIES else len(SEVERITIES),
            key[0],
        ),
    )

    # Round-robin gives each observed rule/severity stratum a chance before repeats.
    while len(selected) < min(target, len(rows)):
        progress = False
        for key in ordered_strata:
            if len(selected) >= target:
                break
            if stratum_counts[key] >= 5:
                continue
            pool = strata[key]
            candidate = next(
                (
                    row
                    for row in pool
                    if row not in selected and repo_counts[row["repo"]] < 5
                ),
                None,
            )
            if candidate is None:
                continue
            selected.append(candidate)
            repo_counts[candidate["repo"]] += 1
            stratum_counts[key] += 1
            progress = True
        if not progress:
            break

    if len(selected) < min(target, len(rows)):
        for row in sorted(
            rows,
            key=lambda item: (
                repo_counts[item["repo"]],
                item["severity"],
                item["rule_id"],
                item["sha"],
                item["source_case_id"],
                item["finding_index"],
            ),
        ):
            if len(selected) >= target:
                break
            if row in selected or repo_counts[row["repo"]] >= 6:
                continue
            selected.append(row)
            repo_counts[row["repo"]] += 1

    return selected


def build_phase_b_packet(
    phase_a_summary: dict[str, Any],
    findings_doc: dict[str, Any],
    *,
    target: int = 60,
) -> tuple[dict[str, Any], dict[str, Any]]:
    _require_phase_a_lock(phase_a_summary)
    rows = _finding_rows(findings_doc)
    selected = _sample(rows, target)
    if not selected:
        raise PhaseBError("no findings selected")

    public_cases: list[dict[str, Any]] = []
    hidden_rows: list[dict[str, Any]] = []

    for number, row in enumerate(selected, start=1):
        finding = row["finding"]
        review_id = f"fp-{number:03d}"
        location = finding.get("location") if isinstance(finding.get("location"), dict) else None
        public_cases.append(
            {
                "case_id": review_id,
                "case_type": "finding",
                "study_phase": "finding_precision_phase_b",
                "repository": {"repo": row["repo"], "sha": row["sha"]},
                "source_case_id": row["source_case_id"],
                "source_scope": row["source_paths"],
                "question": {
                    "type": "finding",
                    "claim": {
                        "agent": finding.get("agent"),
                        "message": finding.get("message"),
                        "location": location,
                        "evidence": finding.get("evidence") or [],
                    },
                    "prompt": (
                        "Is this factual security assertion supported by the pinned source? "
                        "Independently assign severity based on source-proven consequence."
                    ),
                },
                "reviewers": _review_slots(),
            }
        )
        hidden_rows.append(
            {
                "case_id": review_id,
                "source_case_id": row["source_case_id"],
                "repo": row["repo"],
                "sha": row["sha"],
                "scanner_sha": row["scanner_sha"],
                "finding_index": row["finding_index"],
                "rule_id": row["rule_id"],
                "scanner_severity": row["severity"],
                "default_severity": finding.get("default_severity"),
                "confidence": finding.get("confidence"),
                "fingerprint": finding.get("fingerprint"),
                "title": finding.get("title"),
                "source_context": finding.get("source_context"),
                "owasp_agentic": (
                    finding.get("standards", {}).get("owasp_agentic", [])
                    if isinstance(finding.get("standards"), dict)
                    else []
                ),
            }
        )

    public_packet = {
        "schema_version": 1,
        "study": STUDY,
        "phase": "finding_precision_phase_b",
        "raw_horustrace_metadata_hidden": True,
        "selection_basis": "deterministic rule/severity-stratified sample after Phase-A lock",
        "case_count": len(public_cases),
        "cases": public_cases,
    }
    hidden_map = {
        "schema_version": 1,
        "study": STUDY,
        "phase": "finding_precision_phase_b_hidden_map",
        "do_not_distribute_to_reviewers": True,
        "case_count": len(hidden_rows),
        "strata": {
            f"{rule}|{severity}": count
            for (rule, severity), count in sorted(
                Counter((row["rule_id"], row["severity"]) for row in selected).items()
            )
        },
        "cases": hidden_rows,
    }
    return public_packet, hidden_map


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase-a-summary", type=Path, required=True)
    parser.add_argument("--findings", type=Path, required=True)
    parser.add_argument("--review-packet", type=Path, required=True)
    parser.add_argument("--hidden-map", type=Path, required=True)
    parser.add_argument("--target", type=int, default=60)
    args = parser.parse_args()

    public, hidden = build_phase_b_packet(
        _load_json(args.phase_a_summary),
        _load_json(args.findings),
        target=args.target,
    )
    args.review_packet.parent.mkdir(parents=True, exist_ok=True)
    args.hidden_map.parent.mkdir(parents=True, exist_ok=True)
    args.review_packet.write_text(
        yaml.safe_dump(public, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    args.hidden_map.write_text(
        json.dumps(hidden, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"public_cases": public["case_count"], "strata": hidden["strata"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
