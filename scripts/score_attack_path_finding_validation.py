"""Score the human-adjudicated attack-path and finding validation study.

The scorer consumes locked review summaries plus scanner-observation mappings. It does
not adjudicate truth and never rewrites reviewer decisions.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

STUDY = "attack-path-finding-validation-2026"
SEVERITY_RANK = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class ScoreError(ValueError):
    pass


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ScoreError(f"{path}: cannot load JSON") from exc
    if not isinstance(value, dict):
        raise ScoreError(f"{path}: expected JSON object")
    return value


def _ratio(num: int, den: int) -> float | None:
    return round(num / den, 4) if den else None


def _rows(summary: dict[str, Any], phase: str) -> dict[str, dict[str, Any]]:
    if summary.get("study") != STUDY:
        raise ScoreError(f"{phase}: wrong study")
    rows = summary.get("rows")
    if not isinstance(rows, list) or not rows:
        raise ScoreError(f"{phase}: review summary contains no rows")
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        case_id = str(row.get("case_id") or "").strip()
        if not case_id:
            continue
        if case_id in result:
            raise ScoreError(f"{phase}: duplicate case_id {case_id}")
        result[case_id] = row
    return result


def _observation_map(
    doc: dict[str, Any],
    *,
    field: str,
    label: str,
) -> tuple[str, dict[str, bool]]:
    if doc.get("study") != STUDY:
        raise ScoreError(f"{label}: wrong study")
    scanner_sha = str(doc.get("scanner_sha") or "").strip()
    if len(scanner_sha) != 40:
        raise ScoreError(f"{label}: scanner_sha must be a full SHA")
    observations = doc.get("observations")
    if not isinstance(observations, list):
        raise ScoreError(f"{label}: observations must be a list")
    result: dict[str, bool] = {}
    for item in observations:
        if not isinstance(item, dict):
            continue
        case_id = str(item.get("case_id") or "").strip()
        value = item.get(field)
        if not case_id or not isinstance(value, bool):
            raise ScoreError(f"{label}: invalid observation")
        if case_id in result:
            raise ScoreError(f"{label}: duplicate case_id {case_id}")
        result[case_id] = value
    return scanner_sha, result


def _attack_metrics(
    phase_a_rows: dict[str, dict[str, Any]],
    observations: dict[str, bool],
) -> dict[str, Any]:
    tp = fp = fn = tn = unresolved = disagreements = 0
    used: list[str] = []
    for case_id, row in phase_a_rows.items():
        if row.get("case_type") != "attack_path":
            continue
        if not row.get("consensus"):
            disagreements += 1
            continue
        verdict = row.get("consensus_verdict")
        if verdict == "unresolved":
            unresolved += 1
            continue
        if verdict not in {"valid", "invalid"}:
            raise ScoreError(f"attack path {case_id}: invalid consensus verdict")
        if case_id not in observations:
            raise ScoreError(f"attack path {case_id}: missing scanner observation")
        reported = observations[case_id]
        used.append(case_id)
        if verdict == "valid" and reported:
            tp += 1
        elif verdict == "valid":
            fn += 1
        elif reported:
            fp += 1
        else:
            tn += 1
    return {
        "adjudicated_cases": len(used),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": _ratio(tp, tp + fp),
        "recall": _ratio(tp, tp + fn),
        "unresolved_cases": unresolved,
        "review_disagreements": disagreements,
    }


def _finding_recall_metrics(
    phase_a_rows: dict[str, dict[str, Any]],
    observations: dict[str, bool],
) -> dict[str, Any]:
    supported_tp = supported_fn = partial_tp = partial_fn = 0
    unsupported_detected = unsupported_not_detected = 0
    unresolved = disagreements = 0
    partial_reasons: Counter[str] = Counter()

    for case_id, row in phase_a_rows.items():
        if row.get("case_type") != "finding":
            continue
        if not row.get("consensus"):
            disagreements += 1
            continue
        verdict = row.get("consensus_verdict")
        if verdict == "unresolved":
            unresolved += 1
            continue
        if verdict not in {"supported", "partial", "unsupported"}:
            raise ScoreError(f"finding recall {case_id}: invalid consensus verdict")
        if case_id not in observations:
            raise ScoreError(f"finding recall {case_id}: missing scanner observation")

        detected = observations[case_id]
        if verdict == "supported":
            if detected:
                supported_tp += 1
            else:
                supported_fn += 1
        elif verdict == "partial":
            partial_reasons.update(row.get("consensus_partial_reasons", []))
            if detected:
                partial_tp += 1
            else:
                partial_fn += 1
        elif detected:
            unsupported_detected += 1
        else:
            unsupported_not_detected += 1

    strict_total = supported_tp + supported_fn
    material_total = strict_total + partial_tp + partial_fn
    return {
        "supported_tp": supported_tp,
        "supported_fn": supported_fn,
        "partial_tp": partial_tp,
        "partial_fn": partial_fn,
        "recall": _ratio(supported_tp, strict_total),
        "strict_recall": _ratio(supported_tp, strict_total),
        "materially_supported_recall": _ratio(
            supported_tp + partial_tp,
            material_total,
        ),
        "partial_reason_taxonomy": dict(sorted(partial_reasons.items())),
        "unsupported_detected": unsupported_detected,
        "unsupported_not_detected": unsupported_not_detected,
        "unresolved_cases": unresolved,
        "review_disagreements": disagreements,
    }


def _hidden_map(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if doc.get("study") != STUDY:
        raise ScoreError("Phase-B hidden map belongs to a different study")
    if doc.get("do_not_distribute_to_reviewers") is not True:
        raise ScoreError("Phase-B hidden map missing coordinator-only marker")
    cases = doc.get("cases")
    if not isinstance(cases, list):
        raise ScoreError("Phase-B hidden map cases must be a list")
    result: dict[str, dict[str, Any]] = {}
    for item in cases:
        if not isinstance(item, dict):
            continue
        case_id = str(item.get("case_id") or "").strip()
        if not case_id:
            continue
        if case_id in result:
            raise ScoreError(f"Phase-B hidden map duplicate {case_id}")
        result[case_id] = item
    return result


def _finding_precision_and_severity(
    phase_b_rows: dict[str, dict[str, Any]],
    hidden: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    tp = partial = fp = unresolved = disagreements = 0
    exact = one_level = severity_total = 0
    taxonomy: Counter[str] = Counter()
    partial_reasons: Counter[str] = Counter()
    by_rule: dict[str, Counter[str]] = defaultdict(Counter)
    by_owasp: dict[str, Counter[str]] = defaultdict(Counter)

    for case_id, row in phase_b_rows.items():
        if row.get("case_type") != "finding":
            continue
        if case_id not in hidden:
            raise ScoreError(f"Phase-B review {case_id}: missing hidden metadata")
        if not row.get("consensus"):
            disagreements += 1
            continue
        verdict = row.get("consensus_verdict")
        if verdict == "unresolved":
            unresolved += 1
            continue

        rule_id = str(hidden[case_id].get("rule_id") or "unknown")
        mapped_owasp = hidden[case_id].get("owasp_agentic")
        if not isinstance(mapped_owasp, list):
            mapped_owasp = []
        by_rule[rule_id]["sampled"] += 1
        for risk_id in mapped_owasp:
            by_owasp[str(risk_id)]["sampled"] += 1

        if verdict == "supported":
            tp += 1
            by_rule[rule_id]["supported"] += 1
            for risk_id in mapped_owasp:
                by_owasp[str(risk_id)]["supported"] += 1
        elif verdict == "partial":
            partial += 1
            reasons = row.get("consensus_partial_reasons", [])
            if isinstance(reasons, list):
                partial_reasons.update(
                    reason for reason in reasons if isinstance(reason, str)
                )
            by_rule[rule_id]["partial"] += 1
            for risk_id in mapped_owasp:
                by_owasp[str(risk_id)]["partial"] += 1
        elif verdict == "unsupported":
            fp += 1
            by_rule[rule_id]["unsupported"] += 1
            for risk_id in mapped_owasp:
                by_owasp[str(risk_id)]["unsupported"] += 1
        else:
            raise ScoreError(f"Phase-B review {case_id}: invalid consensus verdict")

        # Keep severity agreement strict: partially-qualified claims are reported
        # separately rather than mixed into the historical strict-TP denominator.
        if verdict != "supported" or not row.get("severity_consensus"):
            continue
        human = str(row.get("consensus_severity") or "")
        scanner = str(hidden[case_id].get("scanner_severity") or "")
        if human not in SEVERITY_RANK or scanner not in SEVERITY_RANK:
            continue
        severity_total += 1
        delta = SEVERITY_RANK[scanner] - SEVERITY_RANK[human]
        if delta == 0:
            exact += 1
            taxonomy["exact"] += 1
        elif abs(delta) == 1:
            one_level += 1
            taxonomy[
                "scanner_one_level_higher" if delta > 0 else "scanner_one_level_lower"
            ] += 1
        elif delta > 1:
            taxonomy["scanner_two_plus_levels_higher"] += 1
        else:
            taxonomy["scanner_two_plus_levels_lower"] += 1

    def grouped_precision(groups: dict[str, Counter[str]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, counts in sorted(groups.items()):
            supported = int(counts["supported"])
            partial_count = int(counts["partial"])
            unsupported = int(counts["unsupported"])
            adjudicated = supported + partial_count + unsupported
            result[key] = {
                "sampled": int(counts["sampled"]),
                "supported": supported,
                "partial": partial_count,
                "unsupported": unsupported,
                "precision": _ratio(supported, adjudicated),
                "strict_precision": _ratio(supported, adjudicated),
                "materially_supported_precision": _ratio(
                    supported + partial_count,
                    adjudicated,
                ),
            }
        return result

    adjudicated = tp + partial + fp
    finding = {
        "sampled_scanner_findings": (
            adjudicated + unresolved + disagreements
        ),
        "supported_tp": tp,
        "partial": partial,
        "unsupported_fp": fp,
        "precision": _ratio(tp, adjudicated),
        "strict_precision": _ratio(tp, adjudicated),
        "materially_supported_precision": _ratio(tp + partial, adjudicated),
        "partial_reason_taxonomy": dict(sorted(partial_reasons.items())),
        "unresolved_cases": unresolved,
        "review_disagreements": disagreements,
        "by_rule": grouped_precision(by_rule),
        "by_owasp_agentic": grouped_precision(by_owasp),
    }
    severity = {
        "comparable_supported_findings": severity_total,
        "exact_matches": exact,
        "exact_match_rate": _ratio(exact, severity_total),
        "within_one_level": exact + one_level,
        "within_one_level_rate": _ratio(exact + one_level, severity_total),
        "taxonomy": dict(sorted(taxonomy.items())),
    }
    return finding, severity


def score(
    phase_a_summary: dict[str, Any],
    attack_observations: dict[str, Any],
    finding_recall_observations: dict[str, Any],
    phase_b_summary: dict[str, Any],
    phase_b_hidden: dict[str, Any],
) -> dict[str, Any]:
    phase_a = _rows(phase_a_summary, "Phase A")
    phase_b = _rows(phase_b_summary, "Phase B")
    attack_sha, attack_obs = _observation_map(
        attack_observations,
        field="scanner_reported",
        label="attack observations",
    )
    recall_sha, recall_obs = _observation_map(
        finding_recall_observations,
        field="scanner_detected",
        label="finding recall observations",
    )
    if attack_sha != recall_sha:
        raise ScoreError("attack and finding-recall observations use different scanner SHAs")
    hidden = _hidden_map(phase_b_hidden)
    finding_precision, severity = _finding_precision_and_severity(phase_b, hidden)

    scanner_shas = {
        str(item.get("scanner_sha") or "")
        for item in hidden.values()
        if item.get("scanner_sha")
    }
    if scanner_shas and scanner_shas != {attack_sha}:
        raise ScoreError("Phase-B hidden map uses a different scanner SHA")

    return {
        "schema_version": 1,
        "study": STUDY,
        "scanner_sha": attack_sha,
        "attack_paths": _attack_metrics(phase_a, attack_obs),
        "findings": {
            "recall_reference": _finding_recall_metrics(phase_a, recall_obs),
            "precision_sample": finding_precision,
            "severity": severity,
        },
        "runtime_exploitability": "not_verified",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase-a-summary", type=Path, required=True)
    parser.add_argument("--attack-observations", type=Path, required=True)
    parser.add_argument("--finding-recall-observations", type=Path, required=True)
    parser.add_argument("--phase-b-summary", type=Path, required=True)
    parser.add_argument("--phase-b-hidden-map", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    report = score(
        _load(args.phase_a_summary),
        _load(args.attack_observations),
        _load(args.finding_recall_observations),
        _load(args.phase_b_summary),
        _load(args.phase_b_hidden_map),
    )
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
