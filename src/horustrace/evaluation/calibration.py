"""Stratified evaluation quality reporting (not an independent ground-truth oracle).

Historical G0–G3 adjudication packets remain authoritative. This computes
metrics only from caller-supplied reference labels and preserves unresolved
counts, reference provenance and holdout partitions.
"""
from __future__ import annotations

from collections import defaultdict
from math import sqrt
from typing import Any

from horustrace.evaluation.contracts import EvaluationContractError

REFERENCE_LABELS = frozenset({"supported", "partial", "unsupported", "unresolved"})
PREDICTIONS = frozenset({"supported", "partial", "refuted", "unresolved"})
CATEGORIES = frozenset({"finding", "path"})


def wilson_interval(successes: int, total: int, z: float = 1.96) -> list[float] | None:
    """Wilson score interval; None when a denominator has no eligible observations."""
    if not total:
        return None
    p = successes / total
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    margin = z * sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return [round(max(0, center - margin), 4), round(min(1, center + margin), 4)]


def _summarize(records: list[dict[str, str]]) -> dict[str, Any]:
    eligible = [r for r in records if r["reference"] in {"supported", "unsupported"}]
    tp = sum(r["reference"] == "supported" and r["predicted"] == "supported" for r in eligible)
    fp = sum(r["reference"] == "unsupported" and r["predicted"] == "supported" for r in eligible)
    fn = sum(r["reference"] == "supported" and r["predicted"] == "refuted" for r in eligible)
    tn = sum(r["reference"] == "unsupported" and r["predicted"] == "refuted" for r in eligible)
    unresolved_predictions = sum(r["predicted"] == "unresolved" for r in records)
    partial_references = sum(r["reference"] == "partial" for r in records)
    unresolved_references = sum(r["reference"] == "unresolved" for r in records)
    partial_predictions = sum(r["predicted"] == "partial" for r in records)
    positive_reference = sum(r["reference"] == "supported" for r in eligible)
    reviewed_support = sum(r["reference"] == "supported" and r["predicted"] != "unresolved"
                           for r in eligible)
    return {
        "records": len(records),
        "reference_eligible": len(eligible),
        "reference_unresolved": unresolved_references,
        "reference_partial": partial_references,
        "prediction_unresolved": unresolved_predictions,
        "prediction_partial": partial_predictions,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(tp / (tp + fp), 4) if tp + fp else None,
        # Unresolved predictions remain in recall denominator; never call them negatives.
        "recall": round(tp / positive_reference, 4) if positive_reference else None,
        "precision_wilson_95": wilson_interval(tp, tp + fp),
        "recall_wilson_95": wilson_interval(tp, positive_reference),
        "decisively_scored_positive_support": reviewed_support,
        "excluded_framework_coverage": "not_established_by_this_measure",
    }


def summarize_calibration(rows: list[dict[str, str]]) -> dict[str, Any]:
    """Compare predeclared references with scores; do not silently pool holdouts."""
    fields = {
        "case_id", "repository", "framework", "language", "family",
        "claim_kind", "partition", "reference", "predicted", "label_provenance",
    }
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != fields:
            raise EvaluationContractError("calibration row has missing/unknown fields")
        if row["case_id"] in seen:
            raise EvaluationContractError("calibration case ID duplicated")
        seen.add(row["case_id"])
        if row["reference"] not in REFERENCE_LABELS:
            raise EvaluationContractError("invalid reference label")
        if row["predicted"] not in PREDICTIONS:
            raise EvaluationContractError("invalid predicted label")
        if row["claim_kind"] not in CATEGORIES:
            raise EvaluationContractError("claim_kind must be finding or path")
        if row["partition"] not in {"regression", "calibration", "holdout", "exploratory"}:
            raise EvaluationContractError("invalid partition")
        if not all(isinstance(value, str) and value.strip() for value in row.values()):
            raise EvaluationContractError("calibration fields must be nonempty strings")
    groups: dict[tuple[str, str, str, str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        key = (row["claim_kind"], row["partition"], row["framework"],
               row["language"], row["family"])
        groups[key].append(row)
    report = {
        "overall": {
            kind: _summarize([row for row in rows if row["claim_kind"] == kind])
            for kind in sorted(CATEGORIES)
        },
        "strata": [
            {
                "claim_kind": key[0], "partition": key[1], "framework": key[2],
                "language": key[3], "family": key[4], **_summarize(groups[key]),
            }
            for key in sorted(groups)
        ],
        "label_provenance": sorted({r["label_provenance"] for r in rows}),
        "human_ground_truth_established": bool(rows) and all(
            r["label_provenance"] == "independent_human_review" for r in rows
        ),
        "model_graded_ci_blocking_approved": False,
        "reference_quality": "caller_supplied; verify G0-G3 reviewer lock separately",
        "false_positives_by_repository": dict(sorted(
            (
                repository,
                sum(
                    row["reference"] == "unsupported" and row["predicted"] == "supported"
                    for row in rows if row["repository"] == repository
                ),
            )
            for repository in {row["repository"] for row in rows}
        )),
        "runtime_success_denominator": "not_applicable_to_static_quality",
    }
    return report


def summarize_runtime_attempts(attempts: list) -> dict[str, Any]:
    """Runtime observed rates use valid completed attempts, never scanner claim counts.

    A completed-but-unresolved attempt is excluded from the observed-success
    denominator and remains separately visible. An unexecuted/error attempt is
    neither a demonstrated attack failure nor a demonstrated control.
    """
    from horustrace.evaluation.contracts import Attempt

    if any(not isinstance(attempt, Attempt) for attempt in attempts):
        raise EvaluationContractError("runtime rates require validated Attempt records")
    states = {name: sum(a.execution_state == name for a in attempts)
              for name in ("not_executed", "started", "completed",
                           "error", "timed_out", "skipped", "unknown")}
    outcomes = {name: sum(a.outcome == name for a in attempts)
                for name in ("policy_violation", "control_enforced",
                             "no_violation_observed", "unresolved", "not_executed")}
    eligible = [a for a in attempts
                if a.execution_state == "completed" and a.outcome in {
                    "policy_violation", "control_enforced", "no_violation_observed",
                }]
    violations = sum(a.outcome == "policy_violation" for a in eligible)
    return {
        "all_attempts": len(attempts),
        "execution_states": states,
        "scoped_outcomes": outcomes,
        "completed_valid_denominator": len(eligible),
        "supported_observed_policy_violations": violations,
        "observed_attack_success_rate": (
            round(violations / len(eligible), 4) if eligible else None
        ),
        "observed_attack_success_wilson_95": wilson_interval(violations, len(eligible)),
        "not_a_static_finding_or_path_precision_metric": True,
    }
