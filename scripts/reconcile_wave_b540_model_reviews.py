"""Join a pinned Wave B differential to model-reviewed source evidence.

This overlay is an audit crosswalk, NOT independent adjudication or a GO gate.
It must fail closed on missing, duplicate, stale or mismatched claim identities.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

PINNED_CASE = "ff60-amazon-04"
PINNED_SOURCE_SHA = "30d03d7c9f6512e5bf10601879382fac9c3a16b1"
STATUSES = {"source_confirmed", "false_positive", "unresolved"}


def source_review_overlay(
    differential: dict[str, Any],
    ledgers: list[dict[str, Any]],
    *,
    expected_cases: int = 60,
    expected_claims: int = 73,
) -> dict[str, Any]:
    """Require exact source/claim parity without upgrading model verdicts to truth."""
    cases = differential.get("cases")
    if (
        differential.get("case_count") != expected_cases
        or not isinstance(cases, list)
        or len(cases) != expected_cases
        or differential.get("wave_c_go") is not False
        or differential.get("independent_exhaustive_ground_truth") is not False
    ):
        raise ValueError("differential must be a complete, unapproved pinned cohort")
    changed: dict[str, dict[str, Any]] = {}
    for case in cases:
        details = case.get("changed_claim_details")
        if not isinstance(details, list):
            raise ValueError("missing case claim details")
        for detail in details:
            key = detail.get("claim_key")
            if not isinstance(key, str) or key in changed:
                raise ValueError("duplicate/invalid differential claim key")
            if case.get("case_id") != PINNED_CASE:
                raise ValueError("unexpected changed case outside pinned Amazon source")
            if case.get("source_sha") != PINNED_SOURCE_SHA:
                raise ValueError("changed case source SHA does not match pinned source")
            if not key.startswith(PINNED_CASE + ":"):
                raise ValueError("claim case identity mismatch")
            if detail.get("change") not in {"added", "removed"}:
                raise ValueError("unreviewable claim delta")
            changed[key] = detail
    if len(changed) != expected_claims:
        raise ValueError(f"expected {expected_claims} changed claims, got {len(changed)}")

    reviews: dict[str, dict[str, Any]] = {}
    for ledger in ledgers:
        items = ledger.get("claims")
        if (
            not isinstance(items, list)
            or ledger.get("claim_count") != len(items)
            or ledger.get("repository_sha") != PINNED_SOURCE_SHA
            or ledger.get("reviewer_kind") != "openai_chatgpt_model_as_judge"
            or ledger.get("human_independent_review") is not False
            or ledger.get("exhaustive_negative_universe") is not False
            or ledger.get("runtime_effectiveness_verified") is not False
            or ledger.get("precision") is not None
            or ledger.get("recall") is not None
        ):
            raise ValueError("ledger lacks source pin or explicit model-only limitations")
        for item in items:
            key = item.get("claim_key")
            if not isinstance(key, str) or key in reviews:
                raise ValueError("duplicate/invalid reviewer claim key")
            if (
                item.get("repo_sha") != PINNED_SOURCE_SHA
                or item.get("reviewer_type") != "model_as_judge"
                or item.get("independent_human_review") is not False
                or item.get("runtime_effectiveness") != "not_verified"
                or item.get("status") not in STATUSES
                or not item.get("source_witnesses")
                or not str(item.get("hard_negative_evidence", "")).strip()
            ):
                raise ValueError(f"invalid source-only witness or status: {key}")
            for witness in item["source_witnesses"]:
                if (
                    not isinstance(witness, dict)
                    or len(str(witness.get("blob_sha", ""))) != 40
                    or not str(witness.get("path", "")).startswith("src/")
                    or not witness.get("lines")
                    or not witness.get("fact")
                ):
                    raise ValueError(f"invalid source blob/line witness: {key}")
            reviews[key] = item
    if set(changed) != set(reviews):
        missing = sorted(set(changed) - set(reviews))
        stale = sorted(set(reviews) - set(changed))
        raise ValueError(f"ledger/differential identity mismatch: missing={missing}, stale={stale}")

    rows: list[dict[str, Any]] = []
    for key in sorted(changed):
        claim = changed[key]
        review = reviews[key]
        for field in ("change", "rule_id", "severity"):
            if review.get(field) != claim.get(field):
                raise ValueError(f"ledger/differential {field} mismatch: {key}")
        rows.append({
            "claim_key": key,
            "change": claim["change"],
            "rule_id": claim.get("rule_id"),
            "severity": claim.get("severity"),
            "source_review_status": review["status"],
            "claim_scope": review.get("claim_scope"),
            "raw_structured_provenance_count": claim.get("raw_structured_provenance_count", 0),
            "source_witnesses": review["source_witnesses"],
            "reviewer_type": "model_as_judge",
            "independent_human_review": False,
            "runtime_effectiveness": "not_verified",
        })
    counts = Counter(row["source_review_status"] for row in rows)
    return {
        "schema_version": 1,
        "scope": "model_review_overlay_on_frozen_pinned_claim_deltas",
        "case_id": PINNED_CASE,
        "source_sha": PINNED_SOURCE_SHA,
        "claim_count": len(rows),
        "source_review_counts": dict(sorted(counts.items())),
        "raw_structured_provenance_missing_claims": sum(
            row["raw_structured_provenance_count"] == 0 for row in rows
        ),
        "independent_human_review": False,
        "independent_exhaustive_ground_truth": False,
        "runtime_effectiveness_verified": False,
        "precision": None,
        "recall": None,
        "wave_c_go": False,
        "reviewed_claims": rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--differential", required=True, type=Path)
    parser.add_argument("--ledger", required=True, type=Path, action="append")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = source_review_overlay(
        json.loads(args.differential.read_text(encoding="utf-8")),
        [json.loads(path.read_text(encoding="utf-8")) for path in args.ledger],
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "model_reviewed": report["claim_count"],
        "review_counts": report["source_review_counts"],
        "raw_provenance_missing": report["raw_structured_provenance_missing_claims"],
        "wave_c_go": report["wave_c_go"],
    }))


if __name__ == "__main__":
    main()
