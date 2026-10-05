from __future__ import annotations

import json
from pathlib import Path

from scripts.skill_llm_calibration_study import (
    load_cohort,
    score_results,
)
from horustrace.skill_llm_semantics import SKILL_SECURITY_CONCEPTS


def _semantics(
    present: dict[str, float] | None = None,
) -> dict:
    present = present or {}
    return {
        "concepts": [
            {
                "concept": concept,
                "present": concept in present,
                "confidence": present.get(concept, 0.99),
                "intent": "explicit" if concept in present else "absent",
                "target": "",
                "evidence": ["fixture"] if concept in present else [],
                "limitations": [],
            }
            for concept in SKILL_SECURITY_CONCEPTS
        ]
    }


def test_locked_skill_llm_calibration_cohort_is_valid() -> None:
    cohort = load_cohort(
        Path("research/skill-llm-calibration-v1/cohort.json")
    )

    assert len(cohort["cases"]) == 44
    assert cohort["thresholds"] == [0.65, 0.75, 0.85]
    assert cohort["taxonomy"] == list(SKILL_SECURITY_CONCEPTS)
    strata = {
        name: sum(case["difficulty"] == name for case in cohort["cases"])
        for name in ("explicit", "inferred", "hard_negative", "multilabel")
    }
    assert strata == {
        "explicit": 12,
        "inferred": 12,
        "hard_negative": 12,
        "multilabel": 8,
    }


def test_score_results_respects_confidence_threshold() -> None:
    results = [
        {
            "case_id": "positive",
            "difficulty": "explicit",
            "expected_concepts": ["approval_bypass"],
            "semantics": _semantics({"approval_bypass": 0.80}),
        },
        {
            "case_id": "negative",
            "difficulty": "hard_negative",
            "expected_concepts": [],
            "semantics": _semantics({"approval_bypass": 0.70}),
        },
    ]

    low = score_results(results, 0.65)
    high = score_results(results, 0.75)

    assert low["per_concept"]["approval_bypass"]["tp"] == 1
    assert low["per_concept"]["approval_bypass"]["fp"] == 1
    assert high["per_concept"]["approval_bypass"]["tp"] == 1
    assert high["per_concept"]["approval_bypass"]["fp"] == 0
    assert high["exact_cases"] == 2


def test_score_results_reports_false_negative_details() -> None:
    results = [
        {
            "case_id": "secret",
            "difficulty": "inferred",
            "expected_concepts": ["secret_harvesting"],
            "semantics": _semantics({"secret_harvesting": 0.60}),
        }
    ]

    report = score_results(results, 0.75)

    assert report["micro"]["fn"] == 1
    assert report["errors"][0]["false_negatives"] == ["secret_harvesting"]
    detail = report["errors"][0]["concept_details"]["secret_harvesting"]
    assert detail["confidence"] == 0.60
