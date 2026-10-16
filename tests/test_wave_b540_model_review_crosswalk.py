"""Model review is a diagnostic overlay, never an independent Wave B sign-off."""
from __future__ import annotations

import copy

import pytest

from scripts.reconcile_wave_b540_model_reviews import (
    PINNED_CASE,
    PINNED_SOURCE_SHA,
    source_review_overlay,
)


def _claim(name: str, severity: str, change: str) -> dict:
    return {
        "claim_key": f"{PINNED_CASE}:{name}",
        "rule_id": "AGT040",
        "severity": severity,
        "change": change,
        "raw_structured_provenance_count": 0,
    }


def _review(claim: dict, status: str) -> dict:
    return {
        **claim,
        "repo_sha": PINNED_SOURCE_SHA,
        "status": status,
        "reviewer_type": "model_as_judge",
        "independent_human_review": False,
        "runtime_effectiveness": "not_verified",
        "hard_negative_evidence": "Runtime authority is not established.",
        "source_witnesses": [{
            "blob_sha": "a" * 40,
            "path": "src/agents/worker.py",
            "lines": "18-21",
            "fact": "Original pinned source declares a tool, not runtime access.",
        }],
    }


def _ledger(claim: dict, status: str) -> dict:
    return {
        "claims": [_review(claim, status)],
        "claim_count": 1,
        "repository_sha": PINNED_SOURCE_SHA,
        "reviewer_kind": "openai_chatgpt_model_as_judge",
        "human_independent_review": False,
        "exhaustive_negative_universe": False,
        "runtime_effectiveness_verified": False,
        "precision": None,
        "recall": None,
    }


def _fixture() -> tuple[dict, list[dict]]:
    high = _claim("a" * 20, "high", "added")
    medium = _claim("b" * 20, "medium", "removed")
    differential = {
        "case_count": 1,
        "independent_exhaustive_ground_truth": False,
        "wave_c_go": False,
        "cases": [{
            "case_id": PINNED_CASE,
            "source_sha": PINNED_SOURCE_SHA,
            "changed_claim_details": [high, medium],
        }],
    }
    return differential, [_ledger(high, "source_confirmed"), _ledger(medium, "false_positive")]


def _run(report: dict, ledgers: list[dict]) -> dict:
    return source_review_overlay(report, ledgers, expected_cases=1, expected_claims=2)


def test_complete_source_only_overlay_never_grants_wave_c_go() -> None:
    report, ledgers = _fixture()
    result = _run(report, ledgers)
    assert result["claim_count"] == 2
    assert result["source_review_counts"] == {
        "false_positive": 1, "source_confirmed": 1,
    }
    assert result["raw_structured_provenance_missing_claims"] == 2
    assert result["wave_c_go"] is False
    assert result["independent_human_review"] is False
    assert result["precision"] is None and result["recall"] is None
    assert result["reviewed_claims"][0]["runtime_effectiveness"] == "not_verified"


def test_unreviewed_or_extra_claim_fails_closed() -> None:
    report, ledgers = _fixture()
    with pytest.raises(ValueError, match="identity mismatch"):
        _run(report, ledgers[:1])
    bogus = copy.deepcopy(ledgers[1])
    bogus["claims"][0]["claim_key"] = f"{PINNED_CASE}:{'c' * 20}"
    with pytest.raises(ValueError, match="identity mismatch"):
        _run(report, [ledgers[0], bogus])


def test_mismatched_rule_or_change_is_not_same_claim() -> None:
    report, ledgers = _fixture()
    ledgers[0]["claims"][0]["rule_id"] = "AGT021"
    with pytest.raises(ValueError, match="rule_id mismatch"):
        _run(report, ledgers)
    report, ledgers = _fixture()
    ledgers[1]["claims"][0]["change"] = "added"
    with pytest.raises(ValueError, match="change mismatch"):
        _run(report, ledgers)


def test_human_review_and_runtime_effectiveness_cannot_be_fabricated() -> None:
    report, ledgers = _fixture()
    ledgers[0]["human_independent_review"] = True
    with pytest.raises(ValueError, match="model-only limitations"):
        _run(report, ledgers)
    report, ledgers = _fixture()
    ledgers[0]["claims"][0]["runtime_effectiveness"] = "verified"
    with pytest.raises(ValueError, match="source-only witness"):
        _run(report, ledgers)


def test_case_source_sha_and_duplicate_reviews_fail_closed() -> None:
    report, ledgers = _fixture()
    report["cases"][0]["source_sha"] = "b" * 40
    with pytest.raises(ValueError, match="source SHA"):
        _run(report, ledgers)
    report, ledgers = _fixture()
    with pytest.raises(ValueError, match="duplicate/invalid reviewer"):
        _run(report, [ledgers[0], ledgers[0], ledgers[1]])


def test_empty_or_invented_provenance_is_rejected() -> None:
    report, ledgers = _fixture()
    ledgers[0]["claims"][0]["source_witnesses"][0]["blob_sha"] = "unknown"
    with pytest.raises(ValueError, match="source blob"):
        _run(report, ledgers)
    report, ledgers = _fixture()
    report["independent_exhaustive_ground_truth"] = True
    with pytest.raises(ValueError, match="unapproved pinned cohort"):
        _run(report, ledgers)
