"""Locked synthetic assertion calibration; not a surrogate human truth study."""
import json
from pathlib import Path

import pytest

from horustrace.evaluation.calibration import (
    summarize_calibration,
    summarize_runtime_attempts,
    wilson_interval,
)
from horustrace.evaluation.contracts import (
    Attempt,
    EvaluationCase,
    EvaluationContractError,
    Observation,
)
from horustrace.evaluation.scorers import AssertionSpec, score_assertion


def _case(row):
    return EvaluationCase.from_dict({
        "schema_version": 1, "case_id": row["case_id"],
        "family": row["family"], "scope": "external_agent",
        "objective": "Synthetic bounded assertion",
        "source_sha": "a" * 40, "scanner_sha": "b" * 40,
        "asg_digest": "sha256:" + "c" * 64,
        "target_ref": "fake://approved", "assertion_ids": ["assert.one"],
        "partition": row["partition"],
    })


def test_source_authored_fixture_scores_and_preserves_reference_status():
    path = (Path(__file__).resolve().parents[1] /
            "research/adjudicator-calibration-2026/ASSERTION_FIXTURES_v1.json")
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert doc["status"] == "source_authored_unreviewed"
    assert len(doc["cases"]) == 50
    assert {s: sum(row["reference"] == s for row in doc["cases"])
            for s in ("supported", "refuted", "unresolved")} == {
        "supported": 20, "refuted": 20, "unresolved": 10,
    }
    rows = []
    for row in doc["cases"]:
        observations = tuple(Observation.from_dict(e) for e in row["observations"])
        spec = AssertionSpec(**row["spec"])
        prediction = score_assertion(_case(row), spec, observations).verdict
        assert prediction == row["reference"], row["case_id"]
        rows.append({
            "case_id": row["case_id"], "repository": row["repository"],
            "framework": row["framework"], "language": row["language"],
            "family": row["family"], "claim_kind": row["claim_kind"],
            "partition": row["partition"], "reference": (
                "unsupported" if row["reference"] == "refuted" else row["reference"]
            ), "predicted": prediction,
            "label_provenance": row["label_provenance"],
        })
    report = summarize_calibration(rows)
    assert report["human_ground_truth_established"] is False
    assert report["model_graded_ci_blocking_approved"] is False
    assert sum(report["overall"][k]["records"] for k in ("finding", "path")) == 50
    assert report["overall"]["finding"]["reference_unresolved"] > 0
    assert len(report["strata"]) > 5
    assert any(row["partition"] == "holdout" for row in report["strata"])


def test_unresolved_is_not_free_true_negative_and_empty_denominators_are_explicit():
    rows = [{
        "case_id": "a", "repository": "repo", "framework": "adk", "language": "python",
        "family": "tool", "claim_kind": "path", "partition": "calibration",
        "reference": "supported", "predicted": "unresolved",
        "label_provenance": "automated_source_review",
    }]
    result = summarize_calibration(rows)["overall"]["path"]
    assert result["tp"] == 0 and result["reference_eligible"] == 1
    assert result["recall"] == 0.0
    assert result["precision"] is None
    assert result["prediction_unresolved"] == 1
    assert wilson_interval(0, 0) is None


def test_invalid_labeled_rows_fail_before_statistics():
    with pytest.raises(EvaluationContractError):
        summarize_calibration([{"case_id": "missing"}])



def test_runtime_observation_rates_exclude_errors_and_incomplete_attempts():
    def tested(n, state, outcome, effect):
        obs = [{
            "observation_id": f"event.{n}", "turn": 0,
            "kind": "tool_invocation", "effect": effect,
        }] if effect else []
        assertions = [{
            "assertion_id": "one", "verdict": "supported",
            "scorer_id": "deterministic", "scorer_version": "v1",
            "evidence_ids": [f"event.{n}"],
        }] if effect else []
        return Attempt.from_dict({
            "attempt_id": f"attempt.{n}", "case_id": "case.one",
            "execution_state": state, "outcome": outcome,
            "observations": obs, "assertions": assertions,
            "errors": ["synthetic failure"] if state == "error" else [],
        })

    attempts = [
        tested(1, "completed", "policy_violation", "completed"),
        tested(2, "completed", "control_enforced", "denied"),
        tested(3, "completed", "unresolved", None),
        tested(4, "error", "not_executed", None),
        tested(5, "skipped", "not_executed", None),
    ]
    report = summarize_runtime_attempts(attempts)
    assert report["all_attempts"] == 5
    assert report["completed_valid_denominator"] == 2
    assert report["supported_observed_policy_violations"] == 1
    assert report["observed_attack_success_rate"] == 0.5
    assert report["execution_states"]["error"] == 1
    assert report["execution_states"]["skipped"] == 1
    assert summarize_runtime_attempts([])["observed_attack_success_rate"] is None
