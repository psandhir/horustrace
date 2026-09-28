from __future__ import annotations

import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "real_world_semantic_benchmark.py"
SPEC = importlib.util.spec_from_file_location("semantic_benchmark", SCRIPT)
assert SPEC and SPEC.loader
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


def _benchmark() -> dict:
    return {
        "schema_version": 1,
        "benchmark": "test",
        "original_locked_truth_preserved": True,
        "methodology": {"case_count": 1},
        "cases": [{
            "case_id": "rw-x",
            "source_reference": {
                "repo": "owner/repo",
                "sha": "a" * 40,
                "framework": "custom",
                "paths": ["agent.py"],
            },
            "semantic_model": {
                "authority_facts": [
                    {"evidence_state": "observed", "fact": "A fact"}
                ],
            },
            "policy_expectations": {
                "required": [{
                    "rule_id": "AGT022",
                    "evidence_state": "observed",
                    "reason": "write",
                }],
                "forbidden": [{
                    "rule_id": "AGT020",
                    "evidence_state": "observed",
                    "reason": "not shell",
                }],
                "candidate": [],
            },
            "regression_assertions": [
                {"type": "summary_min", "field": "agents", "value": 1},
                {"type": "finding_present", "rule_id": "AGT022"},
                {"type": "finding_absent", "rule_id": "AGT020"},
            ],
        }],
    }


def test_validate_accepts_separate_semantic_layer() -> None:
    assert mod.validate(_benchmark()) == []


def test_validate_requires_policy_expectations_to_have_assertions() -> None:
    benchmark = _benchmark()
    benchmark["cases"][0]["regression_assertions"] = []
    errors = mod.validate(benchmark)
    assert any(
        "required AGT022 lacks matching regression assertion" in error
        for error in errors
    )
    assert any(
        "forbidden AGT020 lacks matching regression assertion" in error
        for error in errors
    )


def test_score_catches_false_positive_missing_finding_and_summary_gap() -> None:
    result = {
        "scanner_sha": "b" * 40,
        "cases": [{
            "case_id": "rw-x",
            "findings": [{
                "rule_id": "AGT020",
                "location": {"path": "/tmp/tools.py", "line": 1},
            }],
            "observed": {"summary": {"agents": 0}},
        }],
    }
    report = mod.score(result, _benchmark())
    assert report["assertions"] == 3
    assert report["passed"] == 0
    assert report["failed"] == 3


def test_finding_path_filter_only_rejects_targeted_false_positive() -> None:
    benchmark = _benchmark()
    benchmark["cases"][0]["policy_expectations"]["forbidden"][0][
        "path_contains"
    ] = "sql.py"
    benchmark["cases"][0]["regression_assertions"][2]["path_contains"] = "sql.py"
    result = {
        "cases": [{
            "case_id": "rw-x",
            "findings": [{
                "rule_id": "AGT020",
                "location": {"path": "/tmp/other.py", "line": 1},
            }],
            "observed": {"summary": {"agents": 1}},
        }],
    }
    report = mod.score(result, benchmark)
    assert report["cases"][0]["assertions"][2]["passed"] is True
