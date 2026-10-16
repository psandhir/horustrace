"""Guard against accidental weakening of scanner accuracy CI workflows.

These tests preserve scanner-source triggers, full matrices and fail-closed
aggregation. They do not replace GitHub's branch ruleset enforcement.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest
import yaml

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"


def _load(name: str) -> dict:
    result = yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))
    assert isinstance(result, dict)
    return result


def _events(document: dict) -> dict:
    # PyYAML 1.1 interprets the unquoted GitHub Actions on: key as True.
    events = document.get("on", document.get(True))
    assert isinstance(events, dict)
    return events


def _runs(job: dict) -> str:
    return "\n".join(str(step.get("run", "")) for step in job["steps"])


def _broad_source_trigger(document: dict) -> None:
    events = _events(document)
    pull_request = events.get("pull_request")
    assert isinstance(pull_request, dict), "a cohort PR trigger must exist"
    assert "src/horustrace/**" in pull_request.get("paths", []), (
        "every production scanner source change must trigger this cohort"
    )


def _fail_closed_aggregate(document: dict, prerequisite: str) -> dict:
    aggregate = document["jobs"]["aggregate"]
    assert "always()" in str(aggregate.get("if", ""))
    needs = aggregate.get("needs", [])
    if isinstance(needs, str):
        needs = [needs]
    assert prerequisite in needs
    steps = aggregate["steps"]
    assert any("actions/download-artifact@" in step.get("uses", "") for step in steps)
    assert any(
        "actions/upload-artifact@" in step.get("uses", "")
        and step.get("if") == "always()"
        for step in steps
    )
    return aggregate


def test_all_prs_keep_core_ci_and_branch_coverage() -> None:
    document = _load("ci.yml")
    events = _events(document)
    assert "pull_request" in events
    assert events["pull_request"] is None, "core CI may not be path-filtered"
    jobs = document["jobs"]
    assert {"test", "package", "self-scan"} <= jobs.keys()
    assert jobs["test"]["strategy"]["matrix"]["python-version"] == ["3.11", "3.12"]
    commands = _runs(jobs["test"])
    assert "ruff check" in commands
    assert "pytest -q" in commands
    assert "--cov-branch" in commands
    assert "--cov-fail-under=82" in commands
    assert "scripts/run_static_metamorphic.py" in commands
    assert "horustrace scan examples/secure-agent" in _runs(jobs["self-scan"])


def test_full60_is_broad_and_fails_closed_on_missing_cases() -> None:
    document = _load("full-framework-60-post-remediation-20261006.yml")
    _broad_source_trigger(document)
    jobs = document["jobs"]
    prepare = _runs(jobs["prepare"])
    assert "assert len(cases) == 60" in prepare
    assert 'Counter(case["framework"] for case in cases)' in prepare
    assert all(
        f'"{name}": 10' in prepare
        for name in (
            "google-adk", "pydantic-ai", "openai-agents",
            "amazon", "anthropic", "microsoft",
        )
    )
    assert jobs["scan"]["needs"] == "prepare"
    assert jobs["scan"]["strategy"]["fail-fast"] is False
    assert "matrix" in jobs["scan"]["strategy"]
    aggregate = _fail_closed_aggregate(document, "scan")
    commands = _runs(aggregate)
    assert "scripts/pipeline_integrity_study.py" in commands
    assert "full-framework-60-post-remediation-20261006/compare.py" in commands
    assert "--gate-baseline" in commands


def test_fresh16_preserves_all_cases_and_source_claim_truth_gate() -> None:
    document = _load("fresh16-source-claim-regression.yml")
    _broad_source_trigger(document)
    jobs = document["jobs"]
    scan = jobs["scan"]
    assert scan["strategy"]["fail-fast"] is False
    case_ids = scan["strategy"]["matrix"]["case_id"]
    assert len(case_ids) == len(set(case_ids)) == 16
    assert Counter(case.rsplit("-", 1)[0] for case in case_ids) == {
        "gen-adk": 4, "gen-pyd": 4, "gen-oai": 4, "gen-mcp": 4,
    }
    assert any("Verify frozen source cohort" in step.get("name", "")
               for step in scan["steps"])
    aggregate = _fail_closed_aggregate(document, "scan")
    commands = _runs(aggregate)
    assert "scripts/pipeline_integrity_study.py" in commands
    assert "scripts/source_claim_regression_gate.py" in commands
    assert "--baseline-manifest" in commands
    assert "--decisions" in commands


def test_codeql_covers_main_prs_without_file_exclusions() -> None:
    document = _load("codeql.yml")
    events = _events(document)
    assert "main" in events["pull_request"]["branches"]
    assert "paths" not in events["pull_request"]
    assert any(
        "github/codeql-action/analyze@" in step.get("uses", "")
        for step in document["jobs"]["analyze"]["steps"]
    )


def test_mutated_source_trigger_is_rejected() -> None:
    document = _load("full-framework-60-post-remediation-20261006.yml")
    _events(document)["pull_request"]["paths"].remove("src/horustrace/**")
    with pytest.raises(AssertionError, match="production scanner source"):
        _broad_source_trigger(document)


def test_stable_accuracy_gate_always_emits_one_required_context() -> None:
    gate = _load("accuracy-regression-gate.yml")
    events = _events(gate)
    assert "pull_request" in events
    assert "paths" not in (events["pull_request"] or {})
    jobs = gate["jobs"]
    assert "accuracy-regression-gate" in jobs
    job = jobs["accuracy-regression-gate"]
    assert job["name"] == "accuracy-regression-gate"
    assert int(job["timeout-minutes"]) >= 90
    commands = _runs(job)
    assert "scripts/accuracy_regression_gate.py" in commands
    assert "--head" in commands
    assert gate["permissions"]["actions"] == "read"
    assert gate["permissions"]["pull-requests"] == "read"
    # The truth/evaluation contract gate itself must trigger both full matrices.
    for name in (
        "fresh16-source-claim-regression.yml",
        "full-framework-60-post-remediation-20261006.yml",
    ):
        cohort = _load(name)
        paths = _events(cohort)["pull_request"]["paths"]
        assert "src/horustrace/**" in paths
        assert "scripts/accuracy_regression_gate.py" in paths
        assert ".github/workflows/accuracy-regression-gate.yml" in paths
        assert "tests/test_accuracy_regression_gate.py" in paths
