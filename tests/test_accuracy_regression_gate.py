"""Positive/negative contracts for an always-emitted scanner accuracy gate."""
from __future__ import annotations

import io
import json
import time
import zipfile
from pathlib import Path

import pytest

from scripts.accuracy_regression_gate import (
    FRESH_WORKFLOW,
    FULL_WORKFLOW,
    GateError,
    assess_run,
    choose_current_head_run,
    evaluate,
    needs_accuracy_cohorts,
    verify_artifacts,
    verify_jobs,
    verify_summary_zip,
)

SHA = "a" * 40


def _run(*, sha: str = SHA, status: str = "completed",
         conclusion: str | None = "success", pr: int = 10) -> dict:
    return {
        "id": 5,
        "head_sha": sha,
        "event": "pull_request",
        "pull_requests": [{"number": pr}],
        "created_at": "2026-10-16T08:00:00Z",
        "status": status,
        "conclusion": conclusion,
    }


def _jobs(cohort: str, ids: set[str]) -> list[dict]:
    required = (
        ["Enforce versioned pipeline and ADG integrity",
         "Enforce frozen source-claim regression gate"]
        if cohort == FRESH_WORKFLOW else
        ["Fail closed on semantic pipeline and ADG integrity",
         "Compare with exact baseline"]
    )
    entries = list(ids) + ["aggregate"]
    if cohort == FULL_WORKFLOW:
        entries.append("prepare")
    return [{
        "name": name,
        "status": "completed",
        "conclusion": "success",
        "steps": (
            [{"name": step, "conclusion": "success"} for step in required]
            if name == "aggregate" else []
        ),
    } for name in entries]


def _artifacts(cohort: str, ids: set[str]) -> list[dict]:
    prefix = (
        "fresh16-claim-gate-" if cohort == FRESH_WORKFLOW
        else "ff60-post-case-"
    )
    summary = (
        "fresh16-source-claim-gate-summary"
        if cohort == FRESH_WORKFLOW
        else "full-framework-60-post-remediation-summary"
    )
    return [{
        "name": name, "id": i + 1, "size_in_bytes": 128,
        "expired": False,
    } for i, name in enumerate(sorted({prefix + cid for cid in ids} | {summary}))]


def _zip(cohort: str, count: int, *, valid: bool = True) -> bytes:
    data = {
        "pipeline-integrity.json": {
            "total": count,
            "valid": valid,
            "errors": [] if valid else ["missing case"],
            "cases": [{"case_id": str(i), "valid": True}
                      for i in range(count)],
        },
    }
    if cohort == FRESH_WORKFLOW:
        data["semantic-claims.json"] = {"passed": valid}
        data["summary.json"] = {"completed": count, "errors": []}
    else:
        data["comparison.json"] = {
            "regression_gate": {
                "passed": valid, "failures": [] if valid else ["regressed"]
            }
        }
    result = io.BytesIO()
    with zipfile.ZipFile(result, "w") as out:
        for name, document in data.items():
            out.writestr("aggregate/" + name, json.dumps(document))
    return result.getvalue()


def test_only_docs_are_not_applicable_but_scanner_and_truth_contract_are() -> None:
    assert needs_accuracy_cohorts(["docs/overview.md"]) is False
    for changed in (
        "src/horustrace/adapters/adk.py",
        "src/horustrace/rules/builtin.py",
        "research/source-claim-regression/decisions.json",
        ".github/workflows/fresh16-source-claim-regression.yml",
        "scripts/accuracy_regression_gate.py",
    ):
        assert needs_accuracy_cohorts([changed])
    with pytest.raises(GateError, match="missing PR file"):
        needs_accuracy_cohorts([])


def test_head_sha_pr_identity_and_run_conclusions_fail_closed() -> None:
    assert choose_current_head_run([_run(sha="b" * 40)], head_sha=SHA,
                                   pr_number=10) is None
    assert choose_current_head_run([_run(pr=11)], head_sha=SHA,
                                   pr_number=10) is None
    assert choose_current_head_run([_run()], head_sha=SHA,
                                   pr_number=10)["id"] == 5
    assert assess_run(None, SHA) == "pending"
    assert assess_run(_run(status="queued", conclusion=None), SHA) == "pending"
    with pytest.raises(GateError, match="stale"):
        assess_run(_run(sha="b" * 40), SHA)
    for bad in ("failure", "cancelled", "timed_out", "skipped"):
        with pytest.raises(GateError, match="did not succeed"):
            assess_run(_run(conclusion=bad), SHA)


@pytest.mark.parametrize("cohort", [FRESH_WORKFLOW, FULL_WORKFLOW])
def test_jobs_require_every_case_aggregate_and_integrity_steps(cohort: str) -> None:
    ids = {"case-a", "case-b"}
    jobs = _jobs(cohort, ids)
    verify_jobs(jobs, cohort, ids)
    with pytest.raises(GateError, match="missing, duplicate"):
        verify_jobs(jobs[:-1], cohort, ids)
    jobs = _jobs(cohort, ids)
    jobs[0]["conclusion"] = "failure"
    with pytest.raises(GateError, match="not green"):
        verify_jobs(jobs, cohort, ids)
    jobs = _jobs(cohort, ids)
    aggregate = next(job for job in jobs if job["name"] == "aggregate")
    aggregate["steps"][0]["conclusion"] = "skipped"
    with pytest.raises(GateError, match="integrity steps"):
        verify_jobs(jobs, cohort, ids)


@pytest.mark.parametrize("cohort", [FRESH_WORKFLOW, FULL_WORKFLOW])
def test_artifacts_require_all_cases_and_nonempty_summary(cohort: str) -> None:
    ids = {"case-a", "case-b"}
    artifacts = _artifacts(cohort, ids)
    assert verify_artifacts(artifacts, cohort, ids)["id"] > 0
    with pytest.raises(GateError, match="artifact inventory"):
        verify_artifacts(artifacts[:-1], cohort, ids)
    artifacts[0]["expired"] = True
    with pytest.raises(GateError, match="expired"):
        verify_artifacts(artifacts, cohort, ids)


@pytest.mark.parametrize("cohort", [FRESH_WORKFLOW, FULL_WORKFLOW])
def test_aggregate_archive_integrity_and_red_truth_cannot_pass(cohort: str) -> None:
    verify_summary_zip(_zip(cohort, 2), cohort, 2)
    with pytest.raises(GateError, match="integrity"):
        verify_summary_zip(_zip(cohort, 2, valid=False), cohort, 2)
    with pytest.raises(GateError, match="integrity"):
        verify_summary_zip(_zip(cohort, 2), cohort, 3)


class DocsOnlyAPI:
    def pages(self, path: str, collection: str | None = None) -> list[dict]:
        assert path == "/pulls/10/files"
        return [{"filename": "docs/README.md"}]


def test_always_emitted_docs_only_gate_returns_safe_not_applicable(
    tmp_path: Path,
) -> None:
    result = evaluate(
        DocsOnlyAPI(), pr_number=10, head_sha=SHA,
        root=tmp_path, deadline=time.monotonic() + 1,
    )
    assert result["scope"] == "not_applicable"
    assert result["sha"] == SHA
    assert result["cohorts"] == {}
