import json
from pathlib import Path

from scripts.source_claim_regression_gate import (
    _read_decisions,
    _load_reference_manifest,
    _source_path,
    compare,
)


def _claim(rule: str, path: str = "/tmp/runner/target/pkg/agent.py") -> dict:
    return {
        "rule_id": rule,
        "agent": "writer",
        "location": {"path": path, "line": 23, "column": 1},
    }


def _result(findings: list[dict], sha: str = "a" * 40) -> dict:
    return {
        "case_id": "sample-001",
        "repo": "example/sample",
        "sha": sha,
        "framework": "custom",
        "counts": {"findings": len(findings)},
        "findings": findings,
    }


def _review(index: int, verdict: str = "true_positive") -> dict:
    return {"case_id": "sample-001", "finding_index": str(index),
            "rule_id": "AGT022", "verdict": verdict}


def test_matched_source_claims_are_stable_across_checkout_roots() -> None:
    old = _result([_claim("AGT022")])
    new = _result([_claim("AGT022", "/tmp/another/target/pkg/agent.py")])
    report = compare({"sample-001": old}, {"sample-001": new},
                     {("sample-001", 0): _review(0)}, {})
    assert report["passed"] is True
    assert report["removed_claims"] == []


def test_supported_claim_loss_fails_closed_without_review() -> None:
    baseline = _result([_claim("AGT022")])
    candidate = _result([])
    report = compare(
        {"sample-001": baseline}, {"sample-001": candidate},
        {("sample-001", 0): _review(0)}, {},
    )
    assert report["passed"] is False
    assert "unadjudicated" in report["gate_failures"][0]
    assert report["removed_claims"][0]["source_path"] == "pkg/agent.py"


def test_claim_removal_can_be_source_backed_without_count_restoration() -> None:
    baseline = _result([_claim("AGT022")])
    candidate = _result([])
    disposition = {
        "disposition": "scope_narrowed",
        "rationale": "Only in-memory context is updated, not an external database.",
        "source_evidence": {"path": "pkg/agent.py", "line": 23},
    }
    report = compare(
        {"sample-001": baseline}, {"sample-001": candidate},
        {("sample-001", 0): _review(0)}, {("sample-001", 0): disposition},
    )
    assert report["passed"] is True
    assert report["removed_claims"][0]["disposition"] == "scope_narrowed"


def test_historical_false_positive_removal_is_not_regression() -> None:
    baseline = _result([_claim("AGT022")])
    candidate = _result([])
    report = compare(
        {"sample-001": baseline}, {"sample-001": candidate},
        {("sample-001", 0): _review(0, "false_positive")}, {},
    )
    assert report["passed"] is True
    assert len(report["removed_claims"]) == 1


def test_duplicate_source_claims_use_a_multiset_not_set() -> None:
    claim = _claim("AGT022")
    baseline = _result([claim, claim])
    candidate = _result([claim])
    reviews = {("sample-001", i): _review(i) for i in range(2)}
    report = compare({"sample-001": baseline}, {"sample-001": candidate},
                     reviews, {})
    assert report["passed"] is False
    assert len(report["removed_claims"]) == 1


def test_cross_revision_source_sha_change_fails() -> None:
    baseline = _result([_claim("AGT022")])
    candidate = _result([_claim("AGT022")], sha="b" * 40)
    report = compare(
        {"sample-001": baseline}, {"sample-001": candidate},
        {("sample-001", 0): _review(0)}, {},
    )
    assert report["passed"] is False
    assert any("frozen sha changed" in error for error in report["gate_failures"])


def test_decisions_require_concrete_source_evidence(tmp_path: Path) -> None:
    decisions = tmp_path / "decisions.json"
    decisions.write_text(
        json.dumps({"schema_version": 1, "decisions": [{
            "case_id": "sample-001",
            "finding_index": 0,
            "disposition": "corrected_false_positive",
            "rationale": "Only in-memory context changes without persistent write.",
            "source_evidence": {"path": "pkg/agent.py", "line": 23},
        }]}),
        encoding="utf-8",
    )
    assert _read_decisions(decisions)[("sample-001", 0)]["disposition"] == (
        "corrected_false_positive"
    )
    assert _source_path(_claim("AGT022")) == "pkg/agent.py"


def test_locked_postmerge_reference_is_exact_complete_and_unadjudicated() -> None:
    manifest = (
        Path(__file__).parents[1]
        / "research"
        / "source-claim-regression"
        / "postmerge-fresh16-claims.json"
    )
    baseline, reviews = _load_reference_manifest(manifest)
    assert len(baseline) == 16
    assert sum(len(case["findings"]) for case in baseline.values()) == 49
    assert len(reviews) == 49
    assert all(item["verdict"] == "unresolved" for item in reviews.values())

    same = compare(baseline, baseline, reviews, {})
    assert same["passed"] is True
    dropped = {key: {**value, "findings": [], "counts": {"findings": 0}}
               for key, value in baseline.items()}
    report = compare(baseline, dropped, reviews, {})
    assert report["passed"] is False
    assert len(report["removed_claims"]) == 49
    assert any("unadjudicated" in failure for failure in report["gate_failures"])
