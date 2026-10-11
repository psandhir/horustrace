import json

from scripts.pipeline_integrity_study import EXPECTED_STAGES, audit_case, audit_study


def _scan(stages=None, *, valid=True):
    stages = EXPECTED_STAGES if stages is None else stages
    records = [
        {
            "stage": stage,
            "issues": [],
            "agents": 1,
            "attack_paths": 2,
            "findings": 3,
        }
        for stage in stages
    ]
    return {
        "summary": {"agents": 1, "attack_paths": 2, "findings": 3},
        "coverage": {
            "resolution": {
                "analysis_pipeline": {
                    "schema_version": 1,
                    "complete": True,
                    "valid": valid,
                    "stages": records,
                }
            }
        },
    }


def test_valid_study_case_has_no_findings() -> None:
    assert audit_case(_scan(), "case-001") == {
        "case_id": "case-001",
        "valid": True,
        "issues": [],
    }


def test_audit_fails_closed_on_missing_stages_and_wrong_counts() -> None:
    case = _scan(stages=EXPECTED_STAGES[:-1])
    case["summary"]["agents"] = 7
    report = audit_case(case, "case-002")
    assert report["valid"] is False
    assert any("stage order" in error for error in report["issues"])
    assert any("agents count" in error for error in report["issues"])


def test_audit_reports_integrity_issue_not_auto_compliance() -> None:
    case = _scan(valid=False)
    case["coverage"]["resolution"]["analysis_pipeline"]["stages"][-1]["issues"] = [
        "ADG edge has missing target"
    ]
    report = audit_case(case, "case-003")
    assert report["valid"] is False
    assert any("ADG edge" in error for error in report["issues"])


def test_study_fails_with_no_scans(tmp_path) -> None:
    assert audit_study(tmp_path)["valid"] is False


def test_study_reads_case_artifacts(tmp_path) -> None:
    directory = tmp_path / "case-004"
    directory.mkdir()
    (directory / "scan.json").write_text(json.dumps(_scan()), encoding="utf-8")
    result = audit_study(tmp_path)
    assert result["valid"] is True
    assert result["total"] == 1


def test_cohort_contract_rejects_missing_or_unknown_cases(tmp_path) -> None:
    first = tmp_path / "ff60-amazon-01"
    first.mkdir()
    (first / "scan.json").write_text(json.dumps(_scan()), encoding="utf-8")
    missing = audit_study(tmp_path, expected_cases={"ff60-amazon-01", "ff60-amazon-02"})
    assert missing["valid"] is False
    assert any("missing cases" in error for error in missing["errors"])

    unexpected = audit_study(tmp_path, expected_cases={"ff60-microsoft-01"})
    assert unexpected["valid"] is False
    assert any("unexpected cases" in error for error in unexpected["errors"])


def test_cohort_contract_rejects_duplicate_case_ids(tmp_path) -> None:
    for directory in ("download-one/case-01", "download-two/case-01"):
        target = tmp_path / directory
        target.mkdir(parents=True)
        (target / "scan.json").write_text(json.dumps(_scan()), encoding="utf-8")
    result = audit_study(tmp_path, expected_cases={"case-01"})
    assert result["valid"] is False
    assert any("duplicate case IDs" in error for error in result["errors"])
