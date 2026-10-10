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
