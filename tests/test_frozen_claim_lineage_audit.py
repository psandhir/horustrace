"""Offline frozen-cohort claim attribution, not a scanner-output-only recall proxy."""
import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts" / "audit_frozen_claim_lineage.py"
SPEC = importlib.util.spec_from_file_location("frozen_claim_audit", SCRIPT)
assert SPEC and SPEC.loader
audit_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit_module)


def _finding(index, rule, path="agent.py", line=4):
    return {
        "index": index,
        "rule_id": rule,
        "agent": "ops",
        "location": {"path": f"/tmp/a/target/{path}", "line": line},
    }


def _bundle(findings):
    return {
        "case_id": "case1", "repo": "example/repo", "sha": "abcdef",
        "framework": "openai-agents", "findings": findings,
        "counts": {"findings": len(findings)},
    }


def _sample(old=None, new=None, labels=None, blind=None):
    cases = {"cases": [{"case_id": "case1", "repo": "example/repo",
                        "sha": "abcdef", "framework": "openai-agents"}]}
    return audit_module.audit(
        cases,
        {"case1": (_bundle(old or []), "original_sha")},
        {"case1": (_bundle(new or []), "original_sha")},
        labels or {},
        blind_reviews=blind,
    )


def _review(reference, *, blinded=True, independent=True):
    return {
        "claim_id": "review.case1.1",
        "case_id": "case1", "rule_id": "NET001",
        "agent": "ops", "source_path": "agent.py", "source_line": 4,
        "claim_kind": "finding", "framework": "openai-agents",
        "language": "python", "family": "destination_provenance",
        "reference": reference, "reviewer_id": "external_reviewer_1",
        "independent": independent, "scanner_blinded": blinded,
        "partition": "calibration",
    }


def test_legacy_fp_disappears_without_false_independent_precision_claim():
    record = _sample(
        old=[_finding(0, "NET002")], labels={
            ("case1", 0): {"verdict": "false_positive",
                           "reason_category": "provider_managed_destination"},
        },
    )
    assert record["removed_by_prior_verdict"]["false_positive"] == 1
    assert record["independent_accuracy"]["false_negatives"] is None
    assert record["independent_accuracy"]["precision"] is None


def test_source_first_supported_missing_claim_counts_as_false_negative():
    record = _sample(blind=[_review("supported")])
    calibration = record["independent_accuracy"]["calibration"]
    assert calibration["overall"]["finding"]["fn"] == 1
    assert calibration["overall"]["finding"]["recall"] == 0
    assert calibration["model_graded_ci_blocking_approved"] is False


def test_source_first_unsupported_missing_claim_counts_as_true_negative():
    record = _sample(blind=[_review("unsupported")])
    assert record["independent_accuracy"]["calibration"]["overall"]["finding"]["tn"] == 1


def test_source_first_supported_present_claim_counts_as_true_positive():
    record = _sample(new=[_finding(0, "NET001")], blind=[_review("supported")])
    assert record["independent_accuracy"]["calibration"]["overall"]["finding"]["tp"] == 1


@pytest.mark.parametrize("blind,independent", [(False, True), (True, False)])
def test_invalid_review_provenance_is_rejected(blind, independent):
    with pytest.raises(ValueError, match="scanner-blind"):
        _sample(blind=[_review("supported", blinded=blind, independent=independent)])


def test_source_digest_mismatch_fails_closed():
    with pytest.raises(ValueError, match="source-pack digest changed"):
        audit_module.audit(
            {"cases": [{"case_id": "case1", "repo": "example/repo",
                        "sha": "abcdef", "framework": "openai-agents"}]},
            {"case1": (_bundle([]), "before")},
            {"case1": (_bundle([]), "after")}, {},
        )


def test_duplicate_identity_matching_respects_multiplicity():
    record = _sample(
        old=[_finding(0, "CAP005"), _finding(1, "CAP005")],
        new=[_finding(0, "CAP005")],
    )
    assert [x["status"] for x in record["historical_lineage"]] == ["retained", "removed"]


def test_unsafe_location_is_not_used_as_source_evidence():
    with pytest.raises(ValueError, match="Unsafe"):
        audit_module._source_location(_finding(0, "NET001", path="../secrets.txt"))


def test_cli_requires_complete_matching_pinned_cases(tmp_path):
    cohort = {"cases": [{"case_id": "case1", "repo": "example/repo",
                         "sha": "abcdef", "framework": "openai-agents"}]}
    cohort_file = tmp_path / "cohort.json"
    cohort_file.write_text(json.dumps(cohort))
    old = tmp_path / "old"
    new = tmp_path / "new"
    old.mkdir()
    new.mkdir()
    for folder in (old, new):
        case = folder / "one"
        case.mkdir()
        (case / "result.json").write_text(json.dumps(_bundle([])))
        (case / "source-pack.txt").write_text("source snapshot")
    review_file = tmp_path / "reviews.csv"
    review_file.write_text("case_id,finding_index,rule_id,verdict,reason_category\n")
    output = tmp_path / "audit.json"
    assert audit_module.main([
        "--cohort", str(cohort_file),
        "--old-dir", str(old), "--new-dir", str(new),
        "--historical-csv", str(review_file),
        "--output", str(output),
    ]) == 0
    assert json.loads(output.read_text())["cohort_size"] == 1


def test_blind_attack_path_review_uses_path_universe_not_findings():
    reference = _review("supported")
    reference["claim_id"] = "path.case1.1"
    reference["claim_kind"] = "path"
    reference["rule_id"] = "PATH001"
    record = _sample(blind=[reference])
    assert record["independent_accuracy"]["calibration"]["overall"]["path"]["fn"] == 1

    manifest = {"cases": [{"case_id": "case1", "repo": "example/repo",
                           "sha": "abcdef", "framework": "openai-agents"}]}
    candidate = _bundle([])
    candidate["attack_paths"] = [{
        "path_id": "PATH001",
        "agent": "ops", "location": {"path": "/tmp/a/target/agent.py", "line": 4},
    }]
    report = audit_module.audit(
        manifest, {"case1": (_bundle([]), "original_sha")},
        {"case1": (candidate, "original_sha")}, {},
        blind_reviews=[reference],
    )
    assert report["independent_accuracy"]["calibration"]["overall"]["path"]["tp"] == 1
