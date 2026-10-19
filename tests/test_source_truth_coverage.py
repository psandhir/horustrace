"""C02f prevents cherry-picked reference accuracy by surfacing missing strata."""
from __future__ import annotations

import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from horustrace.source_truth_coverage import source_truth_coverage


def _git(path: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(path), *args], stderr=subprocess.DEVNULL,
    ).decode("utf-8").strip()


def _case(tmp_path: Path) -> tuple[dict, dict, dict]:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    (root / "agent.py").write_text(
        "from pydantic_ai import Agent\n"
        "worker = Agent('model')\n"
        "def factory(): return object()\n",
        encoding="utf-8",
    )
    _git(root, "add", "agent.py")
    _git(root, "-c", "user.name=fixture", "-c",
         "user.email=fixture@example.org", "commit", "-qm", "source")
    commit = _git(root, "rev-parse", "HEAD")
    blob = _git(root, "rev-parse", f"{commit}:agent.py")
    expected = {
        "schema_version": 1,
        "manifest_ref": "fixture-no-independent-cohort",
        "expected_scopes": [{
            "scope_id": "case1:agent:runtime",
            "case_id": "case1", "repository": "example/adk",
            "commit_sha": commit, "framework": "adk",
            "construct": "agent", "source_role": "runtime",
        }, {
            "scope_id": "case2:mcp:test",
            "case_id": "case2", "repository": "example/mcp",
            "commit_sha": "d" * 40, "framework": "strands",
            "construct": "mcp_server", "source_role": "test",
        }],
    }
    reference = {
        "schema_version": 1,
        "scopes": [{
            "scope_id": "case1:agent:runtime",
            "case_id": "case1",
            "repository": "example/adk", "commit_sha": commit,
            "construct": "agent", "source_role": "runtime",
            "positive_complete": True, "negative_complete": True,
            "review_method": "independent_blind",
            "review_ref": "synthetic-self-declared",
            "scanner_blind": True,
            "negative_method": "enumerate source constructors and factories",
        }],
        "labels": [{
            "scope_id": "case1:agent:runtime",
            "claim_id": claim,
            "truth": truth,
            "source": {
                "path": "agent.py", "blob_sha": blob,
                "line_start": line, "line_end": line,
            },
            "reason": "fixture only",
        } for claim, truth, line in [
            ("agent:worker", "positive", 2),
            ("factory:not-agent", "negative", 3),
        ]],
    }
    return expected, reference, {"case1:agent:runtime": str(root)}


def test_c02f_missing_framework_context_is_in_denominator(tmp_path: Path) -> None:
    expected, reference, checkouts = _case(tmp_path)
    report = source_truth_coverage(expected, reference, checkouts)
    assert report["expected_scope_count"] == 2
    assert report["referenced_scope_count"] == 1
    assert report["missing_scope_count"] == 1
    assert report["certified_precision"] is None
    assert report["certified_recall"] is None
    assert report["production_cutover_authorized"] is False
    cases = {x["scope_id"]: x for x in report["scopes"]}
    assert cases["case1:agent:runtime"]["source_witnesses_git_verified"] is True
    assert cases["case1:agent:runtime"]["positive_labels"] == 1
    assert cases["case1:agent:runtime"]["negative_labels"] == 1
    assert "external_review_independence_not_verified" in (
        cases["case1:agent:runtime"]["blockers"]
    )
    assert cases["case2:mcp:test"]["blockers"][0] == "missing_reference_scope"
    assert report["framework_construct_context"][0]["framework"] == "adk"


def test_c02f_disputed_label_is_not_silent_negative(tmp_path: Path) -> None:
    expected, reference, checkouts = _case(tmp_path)
    reference["labels"][1]["truth"] = "unknown"
    report = source_truth_coverage(expected, reference, checkouts)
    scope = report["scopes"][0]
    assert scope["negative_labels"] == 0
    assert scope["unknown_labels"] == 1
    assert "no_source_hard_negative_labels" in scope["blockers"]
    assert "unresolved_source_labels" in scope["blockers"]


def test_c02f_declared_closed_reference_remains_uncertified(tmp_path: Path) -> None:
    expected, reference, checkouts = _case(tmp_path)
    expected["expected_scopes"] = expected["expected_scopes"][:1]
    report = source_truth_coverage(expected, reference, checkouts)
    assert report["missing_scope_count"] == 0
    assert report["certified_precision"] is None
    assert report["independent_review_externally_verified"] is False
    assert report["expected_cohort_completeness_externally_verified"] is False


def test_c02f_pinned_case_drift_rejected(tmp_path: Path) -> None:
    expected, reference, checkouts = _case(tmp_path)
    reference["scopes"][0]["commit_sha"] = "a" * 40
    with pytest.raises(ValueError, match="differs"):
        source_truth_coverage(expected, reference, checkouts)


def test_c02f_wrong_source_blob_rejected(tmp_path: Path) -> None:
    expected, reference, checkouts = _case(tmp_path)
    reference["labels"][0]["source"]["blob_sha"] = "f" * 40
    with pytest.raises(ValueError, match="blob SHA"):
        source_truth_coverage(expected, reference, checkouts)


def test_c02f_extra_reference_scope_not_in_cohort_is_rejected(
    tmp_path: Path,
) -> None:
    expected, reference, checkouts = _case(tmp_path)
    copy = deepcopy(reference["scopes"][0])
    copy["scope_id"] = "extra"
    copy["case_id"] = "extra"
    reference["scopes"].append(copy)
    with pytest.raises(ValueError, match="unexpected cohort scopes"):
        source_truth_coverage(expected, reference, checkouts)


def test_c02f_duplicate_expected_scope_rejected(tmp_path: Path) -> None:
    expected, reference, checkouts = _case(tmp_path)
    expected["expected_scopes"].append(
        deepcopy(expected["expected_scopes"][0])
    )
    with pytest.raises(ValueError, match="duplicate expected"):
        source_truth_coverage(expected, reference, checkouts)


def test_c02f_empty_expected_manifest_denies_coverage(tmp_path: Path) -> None:
    expected, reference, checkouts = _case(tmp_path)
    expected["expected_scopes"] = []
    with pytest.raises(ValueError, match="empty expected"):
        source_truth_coverage(expected, reference, checkouts)


def test_c02f_drops_no_explicit_expected_scopes(tmp_path: Path) -> None:
    expected, reference, _checkouts = _case(tmp_path)
    reference["scopes"] = []
    reference["labels"] = []
    result = source_truth_coverage(expected, reference, {})
    assert result["missing_scope_count"] == 2
    assert len(result["scopes"]) == 2
    assert all(not row["reference_present"] for row in result["scopes"])



def test_c02f_empty_label_scope_never_claims_witness_verification(
    tmp_path: Path,
) -> None:
    expected, reference, checkouts = _case(tmp_path)
    expected["expected_scopes"] = expected["expected_scopes"][:1]
    reference["labels"] = []
    report = source_truth_coverage(expected, reference, checkouts)
    assert report["referenced_scope_count"] == 1
    scope = report["scopes"][0]
    assert scope["source_witnesses_git_verified"] is False
    assert scope["positive_labels"] == 0
    assert scope["negative_labels"] == 0
    assert "no_source_positive_labels" in scope["blockers"]
    assert "no_source_hard_negative_labels" in scope["blockers"]
    assert report["certified_precision"] is None
