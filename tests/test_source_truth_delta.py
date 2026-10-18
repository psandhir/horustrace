"""C02e paired reference identities and source-reasoned change ledger tests."""
from __future__ import annotations

import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from horustrace.source_truth_delta import compare_source_snapshots
from horustrace.source_truth_oracle import score_reference


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), *args], stderr=subprocess.DEVNULL,
    ).decode("utf-8").strip()


def _case(tmp_path: Path) -> tuple[dict, dict, dict, dict]:
    root = tmp_path / "source"
    root.mkdir()
    _git(root, "init", "-q")
    (root / "source.py").write_text(
        "from pydantic_ai import Agent\n"
        "worker = Agent('model')\n"
        "def app_factory(): return object()\n"
        "runtime_catalogue = None\n",
        encoding="utf-8",
    )
    _git(root, "add", "source.py")
    _git(root, "-c", "user.name=fixture", "-c",
         "user.email=fixture@example.org", "commit", "-qm", "pinned")
    rev = _git(root, "rev-parse", "HEAD")
    blob = _git(root, "rev-parse", f"{rev}:source.py")
    scope = {
        "scope_id": "case1:agent:runtime",
        "case_id": "case1",
        "repository": "example/scanner-regression-case",
        "commit_sha": rev,
        "construct": "agent",
        "source_role": "runtime",
        "positive_complete": False,
        "negative_complete": False,
        "review_method": "source_reviewer",
        "review_ref": "fixture_unreviewed",
        "scanner_blind": False,
        "negative_method": "inspect constructors, factories and runtime catalogues",
    }
    ref = {"schema_version": 1, "scopes": [scope], "labels": [{
        "scope_id": scope["scope_id"],
        "claim_id": cid,
        "truth": truth,
        "source": {
            "path": "source.py", "blob_sha": blob,
            "line_start": line, "line_end": line,
        },
        "reason": "fixture provisional source label",
    } for cid, truth, line in [
        ("agent:worker", "positive", 2),
        ("factory:app", "negative", 3),
        ("catalogue:unknown", "unknown", 4),
    ]]}
    digest = score_reference(ref, [])["reference_sha256"]
    def snapshot(commit: str, ids: list[str]) -> dict:
        return {
            "schema_version": 1,
            "ontology_version": "v2_source_claims",
            "reference_sha256": digest,
            "scanner_commit_sha": commit,
            "predictions": [{
                "scope_id": scope["scope_id"], "claim_id": x,
            } for x in ids],
        }
    return ref, {scope["scope_id"]: str(root)}, snapshot(
        "a" * 40, ["factory:app", "catalogue:unknown"]
    ), snapshot("b" * 40, ["agent:worker", "catalogue:unknown"])


def test_c02e_same_scope_delta_never_infers_release_accuracy(tmp_path: Path) -> None:
    ref, roots, old, new = _case(tmp_path)
    result = compare_source_snapshots(ref, roots, old, new)
    assert result["source_witnesses_checked"] == 3
    assert result["independent_source_truth_verified"] is False
    assert result["production_cutover_authorized"] is False
    assert result["certified_precision"] is None
    assert result["certified_recall"] is None
    per = {row["claim_id"]: row for row in result["claim_deltas"]}
    assert per["agent:worker"]["change"] == "introduced"
    assert per["agent:worker"]["effect"] == (
        "candidate_true_positive_added_not_certified"
    )
    assert per["factory:app"]["change"] == "removed"
    assert per["factory:app"]["effect"] == (
        "candidate_false_positive_removed_not_certified"
    )
    assert per["catalogue:unknown"]["change"] == "retained"
    assert per["catalogue:unknown"]["source_candidate_label"] == "unknown"
    assert all(row["source_witness_verified"] for row in per.values())
    assert result["scopes"][0]["counts"]["introduced"] == 1
    assert result["scopes"][0]["counts"]["removed"] == 1


def test_c02e_new_unlabelled_prediction_is_not_false_positive(tmp_path: Path) -> None:
    ref, roots, old, new = _case(tmp_path)
    new["predictions"].append({
        "scope_id": "case1:agent:runtime", "claim_id": "shadow:unreviewed",
    })
    result = compare_source_snapshots(ref, roots, old, new)
    claim = next(x for x in result["claim_deltas"]
                 if x["claim_id"] == "shadow:unreviewed")
    assert claim["source_witness"] is None
    assert claim["source_witness_verified"] is False
    assert claim["source_candidate_label"] == "unreviewed"
    assert claim["effect"] == "unresolved_change_requires_source_adjudication"
    assert result["scopes"][0]["counts"]["unresolved_changed_claims"] == 1


def test_c02e_mismatched_reference_digest_is_rejected(tmp_path: Path) -> None:
    ref, roots, old, new = _case(tmp_path)
    new["reference_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="fingerprint mismatch"):
        compare_source_snapshots(ref, roots, old, new)


def test_c02e_wrong_ontology_is_rejected(tmp_path: Path) -> None:
    ref, roots, old, new = _case(tmp_path)
    old["ontology_version"] = "legacy_agent_factory"
    with pytest.raises(ValueError, match="ontology"):
        compare_source_snapshots(ref, roots, old, new)


def test_c02e_same_revision_is_not_old_current_study(tmp_path: Path) -> None:
    ref, roots, old, new = _case(tmp_path)
    new["scanner_commit_sha"] = old["scanner_commit_sha"]
    with pytest.raises(ValueError, match="distinct scanner revisions"):
        compare_source_snapshots(ref, roots, old, new)


def test_c02e_forged_or_missing_git_source_never_yields_delta(tmp_path: Path) -> None:
    ref, roots, old, new = _case(tmp_path)
    ref["labels"][0]["source"]["blob_sha"] = "9" * 40
    with pytest.raises(ValueError, match="blob SHA"):
        compare_source_snapshots(ref, roots, old, new)


def test_c02e_duplicate_prediction_or_bad_scope_is_rejected(tmp_path: Path) -> None:
    ref, roots, old, new = _case(tmp_path)
    new["predictions"].append(deepcopy(new["predictions"][0]))
    with pytest.raises(ValueError, match="duplicate scanner prediction"):
        compare_source_snapshots(ref, roots, old, new)
    ref, roots, old, new = _case(tmp_path / "other")
    new["predictions"][0]["scope_id"] = "not-in-source"
    with pytest.raises(ValueError, match="unknown scope"):
        compare_source_snapshots(ref, roots, old, new)


def test_c02e_empty_source_reference_has_no_accuracy(tmp_path: Path) -> None:
    ref, roots, old, new = _case(tmp_path)
    ref["scopes"] = []
    ref["labels"] = []
    with pytest.raises(ValueError, match="empty source scope"):
        compare_source_snapshots(ref, roots, old, new)


def test_c02e_removed_positive_and_new_negative_are_regressions(
    tmp_path: Path,
) -> None:
    ref, roots, old, new = _case(tmp_path)
    old["predictions"] = [{
        "scope_id": "case1:agent:runtime", "claim_id": "agent:worker",
    }]
    new["predictions"] = [{
        "scope_id": "case1:agent:runtime", "claim_id": "factory:app",
    }]
    result = compare_source_snapshots(ref, roots, old, new)
    effects = {x["effect"] for x in result["claim_deltas"]}
    assert "candidate_true_positive_lost_not_certified" in effects
    assert "candidate_false_positive_added_not_certified" in effects


def test_c02e_public_delta_does_not_leak_checkout_path(tmp_path: Path) -> None:
    ref, roots, old, new = _case(tmp_path)
    result = compare_source_snapshots(ref, roots, old, new)
    assert str(tmp_path) not in str(result)
