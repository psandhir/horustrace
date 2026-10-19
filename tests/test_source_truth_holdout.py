"""C02d provisional unseen holdout sealing: no implicit independence claims."""
from __future__ import annotations

import json
import os
import stat
import sys
from copy import deepcopy

import pytest

from horustrace.source_truth_holdout import main, seal_holdout, verify_holdout_seal


def _inputs() -> tuple[dict, dict, dict]:
    cases = {
        "schema_version": 1,
        "cases": [
            {
                "case_id": "d01-adk-01", "repository": "example/unseen-adk",
                "commit_sha": "a" * 40, "framework": "adk",
                "source_role": "runtime",
            },
            {
                "case_id": "d01-strands-01", "repository": "example/unseen-strands",
                "commit_sha": "b" * 40, "framework": "strands",
                "source_role": "runtime",
            },
            {
                "case_id": "legacy", "repository": "example/exposed-repo",
                "commit_sha": "c" * 40, "framework": "mcp",
                "source_role": "test",
            },
        ],
    }
    exposed = {
        "schema_version": 1,
        "known_exposed_repositories": ["example/exposed-repo"],
        "inventory_declared_complete": True,
        "inventory_ref": "fixture-exposure-inventory-not-independent",
    }
    selection = {
        "schema_version": 1,
        "selected_case_ids": ["d01-strands-01", "d01-adk-01"],
        "source_selection_ref": "synthetic-selection-not-holdout",
        "selection_protocol": "predeclared independent source-only sampling fixture",
    }
    return cases, exposed, selection


def test_c02d_private_manifest_public_commitment_replay() -> None:
    inputs = _inputs()
    sealed = seal_holdout(*inputs)
    public = sealed["public_commitment"]
    private = sealed["private_manifest"]
    assert len(private["selected_cases"]) == 2
    assert public["case_count"] == 2
    assert public["manifest_sha256"] == private["manifest_sha256"]
    assert "selected_cases" not in public
    assert "unseen-adk" not in str(public)
    assert "unseen-strands" not in str(public)
    assert public["holdout_unseen_externally_verified"] is False
    assert private["release_certified"] is False
    verified = verify_holdout_seal(*inputs, private, public)
    assert verified["replay_matches_sealed_inputs"] is True
    assert verified["release_certified"] is False


def test_c02d_order_of_selection_does_not_change_manifest() -> None:
    cases, exposed, selection = _inputs()
    first = seal_holdout(cases, exposed, selection)
    selection["selected_case_ids"].reverse()
    # Selection-input provenance binds the exact original selection input.
    second = seal_holdout(cases, exposed, selection)
    assert first["private_manifest"]["selected_cases"] == (
        second["private_manifest"]["selected_cases"]
    )
    assert first["private_manifest"]["manifest_sha256"] != (
        second["private_manifest"]["manifest_sha256"]
    )


def test_c02d_previously_exposed_repository_is_not_reusable() -> None:
    cases, exposed, selection = _inputs()
    selection["selected_case_ids"] = ["legacy"]
    with pytest.raises(ValueError, match="previously exposed"):
        seal_holdout(cases, exposed, selection)


def test_c02d_no_closed_exposure_inventory_means_no_holdout() -> None:
    cases, exposed, selection = _inputs()
    exposed["inventory_declared_complete"] = False
    with pytest.raises(ValueError, match="incomplete exposure"):
        seal_holdout(cases, exposed, selection)


def test_c02d_missing_candidate_or_duplicate_id_denied() -> None:
    cases, exposed, selection = _inputs()
    selection["selected_case_ids"] = ["unlisted"]
    with pytest.raises(ValueError, match="absent"):
        seal_holdout(cases, exposed, selection)
    selection["selected_case_ids"] = ["d01-adk-01", "d01-adk-01"]
    with pytest.raises(ValueError, match="duplicate selected"):
        seal_holdout(cases, exposed, selection)


def test_c02d_private_manifest_tampering_is_detected() -> None:
    inputs = _inputs()
    original = seal_holdout(*inputs)
    private = deepcopy(original["private_manifest"])
    private["selected_cases"][0]["commit_sha"] = "d" * 40
    with pytest.raises(ValueError, match="private holdout"):
        verify_holdout_seal(
            *inputs, private, original["public_commitment"]
        )


def test_c02d_public_commitment_tampering_is_detected() -> None:
    inputs = _inputs()
    original = seal_holdout(*inputs)
    public = deepcopy(original["public_commitment"])
    public["case_count"] = 77
    with pytest.raises(ValueError, match="public commitment"):
        verify_holdout_seal(
            *inputs, original["private_manifest"], public
        )


@pytest.mark.parametrize("change", ["wrong_sha", "zero_sha", "unportable_id", "bad_role"])
def test_c02d_invalid_candidate_rejected(change: str) -> None:
    cases, exposed, selection = _inputs()
    row = cases["cases"][0]
    if change == "wrong_sha":
        row["commit_sha"] = "main"
    elif change == "zero_sha":
        row["commit_sha"] = "0" * 40
    elif change == "unportable_id":
        row["case_id"] = "../secret"
    else:
        row["source_role"] = "live_authority"
    with pytest.raises(ValueError):
        seal_holdout(cases, exposed, selection)


def test_c02d_two_selected_commits_in_same_repository_are_denied() -> None:
    cases, exposed, selection = _inputs()
    cases["cases"].append({
        "case_id": "d01-adk-02", "repository": "example/unseen-adk",
        "commit_sha": "d" * 40, "framework": "adk", "source_role": "runtime",
    })
    selection["selected_case_ids"] = ["d01-adk-01", "d01-adk-02"]
    with pytest.raises(ValueError, match="multiple commits"):
        seal_holdout(cases, exposed, selection)


def test_c02d_cannot_tell_scanner_predictions_or_labels_to_selector() -> None:
    cases, exposed, selection = _inputs()
    cases["cases"][0]["scanner_detected"] = True
    with pytest.raises(ValueError, match="exactly"):
        seal_holdout(cases, exposed, selection)
    cases, exposed, selection = _inputs()
    selection["scanner_score"] = 1.0
    with pytest.raises(ValueError, match="exactly"):
        seal_holdout(cases, exposed, selection)


def test_c02d_duplicate_candidate_ontology_is_rejected() -> None:
    cases, exposed, selection = _inputs()
    cases["cases"].append(deepcopy(cases["cases"][0]))
    with pytest.raises(ValueError, match="duplicate candidate"):
        seal_holdout(cases, exposed, selection)


def test_c02d_no_selected_cases_is_rejected() -> None:
    cases, exposed, selection = _inputs()
    selection["selected_case_ids"] = []
    with pytest.raises(ValueError, match="empty holdout"):
        seal_holdout(cases, exposed, selection)


def test_c02d_external_access_and_source_truth_are_never_certified() -> None:
    inputs = _inputs()
    sealed = seal_holdout(*inputs)
    for row in sealed.values():
        assert row["external_access_log_verified"] is False
        assert row["release_certified"] is False
    assert sealed["private_manifest"]["reviewer_independence_verified"] is False
    assert sealed["private_manifest"]["source_universe_completeness_verified"] is False


def test_c02d_cli_never_prints_private_case_ids_or_overwrites(
    tmp_path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    candidates, exposure, selection = _inputs()
    inputs = []
    for filename, value in [
        ("candidates.json", candidates),
        ("exposures.json", exposure),
        ("selection.json", selection),
    ]:
        path = tmp_path / filename
        path.write_text(json.dumps(value), encoding="utf-8")
        inputs.append(str(path))
    private = tmp_path / "private.json"
    public = tmp_path / "public.json"
    monkeypatch.setattr(sys, "argv", [
        "source_truth_holdout",
        "--candidates", inputs[0],
        "--exposures", inputs[1],
        "--selection", inputs[2],
        "--private-output", str(private),
        "--public-output", str(public),
    ])
    assert main() == 0
    printed = capsys.readouterr().out
    assert "d01-adk-01" not in printed
    assert "unseen-adk" not in printed
    assert "private_manifest_redacted" in printed
    assert json.loads(private.read_text())["selected_cases"][0]["case_id"]
    assert "selected_cases" not in json.loads(public.read_text())
    if os.name == "posix":
        assert stat.S_IMODE(private.stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        main()



def test_c02d_public_seal_does_not_leak_replayable_pool_hashes() -> None:
    inputs = _inputs()
    first = seal_holdout(*inputs)
    second = seal_holdout(*inputs)
    public = first["public_commitment"]
    assert "candidate_pool_sha256" not in public
    assert "exposure_inventory_sha256" not in public
    assert "selection_input_sha256" not in public
    assert "selection_ref" not in public
    assert "private_nonce" not in public
    assert first["private_manifest"]["private_nonce"] != (
        second["private_manifest"]["private_nonce"]
    )
    assert public["manifest_sha256"] != second["public_commitment"]["manifest_sha256"]
    assert verify_holdout_seal(
        *inputs, first["private_manifest"], first["public_commitment"]
    )["replay_matches_sealed_inputs"] is True


def test_c02d_missing_or_malformed_private_nonce_fails_closed() -> None:
    inputs = _inputs()
    sealed = seal_holdout(*inputs)
    private = deepcopy(sealed["private_manifest"])
    del private["private_nonce"]
    with pytest.raises(ValueError, match="nonce"):
        verify_holdout_seal(*inputs, private, sealed["public_commitment"])
    private = deepcopy(sealed["private_manifest"])
    private["private_nonce"] = "123"
    with pytest.raises(ValueError, match="nonce"):
        verify_holdout_seal(*inputs, private, sealed["public_commitment"])
