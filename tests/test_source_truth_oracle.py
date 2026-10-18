"""Wave C source-oracle methodology and fail-closed hard negatives."""
from __future__ import annotations

from copy import deepcopy

import pytest

from horustrace.source_truth_oracle import (
    score_reference,
    validate_reference,
)

COMMIT = "1" * 40
BLOB = "2" * 40


def _scope(**overrides: object) -> dict[str, object]:
    scope: dict[str, object] = {
        "scope_id": "d01:agents:runtime",
        "case_id": "d01",
        "repository": "example/pinned-case",
        "commit_sha": COMMIT,
        "construct": "agent",
        "source_role": "runtime",
        "positive_complete": True,
        "negative_complete": True,
        "review_method": "independent_blind",
        "review_ref": "external_review_attestation_fixture_only",
        "scanner_blind": True,
        "negative_method": "complete source symbol enumeration and near-miss review",
    }
    scope.update(overrides)
    return scope


def _label(claim_id: str, truth: str, *, path: str = "src/agent.py",
           line: int = 3) -> dict[str, object]:
    return {
        "scope_id": "d01:agents:runtime",
        "claim_id": claim_id,
        "truth": truth,
        "source": {
            "path": path, "blob_sha": BLOB,
            "line_start": line, "line_end": line,
        },
        "reason": "fixture source adjudication, never real human review",
    }


def _oracle() -> dict[str, object]:
    return {
        "schema_version": 1,
        "scopes": [_scope()],
        "labels": [
            _label("agent:real", "positive"),
            _label("factory:not-agent", "negative", line=9),
            _label("alias:not-agent", "negative", line=14),
        ],
    }


def test_c02a_exact_reference_with_positive_negative_universe_scores() -> None:
    ref = _oracle()
    output = score_reference(ref, [
        {"scope_id": "d01:agents:runtime", "claim_id": "agent:real"},
        {"scope_id": "d01:agents:runtime", "claim_id": "factory:not-agent"},
    ])
    assert output["all_scopes_assessable"] is True
    assert output["aggregate"] == {
        "tp": 1, "fp": 1, "fn": 0, "tn": 1,
        "precision": 0.5, "recall": 1.0,
    }
    assert output["independent_reviewer_attestation_externally_verified"] is False
    assert output["mode"] == (
        "offline_source_oracle_methodology_not_release_certification"
    )


def test_c02a_no_predictions_are_not_automatically_zero_precision() -> None:
    output = score_reference(_oracle(), [])
    assert output["aggregate"]["tp"] == 0
    assert output["aggregate"]["fp"] == 0
    assert output["aggregate"]["fn"] == 1
    assert output["aggregate"]["tn"] == 2
    assert output["aggregate"]["precision"] is None
    assert output["aggregate"]["recall"] == 0.0


@pytest.mark.parametrize("scope_change,blocker", [
    ({"positive_complete": False}, "incomplete_positive_universe"),
    ({"negative_complete": False}, "incomplete_negative_universe"),
    ({"review_method": "model_reviewed"}, "reference_not_declared_independent_blind"),
    ({"review_method": "test_author"}, "reference_not_declared_independent_blind"),
    ({"scanner_blind": False}, "review_not_scanner_blind"),
])
def test_c02a_any_incomplete_or_unblinded_scope_denies_metrics(
    scope_change: dict[str, object], blocker: str,
) -> None:
    ref = _oracle()
    ref["scopes"] = [_scope(**scope_change)]
    out = score_reference(ref, [
        {"scope_id": "d01:agents:runtime", "claim_id": "agent:real"},
    ])
    assert out["aggregate"] is None
    assert out["scopes"][0]["status"] == "not_assessed"
    assert blocker in out["scopes"][0]["blockers"]
    assert out["scopes"][0]["precision"] is None


def test_c02a_unknown_and_unlabelled_scanner_claim_never_auto_false_positive() -> None:
    ref = _oracle()
    ref["labels"].append(_label("runtime:unknown", "unknown"))
    out = score_reference(ref, [
        {"scope_id": "d01:agents:runtime", "claim_id": "agent:real"},
        {"scope_id": "d01:agents:runtime", "claim_id": "unseen:tool"},
    ])
    assert out["aggregate"] is None
    assert out["scopes"][0]["unknown_labels"] == 1
    assert out["scopes"][0]["unlabelled_prediction_ids"] == ["unseen:tool"]
    assert set(out["scopes"][0]["blockers"]) == {
        "unlabelled_scanner_predictions", "unresolved_source_labels",
    }


def test_c02a_all_scopes_required_before_pooled_numbers() -> None:
    ref = _oracle()
    second = _scope(scope_id="d02:tools:test", case_id="d02",
                    construct="tool", source_role="test",
                    positive_complete=False, negative_complete=False)
    ref["scopes"].append(second)
    out = score_reference(ref, [
        {"scope_id": "d01:agents:runtime", "claim_id": "agent:real"},
    ])
    assert out["all_scopes_assessable"] is False
    assert out["aggregate"] is None
    assert out["scopes"][0]["status"] == "methodologically_eligible"
    assert out["scopes"][1]["status"] == "not_assessed"


@pytest.mark.parametrize("field,value", [
    ("repository", "https://github.com/sample/example"),
    ("commit_sha", "abcd"),
    ("source_role", "prod_deployed"),
    ("construct", "unbounded_thing"),
    ("positive_complete", 1),
    ("negative_complete", "true"),
    ("review_method", "human_for_sure"),
    ("review_ref", ""),
    ("scanner_blind", None),
    ("negative_method", ""),
])
def test_c02a_invalid_scope_metadata_fails_closed(
    field: str, value: object,
) -> None:
    ref = _oracle()
    ref["scopes"][0][field] = value
    with pytest.raises((ValueError, TypeError)):
        validate_reference(ref)


@pytest.mark.parametrize("path", [
    "../agent.py", "/tmp/agent.py", "C:\\work\\agent.py", "./agent.py",
    "src//agent.py",
])
def test_c02a_witness_path_traversal_is_rejected(path: str) -> None:
    ref = _oracle()
    ref["labels"][0]["source"]["path"] = path
    with pytest.raises(ValueError, match="repository-relative"):
        validate_reference(ref)


@pytest.mark.parametrize("line_start,line_end", [(0, 2), (5, 4), (True, 2),
                                                   (1, 2003)])
def test_c02a_bad_source_line_span_fails_closed(
    line_start: object, line_end: object,
) -> None:
    ref = _oracle()
    ref["labels"][0]["source"]["line_start"] = line_start
    ref["labels"][0]["source"]["line_end"] = line_end
    with pytest.raises(ValueError, match="bounded positive line"):
        validate_reference(ref)


def test_c02a_missing_blob_sha_and_conflicting_label_fail_closed() -> None:
    ref = _oracle()
    ref["labels"][0]["source"]["blob_sha"] = "unverified"
    with pytest.raises(ValueError, match="full 40-hex"):
        validate_reference(ref)
    ref = _oracle()
    duplicate = deepcopy(ref["labels"][0])
    duplicate["truth"] = "negative"
    ref["labels"].append(duplicate)
    with pytest.raises(ValueError, match="duplicate/conflicting"):
        validate_reference(ref)


def test_c02a_unsupported_extra_fields_and_predictions_rejected() -> None:
    ref = _oracle()
    ref["scopes"][0]["independent_verified"] = True
    with pytest.raises(ValueError, match="exactly"):
        validate_reference(ref)

    with pytest.raises(ValueError, match="missing scope"):
        score_reference(_oracle(), [
            {"scope_id": "missing", "claim_id": "agent:real"},
        ])
    with pytest.raises(ValueError, match="duplicate scanner prediction"):
        score_reference(_oracle(), [
            {"scope_id": "d01:agents:runtime", "claim_id": "agent:real"},
            {"scope_id": "d01:agents:runtime", "claim_id": "agent:real"},
        ])


def test_c02a_oracle_digest_independent_of_json_key_order() -> None:
    reference = _oracle()
    copy = {
        "labels": reference["labels"],
        "scopes": reference["scopes"],
        "schema_version": reference["schema_version"],
    }
    left = score_reference(reference, [])
    right = score_reference(copy, [])
    assert left["reference_sha256"] == right["reference_sha256"]


def test_c02a_empty_reference_denies_release_level_metric() -> None:
    out = score_reference({"schema_version": 1, "scopes": [], "labels": []}, [])
    assert out["all_scopes_assessable"] is False
    assert out["aggregate"] is None
