"""C02m: model-assisted source opinions cannot substitute for independent V2 truth."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from horustrace.source_truth_oracle import score_reference, validate_reference

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = (
    ROOT / "research/wave-c-c02m-rw005/model-reviewed-provisional-reference.json"
)
CANDIDATES = (
    ROOT / "research/wave-c-c02g-real-source/rw-005-source-candidates.json"
)
POPULATION = (
    ROOT / "research/wave-c-c02f-active145/expected-agent-review-scopes.json"
)


def _reference() -> dict:
    return json.loads(REFERENCE.read_text(encoding="utf-8"))


def _ledger() -> dict:
    return json.loads(CANDIDATES.read_text(encoding="utf-8"))


def test_c02m_reference_is_valid_pinned_active145_case() -> None:
    source = _reference()
    validate_reference(source)
    population = json.loads(POPULATION.read_text(encoding="utf-8"))
    active = next(
        x for x in population["expected_scopes"] if x["case_id"] == "rw-005"
    )
    assert source["schema_version"] == 1
    assert len(source["scopes"]) == 3
    assert {x["construct"] for x in source["scopes"]} == {
        "agent", "typed_edge", "effective_authority",
    }
    for scope in source["scopes"]:
        assert scope["case_id"] == active["case_id"]
        assert scope["repository"] == active["repository"]
        assert scope["commit_sha"] == active["commit_sha"]
        assert scope["source_role"] == active["source_role"] == "unknown"
        assert scope["review_method"] == "model_reviewed"
        assert scope["review_ref"] == (
            "assistant_source_first_single_pass_not_independent"
        )


def test_c02m_all_opinions_link_existing_pinned_source_witnesses() -> None:
    ledger = _ledger()
    sites = {
        (r["path"], r["blob_sha"], r["line_start"], r["line_end"])
        for r in ledger["observations"]
    }
    reference = _reference()
    assert len(reference["labels"]) == 26
    assert len({(x["scope_id"], x["claim_id"])
                for x in reference["labels"]}) == 26
    for item in reference["labels"]:
        witness = item["source"]
        key = (
            witness["path"], witness["blob_sha"],
            witness["line_start"], witness["line_end"],
        )
        assert key in sites
        assert item["reason"].startswith(
            "MODEL-REVIEWED, UNBLINDED, SOURCE-ONLY:"
        )
        assert "not deployed runtime evidence" in item["reason"]


def test_c02m_counts_distinguish_positive_hard_negative_and_unknown() -> None:
    ref = _reference()
    counts = Counter(
        (label["scope_id"], label["truth"]) for label in ref["labels"]
    )
    assert counts == {
        ("rw-005:agent:unknown", "positive"): 5,
        ("rw-005:agent:unknown", "negative"): 2,
        ("rw-005:typed_edge:unknown", "positive"): 13,
        ("rw-005:typed_edge:unknown", "negative"): 3,
        ("rw-005:effective_authority:unknown", "unknown"): 3,
    }
    assert {label["claim_id"] for label in ref["labels"]
            if label["scope_id"] == "rw-005:agent:unknown"
            and label["truth"] == "negative"} == {
        "source_declared_agent:package_export_new_constructor",
        "source_declared_agent:api_alias_new_constructor",
    }
    assert {label["claim_id"] for label in ref["labels"]
            if label["scope_id"] == "rw-005:typed_edge:unknown"
            and label["truth"] == "negative"} == {
        "declared_model_tool_call:fastapi_metrics_route",
        "declared_direct_tool_listing:report_agent_nonempty",
        "declared_direct_tool_listing:root_list_metrics_inherited_from_child",
    }


def test_c02m_no_effective_authority_is_certified_yes_or_no() -> None:
    ref = _reference()
    authority = [
        l for l in ref["labels"]
        if l["scope_id"] == "rw-005:effective_authority:unknown"
    ]
    assert len(authority) == 3
    assert all(l["truth"] == "unknown" for l in authority)
    assert not any(
        l["claim_id"].startswith("runtime_callability:")
        and l["truth"] != "unknown" for l in ref["labels"]
    )


def test_c02m_model_review_cannot_emit_scored_accuracy_on_any_predictions() -> None:
    ref = _reference()
    predicted = [
        {"scope_id": x["scope_id"], "claim_id": x["claim_id"]}
        for x in ref["labels"] if x["truth"] == "positive"
    ]
    for predictions in ([], predicted):
        score = score_reference(ref, predictions)
        assert score["aggregate"] is None
        assert score["all_scopes_assessable"] is False
        assert score["independent_reviewer_attestation_externally_verified"] is False
        for row in score["scopes"]:
            assert row["status"] == "not_assessed"
            assert row["tp"] is None and row["fp"] is None
            assert row["fn"] is None and row["tn"] is None
            assert row["precision"] is None and row["recall"] is None
            assert "incomplete_positive_universe" in row["blockers"]
            assert "incomplete_negative_universe" in row["blockers"]
            assert "reference_not_declared_independent_blind" in row["blockers"]
            assert "review_not_scanner_blind" in row["blockers"]


def test_c02m_cannot_promote_self_review_to_independent_by_only_editing_flags() -> None:
    ref = _reference()
    for scope in ref["scopes"]:
        assert scope["positive_complete"] is False
        assert scope["negative_complete"] is False
        assert scope["scanner_blind"] is False
        assert scope["review_ref"] != "independent_blind"
        assert scope["negative_method"].strip()
    assert all(scope["source_role"] == "unknown" for scope in ref["scopes"])
