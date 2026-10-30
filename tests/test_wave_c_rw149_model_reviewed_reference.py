"""C02n rw149 source opinions: conditional selection != effective runtime authority."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from horustrace.source_truth_oracle import score_reference, validate_reference

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "research/wave-c-c02n-rw149/model-reviewed-conditional-reference.json"
SITES = ROOT / "research/wave-c-c02j-rw149/conditional-tool-source-candidates.json"

def test_rw149_model_reviewed_reference_links_exact_existing_source_lines() -> None:
    ref = json.loads(REFERENCE.read_text(encoding="utf-8"))
    source = json.loads(SITES.read_text(encoding="utf-8"))
    validate_reference(ref)
    sites = {(x["path"], x["blob_sha"], x["line"]) for x in source["observations"]}
    assert len(ref["labels"]) == 20
    assert len({(x["scope_id"], x["claim_id"]) for x in ref["labels"]}) == 20
    for item in ref["labels"]:
        anchor = item["source"]
        assert (anchor["path"], anchor["blob_sha"], anchor["line_start"]) in sites
        assert anchor["line_start"] == anchor["line_end"]
        assert item["reason"].startswith("MODEL-REVIEWED, UNBLINDED, SOURCE-ONLY:")
        assert "not deployed runtime evidence" in item["reason"]
    for scope in ref["scopes"]:
        assert scope["case_id"] == "rw-149"
        assert scope["repository"] == source["repository"]
        assert scope["commit_sha"] == source["pinned_commit_sha"]
        assert scope["source_role"] == "unknown"
        assert scope["review_method"] == "model_reviewed"
        assert scope["scanner_blind"] is False
        assert scope["positive_complete"] is False
        assert scope["negative_complete"] is False
    assert Counter(x["truth"] for x in ref["labels"]) == {
        "positive": 10, "negative": 7, "unknown": 3,
    }

def test_rw149_conditional_source_negatives_and_authority_unknowns() -> None:
    ref = json.loads(REFERENCE.read_text(encoding="utf-8"))
    labels = {item["claim_id"]: item for item in ref["labels"]}
    assert labels["source_level1:any_selected_tool"]["truth"] == "negative"
    assert labels["source_level1:five_tool_registration"]["truth"] == "negative"
    for symbol in ("execute_query", "get_current_date", "get_stock_query_template"):
        assert labels["source_level2:select_" + symbol]["truth"] == "negative"
        assert labels["source_level3_4:select_" + symbol]["truth"] == "positive"
    for name in ("deployed_demo_level", "installed_sdk_tool_registration",
                 "actual_chainlit_agent_session"):
        assert labels[name]["truth"] == "unknown"

def test_rw149_provisional_review_never_certifies_accuracy() -> None:
    ref = json.loads(REFERENCE.read_text(encoding="utf-8"))
    predicted = [{"scope_id": x["scope_id"], "claim_id": x["claim_id"]}
                 for x in ref["labels"] if x["truth"] == "positive"]
    for candidates in ([], predicted):
        result = score_reference(ref, candidates)
        assert result["aggregate"] is None
        assert result["all_scopes_assessable"] is False
        assert result["independent_reviewer_attestation_externally_verified"] is False
        for scope in result["scopes"]:
            assert scope["status"] == "not_assessed"
            assert scope["precision"] is None and scope["recall"] is None
            assert scope["tp"] is None and scope["fp"] is None
            assert scope["fn"] is None and scope["tn"] is None
            assert "incomplete_positive_universe" in scope["blockers"]
            assert "incomplete_negative_universe" in scope["blockers"]
            assert "reference_not_declared_independent_blind" in scope["blockers"]
            assert "review_not_scanner_blind" in scope["blockers"]
