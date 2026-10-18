"""Fail-closed acceptance tests: source review must not become certified truth."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.verify_wave_b540_unresolved_claims import acceptance_check

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "research" / "accuracy-wave-b540-model-judge-20261015"

def ledgers():
    return [
        json.loads((SOURCES / "high-severity-adjudication.json").read_text()),
        json.loads((SOURCES / "medium-severity-adjudication.json").read_text()),
    ]

def test_pinned_73_claims_are_triaged_without_independent_truth() -> None:
    result = acceptance_check(ledgers())
    assert result["total_historical_claims"] == 73
    assert result["model_only_status_counts"] == {
        "false_positive": 16, "source_confirmed": 45, "unresolved": 12
    }
    assert (result["unresolved_high"], result["unresolved_medium"]) == (4, 8)
    assert all(x["state"] == "source_unresolved_runtime_unverified"
               for x in result["unresolved"])
    assert all(result[k] is False for k in (
        "wave_b_go", "wave_c_go", "installed_dependency_bytes_verified",
        "runtime_mcp_catalogue_verified", "runtime_effectiveness_verified",
        "exhaustive_negative_universe", "independent_ground_truth"
    ))
    assert result["precision"] is None and result["recall"] is None

def test_missing_claim_cannot_be_hidden_in_summary() -> None:
    inp = ledgers()
    inp[0]["claims"].pop()
    with pytest.raises(ValueError, match="historical high claim count"):
        acceptance_check(inp)

def test_unknown_cannot_be_silently_promoted_to_truth() -> None:
    inp = ledgers()
    bad = next(c for c in inp[0]["claims"]
               if c["claim_key"].endswith("34e0345cd816a7b394f5"))
    bad["status"] = "source_confirmed"
    with pytest.raises(ValueError, match="status drift"):
        acceptance_check(inp)

def test_model_review_cannot_impersonate_independent_truth() -> None:
    inp = ledgers()
    inp[1]["human_independent_review"] = True
    with pytest.raises(ValueError, match="falsely certifies"):
        acceptance_check(inp)

def test_missing_blob_witness_is_rejected() -> None:
    inp = ledgers()
    inp[1]["claims"][0]["source_witnesses"][0]["blob_sha"] = ""
    with pytest.raises(ValueError, match="source blob"):
        acceptance_check(inp)

def test_stale_claim_source_sha_fails_closed() -> None:
    inp = ledgers()
    inp[0]["claims"][0]["repo_sha"] = "0" * 40
    with pytest.raises(ValueError, match="unreviewable"):
        acceptance_check(inp)

def test_duplicate_claim_identity_fails_closed() -> None:
    inp = ledgers()
    inp[1]["claims"][0]["claim_key"] = inp[0]["claims"][0]["claim_key"]
    with pytest.raises(ValueError, match="unreviewable"):
        acceptance_check(inp)

def test_wrong_unresolved_rule_fails_closed() -> None:
    inp = ledgers()
    bad = next(c for c in inp[1]["claims"]
               if c["claim_key"].endswith("d3388fd929c8794bfce6"))
    bad["rule_id"] = "CAP001"
    with pytest.raises(ValueError, match="rule or severity"):
        acceptance_check(inp)
