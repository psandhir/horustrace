"""Fail-closed verification of the model-as-judge high-severity review ledger."""
from __future__ import annotations

import json
from pathlib import Path

LEDGER=Path(__file__).resolve().parents[1] / "research" / "accuracy-wave-b540-model-judge-20261015" / "high-severity-adjudication.json"
EXPECTED={
"004130ab23ebfe22175c","06ce2d8bfd46306662b0","0de03732933c171d96b4",
"0fba412fc3b98bceb358","34e0345cd816a7b394f5","378c7ca50b29a355ca61",
"37aa5ce1c6457e9992f0","391d0a5e8be35376802b","669b8b1876b801ce68f3",
"72d67ef754128842c8e9","7b8f55c79105bf3908a2","89d0305419e48068fbb9",
"8e88bbb7d4b7063f6c7e","a825ab344e1f9ba37816","abb0040438226a03dc8d",
"bc41820fb6493440a9ff","cc1183a10f410ef4b0c2","e04baa2a26fe8fa74060",
"e582d6d5ec042bef29e7","e9eccd96b25d7aac2746"
}
def test_full_high_severity_model_judge_coverage() -> None:
    doc=json.loads(LEDGER.read_text(encoding="utf-8"))
    assert doc["claim_count"] == len(doc["claims"]) == 20
    assert {c["claim_key"].split(":")[-1] for c in doc["claims"]} == EXPECTED
    assert doc["repository_sha"]=="30d03d7c9f6512e5bf10601879382fac9c3a16b1"
    assert doc["reviewer_kind"]=="openai_chatgpt_model_as_judge"
    assert doc["human_independent_review"] is False
    assert doc["exhaustive_negative_universe"] is False
    assert doc["precision"] is None and doc["recall"] is None
    assert doc["runtime_effectiveness_verified"] is False
    assert {c["status"] for c in doc["claims"]} == {"source_confirmed","false_positive","unresolved"}
    assert all(c["severity"] == "high" for c in doc["claims"])
    assert all(c["reviewer_type"] == "model_as_judge" for c in doc["claims"])
    assert all(c["independent_human_review"] is False for c in doc["claims"])
    assert all(c["runtime_effectiveness"] == "not_verified" for c in doc["claims"])
    for c in doc["claims"]:
        assert 0.5 <= c["confidence"] <= 1.0
        assert c["reasoning"] and c["hard_negative_evidence"]
        assert c["source_witnesses"]
        assert all(len(w["blob_sha"]) == 40 and w["lines"] and w["fact"] for w in c["source_witnesses"])
        assert all(w["path"].startswith("src/") for w in c["source_witnesses"])
        assert c["repo_sha"] == doc["repository_sha"]
        assert c["change"] in {"added","removed"}
    assert sum(doc["status_counts"].values())==20

def test_deleted_claims_not_conflated_with_deleted_risks() -> None:
    doc=json.loads(LEDGER.read_text(encoding="utf-8"))
    removed=[c for c in doc["claims"] if c["change"]=="removed"]
    assert len(removed)==6
    assert all(c["status"]=="false_positive" for c in removed)
    assert all("not" in c["hard_negative_evidence"].lower() or "source" in c["hard_negative_evidence"].lower() for c in removed)
