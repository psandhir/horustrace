"""Complete 73-key model-source-review coverage, never manufactured human signoff."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "research" / "accuracy-wave-b540-model-judge-20261015"

def test_73_changed_claim_keys_are_model_reviewed_and_disjoint() -> None:
    high = json.loads((ROOT / "high-severity-adjudication.json").read_text(encoding="utf-8"))
    medium = json.loads((ROOT / "medium-severity-adjudication.json").read_text(encoding="utf-8"))
    assert high["claim_count"] == 20
    assert medium["claim_count"] == 53
    keys = [c["claim_key"] for d in (high, medium) for c in d["claims"]]
    assert len(keys) == len(set(keys)) == 73
    assert all(k.startswith("ff60-amazon-04:") for k in keys)
    # Immutable digest of exact per-case claim keys in the last accepted
    # pinned workflow evidence. This rejects a 73-item but wrong-key ledger.
    def key_digest(items: list[str]) -> str:
        return hashlib.sha256("\n".join(sorted(items)).encode()).hexdigest()

    assert key_digest(keys) == (
        "9330227624ff5845ba08abb8449195e5f7b41aa7300276e48c69c803f5452c1c"
    )
    assert key_digest([c["claim_key"] for c in high["claims"]]) == (
        "24286ac70ab80fe452f8f5be32780445a66d4f111562b50902b9b577fe6ed53f"
    )
    assert key_digest([c["claim_key"] for c in medium["claims"]]) == (
        "a3b298caf629d039ca61e07e27f46678b40ed632737847df8e39aab3f52477b9"
    )
    assert sum(medium["status_counts"].values()) == 53
    assert medium["reviewer_kind"] == high["reviewer_kind"] == "openai_chatgpt_model_as_judge"
    for document in (high, medium):
        assert document["human_independent_review"] is False
        assert document["exhaustive_negative_universe"] is False
        assert document["precision"] is None and document["recall"] is None
        for c in document["claims"]:
            assert c["reviewer_type"] == "model_as_judge"
            assert c["independent_human_review"] is False
            assert c["repo_sha"] == document["repository_sha"]
            assert c["status"] in {"source_confirmed", "false_positive", "unresolved"}
            assert c["hard_negative_evidence"] and c["reasoning"]
            assert c["source_witnesses"]
            assert all(len(w["blob_sha"]) == 40 and w["lines"] for w in c["source_witnesses"])

def test_medium_removed_claims_are_only_source_identity_corrections() -> None:
    d = json.loads((ROOT / "medium-severity-adjudication.json").read_text(encoding="utf-8"))
    old = [c for c in d["claims"] if c["change"] == "removed"]
    assert len(old) == 10
    assert all(c["status"] == "false_positive" for c in old)
    assert all("old" in c["claim_scope"] or "phantom" in c["claim_scope"] or "obsolete" in c["claim_scope"] for c in old)
