"""Wave B regression: unresolved model-reviewed claims remain unverified."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "research" / "accuracy-wave-b540-model-judge-20261015"


def test_unresolved_source_claims_are_not_release_truth():
    docs = [
        json.loads((ROOT / name).read_text(encoding="utf-8"))
        for name in ("high-severity-adjudication.json", "medium-severity-adjudication.json")
    ]
    pending = [
        claim for doc in docs for claim in doc["claims"]
        if claim["status"] == "unresolved"
    ]
    assert len(pending) == 12
    assert all(c["reviewer_type"] == "model_as_judge" for c in pending)
    assert all(c["independent_human_review"] is False for c in pending)
    assert all(c["runtime_effectiveness"] == "not_verified" for c in pending)
    assert all(doc["human_independent_review"] is False for doc in docs)
    assert all(doc["precision"] is None and doc["recall"] is None for doc in docs)
