"""Audit contract for legacy Fresh-16 source-claim mismatch ledger."""
import csv
import json
from collections import Counter
from pathlib import Path

BASE = Path(__file__).parents[1] / "research"
CLAIMS = BASE / "source-claim-regression" / "legacy-fresh16-adjudication-20261010.json"
HISTORICAL = BASE / "fresh-unseen-generalization-20" / "adjudication-second-pass.csv"


def test_legacy_32_claims_preserve_original_verdicts_without_auto_waivers() -> None:
    document = json.loads(CLAIMS.read_text(encoding="utf-8"))
    with HISTORICAL.open(newline="", encoding="utf-8") as handle:
        reviews = {(row["case_id"], int(row["finding_index"])): row
                   for row in csv.DictReader(handle)}
    losses = document["lost_claims"]
    assert len(losses) == 32
    assert len({(r["case_id"], r["finding_index"]) for r in losses}) == 32
    assert Counter(r["historical_verdict"] for r in losses) == {
        "false_positive": 16,
        "partial": 14,
        "true_positive": 2,
    }
    for loss in losses:
        matched = reviews[(loss["case_id"], loss["finding_index"])]
        assert loss["rule_id"] == matched["rule_id"]
        assert loss["historical_verdict"] == matched["verdict"]
        assert loss["reason_category"] == matched["reason_category"]
        assert loss["source_evidence"]["path"]
        assert loss["source_evidence"]["line"] >= 1
        if loss["historical_verdict"] == "partial":
            assert loss["status"] == "independent_source_review_required"
    assert {
        r["status"] for r in losses if r["historical_verdict"] == "true_positive"
    } == {"recovered_with_source_bound_agent",
          "unbound_mcp_configuration_scope_review"}
