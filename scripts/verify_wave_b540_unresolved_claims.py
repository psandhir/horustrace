"""Fail-closed Wave B #551 source-only unresolved-claim acceptance contract.

This audit is intentionally NOT an independent accuracy scorer or evidence that
unpinned third-party tool implementations, live tool calls or controls exist.
The historical 73 claim identities are pinned; current scanner fingerprints
must be adjudicated in a separate, same-head source graph evaluation.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

REPO_SHA = "30d03d7c9f6512e5bf10601879382fac9c3a16b1"
CASE_ID = "ff60-amazon-04"
# Only the historically unresolved model-review claims. Updating a verdict
# requires an explicit source witness/reviewer decision, not a count change.
UNRESOLVED: dict[str, tuple[str, str, str]] = {
    "0de03732933c171d96b4": ("CAP004", "high", "per_instance_capability"),
    "34e0345cd816a7b394f5": ("AGT020", "high", "unversioned_python_repl_contract"),
    "391d0a5e8be35376802b": ("CAP003", "high", "per_instance_effect_classes"),
    "e9eccd96b25d7aac2746": ("CAP003", "high", "per_instance_effect_classes"),
    "d3388fd929c8794bfce6": ("AGT040", "medium", "unversioned_python_repl_controls"),
    "1cd6188f31f7ae6ae9ae": ("NET002", "medium", "runtime_destination_control"),
    "2ad096fe63994b320f70": ("NET002", "medium", "runtime_destination_control"),
    "36830b3ae86117942e1e": ("NET002", "medium", "runtime_destination_control"),
    "84724ebc1b42818721ea": ("NET002", "medium", "runtime_destination_control"),
    "9a644fee027e44fe2bd5": ("NET002", "medium", "runtime_destination_control"),
    "ae7e4aadfa7c31e34044": ("NET002", "medium", "runtime_destination_control"),
    "f37bdf0d899c7565a374": ("NET002", "medium", "runtime_destination_control"),
}

def acceptance_check(ledgers: list[dict[str, Any]]) -> dict[str, Any]:
    if len(ledgers) != 2:
        raise ValueError("require both frozen high/medium model-review ledgers")
    expected_severities = (("high", 20), ("medium", 53))
    all_claims: dict[str, dict[str, Any]] = {}
    for ledger, (severity, expected_count) in zip(ledgers, expected_severities):
        claims = ledger.get("claims")
        if not isinstance(claims, list) or len(claims) != expected_count:
            raise ValueError(f"historical {severity} claim count/source drift")
        if (ledger.get("claim_count") != expected_count
            or ledger.get("repository_sha") != REPO_SHA
            or ledger.get("reviewer_kind") != "openai_chatgpt_model_as_judge"
            or ledger.get("human_independent_review") is not False
            or ledger.get("exhaustive_negative_universe") is not False
            or ledger.get("runtime_effectiveness_verified") is not False
            or ledger.get("precision") is not None
            or ledger.get("recall") is not None):
            raise ValueError(f"{severity} ledger falsely certifies independent truth")
        for row in claims:
            key = row.get("claim_key")
            if (not isinstance(key, str)
                or not key.startswith(CASE_ID + ":")
                or key in all_claims
                or row.get("severity") != severity
                or row.get("repo_sha") != REPO_SHA
                or row.get("reviewer_type") != "model_as_judge"
                or row.get("independent_human_review") is not False
                or row.get("runtime_effectiveness") != "not_verified"
                or row.get("status") not in {
                    "source_confirmed", "false_positive", "unresolved"
                }
                or not isinstance(row.get("source_witnesses"), list)
                or not row["source_witnesses"]
                or not str(row.get("hard_negative_evidence") or "").strip()):
                raise ValueError(f"unreviewable/fabricated source claim: {key}")
            for witness in row["source_witnesses"]:
                if (not isinstance(witness, dict)
                    or not str(witness.get("path") or "").startswith("src/")
                    or len(str(witness.get("blob_sha") or "")) != 40
                    or not str(witness.get("lines") or "").strip()
                    or not str(witness.get("fact") or "").strip()):
                    raise ValueError(f"missing source blob and line witness: {key}")
            all_claims[key] = row

    actual_status = Counter(row["status"] for row in all_claims.values())
    if actual_status != {"source_confirmed": 45, "false_positive": 16, "unresolved": 12}:
        raise ValueError(f"historical source-claim status drift: {dict(actual_status)}")
    actual_unresolved = {
        key.split(":", 1)[-1]: row
        for key, row in all_claims.items() if row["status"] == "unresolved"
    }
    if set(actual_unresolved) != set(UNRESOLVED):
        raise ValueError("unresolved third-party claim identities changed silently")
    unresolved_rows: list[dict[str, str]] = []
    for suffix, (rule, severity, dimension) in sorted(UNRESOLVED.items()):
        row = actual_unresolved[suffix]
        if row["rule_id"] != rule or row["severity"] != severity:
            raise ValueError(f"unresolved rule or severity drift: {suffix}")
        unresolved_rows.append({
            "historical_claim_key": row["claim_key"],
            "rule_id": rule,
            "severity": severity,
            "unresolved_dimension": dimension,
            "state": "source_unresolved_runtime_unverified",
            "source_scope": "unversioned third-party implementation and/or dynamic MCP/approval",
        })
    return {
        "schema_version": 1,
        "scope": "historical_model_review_not_current_fingerprint",
        "case_id": CASE_ID,
        "source_sha": REPO_SHA,
        "total_historical_claims": len(all_claims),
        "model_only_status_counts": dict(sorted(actual_status.items())),
        "unresolved": unresolved_rows,
        "unresolved_high": sum(r["severity"] == "high" for r in unresolved_rows),
        "unresolved_medium": sum(r["severity"] == "medium" for r in unresolved_rows),
        "installed_dependency_bytes_verified": False,
        "runtime_mcp_catalogue_verified": False,
        "runtime_effectiveness_verified": False,
        "exhaustive_negative_universe": False,
        "independent_ground_truth": False,
        "precision": None,
        "recall": None,
        "wave_b_go": False,
        "wave_c_go": False,
    }

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--high", type=Path, required=True)
    parser.add_argument("--medium", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = acceptance_check([
        json.loads(args.high.read_text(encoding="utf-8")),
        json.loads(args.medium.read_text(encoding="utf-8")),
    ])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    print(json.dumps({
        "source_only_claims": report["total_historical_claims"],
        "unresolved": len(report["unresolved"]),
        "wave_b_go": report["wave_b_go"],
        "wave_c_go": report["wave_c_go"],
    }))

if __name__ == "__main__":
    main()
