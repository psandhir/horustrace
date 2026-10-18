"""Wave C C02e: exact-source paired claim delta ledger, not a release oracle.

Compares scanner snapshots *on the identical source reference and ontology*.
Every cited source witness must resolve to a pinned Git object before output.
Unknown/missing reference labels remain unresolved, never negative by default.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from typing import Any

from horustrace.source_truth_oracle import score_reference, validate_reference
from horustrace.source_truth_witness import verify_reference_witnesses

_SHA = re.compile(r"[a-fA-F0-9]{40}\Z")
_ONTOLOGY = "v2_source_claims"


def _digest(obj: Any) -> str:
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _snapshot(
    snapshot: Any, reference_digest: str, scope_ids: set[str],
) -> set[tuple[str, str]]:
    if not isinstance(snapshot, dict) or set(snapshot) != {
        "schema_version", "ontology_version", "reference_sha256",
        "scanner_commit_sha", "predictions",
    }:
        raise ValueError("scanner snapshot schema mismatch")
    if type(snapshot["schema_version"]) is not int or snapshot["schema_version"] != 1:
        raise ValueError("unsupported snapshot schema")
    if snapshot["ontology_version"] != _ONTOLOGY:
        raise ValueError("source claim ontology does not match V2")
    if snapshot["reference_sha256"] != reference_digest:
        raise ValueError("snapshot reference fingerprint mismatch")
    sha = snapshot["scanner_commit_sha"]
    if (not isinstance(sha, str) or _SHA.fullmatch(sha) is None
            or sha == "0" * 40):
        raise ValueError("scanner revision requires a full commit SHA")
    preds = snapshot["predictions"]
    if not isinstance(preds, list):
        raise TypeError("scanner snapshot predictions must be a list")
    identities: set[tuple[str, str]] = set()
    for row in preds:
        if not isinstance(row, dict) or set(row) != {"scope_id", "claim_id"}:
            raise ValueError("scanner predicted claim schema mismatch")
        scope_id, claim_id = row["scope_id"], row["claim_id"]
        if (not isinstance(scope_id, str) or scope_id not in scope_ids
                or not isinstance(claim_id, str) or not claim_id.strip()):
            raise ValueError("scanner prediction has unknown scope or invalid identity")
        key = (scope_id, claim_id)
        if key in identities:
            raise ValueError("duplicate scanner prediction")
        identities.add(key)
    return identities


def compare_source_snapshots(
    reference: Any, checkouts: Any, old_snapshot: Any, new_snapshot: Any,
) -> dict[str, Any]:
    """Compare identical pinned scope, while forcing unknowns to remain unknown.

    A Git anchor proves bytes, NOT that an agent/tool/edge/finding claim is
    correct or that reviewers were independent; reports never permit cutover.
    """
    doc = validate_reference(reference)
    if not doc["scopes"]:
        raise ValueError("paired comparison cannot use an empty source scope")
    witnesses = verify_reference_witnesses(doc, checkouts)
    reference_digest = score_reference(doc, [])["reference_sha256"]
    scope_rows = {row["scope_id"]: row for row in doc["scopes"]}
    old = _snapshot(old_snapshot, reference_digest, set(scope_rows))
    new = _snapshot(new_snapshot, reference_digest, set(scope_rows))
    if old_snapshot["scanner_commit_sha"].lower() == (
        new_snapshot["scanner_commit_sha"].lower()
    ):
        raise ValueError("paired evaluation requires two distinct scanner revisions")
    labels = {
        (row["scope_id"], row["claim_id"]): row
        for row in doc["labels"]
    }
    source_proofs = {
        (scope["scope_id"], item["claim_id"]): item["source"]
        for scope in witnesses["scopes"]
        for item in scope["verified_witnesses"]
    }
    counts: dict[str, Counter[str]] = {
        key: Counter() for key in scope_rows
    }
    rows: list[dict[str, Any]] = []
    for scope_id, claim_id in sorted(old | new | set(labels)):
        key = scope_id, claim_id
        before, after = key in old, key in new
        change = (
            "introduced" if after and not before
            else "removed" if before and not after
            else "retained" if before and after else "not_detected"
        )
        label = labels.get(key)
        truth = label["truth"] if label else "unreviewed"
        if change == "introduced" and truth == "positive":
            effect = "candidate_true_positive_added_not_certified"
        elif change == "removed" and truth == "negative":
            effect = "candidate_false_positive_removed_not_certified"
        elif change == "removed" and truth == "positive":
            effect = "candidate_true_positive_lost_not_certified"
        elif change == "introduced" and truth == "negative":
            effect = "candidate_false_positive_added_not_certified"
        elif change in {"introduced", "removed"}:
            effect = "unresolved_change_requires_source_adjudication"
        else:
            effect = "no_inventory_delta_not_accuracy_proof"
        counts[scope_id][change] += 1
        if effect == "unresolved_change_requires_source_adjudication":
            counts[scope_id]["unresolved_changed_claims"] += 1
        rows.append({
            "scope_id": scope_id,
            "claim_id": claim_id,
            "before_detected": before,
            "after_detected": after,
            "change": change,
            "source_candidate_label": truth,
            "source_witness": source_proofs.get(key),
            "source_witness_verified": key in source_proofs,
            "effect": effect,
            "source_truth_independently_attested": False,
        })
    report_scopes = [{
        "scope_id": key,
        "case_id": scope_rows[key]["case_id"],
        "repository": scope_rows[key]["repository"],
        "commit_sha": scope_rows[key]["commit_sha"].lower(),
        "construct": scope_rows[key]["construct"],
        "source_role": scope_rows[key]["source_role"],
        "counts": dict(sorted(counts[key].items())),
        "positive_complete_declared": scope_rows[key]["positive_complete"],
        "negative_complete_declared": scope_rows[key]["negative_complete"],
        "external_completeness_verified": False,
    } for key in sorted(scope_rows)]
    return {
        "schema_version": 1,
        "mode": "source_anchored_paired_claim_delta_not_release_certification",
        "ontology_version": _ONTOLOGY,
        "reference_sha256": reference_digest,
        "old_scanner_commit_sha": old_snapshot["scanner_commit_sha"].lower(),
        "new_scanner_commit_sha": new_snapshot["scanner_commit_sha"].lower(),
        "old_snapshot_sha256": _digest(old_snapshot),
        "new_snapshot_sha256": _digest(new_snapshot),
        "source_witnesses_checked": sum(
            row["source_witnesses_checked"] for row in witnesses["scopes"]
        ),
        "scopes": report_scopes,
        "claim_deltas": rows,
        "independent_source_truth_verified": False,
        "certified_precision": None,
        "certified_recall": None,
        "production_cutover_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare source-pinned legacy/current claim snapshots offline"
    )
    parser.add_argument("--reference", required=True)
    parser.add_argument("--checkouts", required=True)
    parser.add_argument("--old", required=True)
    parser.add_argument("--new", required=True)
    args = parser.parse_args()

    def read(path: str) -> Any:
        with open(path, encoding="utf-8") as stream:
            return json.load(stream)

    print(json.dumps(compare_source_snapshots(
        read(args.reference), read(args.checkouts),
        read(args.old), read(args.new),
    ), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
