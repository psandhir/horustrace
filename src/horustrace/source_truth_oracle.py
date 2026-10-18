"""Wave C C02a: offline, fail-closed source-reference contract and scorer.

This is an isolated research evaluator, not a scanner adapter, finding
producer or runtime authority verifier. It never executes a target repository.
A self-declared independent review is *not* independently audited by code.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import PurePosixPath
from typing import Any

SCHEMA_VERSION = 1
CONSTRUCTS = frozenset({
    "agent", "agent_instance", "workflow", "tool", "mcp_client",
    "mcp_server", "skill", "identity", "resource", "destination",
    "control", "typed_edge", "effective_authority", "finding", "attack_path",
})
SOURCE_ROLES = frozenset({
    "runtime", "cli", "application-support", "test", "example",
    "tutorial", "notebook", "template-generated", "provider_only", "unknown",
})
REVIEW_METHODS = frozenset({
    "independent_blind", "source_reviewer", "model_reviewed",
    "test_author", "unreviewed",
})
TRUTHS = frozenset({"positive", "negative", "unknown"})
_SHA = re.compile(r"[a-fA-F0-9]{40}")  # Pinned Git SHA-1; not a branch/tag.
_REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/#@+-]*")


def _object(value: Any, required: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError(f"{name} must contain exactly {sorted(required)}")
    return value


def _nonempty(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be nonempty text")
    return value


def _identifier(value: Any, name: str) -> str:
    value = _nonempty(value, name)
    if _ID.fullmatch(value) is None:
        raise ValueError(f"{name} must be a portable identifier")
    return value


def _sha(value: Any, name: str) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise ValueError(f"{name} must be a full 40-hex Git object SHA")
    if not any(character != "0" for character in value):
        raise ValueError(f"{name} must not be the all-zero SHA")
    return value.lower()


def _bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be boolean")
    return value


def _source(source: Any) -> None:
    source = _object(
        source, {"path", "blob_sha", "line_start", "line_end"},
        "source witness",
    )
    path = _nonempty(source["path"], "source.path")
    posix = PurePosixPath(path)
    if (path.startswith(("/", "./")) or "\\" in path
            or ".." in path.split("/") or "//" in path
            or str(posix) != path):
        raise ValueError("source.path must be repository-relative and normalized")
    _sha(source["blob_sha"], "source.blob_sha")
    start, end = source["line_start"], source["line_end"]
    if (type(start) is not int or type(end) is not int
            or start < 1 or end < start or end - start > 1000):
        raise ValueError("source witness requires bounded positive line span")


def validate_reference(reference: Any) -> dict[str, Any]:
    """Validate an exact-source V2-style oracle manifest; never infer truth."""
    reference = _object(
        reference, {"schema_version", "scopes", "labels"}, "reference"
    )
    if type(reference["schema_version"]) is not int or (
        reference["schema_version"] != SCHEMA_VERSION
    ):
        raise ValueError("unsupported reference schema version")
    scopes, labels = reference["scopes"], reference["labels"]
    if not isinstance(scopes, list) or not isinstance(labels, list):
        raise ValueError("scopes and labels must be lists")

    indexed: dict[str, dict[str, Any]] = {}
    for raw in scopes:
        scope = _object(raw, {
            "scope_id", "case_id", "repository", "commit_sha", "construct",
            "source_role", "positive_complete", "negative_complete",
            "review_method", "review_ref", "scanner_blind", "negative_method",
        }, "reference scope")
        key = _identifier(scope["scope_id"], "scope_id")
        _identifier(scope["case_id"], "case_id")
        if not isinstance(scope["repository"], str) or not _REPO.fullmatch(
            scope["repository"]
        ):
            raise ValueError("repository must be an owner/name slug")
        _sha(scope["commit_sha"], "scope.commit_sha")
        if scope["construct"] not in CONSTRUCTS:
            raise ValueError("invalid reference construct")
        if scope["source_role"] not in SOURCE_ROLES:
            raise ValueError("invalid source role")
        if scope["review_method"] not in REVIEW_METHODS:
            raise ValueError("invalid review method")
        _nonempty(scope["review_ref"], "review_ref")
        _bool(scope["positive_complete"], "positive_complete")
        _bool(scope["negative_complete"], "negative_complete")
        _bool(scope["scanner_blind"], "scanner_blind")
        if scope["negative_complete"]:
            _nonempty(scope["negative_method"], "negative_method")
        elif scope["negative_method"] is not None:
            _nonempty(scope["negative_method"], "negative_method")
        if key in indexed:
            raise ValueError(f"duplicate reference scope: {key}")
        indexed[key] = scope

    seen: set[tuple[str, str]] = set()
    for raw in labels:
        item = _object(raw, {
            "scope_id", "claim_id", "truth", "source", "reason",
        }, "source label")
        key = _identifier(item["scope_id"], "label.scope_id")
        claim_id = _identifier(item["claim_id"], "label.claim_id")
        if key not in indexed:
            raise ValueError(f"label references missing scope: {key}")
        if item["truth"] not in TRUTHS:
            raise ValueError("invalid truth label")
        _source(item["source"])
        _nonempty(item["reason"], "label.reason")
        pair = (key, claim_id)
        if pair in seen:
            raise ValueError(f"duplicate/conflicting reference label: {pair}")
        seen.add(pair)
    return reference


def score_reference(reference: Any, predictions: Any) -> dict[str, Any]:
    """Only score complete independent-blind positive AND negative universes.

    Missing predictions in a complete universe can be FN/TN. Predictions not
    labelled by this universe are never guessed false positives; the affected
    stratum becomes unassessed until source review.
    """
    document = validate_reference(reference)
    if not isinstance(predictions, list):
        raise ValueError("predictions must be a list")
    indexed = {item["scope_id"]: item for item in document["scopes"]}
    seen: set[tuple[str, str]] = set()
    by_scope: dict[str, set[str]] = {key: set() for key in indexed}
    for prediction in predictions:
        pred = _object(
            prediction, {"scope_id", "claim_id"}, "scanner prediction"
        )
        scope_id = _identifier(pred["scope_id"], "prediction.scope_id")
        claim_id = _identifier(pred["claim_id"], "prediction.claim_id")
        if scope_id not in indexed:
            raise ValueError(f"prediction references missing scope: {scope_id}")
        if (scope_id, claim_id) in seen:
            raise ValueError("duplicate scanner prediction")
        seen.add((scope_id, claim_id))
        by_scope[scope_id].add(claim_id)

    labels: dict[str, dict[str, str]] = {key: {} for key in indexed}
    for item in document["labels"]:
        labels[item["scope_id"]][item["claim_id"]] = item["truth"]

    results: list[dict[str, Any]] = []
    for scope_id in sorted(indexed):
        scope = indexed[scope_id]
        truth = labels[scope_id]
        actual = by_scope[scope_id]
        unlabeled = sorted(actual - truth.keys())
        unknown = sorted(key for key, value in truth.items() if value == "unknown")
        positives = {key for key, value in truth.items() if value == "positive"}
        negatives = {key for key, value in truth.items() if value == "negative"}
        blockers: list[str] = []
        if not scope["positive_complete"]:
            blockers.append("incomplete_positive_universe")
        if not scope["negative_complete"]:
            blockers.append("incomplete_negative_universe")
        if scope["review_method"] != "independent_blind":
            blockers.append("reference_not_declared_independent_blind")
        if not scope["scanner_blind"]:
            blockers.append("review_not_scanner_blind")
        if not positives:
            blockers.append("zero_source_positive_labels")
        if not negatives:
            blockers.append("zero_source_negative_labels")
        if unlabeled:
            blockers.append("unlabelled_scanner_predictions")
        if unknown:
            blockers.append("unresolved_source_labels")
        result: dict[str, Any] = {
            "scope_id": scope_id,
            "case_id": scope["case_id"],
            "construct": scope["construct"],
            "source_role": scope["source_role"],
            "status": "not_assessed" if blockers else "methodologically_eligible",
            "blockers": blockers,
            "positive_labels": len(positives),
            "negative_labels": len(negatives),
            "unknown_labels": len(unknown),
            "unlabelled_prediction_ids": unlabeled,
            "tp": None, "fp": None, "fn": None, "tn": None,
            "precision": None, "recall": None,
        }
        if not blockers:
            tp = len(positives & actual)
            fn = len(positives - actual)
            fp = len(negatives & actual)
            tn = len(negatives - actual)
            result.update({
                "tp": tp, "fp": fp, "fn": fn, "tn": tn,
                "precision": tp / (tp + fp) if tp + fp else None,
                "recall": tp / (tp + fn) if tp + fn else None,
            })
        results.append(result)

    # Never publish a pooled accuracy score from cherry-picked eligible strata
    # when any other requested stratum is incomplete or unresolved.
    complete = bool(results) and all(
        item["status"] == "methodologically_eligible" for item in results
    )
    total = Counter()
    if complete:
        for item in results:
            for key in ("tp", "fp", "fn", "tn"):
                total[key] += item[key]
    aggregate: dict[str, Any] | None = None
    if complete:
        aggregate = {
            **{key: total[key] for key in ("tp", "fp", "fn", "tn")},
            "precision": (
                total["tp"] / (total["tp"] + total["fp"])
                if total["tp"] + total["fp"] else None
            ),
            "recall": (
                total["tp"] / (total["tp"] + total["fn"])
                if total["tp"] + total["fn"] else None
            ),
        }
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "offline_source_oracle_methodology_not_release_certification",
        "independent_reviewer_attestation_externally_verified": False,
        "scopes": results,
        "all_scopes_assessable": complete,
        "aggregate": aggregate,
        "reference_sha256": hashlib.sha256(
            json.dumps(
                document, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Score a pinned source oracle without executing target code"
    )
    parser.add_argument("--reference", required=True)
    parser.add_argument("--predictions", required=True)
    args = parser.parse_args()
    # Local offline files only. No network, runner, or scanner import.
    with open(args.reference, encoding="utf-8") as handle:
        reference = json.load(handle)
    with open(args.predictions, encoding="utf-8") as handle:
        predictions = json.load(handle)
    print(json.dumps(score_reference(reference, predictions), indent=2,
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
