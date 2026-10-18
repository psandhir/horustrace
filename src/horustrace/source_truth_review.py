"""Wave C C02c: source-first review packets and provisional consensus.

A packet is built only from UNKNOWN source candidates at pinned Git blob/line
anchors. No scanner predictions, scanner names or candidate truth are included.
Consensus is a review-workflow aid, never independent source certification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from typing import Any

from horustrace.source_truth_oracle import score_reference, validate_reference
from horustrace.source_truth_witness import verify_reference_witnesses

_DECISIONS = frozenset({"positive", "negative", "unknown"})


def _fingerprint(value: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def prepare_source_review_packet(
    reference: Any, checkouts: Any,
) -> dict[str, Any]:
    """Build a source-only packet: never show expected truth or scan results.

    A C02a reference containing resolved opinions or completeness assertions is
    not suitable as an input to a source-blind initial review.
    """
    doc = validate_reference(reference)
    if any(
        item["positive_complete"] or item["negative_complete"]
        or item["review_method"] != "unreviewed" or item["scanner_blind"]
        for item in doc["scopes"]
    ):
        raise ValueError("review packet input must be explicitly unreviewed and open")
    if any(item["truth"] != "unknown" for item in doc["labels"]):
        raise ValueError("review packet input must not disclose candidate verdicts")

    proof = verify_reference_witnesses(doc, checkouts)
    evidence = {
        (scope["scope_id"], item["claim_id"]): item["source"]
        for scope in proof["scopes"]
        for item in scope["verified_witnesses"]
    }
    scopes = [{
        "scope_id": row["scope_id"],
        "case_id": row["case_id"],
        "repository": row["repository"],
        "commit_sha": row["commit_sha"].lower(),
        "construct": row["construct"],
        "source_role": row["source_role"],
        "negative_search_plan": row["negative_method"],
    } for row in sorted(doc["scopes"], key=lambda r: r["scope_id"])]

    candidates = []
    for item in sorted(
        doc["labels"], key=lambda row: (row["scope_id"], row["claim_id"])
    ):
        witness = evidence[(item["scope_id"], item["claim_id"])]
        candidates.append({
            "scope_id": item["scope_id"],
            "claim_id": item["claim_id"],
            "source": {
                "path": witness["path"],
                "blob_sha": witness["blob_sha"],
                "line_start": witness["line_start"],
                "line_end": witness["line_end"],
                "sha256": witness["sha256"],
            },
        })
    content = {
        "schema_version": 1,
        "mode": "source_only_candidate_review_no_scanner_predictions",
        "source_anchors_verified": True,
        "semantic_claims_verified": False,
        "reviewer_independence_verified": False,
        "universe_completeness_verified": False,
        "scopes": scopes,
        "candidates": candidates,
    }
    return {**content, "packet_sha256": _fingerprint(content)}


def _validate_packet(packet: Any) -> dict[str, Any]:
    expected = {
        "schema_version", "mode", "source_anchors_verified",
        "semantic_claims_verified", "reviewer_independence_verified",
        "universe_completeness_verified", "scopes", "candidates",
        "packet_sha256",
    }
    if not isinstance(packet, dict) or set(packet) != expected:
        raise ValueError("review packet schema mismatch")
    payload = {key: value for key, value in packet.items()
               if key != "packet_sha256"}
    if packet["packet_sha256"] != _fingerprint(payload):
        raise ValueError("review packet digest mismatch")
    if (packet["schema_version"] != 1
            or packet["mode"] != "source_only_candidate_review_no_scanner_predictions"
            or packet["source_anchors_verified"] is not True
            or packet["semantic_claims_verified"] is not False
            or packet["reviewer_independence_verified"] is not False
            or packet["universe_completeness_verified"] is not False):
        raise ValueError("review packet proof flags invalid")
    if not isinstance(packet["scopes"], list) or not isinstance(
        packet["candidates"], list
    ):
        raise ValueError("review packet scopes/candidates must be lists")
    return packet


def adjudicate_review_packet(
    packet: Any, submission: Any,
) -> dict[str, Any]:
    """Provisional two-reviewer source adjudication, never a release oracle.

    Two distinct reviewer *IDs* and source-only declarations are required for
    a consensual positive/negative. They are self-declared, not identity
    proof; all output completeness flags remain false.
    """
    packet = _validate_packet(packet)
    if not isinstance(submission, dict) or set(submission) != {
        "packet_sha256", "reviews",
    }:
        raise ValueError("review submission schema mismatch")
    if submission["packet_sha256"] != packet["packet_sha256"]:
        raise ValueError("review submission not bound to source packet digest")
    if not isinstance(submission["reviews"], list):
        raise TypeError("review submission reviews must be a list")

    claims: dict[tuple[str, str], dict[str, Any]] = {}
    for candidate in packet["candidates"]:
        if not isinstance(candidate, dict) or set(candidate) != {
            "scope_id", "claim_id", "source",
        }:
            raise ValueError("review candidate schema mismatch")
        key = candidate["scope_id"], candidate["claim_id"]
        if not all(isinstance(part, str) and part for part in key):
            raise ValueError("review candidate requires source claim identifiers")
        if key in claims:
            raise ValueError("duplicate source review candidate")
        claims[key] = candidate
    scopes = {row["scope_id"]: row for row in packet["scopes"]}
    if len(scopes) != len(packet["scopes"]) or any(
        scope_id not in scopes for scope_id, _ in claims
    ):
        raise ValueError("review packet contains unscoped candidate")

    opinions: dict[tuple[str, str], dict[str, dict[str, Any]]] = defaultdict(dict)
    for review in submission["reviews"]:
        if not isinstance(review, dict) or set(review) != {
            "scope_id", "claim_id", "reviewer_ref", "review_session_ref",
            "decision", "reason", "source_only_review",
        }:
            raise ValueError("review item schema mismatch")
        key = review["scope_id"], review["claim_id"]
        if key not in claims:
            raise ValueError("review verdict references unknown candidate")
        reviewer = review["reviewer_ref"]
        if (not isinstance(reviewer, str) or not reviewer.strip()
                or not isinstance(review["review_session_ref"], str)
                or not review["review_session_ref"].strip()):
            raise ValueError("review needs reviewer and session references")
        if review["decision"] not in _DECISIONS:
            raise ValueError("review decision must be positive, negative or unknown")
        if not isinstance(review["reason"], str) or not review["reason"].strip():
            raise ValueError("review requires a source-based justification")
        if type(review["source_only_review"]) is not bool:
            raise TypeError("source_only_review must be boolean")
        if reviewer in opinions[key]:
            raise ValueError("duplicate review for one candidate and reviewer")
        opinions[key][reviewer] = review

    results: list[dict[str, Any]] = []
    labels: list[dict[str, Any]] = []
    for key, candidate in sorted(claims.items()):
        reviews = list(opinions[key].values())
        full = len(reviews) >= 2 and all(
            review["source_only_review"] for review in reviews
        )
        decisions = {review["decision"] for review in reviews}
        consensus = full and len(decisions) == 1 and "unknown" not in decisions
        decision = next(iter(decisions)) if consensus else "unknown"
        reason = (
            "provisional_source_review_consensus_pending_external_validation"
            if consensus else "unresolved_or_disputed_source_review"
        )
        results.append({
            "scope_id": key[0],
            "claim_id": key[1],
            "status": "provisional_consensus" if consensus else "unresolved",
            "decision": decision,
            "number_of_reviewers": len(reviews),
            "source_only_declarations": all(
                row["source_only_review"] for row in reviews
            ),
            "external_reviewer_independence_verified": False,
        })
        witness = candidate["source"]
        labels.append({
            "scope_id": key[0],
            "claim_id": key[1],
            "truth": decision,
            "source": {
                "path": witness["path"],
                "blob_sha": witness["blob_sha"],
                "line_start": witness["line_start"],
                "line_end": witness["line_end"],
            },
            "reason": reason,
        })

    # Do not manufacture an independently blinded reference: even agreeing
    # self-described reviewers cannot prove a closed negative universe.
    provisional = {
        "schema_version": 1,
        "scopes": [{
            "scope_id": row["scope_id"],
            "case_id": row["case_id"],
            "repository": row["repository"],
            "commit_sha": row["commit_sha"],
            "construct": row["construct"],
            "source_role": row["source_role"],
            "positive_complete": False,
            "negative_complete": False,
            "review_method": "source_reviewer",
            "review_ref": "provisional_source_review_no_external_attestation",
            "scanner_blind": False,
            "negative_method": row["negative_search_plan"],
        } for row in packet["scopes"]],
        "labels": labels,
    }
    validate_reference(provisional)
    denied = score_reference(provisional, [])
    if denied["aggregate"] is not None:
        raise AssertionError("provisional review must not emit accuracy metrics")
    return {
        "schema_version": 1,
        "mode": "provisional_source_review_not_independent_truth",
        "packet_sha256": packet["packet_sha256"],
        "review_consensus": results,
        "provisional_reference": provisional,
        "release_accuracy_assessable": False,
        "independent_review_externally_verified": False,
        "source_universe_completeness_verified": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a scanner-blind source review packet or adjudicate it"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare")
    prepare.add_argument("--reference", required=True)
    prepare.add_argument("--checkouts", required=True)
    decide = sub.add_parser("adjudicate")
    decide.add_argument("--packet", required=True)
    decide.add_argument("--reviews", required=True)
    args = parser.parse_args()
    if args.command == "prepare":
        with open(args.reference, encoding="utf-8") as handle:
            ref = json.load(handle)
        with open(args.checkouts, encoding="utf-8") as handle:
            checkouts = json.load(handle)
        output = prepare_source_review_packet(ref, checkouts)
    else:
        with open(args.packet, encoding="utf-8") as handle:
            packet = json.load(handle)
        with open(args.reviews, encoding="utf-8") as handle:
            reviews = json.load(handle)
        output = adjudicate_review_packet(packet, reviews)
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
