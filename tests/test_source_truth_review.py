"""Wave C C02c: source-only reviewer packets never certify scanner accuracy."""
from __future__ import annotations

import json
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from horustrace.source_truth_oracle import score_reference
from horustrace.source_truth_review import (
    adjudicate_review_packet,
    prepare_source_review_packet,
)


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), *args], stderr=subprocess.DEVNULL
    ).decode("utf-8").strip()


def _fixture(tmp_path: Path) -> tuple[dict, dict[str, str]]:
    repo = tmp_path / "checkout"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "agents.py").write_text(
        "from pydantic_ai import Agent\n"
        "worker = Agent('model')\n"
        "def application_factory(): return object()\n",
        encoding="utf-8",
    )
    _git(repo, "add", "agents.py")
    _git(repo, "-c", "user.name=fixture", "-c",
         "user.email=fixture@example.org", "commit", "-qm", "source")
    commit = _git(repo, "rev-parse", "HEAD")
    blob = _git(repo, "rev-parse", f"{commit}:agents.py")
    scope_id = "case1:agent"
    reference = {
        "schema_version": 1,
        "scopes": [{
            "scope_id": scope_id, "case_id": "case1",
            "repository": "example/review-fixture",
            "commit_sha": commit, "construct": "agent",
            "source_role": "runtime",
            "positive_complete": False, "negative_complete": False,
            "review_method": "unreviewed", "review_ref": "pending",
            "scanner_blind": False,
            "negative_method": "enumerate factories and constructors",
        }],
        "labels": [{
            "scope_id": scope_id,
            "claim_id": cid,
            "truth": "unknown",
            "source": {
                "path": "agents.py", "blob_sha": blob,
                "line_start": line, "line_end": line,
            },
            "reason": "unreviewed candidate, source only",
        } for cid, line in [("agent:worker", 2), ("factory:app", 3)]],
    }
    return reference, {scope_id: str(repo)}


def _reviews(packet: dict) -> dict:
    return {
        "packet_sha256": packet["packet_sha256"],
        "reviews": [{
            "scope_id": item["scope_id"],
            "claim_id": item["claim_id"],
            "reviewer_ref": reviewer,
            "review_session_ref": "isolated-fixture-" + reviewer,
            "decision": (
                "positive" if item["claim_id"] == "agent:worker"
                else "negative"
            ),
            "reason": "fixture reviewer confirms source construct",
            "source_only_review": True,
        } for item in packet["candidates"] for reviewer in ("r1", "r2")],
    }


def test_c02c_review_packets_have_pinned_anchors_but_no_truth(
    tmp_path: Path,
) -> None:
    reference, checkouts = _fixture(tmp_path)
    packet = prepare_source_review_packet(reference, checkouts)
    assert packet["source_anchors_verified"] is True
    assert packet["semantic_claims_verified"] is False
    assert packet["reviewer_independence_verified"] is False
    assert packet["universe_completeness_verified"] is False
    assert {x["claim_id"] for x in packet["candidates"]} == {
        "agent:worker", "factory:app",
    }
    text = json.dumps(packet)
    assert "scanner_predictions" not in text
    assert '"truth"' not in text
    assert '"reason"' not in text
    assert "source-only" not in text
    assert str(tmp_path) not in text
    assert all(x["source"]["sha256"] for x in packet["candidates"])


def test_c02c_unanimous_review_is_only_provisional_and_cannot_score(
    tmp_path: Path,
) -> None:
    reference, checkouts = _fixture(tmp_path)
    packet = prepare_source_review_packet(reference, checkouts)
    adjudicated = adjudicate_review_packet(packet, _reviews(packet))
    assert adjudicated["release_accuracy_assessable"] is False
    assert adjudicated["independent_review_externally_verified"] is False
    assert all(
        row["status"] == "provisional_consensus"
        for row in adjudicated["review_consensus"]
    )
    provisional = adjudicated["provisional_reference"]
    assert {row["truth"] for row in provisional["labels"]} == {
        "positive", "negative",
    }
    assert provisional["scopes"][0]["review_method"] == "source_reviewer"
    assert provisional["scopes"][0]["positive_complete"] is False
    assert provisional["scopes"][0]["negative_complete"] is False
    assert provisional["scopes"][0]["scanner_blind"] is False
    scored = score_reference(provisional, [
        {"scope_id": "case1:agent", "claim_id": "agent:worker"},
    ])
    assert scored["aggregate"] is None
    assert set(scored["scopes"][0]["blockers"]) >= {
        "incomplete_positive_universe", "incomplete_negative_universe",
        "reference_not_declared_independent_blind", "review_not_scanner_blind",
    }


def test_c02c_disagreement_or_incomplete_reviews_stays_unknown(
    tmp_path: Path,
) -> None:
    ref, roots = _fixture(tmp_path)
    packet = prepare_source_review_packet(ref, roots)
    reviews = _reviews(packet)
    reviews["reviews"][0]["decision"] = "negative"
    result = adjudicate_review_packet(packet, reviews)
    assert next(x for x in result["review_consensus"]
                if x["claim_id"] == "agent:worker")["decision"] == "unknown"
    assert any(x["truth"] == "unknown"
               for x in result["provisional_reference"]["labels"])
    partial = {"packet_sha256": packet["packet_sha256"],
               "reviews": reviews["reviews"][0:1]}
    result = adjudicate_review_packet(packet, partial)
    assert all(x["decision"] == "unknown" for x in result["review_consensus"])


def test_c02c_reviewers_cannot_hide_scanner_exposure_with_declaration(
    tmp_path: Path,
) -> None:
    ref, roots = _fixture(tmp_path)
    packet = prepare_source_review_packet(ref, roots)
    submission = _reviews(packet)
    submission["reviews"][0]["source_only_review"] = False
    result = adjudicate_review_packet(packet, submission)
    candidate = next(
        r for r in result["review_consensus"]
        if r["claim_id"] == "agent:worker"
    )
    assert candidate["decision"] == "unknown"
    assert candidate["source_only_declarations"] is False


def test_c02c_existing_truth_or_claimed_complete_scopes_refused(
    tmp_path: Path,
) -> None:
    ref, roots = _fixture(tmp_path)
    ref["labels"][0]["truth"] = "positive"
    with pytest.raises(ValueError, match="disclose candidate verdicts"):
        prepare_source_review_packet(ref, roots)
    ref["labels"][0]["truth"] = "unknown"
    ref["scopes"][0]["positive_complete"] = True
    with pytest.raises(ValueError, match="unreviewed and open"):
        prepare_source_review_packet(ref, roots)
    ref["scopes"][0]["positive_complete"] = False
    ref["scopes"][0]["review_method"] = "independent_blind"
    with pytest.raises(ValueError, match="unreviewed and open"):
        prepare_source_review_packet(ref, roots)


def test_c02c_packet_requires_real_git_source_anchor(tmp_path: Path) -> None:
    ref, roots = _fixture(tmp_path)
    ref["labels"][0]["source"]["blob_sha"] = "a" * 40
    with pytest.raises(ValueError, match="blob SHA"):
        prepare_source_review_packet(ref, roots)


def test_c02c_tampered_packet_or_wrong_bound_submission_rejected(
    tmp_path: Path,
) -> None:
    ref, roots = _fixture(tmp_path)
    packet = prepare_source_review_packet(ref, roots)
    reviews = _reviews(packet)
    reviews["packet_sha256"] = "a" * 64
    with pytest.raises(ValueError, match="not bound"):
        adjudicate_review_packet(packet, reviews)
    packet["candidates"][0]["source"]["line_end"] = 99
    with pytest.raises(ValueError, match="digest mismatch"):
        adjudicate_review_packet(packet, _reviews(packet))


def test_c02c_duplicate_reviewer_and_unknown_candidate_rejected(
    tmp_path: Path,
) -> None:
    ref, roots = _fixture(tmp_path)
    packet = prepare_source_review_packet(ref, roots)
    submission = _reviews(packet)
    submission["reviews"].append(deepcopy(submission["reviews"][0]))
    with pytest.raises(ValueError, match="duplicate review"):
        adjudicate_review_packet(packet, submission)
    submission = _reviews(packet)
    submission["reviews"][0]["claim_id"] = "never-in-packet"
    with pytest.raises(ValueError, match="unknown candidate"):
        adjudicate_review_packet(packet, submission)


def test_c02c_invalid_attestation_and_review_schema_fail_closed(
    tmp_path: Path,
) -> None:
    ref, roots = _fixture(tmp_path)
    packet = prepare_source_review_packet(ref, roots)
    submission = _reviews(packet)
    submission["reviews"][0]["source_only_review"] = "true"
    with pytest.raises(TypeError, match="boolean"):
        adjudicate_review_packet(packet, submission)
    submission = _reviews(packet)
    submission["reviews"][0]["decision"] = "resolved_without_source"
    with pytest.raises(ValueError, match="positive, negative or unknown"):
        adjudicate_review_packet(packet, submission)
    submission = _reviews(packet)
    submission["reviews"][0]["scanner_detected"] = True
    with pytest.raises(ValueError, match="schema mismatch"):
        adjudicate_review_packet(packet, submission)


def test_c02c_packet_stable_across_copy_of_same_git_source(
    tmp_path: Path,
) -> None:
    ref, roots = _fixture(tmp_path)
    first = prepare_source_review_packet(ref, roots)
    second = prepare_source_review_packet(ref, roots)
    assert first == second
    assert len(first["packet_sha256"]) == 64


def test_c02c_empty_candidate_set_is_never_accepted_as_truth(
    tmp_path: Path,
) -> None:
    ref, roots = _fixture(tmp_path)
    ref["labels"] = []
    packet = prepare_source_review_packet(ref, roots)
    out = adjudicate_review_packet(packet, {
        "packet_sha256": packet["packet_sha256"], "reviews": [],
    })
    assert out["release_accuracy_assessable"] is False
    assert out["provisional_reference"]["labels"] == []
