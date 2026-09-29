from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "attack_path_finding_review.py"
SPEC = importlib.util.spec_from_file_location("attack_path_finding_review", SCRIPT)
assert SPEC and SPEC.loader
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)

ReviewPackError = mod.ReviewPackError
summarize = mod.summarize
validate_review_case = mod.validate_review_case
validate_review_packet = mod.validate_review_packet
summarize_rows = mod.summarize_rows


def _write(path: Path, *, reviewer_b: str = "reviewer-b", seen: bool = False) -> None:
    path.write_text(
        f"""
schema_version: 1
study: attack-path-finding-validation-2026
case_id: ap-001
case_type: attack_path
repository:
  repo: owner/repo
  sha: "1111111111111111111111111111111111111111"
source_scope:
  - app.py
question:
  path_nodes: [source, sink]
reviewers:
  - reviewer_id: reviewer-a
    independent_human: true
    horustrace_output_seen: false
    locked: true
    verdict: valid
    severity: high
    evidence: [app.py]
    rationale: source proves the edge
  - reviewer_id: {reviewer_b}
    independent_human: true
    horustrace_output_seen: {str(seen).lower()}
    locked: true
    verdict: valid
    severity: high
    evidence: [app.py]
    rationale: independently confirmed
""",
        encoding="utf-8",
    )


def test_two_locked_blinded_human_reviews_allow_reveal(tmp_path: Path) -> None:
    case = tmp_path / "ap-001.yaml"
    _write(case)

    row = validate_review_case(case)
    report = summarize([case])

    assert row["consensus"] is True
    assert row["consensus_verdict"] == "valid"
    assert report["scanner_reveal_allowed"] is True


def test_same_reviewer_cannot_fill_both_slots(tmp_path: Path) -> None:
    case = tmp_path / "ap-001.yaml"
    _write(case, reviewer_b="reviewer-a")

    with pytest.raises(ReviewPackError, match="different reviewer_id"):
        validate_review_case(case)


def test_review_is_invalid_if_scanner_output_was_seen(tmp_path: Path) -> None:
    case = tmp_path / "ap-001.yaml"
    _write(case, seen=True)

    with pytest.raises(ReviewPackError, match="blinded"):
        validate_review_case(case)



def test_locked_packet_can_be_validated_directly(tmp_path: Path) -> None:
    packet = tmp_path / "review-packet.yaml"
    packet.write_text(
        """
schema_version: 1
study: attack-path-finding-validation-2026
cases:
  - case_id: ap-001
    case_type: attack_path
    repository:
      repo: owner/repo
      sha: "1111111111111111111111111111111111111111"
    source_scope: [app.py]
    question:
      type: attack_path
    reviewers:
      - reviewer_id: reviewer-a
        independent_human: true
        horustrace_output_seen: false
        locked: true
        verdict: valid
        severity: high
        evidence: [app.py]
        rationale: source proves the edge
      - reviewer_id: reviewer-b
        independent_human: true
        horustrace_output_seen: false
        locked: true
        verdict: valid
        severity: high
        evidence: [app.py]
        rationale: independently confirmed
  - case_id: fp-001
    case_type: finding
    repository:
      repo: owner/repo
      sha: "1111111111111111111111111111111111111111"
    source_scope: [app.py]
    question:
      type: finding
    reviewers:
      - reviewer_id: reviewer-a
        independent_human: true
        horustrace_output_seen: false
        locked: true
        verdict: supported
        severity: medium
        evidence: [app.py]
        rationale: finding is supported
      - reviewer_id: reviewer-b
        independent_human: true
        horustrace_output_seen: false
        locked: true
        verdict: supported
        severity: medium
        evidence: [app.py]
        rationale: independently supported
""",
        encoding="utf-8",
    )

    rows = validate_review_packet(packet)
    report = summarize_rows(rows)

    assert len(rows) == 2
    assert report["attack_path_cases"] == 1
    assert report["finding_cases"] == 1
    assert report["scanner_reveal_allowed"] is True


def test_two_blinded_llm_reviews_are_valid_and_disagreements_escalate(tmp_path: Path) -> None:
    packet = tmp_path / "llm-review-packet.yaml"
    packet.write_text(
        """
schema_version: 1
study: attack-path-finding-validation-2026
cases:
  - case_id: ap-llm-001
    case_type: attack_path
    repository:
      repo: owner/repo
      sha: "1111111111111111111111111111111111111111"
    source_scope: [app.py]
    question:
      type: attack_path
    reviewers:
      - reviewer_id: openai-run-1
        reviewer_kind: llm
        independent_review: true
        independent_human: false
        horustrace_output_seen: false
        locked: true
        model:
          provider: openai
          name: gpt-5.6-sol
          prompt_version: llm-review-v1
        verdict: valid
        severity: high
        evidence: [app.py:10]
        rationale: source proves the edge
      - reviewer_id: google-run-1
        reviewer_kind: llm
        independent_review: true
        independent_human: false
        horustrace_output_seen: false
        locked: true
        model:
          provider: google
          name: gemini-pro
          prompt_version: llm-review-v1
        verdict: invalid
        severity: medium
        evidence: [app.py:10]
        rationale: source does not prove dispatch
""",
        encoding="utf-8",
    )

    rows = validate_review_packet(packet)
    report = summarize_rows(rows)

    assert rows[0]["reviewer_kinds"] == ["llm", "llm"]
    assert rows[0]["evaluator_models"][0]["prompt_version"] == "llm-review-v1"
    assert report["disagreement_cases"] == 1
    assert report["scanner_reveal_allowed"] is True
    assert report["escalation_cases"] == ["ap-llm-001"]
