from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "prepare_llm_review_packet.py"
SPEC = importlib.util.spec_from_file_location("prepare_llm_review_packet", SCRIPT)
assert SPEC and SPEC.loader
mod = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mod
SPEC.loader.exec_module(mod)

Judge = mod.Judge
LLMReviewPacketError = mod.LLMReviewPacketError
prepare_packet = mod.prepare_packet


def _packet() -> dict:
    return {
        "schema_version": 1,
        "study": "attack-path-finding-validation-2026",
        "phase": "source_blind_reference",
        "cases": [
            {
                "case_id": "ap-001",
                "case_type": "attack_path",
                "repository": {"repo": "owner/repo", "sha": "1" * 40},
                "source_scope": ["app.py"],
                "question": {"type": "attack_path"},
                "reviewers": [{}, {}],
            }
        ],
    }


def test_prepare_packet_assigns_two_blinded_llm_judges() -> None:
    prepared = prepare_packet(
        _packet(),
        judge_a=Judge("judge-a-run-1", "openai", "gpt-5.6-sol"),
        judge_b=Judge("judge-b-run-1", "google", "gemini-pro"),
        prompt_version="llm-review-v1",
    )

    assert prepared["review_protocol"] == "dual_blind_llm_v1"
    assert prepared["llm_prompt_version"] == "llm-review-v1"
    reviewers = prepared["cases"][0]["reviewers"]
    assert [review["reviewer_kind"] for review in reviewers] == ["llm", "llm"]
    assert all(review["independent_review"] is True for review in reviewers)
    assert all(review["independent_human"] is False for review in reviewers)
    assert all(review["horustrace_output_seen"] is False for review in reviewers)
    assert all(review["locked"] is False for review in reviewers)
    assert reviewers[0]["model"] == {
        "provider": "openai",
        "name": "gpt-5.6-sol",
        "prompt_version": "llm-review-v1",
    }


def test_prepare_packet_does_not_mutate_source_packet() -> None:
    packet = _packet()
    prepare_packet(
        packet,
        judge_a=Judge("a", "provider-a", "model-a"),
        judge_b=Judge("b", "provider-b", "model-b"),
        prompt_version="v1",
    )
    assert packet["cases"][0]["reviewers"] == [{}, {}]


def test_prepare_packet_requires_distinct_judge_ids() -> None:
    with pytest.raises(LLMReviewPacketError, match="different reviewer_id"):
        prepare_packet(
            _packet(),
            judge_a=Judge("same", "provider-a", "model-a"),
            judge_b=Judge("same", "provider-b", "model-b"),
            prompt_version="v1",
        )
