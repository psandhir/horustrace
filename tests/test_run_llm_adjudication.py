from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "run_llm_adjudication.py"
SPEC = importlib.util.spec_from_file_location("run_llm_adjudication", SCRIPT)
assert SPEC and SPEC.loader
mod = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mod
SPEC.loader.exec_module(mod)

LLMAdjudicationError = mod.LLMAdjudicationError
_neutral_case = mod._neutral_case
_review_schema = mod._review_schema
_source_url = mod._source_url
_validate_reviews = mod._validate_reviews
validate_public_packet = mod.validate_public_packet


def _case(case_type: str = "attack_path") -> dict:
    return {
        "case_id": "case-001",
        "case_type": case_type,
        "category": "proven_authority",
        "study_phase": "source_blind_attack_path",
        "repository": {"repo": "owner/repo", "sha": "1" * 40},
        "source_scope": ["space dir/agent.py"],
        "question": {
            "type": case_type,
            "claim": {"source": "agent-a", "relation": "can_invoke", "target": "tool-a"},
            "prompt": "Is the relationship source-proven?",
        },
        "reviewers": [{}, {}],
    }


def test_neutral_case_does_not_expose_selection_category() -> None:
    neutral = _neutral_case(_case())

    assert "category" not in neutral
    assert "study_phase" not in neutral
    assert neutral["question"]["claim"]["source"] == "agent-a"


def test_public_packet_rejects_hidden_scanner_metadata() -> None:
    packet = {
        "study": "attack-path-finding-validation-2026",
        "cases": [_case()],
        "rule_id": "AGT020",
    }

    with pytest.raises(LLMAdjudicationError, match="hidden scanner metadata"):
        validate_public_packet(packet)


def test_review_schema_is_bounded_to_packet_case_ids() -> None:
    cases = [_case(), {**_case("finding"), "case_id": "case-002"}]
    schema = _review_schema(cases)

    item = schema["properties"]["reviews"]["items"]
    assert item["properties"]["case_id"]["enum"] == ["case-001", "case-002"]
    assert schema["properties"]["reviews"]["minItems"] == 2
    assert item["properties"]["confidence"]["enum"] == ["high", "low", "medium"]
    assert "partial_reasons" in item["required"]
    assert "partial" in item["properties"]["verdict"]["enum"]


def test_validate_reviews_applies_case_specific_verdicts() -> None:
    cases = [_case(), {**_case("finding"), "case_id": "case-002"}]
    payload = {
        "reviews": [
            {
                "case_id": "case-001",
                "verdict": "valid",
                "severity": "medium",
                "confidence": "high",
                "evidence": ["agent.py:10"],
                "rationale": "binding is explicit",
            },
            {
                "case_id": "case-002",
                "verdict": "supported",
                "severity": "informational",
                "confidence": "medium",
                "evidence": ["agent.py:4"],
                "rationale": "entity construction is explicit",
            },
        ]
    }

    reviews = _validate_reviews(payload, cases)

    assert [review.case_id for review in reviews] == ["case-001", "case-002"]
    assert reviews[0].confidence == "high"


def test_validate_reviews_rejects_attack_verdict_for_finding() -> None:
    case = _case("finding")
    payload = {
        "reviews": [
            {
                "case_id": "case-001",
                "verdict": "valid",
                "severity": "medium",
                "confidence": "high",
                "evidence": ["agent.py:10"],
                "rationale": "wrong vocabulary",
            }
        ]
    }

    with pytest.raises(LLMAdjudicationError, match="invalid for finding"):
        _validate_reviews(payload, [case])


def test_source_url_pins_sha_and_quotes_path() -> None:
    url = _source_url("owner/repo", "a" * 40, "space dir/agent.py")

    assert "/owner/repo/" in url
    assert "a" * 40 in url
    assert "space%20dir/agent.py" in url

def test_validate_reviews_accepts_partial_with_reason() -> None:
    case = _case("finding")
    payload = {
        "reviews": [
            {
                "case_id": "case-001",
                "verdict": "partial",
                "partial_reasons": ["destination_provenance"],
                "severity": "medium",
                "confidence": "high",
                "evidence": ["agent.py:10"],
                "rationale": "network authority is real but the destination is fixed",
            }
        ]
    }

    reviews = _validate_reviews(payload, [case])

    assert reviews[0].verdict == "partial"
    assert reviews[0].partial_reasons == ["destination_provenance"]


def test_validate_reviews_rejects_partial_without_reason() -> None:
    case = _case("finding")
    payload = {
        "reviews": [
            {
                "case_id": "case-001",
                "verdict": "partial",
                "partial_reasons": [],
                "severity": "medium",
                "confidence": "high",
                "evidence": ["agent.py:10"],
                "rationale": "qualification omitted",
            }
        ]
    }

    with pytest.raises(LLMAdjudicationError, match="requires at least one"):
        _validate_reviews(payload, [case])

