from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "build_finding_precision_review_packet.py"
SPEC = importlib.util.spec_from_file_location("build_finding_precision_review_packet", SCRIPT)
assert SPEC and SPEC.loader
mod = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mod
SPEC.loader.exec_module(mod)

PhaseBError = mod.PhaseBError
build_phase_b_packet = mod.build_phase_b_packet


def _phase_a(*, allowed: bool = True, disagreements: int = 0) -> dict:
    return {
        "study": "attack-path-finding-validation-2026",
        "cases": 42,
        "consensus_cases": 42 - disagreements,
        "disagreement_cases": disagreements,
        "scanner_reveal_allowed": allowed,
    }


def _findings() -> dict:
    return {
        "scanner_sha": "a" * 40,
        "cases": [
            {
                "case_id": "rw-001",
                "repo": "owner/a",
                "sha": "1" * 40,
                "findings": [
                    {
                        "rule_id": "AGT020",
                        "severity": "high",
                        "default_severity": "high",
                        "title": "Sensitive write",
                        "message": "Agent can invoke a write-capable tool.",
                        "agent": "agent-a",
                        "confidence": "supported",
                        "fingerprint": "fp-a",
                        "source_context": "runtime",
                        "standards": {"owasp_agentic": ["ASI05"]},
                        "evidence": ["tool has write capability"],
                        "location": {"path": "agent.py", "line": 10, "column": 1},
                        "provenance": [
                            {
                                "subject": "agent-a",
                                "fact": "invokes tool",
                                "origin": "static",
                                "location": {"path": "tools.py", "line": 20, "column": 1},
                            }
                        ],
                    },
                    {
                        "rule_id": "NET002",
                        "severity": "medium",
                        "default_severity": "medium",
                        "title": "External network",
                        "message": "Agent can reach an external network destination.",
                        "agent": "agent-a",
                        "confidence": "potential",
                        "fingerprint": "fp-b",
                        "evidence": ["external destination"],
                        "location": {"path": "agent.py", "line": 11, "column": 1},
                        "provenance": [],
                    },
                ],
            },
            {
                "case_id": "rw-002",
                "repo": "owner/b",
                "sha": "2" * 40,
                "findings": [
                    {
                        "rule_id": "AGT020",
                        "severity": "high",
                        "title": "Sensitive write 2",
                        "message": "Another agent can invoke a write-capable tool.",
                        "agent": "agent-b",
                        "confidence": "authority_confirmed",
                        "fingerprint": "fp-c",
                        "evidence": [],
                        "location": {"path": "main.py", "line": 4, "column": 1},
                        "provenance": [],
                    }
                ],
            },
        ],
    }


def test_phase_b_is_blocked_until_phase_a_allows_reveal() -> None:
    with pytest.raises(PhaseBError, match="blocked"):
        build_phase_b_packet(_phase_a(allowed=False), _findings())


def test_phase_b_allows_locked_phase_a_disagreements_for_escalation() -> None:
    public, hidden = build_phase_b_packet(_phase_a(disagreements=1), _findings())

    assert public["case_count"] == 3
    assert hidden["case_count"] == 3


def test_public_packet_hides_scanner_metadata() -> None:
    public, hidden = build_phase_b_packet(_phase_a(), _findings(), target=3)

    assert public["case_count"] == 3
    assert public["raw_horustrace_metadata_hidden"] is True
    assert hidden["case_count"] == 3
    assert set(hidden["strata"]) == {"AGT020|high", "NET002|medium"}

    public_text = repr(public)
    assert "AGT020" not in public_text
    assert "NET002" not in public_text
    assert "fp-a" not in public_text
    assert "fp-b" not in public_text
    assert "fp-c" not in public_text
    assert "Sensitive write" not in public_text
    assert "authority_confirmed" not in public_text

    assert hidden["cases"][0]["rule_id"] in {"AGT020", "NET002"}
    assert any(case.get("owasp_agentic") == ["ASI05"] for case in hidden["cases"])
    assert all(case["reviewers"][0]["locked"] is False for case in public["cases"])
    assert all(
        case["reviewers"][0]["horustrace_output_seen"] is False
        for case in public["cases"]
    )


def test_public_claim_retains_bounded_source_scope() -> None:
    public, _ = build_phase_b_packet(_phase_a(), _findings(), target=1)
    case = public["cases"][0]

    assert case["source_scope"]
    assert case["repository"]["repo"] in {"owner/a", "owner/b"}
    assert case["question"]["claim"]["message"]
