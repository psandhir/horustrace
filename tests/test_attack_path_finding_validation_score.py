from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "score_attack_path_finding_validation.py"
SPEC = importlib.util.spec_from_file_location("score_attack_path_finding_validation", SCRIPT)
assert SPEC and SPEC.loader
mod = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mod
SPEC.loader.exec_module(mod)

score = mod.score


def test_final_metrics_combine_phase_a_and_phase_b() -> None:
    phase_a = {
        "study": "attack-path-finding-validation-2026",
        "rows": [
            {
                "case_id": "ap-1",
                "case_type": "attack_path",
                "consensus": True,
                "consensus_verdict": "valid",
                "severity_consensus": True,
                "consensus_severity": "high",
            },
            {
                "case_id": "ap-2",
                "case_type": "attack_path",
                "consensus": True,
                "consensus_verdict": "invalid",
                "severity_consensus": True,
                "consensus_severity": "medium",
            },
            {
                "case_id": "ap-3",
                "case_type": "attack_path",
                "consensus": True,
                "consensus_verdict": "valid",
                "severity_consensus": True,
                "consensus_severity": "high",
            },
            {
                "case_id": "fr-1",
                "case_type": "finding",
                "consensus": True,
                "consensus_verdict": "supported",
                "severity_consensus": True,
                "consensus_severity": "medium",
            },
            {
                "case_id": "fr-2",
                "case_type": "finding",
                "consensus": True,
                "consensus_verdict": "supported",
                "severity_consensus": True,
                "consensus_severity": "low",
            },
        ],
    }
    attack_obs = {
        "study": "attack-path-finding-validation-2026",
        "scanner_sha": "a" * 40,
        "observations": [
            {"case_id": "ap-1", "scanner_reported": True},
            {"case_id": "ap-2", "scanner_reported": True},
            {"case_id": "ap-3", "scanner_reported": False},
        ],
    }
    recall_obs = {
        "study": "attack-path-finding-validation-2026",
        "scanner_sha": "a" * 40,
        "observations": [
            {"case_id": "fr-1", "scanner_detected": True},
            {"case_id": "fr-2", "scanner_detected": False},
        ],
    }
    phase_b = {
        "study": "attack-path-finding-validation-2026",
        "rows": [
            {
                "case_id": "fp-001",
                "case_type": "finding",
                "consensus": True,
                "consensus_verdict": "supported",
                "severity_consensus": True,
                "consensus_severity": "medium",
            },
            {
                "case_id": "fp-002",
                "case_type": "finding",
                "consensus": True,
                "consensus_verdict": "unsupported",
                "severity_consensus": True,
                "consensus_severity": "low",
            },
            {
                "case_id": "fp-003",
                "case_type": "finding",
                "consensus": True,
                "consensus_verdict": "supported",
                "severity_consensus": True,
                "consensus_severity": "high",
            },
        ],
    }
    hidden = {
        "study": "attack-path-finding-validation-2026",
        "do_not_distribute_to_reviewers": True,
        "cases": [
            {
                "case_id": "fp-001",
                "scanner_sha": "a" * 40,
                "scanner_severity": "medium",
                "rule_id": "AGT022",
                "owasp_agentic": ["ASI02"],
            },
            {
                "case_id": "fp-002",
                "scanner_sha": "a" * 40,
                "scanner_severity": "high",
                "rule_id": "AGT020",
                "owasp_agentic": ["ASI05"],
            },
            {
                "case_id": "fp-003",
                "scanner_sha": "a" * 40,
                "scanner_severity": "critical",
                "rule_id": "AGT020",
                "owasp_agentic": ["ASI05"],
            },
        ],
    }

    report = score(phase_a, attack_obs, recall_obs, phase_b, hidden)

    assert report["attack_paths"]["precision"] == 0.5
    assert report["attack_paths"]["recall"] == 0.5
    assert report["findings"]["recall_reference"]["recall"] == 0.5
    assert report["findings"]["precision_sample"]["precision"] == 0.6667
    assert report["findings"]["severity"]["exact_match_rate"] == 0.5
    assert report["findings"]["severity"]["within_one_level_rate"] == 1.0
    assert report["findings"]["severity"]["taxonomy"] == {
        "exact": 1,
        "scanner_one_level_higher": 1,
    }
    assert report["findings"]["precision_sample"]["by_rule"]["AGT020"] == {
        "sampled": 2,
        "supported": 1,
        "unsupported": 1,
        "precision": 0.5,
    }
    assert report["findings"]["precision_sample"]["by_owasp_agentic"]["ASI05"] == {
        "sampled": 2,
        "supported": 1,
        "unsupported": 1,
        "precision": 0.5,
    }


def test_unresolved_reviews_are_excluded_from_denominators() -> None:
    phase_a = {
        "study": "attack-path-finding-validation-2026",
        "rows": [
            {
                "case_id": "ap-u",
                "case_type": "attack_path",
                "consensus": True,
                "consensus_verdict": "unresolved",
            },
            {
                "case_id": "fr-u",
                "case_type": "finding",
                "consensus": True,
                "consensus_verdict": "unresolved",
            },
        ],
    }
    attack_obs = {
        "study": "attack-path-finding-validation-2026",
        "scanner_sha": "b" * 40,
        "observations": [],
    }
    recall_obs = {
        "study": "attack-path-finding-validation-2026",
        "scanner_sha": "b" * 40,
        "observations": [],
    }
    phase_b = {
        "study": "attack-path-finding-validation-2026",
        "rows": [
            {
                "case_id": "fp-u",
                "case_type": "finding",
                "consensus": True,
                "consensus_verdict": "unresolved",
                "severity_consensus": True,
                "consensus_severity": "unresolved",
            }
        ],
    }
    hidden = {
        "study": "attack-path-finding-validation-2026",
        "do_not_distribute_to_reviewers": True,
        "cases": [
            {
                "case_id": "fp-u",
                "scanner_sha": "b" * 40,
                "scanner_severity": "high",
            }
        ],
    }

    report = score(phase_a, attack_obs, recall_obs, phase_b, hidden)

    assert report["attack_paths"]["precision"] is None
    assert report["attack_paths"]["recall"] is None
    assert report["attack_paths"]["unresolved_cases"] == 1
    assert report["findings"]["recall_reference"]["recall"] is None
    assert report["findings"]["precision_sample"]["precision"] is None
