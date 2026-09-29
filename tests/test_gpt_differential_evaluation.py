from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "gpt_differential_evaluation.py"
SPEC = importlib.util.spec_from_file_location("gpt_differential_evaluation", SCRIPT)
assert SPEC and SPEC.loader
mod = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mod
SPEC.loader.exec_module(mod)

DifferentialError = mod.DifferentialError
build_packet = mod.build_packet
score = mod.score


def _scanner() -> dict:
    return {
        "study": "real-world-agent-security-2026",
        "scanner_sha": "a" * 40,
        "cases": [
            {
                "case_id": "rw-001",
                "repo": "owner/a",
                "sha": "1" * 40,
                "framework": "langgraph",
                "findings": [
                    {
                        "fingerprint": "arg-v1:same",
                        "rule_id": "AGT022",
                        "severity": "medium",
                        "agent": "agent-a",
                        "title": "State-changing tool without approval",
                    },
                    {
                        "fingerprint": "arg-v1:same",
                        "rule_id": "AGT022",
                        "severity": "medium",
                        "agent": "agent-a",
                        "title": "State-changing tool without approval",
                    },
                ],
            },
            {
                "case_id": "rw-002",
                "repo": "owner/b",
                "sha": "2" * 40,
                "framework": "mcp-custom",
                "findings": [
                    {
                        "fingerprint": "arg-v1:other",
                        "rule_id": "NET001",
                        "severity": "high",
                        "agent": None,
                        "title": "Outbound reachability lacks a detected restriction",
                    }
                ],
            },
        ],
    }


def _review() -> dict:
    return {
        "study": "gpt-horustrace-differential-2026",
        "cases": [
            {
                "case_id": "rw-001",
                "findings": [
                    {
                        "finding_id": "gpt-001",
                        "semantic_key": "state_change",
                        "severity": "medium",
                    },
                    {
                        "finding_id": "gpt-002",
                        "semantic_key": "ingress_path",
                        "severity": "high",
                    },
                ],
            },
            {"case_id": "rw-002", "findings": []},
        ],
    }


def _alignment() -> dict:
    return {
        "study": "gpt-horustrace-differential-2026",
        "batch_id": "test-batch",
        "scanner_sha": "a" * 40,
        "gpt_findings": [
            {
                "finding_id": "gpt-001",
                "coverage": "covered",
                "matched_horustrace": [
                    {"case_id": "rw-001", "index": 0, "fingerprint": "arg-v1:same"},
                    {"case_id": "rw-001", "index": 1, "fingerprint": "arg-v1:same"},
                ],
            },
            {
                "finding_id": "gpt-002",
                "coverage": "missed",
                "matched_horustrace": [],
            },
        ],
        "horustrace_findings": [
            {
                "case_id": "rw-001",
                "index": 0,
                "fingerprint": "arg-v1:same",
                "outcome": "source_supported",
            },
            {
                "case_id": "rw-001",
                "index": 1,
                "fingerprint": "arg-v1:same",
                "outcome": "semantic_duplicate",
            },
            {
                "case_id": "rw-002",
                "index": 0,
                "fingerprint": "arg-v1:other",
                "outcome": "effective_authority_review",
            },
        ],
        "attack_paths": {
            "gpt_source_supported_paths": 1,
            "horustrace_reported_paths": 0,
        },
    }


def test_export_packet_withholds_case_specific_scanner_output() -> None:
    packet = build_packet(_scanner(), ["rw-001", "rw-002"])

    assert packet["horustrace_findings_in_packet"] is False
    assert packet["scanner_sha_for_later_join"] == "a" * 40
    assert packet["cases"] == [
        {
            "case_id": "rw-001",
            "repo": "owner/a",
            "sha": "1" * 40,
            "framework": "langgraph",
        },
        {
            "case_id": "rw-002",
            "repo": "owner/b",
            "sha": "2" * 40,
            "framework": "mcp-custom",
        },
    ]
    assert "findings" not in repr(packet["cases"])
    assert packet["review_requirements"]["do_not_use_horustrace_case_output"] is True


def test_score_reports_differential_coverage_and_fingerprint_collision() -> None:
    report = score(_review(), _scanner(), _alignment())

    assert report["gpt_semantic_findings"] == {
        "total": 2,
        "covered": 1,
        "partial": 0,
        "missed": 1,
        "covered_or_partial_rate": 0.5,
        "full_coverage_rate": 0.5,
    }
    assert report["horustrace_finding_adjudication"] == {
        "effective_authority_review": 1,
        "semantic_duplicate": 1,
        "source_supported": 1,
    }
    assert report["severity_alignment_on_matches"] == {"same": 2}
    assert report["fingerprint_collisions"] == [
        {
            "case_id": "rw-001",
            "fingerprint": "arg-v1:same",
            "count": 2,
            "indexes": [0, 1],
            "rules": ["AGT022", "AGT022"],
        }
    ]


def test_score_rejects_cross_case_alignment() -> None:
    alignment = _alignment()
    alignment["gpt_findings"][0]["matched_horustrace"] = [
        {"case_id": "rw-002", "index": 0, "fingerprint": "arg-v1:other"}
    ]

    with pytest.raises(DifferentialError, match="cross-case"):
        score(_review(), _scanner(), alignment)


def test_score_rejects_omitted_scanner_finding() -> None:
    alignment = _alignment()
    alignment["horustrace_findings"] = alignment["horustrace_findings"][:-1]

    with pytest.raises(DifferentialError, match="omitted scanner findings"):
        score(_review(), _scanner(), alignment)


def test_batch_001_artifacts_are_complete_and_case_aligned() -> None:
    root = Path(__file__).resolve().parents[1] / "research" / "gpt-horustrace-differential-2026"
    review = json.loads((root / "batch-001-gpt-source-review.json").read_text(encoding="utf-8"))
    alignment = json.loads((root / "batch-001-alignment.json").read_text(encoding="utf-8"))

    review_case_ids = {case["case_id"] for case in review["cases"]}
    assert review_case_ids == {"rw-017", "rw-065", "rw-112", "rw-139", "rw-152"}
    assert review["reviewer"]["case_specific_horustrace_findings_seen_before_lock"] is False

    gpt_ids = {
        finding["finding_id"]
        for case in review["cases"]
        for finding in case.get("findings", [])
    }
    aligned_ids = {row["finding_id"] for row in alignment["gpt_findings"]}
    assert len(gpt_ids) == 15
    assert aligned_ids == gpt_ids

    statuses = [row["coverage"] for row in alignment["gpt_findings"]]
    assert statuses.count("covered") == 5
    assert statuses.count("partial") == 5
    assert statuses.count("missed") == 5

    scanner_refs = [
        (row["case_id"], row["index"])
        for row in alignment["horustrace_findings"]
    ]
    assert len(scanner_refs) == 36
    assert len(set(scanner_refs)) == len(scanner_refs)
    assert {case_id for case_id, _ in scanner_refs} == review_case_ids
    assert alignment["scanner_sha"] == "9149f4cb27b509cacc150c1f533a8db9927e05df"
