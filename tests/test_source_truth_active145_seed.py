"""Guard the 145-case exact-SHA non-LangGraph source-review population."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from horustrace.source_truth_coverage import source_truth_coverage

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = ROOT / "research/real-world-agent-security-2026/cohort.json"
EXPECTED = ROOT / "research/wave-c-c02f-active145/expected-agent-review-scopes.json"


def test_c02f_active145_seed_matches_frozen_archive_without_mutating_it() -> None:
    archive = json.loads(ARCHIVE.read_text(encoding="utf-8"))
    source = json.loads(EXPECTED.read_text(encoding="utf-8"))
    assert archive["cohort_frozen"] is True
    assert len(archive["cases"]) == 180
    assert len(source["expected_scopes"]) == 145
    expected = {
        case["case_id"]: case
        for case in archive["cases"]
        if case["framework_stratum"] != "langgraph"
    }
    assert len(expected) == 145
    for scope in source["expected_scopes"]:
        case = expected[scope["case_id"]]
        assert scope["scope_id"] == case["case_id"] + ":agent:unknown"
        assert scope["repository"] == case["repo"]
        assert scope["commit_sha"] == case["sha"]
        assert scope["framework"] == case["framework_stratum"]
        assert scope["construct"] == "agent"
        # Unknown role is deliberate. The source case could contain only
        # an MCP provider, a passive import or a source-negative agent site.
        assert scope["source_role"] == "unknown"
    frameworks = Counter(
        x["framework"] for x in source["expected_scopes"]
    )
    assert frameworks == {
        "fastagent": 3, "google-adk": 37, "mcp-custom": 40,
        "openai-agents": 31, "pydantic-ai": 34,
    }
    assert "active145_non_langgraph" in source["manifest_ref"]
    assert "@blob:" in source["manifest_ref"]


def test_c02f_real_seed_without_independent_truth_is_145_no_go() -> None:
    expected = json.loads(EXPECTED.read_text(encoding="utf-8"))
    # Empty versioned reference is explicitly NOT accuracy truth.
    report = source_truth_coverage(
        expected, {"schema_version": 1, "scopes": [], "labels": []}, {},
    )
    assert report["expected_scope_count"] == 145
    assert report["missing_scope_count"] == 145
    assert report["certified_precision"] is None
    assert report["certified_recall"] is None
    assert report["production_cutover_authorized"] is False
    assert all(
        "missing_reference_scope" in row["blockers"]
        for row in report["scopes"]
    )
