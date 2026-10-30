"""Study aggregation fails closed on missing or changed frozen source cases."""
from __future__ import annotations

import json

import pytest

from scripts.verify_accuracy_wave_a_baseline import ROOT
from scripts.wave_a_aggregate_traces import TraceStudyError, aggregate

COHORT = ROOT / "research/accuracy-wave-a-retrospective-20261014/cohort.json"
STAGES = [
    "discovered", "initial_instances_consolidated", "mcp_context_resolved",
    "source_semantics_resolved", "delegation_projected", "skills_bound",
    "normalized", "flows_resolved", "attack_paths", "adg", "findings",
]


def _write_case(root, case):
    path = root / case["case_id"]
    path.mkdir()
    result = {
        **{key: case[key] for key in (
            "case_id", "repo", "sha", "framework", "application_path"
        )},
        "schema_version": 1,
        "entities": 0, "tools": 0, "mcp_servers": 0,
        "skills": 0, "findings": 0, "attack_paths": 0,
        "trace_stage_count": 11, "trace_truncated": False,
    }
    path.joinpath("result.json").write_text(json.dumps(result))
    path.joinpath("trace.json").write_text(json.dumps({
        "stages": [
            {"stage": name, "added": 0, "removed": 0, "entities": 0}
            for name in STAGES
        ],
        "events_truncated": False,
    }))


def test_full_wave_a_aggregate_has_no_implied_accuracy(tmp_path):
    cases = json.loads(COHORT.read_text())["cases"]
    for case in cases:
        _write_case(tmp_path, case)
    report = aggregate(tmp_path)
    assert report["cases_completed"] == report["cases_expected"] == 30
    assert report["independent_source_adjudication"] is False
    assert report["precision_recall"] is None
    assert set(report["stages"]) == set(STAGES)


def test_wave_a_aggregate_fails_on_missing_pinned_case(tmp_path):
    cases = json.loads(COHORT.read_text())["cases"]
    for case in cases[:-1]:
        _write_case(tmp_path, case)
    with pytest.raises(TraceStudyError, match="Missing expected pinned cases"):
        aggregate(tmp_path)


def test_wave_a_aggregate_rejects_source_revision_drift(tmp_path):
    cases = json.loads(COHORT.read_text())["cases"]
    for case in cases:
        _write_case(tmp_path, case)
    path = tmp_path / cases[0]["case_id"] / "result.json"
    data = json.loads(path.read_text())
    data["sha"] = "0" * 40
    path.write_text(json.dumps(data))
    with pytest.raises(TraceStudyError, match="source mismatch"):
        aggregate(tmp_path)
