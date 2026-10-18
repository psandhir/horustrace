"""Frozen original reference completeness is NOT independent V2 full accuracy."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from scripts.audit_wave_b540_active_truth_coverage import DIMENSIONS, audit

ROOT = Path(__file__).resolve().parents[1] / "research/real-world-agent-security-2026"


def _original() -> tuple[dict, dict]:
    cohort = json.loads((ROOT / "cohort.json").read_text())
    truth = {
        key: json.loads(path.read_text())
        for path in sorted((ROOT / "ground-truth").glob("rw-*.json"))
        if (key := path.stem)
    }
    return cohort, truth


def test_active145_only_counts_explicit_complete_reference_cases() -> None:
    cohort, truth = _original()
    report = audit(cohort, truth)
    assert report["original_frozen_cases_unchanged"] == 180
    assert report["active_cases"] == 145
    assert report["archived_langgraph_cases_excluded_only_from_active"] == 35
    assert report["reference_completeness"]["agent_entities"] == {
        "complete": 56, "incomplete": 89
    }
    assert len(report["case_rows"]) == 145
    assert sum(r["framework"] == "langgraph" for r in report["case_rows"]) == 0
    for k in DIMENSIONS:
        assert sum(report["reference_completeness"][k].values()) == 145
    assert report["independent_blind_v2_truth"] is False
    assert report["v2_bounded_negative_truth_complete"] is False
    assert report["agent_precision"] is None and report["agent_recall"] is None
    assert report["graph_precision"] is None and report["graph_recall"] is None
    assert report["wave_b_go"] is False and report["wave_c_go"] is False


def test_incomplete_agents_cannot_be_counted_as_closed_world_negative() -> None:
    cohort, truth = _original()
    report = audit(cohort, truth)
    partial = [x for x in report["case_rows"]
               if not x["reference_completeness"]["agent_entities"]]
    assert len(partial) == 89
    assert all(not x["eligible_for_closed_world_negative_scoring"]["agent_entities"]
               for x in partial)


def test_missing_truth_cannot_be_treated_as_negative() -> None:
    c, truth = _original()
    truth.pop("rw-001")
    with pytest.raises(ValueError, match="missing or duplicate"):
        audit(c, truth)


def test_truth_source_sha_drift_is_fail_closed() -> None:
    c, truth = _original()
    truth["rw-001"]["source_reference"]["sha"] = "f" * 40
    with pytest.raises(ValueError, match="source revision"):
        audit(c, truth)


def test_missing_explicit_per_dimension_completeness_is_fail_closed() -> None:
    c, truth = _original()
    del truth["rw-001"]["tier_a"]["reference_completeness"]["tools"]
    with pytest.raises(ValueError, match="missing explicit"):
        audit(c, truth)


def test_tracked_historical_langgraph_exclusion_must_remain_exact() -> None:
    c, truth = _original()
    c["cases"][0]["framework_stratum"] = "langgraph"
    with pytest.raises(ValueError, match="active 145"):
        audit(c, truth)


def test_unreviewed_truth_cannot_be_scored() -> None:
    c, truth = _original()
    truth["rw-001"]["truth_lock"]["horustrace_output_seen"] = True
    with pytest.raises(ValueError, match="truth lock invalid"):
        audit(c, truth)


def test_source_rationale_requires_evidence_even_when_absent() -> None:
    c, truth = _original()
    truth["rw-001"]["assertions"][0]["evidence"] = []
    with pytest.raises(ValueError, match="unsupported source label"):
        audit(c, truth)


def test_no_old_truth_rewrite_or_human_blind_promotion() -> None:
    c, truth = _original()
    snapshot = copy.deepcopy(truth["rw-001"])
    report = audit(c, truth)
    assert truth["rw-001"] == snapshot
    assert report["independent_blind_v2_truth"] is False
