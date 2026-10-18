"""V2 oracle eligibility: no closed-world negatives from old completeness."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from scripts.audit_wave_b540_v2_oracle_eligibility import oracle_eligibility

ROOT = Path(__file__).resolve().parents[1] / "research/real-world-agent-security-2026"


def original() -> tuple[dict, dict]:
    cohort = json.loads((ROOT / "cohort.json").read_text(encoding="utf-8"))
    truth = {
        key: json.loads(p.read_text(encoding="utf-8"))
        for p in sorted((ROOT / "ground-truth").glob("rw-*.json"))
        if (key := p.stem)
    }
    return cohort, truth


def test_legacy_56_complete_cannot_be_reported_as_v2_oracle() -> None:
    c, truth = original()
    report = oracle_eligibility(c, truth)
    assert report["active_cases"] == 145
    assert report["legacy_agent_complete"] == 56
    assert report["legacy_agent_incomplete"] == 89
    assert report["legacy_completeness_v2_disposition"] == {
        "historical_agent_ontology_incompatible": 1,
        "historical_agent_reference_incomplete": 89,
        "historically_complete_v2_not_yet_adjudicated": 55,
    }
    assert report["independent_v2_negative_label_complete_cases"] == 0
    assert report["independently_certified_v2_agent_precision"] is None
    assert report["independently_certified_v2_agent_recall"] is None
    assert not report["methodologically_independent_new_v2_oracle"]
    assert not report["wave_b_go"] and not report["wave_c_go"]


def test_known_factory_conflict_keeps_frozen_label_but_rejects_v2_truth() -> None:
    c, truth = original()
    preserved = copy.deepcopy(truth["rw-001"])
    report = oracle_eligibility(c, truth)
    row = next(x for x in report["case_rows"] if x["case_id"] == "rw-001")
    assert row["historical_agent_complete_flag_only"] is True
    assert row["v2_agent_reference_status"] == "historical_agent_ontology_incompatible"
    assert row["v2_accuracy_eligibility_reason"] == (
        "known_factory_as_agent_source_ontology_conflict"
    )
    assert row["v2_agent_negative_universe_certified"] is False
    assert row["v2_agent_precision_recall_eligible"] is False
    assert report["known_complete_flag_ontology_conflicts"]["rw-001"][
        "historical_factory_as_agent_positives"
    ] == 6
    assert truth["rw-001"] == preserved
    assert report["frozen_180_truth_rewritten"] is False


def test_other_historical_complete_cases_are_unreviewed_not_compatible() -> None:
    c, truth = original()
    report = oracle_eligibility(c, truth)
    pending = [
        x for x in report["case_rows"]
        if x["v2_agent_reference_status"] ==
        "historically_complete_v2_not_yet_adjudicated"
    ]
    assert len(pending) == 55
    assert all(not x["v2_agent_precision_recall_eligible"] for x in pending)


def test_original_89_incomplete_remain_excluded() -> None:
    c, truth = original()
    report = oracle_eligibility(c, truth)
    pending = [
        x for x in report["case_rows"]
        if x["v2_agent_reference_status"] == "historical_agent_reference_incomplete"
    ]
    assert len(pending) == 89
    assert all(not x["v2_agent_negative_universe_certified"] for x in pending)


def test_missing_known_conflict_source_assertion_fails_closed() -> None:
    c, truth = original()
    truth["rw-001"]["assertions"] = [
        row for row in truth["rw-001"]["assertions"]
        if row.get("subject") != "fast"
    ]
    with pytest.raises(ValueError, match="known factory-as-agent"):
        oracle_eligibility(c, truth)


def test_false_reference_complete_flip_does_not_become_v2_truth() -> None:
    c, truth = original()
    truth["rw-001"]["tier_a"]["reference_completeness"]["agent_entities"] = False
    with pytest.raises(ValueError, match="historically complete"):
        oracle_eligibility(c, truth)


def test_added_absent_source_label_changes_negative_universe() -> None:
    c, truth = original()
    row = copy.deepcopy(truth["rw-002"]["assertions"][0])
    row["expected_state"] = "absent"
    truth["rw-002"]["assertions"].append(row)
    with pytest.raises(ValueError, match="source-negative assertion universe"):
        oracle_eligibility(c, truth)


def test_relabeling_review_as_human_does_not_create_independent_oracle() -> None:
    c, truth = original()
    truth["rw-001"]["source_reference"]["human_dual_review"] = True
    report = oracle_eligibility(c, truth)
    assert report["independent_v2_negative_label_complete_cases"] == 0
    assert not report["methodologically_independent_new_v2_oracle"]


def test_no_mutation_of_archived_langgraph_cases() -> None:
    c, truth = original()
    snapshot = copy.deepcopy(truth["rw-175"])
    result = oracle_eligibility(c, truth)
    assert truth["rw-175"] == snapshot
    assert len(result["case_rows"]) == 145
    assert all(r["framework"] != "langgraph" for r in result["case_rows"])
