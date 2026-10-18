"""Wave B closeout gate: engineering pilot complete != release certified."""
from __future__ import annotations

import pytest

from scripts.verify_wave_b540_engineering_closeout import (
    VALIDATED_SCANNER_TREE,
    closeout,
)


def _data():
    ledger = {"cases": {
        "gen-pyd-001": {"tool_edges": [{}] * 22},
        "ff60-microsoft-04": {"server_edges": [{}] * 2},
        "gen-mcp-003": {"tool_edges": [{}] * 53},
        "ff60-amazon-04": {
            "constructor_sites": [{}] * 10,
            "orchestrator_tool_membership": [{}] * 9,
        },
    }}
    oracle = {
        "legacy_completeness_v2_disposition": {
            "historical_agent_ontology_incompatible": 1,
            "historical_agent_reference_incomplete": 89,
            "historically_complete_v2_not_yet_adjudicated": 55,
        },
        "independent_v2_negative_label_complete_cases": 0,
        "active_cases": 145,
        "langgraph_active": False,
        "independently_certified_v2_agent_precision": None,
    }
    claims = {
        "total_historical_claims": 73,
        "unresolved": [{} for _ in range(12)],
    }
    ruleset = {
        "enforcement": "active",
        "rules": [{
            "type": "required_status_checks",
            "parameters": {"required_status_checks": [
                {"context": x} for x in (
                    "package", "test (3.11)", "test (3.12)", "self-scan", "analyze"
                )
            ]},
        }],
    }
    return ledger, oracle, claims, ruleset


def _run(ledger=None, oracle=None, claims=None, ruleset=None, sha=None):
    dl, o, c, r = _data()
    return closeout(
        scanner_tree=VALIDATED_SCANNER_TREE if sha is None else sha,
        ledger=dl if ledger is None else ledger,
        oracle=o if oracle is None else oracle,
        claims=c if claims is None else claims,
        ruleset=r if ruleset is None else ruleset,
    )


def test_qualified_pilot_closeout_does_not_certify_security_release():
    report = _run()
    assert report["source_pilot_evidence_work_completed"]
    assert report["engineering_pilot_closeout_supported"]
    assert report["scanner_source_tree_matches_frozen_cohort_validated_head"]
    assert report["security_release_go"] is False
    assert report["wave_c_production_cutover_go"] is False
    assert report["authority_and_path_accuracy_certified"] is False
    assert report["source_accuracy_precision"] is None
    assert report["v2_exhaustive_independent_negative_cases_certified"] == 0
    assert report["historical_unresolved_runtime_claims"] == 12
    assert report["accuracy_required_status_enforced"] is False


def test_scanner_change_requires_new_cohorts():
    with pytest.raises(ValueError, match="scanner has changed"):
        _run(sha="0" * 40)


def test_missing_source_pilot_evidence_is_fatal():
    d, _, _, _ = _data()
    d["cases"]["gen-mcp-003"]["tool_edges"].pop()
    with pytest.raises(ValueError, match="source-positive ledger drift"):
        _run(ledger=d)


def test_dropped_pilot_case_fails_closed():
    d, _, _, _ = _data()
    del d["cases"]["ff60-amazon-04"]
    with pytest.raises(ValueError, match="five-pilot source ledger"):
        _run(ledger=d)


def test_missing_amazon_runtime_unknown_claim_fails_closed():
    _, _, c, _ = _data()
    c["unresolved"].pop()
    with pytest.raises(ValueError, match="twelve external"):
        _run(claims=c)


def test_fake_independent_v2_negative_universe_rejected():
    _, o, _, _ = _data()
    o["independent_v2_negative_label_complete_cases"] = 55
    with pytest.raises(ValueError, match="independent V2 negative"):
        _run(oracle=o)


def test_legacy_incomplete_cannot_be_silently_promoted():
    _, o, _, _ = _data()
    o["legacy_completeness_v2_disposition"][
        "historical_agent_reference_incomplete"
    ] = 0
    with pytest.raises(ValueError, match="independent V2 negative"):
        _run(oracle=o)


def test_required_core_checks_cannot_be_weakened():
    _, _, _, rule = _data()
    rule["rules"][0]["parameters"]["required_status_checks"] = [
        {"context": "package"}
    ]
    with pytest.raises(ValueError, match="were weakened"):
        _run(ruleset=rule)


def test_real_ruleset_accuracy_gate_changes_only_admin_followup():
    _, _, _, rule = _data()
    rule["rules"][0]["parameters"]["required_status_checks"].append(
        {"context": "accuracy-regression-gate"}
    )
    out = _run(ruleset=rule)
    assert out["accuracy_required_status_enforced"] is True
    assert out["admin_followup"] is None
    assert out["security_release_go"] is False
    assert out["wave_c_production_cutover_go"] is False


def test_fabricated_precision_cannot_be_certified():
    _, oracle, _, _ = _data()
    oracle["independently_certified_v2_agent_precision"] = 1.0
    with pytest.raises(ValueError, match="unsupported V2 precision"):
        _run(oracle=oracle)
