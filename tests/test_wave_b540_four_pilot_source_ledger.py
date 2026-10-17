"""Fail-closed invariants for the four frozen Wave B #540 source-edge pilots.

This verifies the repository evidence ledger, not live MCP reachability,
credential effectiveness, or independently measured precision/recall.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

LEDGER = (
    Path(__file__).resolve().parents[1]
    / "research/accuracy-wave-b540-four-pilot-20261017/source-edge-ledger.json"
)


def _load() -> dict:
    return json.loads(LEDGER.read_text(encoding="utf-8"))


def _assert_source_anchor(edge: dict) -> None:
    witness = edge["registration_witness"]
    assert witness["path"] and witness["line"] > 0
    assert len(witness["blob_sha"]) == 40


def test_frozen_source_edge_universe_is_explicit() -> None:
    doc = _load()
    assert doc["schema_version"] == 1
    assert set(doc["case_ids"]) == set(doc["cases"])
    assert set(doc["case_ids"]) == {
        "gen-pyd-001",
        "ff60-microsoft-04",
        "gen-mcp-003",
        "ff60-amazon-04",
    }
    assert doc["accuracy"] == {
        "precision": None,
        "recall": None,
        "independent_source_adjudication": False,
        "wave_c_go": False,
    }
    assert doc["decision"] == "SOURCE_MECHANISMS_REVIEWED_RELEASE_NO_GO"


def test_pharmiq_exposure_does_not_prove_callability() -> None:
    case = _load()["cases"]["gen-pyd-001"]
    assert {e["edge"] for e in case["source_edges"]} == {
        "AGENT_BINDS_CLIENT",
        "CLIENT_CONNECTS_TO_SERVER",
    }
    assert len(case["tool_edges"]) == 22
    assert len({e["tool"] for e in case["tool_edges"]}) == 22
    for edge in case["tool_edges"]:
        _assert_source_anchor(edge)
        assert edge["edge"] == "EXPOSES_TOOL"
        assert edge["source_status"] == "source_decorator_registered"
        assert edge["agent_can_call"] == "unresolved"
        assert edge["runtime_effectiveness"] == "not_verified"


def test_microsoft_manifest_is_not_remote_tool_catalogue() -> None:
    case = _load()["cases"]["ff60-microsoft-04"]
    assert {e["server"] for e in case["server_edges"]} == {
        "mcp_MailTools",
        "mcp_CalendarTools",
    }
    assert case["catalogue_state"] == "unresolved_remote"
    assert case["source"].endswith("WorkIqToolProvider.cs")
    for edge in case["server_edges"]:
        assert edge["edge"] == "CLIENT_CONNECTS_TO_SERVER"
        assert edge["source_status"] == "manifest_declared"
        assert edge["runtime_catalogue"] == "unresolved_ListToolsAsync"
        assert edge["runtime_connection"] == "unresolved_token_and_transport"
        assert edge["tool_names"] == []
        assert edge["agent_can_call"] == "unresolved"
        assert len(edge["registration_witness"]["blob_sha"]) == 40


def test_couchbase_each_conditional_registration_has_local_source() -> None:
    case = _load()["cases"]["gen-mcp-003"]
    edges = case["tool_edges"]
    assert len(edges) == 53
    assert len({(e["server"], e["tool"]) for e in edges}) == 53
    assert Counter((e["server"], e["bucket"]) for e in edges) == {
        ("operational", "read_only"): 28,
        ("operational", "write"): 12,
        ("operational_insights", "read_only"): 11,
        ("operational_insights", "write"): 2,
    }
    assert case["source_context"] == "provider_only"
    assert case["inferred_agent_count"] == 0
    for edge in edges:
        _assert_source_anchor(edge)
        assert edge["source_status"] == "conditional_source_candidate"
        assert edge["edge"] == "EXPOSES_TOOL"
        assert edge["import_witness"]["line"] > 0
        assert edge["implementation_target_path"].startswith("src/cb_mcp/tools/")
        assert edge["definition_witness"]["path"] == edge["implementation_target_path"]
        assert edge["definition_witness"]["line"] > 0
        assert len(edge["definition_witness"]["blob_sha"]) == 40
        assert edge["read_only_mode"] == (
            "must_be_false" if edge["bucket"] == "write" else "either"
        )
        assert edge["disabled_tools"] == "unresolved"
        assert edge["auth_scopes"] == "unresolved"
        assert edge["agent_can_call"] == "unresolved"
        assert edge["runtime_effectiveness"] == "not_verified"


def test_amazon_distinct_sources_are_not_live_delegations() -> None:
    case = _load()["cases"]["ff60-amazon-04"]
    sites = case["constructor_sites"]
    assert len(sites) == 10
    assert len({(x["source_witness"]["path"], x["source_witness"]["line"]) for x in sites}) == 10
    assert case["historic_stage_delta"] == {
        "observed_constructors": 10,
        "initial_consolidation_retained": 2,
        "source_distinct_removed": 8,
        "current_constructor_sites": 10,
    }
    for site in sites:
        assert site["source_status"] == "source_visible"
        assert site["edge"] == "SOURCE_AGENT_CONSTRUCTOR"
        assert site["source_witness"]["line"] > 0
        assert len(site["source_witness"]["commit"]) == 40
        assert len(site["source_witness"]["blob_sha"]) == 40
        assert site["live_delegation"] == "unresolved"
        assert site["agent_can_call"] == "unresolved"
        assert site["runtime_instance"] in {
            "conditional_entrypoint",
            "deferred",
            "deferred_unresolved_import",
            "deferred_indirect",
        }
    wrappers = case["orchestrator_tool_membership"]
    assert len(wrappers) == 9
    assert len({w["main_symbol"] for w in wrappers}) == 9
    assert Counter(w["source_status"] for w in wrappers) == {
        "source_visible_decorated_wrapper": 7,
        "unresolved_package_import_mismatch": 1,
        "partial_indirect_constructor_binding": 1,
    }
    unresolved_wrappers = {
        w["main_symbol"]
        for w in wrappers
        if w["source_status"] != "source_visible_decorated_wrapper"
    }
    assert unresolved_wrappers == {"pricing_explorer", "tech_analysis_writer"}
    for wrapper in wrappers:
        assert wrapper["edge"] == "ORCHESTRATOR_TOOL_COMPOSITION_CANDIDATE"
        assert wrapper["source_decorator_line"] > 0
        assert wrapper["source_definition_line"] > wrapper["source_decorator_line"]
        assert len(wrapper["origin_blob_sha"]) == 40
        assert wrapper["runtime_execution"] == "unresolved"
        assert wrapper["agent_can_call"] == "unresolved"

    assert case["package_import_hard_negative"]["imported_callable"] == (
        "compare_regional_pricing"
    )


def test_no_case_claims_runtime_authority_or_independent_truth() -> None:
    doc = _load()
    assert doc["accuracy"]["precision"] is None
    assert doc["accuracy"]["recall"] is None
    for name, case in doc["cases"].items():
        assert len(case["hard_negatives"]) >= 3, name
        for key in ("tool_edges", "server_edges", "constructor_sites"):
            for edge in case.get(key, []):
                assert edge.get("agent_can_call") == "unresolved"
                assert edge.get("runtime_effectiveness") != "verified"
