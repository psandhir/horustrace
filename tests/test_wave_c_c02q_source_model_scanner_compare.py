"""C02q: exact-source current ADG differential never certifies model correctness."""
from __future__ import annotations

import json
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from horustrace.models import Graph
from horustrace.source_truth_llm_judge import adjudicate_pinned_ledger_opinions
from scripts.wave_c_c02q_source_model_scanner_compare import (
    PINS,
    compare_adg_with_model_opinions,
    verify_git_source_witnesses,
    source_mcp_adapter_probe,
)

ROOT = Path(__file__).resolve().parents[1]


def _ref(case: str) -> dict:
    if case == "rw-005":
        return json.loads(
            (ROOT / PINS[case][4]).read_text(encoding="utf-8")
        )
    ledger = (ROOT / PINS[case][3]).read_bytes()
    decisions = json.loads((ROOT / PINS[case][4]).read_text(encoding="utf-8"))
    return adjudicate_pinned_ledger_opinions(ledger, decisions)["reference"]


def _node(node_id: str, kind: str, name: str, path: str,
          line: int, attrs: dict | None = None) -> dict:
    return {
        "id": node_id, "kind": kind, "name": name, "framework": "test",
        "location": {"path": path, "line": line},
        "attributes": attrs or {},
    }


def _edge(edge_id: str, kind: str, source: str, target: str) -> dict:
    return {
        "id": edge_id, "kind": kind, "source": source, "target": target,
        "location": None, "attributes": {},
    }


def test_c02q_rw005_real_model_opinions_map_to_source_native_adg_sites() -> None:
    ref = _ref("rw-005")
    nodes = [
        _node("a_ingest", "agent", "ingestion_agent", "agent.py", 17),
        _node("a_anomaly", "agent", "anomaly_detection_agent", "agent.py", 44),
        _node("a_cause", "agent", "root_cause_agent", "agent.py", 70),
        _node("a_report", "agent", "incident_report_agent", "agent.py", 106),
        _node("a_root", "agent", "data_quality_guardian", "agent.py", 134),
        _node("t_metrics", "tool", "ingestion_agent:list_metrics", "tools.py", 10,
              {"tool_name": "list_metrics"}),
        _node("t_timeseries", "tool", "ingestion_agent:get_metric_timeseries",
              "tools.py", 15, {"tool_name": "get_metric_timeseries"}),
    ]
    edges = [
        _edge("delegate_ingest", "DELEGATES_TO", "a_root", "a_ingest"),
        _edge("delegate_anomaly", "DELEGATES_TO", "a_root", "a_anomaly"),
        _edge("tool_metrics", "INVOKES", "a_ingest", "t_metrics"),
        _edge("tool_timeseries", "INVOKES", "a_ingest", "t_timeseries"),
    ]
    res = compare_adg_with_model_opinions(
        "rw-005", ref, {"nodes": nodes, "edges": edges},
    )
    by_claim = {row["claim_id"]: row for row in res["rows"]}
    assert len(res["rows"]) == 26
    for key in (
        "source_declared_agent:ingestion_constructor",
        "source_declared_agent:anomaly_constructor",
        "source_declared_agent:cause_constructor",
        "source_declared_agent:report_constructor",
        "source_declared_agent:coordinator_constructor",
        "declared_subagent:root_to_ingestion",
        "declared_subagent:root_to_anomaly",
        "declared_direct_tool_listing:ingestion_list_metrics",
        "declared_direct_tool_listing:ingestion_timeseries",
    ):
        assert by_claim[key]["category"] == "candidate_source_declaration_projected"
    assert by_claim["declared_subagent:root_to_report"]["category"] == (
        "candidate_positive_not_projected"
    )
    assert by_claim["source_declared_agent:api_alias_new_constructor"]["category"] == (
        "candidate_negative_not_projected_no_truth_proof"
    )
    assert by_claim["runtime_callability:coordinator_delegation"]["category"] == (
        "source_model_runtime_unknown"
    )
    assert by_claim["declared_runner_reference:api_root"]["category"] == (
        "not_mapped_to_legacy_adg_ontology"
    )
    assert res["model_review_independent"] is False
    assert res["certified_precision"] is None and res["certified_fn"] is None
    assert res["production_cutover_authorized"] is False


def test_c02q_rw005_repeated_agent_alias_becomes_discrepancy_not_trusted_fp() -> None:
    ref = _ref("rw-005")
    adg = {
        "nodes": [
            _node("alias", "agent", "root_agent_alias", "api.py", 51),
        ], "edges": [],
    }
    result = compare_adg_with_model_opinions("rw-005", ref, adg)
    aliased = next(
        r for r in result["rows"]
        if r["claim_id"] == "source_declared_agent:api_alias_new_constructor"
    )
    assert aliased["category"] == "candidate_invalid_projection_for_review"
    assert aliased["independent_source_truth_verified"] is False
    assert result["certified_fp"] is None


def test_c02q_rw005_child_tool_does_not_create_parent_direct_invokes() -> None:
    ref = _ref("rw-005")
    nodes = [
        _node("root", "agent", "root", "agent.py", 134),
        _node("child", "agent", "child", "agent.py", 17),
        _node("metrics", "tool", "child:list_metrics", "tools.py", 8,
              {"tool_name": "list_metrics"}),
    ]
    only_child = [_edge("edge", "INVOKES", "child", "metrics")]
    source = compare_adg_with_model_opinions("rw-005", ref, {
        "nodes": nodes, "edges": only_child,
    })
    claim = "declared_direct_tool_listing:root_list_metrics_inherited_from_child"
    a = next(x for x in source["rows"] if x["claim_id"] == claim)
    assert a["category"] == "candidate_negative_not_projected_no_truth_proof"
    direct_root = compare_adg_with_model_opinions("rw-005", ref, {
        "nodes": nodes, "edges": [_edge("edge", "INVOKES", "root", "metrics")],
    })
    b = next(x for x in direct_root["rows"] if x["claim_id"] == claim)
    assert b["category"] == "candidate_invalid_projection_for_review"
    assert direct_root["runtime_effective_authority_verified"] is False


def test_c02q_rw080_two_same_named_mcp_servers_must_stay_distinct() -> None:
    ref = _ref("rw-080")
    nodes = [
        _node("one", "mcp_server", "Calculator", "mcp_server_1.py", 33),
        _node("two", "mcp_server", "Calculator", "mcp_server_2.py", 28),
        _node("tool", "tool", "add", "mcp_server_1.py", 37),
    ]
    edges = [_edge("expose", "EXPOSES_TOOL", "one", "tool")]
    output = compare_adg_with_model_opinions("rw-080", ref, {
        "nodes": nodes, "edges": edges,
    })
    assert output["adg_mcp_servers"] == 2
    by = {r["claim_id"]: r for r in output["rows"]}
    assert by["source_mcp_server:server1_FastMCP_declaration"]["category"] == (
        "candidate_source_declaration_projected"
    )
    assert by["source_mcp_server:server2_FastMCP_declaration"]["category"] == (
        "candidate_source_declaration_projected"
    )
    assert by["source_edge:server1_declares_mcp_tool_decorator"]["category"] == (
        "candidate_source_declaration_projected"
    )
    assert by["source_edge:server2_declares_mcp_tool_decorator"]["category"] == (
        "candidate_positive_not_projected"
    )
    assert by["runtime_authority:duplicate_tool_name_collision_occurs"][
        "category"
    ] == "source_model_runtime_unknown"
    assert by["source_edge:decorator_guarantees_AGENT_CAN_CALL"]["category"] == (
        "not_mapped_to_legacy_adg_ontology"
    )
    assert output["certified_fp"] is None


def test_c02q_unknown_runtime_remains_unknown_even_with_source_adg_binding() -> None:
    ref = _ref("rw-080")
    nodes = [
        _node("mcp", "mcp_server", "Calculator", "mcp_server_1.py", 33),
        _node("tool", "tool", "add", "mcp_server_1.py", 37),
        _node("agent", "agent", "AgentLoop", "agent.py", 100),
    ]
    edges = [
        _edge("expose", "EXPOSES_TOOL", "mcp", "tool"),
        _edge("call", "INVOKES", "agent", "tool"),
    ]
    report = compare_adg_with_model_opinions("rw-080", ref, {
        "nodes": nodes, "edges": edges,
    })
    assert report["runtime_effective_authority_verified"] is False
    assert report["counts"]["source_model_runtime_unknown"] == 5
    assert report["certified_tp"] is None
    assert report["certified_recall"] is None


@pytest.mark.parametrize("bad", [
    {"nodes": {}, "edges": []},
    {"nodes": [], "edges": {}},
    {"nodes": [
        _node("dup", "agent", "a", "agent.py", 17),
        _node("dup", "agent", "b", "agent.py", 44),
    ], "edges": []},
    {"nodes": [], "edges": [_edge("orphan", "INVOKES", "missing", "missing")]},
])
def test_c02q_incomplete_or_corrupt_scanner_adg_rejected(bad: dict) -> None:
    with pytest.raises(ValueError):
        compare_adg_with_model_opinions("rw-005", _ref("rw-005"), bad)


def test_c02q_unindependent_model_cannot_be_promoted_to_accuracy() -> None:
    reference = _ref("rw-005")
    reference["scopes"][0]["positive_complete"] = True
    with pytest.raises(ValueError, match="provisional model reference"):
        compare_adg_with_model_opinions(
            "rw-005", reference, {"nodes": [], "edges": []},
        )


def test_c02q_missing_checkout_revision_fails_closed(tmp_path: Path) -> None:
    ledger = json.loads((ROOT / PINS["rw-005"][3]).read_text())
    with pytest.raises(subprocess.CalledProcessError):
        verify_git_source_witnesses(
            tmp_path, ledger, expected_commit=PINS["rw-005"][1],
            expected_repo=PINS["rw-005"][0],
        )


def test_c02q_wrong_source_repository_claim_fails_closed(tmp_path: Path) -> None:
    ledger = json.loads((ROOT / PINS["rw-005"][3]).read_text())
    ledger["repository"] = "other/rewritten"
    with pytest.raises(ValueError, match="ledger not bound"):
        verify_git_source_witnesses(
            tmp_path, ledger, expected_commit=PINS["rw-005"][1],
            expected_repo=PINS["rw-005"][0],
        )


def test_c02q_pin_and_source_reference_are_immutable_by_reviewer() -> None:
    for case_id in PINS:
        reference = _ref(case_id)
        original = deepcopy(reference)
        assert len(reference["labels"]) == (26 if case_id == "rw-005" else 28)
        assert all(s["review_method"] == "model_reviewed" for s in reference["scopes"])
        assert all(s["positive_complete"] is False
                   and s["negative_complete"] is False
                   for s in reference["scopes"])
        assert reference == original



def test_c02q_raw_mcp_adapter_probe_finds_source_decorators_without_authority(
    tmp_path: Path,
) -> None:
    from scripts.wave_c_c02q_source_model_scanner_compare import MCP_SERVER_CLAIMS

    for path, line in sorted(set(MCP_SERVER_CLAIMS.values())):
        source = tmp_path / path
        source.write_text(
            "from mcp.server.fastmcp import FastMCP\n"
            + "\n" * (line - 2)
            + 'mcp = FastMCP("Calculator")\n'
            + "@mcp.tool()\n"
            + "def my_tool():\n"
            + "    return 1\n",
            encoding="utf-8",
        )
    data = source_mcp_adapter_probe(tmp_path, Graph(), {"nodes": [], "edges": []})
    assert data["authority_verified"] is False
    assert len(data["source_server_files"]) == 4
    assert all(row["mcp_adapter_detector"] is True
               for row in data["source_server_files"])
    assert all(row["raw_adapter_server_constructor_seen"] is True
               for row in data["source_server_files"])
    assert all(row["raw_adapter_tool_count"] == 1
               for row in data["source_server_files"])
    assert all(row["final_graph_unbound_server_constructor_seen"] is False
               and row["final_adg_exposes_tool_edges"] == 0
               for row in data["source_server_files"])
    assert all(row["effective_agent_can_call"] is None
               and row["runtime_server_connected"] is None
               for row in data["source_server_files"])
