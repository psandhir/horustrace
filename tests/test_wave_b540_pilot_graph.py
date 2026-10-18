"""Five-pilot scanner parity: strict source pins, typed hard negatives, null TP/FP."""
from __future__ import annotations

import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.reconcile_wave_b540_pilot_graph import PINS, source_evidence_report

ROOT = Path(__file__).resolve().parents[1]
LEDGER = json.loads((
    ROOT / "research/accuracy-wave-b540-four-pilot-20261017/source-edge-ledger.json"
).read_text())


def _case(case_id: str, tmp_path: Path, *, source: dict | None = None,
          agent_sources: list[tuple[str, str, int]] | None = None) -> dict:
    repo, sha, root = PINS[case_id]
    agents = []
    for name, path, line in agent_sources or []:
        agents.append(SimpleNamespace(
            name=name, location=SimpleNamespace(path=tmp_path / path, line=line)
        ))
    graph = SimpleNamespace(
        agents=agents, unbound_mcp_servers=[],
        unresolved_mcp_references=[], attack_paths=[]
    )
    shadow = {
        "source_edge_adjudicated": False, "runtime_effectiveness": "not_verified",
        "comparison": {"graph_behavior_changed": False},
        "bindings": [], "inventory_partition": {
            "observations_by_role": {
                "unbound_mcp_inventory": {"test": 121, "runtime": 3}
            },
        },
        "source_native": {"entities": [
            {"name": e["tool"], "kind": "tool"}
            for e in LEDGER["cases"]["gen-pyd-001"]["tool_edges"]
        ]},
        "source_native_toolsets": {"entities": [
            {"name": e["tool"], "kind": "tool"}
            for e in LEDGER["cases"]["gen-mcp-003"]["tool_edges"]
        ]},
        "source_native_strands": {"entities": [
            {"name": e["definition_symbol"], "kind": "tool"}
            for e in LEDGER["cases"]["ff60-amazon-04"][
                "orchestrator_tool_membership"
            ] if e["nested_constructor_link_status"] == (
                "source_visible_deferred_two_hop"
            )
        ]},
    }
    return {
        "case_id": case_id, "repo": repo, "source_sha": sha,
        "application_path": root, "ledger": LEDGER,
        "graph": graph, "shadow": shadow,
        "adg": {"nodes": [], "edges": []},
        "authority": {"relationships": []},
        "findings": [], "repository_root": tmp_path,
    }


@pytest.mark.parametrize("case", list(PINS))
def test_all_five_cases_are_pinned_noncertified(case: str, tmp_path: Path) -> None:
    args = _case(case, tmp_path)
    result = source_evidence_report(**args)
    assert result["case_id"] == case
    assert result["source_precision"] is None
    assert result["source_recall"] is None
    assert result["finding_precision"] is None
    assert result["attack_path_precision"] is None
    assert result["wave_b_go"] is False and result["wave_c_go"] is False
    assert result["runtime_effectiveness_verified"] is False
    assert result["exhaustive_negative_label_universe"] is False
    assert result["scanner"]["potential_attack_paths"] == 0
    assert result["source_native_candidate_missing"] == []


def test_amazon_exact_source_location_and_deferred_identity(tmp_path: Path) -> None:
    args = _case("ff60-amazon-04", tmp_path, agent_sources=[
        ("orchestrator", "src/main.py", 56),
        ("cfn_explorer", "src/agents/cfn_explorer.py", 92),
    ])
    result = source_evidence_report(**args)
    observed = {r["symbol"]: r["legacy_graph_source_sites"]
                for r in result["amazon_constructor_source_diff"]}
    assert observed["orchestrator"] == 1
    assert observed["cfn_explorer"] == 1
    assert all(r["live_delegation"] == "unresolved"
               for r in result["amazon_constructor_source_diff"])
    assert sum(observed.values()) == 2


def test_missing_source_native_tool_is_a_queue_not_automatic_false_negative(
    tmp_path: Path,
) -> None:
    args = _case("gen-pyd-001", tmp_path)
    args["shadow"]["source_native"]["entities"] = []
    result = source_evidence_report(**args)
    assert len(result["source_native_candidate_missing"]) == 22
    assert result["source_recall"] is None


def test_remote_dynamic_catalogue_does_not_prove_zero_tools(
    tmp_path: Path,
) -> None:
    args = _case("ff60-microsoft-04", tmp_path)
    args["ledger"] = copy.deepcopy(LEDGER)
    args["ledger"]["cases"]["ff60-microsoft-04"]["server_edges"][0][
        "tool_names"
    ] = ["imaginary_remote_tool"]
    with pytest.raises(ValueError, match="dynamic ListToolsAsync"):
        source_evidence_report(**args)


def test_provider_only_case_cannot_gain_agent_without_evidence(
    tmp_path: Path,
) -> None:
    args = _case("gen-mcp-003", tmp_path, agent_sources=[
        ("invented", "src/dummy.py", 42)
    ])
    with pytest.raises(ValueError, match="provider-only"):
        source_evidence_report(**args)


def test_shadow_does_not_promote_binding_to_call_authority(
    tmp_path: Path,
) -> None:
    args = _case("gen-pyd-001", tmp_path)
    args["shadow"]["bindings"] = [{"kind": "agent_can_call"}]
    with pytest.raises(ValueError, match="AGENT_CAN_CALL"):
        source_evidence_report(**args)


def test_runtime_authority_claim_without_runtime_evidence_is_rejected(
    tmp_path: Path,
) -> None:
    args = _case("ff60-amazon-04", tmp_path)
    args["authority"]["relationships"] = [{
        "runtime_effectiveness": "verified",
    }]
    with pytest.raises(ValueError, match="executed authority"):
        source_evidence_report(**args)


def test_wrong_pinned_scope_fails_closed(tmp_path: Path) -> None:
    args = _case("ff60-amazon-04", tmp_path)
    args["application_path"] = "."
    with pytest.raises(ValueError, match="scope drift"):
        source_evidence_report(**args)


def test_WAB05_test_server_must_not_be_reported_as_runtime(
    tmp_path: Path,
) -> None:
    args = _case("gen-mcp-001", tmp_path)
    args["shadow"]["inventory_partition"]["observations_by_role"][
        "unbound_mcp_inventory"
    ] = {"test": 120, "runtime": 4}
    with pytest.raises(ValueError, match="WAB-05 source-role"):
        source_evidence_report(**args)


def test_missing_adg_is_a_failure_not_zero_edges(tmp_path: Path) -> None:
    args = _case("gen-pyd-001", tmp_path)
    args["adg"] = {}
    with pytest.raises(ValueError, match="missing ADG"):
        source_evidence_report(**args)


def test_findings_provenance_gaps_are_exposed_not_hidden(
    tmp_path: Path,
) -> None:
    args = _case("gen-pyd-001", tmp_path)
    args["findings"] = [SimpleNamespace(as_dict=lambda: {
        "rule_id": "AGT040", "severity": "high", "source_context": "runtime",
        "assessment": "static_configuration", "location": None,
        "provenance": [], "limitations": ["no runtime evidence"],
    })]
    result = source_evidence_report(**args)
    assert result["incomplete_finding_source_anchors"] == 1
    assert result["incomplete_finding_provenance"] == 1
    assert result["wave_b_go"] is False
