"""Scanner stage contracts: no target execution or runtime authority upgrades."""
from pathlib import Path
from types import SimpleNamespace

import pytest

from horustrace.models import Agent, Graph
from horustrace.pipeline_contract import (
    PIPELINE_STAGES,
    PipelineCheckpoints,
    validate_adg_integrity,
)
from horustrace.scanner import scan


def _node(node_id: str) -> SimpleNamespace:
    return SimpleNamespace(node_id=node_id)


def _edge(edge_id: str, source: str, target: str) -> SimpleNamespace:
    return SimpleNamespace(edge_id=edge_id, source=source, target=target)


def test_valid_adg_links_are_accepted() -> None:
    graph = Graph()
    graph.adg = SimpleNamespace(
        nodes=[_node("n1"), _node("n2")],
        edges=[_edge("e1", "n1", "n2")],
    )
    assert validate_adg_integrity(graph) == []


def test_invalid_adg_ids_and_dangling_edges_are_reported() -> None:
    graph = Graph()
    graph.adg = SimpleNamespace(
        nodes=[_node("n1"), _node("n1")],
        edges=[_edge("e1", "n1", "missing"), _edge("e1", "n1", "n1")],
    )
    errors = validate_adg_integrity(graph)
    assert any("duplicate ADG node" in issue for issue in errors)
    assert any("duplicate ADG edge" in issue for issue in errors)
    assert any("missing target" in issue for issue in errors)


def test_pipeline_rejects_out_of_order_checkpoints() -> None:
    pipeline = PipelineCheckpoints()
    with pytest.raises(ValueError, match="out-of-order"):
        pipeline.record("adg", Graph())
    pipeline.record("discovered", Graph())
    with pytest.raises(ValueError, match="out-of-order"):
        pipeline.record("discovered", Graph())
    with pytest.raises(ValueError, match="final finding"):
        for stage in PIPELINE_STAGES[1:-1]:
            pipeline.record(stage, Graph())
        pipeline.record("findings", Graph())


def test_pipeline_records_semantic_violations_without_mutating_security_evidence() -> None:
    graph = Graph(agents=[Agent(name="sample")])
    pipeline = PipelineCheckpoints()
    pipeline.record("discovered", graph)
    graph.agents[0].metadata["enforcing_tool_control"] = True
    pipeline.record("normalized", graph)
    result = pipeline.as_dict()
    assert result["valid"] is False
    assert result["stages"][1]["issues"]
    assert graph.agents[0].metadata["enforcing_tool_control"] is True
    with pytest.raises(ValueError, match="deprecated"):
        pipeline.assert_valid()


def test_scan_emits_complete_pipeline_and_consistent_counts() -> None:
    root = Path(__file__).resolve().parents[1]
    graph, findings = scan(root / "examples" / "secure-agent")
    report = graph.coverage.resolution["analysis_pipeline"]
    assert report["schema_version"] == 1
    assert report["complete"] is True
    assert [stage["stage"] for stage in report["stages"]] == list(PIPELINE_STAGES)
    assert report["stages"][-1]["findings"] == len(findings)
    assert report["stages"][-1]["attack_paths"] == len(graph.attack_paths)
    assert report["stages"][-1]["agents"] == len(graph.agents)
