"""Wave C01a shadow reconciliation contracts and hard negatives."""
from __future__ import annotations

import json
from pathlib import Path

from horustrace.models import Agent, Graph, MCPServer, Skill, SourceLocation, Tool
from horustrace.semantic_discovery import (
    SemanticBinding,
    SemanticBindingKind,
    SemanticDiscovery,
    SemanticEntity,
    SemanticEntityKind,
    SemanticResolution,
)
from horustrace.semantic_reconciliation import reconcile_shadow_projection
from horustrace.semantic_shadow import build_shadow_discovery, shadow_observation_report


def _agent(root: Path) -> Agent:
    return Agent(
        name="assistant",
        location=SourceLocation(root / "src" / "agent.py", line=8),
        metadata={"framework": "pydantic-ai", "secret": "NEVER_EXPORT_ME"},
        tools=[Tool(
            name="lookup", kind="function",
            location=SourceLocation(root / "src" / "tools.py", line=21),
        )],
        mcp_servers=[MCPServer(
            name="local",
            transport="stdio",
            location=SourceLocation(root / "src" / "server.py", line=3),
        )],
    )


def test_c01a_reconciliation_is_shadow_only_and_counted(tmp_path: Path) -> None:
    graph = Graph(agents=[_agent(tmp_path)])
    before_agents = list(graph.agents)
    report = reconcile_shadow_projection(
        graph, build_shadow_discovery(graph, tmp_path)
    )
    assert graph.agents == before_agents
    assert report["mode"] == "shadow_diagnostics_no_graph_cutover"
    assert report["source_precision"] is None
    assert report["source_recall"] is None
    assert report["production_projection_authorized"] is False
    assert report["endpoint_type_violations"] == []
    assert report["unsupported_legacy_authority_promotions"] == []
    assert report["legacy_member_reconciliation"]["binds_mcp"] == {
        "legacy_occurrences": 1,
        "distinct_shadow_edges": 1,
        "occurrence_difference_unadjudicated": 0,
    }
    assert {x["kind"] for x in report["typed_edge_lineage"]} == {"binds_mcp"}
    assert "NEVER_EXPORT_ME" not in json.dumps(report)


def test_c01a_duplicate_source_agents_never_merge(tmp_path: Path) -> None:
    graph = Graph(agents=[
        Agent(name="worker", location=SourceLocation(tmp_path / "main.py", line=9)),
        Agent(name="worker", location=SourceLocation(tmp_path / "main.py", line=9)),
    ])
    report = reconcile_shadow_projection(
        graph, build_shadow_discovery(graph, tmp_path)
    )
    assert len(report["same_source_agent_identity_collisions"]) == 1
    collision = report["same_source_agent_identity_collisions"][0]
    assert collision["source_path"] == "main.py"
    assert len(set(collision["entity_ids"])) == 2
    assert len(report["unresolved_entity_ids"]) == 2



def test_c01a_explicit_same_site_instance_keys_are_not_ambiguous(
    tmp_path: Path,
) -> None:
    location = SourceLocation(tmp_path / "src" / "agent.py", line=17)
    graph = Graph(agents=[
        Agent(name="worker", location=location, metadata={
            "instance_key": "worker-instance-a", "framework": "pydantic-ai",
        }),
        Agent(name="worker", location=location, metadata={
            "instance_key": "worker-instance-b", "framework": "pydantic-ai",
        }),
    ])
    report = reconcile_shadow_projection(
        graph, build_shadow_discovery(graph, tmp_path)
    )
    assert report["same_source_agent_identity_collisions"] == []
    assert len(report["same_source_explicit_instance_groups"]) == 1
    group = report["same_source_explicit_instance_groups"][0]
    assert group["status"] == "distinct_explicit_instance_keys"
    assert len(set(group["entity_ids"])) == 2

def test_c01a_exposure_is_not_callable_authority() -> None:
    agent = SemanticEntity(
        "agent", "operator", SemanticEntityKind.AGENT, "custom"
    )
    server = SemanticEntity(
        "server", "remote", SemanticEntityKind.MCP_SERVER, "custom"
    )
    tool = SemanticEntity("tool", "query", SemanticEntityKind.TOOL, "custom")
    exposure = SemanticBinding(
        "exposure", "server", "tool", SemanticBindingKind.EXPOSES_TOOL,
        "source_registers_function", SemanticResolution.PROVEN,
    )
    graph = Graph()
    report = reconcile_shadow_projection(
        graph, SemanticDiscovery(
            entities=[agent, server, tool], bindings=[exposure]
        )
    )
    assert report["endpoint_type_violations"] == []
    assert report["exposes_tool_edges_do_not_imply_agent_can_call"] is True
    assert report["typed_edge_lineage"][0]["kind"] == "exposes_tool"
    assert not any(
        item["kind"] == "agent_can_call"
        for item in report["typed_edge_lineage"]
    )
    assert report["production_projection_authorized"] is False


def test_c01a_invalid_typed_endpoints_are_reported_not_projected() -> None:
    source = SemanticEntity(
        "tool", "caller", SemanticEntityKind.TOOL, "custom"
    )
    target = SemanticEntity(
        "server", "remote", SemanticEntityKind.MCP_SERVER, "custom"
    )
    invalid = SemanticBinding(
        "wrong", "tool", "server", SemanticBindingKind.EXPOSES_TOOL,
        "invalid_mcp_endpoint", SemanticResolution.PARTIAL,
    )
    report = reconcile_shadow_projection(
        Graph(), SemanticDiscovery(entities=[source, target], bindings=[invalid])
    )
    assert report["endpoint_type_violations"] == [{
        "binding_id": "wrong",
        "kind": "exposes_tool",
        "actual": ["tool", "mcp_server"],
        "required": ["mcp_server", "tool"],
    }]
    assert report["production_projection_authorized"] is False


def test_c01a_legacy_proven_call_is_not_accepted_as_truth() -> None:
    agent = SemanticEntity(
        "agent", "caller", SemanticEntityKind.AGENT, "custom"
    )
    tool = SemanticEntity("tool", "sink", SemanticEntityKind.TOOL, "custom")
    call = SemanticBinding(
        "unsafe", "agent", "tool", SemanticBindingKind.AGENT_CAN_CALL,
        "legacy_inference", SemanticResolution.PROVEN,
        metadata={"origin": "legacy_graph_projection_not_independently_adjudicated"},
    )
    report = reconcile_shadow_projection(
        Graph(), SemanticDiscovery(entities=[agent, tool], bindings=[call])
    )
    assert report["unsupported_legacy_authority_promotions"] == ["unsafe"]
    assert report["source_adjudicated"] is False


def test_c01a_cross_context_requires_review_not_claimed_invalid(
    tmp_path: Path,
) -> None:
    graph = Graph(agents=[Agent(
        name="worker",
        location=SourceLocation(tmp_path / "src" / "agent.py", line=5),
        skills=[Skill(
            name="sample",
            location=SourceLocation(
                tmp_path / "tests" / "test_skill.py", line=11,
            ),
        )],
    )])
    report = reconcile_shadow_projection(
        graph, build_shadow_discovery(graph, tmp_path)
    )
    assert len(report["cross_source_context_edges"]) == 1
    assert report["endpoint_type_violations"] == []
    assert report["cross_source_context_edges"][0]["status"] == (
        "needs_source_scope_review_not_invalid_by_default"
    )


def test_c01a_report_is_portable_and_integrated(tmp_path: Path) -> None:
    left_root = tmp_path / "one"
    right_root = tmp_path / "two"
    left = shadow_observation_report(Graph(agents=[_agent(left_root)]), left_root)
    right = shadow_observation_report(Graph(agents=[_agent(right_root)]), right_root)
    assert "reconciliation" in left
    assert left["reconciliation"] == right["reconciliation"]
    assert str(left_root) not in json.dumps(left["reconciliation"])
    assert "NEVER_EXPORT_ME" not in json.dumps(left)
    assert left["comparison"]["graph_behavior_changed"] is False


def test_c01a_member_collision_is_not_labelled_false_negative(
    tmp_path: Path,
) -> None:
    graph = Graph(agents=[Agent(
        name="operator",
        location=SourceLocation(tmp_path / "src" / "app.py", line=1),
        tools=[
            Tool(name="shared", kind="function"),
            Tool(name="shared", kind="function"),
        ],
    )])
    discovery = build_shadow_discovery(graph, tmp_path)
    report = reconcile_shadow_projection(graph, discovery)
    delta = report["legacy_member_reconciliation"]["invokes"]
    assert delta["legacy_occurrences"] == 2
    assert delta["distinct_shadow_edges"] == 1
    assert delta["occurrence_difference_unadjudicated"] == 1
    assert report["source_recall"] is None
