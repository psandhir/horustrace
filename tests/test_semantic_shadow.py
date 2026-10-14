"""Wave B01: passive v2 observations and graph-projection hard negatives."""
from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from horustrace.models import Agent, Graph, MCPServer, Skill, SourceLocation, Tool
from horustrace.semantic_discovery import (
    SemanticDiscovery, SemanticEntity, SemanticEntityKind, SemanticObservation,
    SemanticResolution,
)
from horustrace.semantic_shadow import build_shadow_discovery, shadow_observation_report


def _fixture(root: Path) -> Graph:
    agent_location = SourceLocation(root / "src" / "agent.py", line=12)
    tool_location = SourceLocation(root / "src" / "tools.py", line=5)
    server_location = SourceLocation(root / "src" / "mcp.py", line=17)
    return Graph(
        agents=[
            Agent(
                name="researcher",
                location=agent_location,
                metadata={
                    "instance_key": "src/agent.py:researcher#first",
                    "framework": "pydantic-ai",
                    "private_token": "NO_SECRET_IN_SIDECAR",
                },
                tools=[Tool(name="search", kind="function", location=tool_location)],
                mcp_servers=[MCPServer(
                    name="local_mcp",
                    transport="stdio",
                    command="python",
                    args=["mcp_server.py"],
                    allowed_tools=["execute_system_command"],
                    location=server_location,
                )],
                skills=[Skill(name="research", location=SourceLocation(
                    root / "skills" / "research" / "SKILL.md",
                    line=1,
                ))],
            ),
            Agent(
                name="researcher",
                location=agent_location,
                metadata={
                    "instance_key": "src/agent.py:researcher#second",
                    "framework": "pydantic-ai",
                },
            ),
        ],
        unbound_tools=[Tool(
            name="unrelated", kind="function",
            location=SourceLocation(root / "test_helpers.py", line=4),
        )],
        unbound_mcp_servers=[MCPServer(
            name="local_mcp", transport="stdio",
            location=SourceLocation(root / "tests" / "test_server.py", line=3),
        )],
        unresolved_mcp_references=[MCPServer(
            name="remote_runtime", transport="streamable-http",
            location=SourceLocation(root / "app.py", line=40),
        )],
    )


def test_v2_shadow_has_qualified_instances_and_no_fictional_authority(tmp_path: Path) -> None:
    graph = _fixture(tmp_path)
    before = deepcopy(graph)
    report = shadow_observation_report(graph, tmp_path)

    assert graph == before
    assert report["schema_version"] == 2
    assert report["mode"] == "passive_shadow_from_legacy_graph"
    assert report["source_edge_adjudicated"] is False
    assert report["comparison"]["source_precision"] is None
    assert report["comparison"]["source_recall"] is None
    assert report["comparison"]["legacy_member_links"] == {
        "invokes": 1, "binds_mcp": 1, "uses_skill": 1, "uses_identity": 0,
    }

    agents = [node for node in report["entities"] if node["kind"] == "agent"]
    assert len(agents) == 2
    assert agents[0]["entity_id"] != agents[1]["entity_id"]
    edges = report["bindings"]
    assert {edge["kind"] for edge in edges} == {"invokes", "binds_mcp", "uses_skill"}
    assert len(edges) == 3
    assert all(edge["resolution"] == "partial" for edge in edges)
    assert len({edge["source_id"] for edge in edges}) == 1
    assert len({edge["target_id"] for edge in edges}) == 3
    assert all(edge["source_id"] in {agent["entity_id"] for agent in agents} for edge in edges)
    assert not any(edge["kind"] in ("exposes_tool", "agent_can_call") for edge in edges)

    unresolved = [o for o in report["observations"]
                  if o["role"] == "unresolved_mcp_reference"]
    assert len(unresolved) == 1
    assert unresolved[0]["resolution"] == "unresolved"
    assert any(o["role"] == "unbound_tool_inventory" for o in report["observations"])
    assert any(o["role"] == "unbound_mcp_inventory" for o in report["observations"])
    assert any(o["role"] == "agent_skill_membership_observed" for o in report["observations"])
    text = json.dumps(report, sort_keys=True)
    assert str(tmp_path) not in text
    assert "NO_SECRET_IN_SIDECAR" not in text
    assert "execute_system_command" not in text


def test_v2_shadow_identity_and_observations_are_portable(tmp_path: Path) -> None:
    left = shadow_observation_report(_fixture(tmp_path / "checkout-A"), tmp_path / "checkout-A")
    right = shadow_observation_report(_fixture(tmp_path / "checkout-B"), tmp_path / "checkout-B")
    assert left == right


def test_shadow_discovery_rejects_missing_evidence_endpoint() -> None:
    discovery = SemanticDiscovery(
        entities=[SemanticEntity(
            entity_id="semantic-v1:entity:one", name="agent",
            kind=SemanticEntityKind.AGENT, framework="test",
        )],
        observations=[SemanticObservation(
            observation_id="semantic-v2:observation:one",
            entity_id="semantic-v1:entity:missing",
            role="agent_instance_observed",
            resolution=SemanticResolution.UNRESOLVED,
            parser_id="test", source_key="main.py", reason="missing",
        )],
        schema_version=2,
    )
    with pytest.raises(ValueError, match="observation endpoint does not exist"):
        discovery.validate()


def test_cli_opt_in_shadow_output_does_not_change_scan_result(tmp_path: Path) -> None:
    from horustrace.cli import main

    (tmp_path / "agent.py").write_text(
        "from pydantic_ai import Agent\n"
        "agent = Agent('test:model')\n",
        encoding="utf-8",
    )
    normal = tmp_path / "normal.json"
    shadow_scan = tmp_path / "shadow.json"
    sidecar = tmp_path / "semantic-shadow.json"

    # Output files are ignored by the Python scanner; do not include them
    # in the source sidecar comparison.
    assert main(["scan", str(tmp_path / "agent.py"), "--format", "json",
                 "--output", str(normal)]) == 0
    assert main(["scan", str(tmp_path / "agent.py"), "--format", "json",
                 "--output", str(shadow_scan),
                 "--shadow-observation-output", str(sidecar)]) == 0
    assert json.loads(normal.read_text()) == json.loads(shadow_scan.read_text())
    document = json.loads(sidecar.read_text())
    assert document["schema_version"] == 2
    assert document["runtime_effectiveness"] == "not_verified"
    assert document["comparison"]["graph_behavior_changed"] is False
