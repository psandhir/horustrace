"""Unbound MCP exposures retain exact test/runtime source roles in the ADG."""
from __future__ import annotations

from pathlib import Path

from horustrace.adg import build_adg
from horustrace.models import Graph, MCPServer, SourceLocation, Tool


def _site(root: Path, path: str, owner: str, name: str):
    source = root / path
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text("# static fixture\n", encoding="utf-8")
    server = MCPServer(
        name=owner, transport="stdio", location=SourceLocation(source, 3),
        metadata={
            "topology_visible_unbound": True,
            "discovery_source": "mcp_python",
            "discovered_tools": [
                {"name": name, "location": {"path": str(source), "line": 11}},
            ],
        },
    )
    tool = Tool(
        name=name, kind="mcp_exposed_tool", location=SourceLocation(source, 11),
        metadata={
            "server": owner, "topology_visible_unbound": True,
            "discovery_source": "mcp_python",
        },
    )
    return server, tool


def test_unbound_source_edges_preserve_test_vs_runtime_roles(
    tmp_path: Path,
) -> None:
    test_server, test_tool = _site(
        tmp_path, "tests/test_daemon_proxy.py", "owner-fixture", "demo_tool"
    )
    production_server, production_tool = _site(
        tmp_path, "linkedin_mcp_server/server.py", "linkedin-production-source",
        "get_profile",
    )
    doc = build_adg(Graph(
        unbound_mcp_servers=[test_server, production_server],
        unbound_tools=[test_tool, production_tool],
    ), tmp_path).as_dict()
    exposures = [e for e in doc["edges"] if e["kind"] == "EXPOSES_TOOL"]
    assert len(exposures) == 2
    assert {e["attributes"]["source_context"] for e in exposures} == {
        "test", "runtime"
    }
    assert {e["attributes"]["server_source_context"] for e in exposures} == {
        "test", "runtime"
    }
    assert all(e["attributes"]["agent_binding"] == "unbound"
               and e["attributes"]["authority_verified"] is False
               and e["attributes"]["deployment_verified"] is False
               for e in exposures)
    node_by_id = {node["id"]: node for node in doc["nodes"]}
    for e in exposures:
        server = node_by_id[e["source"]]
        tool = node_by_id[e["target"]]
        assert server["kind"] == "mcp_server"
        assert server["attributes"]["source_context"] == e["attributes"][
            "server_source_context"
        ]
        assert tool["attributes"]["source_context"] == e["attributes"][
            "source_context"
        ]
        assert server["attributes"]["deployment_verified"] is False
        assert tool["attributes"]["deployment_verified"] is False
    assert not any(e["kind"] == "AGENT_CAN_CALL" for e in doc["edges"])


def test_an_unlinked_mcp_tool_does_not_gain_an_exposes_tool_edge(
    tmp_path: Path,
) -> None:
    server, tool = _site(
        tmp_path, "tests/test_server.py", "test-owner", "registered"
    )
    # A name match without a matching exact decorator definition is not
    # sufficient to materialize an exposure edge.
    tool.location = SourceLocation(tool.location.path, 20)
    doc = build_adg(Graph(
        unbound_mcp_servers=[server], unbound_tools=[tool],
    ), tmp_path).as_dict()
    assert not [e for e in doc["edges"] if e["kind"] == "EXPOSES_TOOL"]


def test_source_runtime_path_is_not_deployment_attestation(
    tmp_path: Path,
) -> None:
    server, tool = _site(
        tmp_path, "linkedin_mcp_server/server.py", "production-source", "search"
    )
    result = build_adg(Graph(
        unbound_mcp_servers=[server], unbound_tools=[tool],
    ), tmp_path).as_dict()
    edges = [e for e in result["edges"] if e["kind"] == "EXPOSES_TOOL"]
    assert len(edges) == 1
    assert edges[0]["attributes"]["source_context"] == "runtime"
    assert edges[0]["attributes"]["authority_verified"] is False
    assert edges[0]["attributes"]["deployment_verified"] is False
