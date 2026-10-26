"""C02r source-only MCP implementation shadow: owner-identity and hard negatives."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path

from horustrace.mcp_source_implementation_shadow import (
    project_bound_source_mcp_implementations,
)
from horustrace.models import Agent, Graph, MCPServer, SourceLocation, Tool


def _source(
    root: Path, implementation: str, tool_name: str, tool_line: int,
    *, server_name: str = "Calculator", config_name: str = "math",
) -> tuple[MCPServer, Tool]:
    path = (root / implementation).resolve()
    tool = Tool(
        name=tool_name,
        kind="mcp_exposed_tool",
        location=SourceLocation(path, tool_line),
        metadata={"server": "mcp", "binding_state": "bound_via_mcp"},
    )
    server = MCPServer(
        name=config_name, transport="stdio",
        location=SourceLocation(root / "agent.py", 12),
        metadata={
            "repository_resolved": True,
            "binding_origin": "local_stdio_script",
            "implementation_path": str(path),
            "implementation_line": 33,
            "implementation_name": server_name,
            "implementation_source": "FastMCP",
            "discovered_tools": [{
                "name": tool_name,
                "location": {
                    "path": str(path), "line": tool_line, "column": 1,
                },
            }],
        },
    )
    return server, tool


def test_c02r_same_name_servers_are_distinct_by_immutable_source_path(
    tmp_path: Path,
) -> None:
    first, one = _source(tmp_path, "mcp_server_1.py", "add", 37)
    second, two = _source(
        tmp_path, "mcp_server_2.py", "add", 97, config_name="documents",
    )
    g = Graph(agents=[Agent(name="agent_loop", mcp_servers=[first, second])],
              unbound_tools=[one, two])
    before = deepcopy(g)
    out = project_bound_source_mcp_implementations(g, tmp_path)
    assert g == before
    assert out == project_bound_source_mcp_implementations(g, tmp_path)
    implementations = [
        node for node in out["nodes"]
        if node["kind"] == "mcp_source_implementation"
    ]
    assert len(implementations) == 2
    assert {item["name"] for item in implementations} == {"Calculator"}
    assert len({item["id"] for item in implementations}) == 2
    assert {item["location"]["path"] for item in implementations} == {
        "mcp_server_1.py", "mcp_server_2.py",
    }
    assert out["edge_kinds"] == {
        "CONFIG_RESOLVES_TO_SOURCE_IMPLEMENTATION": 2,
        "EXPOSES_TOOL": 2,
    }
    assert not any(edge["kind"] in {"INVOKES", "AGENT_CAN_CALL"}
                   for edge in out["edges"])
    assert all(edge["effective_agent_can_call"] is None
               for edge in out["edges"])
    assert out["effective_authority_verified"] is False
    assert out["certified_precision"] is None
    assert out["production_cutover_authorized"] is False


def test_c02r_tool_exposure_requires_exact_same_file_and_line(
    tmp_path: Path,
) -> None:
    server, tool = _source(tmp_path, "mcp_server_1.py", "add", 37)
    wrong = deepcopy(tool)
    wrong.location = SourceLocation(tmp_path / "mcp_server_2.py", 37)
    graph = Graph(
        agents=[Agent(name="loop", mcp_servers=[server])],
        unbound_tools=[wrong],
    )
    result = project_bound_source_mcp_implementations(graph, tmp_path)
    assert result["edge_kinds"] == {
        "CONFIG_RESOLVES_TO_SOURCE_IMPLEMENTATION": 1,
    }
    assert [x["reason"] for x in result["unresolved"]] == [
        "missing_or_ambiguous_source_tool"
    ]
    assert not any(x["kind"] == "mcp_source_tool" for x in result["nodes"])


def test_c02r_mcp_resource_and_wrong_name_never_promote_tool_edge(
    tmp_path: Path,
) -> None:
    server, tool = _source(tmp_path, "mcp_server_1.py", "add", 37)
    tool.kind = "mcp_exposed_resource"
    result = project_bound_source_mcp_implementations(
        Graph(agents=[Agent(name="loop", mcp_servers=[server])],
              unbound_tools=[tool]), tmp_path,
    )
    assert not any(x["kind"] == "EXPOSES_TOOL" for x in result["edges"])
    assert result["certified_recall"] is None


def test_c02r_ambiguous_source_tools_are_unresolved_not_guessed(
    tmp_path: Path,
) -> None:
    server, tool = _source(tmp_path, "mcp_server_1.py", "add", 37)
    graph = Graph(agents=[Agent(name="loop", mcp_servers=[server])],
                  unbound_tools=[tool, deepcopy(tool)])
    result = project_bound_source_mcp_implementations(graph, tmp_path)
    assert [x["reason"] for x in result["unresolved"]] == [
        "missing_or_ambiguous_source_tool"
    ]
    assert result["edge_kinds"] == {
        "CONFIG_RESOLVES_TO_SOURCE_IMPLEMENTATION": 1
    }


def test_c02r_unresolved_dynamic_server_does_not_produce_source_implementation(
    tmp_path: Path,
) -> None:
    server, tool = _source(tmp_path, "mcp_server_1.py", "add", 37)
    server.metadata["repository_resolved"] = False
    output = project_bound_source_mcp_implementations(
        Graph(agents=[Agent(name="loop", mcp_servers=[server])],
              unbound_tools=[tool]), tmp_path,
    )
    assert output["nodes"] == []
    assert output["edges"] == []
    assert output["runtime_tool_catalogue_verified"] is False


def test_c02r_external_path_never_leaks_into_source_projection(
    tmp_path: Path,
) -> None:
    server, tool = _source(tmp_path, "mcp_server_1.py", "add", 37)
    server.metadata["implementation_path"] = str(tmp_path.parent / "elsewhere.py")
    output = project_bound_source_mcp_implementations(
        Graph(agents=[Agent(name="loop", mcp_servers=[server])],
              unbound_tools=[tool]), tmp_path,
    )
    assert output["nodes"] == []
    assert output["edges"] == []
    assert [x["reason"] for x in output["unresolved"]] == [
        "incomplete_source_implementation"
    ]


def test_c02r_stdio_client_config_not_conflated_with_source_server(
    tmp_path: Path,
) -> None:
    server, tool = _source(tmp_path, "mcp_server_1.py", "add", 37)
    output = project_bound_source_mcp_implementations(
        Graph(agents=[Agent(name="loop", mcp_servers=[server])],
              unbound_tools=[tool]), tmp_path,
    )
    nodes = {x["id"]: x for x in output["nodes"]}
    config_edges = [
        x for x in output["edges"]
        if x["kind"] == "CONFIG_RESOLVES_TO_SOURCE_IMPLEMENTATION"
    ]
    assert len(config_edges) == 1
    edge = config_edges[0]
    assert nodes[edge["source"]]["kind"] == "mcp_client_configuration"
    assert nodes[edge["target"]]["kind"] == "mcp_source_implementation"
    assert nodes[edge["target"]]["effective_authority"] == "unknown"


def test_c02r_no_source_membership_without_runtime_universe_is_not_accuracy(
    tmp_path: Path,
) -> None:
    output = project_bound_source_mcp_implementations(Graph(), tmp_path)
    assert not output["nodes"] and not output["edges"]
    assert output["independent_source_truth_verified"] is False
    assert output["certified_precision"] is None
    assert output["certified_recall"] is None
    assert output["production_cutover_authorized"] is False
