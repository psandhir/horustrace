"""Source-proven MCP tool exposure never implies agent invocation."""
from pathlib import Path

from horustrace.adg import build_adg
from horustrace.models import Graph, MCPServer, SourceLocation, Tool
from horustrace.scanner import scan


def _graph(tmp_path: Path, *, tool_file: Path | None = None) -> Graph:
    server_file = tmp_path / "server.py"
    server_file.write_text("from mcp.server.fastmcp import FastMCP\n", encoding="utf-8")
    tool_file = tool_file or server_file
    if tool_file != server_file:
        tool_file.write_text("def read(): ...\n", encoding="utf-8")
    location = SourceLocation(path=tool_file, line=7)
    tool = Tool(
        name="read",
        kind="mcp_exposed_tool",
        location=location,
        capabilities={"data.read"},
        metadata={
            "server": "mcp",
            "framework": "mcp",
            "topology_visible_unbound": True,
            "binding_state": "unbound",
            "discovery_source": "mcp_python_tool_decorator",
        },
    )
    server = MCPServer(
        name="Example",
        transport="stdio",
        location=SourceLocation(path=server_file, line=2),
        metadata={
            "alias": "mcp",
            "discovery_source": "mcp_python",
            "framework": "mcp",
            "topology_visible_unbound": True,
            "binding_state": "unbound",
            "discovered_tools": [
                {"name": "read", "location": {
                    "path": str(tool_file), "line": 7, "column": 1,
                }},
            ],
        },
    )
    return Graph(unbound_tools=[tool], unbound_mcp_servers=[server])


def test_source_proven_server_exposes_tool_without_agent_binding(tmp_path: Path) -> None:
    graph = _graph(tmp_path)
    adg = build_adg(graph, tmp_path)
    exposes = [edge for edge in adg.edges if edge.kind == "EXPOSES_TOOL"]
    assert len(exposes) == 1
    nodes = {node.node_id: node for node in adg.nodes}
    assert nodes[exposes[0].source].kind == "mcp_server"
    assert nodes[exposes[0].target].kind == "tool"
    assert exposes[0].attributes["agent_binding"] == "unbound"
    assert exposes[0].attributes["authority_verified"] is False
    assert not [edge for edge in adg.edges if edge.kind == "INVOKES"]
    assert graph.agents == []


def test_mcp_exposure_rejects_mismatched_tool_source_location(tmp_path: Path) -> None:
    wrong_file = tmp_path / "other.py"
    graph = _graph(tmp_path, tool_file=wrong_file)
    graph.unbound_mcp_servers[0].metadata["discovered_tools"][0]["location"]["line"] = 9
    adg = build_adg(graph, tmp_path)
    assert not any(edge.kind == "EXPOSES_TOOL" for edge in adg.edges)


def test_mcp_exposure_rejects_unverified_config_only_tool_names(tmp_path: Path) -> None:
    graph = _graph(tmp_path)
    graph.unbound_mcp_servers[0].metadata["discovery_source"] = "mcp_config"
    adg = build_adg(graph, tmp_path)
    assert not any(edge.kind == "EXPOSES_TOOL" for edge in adg.edges)


def test_scan_exposes_decorated_tool_in_standalone_mcp_repo(tmp_path: Path) -> None:
    target = tmp_path / "server.py"
    target.write_text(
        """from mcp.server.fastmcp import FastMCP
mcp = FastMCP("demo")

@mcp.tool()
def read_secret(identifier: str) -> str:
    return identifier
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    assert graph.agents == []
    assert graph.adg is not None
    assert any(edge.kind == "EXPOSES_TOOL" for edge in graph.adg.edges)
