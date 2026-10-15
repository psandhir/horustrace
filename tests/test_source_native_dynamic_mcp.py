"""Wave B02/B03 dynamic MCP evidence: source positives and hard negatives."""
from __future__ import annotations

import json
from pathlib import Path

from horustrace.models import Graph
from horustrace.semantic_shadow import shadow_observation_report
from horustrace.source_native_dynamic_mcp import inspect_dynamic_mcp_registration


def _factory(root: Path, body: str | None = None) -> None:
    content = body if body is not None else (
        "from fastmcp import FastMCP\n"
        "from fastmcp.tools import FunctionTool\n"
        "def build_app(tools):\n"
        "    mcp = FastMCP('records')\n"
        "    for tool in tools:\n"
        "        tool_obj = FunctionTool.from_function(tool)\n"
        "        mcp.add_tool(tool_obj)\n"
        "    return mcp\n"
    )
    (root / "app.py").write_text(content, encoding="utf-8")


def _remote(root: Path, code: str | None = None) -> None:
    (root / "WorkIqToolProvider.cs").write_text(
        code if code is not None else (
            "using ModelContextProtocol.Client;\n"
            "public class Provider {\n"
            "  async Task GetToolsAsync() {\n"
            "    var transport = new HttpClientTransport(new HttpClientTransportOptions());\n"
            "    var client = await McpClient.CreateAsync(transport);\n"
            "    var serverTools = await client.ListToolsAsync();\n"
            "  }\n"
            "}\n"
        ),
        encoding="utf-8",
    )


def test_factory_registration_is_source_observed_but_names_unresolved(
    tmp_path: Path,
) -> None:
    _factory(tmp_path)
    discovery = inspect_dynamic_mcp_registration(tmp_path)
    doc = discovery.as_dict()
    assert doc["schema_version"] == 2
    assert {item["kind"] for item in doc["entities"]} == {
        "mcp_server", "unknown",
    }
    assert len(doc["bindings"]) == 1
    edge = doc["bindings"][0]
    assert edge["kind"] == "contains"
    assert edge["resolution"] == "partial"
    assert edge["metadata"]["catalogue_state"] == "unresolved_dynamic"
    assert edge["metadata"]["agent_callability"] == "not_adjudicated"
    assert any(
        ob["role"] == "dynamic_factory_tool_registration"
        and ob["resolution"] == "unresolved"
        for ob in doc["observations"]
    )
    assert not any(e["kind"] in ("exposes_tool", "agent_can_call")
                   for e in doc["bindings"])
    assert str(tmp_path) not in json.dumps(doc)
    assert not any(e["kind"] == "tool" for e in doc["entities"])


def test_factory_hard_negatives_no_link_without_original_symbols_or_flow(
    tmp_path: Path,
) -> None:
    cases = [
        # Source comment/text alone is not registration.
        "from fastmcp import FastMCP\nfrom fastmcp.tools import FunctionTool\n"
        "'FunctionTool.from_function(tool); mcp.add_tool(tool_obj)'\n",
        # FastMCP constructor is redefined after import.
        "from fastmcp import FastMCP\nfrom fastmcp.tools import FunctionTool\n"
        "FastMCP = lambda *a: None\n"
        "def build_app(tools):\n"
        "    mcp = FastMCP('x')\n"
        "    for tool in tools:\n"
        "        obj = FunctionTool.from_function(tool)\n"
        "        mcp.add_tool(obj)\n"
        "    return mcp\n",
        # Wrong method/symbol should not prove FastMCP tool registration.
        "from fastmcp import FastMCP\nfrom fastmcp.tools import FunctionTool\n"
        "def build_app(tools):\n"
        "    mcp = FastMCP('x')\n"
        "    for tool in tools:\n"
        "        obj = FunctionTool.from_function(tool)\n"
        "        other.add_tool(obj)\n"
        "    return mcp\n",
        # Not source-observable returned server.
        "from fastmcp import FastMCP\nfrom fastmcp.tools import FunctionTool\n"
        "def build_app(tools):\n"
        "    mcp = FastMCP('x')\n"
        "    for tool in tools:\n"
        "        obj = FunctionTool.from_function(tool)\n"
        "        mcp.add_tool(obj)\n"
        "    return other\n",
    ]
    for content in cases:
        _factory(tmp_path, content)
        assert inspect_dynamic_mcp_registration(tmp_path).bindings == []


def test_remote_enumeration_unknown_not_zero_and_no_remote_tool_names(
    tmp_path: Path,
) -> None:
    _remote(tmp_path)
    doc = inspect_dynamic_mcp_registration(tmp_path).as_dict()
    assert len(doc["entities"]) == 2
    assert {item["kind"] for item in doc["entities"]} == {
        "mcp_client", "unknown",
    }
    assert len(doc["bindings"]) == 1
    assert doc["bindings"][0]["kind"] == "dispatches_to"
    assert doc["bindings"][0]["resolution"] == "unresolved"
    assert any(
        item["role"] == "runtime_enumerated_tool_catalogue_unresolved"
        and item["resolution"] == "unresolved"
        for item in doc["observations"]
    )
    assert not any(e["kind"] in ("exposes_tool", "agent_can_call")
                   for e in doc["bindings"])
    assert all(e["kind"] != "tool" for e in doc["entities"])


def test_csharp_comments_or_missing_client_construction_do_not_prove_catalogue(
    tmp_path: Path,
) -> None:
    _remote(
        tmp_path,
        "using ModelContextProtocol.Client;\n"
        "/* var client = await McpClient.CreateAsync(transport); */\n"
        "var transport = new HttpClientTransport(new HttpClientTransportOptions());\n"
        "// var tools = await client.ListToolsAsync();\n",
    )
    assert inspect_dynamic_mcp_registration(tmp_path).entities == []
    _remote(
        tmp_path,
        "using ModelContextProtocol.Client;\n"
        "var transport = new HttpClientTransport(new HttpClientTransportOptions());\n"
        "var tools = await client.ListToolsAsync();\n",
    )
    assert inspect_dynamic_mcp_registration(tmp_path).entities == []


def test_portable_source_paths_and_sidecar_no_graph_mutation(tmp_path: Path) -> None:
    left = tmp_path / "left"
    right = tmp_path / "right"
    left.mkdir()
    right.mkdir()
    for root in (left, right):
        _factory(root)
        _remote(root)
    l = inspect_dynamic_mcp_registration(left).as_dict()
    r = inspect_dynamic_mcp_registration(right).as_dict()
    assert l == r
    assert len(l["bindings"]) == 2
    graph = Graph()
    before = graph.as_dict() if hasattr(graph, "as_dict") else repr(graph)
    output = shadow_observation_report(graph, left)
    assert output["source_native_dynamic"]["bindings"] == l["bindings"]
    assert output["comparison"]["graph_behavior_changed"] is False
    assert (graph.as_dict() if hasattr(graph, "as_dict") else repr(graph)) == before
    assert str(left) not in json.dumps(output)
