from pathlib import Path

from horustrace.effective_authority import effective_authority_relationships
from horustrace.scanner import scan


def test_adk_runtime_toolbox_collection_remains_bound_authority(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from google.adk.agents import Agent
from toolbox_core import ToolboxSyncClient

toolbox = ToolboxSyncClient("https://toolbox.example.test")
tools = toolbox.load_toolset("customer_data_tools")
root_agent = Agent(name="claims_assistant", model="gemini-2.5-flash", tools=tools)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "claims_assistant")
    dynamic = next(item for item in agent.tools if item.kind == "dynamic_tool_collection")

    assert dynamic.metadata["dynamic_bound_collection"] is True
    assert dynamic.metadata["catalogue_source"] == "toolbox.load_toolset"
    assert dynamic.metadata["catalogue_name"] == "customer_data_tools"
    assert agent.metadata["dynamic_tools_source_bound"] is True

    relationships = effective_authority_relationships(graph)
    relationship = next(
        item
        for item in relationships
        if item.agent == "claims_assistant" and item.target_name == "tools"
    )
    assert relationship.target_kind == "tool"
    assert relationship.dimensions["target"] == "resolved"
    assert "capabilities" in relationship.unresolved


def test_openai_arcade_collection_remains_bound_authority(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from agents import Agent
from agents_arcade import get_arcade_tools

async def build_agent(client):
    tools = await get_arcade_tools(client, toolkits=["gmail"])
    agent = Agent(name="Email Task Extractor", tools=tools)
    return agent
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "Email Task Extractor")
    dynamic = next(item for item in agent.tools if item.kind == "dynamic_tool_collection")

    assert dynamic.metadata["dynamic_bound_collection"] is True
    assert dynamic.metadata["catalogue_source"] == "get_arcade_tools"
    assert dynamic.metadata["catalogue_name"] == ["gmail"]
    assert agent.metadata["dynamic_tools_source_bound"] is True

    relationship = next(
        item
        for item in effective_authority_relationships(graph)
        if item.agent == "Email Task Extractor" and item.target_name == "tools"
    )
    assert relationship.dimensions["target"] == "resolved"
    assert "capabilities" in relationship.unresolved


def test_pydantic_function_local_mcp_http_server_binds_to_agent(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent
from pydantic_ai.mcp import MCPServerHTTP

async def call_agent(query: str, mcp_server: str):
    server = MCPServerHTTP(url=mcp_server)
    agent = Agent("openai:gpt-4o", mcp_servers=[server])
    return await agent.run(query)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    server = next(item for item in agent.mcp_servers if item.name == "server")

    assert server.transport == "streamable-http"
    assert server.metadata["dynamic_mcp_endpoint"] is True
    assert not any(item.name == "server" for item in graph.unbound_mcp_servers)

    relationship = next(
        item
        for item in effective_authority_relationships(graph)
        if item.agent == "agent"
        and item.target_kind == "mcp_server"
        and item.target_name == "server"
    )
    assert relationship.dimensions["target"] == "resolved"
    assert "tool_scope" in relationship.unresolved
