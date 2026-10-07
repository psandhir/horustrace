from pathlib import Path

import pytest

from horustrace.inventory_semantics import data_resource_attributes
from horustrace.scanner import scan
from horustrace.semantic_contract import validate_graph_semantics

FRAMEWORK_DATA_CASES = (
    (
        "google-adk",
        "agent.py",
        """
from google.adk import Agent
from google.adk.tools.bigquery import BigQueryToolset

bq = BigQueryToolset(dataset="analytics")
root_agent = Agent(name="analyst", model="gemini-2.5-pro", tools=[bq])
""",
        "analytics",
        "database",
        "google-cloud",
    ),
    (
        "openai-agents",
        "agent.py",
        """
from agents import Agent, FileSearchTool

search = FileSearchTool(vector_store_ids=["vs_orders"])
agent = Agent(name="research", tools=[search])
""",
        "vs_orders",
        "vector_store",
        "openai",
    ),
    (
        "pydantic-ai",
        "agent.py",
        """
from pydantic_ai import Agent
from pydantic_ai.capabilities import LocalWorkspace
from pydantic_ai_harness import FileSystem

agent = Agent(
    "openai:gpt-5",
    capabilities=[
        LocalWorkspace("/workspace"),
        FileSystem(),
    ],
)
""",
        "/workspace",
        "filesystem",
        "local",
    ),
    (
        "amazon-strands",
        "agent.py",
        """
from strands import Agent, tool

@tool
def read_manual() -> str:
    return "s3://order-docs/manuals/"

agent = Agent(name="docs", tools=[read_manual])
""",
        "s3://order-docs/manuals/",
        "object_store",
        "aws",
    ),
    (
        "claude-agent-sdk",
        "agent.py",
        """
from claude_agent_sdk import ClaudeAgentOptions, query

options = ClaudeAgentOptions(
    model="sonnet",
    tools=["Read"],
    cwd="/srv/app",
)

async def run():
    async for message in query(prompt="inspect", options=options):
        pass
""",
        "/srv/app",
        "filesystem",
        "unknown",
    ),
    (
        "microsoft-agent-framework-python",
        "agent.py",
        """
from agent_framework import Agent
from agent_framework.openai import OpenAIResponsesClient

client = OpenAIResponsesClient()
search = client.get_file_search_tool(vector_store_ids=["vs_docs"])
agent = Agent(client=client, name="docs", tools=[search])
""",
        "vs_docs",
        "vector_store",
        "unknown",
    ),
    (
        "microsoft-agent-framework-dotnet",
        "Agent.cs",
        r"""
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

AIAgent agent = chatClient.AsHarnessAgent(new HarnessAgentOptions
{
    Name = "DataAgent",
    DisableWebSearch = true,
    DisableFileMemory = true,
    DisableAgentSkillsProvider = true,
    FileAccessStore = new FileSystemAgentFileStore("working"),
});
""",
        "working",
        "filesystem",
        "unknown",
    ),
)


def _resources(graph):
    return [
        resource
        for agent in graph.agents
        for tool in agent.tools
        for resource in tool.resources
    ]


@pytest.mark.parametrize(
    (
        "case_name",
        "filename",
        "source",
        "selector",
        "connection_type",
        "provider",
    ),
    FRAMEWORK_DATA_CASES,
)
def test_frameworks_emit_canonical_data_resource_provenance(
    tmp_path: Path,
    case_name: str,
    filename: str,
    source: str,
    selector: str,
    connection_type: str,
    provider: str,
) -> None:
    (tmp_path / filename).write_text(source, encoding="utf-8")

    graph, _ = scan(tmp_path)

    assert validate_graph_semantics(graph) == [], case_name
    resource = next(
        item
        for item in _resources(graph)
        if item.selector == selector
    )

    assert resource.metadata["data_connection_type"] == connection_type, case_name
    assert resource.metadata["data_connection_resolution"] == "resolved", case_name
    assert resource.metadata["selector_provenance"], case_name
    assert resource.metadata["resource_provenance"], case_name
    assert resource.metadata["data_source_reference"], case_name

    attributes = data_resource_attributes(resource)
    assert attributes["connection_type"] == connection_type, case_name
    assert attributes["scope_resolution"] == "resolved", case_name
    assert attributes["provider"] == provider, case_name

    data_nodes = [
        node
        for node in graph.adg.nodes
        if node.kind == "data_resource"
        and node.attributes.get("selector") == selector
    ]
    assert data_nodes, case_name
    assert data_nodes[0].attributes["connection_type"] == connection_type, case_name
    assert (
        data_nodes[0].attributes["data_connection_resolution"] == "resolved"
    ), case_name


def test_openai_dynamic_vector_store_remains_explicitly_unresolved(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from agents import Agent, FileSearchTool

search = FileSearchTool(vector_store_ids=runtime_vector_store_ids)
agent = Agent(name="research", tools=[search])
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    resource = next(
        item
        for item in _resources(graph)
        if item.kind == "vector_store"
    )

    assert resource.selector == "<configured-vector-store>"
    assert resource.metadata["data_connection_type"] == "vector_store"
    assert resource.metadata["data_provider"] == "openai"
    assert resource.metadata["data_connection_resolution"] == "dynamic"


def test_data_contract_does_not_invent_optional_ownership_dimensions(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from claude_agent_sdk import ClaudeAgentOptions, query

options = ClaudeAgentOptions(tools=["Read"], cwd="/srv/app")

async def run():
    async for message in query(prompt="inspect", options=options):
        pass
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    resource = next(item for item in _resources(graph) if item.selector == "/srv/app")
    attributes = data_resource_attributes(resource)

    assert attributes["provider"] == "unknown"
    assert attributes["account"] == "unknown"
    assert attributes["project"] == "unknown"
    assert attributes["tenant"] == "unknown"
