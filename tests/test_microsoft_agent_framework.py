from pathlib import Path

from horustrace.adapters.registry import detect_python_frameworks
from horustrace.scanner import scan


def write(tmp_path: Path, text: str, name: str = "agent.py") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_microsoft_agent_framework_detects_canonical_async_with_agent_and_http_mcp(
    tmp_path: Path,
) -> None:
    source = write(
        tmp_path,
        """
from agent_framework import Agent, MCPStreamableHTTPTool
from agent_framework.openai import OpenAIChatClient

async def main():
    async with Agent(
        client=OpenAIChatClient(),
        name="DocsAgent",
        tools=MCPStreamableHTTPTool(
            name="Microsoft Learn MCP",
            url="https://learn.microsoft.com/api/mcp",
            allowed_tools=["microsoft_docs_search"],
            approval_mode="always_require",
            header_provider=auth_headers,
        ),
    ) as agent:
        await agent.run("help")
""",
    )

    assert "microsoft-agent-framework" in detect_python_frameworks(source)
    graph, _ = scan(tmp_path)

    agent = next(item for item in graph.agents if item.name == "DocsAgent")
    assert agent.metadata["framework"] == "microsoft-agent-framework"
    server = agent.mcp_servers[0]
    assert server.transport == "streamable-http"
    assert server.url == "https://learn.microsoft.com/api/mcp"
    assert server.allowed_tools == ["microsoft_docs_search"]
    assert server.approval is True
    assert server.authenticated is True


def test_microsoft_agent_framework_preserves_tool_decorator_approval_and_source_semantics(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        """
import subprocess
from agent_framework import Agent, tool

@tool(approval_mode="always_require")
def run_command(command: str):
    return subprocess.run(command, shell=True)

@tool(approval_mode="never_require")
def execute(left: int, right: int):
    return left + right

agent = Agent(
    client=client,
    name="ops",
    tools=[run_command, execute],
)
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "ops")
    tools = {tool.name: tool for tool in agent.tools}

    assert tools["run_command"].approval is True
    assert "process.execute" in tools["run_command"].capabilities
    assert tools["execute"].approval is False
    assert "process.execute" not in tools["execute"].capabilities


def test_microsoft_agent_framework_foundry_hosted_mcp_is_bound_to_agent(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        """
from agent_framework import Agent
from agent_framework.foundry import FoundryChatClient

client = FoundryChatClient(credential=credential)
mcp_tool = client.get_mcp_tool(
    name="Microsoft Learn MCP",
    url="https://learn.microsoft.com/api/mcp",
    approval_mode={"never_require_approval": ["microsoft_docs_search"]},
)

async def main():
    async with Agent(client=client, name="DocsAgent", tools=[mcp_tool]) as agent:
        await agent.run("help")
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "DocsAgent")
    server = next(item for item in agent.mcp_servers if item.name == "Microsoft Learn MCP")

    assert server.transport == "hosted"
    assert server.url == "https://learn.microsoft.com/api/mcp"
    assert server.metadata["provider_managed"] is True
    assert server.metadata["hosted_mcp"] is True
    assert server.metadata["conditional_approval"] is True
    assert server.metadata["never_require_approval"] == ["microsoft_docs_search"]


def test_microsoft_agent_framework_per_run_mcp_binding_from_context_manager(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        """
from agent_framework import Agent, MCPStdioTool

async def main():
    async with MCPStdioTool(
        name="calculator",
        command="uvx",
        args=["mcp-server-calculator"],
    ) as mcp_server:
        agent = Agent(client=client, name="math")
        await agent.run("2+2", tools=mcp_server)
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "math")
    server = next(item for item in agent.mcp_servers if item.name == "calculator")

    assert server.transport == "stdio"
    assert server.command == "uvx"
    assert server.args == ["mcp-server-calculator"]
    assert server.metadata["runtime_tool_binding"] is True
    assert agent.metadata["runtime_tool_bindings"] == 1
    assert not any(item.name == "calculator" for item in graph.unbound_mcp_servers)


def test_microsoft_agent_framework_foundry_toolbox_is_authenticated_mcp_boundary(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        """
from agent_framework import Agent
from agent_framework.foundry import FoundryChatClient, FoundryToolbox

toolbox = FoundryToolbox(credential)
agent = Agent(
    client=FoundryChatClient(
        project_endpoint=project_endpoint,
        model=model,
        credential=credential,
    ),
    name="research",
    tools=[toolbox],
)
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "research")
    server = next(item for item in agent.mcp_servers if item.name == "toolbox")

    assert agent.metadata["foundry_backed"] is True
    assert server.transport == "foundry-toolbox"
    assert server.authenticated is True
    assert server.metadata["provider"] == "microsoft-foundry"
    assert server.metadata["network_scope"] == "operator_configured_destination"
    assert not any(tool.name == "toolbox" for tool in agent.tools)


def test_microsoft_agent_framework_provider_tools_preserve_effective_capabilities(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        """
from agent_framework import Agent
from agent_framework.foundry import FoundryChatClient

client = FoundryChatClient(credential=credential)
agent = Agent(
    client=client,
    name="analyst",
    tools=[
        client.get_code_interpreter_tool(),
        client.get_web_search_tool(),
    ],
)
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "analyst")

    assert "process.execute" in agent.capabilities
    assert "data.write" in agent.capabilities
    assert "data.read" in agent.capabilities
    assert "network.external" in agent.capabilities


def test_microsoft_agent_framework_agent_as_tool_projects_child_authority(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        """
import subprocess
from agent_framework import Agent

def run_command(command: str):
    return subprocess.run(command, shell=True)

child = Agent(client=client, name="privileged_child", tools=[run_command])
child_tool = child.as_tool(
    name="privileged_child_tool",
    approval_mode="always_require",
)
parent = Agent(client=client, name="coordinator", tools=[child_tool])
""",
    )

    graph, _ = scan(tmp_path)
    parent = next(item for item in graph.agents if item.name == "coordinator")
    delegated = next(item for item in parent.tools if item.kind == "delegated_agent")

    assert delegated.approval is True
    assert "agent.delegate" in delegated.capabilities
    assert "process.execute" in delegated.capabilities
    assert delegated.metadata["delegated_agent_targets"] == ["privileged_child"]
    assert delegated.metadata["authority_binding"] == "delegation_projection"
    assert delegated.metadata["authority_binding_basis"] == "microsoft_agent_as_tool"


def test_microsoft_agent_framework_operator_configured_mcp_endpoint_is_not_broad_literal(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        """
import os
from agent_framework import Agent, MCPStreamableHTTPTool

mcp = MCPStreamableHTTPTool(
    name="internal",
    url=os.environ["MCP_ENDPOINT"],
)
agent = Agent(client=client, name="ops", tools=[mcp])
""",
    )

    graph, _ = scan(tmp_path)
    server = next(
        item
        for agent in graph.agents
        for item in agent.mcp_servers
        if item.name == "internal"
    )

    assert server.url is None
    assert server.metadata["dynamic_mcp_endpoint_basis"] == "operator_configuration"
    assert server.metadata["network_scope"] == "operator_configured_destination"



def test_microsoft_agent_framework_detects_provider_client_create_agent_return(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        """
from typing import Annotated
from agent_framework import ai_function
from agent_framework.openai import OpenAIResponsesClient

def get_weather(
    location: Annotated[str, "The city and state"],
) -> str:
    return f"sunny in {location}"

def get_weather_detail(
    location: Annotated[str, "The city and state"],
) -> str:
    return f"detailed weather in {location}"

def get_agent():
    return OpenAIResponsesClient().create_agent(
        name="WeatherAgent",
        tools=[get_weather, get_weather_detail],
    )
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "WeatherAgent")

    assert agent.metadata["framework"] == "microsoft-agent-framework"
    assert agent.metadata["agent_type"] == "client.create_agent"
    assert (
        agent.metadata["binding_origin"]
        == "agent_framework_client.create_agent"
    )
    assert "OpenAIResponsesClient" in str(agent.metadata["client"])
    assert {item.name for item in agent.tools} == {
        "get_weather",
        "get_weather_detail",
    }


def test_microsoft_agent_framework_client_create_agent_requires_maf_provenance(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        """
from agent_framework import ai_function

class LocalFactory:
    def create_agent(self, **kwargs):
        return kwargs

factory = LocalFactory()
not_a_maf_agent = factory.create_agent(name="LocalOnly")
""",
    )

    graph, _ = scan(tmp_path)

    assert graph.agents == []
