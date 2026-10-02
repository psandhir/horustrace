from pathlib import Path

from horustrace.effective_authority import effective_authority_report
from horustrace.scanner import scan


def test_openai_pure_semantic_name_does_not_create_privileged_effect(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from agents import Agent, function_tool

@function_tool
def create_escalation_summary(text: str) -> str:
    return f"Escalation: {text}"

agent = Agent(name="support", tools=[create_escalation_summary])
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "support")
    tool = next(item for item in agent.tools if item.name == "create_escalation_summary")

    assert "data.write" not in tool.capabilities
    assert "external.write" not in tool.capabilities
    assert "network.external" not in tool.capabilities
    assert set(tool.metadata["suppressed_name_only_capabilities"]) >= {"data.write"}


def test_adk_pure_send_name_does_not_create_external_effect(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from google.adk.agents import Agent

def send_email() -> str:
    return "Subject: hello"

root_agent = Agent(name="assistant", model="gemini-2.5-flash", tools=[send_email])
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "assistant")
    tool = next(item for item in agent.tools if item.name == "send_email")

    assert "external.write" not in tool.capabilities
    assert "network.external" not in tool.capabilities


def test_openai_composed_awaited_tool_collection_preserves_dynamic_and_static_tools(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from agents import Agent, function_tool

async def bl_tools(names):
    return []

@function_tool
def weather(city: str) -> str:
    return city

async def build():
    tools = await bl_tools(["blaxel-search"]) + [weather]
    return Agent(name="assistant", tools=tools)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "assistant")

    assert any(tool.name == "weather" for tool in agent.tools)
    dynamic = [tool for tool in agent.tools if tool.kind == "dynamic_tool_collection"]
    assert len(dynamic) == 1
    assert dynamic[0].metadata["catalogue_source"] == "bl_tools"
    assert dynamic[0].metadata["tool_scope_unresolved"] is True


def test_openai_local_mcp_collection_factory_preserves_unresolved_binding(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from agents import Agent
from agents.mcp import MCPServerStdio

def prepare_mcp_servers(config):
    servers = []
    servers.append(MCPServerStdio(name="filesystem", params=config))
    return servers

def build(config):
    mcp_servers = prepare_mcp_servers(config)
    return Agent(name="assistant", mcp_servers=mcp_servers)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "assistant")

    assert len(agent.mcp_servers) == 1
    server = agent.mcp_servers[0]
    assert server.name == "mcp_servers"
    assert server.metadata["binding_origin"] == "local_mcp_collection_factory"
    assert server.metadata["tool_catalogue_unresolved"] is True

    report = effective_authority_report(graph)
    assert any(
        relationship["agent"] == "assistant"
        and relationship["target"]["kind"] == "mcp_server"
        for relationship in report["relationships"]
    )
