from pathlib import Path

from horustrace.effective_authority import effective_authority_report
from horustrace.scanner import scan


def test_pydantic_direct_factory_return_agent_is_normalized(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent

def create_agent(model: str, system_prompt: str) -> Agent:
    return Agent(model, system_prompt=system_prompt)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    agent = next(item for item in graph.agents if item.name == "create_agent")
    assert agent.metadata["factory_function"] == "create_agent"
    assert agent.metadata["factory_return"] is True
    assert agent.metadata["binding_origin"] == "direct_factory_return"
    assert str(agent.metadata["instance_key"]).endswith(":create_agent")


def test_openai_function_parameter_mcp_is_bound_unresolved_authority(
    tmp_path: Path,
) -> None:
    (tmp_path / "runner.py").write_text(
        """
from agents import Agent
from agents.mcp import MCPServer

async def run_flow(mcp_server: MCPServer) -> None:
    assistant = Agent(
        name="assistant",
        instructions="Use the supplied MCP tools.",
        mcp_servers=[mcp_server],
    )
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "assistant")

    assert len(agent.mcp_servers) == 1
    server = agent.mcp_servers[0]
    assert server.name == "mcp_server"
    assert server.transport == "unknown"
    assert server.metadata["binding_origin"] == "function_parameter"
    assert server.metadata["source_bound_parameter"] is True
    assert server.metadata["transport_unresolved"] is True
    assert server.metadata["tool_catalogue_unresolved"] is True

    report = effective_authority_report(graph)
    relationships = [
        item
        for item in report["relationships"]
        if item["agent"] == "assistant"
        and item["target"]["kind"] == "mcp_server"
        and item["target"]["name"] == "mcp_server"
    ]
    assert len(relationships) == 1
    relationship = relationships[0]
    assert relationship["resolution"] in {"partially_resolved", "unknown"}
    assert relationship["tool_scope"]["scope"] == "unknown"
