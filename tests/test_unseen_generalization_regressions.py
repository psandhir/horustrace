import json
from pathlib import Path

from horustrace.scanner import scan


def test_mcp_authorization_header_with_env_interpolation_is_not_literal_secret(
    tmp_path: Path,
) -> None:
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "greptile": {
                        "url": "https://api.greptile.com/mcp",
                        "headers": {
                            "Authorization": "Bearer ${GREPTILE_API_KEY}",
                        },
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    server = graph.all_mcp_servers()[0]

    assert server.metadata["literal_credential_sources"] == []
    assert not any(finding.rule_id == "AGT051" for finding in findings)


def test_openai_hosted_search_and_image_tools_preserve_provider_destination(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from agents import Agent, ImageGenerationTool, WebSearchTool

agent = Agent(
    name="Research",
    tools=[WebSearchTool(), ImageGenerationTool()],
)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "Research")

    hosted = {
        tool.metadata.get("hosted_tool"): tool
        for tool in agent.tools
        if tool.metadata.get("hosted_tool")
    }
    for name in ("WebSearchTool", "ImageGenerationTool"):
        destinations = hosted[name].destinations
        assert len(destinations) == 1
        assert destinations[0].restricted is True
        assert destinations[0].metadata["network_scope"] == "fixed_provider_network"
        assert destinations[0].metadata["provider"] == "openai"

    assert not any(
        finding.rule_id == "NET002" and finding.agent == "Research"
        for finding in findings
    )


def test_langgraph_workflow_projection_is_not_effective_authority_and_interrupt_is_preserved(
    tmp_path: Path,
) -> None:
    (tmp_path / "graph.py").write_text(
        """
from langgraph.graph import StateGraph

def assistant(state):
    return llm.invoke(state["messages"])

def sensitive(state):
    current = state.get("value")
    save(current)
    return state

builder = StateGraph(dict)
builder.add_node("assistant", assistant)
builder.add_node("sensitive", sensitive)
builder.add_edge("assistant", "sensitive")
graph = builder.compile(interrupt_before=["sensitive"])
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    workflow = next(
        agent
        for agent in graph.agents
        if agent.metadata.get("framework") == "langgraph"
    )
    sensitive = next(tool for tool in workflow.tools if tool.name == "sensitive")

    assert sensitive.metadata["authority_binding"] == "workflow_projection"
    assert sensitive.approval is True
    assert sensitive.guardrails is True
    assert sensitive.metadata["approval_mechanism"] == "langgraph_interrupt_before"
    assert sensitive.metadata["approval_mandatory"] is True
    assert not any(
        finding.agent == workflow.name
        and finding.rule_id in {"AGT020", "AGT021", "AGT022", "AGT040", "CAP004", "CAP005", "NET002"}
        for finding in findings
    )


def test_pydantic_restricted_eval_is_not_host_process_authority(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
import math
from pydantic_ai import Agent, RunContext

agent = Agent("openai:gpt-5.2")

@agent.tool
def calculate(ctx: RunContext[None], expression: str) -> str:
    allowed_names = {"sqrt": math.sqrt, "pi": math.pi}
    result = eval(expression, {"__builtins__": {}}, allowed_names)
    return str(result)

@agent.tool
async def web_search(ctx: RunContext[None], query: str) -> str:
    return await client.get("https://api.example.test/search", params={"q": query})
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    calculate = next(tool for tool in agent.tools if tool.name == "calculate")

    assert "process.execute" in calculate.capabilities
    assert calculate.metadata["process_execution_constrained"] is True
    assert calculate.metadata["host_process_execution"] is False
    assert not any(finding.rule_id == "AGT020" for finding in findings)
    assert not any(finding.rule_id == "CAP004" for finding in findings)
    assert any(
        finding.rule_id == "AGT040" and finding.agent == "agent"
        for finding in findings
    )


def test_mcp_execute_named_provider_operation_does_not_imply_host_process(
    tmp_path: Path,
) -> None:
    (tmp_path / "server.py").write_text(
        """
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Provider API")

@mcp.tool()
def execute_batch(batch_id: str):
    return provider.execute_batch(batch_id)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    tool = next(item for item in graph.unbound_tools if item.name == "execute_batch")

    assert "process.execute" not in tool.capabilities
