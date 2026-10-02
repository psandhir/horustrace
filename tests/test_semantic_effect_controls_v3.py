import ast
from pathlib import Path

from horustrace.adapters.pydantic_ai import _function_capabilities
from horustrace.scanner import scan


def test_adk_post_query_transport_is_not_external_write(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
import requests
from google.adk.agents import Agent

def search_corpus(query: str):
    response = requests.post(
        "https://discoveryengine.googleapis.com/v1/projects/demo/locations/global/search",
        json={"query": query},
    )
    return response.json()

root_agent = Agent(name="search-agent", tools=[search_corpus])
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "search-agent")
    tool = next(item for item in agent.tools if item.name == "search_corpus")

    assert "network.external" in tool.capabilities
    assert "external.write" not in tool.capabilities
    assert "data.write" not in tool.capabilities
    assert not any(
        finding.rule_id in {"ADK001", "AGT040"}
        and finding.agent == "search-agent"
        for finding in findings
    )


def test_pydantic_dotted_update_is_body_write_evidence() -> None:
    tree = ast.parse(
        """
async def update_graph(ctx, node_id, value):
    await ctx.deps.gate.arequire("graph:update", node_id)
    ctx.deps.graph.update(node_id, value)
"""
    )
    function = tree.body[0]
    assert isinstance(function, ast.AsyncFunctionDef)
    assert "data.write" in _function_capabilities(function)


def test_pydantic_mandatory_authorization_gate_counts_as_control(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent, RunContext

agent = Agent("openai:gpt-4o")

@agent.tool
async def update_graph(ctx: RunContext[object], node_id: str, value: str) -> str:
    await ctx.deps.gate.arequire("graph:update", node_id)
    ctx.deps.graph.update(node_id, value)
    return "updated"
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    tool = next(item for item in agent.tools if item.name == "update_graph")

    assert "data.write" in tool.capabilities
    assert tool.guardrails is True
    assert tool.approval is not True
    assert tool.metadata["authorization_gate"] is True
    assert tool.metadata["guardrail_mechanism"] == "mandatory_authorization_gate"
    assert not any(
        finding.rule_id in {"AGT022", "AGT040"}
        and finding.agent == "agent"
        for finding in findings
    )


def test_openai_add_function_is_pure_without_body_side_effect(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from agents import Agent, function_tool

@function_tool
def add(a: int, b: int) -> int:
    return a + b

agent = Agent(name="calculator", tools=[add])
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "calculator")
    tool = next(item for item in agent.tools if item.name == "add")

    assert "data.write" not in tool.capabilities
    assert "destructive.write" not in tool.capabilities
    assert "external.write" not in tool.capabilities
    assert "data.write" in tool.metadata["suppressed_name_only_capabilities"]
    assert not any(
        finding.rule_id in {"AGT022", "AGT040", "CAP005"}
        and finding.agent == "calculator"
        for finding in findings
    )


def test_pydantic_add_function_is_pure_without_body_side_effect(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent

agent = Agent("openai:gpt-4o")

@agent.tool_plain
def add(a: int, b: int) -> int:
    return a + b
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    tool = next(item for item in agent.tools if item.name == "add")

    assert "data.write" not in tool.capabilities
    assert "destructive.write" not in tool.capabilities
    assert not any(
        finding.rule_id in {"AGT022", "AGT040", "CAP005"}
        and finding.agent == "agent"
        for finding in findings
    )
