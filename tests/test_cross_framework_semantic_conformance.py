from pathlib import Path

import pytest

from horustrace.effective_authority import effective_authority_report
from horustrace.scanner import scan
from horustrace.semantic_contract import validate_graph_semantics


FRAMEWORK_CASES = (
    (
        "google-adk",
        """
import subprocess
from google.adk import Agent

def run_command(command: str):
    return subprocess.run(command, shell=True)

root_agent = Agent(
    name="ops",
    model="gemini-flash-latest",
    tools=[run_command],
)
""",
    ),
    (
        "openai-agents",
        """
import subprocess
from agents import Agent, function_tool

@function_tool
def run_command(command: str):
    return subprocess.run(command, shell=True)

agent = Agent(name="ops", tools=[run_command])
""",
    ),
    (
        "pydantic-ai",
        """
import subprocess
from pydantic_ai import Agent

agent = Agent("openai:gpt-5.2")

@agent.tool
def run_command(command: str):
    return subprocess.run(command, shell=True)
""",
    ),
    (
        "amazon",
        """
import subprocess
from strands import Agent, tool

@tool
def run_command(command: str):
    return subprocess.run(command, shell=True)

agent = Agent(name="ops", tools=[run_command])
""",
    ),
    (
        "anthropic",
        """
from claude_agent_sdk import ClaudeAgentOptions, query

options = ClaudeAgentOptions(tools=["Bash"])

async def run():
    async for message in query(prompt="inspect", options=options):
        pass
""",
    ),
    (
        "microsoft",
        """
import subprocess
from agent_framework import Agent, tool

@tool(approval_mode="never_require")
def run_command(command: str):
    return subprocess.run(command, shell=True)

agent = Agent(client=client, name="ops", tools=[run_command])
""",
    ),
)


@pytest.mark.parametrize(("case_name", "source"), FRAMEWORK_CASES)
def test_process_execution_normalizes_to_same_canonical_authority(
    tmp_path: Path,
    case_name: str,
    source: str,
) -> None:
    (tmp_path / "agent.py").write_text(source, encoding="utf-8")

    graph, _ = scan(tmp_path)

    assert validate_graph_semantics(graph) == [], case_name
    assert graph.agents, case_name

    process_tools = [
        (agent, tool)
        for agent in graph.agents
        for tool in agent.tools
        if "process.execute" in tool.capabilities
    ]
    assert process_tools, case_name

    agent, tool = process_tools[0]
    relationships = effective_authority_report(graph)["relationships"]
    relationship = next(
        item
        for item in relationships
        if item["agent"] == agent.name
        and item["target"] == {"kind": "tool", "name": tool.name}
    )

    assert "process.execute" in relationship["capabilities"], case_name
    assert relationship["target"]["kind"] == "tool", case_name
    assert relationship["source_context"] == "runtime", case_name
    assert relationship["dimensions"]["target"] == "resolved", case_name
    assert relationship["dimensions"]["capabilities"] == "resolved", case_name
    assert "enforcing_tool_control" not in agent.metadata, case_name
