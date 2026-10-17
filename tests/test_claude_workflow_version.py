"""Pinned-source positive and hard-negative Claude Workflow SDK contract fixtures.

The SDK dependency range is source evidence, not proof of installed CLI/runtime.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from horustrace.adapters.claude_agent_sdk import scan_python_file
from horustrace.adapters.claude_agent_sdk_typescript import (
    scan_claude_agent_sdk_typescript_file,
)
from horustrace.adapters.claude_workflow_version import (
    annotate_workflow_tool_availability,
    declared_workflow_support,
)
from horustrace.effective_authority import effective_authority_relationships
from horustrace.models import Agent, Tool

_PYTHON = '''
from claude_agent_sdk import query, ClaudeAgentOptions

options = ClaudeAgentOptions(allowed_tools=["Read"], permission_mode="default")

async def run():
    async for _ in query(prompt="inspect", options=options):
        pass
'''
_TYPESCRIPT = '''
import { query } from "@anthropic-ai/claude-agent-sdk";
const options = { allowedTools: ["Read"], permissionMode: "default" };
async function run() {
  for await (const m of query({prompt: "inspect", options})) {
    console.log(m);
  }
}
'''


@pytest.mark.parametrize(
    ("specifier", "expected"),
    [
        (">=0.1.39,<0.2.0", "unsupported"),  # pinned Anthropic-01
        ("==0.1.80", "unsupported"),
        (">=0.2.90", "supported"),
        (">=0.2.0", "unknown"),
    ],
)
def test_python_declared_workflow_sdk_bounds(
    tmp_path: Path, specifier: str, expected: str
) -> None:
    path = tmp_path / "agent.py"
    path.write_text(_PYTHON, encoding="utf-8")
    (tmp_path / "requirements.txt").write_text(
        f"claude-agent-sdk{specifier}\n", encoding="utf-8"
    )
    assert declared_workflow_support(path, language="python") == expected
    graph = scan_python_file(path)
    agent = next(item for item in graph.agents if item.name == "options")
    workflow = [tool for tool in agent.tools if tool.name == "Workflow"]
    assert agent.metadata["workflow_sdk_version_support"] == expected
    if expected == "unsupported":
        assert not workflow
        assert agent.metadata["workflow_tool_omitted_incompatible_sdk"] is True
        assert not any(
            edge.target_name == "Workflow" for edge in effective_authority_relationships(graph)
        )
        assert "Bash" in {tool.name for tool in agent.tools}  # no broad permission filter
    else:
        assert len(workflow) == 1
        if expected == "unknown":
            assert workflow[0].metadata["workflow_version_unresolved"] is True
            assert any(
                edge.target_name == "Workflow" and edge.core_resolution != "fully_resolved"
                for edge in effective_authority_relationships(graph)
            )


def test_python_pyproject_only_sdk_range_is_respected(tmp_path: Path) -> None:
    path = tmp_path / "agent.py"
    path.write_text(_PYTHON, encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "case"\nversion = "1"\n'
        'dependencies = ["claude-agent-sdk>=0.1.39,<0.2.0"]\n',
        encoding="utf-8",
    )
    assert declared_workflow_support(path, language="python") == "unsupported"
    assert "Workflow" not in {tool.name for a in scan_python_file(path).agents for tool in a.tools}


@pytest.mark.parametrize(
    ("specifier", "expected"),
    [
        ("^0.1.80", "unsupported"),
        ("~0.1.80", "unsupported"),
        ("^0.2.80", "unknown"),
        ("~0.2.80", "unknown"),
        ("^0.2.90", "supported"),
        ("~0.2.90", "supported"),
        ("^0.3.246", "supported"),  # pinned ff60-anthropic-06
        ("~0.3.246", "supported"),
        (">=0.2.90", "supported"),
        (">=0.2.0", "unknown"),
        ("latest", "unknown"),
    ],
)
def test_typescript_declared_workflow_sdk_bounds(
    tmp_path: Path, specifier: str, expected: str
) -> None:
    path = tmp_path / "agent.ts"
    path.write_text(_TYPESCRIPT, encoding="utf-8")
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"@anthropic-ai/claude-agent-sdk": specifier}}),
        encoding="utf-8",
    )
    assert declared_workflow_support(path, language="typescript") == expected
    graph = scan_claude_agent_sdk_typescript_file(path)
    agent = next(item for item in graph.agents if item.name == "options")
    tools = {tool.name: tool for tool in agent.tools}
    assert agent.metadata["workflow_sdk_version_support"] == expected
    assert ("Workflow" in tools) == (expected != "unsupported")
    assert "Bash" in tools
    if expected == "unknown":
        assert tools["Workflow"].metadata["tool_catalogue_unresolved"] is True


def test_unpinned_workflow_is_unresolved_not_absent(tmp_path: Path) -> None:
    path = tmp_path / "agent.py"
    path.write_text(_PYTHON, encoding="utf-8")
    graph = scan_python_file(path)
    agent = next(a for a in graph.agents if a.name == "options")
    tool = next(tool for tool in agent.tools if tool.name == "Workflow")
    assert agent.metadata["workflow_sdk_version_support"] == "unknown"
    assert tool.metadata["workflow_version_unresolved"] is True
    assert "Workflow" in {edge.target_name for edge in effective_authority_relationships(graph)}


def test_incompatible_sdk_does_not_erase_custom_workflow_tool(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "claude-agent-sdk>=0.1.39,<0.2.0\n", encoding="utf-8"
    )
    path = tmp_path / "agent.py"
    agent = Agent(name="agent", tools=[
        Tool(name="Workflow", kind="function", capabilities={"data.read"}),
        Tool(name="Workflow", kind="dynamic_workflow", capabilities={"agent.delegate"}),
    ])
    annotate_workflow_tool_availability([agent], path, language="python")
    assert [(tool.name, tool.kind) for tool in agent.tools] == [("Workflow", "function")]
    assert agent.metadata["workflow_tool_omitted_incompatible_sdk"] is True
