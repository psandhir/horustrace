from pathlib import Path

from horustrace.adapters.claude_agent_sdk import (
    is_claude_agent_sdk_file,
    scan_python_file,
)
from horustrace.adapters.registry import detect_python_frameworks


def _write(tmp_path: Path, source: str) -> Path:
    path = tmp_path / "agent.py"
    path.write_text(source, encoding="utf-8")
    return path


def test_detects_claude_agent_sdk_without_false_positive(tmp_path: Path) -> None:
    positive = _write(
        tmp_path,
        "from claude_agent_sdk import ClaudeAgentOptions, query\n",
    )
    assert is_claude_agent_sdk_file(positive)
    assert "claude-agent-sdk" in detect_python_frameworks(positive)

    negative = tmp_path / "plain.py"
    negative.write_text("def query():\n    return 'claude_agent_sdk'\n", encoding="utf-8")
    assert not is_claude_agent_sdk_file(negative)


def test_allowed_tools_are_auto_approval_not_authority_allowlist(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
from claude_agent_sdk import ClaudeAgentOptions, query

options = ClaudeAgentOptions(
    tools=["Read", "Bash"],
    allowed_tools=["Read"],
)

async def run():
    async for message in query(prompt="inspect", options=options):
        pass
""",
    )

    graph = scan_python_file(path)
    assert len(graph.agents) == 1
    agent = graph.agents[0]
    tools = {tool.name: tool for tool in agent.tools}

    assert set(tools) == {"Read", "Bash"}
    assert tools["Read"].approval is False
    assert tools["Read"].metadata["approval_basis"] == "allowed_tools"
    assert tools["Bash"].approval is None
    assert agent.metadata["allowed_tools_auto_approve"] == ["Read"]


def test_bare_disallow_removes_tool_but_scoped_rule_preserves_tool(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
from claude_agent_sdk import ClaudeAgentOptions, query

options = ClaudeAgentOptions(
    tools=["Bash", "WebFetch"],
    disallowed_tools=["Bash", "WebFetch(example.com)"],
)

async def run():
    async for message in query(prompt="inspect", options=options):
        pass
""",
    )

    graph = scan_python_file(path)
    agent = graph.agents[0]
    tools = {tool.name: tool for tool in agent.tools}

    assert "Bash" not in tools
    assert "WebFetch" in tools
    assert tools["WebFetch"].metadata["scoped_deny_rules"] == [
        "WebFetch(example.com)"
    ]


def test_sdk_mcp_server_projects_custom_tool_authority(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
import subprocess
from claude_agent_sdk import ClaudeAgentOptions, create_sdk_mcp_server, query, tool

@tool("run_job", "Run a local job", {"name": str})
async def run_job(args):
    subprocess.run(["worker", args["name"]], check=True)
    return {"content": [{"type": "text", "text": "ok"}]}

worker = create_sdk_mcp_server(
    name="worker-server",
    tools=[run_job],
)

options = ClaudeAgentOptions(
    mcp_servers={"worker": worker},
    allowed_tools=["mcp__worker__run_job"],
)

async def run():
    async for message in query(prompt="run it", options=options):
        pass
""",
    )

    graph = scan_python_file(path)
    agent = graph.agents[0]

    assert len(agent.mcp_servers) == 1
    server = agent.mcp_servers[0]
    assert server.name == "worker"
    assert server.transport == "sdk"
    assert server.metadata["in_process"] is True
    assert server.metadata["discovered_tools"] == ["run_job"]
    assert "process.execute" in server.metadata["discovered_tool_capabilities"]
    assert server.metadata["auto_approved_tool_rules"] == ["mcp__worker__run_job"]


def test_agent_definitions_become_delegated_authority(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
from claude_agent_sdk import AgentDefinition, ClaudeAgentOptions, query

options = ClaudeAgentOptions(
    tools=["Read", "Agent"],
    agents={
        "operator": AgentDefinition(
            description="runs operational checks",
            prompt="inspect the service",
            tools=["Read", "Bash"],
            disallowedTools=["Write"],
            permissionMode="default",
        )
    },
)

async def run():
    async for message in query(prompt="inspect", options=options):
        pass
""",
    )

    graph = scan_python_file(path)
    root = next(agent for agent in graph.agents if agent.name == "options")
    child = next(agent for agent in graph.agents if agent.name == "operator")

    assert root.metadata["delegates_to"] == ["operator"]
    delegated = next(tool for tool in root.tools if tool.kind == "delegated_agent")
    assert delegated.metadata["delegate_target"] == "operator"
    assert delegated.metadata["authority_binding"] == "delegation_projection"
    assert "agent.delegate" in delegated.capabilities
    assert {tool.name for tool in child.tools} == {"Read", "Bash"}
    assert child.metadata["permission_mode"] == "default"


def test_security_control_and_completeness_metadata_is_preserved(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
from claude_agent_sdk import ClaudeAgentOptions, HookMatcher, query

async def gate(input_data, tool_use_id, context):
    return {}

options = ClaudeAgentOptions(
    tools=["Bash", "Read"],
    permission_mode="bypassPermissions",
    setting_sources=[],
    strict_mcp_config=True,
    can_use_tool=gate,
    hooks={"PreToolUse": [HookMatcher(matcher="Bash", hooks=[gate])]},
    sandbox={"enabled": True, "allowUnsandboxedCommands": True},
    cwd="/srv/app",
    add_dirs=["/srv/shared"],
)

async def run():
    async for message in query(prompt="inspect", options=options):
        pass
""",
    )

    graph = scan_python_file(path)
    agent = graph.agents[0]
    tools = {tool.name: tool for tool in agent.tools}

    assert agent.metadata["permission_mode"] == "bypassPermissions"
    assert agent.metadata["setting_sources"] == []
    assert agent.metadata["filesystem_settings_disabled"] is True
    assert agent.metadata["strict_mcp_config"] is True
    assert agent.metadata["can_use_tool_fallback_only"] is True
    assert agent.metadata["hook_events"] == ["PreToolUse"]
    assert agent.metadata["sandbox_enabled"] is True
    assert agent.metadata["allow_unsandboxed_commands"] is True
    assert agent.metadata["silent_sandbox_escape_possible"] is True
    assert tools["Bash"].approval is False
    selectors = {resource.selector for resource in tools["Bash"].resources}
    assert selectors == {"/srv/app", "/srv/shared"}
