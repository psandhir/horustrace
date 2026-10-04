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



def test_client_constructor_in_return_resolves_inline_options_and_typed_mcp(
    tmp_path: Path,
) -> None:
    path = _write(
        tmp_path,
        """
from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient, HookMatcher
from claude_agent_sdk.types import McpStdioServerConfig

async def gate(input_data, tool_use_id, context):
    return {}

def make_client():
    return ClaudeSDKClient(
        options=ClaudeAgentOptions(
            permission_mode="bypassPermissions",
            hooks={"PreToolUse": [HookMatcher(hooks=[gate])]},
            mcp_servers={
                "mongo": McpStdioServerConfig(
                    command="npx",
                    args=["-y", "mongodb-mcp-server@latest"],
                )
            },
        )
    )
""",
    )

    graph = scan_python_file(path)
    roots = [agent for agent in graph.agents if agent.metadata.get("sdk_entrypoint")]
    assert roots
    root = roots[0]
    assert root.metadata["permission_mode"] == "bypassPermissions"
    assert root.metadata["hook_events"] == ["PreToolUse"]
    assert root.mcp_servers[0].name == "mongo"
    assert root.mcp_servers[0].transport == "stdio"
    assert root.mcp_servers[0].command == "npx"


def test_helper_returned_options_bind_to_async_with_client(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient

def build_options():
    return ClaudeAgentOptions(
        allowed_tools=["Read", "Write"],
        permission_mode="acceptEdits",
    )

async def run():
    async with ClaudeSDKClient(options=build_options()) as client:
        await client.query("inspect")
""",
    )

    graph = scan_python_file(path)
    root = next(
        agent
        for agent in graph.agents
        if agent.metadata.get("sdk_entrypoint")
        and agent.metadata.get("permission_mode") == "acceptEdits"
    )
    assert {tool.name for tool in root.tools} >= {"Read", "Write"}
    assert root.metadata["allowed_tools_auto_approve"] == ["Read", "Write"]


def test_attribute_stored_options_and_dynamic_mcp_are_preserved(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
from claude_agent_sdk import ClaudeAgentOptions, query

def build_servers():
    return discover_servers()

class Runner:
    def __init__(self):
        self.servers = build_servers()
        self.options = ClaudeAgentOptions(
            permission_mode="bypassPermissions",
            mcp_servers=self.servers,
        )

    async def run(self):
        async for message in query(prompt="inspect", options=self.options):
            pass
""",
    )

    graph = scan_python_file(path)
    root = next(
        agent
        for agent in graph.agents
        if agent.metadata.get("permission_mode") == "bypassPermissions"
    )
    assert root.metadata["dynamic_mcp_servers"] is True
    assert any(
        server.name == "<dynamic-mcp>"
        and server.metadata["conditional"] is True
        for server in root.mcp_servers
    )


def test_method_returned_options_expand_kwargs_and_preserve_mcp(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient

class Mode:
    def options(self):
        common = {
            "permission_mode": "bypassPermissions",
            "allowed_tools": ["Read"],
        }
        if enabled():
            return ClaudeAgentOptions(
                mcp_servers={"roam": {"command": "roam", "args": ["mcp"]}},
                **common,
            )
        return ClaudeAgentOptions(**common)

mode = Mode()

async def run():
    async with ClaudeSDKClient(options=mode.options()) as client:
        await client.query("inspect")
""",
    )

    graph = scan_python_file(path)
    roots = [
        agent
        for agent in graph.agents
        if agent.metadata.get("sdk_entrypoint")
        and agent.metadata.get("permission_mode") == "bypassPermissions"
    ]
    assert len(roots) >= 2
    assert any(server.name == "roam" for agent in roots for server in agent.mcp_servers)
    assert all(agent.metadata["allowed_tools_auto_approve"] == ["Read"] for agent in roots)


def test_dynamic_subagent_registry_becomes_conditional_delegation(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
from claude_agent_sdk import ClaudeAgentOptions, query

def build_options():
    agents = load_all_agents()
    return ClaudeAgentOptions(
        agents=agents,
        allowed_tools=["Agent"],
    )

async def run():
    async for message in query(prompt="inspect", options=build_options()):
        pass
""",
    )

    graph = scan_python_file(path)
    root = next(agent for agent in graph.agents if agent.metadata.get("dynamic_subagents"))
    delegated = next(tool for tool in root.tools if tool.kind == "delegated_agent")
    assert delegated.name == "<dynamic-subagents>"
    assert delegated.metadata["conditional"] is True
    assert "agent.delegate" in delegated.capabilities


def test_expanded_kwargs_preserve_permission_and_hooks(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
from claude_agent_sdk import ClaudeAgentOptions, HookMatcher, query

options_kwargs = {
    "permission_mode": "bypassPermissions",
    "hooks": {"PreToolUse": [HookMatcher(hooks=[])]},
}
options = ClaudeAgentOptions(**options_kwargs)

async def run():
    async for message in query(prompt="inspect", options=options):
        pass
""",
    )

    graph = scan_python_file(path)
    root = next(agent for agent in graph.agents if agent.name == "options")
    assert root.metadata["permission_mode"] == "bypassPermissions"
    assert root.metadata["hook_events"] == ["PreToolUse"]



def test_unbound_options_builder_preserves_dynamic_security_surface(
    tmp_path: Path,
) -> None:
    path = _write(
        tmp_path,
        """
from claude_agent_sdk import ClaudeAgentOptions, HookMatcher

def build_options():
    agents = load_agents()
    mcp_registry = load_mcp_registry()
    return ClaudeAgentOptions(
        agents=agents,
        mcp_servers=mcp_registry,
        hooks={"PreToolUse": [HookMatcher(hooks=[])]},
    )
""",
    )

    graph = scan_python_file(path)
    root = next(agent for agent in graph.agents if agent.name == "build_options")
    assert root.metadata["option_builder_return"] is True
    assert root.metadata["execution_binding_unresolved"] is True
    assert root.metadata["dynamic_subagents"] is True
    assert root.metadata["dynamic_mcp_servers"] is True
    assert root.metadata["hook_events"] == ["PreToolUse"]
    assert any(tool.kind == "delegated_agent" for tool in root.tools)
    assert any(server.name == "<dynamic-mcp>" for server in root.mcp_servers)
