from pathlib import Path

from horustrace.effective_authority import effective_authority_relationships
from horustrace.scanner import scan


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_pydantic_expanded_kwargs_preserve_dynamic_authority(tmp_path: Path) -> None:
    _write(
        tmp_path / "agent.py",
        """
import pydantic_ai


def build_agent(tools, active_mcp_servers):
    agent_kwargs = {
        "model": "openai:gpt-5.2",
        "name": "worker",
    }
    if tools:
        agent_kwargs["tools"] = tools
    if active_mcp_servers:
        agent_kwargs["toolsets"] = active_mcp_servers

    agentlet = pydantic_ai.Agent[Any, Any](**agent_kwargs)
    return agentlet
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agentlet")
    dynamic = {item.kind: item for item in agent.tools if item.metadata.get("dynamic_authority")}

    assert "pydantic_dynamic_tools" in dynamic
    assert "pydantic_dynamic_toolsets" in dynamic
    assert all(item.metadata["tool_catalogue_unresolved"] is True for item in dynamic.values())

    relationships = {
        item.target_name: item
        for item in effective_authority_relationships(graph)
        if item.agent == "agentlet"
    }
    assert "dynamic-tools:agentlet" in relationships
    assert relationships["dynamic-tools:agentlet"].resolution == "partially_resolved"


def test_pydantic_dynamic_constructor_arguments_remain_visible(tmp_path: Path) -> None:
    _write(
        tmp_path / "agent.py",
        """
from pydantic_ai import Agent


def build_agent(tools, toolsets, builtin_tools):
    return Agent(
        "openai:gpt-5.2",
        tools=list(tools) if tools else (),
        toolsets=list(toolsets) if toolsets else None,
        builtin_tools=builtin_tools,
    )
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "build_agent")
    dimensions = {
        item.metadata.get("authority_dimension")
        for item in agent.tools
        if item.metadata.get("dynamic_authority")
    }
    assert {"tools", "toolsets", "builtin_tools"} <= dimensions


def test_pydantic_mcp_capability_resolves_named_stdio_transport(tmp_path: Path) -> None:
    _write(
        tmp_path / "agent.py",
        """
from fastmcp.client.transports.stdio import StdioTransport
from pydantic_ai import Agent
from pydantic_ai.capabilities import MCP as MCPCapability

STORAGE = "/tmp/browser.json"
playwright_mcp_args = [
    "run",
    "python",
    "-m",
    "browser_mcp",
    f"--storage-state={STORAGE}",
]
playwright_transport = StdioTransport(
    command="uv",
    args=playwright_mcp_args,
)
playwright_cap = MCPCapability(
    local=playwright_transport,
    id="playwright",
    defer_loading=False,
)

agent = Agent(
    "openai:gpt-5.2",
    capabilities=[playwright_cap],
)
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    server = next(item for item in agent.mcp_servers if item.name == "playwright")

    assert server.transport == "stdio"
    assert server.command == "uv"
    assert server.args == ["run", "python", "-m", "browser_mcp"]
    assert server.metadata["dynamic_args"] is True
    assert server.metadata["partial_transport_configuration"] is True


def test_repository_function_toolset_subclass_preserves_remote_sandbox_authority(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "pkg" / "__init__.py",
        "",
    )
    _write(
        tmp_path / "pkg" / "executor.py",
        """
from daytona import Daytona


def run_python_ephemeral(code: str):
    client = Daytona()
    sandbox = client.create(timeout=120)
    return sandbox.process.code_run(code)


def run_shell_ephemeral(command: str):
    client = Daytona()
    sandbox = client.create(timeout=120)
    return sandbox.process.exec(command)
""",
    )
    _write(
        tmp_path / "pkg" / "tools.py",
        """
from pydantic_ai import FunctionToolset

from .executor import run_python_ephemeral, run_shell_ephemeral


def run_python(code: str):
    return run_python_ephemeral(code)


def run_shell(command: str):
    return run_shell_ephemeral(command)


class DaytonaToolset(FunctionToolset):
    def __init__(self, *, include_shell: bool = True, **kwargs):
        tools = [run_python]
        if include_shell:
            tools.append(run_shell)
        super().__init__(tools, **kwargs)
""",
    )
    _write(
        tmp_path / "pkg" / "agent.py",
        """
from pydantic_ai import Agent

from .tools import DaytonaToolset


agent = Agent(
    "openai:gpt-5.2",
    toolsets=[DaytonaToolset()],
)
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    tools = {item.name: item for item in agent.tools}

    assert {"run_python", "run_shell"} <= set(tools)
    assert not any(item.kind == "pydantic_function_toolset" for item in agent.tools)
    for name in ("run_python", "run_shell"):
        tool = tools[name]
        assert "process.execute" in tool.capabilities
        assert "network.external" in tool.capabilities
        assert tool.metadata["execution_boundary"] == "remote-sandbox"
        assert tool.metadata["sandbox_provider"] == "daytona"
        assert any(
            destination.target == "<provider:daytona>"
            for destination in tool.destinations
        )


def test_repository_imported_agent_run_and_smtp_are_reconstructed(tmp_path: Path) -> None:
    _write(tmp_path / "pkg" / "__init__.py", "")
    _write(
        tmp_path / "pkg" / "child.py",
        """
import requests
from pydantic_ai import Agent

sub_agent = Agent("openai:gpt-5.2")


@sub_agent.tool_plain
def browse(url: str) -> str:
    return requests.get(url, timeout=5).text
""",
    )
    _write(
        tmp_path / "pkg" / "parent.py",
        """
import smtplib
from email.message import EmailMessage

from pydantic_ai import Agent

from .child import sub_agent


main_agent = Agent("openai:gpt-5.2")


@main_agent.tool_plain
async def spawn_sub_agents(prompt: str) -> str:
    result = await sub_agent.run(prompt)
    return result.output


@main_agent.tool_plain
def send_email(to: str, body: str) -> None:
    msg = EmailMessage()
    msg["To"] = to
    msg.set_content(body)
    with smtplib.SMTP("smtp.example.test", 587) as server:
        server.send_message(msg)
""",
    )

    graph, _ = scan(tmp_path)
    main = next(item for item in graph.agents if item.name == "main_agent")
    spawn = next(item for item in main.tools if item.name == "spawn_sub_agents")
    email = next(item for item in main.tools if item.name == "send_email")

    assert "agent.delegate" in spawn.capabilities
    assert spawn.metadata["delegate_target"] == "sub_agent"
    assert (
        spawn.metadata["delegation_basis"]
        == "repository_imported_pydantic_agent_run"
    )
    assert "network.external" in spawn.capabilities

    assert {"network.external", "external.write"} <= email.capabilities
    assert any(
        destination.target == "<operator-configured:smtp>"
        for destination in email.destinations
    )
    assert any(
        evidence.startswith("smtp:")
        for evidence in email.metadata.get("repository_effect_evidence", [])
    )


def test_pydantic_factory_instances_keep_post_construction_tool_bindings(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "agent.py",
        """
import requests
from pydantic_ai import Agent


def _build_agent(custom: bool) -> Agent:
    return Agent(
        "openai:gpt-5.2",
        instructions="custom" if custom else "default",
    )


_agent = _build_agent(False)
_agent_custom = _build_agent(True)


def _scrape_tool(url: str) -> str:
    response = requests.get(
        "https://proxy.example.test/browser",
        params={"url": url},
        timeout=10,
    )
    return response.text


_agent.tool(_scrape_tool)
_agent_custom.tool(_scrape_tool)
""",
    )

    graph, _ = scan(tmp_path)
    agents = {
        item.name: item
        for item in graph.agents
        if item.metadata.get("framework") == "pydantic-ai"
    }

    assert {"_agent", "_agent_custom"} <= set(agents)
    assert "_build_agent" not in agents
    for name in ("_agent", "_agent_custom"):
        agent = agents[name]
        tool = next(item for item in agent.tools if item.name == "_scrape_tool")
        assert "network.external" in tool.capabilities
        assert agent.metadata["factory_function"] == "_build_agent"
        assert agent.metadata["factory_instance"] is True


def test_conditional_pydantic_capability_is_typed_not_dynamic_placeholder(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "agent.py",
        """
from dataclasses import dataclass
from pydantic_ai import Agent
from pydantic_ai.capabilities import WebSearch


@dataclass
class Settings:
    web_search: bool = True


settings = Settings()

agent = Agent(
    "openai:gpt-5.2",
    capabilities=[WebSearch()] if settings.web_search else [],
)
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    web_search = next(item for item in agent.tools if item.name == "WebSearch")

    assert web_search.kind == "web_search"
    assert web_search.metadata["availability"] == "conditional"
    assert web_search.metadata["availability_condition"] == "settings.web_search"
    assert not any(
        item.kind == "pydantic_dynamic_capabilities"
        for item in agent.tools
    )
