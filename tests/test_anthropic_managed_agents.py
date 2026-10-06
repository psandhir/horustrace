from pathlib import Path

from horustrace.adapters.anthropic_managed_agents import (
    is_anthropic_managed_agents_file,
    scan_anthropic_managed_agents_file,
)
from horustrace.effective_authority import effective_authority_report
from horustrace.scanner import scan


def _write(tmp_path: Path, source: str, name: str = "agent.py") -> Path:
    path = tmp_path / name
    path.write_text(source, encoding="utf-8")
    return path


def test_managed_agent_tool_and_mcp_permission_policies(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
from anthropic import Anthropic

client = Anthropic()
agent = client.beta.agents.create(
    name="ops-agent",
    model="claude-opus-5-5",
    tools=[
        {
            "type": "agent_toolset_20260401",
            "default_config": {
                "permission_policy": {"type": "auto"}
            },
            "configs": [
                {
                    "name": "bash",
                    "permission_policy": {"type": "always_ask"},
                },
                {
                    "name": "web_fetch",
                    "permission_policy": {"type": "always_allow"},
                    "allowed_domains": ["status.example.com"],
                },
            ],
        },
        {
            "type": "mcp_toolset",
            "mcp_server_name": "github",
            "default_config": {
                "permission_policy": {"type": "always_ask"}
            },
        },
    ],
    mcp_servers=[
        {
            "type": "url",
            "name": "github",
            "url": "https://mcp.example.com/github",
        }
    ],
)
""",
    )

    assert is_anthropic_managed_agents_file(path)
    graph = scan_anthropic_managed_agents_file(path)
    agent = graph.agents[0]

    assert agent.name == "ops-agent"
    bash = next(item for item in agent.tools if item.name == "bash")
    web = next(item for item in agent.tools if item.name == "web_fetch")
    server = next(item for item in agent.mcp_servers if item.name == "github")

    assert bash.approval is True
    assert bash.metadata["execution_boundary"] == "managed-sandbox"
    assert "process.execute" in bash.capabilities

    assert web.approval is False
    assert web.metadata["allowed_domains"] == ["status.example.com"]
    assert web.destinations[0].target == "https://status.example.com"

    assert server.approval is True
    assert server.url == "https://mcp.example.com/github"


def test_managed_agent_multiagent_skills_environment_and_vault(tmp_path: Path) -> None:
    _write(
        tmp_path,
        """
from anthropic import Anthropic

client = Anthropic()

agent = client.beta.agents.create(
    name="research-coordinator",
    model={"id": "claude-opus-5-5", "effort": "high"},
    skills=[
        {"type": "custom", "skill_id": "skill_sec_review", "version": "3"}
    ],
    multiagent={
        "type": "coordinator",
        "agents": [
            {"type": "agent", "id": "agent_search", "version": 4},
            {"type": "advisor", "model": "claude-sonnet-5"},
        ],
    },
    tools=[
        {"type": "agent_toolset_20260401"},
        {
            "type": "mcp_toolset",
            "mcp_server_name": "partner",
            "default_config": {
                "permission_policy": {"type": "always_ask"}
            },
        },
    ],
    mcp_servers=[
        {
            "type": "url",
            "name": "partner",
            "url": "https://mcp.partner.example/api",
        }
    ],
)

environment = client.beta.environments.create(
    name="restricted",
    config={
        "type": "cloud",
        "networking": {
            "type": "limited",
            "allowed_hosts": ["api.internal.example"],
            "allow_mcp_servers": True,
            "allow_package_managers": False,
        },
    },
)

session = client.beta.sessions.create(
    agent=agent.id,
    environment_id=environment.id,
    vault_ids=["vault_partner"],
)
""",
        "managed.py",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "research-coordinator")

    assert agent.metadata["skills"] == ["skill_sec_review"]
    assert set(agent.metadata["delegates_to"]) == {"agent_search", "claude-sonnet-5"}
    delegated = [item for item in agent.tools if item.kind == "delegated_agent"]
    assert len(delegated) == 2
    assert "agent.delegate" in agent.capabilities

    assert agent.metadata["environment_type"] == "cloud"
    assert agent.metadata["networking_type"] == "limited"
    assert agent.metadata["allowed_hosts"] == ["api.internal.example"]
    assert agent.metadata["allow_mcp_servers"] is True
    assert agent.metadata["allow_package_managers"] is False
    assert agent.metadata["vault_ids"] == ["vault_partner"]

    partner = next(item for item in agent.mcp_servers if item.name == "partner")
    assert partner.approval is True
    assert partner.metadata["session_scoped_auth"] is True
    assert partner.metadata["vault_ids_available"] == ["vault_partner"]


def test_managed_agent_preserves_dynamic_allowed_hosts_and_mcp_endpoint(
    tmp_path: Path,
) -> None:
    path = _write(
        tmp_path,
        """
import os
from anthropic import Anthropic

DASHCLAW_URL = os.environ.get("DASHCLAW_URL", "http://localhost:3000")
client = Anthropic()

agent = client.beta.agents.create(
    name="governed",
    model="claude-sonnet-4-6",
    tools=[{"type": "agent_toolset_20260401"}],
    mcp_servers=[
        {
            "type": "url",
            "url": f"{DASHCLAW_URL}/api/mcp",
            "name": "dashclaw",
        }
    ],
)
environment = client.beta.environments.create(
    name="restricted",
    config={
        "type": "cloud",
        "networking": {
            "type": "limited",
            "allowed_hosts": [
                DASHCLAW_URL.replace("http://", "").replace("https://", "")
            ],
            "allow_mcp_servers": True,
        },
    },
)
session = client.beta.sessions.create(
    agent=agent.id,
    environment_id=environment.id,
)
""",
    )

    graph = scan_anthropic_managed_agents_file(path)
    agent = next(item for item in graph.agents if item.name == "governed")

    assert agent.metadata["environment_type"] == "cloud"
    assert agent.metadata["networking_type"] == "limited"
    assert agent.metadata["allowed_hosts"] == ["<configured-host:DASHCLAW_URL>"]
    assert agent.metadata["allowed_hosts_dynamic"] is True
    assert agent.metadata["allowed_host_sources"] == ["DASHCLAW_URL"]
    assert agent.metadata["allow_mcp_servers"] is True

    server = next(item for item in agent.mcp_servers if item.name == "dashclaw")
    assert server.metadata["dynamic_mcp_endpoint"] is True
    assert server.metadata["mcp_url_source"] == "DASHCLAW_URL"
    assert "DASHCLAW_URL" in server.metadata["mcp_url_expression"]


def test_managed_agent_awaited_construction_is_discovered(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
from anthropic import AsyncAnthropic

client = AsyncAnthropic()

async def create():
    environment = await client.beta.environments.create(
        name="cloud",
        config={"type": "cloud"},
    )
    agent = await client.beta.agents.create(
        name="awaited-managed-agent",
        model="claude-sonnet-4-6",
        tools=list(load_tools()),
    )
    await start(agent.id, environment.id)
""",
    )

    graph = scan_anthropic_managed_agents_file(path)

    agent = next(item for item in graph.agents if item.name == "awaited-managed-agent")
    assert agent.metadata["managed_runtime"] is True
    assert agent.metadata["model"] == "claude-sonnet-4-6"



def test_managed_agent_dynamic_tools_become_unresolved_authority(
    tmp_path: Path,
) -> None:
    path = _write(
        tmp_path,
        """
from anthropic import AsyncAnthropic

client = AsyncAnthropic()

class Harness:
    def __init__(self, params):
        self.params = params

    async def create(self):
        agent = await client.beta.agents.create(
            name="search-evals-suite",
            model="claude-sonnet-4-6",
            tools=list(self.params.tools),
        )
        return agent
""",
    )

    graph = scan_anthropic_managed_agents_file(path)
    agent = next(item for item in graph.agents if item.name == "search-evals-suite")
    catalogue = next(
        item for item in agent.tools if item.kind == "dynamic_tool_collection"
    )

    assert catalogue.name == "<dynamic-managed-tool-catalogue>"
    assert catalogue.capabilities == set()
    assert catalogue.metadata["dynamic_bound_collection"] is True
    assert catalogue.metadata["tool_catalogue_unresolved"] is True
    assert catalogue.metadata["binding_expression"] == "list(self.params.tools)"
    assert agent.metadata["dynamic_tool_catalogue"] is True

    report = effective_authority_report(graph)
    relationship = next(
        item
        for item in report["relationships"]
        if item["agent"] == "search-evals-suite"
        and item["target"] == {
            "kind": "tool",
            "name": "<dynamic-managed-tool-catalogue>",
        }
    )

    assert relationship["capabilities"] == []
    assert relationship["semantics"]["tool_catalogue_unresolved"] is True
    assert relationship["dimensions"]["tool_scope"] == "unknown"
    assert "tool_catalogue" in relationship["unresolved"]
    assert "capabilities" in relationship["unresolved"]
    assert relationship["core_resolution"] == "partially_resolved"
    assert relationship["core_unresolved"] == ["capabilities"]


def test_managed_agent_literal_toolset_does_not_add_dynamic_catalogue(
    tmp_path: Path,
) -> None:
    path = _write(
        tmp_path,
        """
from anthropic import Anthropic

client = Anthropic()
agent = client.beta.agents.create(
    name="literal-tools",
    model="claude-sonnet-4-6",
    tools=[{"type": "agent_toolset_20260401"}],
)
""",
    )

    graph = scan_anthropic_managed_agents_file(path)
    agent = next(item for item in graph.agents if item.name == "literal-tools")

    assert any(tool.name == "bash" for tool in agent.tools)
    assert not any(
        tool.kind == "dynamic_tool_collection" for tool in agent.tools
    )
    assert "dynamic_tool_catalogue" not in agent.metadata
