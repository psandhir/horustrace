from pathlib import Path

from horustrace.effective_authority import effective_authority_report
from horustrace.scanner import scan


def test_detects_shell_without_approval(tmp_path: Path) -> None:
    source = tmp_path / "agent.py"
    source.write_text(
        """
from agents import Agent, ShellTool
agent = Agent(name='Ops', tools=[ShellTool()])
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)

    assert len(graph.agents) == 1
    assert any(f.rule_id == "AGT020" for f in findings)


def test_approval_suppresses_shell_rule(tmp_path: Path) -> None:
    source = tmp_path / "agent.py"
    source.write_text(
        """
from agents import Agent, ShellTool
agent = Agent(name='Ops', tools=[ShellTool(needs_approval=True)])
""",
        encoding="utf-8",
    )

    _, findings = scan(tmp_path)
    assert not any(f.rule_id == "AGT020" for f in findings)


def test_resolves_named_tool_list(tmp_path: Path) -> None:
    source = tmp_path / "agent.py"
    source.write_text(
        """
from agents import Agent, ShellTool
shell = ShellTool()
tools = [shell]
agent = Agent(name='Ops', tools=tools)
""",
        encoding="utf-8",
    )
    graph, findings = scan(tmp_path)
    assert graph.agents[0].tools[0].name == "shell"
    assert any(f.rule_id == "AGT020" for f in findings)


def test_apply_patch_is_state_changing(tmp_path: Path) -> None:
    source = tmp_path / "agent.py"
    source.write_text(
        """
from agents import Agent, ApplyPatchTool
agent = Agent(name='Coder', tools=[ApplyPatchTool()])
""",
        encoding="utf-8",
    )
    _, findings = scan(tmp_path)
    assert any(f.rule_id == "AGT022" for f in findings)


def test_openai_mcp_static_tool_filter_is_normalized(tmp_path: Path) -> None:
    source = tmp_path / "agent.py"
    source.write_text(
        """
from agents import Agent
from agents.mcp import MCPServerStreamableHttp, create_static_tool_filter
server = MCPServerStreamableHttp(
    params={"url": "https://mcp.example.com", "headers": {"Authorization": "Bearer x"}},
    tool_filter=create_static_tool_filter(
        allowed_tool_names=["search_messages", "read_thread"],
        blocked_tool_names=["send_message"],
    ),
)
agent = Agent(name="Reader", mcp_servers=[server])
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    server = graph.agents[0].mcp_servers[0]
    assert server.allowed_tools == ["search_messages", "read_thread"]
    assert server.denied_tools == ["send_message"]
    assert not any(f.rule_id == "AGT032" for f in findings)


def test_openai_runtime_clone_binds_mcp_server(tmp_path: Path) -> None:
    source = tmp_path / "agent.py"
    source.write_text(
        """
from agents import Agent, Runner
from agents.mcp import MCPServerStreamableHttp
agent = Agent(name="Starter")
async def run():
    server = MCPServerStreamableHttp(
        params={"url": "https://mcp.example.com", "headers": {"Authorization": "Bearer x"}},
    )
    async with server:
        agent_with_mcp = agent.clone(mcp_servers=[server])
        return await Runner.run(agent_with_mcp, input="hello")
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    assert len(graph.agents) == 1
    assert [server.name for server in graph.agents[0].mcp_servers] == ["server"]
    assert graph.agents[0].metadata["runtime_clone_mcp"] is True
    assert any(f.rule_id == "AGT032" for f in findings)



def test_openai_inline_confirmation_gate_is_modeled(tmp_path: Path) -> None:
    source = tmp_path / "agent.py"
    source.write_text(
        """
from agents import Agent, function_tool

@function_tool
def publish_message(confirmed: bool = False):
    if not confirmed:
        return "preview"
    return send_message("hello")

agent = Agent(name="Publisher", tools=[publish_message])
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    tool = next(t for t in graph.agents[0].tools if t.name == "publish_message")

    assert tool.approval is True
    assert tool.guardrails is True
    assert tool.metadata.get("approval_mechanism") == "inline_confirmation"
    assert tool.metadata.get("approval_scope") == "execution_gate"
    assert graph.adg is not None
    control = next(
        node
        for node in graph.adg.nodes
        if node.kind == "approval_control"
        and node.attributes.get("protects_tool") == "publish_message"
    )
    assert control.attributes["mechanism"] == "inline_confirmation"
    assert control.attributes["scope"] == "execution_gate"
    assert control.attributes["mandatory"] is True
    assert any(
        edge.kind == "GUARDED_BY" and edge.target == control.node_id
        for edge in graph.adg.edges
    )
    assert not any(
        f.rule_id in {"AGT022", "AGT040"} and f.agent == "Publisher"
        for f in findings
    )


def test_openai_confirmation_parameter_without_return_gate_is_not_approval(tmp_path: Path) -> None:
    source = tmp_path / "agent.py"
    source.write_text(
        """
from agents import Agent, function_tool

@function_tool
def publish_message(confirmed: bool = False):
    if not confirmed:
        log_preview()
    return send_message("hello")

agent = Agent(name="Publisher", tools=[publish_message])
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    tool = next(t for t in graph.agents[0].tools if t.name == "publish_message")

    assert tool.approval is not True
    assert tool.metadata.get("approval_mechanism") is None



def test_openai_confirmation_helper_does_not_inherit_publish_authority_from_name(
    tmp_path: Path,
) -> None:
    (tmp_path / "slack_tools.py").write_text(
        """
from agents import function_tool

@function_tool
def confirm_slack_publish(ctx):
    ctx.context.slack_publish_confirmed = True
    return "confirmed"
""",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        """
from agents import Agent
from slack_tools import confirm_slack_publish

agent = Agent(name="Publisher", tools=[confirm_slack_publish])
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    tool = next(t for t in graph.agents[0].tools if t.name == "confirm_slack_publish")

    assert "external.write" not in tool.capabilities
    assert "network.external" not in tool.capabilities
    assert set(tool.metadata["suppressed_name_only_capabilities"]) == {
        "external.write",
        "network.external",
    }
    assert tool.metadata["capability_inference"] == "control_helper_body_corroboration"
    assert not any(
        f.rule_id == "AGT040" and f.agent == "Publisher"
        for f in findings
    )


def test_openai_control_helper_keeps_side_effect_when_body_corroborates_it(
    tmp_path: Path,
) -> None:
    source = tmp_path / "agent.py"
    source.write_text(
        """
from agents import Agent, function_tool

@function_tool
def confirm_and_publish():
    return publish_message("hello")

agent = Agent(name="Publisher", tools=[confirm_and_publish])
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    tool = next(t for t in graph.agents[0].tools if t.name == "confirm_and_publish")

    assert {"external.write", "network.external"} <= tool.capabilities
    assert "suppressed_name_only_capabilities" not in tool.metadata


def test_openai_legacy_server_sse_binds_direct_mcp_agent(tmp_path: Path) -> None:
    source = tmp_path / "agent.py"
    source.write_text(
        """
from agents import Agent, ServerSse

discord_mcp = ServerSse(url="http://localhost:5000")

discord_agent = Agent(
    name="Discord",
    mcp_servers=[discord_mcp],
)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "Discord")

    assert len(agent.mcp_servers) == 1
    server = agent.mcp_servers[0]
    assert server.name == "discord_mcp"
    assert server.transport == "sse"
    assert server.url == "http://localhost:5000"
    assert server.metadata["context_binding"] == "bound"
    assert server.metadata["effective_agent"] == "Discord"


def test_openai_alias_of_imported_fastmcp_server_binds_to_agent(
    tmp_path: Path,
) -> None:
    package = tmp_path / "memory"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "server.py").write_text(
        """
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Memory Graph")

@mcp.tool()
async def create_entities(items):
    return items

@mcp.tool()
async def delete_entities(names):
    return None

@mcp.tool()
async def search_nodes(query):
    return []
""",
        encoding="utf-8",
    )
    (package / "agent.py").write_text(
        """
from agents import Agent
from .server import mcp

memory_mcp = mcp

memory_agent = Agent(
    name="Memory Agent",
    mcp_servers=[memory_mcp],
)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "Memory Agent")

    assert len(agent.mcp_servers) == 1
    server = agent.mcp_servers[0]
    assert server.name == "Memory Graph"
    assert server.metadata["repository_resolved"] is True
    assert server.metadata["import_symbol"] == "mcp"
    assert server.metadata["context_binding"] == "bound"
    assert server.metadata["effective_agent"] == "Memory Agent"
    assert {item["name"] for item in server.metadata["discovered_tools"]} == {
        "create_entities",
        "delete_entities",
        "search_nodes",
    }

    authority = effective_authority_report(graph)
    relationship = next(
        item
        for item in authority["relationships"]
        if item["agent"] == "Memory Agent"
        and item["target"]["kind"] == "mcp_server"
    )
    assert {"mcp.local", "data.read", "data.write", "destructive.write"} <= set(
        relationship["capabilities"]
    )
    assert relationship["tool_scope"]["catalogue_known"] is True
    assert relationship["tool_scope"]["scope"] == "unrestricted_or_unknown"


def test_openai_semantic_tool_verbs_cover_clear_and_notification_actions(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from agents import Agent, function_tool

@function_tool
def clear_history():
    return None

@function_tool
def schedule_a_push_notification():
    return None

@function_tool
def unsubscribe_from_push_notification():
    return None

agent = Agent(
    name="Operations",
    tools=[
        clear_history,
        schedule_a_push_notification,
        unsubscribe_from_push_notification,
    ],
)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "Operations")
    by_name = {tool.name: tool for tool in agent.tools}

    assert "destructive.write" in by_name["clear_history"].capabilities
    assert {"data.write", "external.write", "network.external"} <= (
        by_name["schedule_a_push_notification"].capabilities
    )
    assert {"destructive.write", "external.write", "network.external"} <= (
        by_name["unsubscribe_from_push_notification"].capabilities
    )
    assert any(
        finding.rule_id == "AGT021"
        and finding.agent == "Operations"
        and finding.location
        for finding in findings
    )


def test_openai_imported_mcp_server_reconstructs_agent_auth_and_tool_scope(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        """
import os
from agents.mcp import MCPServerStreamableHttp, create_static_tool_filter

slack_server = MCPServerStreamableHttp(
    params={
        "url": "https://mcp.example.com",
        "headers": {"Authorization": f"Bearer {os.getenv('MCP_TOKEN')}"},
    },
    tool_filter=create_static_tool_filter(
        allowed_tool_names=["search_messages", "read_thread"],
        blocked_tool_names=["send_message"],
    ),
)
""",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        """
from agents import Agent
from server import slack_server

agent = Agent(name="Reader", mcp_servers=[slack_server])
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(a for a in graph.agents if a.name == "Reader")

    assert len(agent.mcp_servers) == 1
    server = agent.mcp_servers[0]
    assert server.metadata["context_binding"] == "bound"
    assert server.metadata["effective_agent"] == "Reader"
    assert server.metadata["authority_scope"] == "explicit_allowlist"
    assert server.metadata["credential_source"] == "env:MCP_TOKEN"
    assert server.identity == "Reader:slack_server:mcp-auth"
    assert server.allowed_tools == ["search_messages", "read_thread"]
    assert server.denied_tools == ["send_message"]
    assert not graph.unbound_mcp_servers

    identity = next(i for i in agent.identities if i.name == server.identity)
    assert identity.credential_source == "env:MCP_TOKEN"

    assert graph.adg is not None
    edge_kinds = {edge.kind for edge in graph.adg.edges}
    assert "USES_IDENTITY" in edge_kinds
    assert "ALLOWS_TOOL" in edge_kinds
    assert "DENIES_TOOL" in edge_kinds
    assert any(node.kind == "mcp_tool_scope" for node in graph.adg.nodes)



def test_function_parameter_tools_do_not_bind_unrelated_sequence(tmp_path: Path) -> None:
    source = tmp_path / "agent.py"
    source.write_text(
        """
from agents import Agent, HostedMCPTool

async def run_agent(tools):
    agent = Agent(name="flight-search-agent", tools=tools)
    return agent

async def main():
    tools = [HostedMCPTool(tool_config={"type": "mcp"})]
    return tools
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    agent = next(item for item in graph.agents if item.name == "flight-search-agent")
    assert agent.tools == []
    assert agent.metadata["dynamic_tools"] is True


def test_module_level_named_tool_sequence_still_binds(tmp_path: Path) -> None:
    source = tmp_path / "agent.py"
    source.write_text(
        """
from agents import Agent, WebSearchTool

search = WebSearchTool()
tools = [search]
agent = Agent(name="search-agent", tools=tools)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    agent = next(item for item in graph.agents if item.name == "search-agent")
    assert [tool.name for tool in agent.tools] == ["search"]


def test_openai_same_runtime_name_keeps_source_scoped_instances(
    tmp_path: Path,
) -> None:
    (tmp_path / "left.py").write_text(
        """
from agents import Agent, WebSearchTool

search_agent = Agent(name="Search", tools=[WebSearchTool()])
""",
        encoding="utf-8",
    )
    (tmp_path / "right.py").write_text(
        """
from agents import Agent, WebSearchTool

search_agent = Agent(name="Search", tools=[WebSearchTool()])
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    searches = [agent for agent in graph.agents if agent.name == "Search"]
    assert len(searches) == 2
    assert len({agent.metadata["instance_key"] for agent in searches}) == 2
    assert {agent.location.path.name for agent in searches if agent.location} == {
        "left.py",
        "right.py",
    }


def test_openai_source_instances_share_logical_manifest_overlay(
    tmp_path: Path,
) -> None:
    for filename in ("left.py", "right.py"):
        (tmp_path / filename).write_text(
            """
from agents import Agent, WebSearchTool

search_agent = Agent(name="Search", tools=[WebSearchTool()])
""",
            encoding="utf-8",
        )
    (tmp_path / "horustrace.manifest.yaml").write_text(
        """
version: 1
agents:
  - name: Search
    policy:
      denied_capabilities: [network.external]
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    searches = [agent for agent in graph.agents if agent.name == "Search"]
    assert len(searches) == 2
    assert all(
        "network.external" in agent.policy.denied_capabilities
        for agent in searches
    )


def test_openai_agent_as_tool_preserves_underlying_source_target(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from agents import Agent
import memory_agents

search_agent = Agent(name="Search")
manager = Agent(
    name="Manager",
    tools=[
        search_agent.as_tool(
            tool_name="web_search",
            tool_description="Search the web",
        ),
        memory_agents.agent.as_tool(
            tool_name="memory_search",
            tool_description="Search memory",
        ),
    ],
)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    manager = next(agent for agent in graph.agents if agent.name == "Manager")
    by_name = {tool.name: tool for tool in manager.tools}

    assert by_name["web_search"].metadata["delegate_target"] == "search_agent"
    assert by_name["web_search"].metadata["binding_origin"] == "agent_as_tool"
    assert by_name["memory_search"].metadata["delegate_target"] == "memory_agents.agent"
    assert by_name["memory_search"].metadata["binding_origin"] == "agent_as_tool"

def test_openai_function_tool_tracks_model_selected_url_through_external_client(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from agents import Agent, function_tool
from gitingest import ingest_async
from tavily import AsyncTavilyClient

client = AsyncTavilyClient(api_key="x")

@function_tool
async def ingest_repo(url: str):
    return await ingest_async(url)

@function_tool
async def crawl_page(url: str):
    return await client.crawl(url=url)

@function_tool
async def scrape_page(url: str):
    return await client.extract(urls=[url])

agent = Agent(
    name="Network Agent",
    tools=[ingest_repo, crawl_page, scrape_page],
)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "Network Agent")

    by_name = {tool.name: tool for tool in agent.tools}
    for name in ("ingest_repo", "crawl_page", "scrape_page"):
        tool = by_name[name]
        assert "network.external" in tool.capabilities
        assert any(
            destination.target == "<dynamic-url>"
            and destination.metadata.get("source") == "model_selected_url_argument"
            for destination in tool.destinations
        )

    assert any(finding.rule_id == "NET001" for finding in findings)
    assert not any(finding.rule_id == "NET002" for finding in findings)


def test_openai_url_parameter_without_external_network_sink_stays_constrained(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from agents import Agent, function_tool

def normalize(value: str) -> str:
    return value.strip()

@function_tool
def format_url(url: str) -> str:
    return normalize(url)

agent = Agent(name="Formatter", tools=[format_url])
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    tool = next(item for item in graph.agents[0].tools if item.name == "format_url")

    assert not tool.destinations
    assert "network.external" not in tool.capabilities
    assert not any(finding.rule_id in {"NET001", "NET002"} for finding in findings)

