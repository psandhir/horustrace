from pathlib import Path

from horustrace.scanner import scan


def test_openai_native_mcp_binding_reconstructs_authority(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
import os
from agents import Agent
from agents.mcp import MCPServerStreamableHttp, create_static_tool_filter

slack = MCPServerStreamableHttp(
    params={
        "url": "https://mcp.example.test/mcp",
        "headers": {"Authorization": f"Bearer {os.getenv('MCP_TOKEN')}"},
    },
    tool_filter=create_static_tool_filter(
        allowed_tool_names=["search_messages", "read_thread"],
        blocked_tool_names=["send_message"],
    ),
)
agent = Agent(name="agent", mcp_servers=[slack])
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    agent = next(item for item in graph.agents if item.name == "agent")
    assert [server.name for server in agent.mcp_servers] == ["slack"]

    server = agent.mcp_servers[0]
    assert server.metadata["effective_agent"] == "agent"
    assert server.metadata["auth_mechanism"] == "authorization-header"
    assert server.metadata["credential_source"] == "env:MCP_TOKEN"
    assert server.allowed_tools == ["search_messages", "read_thread"]
    assert server.denied_tools == ["send_message"]
    assert server.authenticated is True
    assert not any(item.name == "slack" for item in graph.unbound_mcp_servers)

    adg = graph.adg.as_dict()
    edge_kinds = {edge["kind"] for edge in adg["edges"]}
    assert "INVOKES" in edge_kinds
    assert "CONNECTS_TO" in edge_kinds
    assert "ALLOWS_TOOL" in edge_kinds
    assert "DENIES_TOOL" in edge_kinds

def test_filesystem_mcp_resource_authority_is_projected(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from agents import Agent
from agents.mcp import MCPServerStdio

filesystem = MCPServerStdio(
    params={
        "command": "npx",
        "args": [
            "-y",
            "@modelcontextprotocol/server-filesystem",
            "/srv/customer-data",
        ],
    }
)
agent = Agent(name="agent", mcp_servers=[filesystem])
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    agent = next(item for item in graph.agents if item.name == "agent")
    server = next(item for item in agent.mcp_servers if item.name == "filesystem")
    assert [(item.kind, item.selector) for item in server.resources] == [
        ("filesystem", "/srv/customer-data")
    ]
    assert {"data.read", "data.write"} <= server.resources[0].access
    assert any(
        item.kind == "filesystem" and item.selector == "/srv/customer-data"
        for item in agent.effective_resources
    )

    adg = graph.adg.as_dict()
    resource_nodes = [
        node
        for node in adg["nodes"]
        if node["kind"] == "data_resource"
        and node["attributes"].get("selector") == "/srv/customer-data"
    ]
    assert len(resource_nodes) == 1

def test_unconsumed_mcp_client_remains_unbound(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from langchain_mcp_adapters.client import MultiServerMCPClient

client = MultiServerMCPClient({
    "weather": {
        "url": "https://weather.example.test/mcp",
        "transport": "streamable_http",
    }
})
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    assert not graph.agents
    assert any(item.name == "weather" for item in graph.unbound_mcp_servers)


def test_bound_mcp_url_parameters_emit_destination_authority_without_attack_path(
    tmp_path: Path,
) -> None:
    (tmp_path / "fire_crawl.py").write_text(
        """
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("firecrawl")

class FirecrawlApp:
    def scrape_url(self, url, params=None):
        return {"url": url}

    def crawl_url(self, url, params=None):
        return {"url": url}

app = FirecrawlApp()

@mcp.tool()
async def scrape_url(url: str) -> str:
    response = app.scrape_url(url=url, params={"formats": ["markdown"]})
    return str(response)

@mcp.tool()
async def crawl_website(url: str) -> str:
    response = app.crawl_url(url, params={"limit": 10})
    return str(response)

if __name__ == "__main__":
    mcp.run()
""",
        encoding="utf-8",
    )
    (tmp_path / "exa_web_search.py").write_text(
        """
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("websearch")

class Exa:
    def search_and_contents(self, query, **kwargs):
        return []

exa = Exa()

@mcp.tool()
async def search_web(query: str) -> str:
    return str(exa.search_and_contents(query, summary={"query": "points"}))

if __name__ == "__main__":
    mcp.run()
""",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        """
from agents import Agent
from agents.mcp import MCPServerStdio

firecrawl = MCPServerStdio(
    params={"command": "python", "args": ["fire_crawl.py"]}
)
websearch = MCPServerStdio(
    params={"command": "python", "args": ["exa_web_search.py"]}
)
agent = Agent(name="agent", mcp_servers=[firecrawl, websearch])
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)

    agent = next(item for item in graph.agents if item.name == "agent")
    by_name = {server.name: server for server in agent.mcp_servers}

    firecrawl_tools = by_name["firecrawl"].metadata["discovered_tools"]
    assert any(
        item["name"] == "scrape_url"
        and item["dynamic_destination_authority"] is True
        and item["model_selected_url_parameters"] == ["url"]
        for item in firecrawl_tools
    )
    assert any(
        item["name"] == "crawl_website"
        and item["dynamic_destination_authority"] is True
        for item in firecrawl_tools
    )

    search_tools = by_name["websearch"].metadata["discovered_tools"]
    assert all(
        item["dynamic_destination_authority"] is False
        for item in search_tools
    )

    net004 = [finding for finding in findings if finding.rule_id == "NET004"]
    assert len(net004) == 1
    assert net004[0].agent == "agent"
    assert "firecrawl" in net004[0].message.lower()
    assert not any(path.path_id.startswith("PATH") for path in graph.attack_paths)
