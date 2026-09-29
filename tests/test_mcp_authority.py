from pathlib import Path

from horustrace.scanner import scan


def test_langgraph_mcp_client_get_tools_reconstructs_authority(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
import os
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent

client = MultiServerMCPClient({
    "slack": {
        "url": "https://mcp.example.test/mcp",
        "transport": "streamable_http",
        "headers": {"Authorization": f"Bearer {os.getenv('MCP_TOKEN')}"},
        "allowed_tools": ["search_messages", "read_thread"],
        "denied_tools": ["send_message"],
    }
})

async def build():
    tools = await client.get_tools()
    agent = create_react_agent("openai:gpt-4o", tools=tools)
    return agent
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    agent = next(item for item in graph.agents if item.name == "agent")
    assert [server.name for server in agent.mcp_servers] == ["slack"]

    server = agent.mcp_servers[0]
    assert server.metadata["binding_origin"] == "mcp_client_get_tools"
    assert server.metadata["effective_agent"] == "agent"
    assert server.metadata["context_binding"] == "bound"
    assert server.metadata["auth_mechanism"] == "authorization-header"
    assert server.metadata["credential_source"] == "env:MCP_TOKEN"
    assert server.metadata["authority_scope"] == "explicit_allowlist"
    assert server.allowed_tools == ["search_messages", "read_thread"]
    assert server.denied_tools == ["send_message"]
    assert server.identity == "agent:slack:mcp-auth"
    assert not any(item.name == "slack" for item in graph.unbound_mcp_servers)

    identity = next(
        item for item in agent.identities if item.name == server.identity
    )
    assert identity.credential_source == "env:MCP_TOKEN"

    adg = graph.adg.as_dict()
    edge_kinds = {edge["kind"] for edge in adg["edges"]}
    assert "INVOKES" in edge_kinds
    assert "USES_IDENTITY" in edge_kinds
    assert "CONNECTS_TO" in edge_kinds
    assert "ALLOWS_TOOL" in edge_kinds
    assert "DENIES_TOOL" in edge_kinds


def test_filesystem_mcp_resource_authority_is_projected(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent

client = MultiServerMCPClient({
    "filesystem": {
        "transport": "stdio",
        "command": "npx",
        "args": [
            "-y",
            "@modelcontextprotocol/server-filesystem",
            "/srv/customer-data",
        ],
    }
})

async def build():
    tools = await client.get_tools()
    agent = create_react_agent("openai:gpt-4o", tools=tools)
    return agent
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    agent = next(item for item in graph.agents if item.name == "agent")
    server = next(
        item for item in agent.mcp_servers if item.name == "filesystem"
    )
    assert [(item.kind, item.selector) for item in server.resources] == [
        ("filesystem", "/srv/customer-data")
    ]
    assert {"data.read", "data.write"} <= server.resources[0].access
    assert any(
        item.kind == "filesystem"
        and item.selector == "/srv/customer-data"
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
    resource_id = resource_nodes[0]["id"]
    assert any(
        edge["kind"] == "READS_FROM"
        and edge["target"] == resource_id
        for edge in adg["edges"]
    )
    assert any(
        edge["kind"] == "WRITES_TO"
        and edge["target"] == resource_id
        for edge in adg["edges"]
    )


def test_unconsumed_mcp_client_remains_unbound(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent

client = MultiServerMCPClient({
    "weather": {
        "url": "https://weather.example.test/mcp",
        "transport": "streamable_http",
    }
})
agent = create_react_agent("openai:gpt-4o", tools=[])
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    agent = next(item for item in graph.agents if item.name == "agent")
    assert agent.mcp_servers == []
    assert any(item.name == "weather" for item in graph.unbound_mcp_servers)


def test_langchain_create_agent_consumes_literal_mcp_client_tools(
    tmp_path: Path,
) -> None:
    (tmp_path / "cyber_agent.py").write_text(
        """from langchain.agents import create_agent
from langchain_mcp_adapters.client import MultiServerMCPClient

async def main():
    client = MultiServerMCPClient(
        {
            "cyber_tools": {
                "command": "python",
                "args": ["cyber_mcp_server.py"],
                "transport": "stdio",
            }
        }
    )
    tools = await client.get_tools()
    agent = create_agent(model="openai:gpt-5.4-mini", tools=tools)
    return agent
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    agent = next(item for item in graph.agents if item.name == "agent")
    assert agent.metadata["framework"] == "langchain"
    assert [server.name for server in agent.mcp_servers] == ["cyber_tools"]

    server = agent.mcp_servers[0]
    assert server.metadata["binding_origin"] == "mcp_client_get_tools"
    assert server.metadata["effective_agent"] == "agent"
    assert server.metadata["context_binding"] == "bound"
    assert not any(
        item.name == "cyber_tools" for item in graph.unbound_mcp_servers
    )

    assert graph.adg is not None
    server_nodes = [
        node
        for node in graph.adg.nodes
        if node.kind == "mcp_server"
        and node.attributes.get("effective_agent") == "agent"
    ]
    assert len(server_nodes) == 1
    assert any(
        edge.kind == "INVOKES"
        and edge.target == server_nodes[0].node_id
        for edge in graph.adg.edges
    )



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
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent

client = MultiServerMCPClient({
    "firecrawl": {
        "command": "python",
        "args": ["fire_crawl.py"],
        "transport": "stdio",
    },
    "websearch": {
        "command": "python",
        "args": ["exa_web_search.py"],
        "transport": "stdio",
    },
})

async def build():
    tools = await client.get_tools()
    agent = create_react_agent("openai:gpt-4o", tools=tools)
    return agent
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
