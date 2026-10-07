from pathlib import Path

from horustrace.effective_authority import effective_authority_report
from horustrace.scanner import scan


def test_custom_mcp_connection_wrapper_is_structurally_visible(
    tmp_path: Path,
) -> None:
    (tmp_path / "client.py").write_text(
        """
from mcp import ClientSession, StdioServerParameters

class MCPServerConnection:
    def __init__(self, command: str):
        self.command = command
        self.session = None

    async def connect(self):
        params = StdioServerParameters(command=self.command, args=[])
        self.session = ClientSession(read_stream, write_stream)

server = MCPServerConnection("python")
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    assert graph.agents == []
    server = next(item for item in graph.unbound_mcp_servers if item.name == "server")
    assert server.transport == "stdio"
    assert server.metadata["wrapper_class"] == "MCPServerConnection"
    assert graph.adg is not None
    node = next(
        item
        for item in graph.adg.nodes
        if item.kind == "mcp_server" and item.name == "server"
    )
    assert node.attributes["unbound"] is True
    assert not any(edge.kind == "INVOKES" and edge.target == node.node_id for edge in graph.adg.edges)
    assert effective_authority_report(graph)["relationships"] == []


def test_custom_mcp_server_wrapper_requires_strong_mcp_internals(
    tmp_path: Path,
) -> None:
    (tmp_path / "server.py").write_text(
        """
from mcp.server import Server

class AWSMCPServer:
    def __init__(self):
        self.server = Server("aws-cli-server")

server = AWSMCPServer()
""",
        encoding="utf-8",
    )
    (tmp_path / "config.py").write_text(
        """
from mcp import ClientSession

class MCPServerConfig:
    def __init__(self, name):
        self.name = name

config = MCPServerConfig("docs")
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    names = {server.name for server in graph.unbound_mcp_servers}
    assert "server" in names
    assert "config" not in names


def test_openai_mcp_definition_is_visible_without_agent_binding(
    tmp_path: Path,
) -> None:
    (tmp_path / "care.py").write_text(
        """
from agents.mcp.server import MCPServerSse

care_mcp = MCPServerSse(
    name="KnoliaCare",
    params={"url": "http://localhost:8002/sse"},
)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    assert graph.agents == []
    server = next(item for item in graph.unbound_mcp_servers if item.name == "care_mcp")
    assert server.transport == "sse"
    assert server.url == "http://localhost:8002/sse"
    assert graph.adg is not None
    node = next(
        item
        for item in graph.adg.nodes
        if item.kind == "mcp_server" and item.name == "care_mcp"
    )
    assert node.attributes["unbound"] is True
    assert not any(edge.kind == "INVOKES" and edge.target == node.node_id for edge in graph.adg.edges)


def test_pydantic_legacy_mcp_servers_binding_is_normalized(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent
from pydantic_ai.mcp import MCPServerStdio

mcp_server = MCPServerStdio("python", ["mcp_server.py"], env={})
agent = Agent("openai:gpt-5", mcp_servers=[mcp_server])
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    agent = next(item for item in graph.agents if item.name == "agent")
    server = next(item for item in agent.mcp_servers if item.name == "mcp_server")
    assert server.transport == "stdio"
    assert server.command == "python"
    assert server.args == ["mcp_server.py"]


def test_pydantic_mcp_server_stdio_works_in_toolsets(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent
from pydantic_ai.mcp import MCPServerStdio

server = MCPServerStdio(
    "uvx",
    args=["mcp-run-python@latest", "stdio"],
    timeout=10,
)
agent = Agent(
    "openai:gpt-5",
    toolsets=[server],
)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    agent = next(item for item in graph.agents if item.name == "agent")
    server = next(item for item in agent.mcp_servers if item.name == "server")
    assert server.transport == "stdio"
    assert server.command == "uvx"
    assert server.args == ["mcp-run-python@latest", "stdio"]


def test_pydantic_aliased_mcp_server_stdio_is_normalized(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent as PyAIAgent
from pydantic_ai.mcp import MCPServerStdio as PyAIMCPServerStdio

tavily_mcp_server = PyAIMCPServerStdio(
    command="npx",
    args=["-y", "tavily-mcp@0.1.4"],
)
researcher_agent = PyAIAgent(
    "openai:gpt-5",
    mcp_servers=[tavily_mcp_server],
)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    agent = next(
        item for item in graph.agents
        if item.name == "researcher_agent"
    )
    server = next(
        item for item in agent.mcp_servers
        if item.name == "tavily_mcp_server"
    )
    assert server.transport == "stdio"
    assert server.command == "npx"
    assert server.args == ["-y", "tavily-mcp@0.1.4"]
    assert server.metadata["constructor_alias"] == "PyAIMCPServerStdio"
    assert not any(
        item.name == "tavily_mcp_server"
        for item in graph.unbound_mcp_servers
    )
    assert graph.adg is not None
    node = next(
        item
        for item in graph.adg.nodes
        if item.kind == "mcp_server"
        and item.name == "researcher_agent:tavily_mcp_server"
    )
    assert any(
        edge.kind == "INVOKES" and edge.target == node.node_id
        for edge in graph.adg.edges
    )


def test_shadowed_fastmcp_assignment_keeps_only_runtime_instance(
    tmp_path: Path,
) -> None:
    (tmp_path / "server.py").write_text(
        """
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("abandoned")
mcp = FastMCP("effective")

if __name__ == "__main__":
    mcp.run(transport="stdio")
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    servers = [
        server
        for server in graph.unbound_mcp_servers
        if server.metadata.get("source") == "FastMCP"
    ]
    assert len(servers) == 1
    assert servers[0].name == "effective"
    assert servers[0].transport == "stdio"
    assert servers[0].metadata["shadowed_constructions"] == [
        {"line": 4, "name": "abandoned"}
    ]


def test_remote_mcp_oauth_provider_is_recognized_with_dynamic_endpoint(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from mcp.client.auth import OAuthClientProvider
from mcp.client.streamable_http import streamablehttp_client

class MCPConnection:
    def __init__(self, url):
        self.url = url

    async def connect(self):
        oauth = OAuthClientProvider(
            server_url=self.url,
            client_metadata=metadata,
            storage=storage,
            redirect_handler=redirect_handler,
            callback_handler=callback_handler,
        )
        async with streamablehttp_client(self.url, auth=oauth) as streams:
            return streams
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)

    server = next(
        server
        for server in graph.unbound_mcp_servers
        if server.transport == "streamable-http"
    )
    assert server.url is None
    assert server.authenticated is True
    assert server.metadata["auth_mechanism"] == "oauth2.1"
    assert server.metadata["dynamic_mcp_endpoint"] is True
    assert server.metadata["binding_state"] == "unbound"
    assert not any(
        finding.rule_id in {"AGT030", "AGT031", "AGT032", "NET001"}
        for finding in findings
    )

def test_remote_mcp_explicit_http_client_without_auth_is_flagged(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
import httpx
from mcp.client.streamable_http import streamable_http_client

async def connect(url):
    headers = {
        "Accept": "application/json, text/event-stream",
        "User-Agent": "example/1.0",
    }
    async with httpx.AsyncClient(headers=headers) as http_client:
        async with streamable_http_client(url, http_client=http_client) as streams:
            return streams
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)

    server = next(
        server
        for server in graph.unbound_mcp_servers
        if server.transport == "streamable-http"
    )
    assert server.authenticated is False
    assert server.metadata["auth_mechanism"] == "explicit-http-client-no-auth"
    assert server.metadata["dynamic_mcp_endpoint"] is True
    assert server.metadata["binding_state"] == "unbound"
    assert not any(
        finding.rule_id in {"AGT030", "AGT031", "AGT032", "NET001"}
        for finding in findings
    )


def test_remote_mcp_http_client_auth_header_is_not_flagged(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
import httpx
from mcp.client.streamable_http import streamable_http_client

async def connect(url):
    headers = {"Authorization": "Bearer token"}
    async with httpx.AsyncClient(headers=headers) as http_client:
        async with streamable_http_client(url, http_client=http_client) as streams:
            return streams
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)

    server = next(
        server
        for server in graph.unbound_mcp_servers
        if server.transport == "streamable-http"
    )
    assert server.authenticated is True
    assert server.metadata["auth_mechanism"] == "http-header"
    assert not any(finding.rule_id == "AGT030" for finding in findings)

