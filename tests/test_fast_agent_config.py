from pathlib import Path

from horustrace.scanner import scan


def test_fast_agent_yaml_server_binds_to_agent_reference(tmp_path: Path) -> None:
    (tmp_path / "fast-agent.yaml").write_text(
        """
mcp:
  servers:
    filesystem:
      target: "npx -y @modelcontextprotocol/server-filesystem ."
""",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        """
from fast_agent import FastAgent

fast = FastAgent("App")

@fast.agent(name="worker", servers=["filesystem"])
async def main():
    pass
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "worker")

    assert len(agent.mcp_servers) == 1
    server = agent.mcp_servers[0]
    assert server.name == "filesystem"
    assert server.transport == "stdio"
    assert server.command == "npx"
    assert server.args == [
        "-y",
        "@modelcontextprotocol/server-filesystem",
        ".",
    ]
    assert server.metadata["source"] == "fast_agent_yaml"
    assert server.metadata["binding_origin"] == "fast_agent_servers_reference"
    assert server.metadata["effective_agent"] == "worker"
    assert graph.unbound_mcp_servers == []


def test_fast_agent_yaml_remote_auth_evidence_is_preserved(tmp_path: Path) -> None:
    (tmp_path / "fast-agent.yaml").write_text(
        """
mcp:
  servers:
    remote:
      target: "https://mcp.example.test/mcp"
      headers:
        Authorization: "Bearer ${MCP_TOKEN}"
""",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        """
from fast_agent import FastAgent

fast = FastAgent("App")

@fast.agent(name="worker", servers=["remote"])
async def main():
    pass
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    server = next(
        item
        for item in graph.agents[0].mcp_servers
        if item.name == "remote"
    )

    assert server.url == "https://mcp.example.test/mcp"
    assert server.authenticated is True
    assert server.metadata["credential_source"] == "env:MCP_TOKEN"
    assert server.identity == "worker:remote:mcp-auth"


def test_fast_agent_binding_uses_nearest_config_scope(tmp_path: Path) -> None:
    (tmp_path / "fast-agent.yaml").write_text(
        """
mcp:
  servers:
    shared:
      target: "https://parent.example.test/mcp"
""",
        encoding="utf-8",
    )
    child = tmp_path / "examples" / "demo"
    child.mkdir(parents=True)
    (child / "fast-agent.yaml").write_text(
        """
mcp:
  servers:
    shared:
      target: "https://child.example.test/mcp"
""",
        encoding="utf-8",
    )
    (child / "agent.py").write_text(
        """
from fast_agent import FastAgent

fast = FastAgent("Scoped")

@fast.agent(name="worker", servers=["shared"])
async def main():
    pass
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "worker")

    assert [server.url for server in agent.mcp_servers] == [
        "https://child.example.test/mcp"
    ]
    assert len(graph.unbound_mcp_servers) == 1
    assert graph.unbound_mcp_servers[0].url == "https://parent.example.test/mcp"


def test_fast_agent_duplicate_same_scope_remains_ambiguous(tmp_path: Path) -> None:
    first = tmp_path / "one"
    second = tmp_path / "two"
    first.mkdir()
    second.mkdir()
    for directory, url in (
        (first, "https://one.example.test/mcp"),
        (second, "https://two.example.test/mcp"),
    ):
        (directory / "mcp.json").write_text(
            '{"mcpServers":{"shared":{"url":"' + url + '"}}}',
            encoding="utf-8",
        )
    (tmp_path / "agent.py").write_text(
        """
from fast_agent import FastAgent

fast = FastAgent("App")

@fast.agent(name="worker", servers=["shared"])
async def main():
    pass
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    assert graph.agents[0].mcp_servers == []
    assert len(graph.unbound_mcp_servers) == 2
    assert len(graph.unresolved_mcp_references) == 1
    reference = graph.unresolved_mcp_references[0]
    assert reference.name == "shared"
    assert reference.metadata["context_binding"] == "ambiguous_fast_agent_reference"
    assert reference.metadata["candidate_count"] == 2


def test_fast_agent_http_oauth_is_enabled_by_default(tmp_path: Path) -> None:
    (tmp_path / "fast-agent.yaml").write_text(
        """
mcp:
  servers:
    remote:
      target: "https://huggingface.co/mcp?login"
""",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        """
from fast_agent import FastAgent

fast = FastAgent("App")

@fast.agent(name="worker", servers=["remote"])
async def main():
    pass
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    server = graph.agents[0].mcp_servers[0]

    assert server.authenticated is True
    assert "oauth" in server.metadata["auth_keys"]
    assert server.metadata["credential_source"] == "oauth:keyring"
    assert not any(item.rule_id == "AGT030" for item in findings)


def test_fast_agent_http_oauth_can_be_explicitly_disabled(tmp_path: Path) -> None:
    (tmp_path / "fast-agent.yaml").write_text(
        """
mcp:
  servers:
    remote:
      target: "https://mcp.example.test/mcp"
      auth:
        oauth: false
""",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        """
from fast_agent import FastAgent

fast = FastAgent("App")

@fast.agent(name="worker", servers=["remote"])
async def main():
    pass
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    server = graph.agents[0].mcp_servers[0]

    assert server.authenticated is False
    assert "oauth" not in server.metadata["auth_keys"]
    assert any(item.rule_id == "AGT030" for item in findings)


def test_fastagent_config_yaml_filename_binds_named_server(tmp_path: Path) -> None:
    (tmp_path / "fastagent.config.yaml").write_text(
        """
mcp:
  servers:
    browser:
      target: "npx -y chrome-devtools-mcp@latest"
""",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        """
from fast_agent import FastAgent

fast = FastAgent("App")

@fast.agent(name="researcher", servers=["browser"])
async def main():
    pass
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "researcher")

    assert [server.name for server in agent.mcp_servers] == ["browser"]
    assert agent.mcp_servers[0].metadata["binding_origin"] == (
        "fast_agent_servers_reference"
    )
    assert agent.mcp_servers[0].metadata["effective_agent"] == "researcher"
    assert any(
        item.rule_id == "AGT050"
        and item.location
        and item.location.path.name == "fastagent.config.yaml"
        for item in findings
    )


def test_fastagent_config_yml_filename_is_supported(tmp_path: Path) -> None:
    (tmp_path / "fastagent.config.yml").write_text(
        """
mcp:
  servers:
    local:
      target: "python local_server.py"
""",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        """
from fast_agent import FastAgent

fast = FastAgent("App")

@fast.agent(name="worker", servers=["local"])
async def main():
    pass
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "worker")
    assert [server.name for server in agent.mcp_servers] == ["local"]


def test_fast_agent_resolved_config_does_not_leave_unresolved_reference_diagnostic(
    tmp_path: Path,
) -> None:
    (tmp_path / "fast-agent.yaml").write_text(
        """
mcp:
  servers:
    remote_shell_toolkit:
      command: ./resources/remote_shell_toolkit.exe
""",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        """
from mcp_agent.core.fastagent import FastAgent

fast = FastAgent("shell")

@fast.agent(
    name="worker",
    servers=["remote_shell_toolkit"],
    tools={"remote_shell_toolkit": ["write_to_remote_shell"]},
)
async def worker():
    pass
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "worker")
    server = next(
        item for item in agent.mcp_servers
        if item.name == "remote_shell_toolkit"
    )

    assert server.command == "./resources/remote_shell_toolkit.exe"
    assert server.allowed_tools == ["write_to_remote_shell"]
    assert server.metadata["repository_resolved"] is True
    assert not any(
        diagnostic.details.get("construct") == "mcp_server_reference"
        and diagnostic.location == agent.location
        for diagnostic in graph.coverage.diagnostics
    )


def test_fast_agent_missing_config_retains_unresolved_reference_diagnostic(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from mcp_agent.core.fastagent import FastAgent

fast = FastAgent("shell")

@fast.agent(name="worker", servers=["missing_server"])
async def worker():
    pass
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    assert any(item.name == "worker" for item in graph.agents)

    assert any(
        diagnostic.details.get("construct") == "mcp_server_reference"
        and diagnostic.details.get("server_refs") == ["missing_server"]
        for diagnostic in graph.coverage.diagnostics
    )
    assert any(
        server.name == "missing_server"
        for server in graph.unresolved_mcp_references
    )
