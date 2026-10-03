from pathlib import Path

from horustrace.adapters.microsoft_foundry import scan_foundry_config
from horustrace.scanner import scan


def write(tmp_path: Path, text: str, name: str = "azure.yaml") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_foundry_azure_yaml_normalizes_hosted_agent_toolbox_and_agent_identity(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        """
services:
  agent-tools:
    host: azure.ai.toolbox
    uses:
      - ai-project
    tools:
      - type: code_interpreter
        name: code_interpreter
      - type: web_search
        name: web_search

  research-agent:
    host: azure.ai.agent
    project: src/research-agent
    uses:
      - ai-project
      - agent-tools
    protocols:
      - protocol: responses
        version: 2.0.0
    environmentVariables:
      - name: FOUNDRY_PROJECT_ENDPOINT
        value: https://example.services.ai.azure.com/api/projects/prod
      - name: PRIVATE_TOKEN
        value: do-not-copy-this-secret
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "research-agent")

    assert agent.metadata["framework"] == "microsoft-foundry-hosted"
    assert agent.metadata["hosted_agent"] is True
    assert agent.metadata["runtime_host"] == "azure.ai.agent"
    assert agent.metadata["environment_variables"] == [
        "FOUNDRY_PROJECT_ENDPOINT",
        "PRIVATE_TOKEN",
    ]
    assert "do-not-copy-this-secret" not in repr(agent.metadata)

    identity = next(
        item
        for item in agent.identities
        if item.metadata.get("identity_kind") == "foundry_agent_identity"
    )
    assert identity.provider == "azure"
    assert identity.metadata["runtime_resolved"] is False

    toolbox = next(item for item in agent.mcp_servers if item.name == "agent-tools")
    assert toolbox.transport == "foundry-toolbox"
    assert toolbox.authenticated is True
    assert toolbox.metadata["authentication"] == "entra"

    assert "process.execute" in agent.capabilities
    assert "data.write" in agent.capabilities
    assert "network.external" in agent.capabilities


def test_foundry_toolbox_external_endpoint_is_preserved_as_destination(
    tmp_path: Path,
) -> None:
    path = write(
        tmp_path,
        """
services:
  ops-tools:
    host: azure.ai.toolbox
    tools:
      - type: mcp
        name: ticketing
        endpoint: https://mcp.example.com/tools

  support:
    host: azure.ai.agent
    uses:
      - ops-tools
""",
    )

    graph = scan_foundry_config(path)
    agent = next(item for item in graph.agents if item.name == "support")
    tool = next(item for item in agent.tools if item.name == "ticketing")

    assert tool.kind == "foundry_mcp_tool"
    assert "network.external" in tool.capabilities
    assert tool.destinations[0].target == "https://mcp.example.com/tools"
    assert tool.destinations[0].restricted is True


def test_unrelated_yaml_does_not_create_foundry_entities(tmp_path: Path) -> None:
    path = write(
        tmp_path,
        """
name: ordinary-config
settings:
  enabled: true
""",
        name="config.yaml",
    )

    graph = scan_foundry_config(path)

    assert graph.agents == []
    assert graph.unbound_mcp_servers == []
    assert graph.identities == []
