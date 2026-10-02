from pathlib import Path

from horustrace.scanner import scan


def test_openai_run_context_mutation_is_not_persistent_data_write(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic import BaseModel
from agents import Agent, RunContextWrapper, function_tool

class Context(BaseModel):
    confirmation_number: str | None = None
    seat_number: str | None = None

@function_tool
async def update_seat(
    context: RunContextWrapper[Context],
    confirmation_number: str,
    new_seat: str,
) -> str:
    context.context.confirmation_number = confirmation_number
    context.context.seat_number = new_seat
    return f"updated {new_seat}"

agent = Agent(name="Seat Booking Agent", tools=[update_seat])
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "Seat Booking Agent")
    tool = next(item for item in agent.tools if item.name == "update_seat")

    assert "data.write" not in tool.capabilities
    assert tool.metadata["effect_scope"] == "run_context"
    assert tool.metadata["persistent_effect_proven"] is False
    assert not any(
        finding.rule_id in {"AGT022", "AGT040", "CAP005"}
        and finding.agent == "Seat Booking Agent"
        for finding in findings
    )


def test_unbound_mcp_config_is_inventory_not_agent_risk(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(
        """
{
  "mcpServers": {
    "context7": {
      "type": "http",
      "url": "https://mcp.context7.com/mcp",
      "headers": {"CONTEXT7_API_KEY": "${CONTEXT7_API_KEY}"}
    },
    "grep.app": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://mcp.grep.app"]
    }
  }
}
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)

    assert len(graph.unbound_mcp_servers) == 2
    context7 = next(
        server for server in graph.unbound_mcp_servers
        if server.name == "context7"
    )
    assert context7.authenticated is True
    assert "context7_api_key" in context7.metadata["auth_keys"]
    assert not any(
        finding.rule_id in {"AGT030", "AGT031", "AGT032", "AGT050"}
        for finding in findings
    )


def test_adk_application_integration_explicit_trigger_constrains_surface_and_egress(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from google.adk.agents import Agent
from google.adk.tools.application_integration_tool.application_integration_toolset import ApplicationIntegrationToolset

integration_tool = ApplicationIntegrationToolset(
    project="demo-project",
    location="us-central1",
    integration="sendEmail",
    triggers=["api_trigger/send_email"],
    tool_instructions="Send an email.",
)

root_agent = Agent(
    name="sar_agent",
    model="gemini-2.5-flash",
    tools=[integration_tool],
)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "sar_agent")
    tool = next(item for item in agent.tools if item.name == "integration_tool")

    assert tool.metadata["explicit_surface_constraint"] is True
    assert tool.metadata["network_scope"] == "fixed_managed_service"
    assert tool.metadata["integration"] == "sendEmail"
    assert tool.metadata["integration_triggers"] == ["api_trigger/send_email"]
    assert any(
        destination.restricted is True
        and destination.metadata.get("network_scope") == "fixed_managed_service"
        for destination in tool.destinations
    )
    assert not any(
        finding.rule_id in {"ADK007", "NET002", "PATH009"}
        and finding.agent == "sar_agent"
        for finding in findings
    )


def test_adk_environment_derived_a2a_endpoint_is_operator_configured(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
import os
from google.adk.agents.remote_a2a_agent import RemoteA2aAgent

def build_agent():
    cdagent_url = os.environ.get("CDAGENT_URL", "")
    remote = RemoteA2aAgent(
        name="cd_agent",
        agent_card=f"{cdagent_url}/.well-known/agent-card.json",
    )
    return remote
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "cd_agent")
    tool = next(item for item in agent.tools if item.kind == "adk_a2a_remote")

    assert tool.metadata["network_scope"] == "operator_configured_destination"
    assert tool.metadata["configuration_source"] == "CDAGENT_URL"
    assert any(
        destination.restricted is True
        and destination.metadata.get("network_scope")
        == "operator_configured_destination"
        for destination in tool.destinations
    )
    assert not any(
        finding.rule_id == "NET002" and finding.agent == "cd_agent"
        for finding in findings
    )
