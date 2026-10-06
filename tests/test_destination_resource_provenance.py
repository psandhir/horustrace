from pathlib import Path

from horustrace.effective_authority import effective_authority_report
from horustrace.scanner import scan


def test_anthropic_environment_allowed_hosts_bounds_managed_network_authority(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from anthropic import Anthropic

client = Anthropic()
agent = client.beta.agents.create(
    name="governed",
    model="claude-sonnet-4-6",
    tools=[{"type": "agent_toolset_20260401"}],
    mcp_servers=[
        {
            "type": "url",
            "name": "partner",
            "url": get_partner_mcp_url(),
        }
    ],
)
environment = client.beta.environments.create(
    name="restricted",
    config={
        "type": "cloud",
        "networking": {
            "type": "limited",
            "allowed_hosts": ["api.internal.example", "mcp.partner.example"],
            "allow_mcp_servers": True,
        },
    },
)
session = client.beta.sessions.create(
    agent=agent.id,
    environment_id=environment.id,
)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "governed")

    assert {item.target for item in agent.network} == {
        "api.internal.example",
        "mcp.partner.example",
    }
    web_fetch = next(item for item in agent.tools if item.name == "web_fetch")
    assert web_fetch.metadata["network_scope"] == "environment_allowlist"
    assert web_fetch.destinations[0].restricted is True
    assert (
        web_fetch.destinations[0].metadata["constrained_by"]
        == "environment_allowed_hosts"
    )

    server = next(item for item in agent.mcp_servers if item.name == "partner")
    assert server.metadata["network_scope"] == "environment_allowlist"
    assert server.metadata["environment_allowed_hosts"] == [
        "api.internal.example",
        "mcp.partner.example",
    ]

    report = effective_authority_report(graph)
    relationship = next(
        item
        for item in report["relationships"]
        if item["agent"] == "governed"
        and item["target"]["kind"] == "mcp_server"
        and item["target"]["name"] == "partner"
    )
    assert relationship["dimensions"]["destinations"] == "resolved"
    assert {item["target"] for item in relationship["destinations"]} == {
        "api.internal.example",
        "mcp.partner.example",
    }
    assert not any(
        item.rule_id in {"NET001", "NET002"} and item.agent == "governed"
        for item in findings
    )


def test_openai_fixed_literal_destination_is_source_bounded(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
import requests
from agents import Agent, function_tool

@function_tool
def notify(message: str):
    return requests.post(
        "https://api.pushover.net/1/messages.json",
        data={"message": message},
    ).text

agent = Agent(name="Notifier", tools=[notify])
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "Notifier")
    notify = next(item for item in agent.tools if item.name == "notify")

    destination = next(
        item
        for item in notify.destinations
        if item.target == "https://api.pushover.net/1/messages.json"
    )
    assert destination.restricted is True
    assert destination.metadata["network_scope"] == "fixed_literal_destination"
    assert not any(
        item.rule_id in {"NET001", "NET002"} and item.agent == "Notifier"
        for item in findings
    )


def test_amazon_localhost_destination_is_fixed_local_service(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
import requests
from strands import Agent, tool

@tool
def market_quote(symbol: str):
    return requests.post(
        "http://localhost:8080/quote",
        json={"symbol": symbol},
    ).json()

agent = Agent(tools=[market_quote])
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    tool = next(item for item in agent.tools if item.name == "market_quote")
    destination = next(
        item for item in tool.destinations if item.target == "http://localhost:8080/quote"
    )

    assert destination.restricted is True
    assert destination.metadata["network_scope"] == "fixed_local_service"
    assert destination.metadata["local_service"] is True
    assert not any(
        item.rule_id in {"NET001", "NET002"} and item.agent == "agent"
        for item in findings
    )


def test_literal_aws_resources_receive_fixed_source_provenance(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
import boto3
from strands import Agent, tool

@tool
def load_report():
    s3 = boto3.client("s3")
    return s3.get_object(
        Bucket="audit-reports",
        Key="daily.json",
    )

@tool
def load_pinned_report():
    return "s3://audit-reports/daily.json"

agent = Agent(tools=[load_pinned_report])
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    tool = next(item for item in agent.tools if item.name == "load_pinned_report")
    resource = next(
        item for item in tool.resources if item.selector == "s3://audit-reports/daily.json"
    )
    assert resource.metadata["resource_constraint_basis"] == "fixed_source_selector"
    assert resource.metadata["constraint_state"] == "bounded"
