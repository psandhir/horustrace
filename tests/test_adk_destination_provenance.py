from pathlib import Path

from horustrace.effective_authority import effective_authority_report
from horustrace.scanner import scan


def test_adk_environment_endpoint_is_operator_configured_destination(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
import os
import requests
from google.adk.agents import Agent

CHECK_ORDER_STATUS_ENDPOINT = os.environ["CHECK_ORDER_STATUS_ENDPOINT"]

def check_status():
    return requests.get(CHECK_ORDER_STATUS_ENDPOINT).json()

root_agent = Agent(
    name="renovation",
    model="gemini-2.5-flash",
    tools=[check_status],
)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "renovation")
    tool = next(item for item in agent.tools if item.name == "check_status")

    assert tool.metadata["network_scope"] == "operator_configured_destination"
    assert tool.metadata["destination_constraint_basis"] == "operator_configuration"
    assert tool.metadata["configuration_sources"] == [
        "CHECK_ORDER_STATUS_ENDPOINT"
    ]
    assert len(tool.destinations) == 1
    destination = tool.destinations[0]
    assert destination.target == "<operator-configured:CHECK_ORDER_STATUS_ENDPOINT>"
    assert destination.restricted is True
    assert (
        destination.metadata["network_scope"]
        == "operator_configured_destination"
    )
    assert not any(
        destination.target == "<dynamic-url>"
        for destination in tool.destinations
    )
    assert not any(
        finding.rule_id in {"NET001", "NET002"}
        and finding.agent == "renovation"
        for finding in findings
    )


def test_adk_operator_base_plus_runtime_path_remains_dynamic(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
import os
import requests
from google.adk.agents import Agent

API_BASE = os.getenv("API_BASE")

def fetch_path(path: str):
    return requests.get(API_BASE + path).text

root_agent = Agent(
    name="reader",
    model="gemini-2.5-flash",
    tools=[fetch_path],
)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "reader")
    tool = next(item for item in agent.tools if item.name == "fetch_path")

    assert any(
        destination.target == "<dynamic-url>"
        and destination.restricted is False
        for destination in tool.destinations
    )
    assert tool.metadata.get("network_scope") != "operator_configured_destination"


def test_adk_remote_a2a_os_environ_subscript_is_operator_configured(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
import os
from google.adk.agents.remote_a2a_agent import RemoteA2aAgent

remote = RemoteA2aAgent(
    name="remote",
    agent_card=os.environ["REMOTE_AGENT_CARD"],
)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "remote")
    tool = next(item for item in agent.tools if item.kind == "adk_a2a_remote")

    assert tool.metadata["network_scope"] == "operator_configured_destination"
    assert tool.metadata["configuration_source"] == "REMOTE_AGENT_CARD"
    assert tool.destinations[0].restricted is True


def test_engine_mcp_registry_urls_are_source_correlated_but_not_enforced(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        "from google.adk.agents import Agent\n"
        "from idun_agent_engine.mcp import get_adk_tools\n"
        'root_agent = Agent(name="mcp_adk", tools=get_adk_tools())\n',
        encoding="utf-8",
    )
    (tmp_path / "config.yaml").write_text(
        'agent:\n  type: ADK\n  config:\n    agent: "./agent.py:root_agent"\n'
        "mcp_servers:\n"
        "  - name: docs\n    transport: streamable_http\n"
        "    url: https://docs.example.test/mcp\n"
        "  - name: data\n    transport: streamable_http\n"
        "    url: https://data.example.test/mcp\n",
        encoding="utf-8",
    )
    graph, findings = scan(tmp_path)
    report = effective_authority_report(graph)
    relation = next(
        x for x in report["relationships"]
        if x["agent"] == "mcp_adk"
        and x["target"] == {"kind": "mcp_server", "name": "get_adk_tools"}
    )
    expected = {"https://docs.example.test/mcp", "https://data.example.test/mcp"}
    assert {x["target"] for x in relation["destinations"]} == expected
    assert all(x["kind"] == "configured_registry_endpoint" for x in relation["destinations"])
    assert all(x["restriction_enforcement"] == "not_verified" for x in relation["destinations"])
    assert all(x["restricted"] is False for x in relation["destinations"])
    assert relation["dimensions"]["destinations"] == "partially_resolved"
    assert relation["semantics"]["destination_binding_resolution"] == (
        "configured_registry_endpoints"
    )
    assert relation["runtime_effectiveness"] == "not_verified"
    risk = [
        x for x in findings
        if x.rule_id == "NET002" and x.agent == "mcp_adk"
    ]
    assert risk
    assert "configured" in risk[0].title.lower()
    assert any(
        part.startswith("configured_mcp_endpoints=")
        and all(url in part for url in expected)
        for part in risk[0].evidence
    )


def test_mcp_registry_not_attributed_without_exact_application_reference(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        "from google.adk.agents import Agent\n"
        "from idun_agent_engine.mcp import get_adk_tools\n"
        'root_agent = Agent(name="mcp_adk", tools=get_adk_tools())\n',
        encoding="utf-8",
    )
    (tmp_path / "config.yaml").write_text(
        'agent:\n  type: ADK\n  config:\n    agent: "./other.py:root_agent"\n'
        "mcp_servers:\n"
        "  - name: unrelated\n    url: https://unrelated.example.test/mcp\n",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    report = effective_authority_report(graph)
    assert not any(
        destination["target"] == "https://unrelated.example.test/mcp"
        for relation in report["relationships"]
        for destination in relation["destinations"]
    )
    assert not any(
        relation["semantics"].get("destination_binding_resolution")
        == "configured_registry_endpoints"
        for relation in report["relationships"]
    )
