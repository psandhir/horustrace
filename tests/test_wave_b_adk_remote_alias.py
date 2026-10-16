"""Pinned regression for ff60-google-adk-05 remote AgentTool delegation (#569)."""

from pathlib import Path

from horustrace.effective_authority import effective_authority_report
from horustrace.scanner import scan


def _write(root: Path, name: str, contents: str) -> None:
    (root / name).write_text(contents, encoding="utf-8")


def test_adk_agenttool_imported_remote_source_alias_is_resolved(tmp_path: Path) -> None:
    # The remote proxy and locally hosted agent intentionally share the
    # runtime name "routing_agent"; only the Python source alias identifies
    # the actual imported delegate.
    _write(tmp_path, "routing.py", """
from google.adk.agents import Agent
from google.adk.agents.remote_a2a_agent import RemoteA2aAgent
routing_agent = Agent(name="routing_agent", model="gemini-2.5-flash")
remote_routing_agent = RemoteA2aAgent(
    name="routing_agent", agent_card="https://routing.example.test/card"
)
""")
    _write(tmp_path, "discovery.py", """
from google.adk.agents.remote_a2a_agent import RemoteA2aAgent
remote_discovery_agent = RemoteA2aAgent(
    name="discover_places", agent_card="https://places.example.test/card"
)
""")
    _write(tmp_path, "composer.py", """
from google.adk.agents import Agent
composer_agent = Agent(name="composer_agent", model="gemini-2.5-flash")
""")
    _write(tmp_path, "agent.py", """
from google.adk.agents import Agent
from google.adk.tools.agent_tool import AgentTool
from discovery import remote_discovery_agent
from routing import remote_routing_agent
from composer import composer_agent

root_agent = Agent(name="local_explorer_assistant", model="gemini-2.5-flash", tools=[
    AgentTool(agent=remote_discovery_agent),
    AgentTool(agent=remote_routing_agent),
    AgentTool(agent=composer_agent),
])
""")
    graph, _ = scan(tmp_path)
    relations = effective_authority_report(graph)["relationships"]
    delegates = {
        item["target"]["name"]
        for item in relations
        if item["agent"] == "local_explorer_assistant"
        and item["target"]["kind"] == "delegation"
    }
    assert delegates == {"discover_places", "routing_agent", "composer_agent"}
    parent = next(a for a in graph.agents if a.name == "local_explorer_assistant")
    projected = [t for t in parent.tools if t.kind == "delegated_agent"]
    assert {t.metadata["delegate_target"] for t in projected} == delegates
    routing = next(t for t in projected if t.name == "delegate:routing_agent")
    assert "network.external" in routing.capabilities
    assert not any(t.name == "delegate:unrelated_agent" for t in projected)


def test_adk_ambiguous_imported_source_alias_stays_unresolved(tmp_path: Path) -> None:
    _write(tmp_path, "route_a.py", """
from google.adk.agents.remote_a2a_agent import RemoteA2aAgent
remote_routing_agent = RemoteA2aAgent(name="route_a", agent_card="https://a.example.test/card")
""")
    _write(tmp_path, "route_b.py", """
from google.adk.agents.remote_a2a_agent import RemoteA2aAgent
remote_routing_agent = RemoteA2aAgent(name="route_b", agent_card="https://b.example.test/card")
""")
    _write(tmp_path, "agent.py", """
from google.adk.agents import Agent
from google.adk.tools.agent_tool import AgentTool
from route_a import remote_routing_agent
root_agent = Agent(name="router", tools=[AgentTool(agent=remote_routing_agent)])
""")
    graph, _ = scan(tmp_path)
    parent = next(a for a in graph.agents if a.name == "router")
    assert not [t for t in parent.tools if t.kind == "delegated_agent"]
    assert any(d.kind == "unresolved_delegation" for d in graph.coverage.diagnostics)
