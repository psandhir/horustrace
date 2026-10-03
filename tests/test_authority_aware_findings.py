from pathlib import Path

from horustrace.adg import build_adg
from horustrace.models import Agent, Graph, MCPServer, NetworkDestination, SourceLocation, Tool
from horustrace.rules.builtin import evaluate
from horustrace.semantics import annotate_risk_semantics


def _finding(findings, rule_id: str):
    return next(item for item in findings if item.rule_id == rule_id)


def test_agt040_links_to_tool_authority_relationship(tmp_path: Path) -> None:
    location = SourceLocation(tmp_path / "agent.py", line=5)
    graph = Graph(
        agents=[
            Agent(
                name="writer",
                tools=[
                    Tool(
                        name="mutate",
                        kind="function",
                        capabilities={"data.write"},
                        location=location,
                    )
                ],
                location=location,
            )
        ]
    )
    graph.adg = build_adg(graph, tmp_path)

    finding = _finding(evaluate(graph), "AGT040")

    assert finding.authority_relationship_id is not None
    assert finding.authority_relationship_id.startswith("authority-v1:")
    assert any(
        item == f"authority_relationship={finding.authority_relationship_id}"
        for item in finding.evidence
    )


def test_agt040_respects_inherited_authority_control(tmp_path: Path) -> None:
    location = SourceLocation(tmp_path / "agent.py", line=5)
    graph = Graph(
        agents=[
            Agent(
                name="writer",
                tools=[
                    Tool(
                        name="mutate",
                        kind="function",
                        capabilities={"data.write"},
                        location=location,
                    )
                ],
                location=location,
                metadata={
                    "callbacks": {"before_tool_callback": "guard"},
                    "tool_control_state": "enforcing",
                    "tool_control_enforcing": True,
                    "tool_control_mechanism": "adk_before_tool_callback",
                },
            )
        ]
    )
    graph.adg = build_adg(graph, tmp_path)

    assert not any(item.rule_id == "AGT040" for item in evaluate(graph))


def test_agt032_links_bound_mcp_authority_relationship(tmp_path: Path) -> None:
    location = SourceLocation(tmp_path / "agent.py", line=6)
    server = MCPServer(
        name="remote",
        transport="streamable_http",
        url="https://mcp.example.test",
        authenticated=True,
        location=location,
    )
    graph = Graph(
        agents=[
            Agent(
                name="mcp-agent",
                mcp_servers=[server],
                location=location,
            )
        ]
    )
    graph.adg = build_adg(graph, tmp_path)

    finding = _finding(evaluate(graph), "AGT032")

    assert finding.authority_relationship_id is not None
    assert "tool_scope_resolution=unknown" in finding.evidence


def test_net002_uses_unresolved_destination_authority(tmp_path: Path) -> None:
    location = SourceLocation(tmp_path / "agent.py", line=8)
    graph = Graph(
        agents=[
            Agent(
                name="networked",
                tools=[
                    Tool(
                        name="send",
                        kind="function",
                        capabilities={"network.external"},
                        location=location,
                    )
                ],
                location=location,
            )
        ]
    )
    graph.adg = build_adg(graph, tmp_path)

    finding = _finding(evaluate(graph), "NET002")

    assert finding.authority_relationship_id is not None
    assert any(
        item.startswith("authority_relationship=")
        for item in finding.evidence
    )


def test_net002_not_emitted_for_fixed_destination_relationship(tmp_path: Path) -> None:
    location = SourceLocation(tmp_path / "agent.py", line=8)
    graph = Graph(
        agents=[
            Agent(
                name="networked",
                tools=[
                    Tool(
                        name="send",
                        kind="function",
                        capabilities={"network.external"},
                        destinations=[
                            NetworkDestination(
                                target="https://api.example.test",
                                restricted=True,
                                location=location,
                            )
                        ],
                        location=location,
                    )
                ],
                location=location,
            )
        ]
    )
    annotate_risk_semantics(graph)
    graph.adg = build_adg(graph, tmp_path)

    assert graph.agents[0].tools[0].metadata["network_semantics"] == (
        "fixed_provider_network"
    )
    assert not any(item.rule_id == "NET002" for item in evaluate(graph))


def test_cap005_uses_authority_relationship_evidence(tmp_path: Path) -> None:
    location = SourceLocation(tmp_path / "agent.py", line=9)
    graph = Graph(
        agents=[
            Agent(
                name="rw",
                tools=[
                    Tool(
                        name="rw-tool",
                        kind="function",
                        capabilities={"data.read", "data.write"},
                        location=location,
                    )
                ],
                location=location,
            )
        ]
    )
    graph.adg = build_adg(graph, tmp_path)

    finding = _finding(evaluate(graph), "CAP005")

    assert any(
        item.startswith("authority_relationship=")
        for item in finding.evidence
    )
    assert finding.authority_relationship_id is not None


def test_net002_not_emitted_for_fixed_managed_service_semantics(tmp_path: Path) -> None:
    location = SourceLocation(tmp_path / "agent.py", line=11)
    graph = Graph(
        agents=[
            Agent(
                name="managed-search",
                tools=[
                    Tool(
                        name="google_search",
                        kind="function",
                        capabilities={"network.external"},
                        location=location,
                        metadata={"network_scope": "fixed_managed_service"},
                    )
                ],
                location=location,
            )
        ]
    )
    graph.adg = build_adg(graph, tmp_path)

    assert not any(item.rule_id == "NET002" for item in evaluate(graph))
