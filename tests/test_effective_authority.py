from pathlib import Path

from horustrace.adg import build_adg
from horustrace.effective_authority import effective_authority_report
from horustrace.models import (
    Agent,
    Graph,
    Identity,
    MCPServer,
    NetworkDestination,
    ResourceScope,
    SourceLocation,
    Tool,
)


def _graph(root: Path) -> Graph:
    location = SourceLocation(root / "agent.py", line=7)
    identity = Identity(
        name="support-agent",
        provider="gcp",
        credential_source="workload_identity",
        roles={"roles/viewer"},
        location=location,
    )
    tool = Tool(
        name="update_ticket",
        kind="function",
        capabilities={"data.read", "data.write"},
        approval=True,
        resources=[
            ResourceScope(
                kind="ticket",
                selector="support/*",
                access={"data.read", "data.write"},
                location=location,
            )
        ],
        destinations=[
            NetworkDestination(
                target="https://support.example.test",
                restricted=True,
                location=location,
                metadata={"source": "fixture"},
            )
        ],
        identity=identity.name,
        location=location,
        metadata={
            "approval_mechanism": "human_confirmation",
            "mutation_semantics": "persistent_internal_write",
            "network_semantics": "fixed_provider",
        },
    )
    server = MCPServer(
        name="github",
        transport="streamable_http",
        url="https://api.github.com/mcp",
        authenticated=True,
        approval=False,
        allowed_tools=["issues_read", "issues_update"],
        denied_tools=["repo_delete"],
        identity=identity.name,
        location=location,
        metadata={
            "auth_mechanism": "workload_identity",
            "binding_origin": "framework_agent_configuration",
        },
    )
    graph = Graph(
        agents=[
            Agent(
                name="support",
                tools=[tool],
                mcp_servers=[server],
                identities=[identity],
                location=location,
            )
        ]
    )
    graph.adg = build_adg(graph, root)
    return graph


def _relationship(report: dict, kind: str, name: str) -> dict:
    return next(
        item
        for item in report["relationships"]
        if item["target"] == {"kind": kind, "name": name}
    )


def test_effective_authority_reconstructs_direct_tool_relationship(tmp_path: Path) -> None:
    report = effective_authority_report(_graph(tmp_path))
    relationship = _relationship(report, "tool", "update_ticket")

    assert relationship["agent"] == "support"
    assert relationship["capabilities"] == ["data.read", "data.write"]
    assert relationship["identity"]["name"] == "support-agent"
    assert relationship["identity"]["credential_source"] == "workload_identity"
    assert relationship["approval"] == {
        "required": True,
        "guardrails": False,
        "inherited_control": False,
        "mechanism": "human_confirmation",
    }
    assert relationship["resources"][0]["selector"] == "support/*"
    assert relationship["destinations"][0]["target"] == "https://support.example.test"
    assert relationship["semantics"]["mutation"] == "persistent_internal_write"
    assert relationship["semantics"]["network"] == "fixed_provider"
    assert relationship["runtime_effectiveness"] == "not_verified"
    assert len(relationship["evidence"]) == 1
    assert relationship["evidence"][0]["kind"] == "INVOKES"


def test_effective_authority_reconstructs_mcp_relationship(tmp_path: Path) -> None:
    report = effective_authority_report(_graph(tmp_path))
    relationship = _relationship(report, "mcp_server", "github")

    assert relationship["agent"] == "support"
    assert relationship["capabilities"] == ["mcp.remote", "network.external"]
    assert relationship["tool_scope"] == {
        "scope": "explicit_allowlist",
        "allowed": ["issues_read", "issues_update"],
        "denied": ["repo_delete"],
        "catalogue_known": True,
    }
    assert relationship["identity"]["name"] == "support-agent"
    assert relationship["destinations"][0]["target"] == "https://api.github.com/mcp"
    assert relationship["semantics"]["binding_origin"] == "framework_agent_configuration"
    assert relationship["semantics"]["authentication_state"] == "authenticated"
    assert relationship["semantics"]["authentication_mechanism"] == "workload_identity"
    assert relationship["runtime_effectiveness"] == "not_verified"
    assert len(relationship["evidence"]) == 1


def test_effective_authority_keeps_missing_dimensions_explicit(tmp_path: Path) -> None:
    location = SourceLocation(tmp_path / "agent.py", line=3)
    graph = Graph(
        agents=[
            Agent(
                name="minimal",
                tools=[
                    Tool(
                        name="opaque",
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

    relationship = effective_authority_report(graph)["relationships"][0]

    assert relationship["resolution"] == "partially_resolved"
    assert relationship["detail_resolution"] == "partially_resolved"
    assert relationship["core_resolution"] == "fully_resolved"
    assert relationship["core_dimensions"] == {
        "target": "resolved",
        "capabilities": "resolved",
    }
    assert relationship["core_unresolved"] == []
    assert relationship["identity"] is None
    assert relationship["resources"] == []
    assert relationship["destinations"] == []
    assert relationship["unresolved"] == [
        "approval",
        "destinations",
        "identity",
        "resources",
    ]
    assert relationship["dimensions"]["identity"] == "unknown"
    assert relationship["dimensions"]["approval"] == "unknown"
    assert relationship["runtime_effectiveness"] == "not_verified"


def test_effective_authority_mcp_core_requires_tool_scope(tmp_path: Path) -> None:
    location = SourceLocation(tmp_path / "agent.py", line=5)
    server = MCPServer(
        name="dynamic",
        transport="streamable_http",
        url="https://mcp.example.test",
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

    relationship = effective_authority_report(graph)["relationships"][0]

    assert relationship["target"] == {
        "kind": "mcp_server",
        "name": "dynamic",
    }
    assert relationship["core_resolution"] == "partially_resolved"
    assert relationship["core_dimensions"]["target"] == "resolved"
    assert relationship["core_dimensions"]["capabilities"] == "resolved"
    assert relationship["core_dimensions"]["tool_scope"] == "unknown"
    assert relationship["core_unresolved"] == ["tool_scope"]

def test_effective_authority_report_summary_counts_relationship_types(tmp_path: Path) -> None:
    report = effective_authority_report(_graph(tmp_path))

    assert report["schema_version"] == 1
    assert report["runtime_effectiveness"] == "not_verified"
    assert report["summary"]["relationships"] == 2
    assert report["summary"]["core_fully_resolved_relationships"] == 2
    assert report["summary"]["core_partially_resolved_relationships"] == 0
    assert report["summary"]["core_unknown_relationships"] == 0
    assert report["summary"]["core_fully_resolved_ratio"] == 1.0
    assert report["summary"]["tool_relationships"] == 1
    assert report["summary"]["mcp_relationships"] == 1
    assert report["summary"]["relationships_with_identity"] == 2
    assert report["summary"]["relationships_with_approval_evidence"] == 2
    assert report["summary"]["relationships_with_destination_evidence"] == 2


def test_effective_authority_includes_inherited_agent_tool_control(tmp_path: Path) -> None:
    location = SourceLocation(tmp_path / "agent.py", line=4)
    graph = Graph(
        agents=[
            Agent(
                name="controlled",
                tools=[
                    Tool(
                        name="write",
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

    relationship = effective_authority_report(graph)["relationships"][0]

    assert relationship["dimensions"]["approval"] == "resolved"
    assert relationship["approval"]["inherited_control"] is True
    assert relationship["approval"]["mechanism"] == "adk_before_tool_callback"
    assert "approval" not in relationship["unresolved"]


def test_effective_authority_does_not_credit_callback_presence_without_enforcement(
    tmp_path: Path,
) -> None:
    location = SourceLocation(tmp_path / "agent.py", line=4)
    graph = Graph(
        agents=[
            Agent(
                name="observed_only",
                tools=[
                    Tool(
                        name="write",
                        kind="function",
                        capabilities={"data.write"},
                        location=location,
                    )
                ],
                location=location,
                metadata={
                    "callbacks": {"before_tool_callback": "log_only"},
                    "tool_control_state": "non_enforcing",
                    "tool_control_enforcing": False,
                },
            )
        ]
    )
    graph.adg = build_adg(graph, tmp_path)

    relationship = effective_authority_report(graph)["relationships"][0]

    assert relationship["dimensions"]["approval"] == "unknown"
    assert relationship["approval"]["inherited_control"] is False
    assert "approval" in relationship["unresolved"]


def test_effective_authority_excludes_workflow_projection_tools(tmp_path: Path) -> None:
    location = SourceLocation(tmp_path / "workflow.py", line=8)
    projected = Tool(
        name="normalize",
        kind="langgraph_node",
        capabilities={"data.read"},
        location=location,
        metadata={
            "framework": "langgraph",
            "authority_binding": "workflow_projection",
            "authority_binding_basis": "langgraph_add_node",
        },
    )
    graph = Graph(
        agents=[
            Agent(
                name="workflow",
                tools=[projected],
                location=location,
                metadata={"framework": "langgraph"},
            )
        ]
    )
    graph.adg = build_adg(graph, tmp_path)

    report = effective_authority_report(graph)

    assert report["relationships"] == []
    projected_node = next(
        node
        for node in graph.adg.nodes
        if node.kind == "tool" and node.attributes.get("tool_name") == "normalize"
    )
    assert projected_node.attributes["authority_binding"] == "workflow_projection"
    assert not any(
        edge.kind == "INVOKES" and edge.target == projected_node.node_id
        for edge in graph.adg.edges
    )


def test_effective_authority_exposes_agent_as_tool_binding_provenance(
    tmp_path: Path,
) -> None:
    location = SourceLocation(tmp_path / "agent.py", line=10)
    graph = Graph(
        agents=[
            Agent(
                name="Manager",
                tools=[
                    Tool(
                        name="web_search",
                        kind="delegated_agent",
                        capabilities={"agent.delegate"},
                        location=location,
                        metadata={
                            "framework": "openai-agents",
                            "binding_origin": "agent_as_tool",
                            "delegate_target": "search_agent",
                        },
                    )
                ],
                location=location,
            )
        ]
    )
    graph.adg = build_adg(graph, tmp_path)

    relationship = effective_authority_report(graph)["relationships"][0]

    assert relationship["target"] == {"kind": "tool", "name": "web_search"}
    assert relationship["semantics"]["binding_origin"] == "agent_as_tool"
    assert relationship["semantics"]["delegate_target"] == "search_agent"



def test_effective_authority_surfaces_csharp_repository_effect_evidence(
    tmp_path: Path,
) -> None:
    binding = SourceLocation(tmp_path / "Program.cs", line=20, column=9)
    implementation = SourceLocation(
        tmp_path / "Tools" / "CurrencyConverterTool.cs",
        line=43,
        column=35,
    )
    destination_location = SourceLocation(
        tmp_path / "Tools" / "CurrencyConverterTool.cs",
        line=18,
        column=39,
    )
    tool = Tool(
        name="ConvertCurrency",
        kind="function",
        capabilities={"data.read", "network.external"},
        destinations=[
            NetworkDestination(
                target="https://open.er-api.com/v6/",
                restricted=True,
                location=destination_location,
                metadata={
                    "source": "csharp_class_base_address",
                    "repository_effect_summary": True,
                    "source_symbol": (
                        "CurrencyConverterTool.ConvertCurrency"
                    ),
                },
            )
        ],
        location=binding,
        metadata={
            "framework": "microsoft-agent-framework-dotnet",
            "binding_origin": "AIFunctionFactory.Create",
            "repository_effect_resolution": "resolved",
            "repository_effect_resolved": True,
            "repository_effect_partial": False,
            "repository_effect_unresolved_calls": [],
            "repository_effect_sources": [
                "Tools/CurrencyConverterTool.cs"
            ],
            "repository_effect_evidence_details": [
                {
                    "path": "Tools/CurrencyConverterTool.cs",
                    "line": 34,
                    "column": 5,
                    "symbol": (
                        "CurrencyConverterTool.ConvertCurrency"
                    ),
                    "kind": "csharp_method",
                }
            ],
            "repository_effect_capability_evidence": {
                "network.external": [
                    {
                        "path": "Tools/CurrencyConverterTool.cs",
                        "line": implementation.line,
                        "column": implementation.column,
                        "symbol": (
                            "CurrencyConverterTool.ConvertCurrency"
                        ),
                        "kind": "csharp_effect",
                    }
                ]
            },
        },
    )
    graph = Graph(
        agents=[
            Agent(
                name="ItineraryPlannerAgent",
                tools=[tool],
                location=binding,
            )
        ]
    )
    graph.adg = build_adg(graph, tmp_path)

    relationship = effective_authority_report(graph)["relationships"][0]

    assert relationship["location"]["path"].endswith("Program.cs")
    assert relationship["dimensions"]["source_effects"] == "resolved"
    assert relationship["semantics"]["source_effect_resolution"] == "resolved"
    assert relationship["semantics"]["source_effect_partial"] is False
    assert relationship["semantics"]["source_effect_sources"] == [
        "Tools/CurrencyConverterTool.cs"
    ]

    evidence = relationship["evidence"]
    assert any(item["kind"] == "INVOKES" for item in evidence)
    assert any(
        item["kind"] == "SOURCE_METHOD"
        and item["symbol"] == "CurrencyConverterTool.ConvertCurrency"
        and item["location"]["path"] == "Tools/CurrencyConverterTool.cs"
        and item["location"]["line"] == 34
        for item in evidence
    )
    assert any(
        item["kind"] == "SOURCE_EFFECT"
        and item.get("effect") == "capability"
        and item.get("capability") == "network.external"
        and item["location"]["path"] == "Tools/CurrencyConverterTool.cs"
        and item["location"]["line"] == 43
        for item in evidence
    )
    assert any(
        item["kind"] == "SOURCE_EFFECT"
        and item.get("effect") == "destination"
        and item.get("target") == "https://open.er-api.com/v6/"
        and item["location"]["line"] == 18
        for item in evidence
    )


def test_effective_authority_marks_partial_csharp_source_effects(
    tmp_path: Path,
) -> None:
    location = SourceLocation(tmp_path / "Program.cs", line=10)
    tool = Tool(
        name="Entry",
        kind="function",
        capabilities={"data.read"},
        location=location,
        metadata={
            "framework": "microsoft-agent-framework-dotnet",
            "repository_effect_resolution": "partial",
            "repository_effect_resolved": False,
            "repository_effect_partial": True,
            "repository_effect_unresolved_calls": ["Send"],
            "repository_effect_sources": ["OverloadedTool.cs"],
        },
    )
    graph = Graph(
        agents=[
            Agent(
                name="PartialAgent",
                tools=[tool],
                location=location,
            )
        ]
    )
    graph.adg = build_adg(graph, tmp_path)

    relationship = effective_authority_report(graph)["relationships"][0]

    assert relationship["resolution"] == "partially_resolved"
    assert relationship["core_resolution"] == "partially_resolved"
    assert relationship["core_dimensions"]["source_effects"] == (
        "partially_resolved"
    )
    assert relationship["core_unresolved"] == ["source_effects"]
    assert relationship["dimensions"]["source_effects"] == (
        "partially_resolved"
    )
    assert "source_effects" in relationship["unresolved"]
    assert relationship["semantics"]["source_effect_resolution"] == "partial"
    assert relationship["semantics"]["source_effect_partial"] is True
    assert relationship["semantics"]["source_effect_unresolved_calls"] == [
        "Send"
    ]


def test_duplicate_local_identity_does_not_assign_arbitrary_permissions(tmp_path: Path) -> None:
    graph = _graph(tmp_path)
    graph.agents[0].identities.append(
        Identity(name="support-agent", provider="aws", permissions={"admin:*"})
    )
    report = effective_authority_report(graph)
    for kind, target in (("tool", "update_ticket"), ("mcp_server", "github")):
        relationship = _relationship(report, kind, target)
        assert relationship["identity"] is None
        assert "identity" in relationship["unresolved"]


def test_unique_local_identity_shadows_graph_identity(tmp_path: Path) -> None:
    graph = _graph(tmp_path)
    graph.identities.append(
        Identity(name="support-agent", provider="aws", permissions={"admin:*"})
    )
    relationship = _relationship(effective_authority_report(graph), "tool", "update_ticket")
    assert relationship["identity"]["provider"] == "gcp"
    assert relationship["identity"]["roles"] == ["roles/viewer"]
