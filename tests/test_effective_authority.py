from pathlib import Path

from horustrace.adg import build_adg
from horustrace.effective_authority import effective_authority_report
from horustrace.models import (
    Agent,
    EvidenceFact,
    Graph,
    Identity,
    MCPServer,
    NetworkDestination,
    ResourceScope,
    Skill,
    SourceLocation,
    Tool,
)
from horustrace.semantic_contract import (
    DataConnectionResolution,
    set_data_resource_provenance,
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


def test_identity_source_provenance_is_preserved_for_tool_and_mcp(
    tmp_path: Path,
) -> None:
    graph = _graph(tmp_path)
    identity = graph.agents[0].identities[0]
    location = SourceLocation(tmp_path / "deployment.yaml", line=12)
    identity.provenance.append(
        EvidenceFact(
            subject="support-agent",
            fact="identity bound through declared workload configuration",
            origin="source_config",
            location=location,
        )
    )
    report = effective_authority_report(graph)
    for kind, target in (("tool", "update_ticket"), ("mcp_server", "github")):
        relationship = _relationship(report, kind, target)
        assert relationship["identity"]["location"]["path"].endswith("agent.py")
        assert relationship["identity"]["provenance"] == [
            {
                "subject": "support-agent",
                "fact": "identity bound through declared workload configuration",
                "origin": "source_config",
                "location": {
                    "path": str(location.path),
                    "line": 12,
                    "column": 1,
                },
            }
        ]
        assert relationship["semantics"]["identity_binding"] == {
            "reference": "support-agent",
            "resolution": "agent_local",
        }
        assert relationship["runtime_effectiveness"] == "not_verified"


def test_identity_scope_and_missing_reference_are_not_conflated(tmp_path: Path) -> None:
    graph = _graph(tmp_path)
    graph.identities = list(graph.agents[0].identities)
    graph.agents[0].identities = []
    report = effective_authority_report(graph)
    tool = _relationship(report, "tool", "update_ticket")
    assert tool["semantics"]["identity_binding"] == {
        "reference": "support-agent",
        "resolution": "graph_wide",
    }
    assert tool["identity"]["name"] == "support-agent"
    assert tool["identity"]["provenance"] == []

    graph.agents[0].tools[0].identity = "not-present"
    missing = _relationship(
        effective_authority_report(graph), "tool", "update_ticket"
    )
    assert missing["identity"] is None
    assert missing["semantics"]["identity_binding"] == {
        "reference": "not-present",
        "resolution": "unresolved_reference",
    }
    assert "identity" in missing["unresolved"]


def test_ambiguous_identity_reports_resolution_without_iam_attribution(
    tmp_path: Path,
) -> None:
    graph = _graph(tmp_path)
    graph.agents[0].identities.append(
        Identity(name="support-agent", provider="aws", permissions={"admin:*"})
    )
    report = effective_authority_report(graph)
    for kind, target in (("tool", "update_ticket"), ("mcp_server", "github")):
        relationship = _relationship(report, kind, target)
        assert relationship["identity"] is None
        assert relationship["semantics"]["identity_binding"] == {
            "reference": "support-agent",
            "resolution": "ambiguous_agent_local",
        }
        assert relationship["dimensions"]["identity"] == "unknown"


def test_identity_authority_keeps_iam_roles_permissions_and_oauth_separate(
    tmp_path: Path,
) -> None:
    graph = _graph(tmp_path)
    identity = graph.agents[0].identities[0]
    identity.permissions = {"storage.objects.get"}
    identity.oauth_scopes = {"https://www.googleapis.com/auth/cloud-platform"}
    identity.resource_scope = "projects/demo-prod/buckets/reports"

    report = effective_authority_report(graph)
    expected = {
        "declared_roles": ["roles/viewer"],
        "declared_permissions": ["storage.objects.get"],
        "declared_oauth_scopes": [
            "https://www.googleapis.com/auth/cloud-platform"
        ],
        "resource_scope": "projects/demo-prod/buckets/reports",
        "resource_scope_resolution": "declared",
        "role_permission_expansion": "unresolved",
        "oauth_scopes_are_iam_permissions": False,
        "runtime_effectiveness": "not_verified",
    }
    for kind, target in (("tool", "update_ticket"), ("mcp_server", "github")):
        relationship = _relationship(report, kind, target)
        assert relationship["identity"]["authority_evidence"] == expected
        assert relationship["identity"]["permissions"] == ["storage.objects.get"]
        assert relationship["runtime_effectiveness"] == "not_verified"


def test_identity_role_only_does_not_imply_permission_or_global_scope(
    tmp_path: Path,
) -> None:
    report = effective_authority_report(_graph(tmp_path))
    for kind, target in (("tool", "update_ticket"), ("mcp_server", "github")):
        relationship = _relationship(report, kind, target)
        iam = relationship["identity"]["authority_evidence"]
        assert iam["declared_roles"] == ["roles/viewer"]
        assert iam["declared_permissions"] == []
        assert iam["declared_oauth_scopes"] == []
        assert iam["resource_scope"] is None
        assert iam["resource_scope_resolution"] == "unknown"
        assert iam["role_permission_expansion"] == "unresolved"
        assert iam["runtime_effectiveness"] == "not_verified"


def test_missing_identity_does_not_invent_iam_authority(tmp_path: Path) -> None:
    graph = _graph(tmp_path)
    graph.agents[0].tools[0].identity = "missing"
    relationship = _relationship(
        effective_authority_report(graph), "tool", "update_ticket"
    )
    assert relationship["identity"] is None
    assert relationship["semantics"]["identity_binding"]["resolution"] == (
        "unresolved_reference"
    )


def test_dynamic_resource_selector_keeps_source_evidence_and_partial_authority(
    tmp_path: Path,
) -> None:
    graph = _graph(tmp_path)
    location = SourceLocation(tmp_path / "storage.py", line=17)
    resource = ResourceScope(
        kind="bucket",
        selector="current-bucket",
        access={"data.read"},
        location=location,
        provenance=[
            EvidenceFact(
                subject="bucket",
                fact="selector supplied through runtime configuration",
                origin="source_code",
                location=location,
            )
        ],
    )
    # The rendered selector looks concrete, but the producer can prove it is
    # dynamically selected. Respect the explicit canonical resolution.
    set_data_resource_provenance(
        resource,
        resolution=DataConnectionResolution.DYNAMIC,
        source_reference="storage.py:17",
    )
    graph.agents[0].tools[0].resources = [resource]
    relationship = _relationship(
        effective_authority_report(graph), "tool", "update_ticket"
    )

    assert relationship["dimensions"]["resources"] == "partially_resolved"
    assert "resource_selector" in relationship["unresolved"]
    projected = relationship["resources"][0]
    assert projected["selector"] == "current-bucket"
    assert projected["selector_resolution"] == "dynamic"
    assert projected["selector_authority_status"] == "partially_resolved"
    assert projected["access"] == ["data.read"]
    assert projected["access_resolution"] == "declared"
    assert projected["provenance"] == [
        {
            "subject": "bucket",
            "fact": "selector supplied through runtime configuration",
            "origin": "source_code",
            "location": {
                "path": str(location.path),
                "line": 17,
                "column": 1,
            },
        }
    ]
    assert relationship["runtime_effectiveness"] == "not_verified"


def test_resource_certainty_is_shared_by_mcp_servers_and_skills(
    tmp_path: Path,
) -> None:
    graph = _graph(tmp_path)
    unresolved = ResourceScope(
        kind="database",
        selector="<model-selected-data-store>",
        access={"data.read"},
    )
    graph.agents[0].mcp_servers[0].resources = [unresolved]
    graph.agents[0].skills = [
        Skill(
            name="retrieve",
            resources=[ResourceScope(kind="bucket", selector="*")],
        )
    ]
    report = effective_authority_report(graph)
    mcp = _relationship(report, "mcp_server", "github")
    skill = _relationship(report, "skill", "retrieve")
    assert mcp["resources"][0]["selector_resolution"] == "model_selected"
    assert mcp["dimensions"]["resources"] == "partially_resolved"
    assert "resource_selector" in mcp["unresolved"]
    assert skill["resources"][0]["selector_resolution"] == "broad_or_unknown"
    assert skill["dimensions"]["resources"] == "unknown"
    assert "resource_selector" in skill["unresolved"]


def test_resource_scope_mixed_and_missing_cases_do_not_overclaim(
    tmp_path: Path,
) -> None:
    graph = _graph(tmp_path)
    fixed = ResourceScope(
        kind="bucket", selector="production-reports", access={"data.read"}
    )
    undisclosed = ResourceScope(kind="bucket", selector="bucket-from-configuration")
    set_data_resource_provenance(
        undisclosed,
        resolution=DataConnectionResolution.NOT_EXPOSED,
        limitation="resource name is not visible at source review",
    )
    graph.agents[0].tools[0].resources = [fixed, undisclosed]
    relationship = _relationship(
        effective_authority_report(graph), "tool", "update_ticket"
    )
    assert relationship["dimensions"]["resources"] == "partially_resolved"
    assert relationship["resources"][0]["selector_resolution"] == "resolved"
    assert relationship["resources"][1]["selector_resolution"] == "not_exposed"
    assert relationship["resources"][1]["access_resolution"] == "unknown"

    graph.agents[0].tools[0].resources = [fixed]
    fixed_only = _relationship(
        effective_authority_report(graph), "tool", "update_ticket"
    )
    assert fixed_only["dimensions"]["resources"] == "resolved"
    assert "resource_selector" not in fixed_only["unresolved"]

    # Malformed explicit metadata must not be treated as resolved just because
    # the selector is a plausible literal.
    fixed.metadata["data_connection_resolution"] = "invalid"
    invalid = _relationship(
        effective_authority_report(graph), "tool", "update_ticket"
    )
    assert invalid["dimensions"]["resources"] == "unknown"
    assert invalid["resources"][0]["selector_resolution"] == "broad_or_unknown"


def test_dynamic_egress_target_is_not_claimed_as_fixed(
    tmp_path: Path,
) -> None:
    graph = _graph(tmp_path)
    location = SourceLocation(tmp_path / "network.py", line=21)
    graph.agents[0].tools[0].destinations = [
        NetworkDestination(
            target="https://${SERVICE_HOST}/v1",
            restricted=True,
            location=location,
            provenance=[
                EvidenceFact(
                    subject="service-host",
                    fact="endpoint host supplied by runtime environment",
                    origin="source_code",
                    location=location,
                )
            ],
        )
    ]
    relationship = _relationship(
        effective_authority_report(graph), "tool", "update_ticket"
    )
    assert relationship["dimensions"]["destinations"] == "partially_resolved"
    assert "destination_target" in relationship["unresolved"]
    destination = relationship["destinations"][0]
    assert destination["target"] == "https://${SERVICE_HOST}/v1"
    assert destination["target_authority_status"] == "partially_resolved"
    assert destination["restriction_enforcement"] == "not_verified"
    assert destination["provenance"][0]["origin"] == "source_code"
    assert destination["provenance"][0]["location"]["line"] == 21


def test_operator_configured_mcp_endpoint_is_not_resolved(
    tmp_path: Path,
) -> None:
    graph = _graph(tmp_path)
    server = graph.agents[0].mcp_servers[0]
    server.url = None
    server.metadata["dynamic_mcp_endpoint_basis"] = "operator_configuration"
    server.metadata["configuration_source"] = "runtime_settings"
    server.metadata["dynamic_mcp_endpoint"] = False
    relationship = _relationship(
        effective_authority_report(graph), "mcp_server", "github"
    )
    assert relationship["dimensions"]["destinations"] == "partially_resolved"
    assert "destination_target" in relationship["unresolved"]
    assert relationship["semantics"]["destination_binding_resolution"] == (
        "operator_configured"
    )
    assert relationship["capabilities"] == ["mcp.remote", "network.external"]
    assert relationship["destinations"][0]["target"] == "<operator-configured-mcp>"
    assert relationship["destinations"][0]["target_authority_status"] == (
        "partially_resolved"
    )
    assert relationship["destinations"][0]["restriction_enforcement"] == (
        "not_verified"
    )


def test_environment_allowed_hosts_bound_mcp_egress_without_runtime_claim(
    tmp_path: Path,
) -> None:
    graph = _graph(tmp_path)
    server = graph.agents[0].mcp_servers[0]
    server.url = None
    server.metadata["network_scope"] = "environment_allowlist"
    server.metadata["environment_allowed_hosts"] = ["mcp.internal.example"]
    relationship = _relationship(
        effective_authority_report(graph), "mcp_server", "github"
    )
    assert relationship["dimensions"]["destinations"] == "resolved"
    assert relationship["semantics"]["destination_binding_resolution"] == (
        "host_allowlist"
    )
    assert relationship["capabilities"] == ["mcp.remote", "network.external"]
    assert relationship["destinations"][0]["target"] == "mcp.internal.example"
    assert relationship["destinations"][0]["restriction_enforcement"] == (
        "not_verified"
    )


def test_skill_egress_wildcard_is_unknown_not_resolved(
    tmp_path: Path,
) -> None:
    graph = _graph(tmp_path)
    graph.agents[0].skills = [
        Skill(
            name="external-fetch",
            destinations=[
                NetworkDestination(target="*", restricted=False)
            ],
        )
    ]
    relationship = _relationship(
        effective_authority_report(graph), "skill", "external-fetch"
    )
    assert relationship["dimensions"]["destinations"] == "unknown"
    assert "destination_target" in relationship["unresolved"]
    assert relationship["destinations"][0]["target_authority_status"] == "unknown"


def test_fixed_destination_preserves_resolved_scope(tmp_path: Path) -> None:
    report = effective_authority_report(_graph(tmp_path))
    for kind, target in (("tool", "update_ticket"), ("mcp_server", "github")):
        relationship = _relationship(report, kind, target)
        assert relationship["dimensions"]["destinations"] == "resolved"
        assert relationship["destinations"][0]["restriction_enforcement"] == (
            "not_verified"
        )
        assert "destination_target" not in relationship["unresolved"]
