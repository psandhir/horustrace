from horustrace.models import Graph, MCPServer, ResourceScope, Skill, Tool
from horustrace.semantic_contract import validate_graph_semantics


def test_unbound_tool_resource_semantics_are_checked() -> None:
    resource = ResourceScope(
        kind="filesystem",
        selector="data",
        metadata={"data_connection_resolution": "not_a_resolution"},
    )
    graph = Graph(unbound_tools=[Tool(name="files", kind="function", resources=[resource])])
    errors = validate_graph_semantics(graph)
    assert any("invalid data_connection_resolution" in issue for issue in errors)


def test_unresolved_mcp_declarations_are_checked_without_agent_binding() -> None:
    graph = Graph(
        unresolved_mcp_references=[
            MCPServer(
                name="remote",
                transport="sse",
                allowed_tools=[""],
                metadata={"tool_catalogue_unresolved": "unknown"},
            )
        ]
    )
    errors = validate_graph_semantics(graph)
    assert any("tool_catalogue_unresolved must be boolean" in error for error in errors)
    assert any("allowed_tools entries" in error for error in errors)


def test_unbound_skill_capabilities_are_checked() -> None:
    graph = Graph(unbound_skills=[Skill(name="unbound", capabilities={""})])
    assert any("capabilities entries" in error for error in validate_graph_semantics(graph))


def test_valid_unbound_entities_do_not_create_agent_bindings() -> None:
    graph = Graph(unbound_tools=[Tool(name="read", kind="function", capabilities={"data.read"})])
    assert validate_graph_semantics(graph) == []
    assert graph.agents == []
