from pathlib import Path

import pytest

from horustrace.models import Agent, Graph, MCPServer, ResourceScope, Skill, Tool
from horustrace.semantic_contract import (
    DataConnectionResolution,
    ModelResolution,
    ToolControlState,
    set_data_resource_provenance,
    set_model_provenance,
    set_source_context,
    set_tool_control,
    source_context,
    tool_control_enforcing,
    tool_control_mechanism,
    validate_graph_semantics,
)


def test_tool_control_semantics_are_written_atomically() -> None:
    metadata: dict[str, object] = {}

    set_tool_control(
        metadata,
        ToolControlState.ENFORCING,
        mechanism="runtime_guard",
    )

    assert metadata == {
        "tool_control_state": "enforcing",
        "tool_control_enforcing": True,
        "tool_control_mechanism": "runtime_guard",
    }
    assert tool_control_enforcing(metadata) is True
    assert tool_control_mechanism(metadata) == "runtime_guard"


def test_tool_control_state_drives_canonical_enforcement() -> None:
    metadata = {
        "tool_control_state": "non_enforcing",
        "tool_control_enforcing": True,
    }

    assert tool_control_enforcing(metadata) is False
    errors = validate_graph_semantics(
        Graph(agents=[Agent(name="agent", metadata=metadata)])
    )
    assert any("tool_control_enforcing" in error for error in errors)


def test_source_context_uses_controlled_vocabulary() -> None:
    metadata: dict[str, object] = {}
    set_source_context(metadata, "runtime")

    assert source_context(metadata) == "runtime"

    with pytest.raises(ValueError, match="invalid source context"):
        set_source_context(metadata, "production-ish")


def test_semantic_contract_rejects_deprecated_alias() -> None:
    graph = Graph(
        agents=[
            Agent(
                name="agent",
                metadata={"enforcing_tool_control": True},
            )
        ]
    )

    assert any(
        "enforcing_tool_control" in error
        for error in validate_graph_semantics(graph)
    )


def test_delegated_agent_requires_canonical_target() -> None:
    graph = Graph(
        agents=[
            Agent(
                name="parent",
                tools=[Tool(name="child", kind="delegated_agent")],
            )
        ]
    )

    assert any(
        "delegate_target" in error
        for error in validate_graph_semantics(graph)
    )


def test_adapters_do_not_emit_deprecated_tool_control_alias() -> None:
    adapters = Path(__file__).parents[1] / "src" / "horustrace" / "adapters"

    offenders = [
        path.name
        for path in adapters.glob("*.py")
        if "enforcing_tool_control" in path.read_text(encoding="utf-8")
    ]

    assert offenders == []



def test_model_provenance_contract_preserves_partial_resolution() -> None:
    metadata: dict[str, object] = {}

    set_model_provenance(
        metadata,
        provider="amazon-bedrock",
        hosting="provider_hosted",
    )

    assert metadata == {
        "model_provider": "amazon-bedrock",
        "model_hosting": "provider_hosted",
        "model_resolution": "provider_only",
    }
    assert validate_graph_semantics(
        Graph(agents=[Agent(name="agent", metadata=metadata)])
    ) == []


def test_model_provenance_contract_requires_limitation_for_not_exposed() -> None:
    graph = Graph(
        agents=[
            Agent(
                name="hosted",
                metadata={"model_resolution": ModelResolution.NOT_EXPOSED.value},
            )
        ]
    )

    assert any(
        "model_provenance_limitation" in error
        for error in validate_graph_semantics(graph)
    )




def test_data_resource_provenance_is_written_atomically() -> None:
    resource = ResourceScope(
        kind="s3",
        selector="s3://reports/*",
        access={"data.read"},
    )

    set_data_resource_provenance(
        resource,
        provider="aws",
        selector_provenance="literal_configuration",
        resource_provenance="source_configuration",
        source_reference="tool.bucket",
    )

    assert resource.metadata["data_connection_type"] == "object_store"
    assert resource.metadata["data_provider"] == "aws"
    assert resource.metadata["data_connection_resolution"] == "resolved"
    assert resource.metadata["selector_provenance"] == "literal_configuration"
    assert resource.metadata["resource_provenance"] == "source_configuration"
    assert resource.metadata["data_source_reference"] == "tool.bucket"


def test_data_resource_model_selected_selector_has_canonical_resolution() -> None:
    resource = ResourceScope(
        kind="remote_object",
        selector="<model-selected:file_id>",
        access={"data.read"},
    )

    set_data_resource_provenance(
        resource,
        provider="box",
        selector_provenance="model_selected",
        resource_provenance="external_sdk_resource_identifier",
    )

    assert (
        resource.metadata["data_connection_resolution"]
        == DataConnectionResolution.MODEL_SELECTED.value
    )
    assert resource.metadata["data_connection_type"] == "saas_api"


def test_data_resource_not_exposed_requires_limitation() -> None:
    resource = ResourceScope(
        kind="database",
        selector="<unknown>",
        access={"data.read"},
        metadata={"data_connection_resolution": "not_exposed"},
    )
    agent = Agent(
        name="agent",
        tools=[Tool(name="query", kind="function", resources=[resource])],
    )

    errors = validate_graph_semantics(Graph(agents=[agent]))

    assert any("data_connection_limitation" in error for error in errors)



def test_skill_resource_provenance_obeys_shared_semantic_contract() -> None:
    invalid = ResourceScope(
        kind="database",
        selector="<unknown>",
        metadata={"data_connection_resolution": "not_exposed"},
    )
    agent = Agent(name="agent", skills=[Skill(name="lookup", resources=[invalid])])

    errors = validate_graph_semantics(Graph(agents=[agent]))
    assert any("skill 'lookup'" in error and "data_connection_limitation" in error for error in errors)

    valid = ResourceScope(kind="database", selector="<unknown>")
    set_data_resource_provenance(valid, resolution="not_exposed", limitation="runtime-only selector")
    agent.skills[0].resources = [valid]
    assert validate_graph_semantics(Graph(agents=[agent])) == []


@pytest.mark.parametrize("field", ["allowed_tools", "denied_tools"])
def test_mcp_tool_filter_entries_must_be_nonempty_strings(field: str) -> None:
    server = MCPServer(name="remote", transport="stdio")
    setattr(server, field, ["read", ""])
    agent = Agent(name="agent", mcp_servers=[server])
    assert any(field in error for error in validate_graph_semantics(Graph(agents=[agent])))


def test_skill_tool_and_capability_declarations_are_canonical() -> None:
    skill = Skill(name="review", allowed_tools={"", "read"}, capabilities={"data.read"})
    agent = Agent(name="agent", skills=[skill])
    assert any("allowed_tools" in error for error in validate_graph_semantics(Graph(agents=[agent])))
    skill.allowed_tools = {"read"}
    skill.capabilities = {"data.read", ""}
    assert any("capabilities" in error for error in validate_graph_semantics(Graph(agents=[agent])))
    skill.capabilities = {"data.read"}
    assert validate_graph_semantics(Graph(agents=[agent])) == []


@pytest.mark.parametrize("target", ["", "   ", 0, [], {}])
def test_delegated_agent_target_must_be_nonblank_string(target) -> None:
    tool = Tool(name="delegate", kind="delegated_agent", metadata={"delegate_target": target})
    errors = validate_graph_semantics(Graph(agents=[Agent(name="parent", tools=[tool])]))
    assert any("delegate_target" in error for error in errors)


def test_delegated_agent_target_accepts_proven_name() -> None:
    tool = Tool(name="delegate", kind="delegated_agent", metadata={"delegate_target": "child"})
    assert validate_graph_semantics(Graph(agents=[Agent(name="parent", tools=[tool])])) == []
