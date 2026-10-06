from pathlib import Path

import pytest

from horustrace.models import Agent, Graph, Tool
from horustrace.semantic_contract import (
    ToolControlState,
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
