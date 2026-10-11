"""Dynamic delegation is unresolved evidence, not an invented agent edge."""
from horustrace.models import Agent, Graph, Tool
from horustrace.semantic_contract import validate_graph_semantics


def _errors(metadata: dict) -> list[str]:
    graph = Graph(
        agents=[
            Agent(
                name="orchestrator",
                tools=[
                    Tool(
                        name="runtime-subagents",
                        kind="delegated_agent",
                        capabilities={"agent.delegate"},
                        metadata=metadata,
                    ),
                ],
            )
        ]
    )
    return validate_graph_semantics(graph)


def test_runtime_swarm_is_explicitly_unresolved_not_invalid() -> None:
    assert _errors({
        "binding_unresolved": True,
        "dynamic_bound_collection": True,
        "delegation_scope_unresolved": True,
        "authority_binding": "swarm_membership",
    }) == []


def test_claude_dynamic_registry_is_explicitly_unresolved_not_invalid() -> None:
    assert _errors({
        "delegate_target_unresolved": True,
        "authority_binding": "dynamic_agent_registry",
    }) == []


def test_partial_or_false_dynamic_markers_do_not_bypass_contract() -> None:
    for metadata in (
        {},
        {"binding_unresolved": True},
        {"dynamic_bound_collection": True, "delegation_scope_unresolved": True},
        {"delegate_target_unresolved": False},
    ):
        assert any(
            "delegated_agent must declare delegate_target" in error
            for error in _errors(metadata)
        )


def test_resolved_and_unresolved_target_are_mutually_exclusive() -> None:
    assert any("must not assert" in error for error in _errors({
        "delegate_target": "agent-a",
        "delegate_target_unresolved": True,
    }))


def test_concrete_delegation_keeps_its_resolved_target() -> None:
    assert _errors({"delegate_target": "agent-a"}) == []
