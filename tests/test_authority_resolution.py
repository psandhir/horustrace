from horustrace.authority_resolution import (
    authority_resolution_summary,
    compare_authority_resolution,
    exceeds_unresolved_budget,
)
from horustrace.models import Agent, Graph, Tool


def _graph(*, resolved: int, unresolved: int) -> Graph:
    tools = [
        Tool(
            name=f"resolved_{index}",
            kind="function",
            capabilities={"data.read"},
            approval=True,
        )
        for index in range(resolved)
    ]
    for tool in tools:
        tool.resources = []
        tool.destinations = []

    unresolved_tools = [
        Tool(
            name=f"unresolved_{index}",
            kind="function",
            capabilities={"data.read"},
        )
        for index in range(unresolved)
    ]
    return Graph(agents=[Agent(name="agent", tools=[*tools, *unresolved_tools])])


def test_authority_resolution_summary_counts_unresolved_relationships() -> None:
    graph = _graph(resolved=0, unresolved=2)
    summary = authority_resolution_summary(graph)

    assert summary["relationships"] == 2
    assert summary["unresolved_relationships"] == 2
    assert summary["fully_resolved_ratio"] == 0.0
    assert summary["detail_fully_resolved_ratio"] == 0.0
    assert summary["core_fully_resolved_relationships"] == 2
    assert summary["core_unresolved_relationships"] == 0
    assert summary["core_fully_resolved_ratio"] == 1.0
    assert summary["core_unresolved_dimensions"] == {}
    assert summary["unresolved_dimensions"]["approval"] == 2
    assert summary["runtime_effectiveness"] == "not_verified"


def test_authority_resolution_regression_is_change_aware() -> None:
    base = _graph(resolved=0, unresolved=1)
    head = _graph(resolved=0, unresolved=2)

    comparison = compare_authority_resolution(base, head)

    assert comparison["unresolved_relationship_delta"] == 1
    assert comparison["regressed"] is True
    assert comparison["core_unresolved_relationship_delta"] == 0
    assert comparison["core_regressed"] is False



def test_core_resolution_regression_tracks_unknown_capability_surface() -> None:
    base = Graph(
        agents=[
            Agent(
                name="agent",
                tools=[
                    Tool(
                        name="known",
                        kind="function",
                        capabilities={"data.read"},
                    )
                ],
            )
        ]
    )
    head = Graph(
        agents=[
            Agent(
                name="agent",
                tools=[
                    Tool(
                        name="unknown",
                        kind="function",
                    )
                ],
            )
        ]
    )

    comparison = compare_authority_resolution(base, head)

    assert comparison["core_unresolved_relationship_delta"] == 1
    assert comparison["core_regressed"] is True


def test_strict_unresolved_budget_is_not_weakened_by_core_resolution() -> None:
    graph = _graph(resolved=0, unresolved=2)
    summary = authority_resolution_summary(graph)

    assert summary["core_fully_resolved_ratio"] == 1.0
    assert summary["unresolved_relationships"] == 2
    assert exceeds_unresolved_budget(graph, 1) is True

def test_authority_resolution_does_not_regress_when_debt_is_unchanged() -> None:
    comparison = compare_authority_resolution(
        _graph(resolved=0, unresolved=2),
        _graph(resolved=0, unresolved=2),
    )

    assert comparison["unresolved_relationship_delta"] == 0
    assert comparison["regressed"] is False


def test_absolute_unresolved_budget() -> None:
    graph = _graph(resolved=0, unresolved=2)

    assert exceeds_unresolved_budget(graph, 1) is True
    assert exceeds_unresolved_budget(graph, 2) is False
