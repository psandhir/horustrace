"""Regression for Wave B #540: Strands source instances must not merge by label."""
from __future__ import annotations

from pathlib import Path

from horustrace.models import Agent, Graph, SourceLocation, Tool
from horustrace.scanner import _consolidate_agents


def _agent(root: Path, file: str, line: int, *,
           framework: str = "strands-agents",
           instance_key: str | None = None) -> Agent:
    metadata = {"framework": framework}
    if instance_key:
        metadata["instance_key"] = instance_key
    return Agent(
        name="agent",
        location=SourceLocation(root / file, line=line),
        metadata=metadata,
        tools=[Tool(
            name=f"tool_{line}", kind="function",
            location=SourceLocation(root / file, line=line + 1),
        )],
    )


def test_strands_same_name_different_source_instances_remain_distinct(
    tmp_path: Path,
) -> None:
    graph = Graph(agents=[
        _agent(tmp_path, "cfn.py", 92),
        _agent(tmp_path, "writer.py", 72),
        _agent(tmp_path, "pricing.py", 89),
    ])
    _consolidate_agents(graph)
    assert len(graph.agents) == 3
    assert {a.location.path.name for a in graph.agents} == {
        "cfn.py", "writer.py", "pricing.py",
    }
    assert {tool.name for a in graph.agents for tool in a.tools} == {
        "tool_92", "tool_72", "tool_89",
    }
    assert all("instance_key" not in a.metadata for a in graph.agents)


def test_same_line_reobservation_and_explicit_instance_keys_still_merge(
    tmp_path: Path,
) -> None:
    graph = Graph(agents=[
        _agent(tmp_path, "same.py", 10),
        _agent(tmp_path, "same.py", 10),
        _agent(tmp_path, "other.py", 20, instance_key="one"),
        _agent(tmp_path, "other.py", 20, instance_key="one"),
    ])
    _consolidate_agents(graph)
    assert len(graph.agents) == 2
    assert {a.location.line for a in graph.agents} == {10, 20}


def test_distinct_constructor_lines_within_one_source_do_not_merge(
    tmp_path: Path,
) -> None:
    graph = Graph(agents=[
        _agent(tmp_path, "multiple.py", 12),
        _agent(tmp_path, "multiple.py", 34),
    ])
    _consolidate_agents(graph)
    assert len(graph.agents) == 2
    assert {a.location.line for a in graph.agents} == {12, 34}


def test_unrelated_framework_consolidation_contract_unchanged(
    tmp_path: Path,
) -> None:
    # This PR only addresses source-visible Strands constructors; any broader
    # cross-framework identity model needs its own adjudicated contract.
    graph = Graph(agents=[
        _agent(tmp_path, "one.py", 10, framework="other"),
        _agent(tmp_path, "two.py", 20, framework="other"),
    ])
    _consolidate_agents(graph)
    assert len(graph.agents) == 1
    assert {t.name for t in graph.agents[0].tools} == {
        "tool_10", "tool_20",
    }


def test_unlocated_strands_instances_remain_unresolved_under_legacy_key() -> None:
    graph = Graph(agents=[
        Agent(name="agent", metadata={"framework": "strands-agents"}),
        Agent(name="agent", metadata={"framework": "strands-agents"}),
    ])
    _consolidate_agents(graph)
    assert len(graph.agents) == 1
