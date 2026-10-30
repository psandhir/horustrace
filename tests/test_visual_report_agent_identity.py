"""Regression: same-named Pydantic agents must not share security evidence.

The three-repository study PR #653 exposed the failure: local `agent` aliases
in different files were merged by report presentation. These fixtures deliberately
reproduce the underlying source pattern without executing upstream projects.
"""
from pathlib import Path

from horustrace.adg import build_adg
from horustrace.models import (
    Agent,
    AttackPath,
    Finding,
    Graph,
    Severity,
    SourceLocation,
    Tool,
)
from horustrace.visual_report import build_visual_report, render_visual_report_html


def _three_same_named_agents(root: Path) -> tuple[Graph, list[Finding]]:
    runtime = SourceLocation(root / "src" / "service.py", line=12)
    example = SourceLocation(root / "examples" / "basic_capability.py", line=12)
    test = SourceLocation(root / "tests" / "test_agent.py", line=28)
    agents = [
        Agent(
            name="agent",
            location=runtime,
            metadata={"framework": "pydantic-ai"},
            tools=[Tool(
                name="runtime_network",
                kind="function",
                capabilities={"network.external"},
                location=runtime,
            )],
        ),
        Agent(name="agent", location=example, metadata={"framework": "pydantic-ai"}),
        Agent(
            name="agent",
            location=test,
            metadata={"framework": "pydantic-ai"},
            tools=[Tool(
                name="test_shell",
                kind="function",
                capabilities={"process.execute"},
                location=test,
            )],
        ),
    ]
    graph = Graph(
        agents=agents,
        attack_paths=[AttackPath(
            path_id="PATH001",
            title="Ambiguous source",
            agent="agent",
            nodes=["agent", "test_shell"],
            severity=Severity.MEDIUM,
            rationale="Name-only attribution is not proof",
            location=test,
        )],
    )
    graph.adg = build_adg(graph, root)
    findings = [Finding(
        rule_id="TEST001",
        severity=Severity.HIGH,
        title="Potential test shell authority",
        message="Name-only finding",
        recommendation="Review source identity",
        location=test,
        agent="agent",
    )]
    return graph, findings


def test_same_name_agent_authority_is_instance_scoped(tmp_path: Path) -> None:
    graph, findings = _three_same_named_agents(tmp_path)
    report = build_visual_report(graph, findings, tmp_path)
    agents = report["agents"]
    by_path = {a["location"]["path"]: a for a in agents}
    runtime = by_path["src/service.py"]
    example = by_path["examples/basic_capability.py"]
    test = by_path["tests/test_agent.py"]

    assert len(agents) == 3
    assert len({a["id"] for a in agents}) == 3
    assert len({a["display_name"] for a in agents}) == 3
    assert all(a["name"] == "agent" for a in agents)
    assert runtime["source_context"] == "runtime"
    assert example["source_context"] == "example"
    assert test["source_context"] == "test"
    assert "::agent@" in example["display_name"]

    # A test shell cannot appear in the example's profile just because both
    # constructors are bound to the ordinary Python variable name "agent".
    assert report["summary"]["authority_relationships"] == 2
    assert runtime["summary"]["authority_relationships"] == 1
    assert test["summary"]["authority_relationships"] == 1
    assert example["summary"]["authority_relationships"] == 0
    assert {r["target"]["name"] for r in runtime["effective_authority"]} == {
        "runtime_network"
    }
    assert {r["target"]["name"] for r in test["effective_authority"]} == {
        "test_shell"
    }
    assert example["effective_authority"] == []
    assert report["summary"]["write_capable_relationships"] == 0 or (
        report["summary"]["write_capable_relationships"]
        == sum(a["summary"]["write_capable_relationships"] for a in agents)
    )

    for entry in report["tools"]:
        expected = runtime if entry["name"] == "runtime_network" else test
        assert entry["bound_agent_ids"] == [expected["id"]]

    # The legacy name-only risk payload remains globally visible, but cannot
    # contaminate any of the same-named per-agent profiles.
    assert report["summary"]["findings"] == 1
    assert report["summary"]["attack_paths"] == 1
    assert report["summary"]["unattributed_findings"] == 1
    assert report["summary"]["unattributed_attack_paths"] == 1
    assert all(a["summary"]["findings"] == 0 for a in agents)
    assert all(a["summary"]["attack_paths"] == 0 for a in agents)
    assert all(a["attribution_ambiguous"] for a in agents)


def test_agent_report_ids_are_portable_and_are_not_exposed_as_checkout_paths(
    tmp_path: Path,
) -> None:
    left, _ = _three_same_named_agents(tmp_path / "checkout_a")
    right, _ = _three_same_named_agents(tmp_path / "checkout_b")
    one = build_visual_report(left, [], tmp_path / "checkout_a")
    two = build_visual_report(right, [], tmp_path / "checkout_b")
    assert [a["id"] for a in one["agents"]] == [a["id"] for a in two["agents"]]
    assert str(tmp_path) not in str(one["agents"])
    assert str(tmp_path) not in str(one["tools"])
    assert [a["name"] for a in one["agents"]] == ["agent"] * 3


def test_agent_inventory_has_explicit_application_and_all_source_views(
    tmp_path: Path,
) -> None:
    graph, findings = _three_same_named_agents(tmp_path)
    html = render_visual_report_html(graph, findings, tmp_path)
    assert 'AGENT_SOURCE_VIEW="application"' in html
    assert 'data-agent-source-filter=' in html
    assert 'sourceViewMatches(a)' in html
    assert "bound_agent_ids" in html
    assert "Ambiguous name-only reference" not in html
    assert "Never choose an arbitrary same-name agent" in html
