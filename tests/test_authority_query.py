from pathlib import Path

from horustrace.authority_query import (
    query_effective_authority,
    render_authority_query_console,
)
from horustrace.models import Agent, Graph, NetworkDestination, Tool


def _graph(tmp_path: Path) -> Graph:
    worker = Agent(
        name="worker",
        tools=[
            Tool(
                name="publish",
                kind="function",
                capabilities={"external.write", "network.external"},
                approval=False,
                destinations=[
                    NetworkDestination(
                        target="https://api.example.test",
                        restricted=True,
                    )
                ],
            )
        ],
    )
    orchestrator = Agent(
        name="orchestrator",
        metadata={"delegates_to": ["worker"]},
    )
    return Graph(agents=[orchestrator, worker])


def test_query_matches_direct_and_delegated_authority(tmp_path: Path) -> None:
    report = query_effective_authority(
        _graph(tmp_path),
        tmp_path,
        capability="external.write",
    )

    assert report["summary"] == {
        "matches": 2,
        "agents": 2,
        "effective_agents": 1,
        "delegated_matches": 1,
    }
    assert [item["agent"] for item in report["results"]] == [
        "orchestrator",
        "worker",
    ]
    delegated = report["results"][0]
    assert delegated["delegation_path"] == ["orchestrator", "worker"]
    assert delegated["effective_agent"] == "worker"


def test_query_filters_destination_and_agent(tmp_path: Path) -> None:
    report = query_effective_authority(
        _graph(tmp_path),
        tmp_path,
        agent="orchestrator",
        destination="*example.test",
    )

    assert report["summary"]["matches"] == 1
    assert report["results"][0]["agent"] == "orchestrator"



def test_query_filters_core_resolution_separately_from_detail(
    tmp_path: Path,
) -> None:
    report = query_effective_authority(
        _graph(tmp_path),
        tmp_path,
        core_resolution="fully_resolved",
    )

    assert report["summary"]["matches"] == 2
    assert report["query"]["core_resolution"] == "fully_resolved"
    assert all(
        item["relationship"]["core_resolution"] == "fully_resolved"
        for item in report["results"]
    )
    assert all(
        item["relationship"]["detail_resolution"] == "partially_resolved"
        for item in report["results"]
    )

def test_query_does_not_infer_ambiguous_delegation(tmp_path: Path) -> None:
    graph = _graph(tmp_path)
    graph.agents.append(Agent(name="worker"))

    report = query_effective_authority(
        graph,
        tmp_path,
        capability="external.write",
    )

    assert report["summary"]["delegated_matches"] == 0
    assert [item["agent"] for item in report["results"]] == ["worker"]


def test_query_requires_a_security_filter(tmp_path: Path) -> None:
    try:
        query_effective_authority(_graph(tmp_path), tmp_path)
    except ValueError as exc:
        assert "requires at least one" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_query_console_explains_delegation_and_runtime_limit(tmp_path: Path) -> None:
    report = query_effective_authority(
        _graph(tmp_path),
        tmp_path,
        agent="orchestrator",
        capability="external.write",
    )

    rendered = render_authority_query_console(report)

    assert "delegation: orchestrator -> worker" in rendered
    assert "capabilities: external.write, network.external" in rendered
    assert "CORE=fully_resolved; DETAIL=partially_resolved" in rendered
    assert "detail unresolved:" in rendered
    assert "runtime effectiveness: not_verified" in rendered
