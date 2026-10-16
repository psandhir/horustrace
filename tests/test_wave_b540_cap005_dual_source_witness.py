"""CAP005 dual-leg source evidence, not inferred runtime authority.

Wave B #540: a combined read/write finding must never inherit a different
agent instance's facts or fabricate a resolved authority relationship.
"""
from __future__ import annotations

from pathlib import Path

from horustrace.models import (
    Agent, DataSource, EvidenceFact, Finding, Graph, Severity, SourceLocation, Tool,
)
from horustrace.provenance import attach_findings


def _tool(root: Path, name: str, line: int, capabilities: set[str], *,
          origin: str = "inferred", internal: bool = False) -> Tool:
    location = SourceLocation(root / "module.py", line)
    return Tool(
        name=name,
        kind="strands_vended_tool",
        capabilities=capabilities,
        location=location,
        metadata={"agent_internal_artifact": internal},
        provenance=[
            EvidenceFact(name, f"capability={cap}", origin, location)
            for cap in sorted(capabilities)
        ] + [
            EvidenceFact(name, "source_import=strands_tools." + name, "observed", location)
        ],
    )


def _finding(location: SourceLocation | None) -> Finding:
    return Finding(
        "CAP005", Severity.MEDIUM,
        "Combined read and write authority", "message", "recommendation",
        layer=2, location=location, agent="agent",
        evidence=[
            "data.read", "data.write/destructive.write",
            "authority_relationship=authority-v1:unverified-edge",
        ],
    )


def test_cap005_attaches_two_source_legs_only_not_every_import_fact(
    tmp_path: Path,
) -> None:
    shell = _tool(
        tmp_path, "shell", 18,
        {"data.read", "data.write", "process.execute", "network.external"},
    )
    agent = Agent(
        name="agent", location=SourceLocation(tmp_path / "module.py", 75),
        tools=[shell],
    )
    finding = _finding(agent.location)
    attach_findings(Graph(agents=[agent]), [finding])
    assert {fact.fact for fact in finding.provenance} == {
        "capability=data.read", "capability=data.write",
    }
    assert all(fact.origin == "inferred" for fact in finding.provenance)
    assert all(fact.location == shell.location for fact in finding.provenance)
    assert not any("authority_relationship" in fact.fact for fact in finding.provenance)


def test_cap005_read_write_different_tools_keep_respective_source_origins(
    tmp_path: Path,
) -> None:
    reading = _tool(tmp_path, "file_read", 8, {"data.read"}, origin="observed")
    writing = _tool(tmp_path, "file_write", 14, {"data.write"}, origin="inferred")
    agent = Agent(
        name="agent", location=SourceLocation(tmp_path / "module.py", 20),
        tools=[reading, writing],
    )
    finding = _finding(agent.location)
    attach_findings(Graph(agents=[agent]), [finding])
    assert [(fact.subject, fact.origin, fact.location.line) for fact in finding.provenance] == [
        ("file_read", "observed", 8),
        ("file_write", "inferred", 14),
    ]


def test_cap005_missing_write_leg_never_invents_source_evidence(
    tmp_path: Path,
) -> None:
    agent = Agent(
        name="agent", location=SourceLocation(tmp_path / "module.py", 20),
        tools=[_tool(tmp_path, "file_read", 7, {"data.read"})],
    )
    finding = _finding(agent.location)
    attach_findings(Graph(agents=[agent]), [finding])
    assert finding.provenance == []


def test_cap005_ignores_internal_artifact_as_effective_write_witness(
    tmp_path: Path,
) -> None:
    agent = Agent(
        name="agent", location=SourceLocation(tmp_path / "module.py", 20),
        tools=[
            _tool(tmp_path, "file_read", 7, {"data.read"}),
            _tool(tmp_path, "internal_state", 8, {"data.write"}, internal=True),
        ],
    )
    finding = _finding(agent.location)
    attach_findings(Graph(agents=[agent]), [finding])
    assert finding.provenance == []


def test_cap005_same_name_agent_instances_do_not_combine_read_and_write(
    tmp_path: Path,
) -> None:
    first = Agent(
        name="agent", location=SourceLocation(tmp_path / "first.py", 30),
        tools=[_tool(tmp_path, "first_read", 4, {"data.read"})],
    )
    second = Agent(
        name="agent", location=SourceLocation(tmp_path / "second.py", 50),
        tools=[_tool(tmp_path, "second_write", 8, {"data.write"})],
    )
    for location in (first.location, second.location, None):
        finding = _finding(location)
        attach_findings(Graph(agents=[first, second]), [finding])
        assert finding.provenance == []


def test_cap005_data_sources_can_supply_independent_leg(
    tmp_path: Path,
) -> None:
    read_location = SourceLocation(tmp_path / "manifest.yaml", 7)
    source = DataSource(
        name="database", capability="data.read", location=read_location,
        provenance=[
            EvidenceFact("database", "capability=data.read", "declared", read_location),
        ],
    )
    writer = _tool(tmp_path, "writer", 18, {"data.write"})
    agent = Agent(
        name="agent", location=SourceLocation(tmp_path / "module.py", 40),
        tools=[writer], data_sources=[source],
    )
    finding = _finding(agent.location)
    attach_findings(Graph(agents=[agent]), [finding])
    assert {fact.fact for fact in finding.provenance} == {
        "capability=data.read", "capability=data.write",
    }
    assert {fact.origin for fact in finding.provenance} == {"declared", "inferred"}


def test_cap005_requires_located_capability_facts(
    tmp_path: Path,
) -> None:
    reader = _tool(tmp_path, "reader", 4, {"data.read"})
    reader.provenance = [EvidenceFact("reader", "capability=data.read", "inferred")]
    writer = _tool(tmp_path, "writer", 5, {"data.write"})
    agent = Agent(
        name="agent", location=SourceLocation(tmp_path / "module.py", 50),
        tools=[reader, writer],
    )
    finding = _finding(agent.location)
    attach_findings(Graph(agents=[agent]), [finding])
    assert finding.provenance == []
