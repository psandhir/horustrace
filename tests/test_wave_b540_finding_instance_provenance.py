"""Duplicate-name agent instances may only use their own source evidence."""
from __future__ import annotations

from pathlib import Path

from horustrace.models import Agent, EvidenceFact, Finding, Graph, Severity, SourceLocation, Tool
from horustrace.provenance import _source_instance_for_finding, attach_findings


def _instance(root: Path, module: str, line: int) -> Agent:
    location = SourceLocation(root / module, line=line)
    tool_location = SourceLocation(root / module, line=line - 10)
    tool_name = "exec_" + module.removesuffix(".py")
    tool = Tool(
        name=tool_name, kind="function",
        capabilities={"process.execute", "network.external"},
        location=tool_location,
        provenance=[
            EvidenceFact(tool_name, "capability=process.execute", "observed", tool_location),
            EvidenceFact(tool_name, "capability=network.external", "inferred", tool_location),
            EvidenceFact(tool_name, "approval_configuration=None", "observed", tool_location),
        ],
    )
    return Agent(name="agent", tools=[tool], location=location)


def _finding(rule: str, location: SourceLocation | None, *, layer: int) -> Finding:
    return Finding(
        rule, Severity.HIGH, "Source instance test",
        "Source instance test", "Review provenance",
        layer=layer, location=location, agent="agent",
        evidence=(["process.execute", "network.external"] if rule == "CAP004"
                  else ["capability=process.execute", "approval=None"]),
    )


def test_agent_level_caps_are_attributed_to_exact_constructor(tmp_path: Path) -> None:
    first = _instance(tmp_path, "alpha.py", 40)
    second = _instance(tmp_path, "beta.py", 90)
    graph = Graph(agents=[first, second])
    finding = _finding("CAP004", first.location, layer=2)
    assert _source_instance_for_finding(graph, finding) is first
    attach_findings(graph, [finding])
    subjects = {fact.subject for fact in finding.provenance}
    assert subjects == {"exec_alpha"}
    assert any(fact.fact == "capability=process.execute" for fact in finding.provenance)
    assert any(fact.fact == "capability=network.external" for fact in finding.provenance)
    assert all(fact.location == first.tools[0].location for fact in finding.provenance)


def test_tool_rule_uses_own_source_not_other_same_name_agent(tmp_path: Path) -> None:
    first = _instance(tmp_path, "first.py", 40)
    second = _instance(tmp_path, "second.py", 65)
    graph = Graph(agents=[first, second])
    finding = _finding("AGT020", first.tools[0].location, layer=1)
    assert _source_instance_for_finding(graph, finding) is first
    attach_findings(graph, [finding])
    assert finding.provenance
    assert {fact.subject for fact in finding.provenance} == {"exec_first"}
    assert all(fact.location.path == first.tools[0].location.path
               for fact in finding.provenance)


def test_ambiguous_unlocated_duplicate_name_never_steals_evidence(
    tmp_path: Path,
) -> None:
    a = _instance(tmp_path, "a.py", 30)
    b = _instance(tmp_path, "b.py", 45)
    graph = Graph(agents=[a, b])
    finding = _finding("AGT020", None, layer=1)
    assert _source_instance_for_finding(graph, finding) is None
    attach_findings(graph, [finding])
    assert finding.provenance == []


def test_same_tool_location_in_two_instances_is_not_a_unique_owner(
    tmp_path: Path,
) -> None:
    a = _instance(tmp_path, "first.py", 40)
    b = _instance(tmp_path, "other.py", 60)
    b.tools[0].location = a.tools[0].location
    graph = Graph(agents=[a, b])
    finding = _finding("AGT020", a.tools[0].location, layer=1)
    assert _source_instance_for_finding(graph, finding) is None
    attach_findings(graph, [finding])
    assert finding.provenance == []


def test_existing_unique_agent_name_still_attaches_source_witness(
    tmp_path: Path,
) -> None:
    agent = _instance(tmp_path, "only.py", 33)
    graph = Graph(agents=[agent])
    finding = _finding("AGT020", agent.tools[0].location, layer=1)
    attach_findings(graph, [finding])
    assert finding.provenance
    assert {fact.subject for fact in finding.provenance} == {"exec_only"}


def test_cap003_uses_only_declared_privileged_capability_source_facts(
    tmp_path: Path,
) -> None:
    first = _instance(tmp_path, "alpha.py", 40)
    other = _instance(tmp_path, "beta.py", 90)
    graph = Graph(agents=[first, other])
    finding = _finding("CAP003", first.location, layer=2)
    finding.evidence = ["privileged=process.execute,network.external",
                        "threshold=1"]
    attach_findings(graph, [finding])
    assert {fact.fact for fact in finding.provenance} == {
        "capability=process.execute", "capability=network.external",
    }
    assert {fact.subject for fact in finding.provenance} == {"exec_alpha"}
    assert any(fact.origin == "inferred" for fact in finding.provenance)


def test_net002_source_witness_is_outbound_only_not_runtime_allowlist_proof(
    tmp_path: Path,
) -> None:
    first = _instance(tmp_path, "alpha.py", 40)
    other = _instance(tmp_path, "beta.py", 90)
    graph = Graph(agents=[first, other])
    finding = _finding("NET002", first.location, layer=4)
    finding.evidence = ["capabilities=network.external"]
    attach_findings(graph, [finding])
    assert [fact.fact for fact in finding.provenance] == [
        "capability=network.external",
    ]
    assert finding.provenance[0].subject == "exec_alpha"
    assert not any("allowlist" in fact.fact for fact in finding.provenance)


def test_net002_never_invents_missing_egress_evidence(
    tmp_path: Path,
) -> None:
    agent = _instance(tmp_path, "alpha.py", 40)
    agent.tools[0].capabilities = {"data.read"}
    graph = Graph(agents=[agent])
    finding = _finding("NET002", agent.location, layer=4)
    attach_findings(graph, [finding])
    assert finding.provenance == []
