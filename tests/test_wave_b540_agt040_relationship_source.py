"""Wave B AGT040: source-linked authority ID, not shared-line tool inference.

AGT040 represents a source-visible, not runtime-enforced, privilege/control
assessment. Only a unique source relationship can select its tool's facts.
"""
from __future__ import annotations

from pathlib import Path

from horustrace.effective_authority import effective_authority_relationships
from horustrace.models import (
    Agent,
    EvidenceFact,
    Finding,
    Graph,
    Severity,
    SourceLocation,
    Tool,
)
from horustrace.provenance import attach_findings
from horustrace.strands_repository import _build_modules, _vended_tool


def _imported(tmp_path: Path, filename: str, source: str, names: tuple[str, ...]):
    path = tmp_path / filename
    path.write_text(source, encoding="utf-8")
    info = next(iter(_build_modules(tmp_path, [path]).values()))
    tools = [_vended_tool(info, name) for name in names]
    assert all(tool is not None for tool in tools)
    return tools


def _claim(graph: Graph, agent: Agent, tool: Tool, *, related_id: str | None = None,
           capabilities: set[str] | None = None) -> Finding:
    matched = [
        item for item in effective_authority_relationships(graph)
        if item.agent == agent.name
        and item.target_kind == "tool"
        and item.target_name == tool.name
        and item.location is not None
        and tool.location is not None
        and item.location["path"] == str(tool.location.path)
    ]
    assert len(matched) == 1
    identifier = related_id if related_id is not None else matched[0].relationship_id
    values = sorted(capabilities if capabilities is not None else tool.capabilities)
    return Finding(
        "AGT040",
        Severity.MEDIUM,
        "Privileged tool lacks explicit guardrail or approval",
        "Claim about a source-visible tool, not runtime approval",
        "Verify and restrict privileges",
        layer=1,
        agent=agent.name,
        location=tool.location,
        evidence=[
            "capabilities=" + ",".join(values),
            "authority_relationship=" + identifier,
            "approval_resolution=unknown",
        ],
        authority_relationship_id=identifier,
    )


def test_agt040_shared_import_line_selects_exact_tool_not_neighbour(
    tmp_path: Path,
) -> None:
    shell, reader = _imported(
        tmp_path, "joint.py", "from strands_tools import shell, file_read\n",
        ("shell", "file_read"),
    )
    agent = Agent(name="agent", tools=[shell, reader],
                  location=SourceLocation(tmp_path / "joint.py", 12))
    graph = Graph(agents=[agent])
    assert shell.location == reader.location

    shell_claim = _claim(graph, agent, shell)
    reader_claim = _claim(graph, agent, reader)
    attach_findings(graph, [shell_claim, reader_claim])
    for finding, tool in ((shell_claim, shell), (reader_claim, reader)):
        assert finding.provenance
        assert {fact.subject for fact in finding.provenance} == {tool.name}
        assert {fact.fact for fact in finding.provenance} == {
            "source_import=strands_tools." + tool.name,
            *(f"capability={name}" for name in tool.capabilities),
        }
        assert all(fact.location == tool.location for fact in finding.provenance)
        assert all(
            fact.origin == ("observed" if fact.fact.startswith("source_import=") else "inferred")
            for fact in finding.provenance
        )
        assert all(not fact.fact.startswith("approval_configuration=")
                   for fact in finding.provenance)


def test_agt040_unmatched_and_mismatched_ids_fail_closed(tmp_path: Path) -> None:
    shell, reader = _imported(
        tmp_path, "joint.py", "from strands_tools import shell, file_read\n",
        ("shell", "file_read"),
    )
    agent = Agent(name="agent", tools=[shell, reader],
                  location=SourceLocation(tmp_path / "joint.py", 12))
    graph = Graph(agents=[agent])
    shell_claim = _claim(graph, agent, shell)
    reader_claim = _claim(graph, agent, reader)
    other_id = next(
        value.split("=", 1)[1]
        for value in reader_claim.evidence
        if value.startswith("authority_relationship=")
    )
    shell_claim.evidence = [
        "capabilities=" + ",".join(sorted(shell.capabilities)),
        "authority_relationship=" + other_id,
    ]
    shell_claim.authority_relationship_id = other_id
    attach_findings(graph, [shell_claim])
    assert shell_claim.provenance == []

    shell_claim = _claim(graph, agent, shell)
    shell_claim.authority_relationship_id = other_id
    attach_findings(graph, [shell_claim])
    assert shell_claim.provenance == []

    shell_claim = _claim(graph, agent, shell)
    shell_claim.evidence = [
        item for item in shell_claim.evidence
        if not item.startswith("authority_relationship=")
    ]
    attach_findings(graph, [shell_claim])
    assert shell_claim.provenance == []


def test_agt040_same_name_agent_instances_keep_distinct_source_witness(
    tmp_path: Path,
) -> None:
    [first_tool] = _imported(
        tmp_path, "alpha.py", "from strands_tools import shell\n", ("shell",)
    )
    [other_tool] = _imported(
        tmp_path, "beta.py", "from strands_tools import shell\n", ("shell",)
    )
    first = Agent(
        name="agent", tools=[first_tool],
        location=SourceLocation(tmp_path / "alpha.py", 18),
    )
    second = Agent(
        name="agent", tools=[other_tool],
        location=SourceLocation(tmp_path / "beta.py", 19),
    )
    graph = Graph(agents=[first, second])
    first_claim = _claim(graph, first, first_tool)
    second_claim = _claim(graph, second, other_tool)
    attach_findings(graph, [first_claim, second_claim])
    assert first_claim.provenance and second_claim.provenance
    assert {fact.location.path for fact in first_claim.provenance} == {
        tmp_path / "alpha.py"
    }
    assert {fact.location.path for fact in second_claim.provenance} == {
        tmp_path / "beta.py"
    }

    # Merely moving a valid relationship ID across source instances does
    # not permit a name-only attribution.
    wrong_claim = _claim(graph, first, first_tool)
    wrong_claim.evidence = [
        item if not item.startswith("authority_relationship=")
        else "authority_relationship=" + second_claim.authority_relationship_id
        for item in wrong_claim.evidence
    ]
    wrong_claim.authority_relationship_id = second_claim.authority_relationship_id
    attach_findings(graph, [wrong_claim])
    assert wrong_claim.provenance == []


def test_agt040_duplicate_same_name_and_line_remains_unresolved(
    tmp_path: Path,
) -> None:
    [tool] = _imported(
        tmp_path, "joint.py", "from strands_tools import shell\n", ("shell",)
    )
    twin = Tool(
        name=tool.name,
        kind=tool.kind,
        capabilities=set(tool.capabilities),
        location=tool.location,
        provenance=list(tool.provenance),
    )
    agent = Agent(
        name="agent", tools=[tool, twin],
        location=SourceLocation(tmp_path / "joint.py", 15),
    )
    graph = Graph(agents=[agent])
    relationships = effective_authority_relationships(graph)
    assert len(relationships) == 2
    claim = Finding(
        "AGT040", Severity.MEDIUM, "duplicate", "message", "recommendation",
        agent=agent.name, layer=1, location=tool.location,
        evidence=[
            "capabilities=" + ",".join(sorted(tool.capabilities)),
            "authority_relationship=" + relationships[0].relationship_id,
        ],
        authority_relationship_id=relationships[0].relationship_id,
    )
    attach_findings(graph, [claim])
    assert claim.provenance == []


def test_agt040_preserves_only_matched_tool_observed_controls(
    tmp_path: Path,
) -> None:
    shell, reader = _imported(
        tmp_path, "joint.py", "from strands_tools import shell, file_read\n",
        ("shell", "file_read"),
    )
    assert shell.location is not None and reader.location is not None
    shell.provenance.extend([
        EvidenceFact(shell.name, "approval_configuration=None", "observed", shell.location),
        EvidenceFact(shell.name, "guardrail_hook_detected=False", "observed", shell.location),
        EvidenceFact(shell.name, "approval_configuration=unknown", "inferred", shell.location),
    ])
    reader.provenance.append(
        EvidenceFact(reader.name, "approval_configuration=True", "observed", reader.location)
    )
    agent = Agent(
        name="agent", tools=[shell, reader],
        location=SourceLocation(tmp_path / "joint.py", 20),
    )
    graph = Graph(agents=[agent])
    finding = _claim(graph, agent, shell)
    attach_findings(graph, [finding])
    assert ("approval_configuration=None", "observed") in {
        (fact.fact, fact.origin) for fact in finding.provenance
    }
    assert ("guardrail_hook_detected=False", "observed") in {
        (fact.fact, fact.origin) for fact in finding.provenance
    }
    assert ("approval_configuration=True", "observed") not in {
        (fact.fact, fact.origin) for fact in finding.provenance
    }
    assert ("approval_configuration=unknown", "inferred") not in {
        (fact.fact, fact.origin) for fact in finding.provenance
    }


def test_agt040_claim_capabilities_must_belong_to_selected_relationship(
    tmp_path: Path,
) -> None:
    [reader] = _imported(
        tmp_path, "joint.py", "from strands_tools import file_read\n",
        ("file_read",),
    )
    agent = Agent(
        name="agent", tools=[reader],
        location=SourceLocation(tmp_path / "joint.py", 22),
    )
    graph = Graph(agents=[agent])
    finding = _claim(
        graph, agent, reader, capabilities={"process.execute", "data.read"}
    )
    attach_findings(graph, [finding])
    assert finding.provenance == []
