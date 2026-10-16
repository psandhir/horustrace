"""Source-anchored Strands imports and explicitly inferred tool effects.

Wave B #540: evidence display must not turn a third-party tool name into a
source-observed runtime effect or attach one same-name agent's facts to another.
"""
from __future__ import annotations

from pathlib import Path

from horustrace.effective_authority import effective_authority_relationships
from horustrace.models import Agent, EvidenceFact, Finding, Graph, Severity, SourceLocation
from horustrace.provenance import attach_findings
from horustrace.strands_repository import _build_modules, _vended_tool


def _vended(root: Path, name: str, text: str):
    source = root / name
    source.write_text(text, encoding="utf-8")
    info = next(iter(_build_modules(root, [source]).values()))
    return info


def test_import_is_observed_but_tool_effects_are_inferred(tmp_path: Path) -> None:
    info = _vended(
        tmp_path, "writer.py",
        "# non-import code\nfrom strands_tools import shell as run_shell\n",
    )
    tool = _vended_tool(info, "run_shell")
    assert tool is not None
    assert tool.location == SourceLocation(tmp_path / "writer.py", 2, 1)
    assert any(
        fact.fact == "source_import=strands_tools.shell"
        and fact.origin == "observed"
        for fact in tool.provenance
    )
    assert any(
        fact.fact == "capability=process.execute"
        and fact.origin == "inferred"
        for fact in tool.provenance
    )
    assert all(
        fact.location == tool.location for fact in tool.provenance
    )
    assert not any(
        fact.fact.startswith("capability=") and fact.origin == "observed"
        for fact in tool.provenance
    )
    assert not any(
        "approval" in fact.fact or "allowlist" in fact.fact
        for fact in tool.provenance
    )


def test_same_name_agents_only_receive_their_own_inferred_capability_facts(
    tmp_path: Path,
) -> None:
    first_info = _vended(
        tmp_path, "alpha.py", "from strands_tools import shell\n",
    )
    second_info = _vended(
        tmp_path, "beta.py", "from strands_tools import file_read\n",
    )
    first_tool = _vended_tool(first_info, "shell")
    second_tool = _vended_tool(second_info, "file_read")
    assert first_tool is not None and second_tool is not None

    first = Agent(
        name="agent",
        location=SourceLocation(tmp_path / "alpha.py", 20),
        tools=[first_tool],
    )
    second = Agent(
        name="agent",
        location=SourceLocation(tmp_path / "beta.py", 30),
        tools=[second_tool],
    )
    graph = Graph(agents=[first, second])

    privileged = Finding(
        "CAP003", Severity.HIGH, "privileged", "message", "recommendation",
        location=first.location, agent="agent", layer=2,
        evidence=["privileged=process.execute,network.external", "threshold=1"],
    )
    attach_findings(graph, [privileged])
    assert privileged.provenance
    assert {fact.subject for fact in privileged.provenance} == {"shell"}
    assert all(fact.origin == "inferred" for fact in privileged.provenance)
    assert all(fact.location == first_tool.location for fact in privileged.provenance)

    outbound = Finding(
        "NET002", Severity.MEDIUM, "network", "message", "recommendation",
        location=first.location, agent="agent", layer=4,
        evidence=["capabilities=network.external"],
    )
    attach_findings(graph, [outbound])
    assert outbound.provenance
    assert {fact.fact for fact in outbound.provenance} == {
        "capability=network.external",
        "capability=external.write",
    }
    assert all(fact.origin == "inferred" for fact in outbound.provenance)
    assert not any(
        "allowlist" in fact.fact for fact in outbound.provenance
    )


def test_shadowed_ambiguous_import_has_no_fabricated_source_facts(
    tmp_path: Path,
) -> None:
    info = _vended(
        tmp_path, "ambiguous.py",
        "from strands_tools import shell as tool_alias\n"
        "from strands_tools import shell as tool_alias\n",
    )
    assert _vended_tool(info, "tool_alias") is None


def test_shared_import_line_does_not_copy_unrelated_tool_capabilities(
    tmp_path: Path,
) -> None:
    info = _vended(
        tmp_path, "joint.py",
        "from strands_tools import shell, file_read\n",
    )
    shell = _vended_tool(info, "shell")
    file_read = _vended_tool(info, "file_read")
    assert shell is not None and file_read is not None
    # Both aliases are legitimately on the same AST source line.
    assert shell.location == file_read.location
    agent = Agent(
        name="worker",
        location=SourceLocation(tmp_path / "joint.py", 12),
        tools=[shell, file_read],
    )
    graph = Graph(agents=[agent])
    execution = Finding(
        "AGT020", Severity.HIGH, "execution", "message", "recommendation",
        location=shell.location, agent="worker", layer=1,
        evidence=["capability=process.execute", "approval=None"],
    )
    attach_findings(graph, [execution])
    assert {fact.fact for fact in execution.provenance} == {
        "capability=process.execute",
    }
    assert {fact.subject for fact in execution.provenance} == {"shell"}

    relationship = Finding(
        "AGT040", Severity.MEDIUM, "authority", "message", "recommendation",
        location=shell.location, agent="worker", layer=1,
        evidence=[
            "capabilities=data.read,data.write",
            "authority_relationship=authority-v1:source-unknown",
        ],
    )
    attach_findings(graph, [relationship])
    # Shared import location cannot prove which specific authority edge was
    # effective; avoid repeating every imported tool's inferred facts.
    assert relationship.provenance == []

    # A mismatched authority ID must remain unresolved, even if there
    # are source-observed facts on the same multi-symbol import line.
    shell.provenance.extend([
        EvidenceFact(
            "shell", "capability=process.execute", "observed", shell.location,
        ),
        EvidenceFact(
            "shell", "approval_configuration=None", "observed", shell.location,
        ),
    ])
    attach_findings(graph, [relationship])
    assert relationship.provenance == []

    # A real, source-qualified ID restores exactly the matched tool's
    # original observed evidence AND its separately inferred effects.
    matching = [
        item for item in effective_authority_relationships(graph)
        if item.target_kind == "tool" and item.target_name == "shell"
    ]
    assert len(matching) == 1
    relationship.evidence = [
        "capabilities=" + ",".join(sorted(shell.capabilities)),
        f"authority_relationship={matching[0].relationship_id}",
    ]
    relationship.authority_relationship_id = matching[0].relationship_id
    attach_findings(graph, [relationship])
    assert {(fact.fact, fact.origin) for fact in relationship.provenance} == {
        ("source_import=strands_tools.shell", "observed"),
        ("capability=process.execute", "observed"),
        ("capability=process.execute", "inferred"),
        ("capability=data.read", "inferred"),
        ("capability=data.write", "inferred"),
        ("capability=destructive.write", "inferred"),
        ("capability=network.external", "inferred"),
        ("capability=external.write", "inferred"),
        ("approval_configuration=None", "observed"),
    }
