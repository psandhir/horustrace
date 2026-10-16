"""Source-anchored Strands imports and explicitly inferred tool effects.

Wave B #540: evidence display must not turn a third-party tool name into a
source-observed runtime effect or attach one same-name agent's facts to another.
"""
from __future__ import annotations

from pathlib import Path

from horustrace.models import Agent, Finding, Graph, Severity, SourceLocation
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
