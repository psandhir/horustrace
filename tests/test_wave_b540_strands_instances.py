"""Regression for Wave B #540: Strands source instances must not merge by label."""
from __future__ import annotations

from pathlib import Path

from horustrace.models import Agent, Finding, Graph, Severity, SourceLocation, Tool
from horustrace.rules.builtin import _qualify_deferred_strands_findings
from horustrace.scanner import _consolidate_agents
from horustrace.strands_repository import _build_modules, _vended_tool


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


def test_vended_tool_provenance_uses_import_line_not_module_line_one(
    tmp_path: Path,
) -> None:
    package = tmp_path / "src"
    package.mkdir()
    source = package / "tool.py"
    source.write_text(
        "from __future__ import annotations\n"
        "# unrelated leading line\n"
        "from strands_tools import shell as execute_shell\n"
        "from strands_tools import file_read\n",
        encoding="utf-8",
    )
    modules = _build_modules(package, [source])
    assert len(modules) == 1
    info = next(iter(modules.values()))
    tool = _vended_tool(info, "execute_shell")
    assert tool is not None
    assert tool.location is not None
    assert tool.location.line == 3
    assert tool.metadata["source_symbol_origin"] == "import_statement"
    assert tool.name == "shell"
    other = _vended_tool(info, "file_read")
    assert other is not None
    assert other.location is not None
    assert other.location.line == 4


def test_ambiguous_vended_import_alias_does_not_invent_source_binding(
    tmp_path: Path,
) -> None:
    package = tmp_path / "src"
    package.mkdir()
    source = package / "tool.py"
    source.write_text(
        "from strands_tools import shell as tool_alias\n"
        "from strands_tools import shell as tool_alias\n",
        encoding="utf-8",
    )
    info = next(iter(_build_modules(package, [source]).values()))
    assert _vended_tool(info, "tool_alias") is None


def test_deferred_wrapper_findings_have_scope_limits_without_filtering(
    tmp_path: Path,
) -> None:
    target = tmp_path / "agents" / "worker.py"
    graph = Graph(agents=[
        Agent(
            name="agent",
            location=SourceLocation(target, line=17),
            metadata={
                "framework": "strands-agents",
                "construction_scope": "tool_wrapper_deferred_invocation",
            },
        ),
        Agent(
            name="agent",
            location=SourceLocation(tmp_path / "agents" / "other.py", line=12),
            metadata={
                "framework": "strands-agents",
                "construction_scope": "function_local_conditional",
            },
        ),
    ])
    findings = [
        Finding(
            rule_id="AGT040",
            severity=Severity.MEDIUM,
            title="Guardrail",
            message="Source lacks controls",
            recommendation="Require approval",
            agent="agent",
            location=SourceLocation(target, line=3),
        ),
        Finding(
            rule_id="CAP005",
            severity=Severity.MEDIUM,
            title="Broad data access",
            message="Source shows read and write",
            recommendation="Constrain",
            agent="agent",
            location=SourceLocation(tmp_path / "agents" / "other.py", line=12),
        ),
    ]
    _qualify_deferred_strands_findings(graph, findings)
    assert len(findings) == 2
    assert len(findings[0].limitations) == 1
    assert "conditional source configuration" in findings[0].limitations[0]
    assert findings[1].limitations == []
    _qualify_deferred_strands_findings(graph, findings)
    assert len(findings[0].limitations) == 1


def test_ambiguous_same_source_strands_findings_are_not_misattributed(
    tmp_path: Path,
) -> None:
    location = SourceLocation(tmp_path / "worker.py", line=10)
    agents = [
        Agent(
            name="agent",
            location=location,
            metadata={
                "framework": "strands-agents",
                "construction_scope": "tool_wrapper_deferred_invocation",
            },
        )
        for _ in range(2)
    ]
    finding = Finding(
        rule_id="AGT040",
        severity=Severity.MEDIUM,
        title="Guardrail",
        message="Unknown attribution",
        recommendation="Review",
        location=location,
        agent="agent",
    )
    _qualify_deferred_strands_findings(Graph(agents=agents), [finding])
    assert finding.limitations == []
