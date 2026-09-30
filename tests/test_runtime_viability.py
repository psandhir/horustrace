from pathlib import Path

from horustrace.scanner import scan


def test_undefined_agent_constructor_name_qualifies_declared_authority(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent

def run_python(code: str):
    exec(code)

agent = Agent(
    "openai:gpt-5.2",
    tools=[run_python],
    model_settings=settings,
)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    assert agent.metadata["runtime_viability"] == "blocked_by_source_error"
    assert any(
        blocker.get("kind") == "undefined_agent_constructor_name"
        and blocker.get("name") == "settings"
        for blocker in agent.metadata["runtime_blockers"]
    )
    assert any(
        diagnostic.kind == "runtime_viability_blocker"
        and diagnostic.incomplete is False
        for diagnostic in graph.coverage.diagnostics
    )
    process_finding = next(
        finding
        for finding in findings
        if finding.rule_id == "AGT020" and finding.agent == "agent"
    )
    assert "runtime_viability=blocked_by_source_error" in process_finding.evidence
    assert any("live runtime reachability is not proven" in item for item in process_finding.limitations)


def test_missing_local_import_qualifies_adk_agent_runtime(
    tmp_path: Path,
) -> None:
    package = tmp_path / "local_tools"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "agent.py").write_text(
        """
from google.adk.agents import Agent
from local_tools.missing import update_record

agent = Agent(name="ops", model="gemini-3.1-flash-lite", tools=[update_record])
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "ops")
    assert agent.metadata["runtime_viability"] == "blocked_by_source_error"
    assert any(
        blocker.get("kind") == "missing_local_module"
        and blocker.get("module") == "local_tools.missing"
        for blocker in agent.metadata["runtime_blockers"]
    )
