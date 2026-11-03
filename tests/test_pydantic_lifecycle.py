"""Source-only Pydantic lifecycle witnesses: never execute target code."""
import ast
from pathlib import Path

from horustrace.adapters.pydantic_ai import (
    _is_pydantic_agent_call,
    _pydantic_agent_imports,
    _target_names,
)
from horustrace.pydantic_lifecycle import collect_pydantic_constructor_phases
from horustrace.scanner import scan


def _phases(source: str):
    tree = ast.parse(source)
    names, modules = _pydantic_agent_imports(tree)
    return collect_pydantic_constructor_phases(
        tree,
        is_constructor=lambda call: _is_pydantic_agent_call(call, names, modules),
        assignment_targets=_target_names,
    )


def test_reconstructed_self_agent_keeps_initial_source_constructor(
    tmp_path: Path,
) -> None:
    target = tmp_path / "mcp_agent.py"
    target.write_text(
        """from pydantic_ai import Agent as PydanticAgent, RunContext

class SSEMCPAgent:
    def __init__(self):
        self.agent = PydanticAgent("openai:first")

        @self.agent.tool
        async def date_tool(ctx: RunContext) -> str:
            return "today"

    def _update_system_prompt(self, available_tools):
        if available_tools:
            self.agent = PydanticAgent("openai:replacement")
            for tool in available_tools:
                self.agent.tool(tool)

class Agent:
    def __init__(self):
        self.agent = "not a Pydantic agent"

outer = Agent()
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    pydantic = [
        item for item in graph.agents
        if item.metadata.get("framework") == "pydantic-ai"
    ]
    assert len(pydantic) == 1
    agent = pydantic[0]
    assert agent.name == "self.agent"
    assert agent.location is not None and agent.location.line == 5
    assert agent.metadata["source_binding_scope"] == "SSEMCPAgent"
    assert agent.metadata["lifecycle_reconstruction_source_only"] is True
    assert agent.metadata["lifecycle_effective_tool_authority"] == "unresolved"
    witnesses = agent.metadata["constructor_phases"]
    assert len(witnesses) == 2
    assert [phase["line"] for phase in witnesses] == [5, 13]
    assert [phase["phase"] for phase in witnesses] == [
        "initial_source_constructor", "source_reconstruction"
    ]
    assert witnesses[0]["conditional"] is False
    assert witnesses[1]["conditions"] == ["if (available_tools)"]
    assert all(phase["runtime_effectiveness"] == "not_verified" for phase in witnesses)
    assert any(tool.name == "date_tool" for tool in agent.tools)
    assert not any(item.name == "outer" for item in pydantic)


def test_same_attribute_in_different_classes_is_not_one_lifecycle() -> None:
    source = """from pydantic_ai import Agent

class First:
    def __init__(self):
        self.agent = Agent("openai:first")

class Second:
    def __init__(self):
        self.agent = Agent("openai:second")
"""
    phases = _phases(source)["self.agent"]
    assert len(phases) == 2
    assert {phase.scope for phase in phases} == {"First", "Second"}
    assert {phase.enclosing_function for phase in phases} == {"__init__"}


def test_distinct_class_collision_is_explicitly_diagnosed(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """from pydantic_ai import Agent
class First:
    def __init__(self):
        self.agent = Agent("openai:first")
class Second:
    def __init__(self):
        self.agent = Agent("openai:second")
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    assert any(
        "different lexical scopes" in diagnostic.message
        for diagnostic in graph.coverage.diagnostics
    )
    # Do not manufacture a lifecycle joining the two unrelated classes.
    assert all(
        "constructor_phases" not in item.metadata
        for item in graph.agents
        if item.metadata.get("framework") == "pydantic-ai"
    )


def test_conditional_else_branches_are_source_only() -> None:
    source = """from pydantic_ai import Agent
class Wrapper:
    def configure(self, enabled):
        if enabled:
            self.agent = Agent("openai:enabled")
        else:
            self.agent = Agent("openai:disabled")
"""
    phases = _phases(source)["self.agent"]
    assert len(phases) == 2
    assert phases[0].scope == phases[1].scope == "Wrapper"
    assert phases[0].conditions == ("if (enabled)",)
    assert phases[1].conditions == ("else of (enabled)",)


def test_unrelated_local_agent_does_not_enter_constructor_lifecycle() -> None:
    assert _phases(
        """from pydantic_ai import Agent as PydanticAgent
class Agent:
    pass
bad = Agent()
good = PydanticAgent("openai:valid")
"""
    ).keys() == {"good"}
