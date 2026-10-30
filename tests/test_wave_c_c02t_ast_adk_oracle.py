"""C02t source-only ADK constructor/delegation/tool AST regression tests."""

from __future__ import annotations

import pytest

from horustrace.source_truth_ast_adk import inspect_adk_python, inspect_adk_scope

ADK = """
from google.adk.agents import LlmAgent
child = LlmAgent(name="child", tools=[reader, writer])
report = LlmAgent(name="report", tools=[])
root = LlmAgent(name="root", sub_agents=[child, report])
"""

API_ALIAS = """
import importlib
mod = importlib.import_module("package.agent")
root_alias = mod.root
runner = Runner(agent=root_alias)
"""


def test_c02t_constructors_and_explicit_bindings() -> None:
    data = inspect_adk_python("agent.py", ADK)
    assert [x["name"] for x in data["agents"]] == ["child", "report", "root"]
    assert [(x["source_agent"], x["target_symbol"])
            for x in data["direct_tool_entries"]] == [
        ("child", "reader"), ("child", "writer"),
    ]
    assert [(x["source_agent"], x["target_symbol"])
            for x in data["sub_agent_entries"]] == [
        ("root", "child"), ("root", "report"),
    ]
    assert not data["unresolved"]


def test_c02t_importlib_alias_runner_and_string_are_not_agents() -> None:
    data = inspect_adk_python("api.py", API_ALIAS)
    assert not data["agents"]
    assert not data["direct_tool_entries"]
    assert not data["sub_agent_entries"]
    assert not data["unresolved"]


def test_c02t_source_identity_distinguishes_same_named_agents() -> None:
    source = ADK.replace('name="child"', 'name="root"')
    data = inspect_adk_python("agent.py", source)
    assert len(data["agents"]) == 3
    assert len({x["id"] for x in data["agents"]}) == 3


def test_c02t_metamorphic_prompt_comments_do_not_add_agents() -> None:
    before = inspect_adk_python("agent.py", ADK)
    after = inspect_adk_python(
        "agent.py", ADK + '\n# LlmAgent(name="imaginary")\n'
        + 'prompt = "LlmAgent(name=ghost)"\n',
    )
    assert len(before["agents"]) == len(after["agents"])
    assert len(before["direct_tool_entries"]) == len(after["direct_tool_entries"])


def test_c02t_dynamic_tools_are_not_silently_inferred() -> None:
    source = """
from google.adk.agents import LlmAgent
agent = LlmAgent(name="test", tools=choose_tools())
"""
    data = inspect_adk_python("agent.py", source)
    assert len(data["agents"]) == 1
    assert data["direct_tool_entries"] == []
    assert any(x["reason"] == "dynamic_tools" for x in data["unresolved"])


def test_c02t_nonlocal_delegate_is_unresolved_not_new_instance() -> None:
    source = """
from google.adk.agents import LlmAgent
root = LlmAgent(name="root", sub_agents=[imported_child])
"""
    data = inspect_adk_python("agent.py", source)
    assert len(data["agents"]) == 1
    assert len(data["sub_agent_entries"]) == 1
    assert data["unresolved"][0]["reason"] == (
        "sub_agent_target_not_declared_in_source_file"
    )


def test_c02t_nested_factory_not_promoted_to_deployed_instance() -> None:
    source = """
from google.adk.agents import LlmAgent
def factory():
    return LlmAgent(name="runtime")
"""
    data = inspect_adk_python("agent.py", source)
    assert data["agents"] == []
    assert data["unresolved"][0]["reason"] == (
        "non_literal_or_nested_agent_constructor"
    )


def test_c02t_reassigned_agent_is_explicitly_unresolved() -> None:
    data = inspect_adk_python("agent.py", ADK + "\nroot = object()\n")
    assert any(x["reason"] == "agent_symbol_rebound" for x in data["unresolved"])


def test_c02t_scope_syntax_path_and_release_proofs() -> None:
    with pytest.raises(ValueError):
        inspect_adk_scope({})
    for name in ("../unsafe.py", "/root/private.py", "x.js", "x\\y.py"):
        with pytest.raises(ValueError):
            inspect_adk_python(name, ADK)
    with pytest.raises(SyntaxError):
        inspect_adk_python("agent.py", "LlmAgent(")
    data = inspect_adk_scope({"agent.py": ADK, "api.py": API_ALIAS})
    assert data["independent_human_review_verified"] is False
    assert data["runtime_callability_verified"] is False
    assert data["certified_precision"] is None
    assert data["certified_recall"] is None
    assert data["production_cutover_authorized"] is False
