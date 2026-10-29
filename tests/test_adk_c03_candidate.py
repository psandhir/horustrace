"""C03e ADK source-only projection, hard negatives and discard rollback."""
from __future__ import annotations

import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from horustrace.adg import AgentDependencyGraph
from horustrace.adk_c03_candidate import (
    build_adk_source_candidate,
    verify_adk_candidate_rollback,
)


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(root), *args],
        check=True, capture_output=True,
    )


def _fixture(root: Path) -> None:
    (root / "agent.py").write_text(
        'from google.adk.agents import LlmAgent\n'
        'child_agent = LlmAgent(name="child", tools=[safe_tool, audit_tool])\n'
        'root_agent = LlmAgent(name="root", sub_agents=[child_agent])\n',
        encoding="utf-8",
    )
    (root / "other.py").write_text(
        'from google.adk.agents import LlmAgent\n'
        'separate_agent = LlmAgent(name="child", tools=[another_tool])\n',
        encoding="utf-8",
    )
    (root / "api.py").write_text(
        'from agent import root_agent as alias\n'
        'from google.adk.runners import Runner\n'
        'runner = Runner(agent=alias, app_name="test")\n',
        encoding="utf-8",
    )
    _git(root, "init", "-q")
    _git(root, "add", "agent.py", "other.py", "api.py")
    _git(
        root, "-c", "user.name=C03 Test", "-c",
        "user.email=c03@example.test", "commit", "-qm", "source",
    )


def _candidate(root: Path) -> dict:
    return build_adk_source_candidate(
        AgentDependencyGraph(), root, ["agent.py", "other.py", "api.py"],
    )


def test_c03e_distinct_agent_instances_and_direct_source_relationships(
    tmp_path: Path,
) -> None:
    _fixture(tmp_path)
    base = AgentDependencyGraph()
    original = deepcopy(base.as_dict())
    digest = base.canonical_digest()
    result = build_adk_source_candidate(
        base, tmp_path, ["other.py", "api.py", "agent.py"],
    )
    assert result == build_adk_source_candidate(
        base, tmp_path, ["agent.py", "other.py", "api.py"],
    )
    assert base.as_dict() == original
    assert base.canonical_digest() == digest
    assert result["differential"]["added_source_edge_kinds"] == {
        "ADK_DIRECT_TOOL_LIST_ENTRY": 3,
        "ADK_SUB_AGENT_LIST_ENTRY": 1,
    }
    nodes = result["candidate_adg"]["nodes"]
    assert len(nodes) == 6  # 3 agent constructors + 3 direct tool references
    assert len([n for n in nodes if n["kind"] == "adk_agent_constructor"]) == 3
    assert len({n["id"] for n in nodes if n["name"] == "child"}) == 2
    assert not any(n["name"] in ("alias", "Runner") for n in nodes)
    assert len(result["candidate_adg"]["edges"]) == 4
    assert result["candidate_adg"]["schema_version"] != 1
    assert result["production_cutover_authorized"] is False
    assert result["runtime_authority_verified"] is False
    assert result["certified_precision"] is None
    assert result["certified_recall"] is None
    assert all(n["attributes"]["source_only"] is True for n in nodes)
    assert all(e["attributes"]["effective_agent_can_call"] is None
               for e in result["candidate_adg"]["edges"])
    verify_adk_candidate_rollback(base, result)


def test_c03e_tampered_or_untracked_source_fails_closed(tmp_path: Path) -> None:
    _fixture(tmp_path)
    path = tmp_path / "agent.py"
    path.write_text(path.read_text().replace('"child"', '"changed"'),
                    encoding="utf-8")
    with pytest.raises(ValueError, match="modified"):
        _candidate(tmp_path)
    (tmp_path / "untracked.py").write_text("print('test')\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not tracked"):
        build_adk_source_candidate(
            AgentDependencyGraph(), tmp_path, ["untracked.py"],
        )
    with pytest.raises(ValueError, match="unsafe"):
        build_adk_source_candidate(
            AgentDependencyGraph(), tmp_path, ["../agent.py"],
        )


def test_c03e_dynamic_tool_list_is_unknown_not_empty(tmp_path: Path) -> None:
    _fixture(tmp_path)
    path = tmp_path / "agent.py"
    path.write_text(
        'from google.adk.agents import LlmAgent\n'
        'root_agent = LlmAgent(name="root", tools=load_tools())\n',
        encoding="utf-8",
    )
    _git(tmp_path, "add", "agent.py")
    _git(tmp_path, "-c", "user.name=C03 Test", "-c",
         "user.email=c03@example.test", "commit", "-qm", "dynamic")
    with pytest.raises(ValueError, match="unresolved"):
        _candidate(tmp_path)


def test_c03e_rebound_agent_symbol_is_unresolved(tmp_path: Path) -> None:
    _fixture(tmp_path)
    path = tmp_path / "agent.py"
    path.write_text(path.read_text() + 'root_agent = get_agent()\n',
                    encoding="utf-8")
    _git(tmp_path, "add", "agent.py")
    _git(tmp_path, "-c", "user.name=C03 Test", "-c",
         "user.email=c03@example.test", "commit", "-qm", "rebound")
    with pytest.raises(ValueError, match="unresolved"):
        _candidate(tmp_path)


def test_c03e_candidate_tampering_and_authority_promotion_fail(
    tmp_path: Path,
) -> None:
    _fixture(tmp_path)
    base = AgentDependencyGraph()
    result = _candidate(tmp_path)
    for mutate in (
        lambda x: x.update({"production_cutover_authorized": True}),
        lambda x: x.update({"certified_precision": 1.0}),
        lambda x: x["candidate_adg"].update({"schema_version": 1}),
        lambda x: x["candidate_adg"]["edges"][0].update({
            "kind": "AGENT_CAN_CALL",
        }),
        lambda x: x["candidate_adg"]["nodes"][0]["attributes"].update({
            "effective_authority": "allowed",
        }),
        lambda x: x["differential"].update({
            "effective_agent_can_call_edges_added": 1,
        }),
    ):
        altered = deepcopy(result)
        mutate(altered)
        with pytest.raises((TypeError, ValueError)):
            verify_adk_candidate_rollback(base, altered)
