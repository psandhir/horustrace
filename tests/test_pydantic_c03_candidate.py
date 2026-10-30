"""C03g conditional Pydantic tool candidate hard negatives and rollback."""
from __future__ import annotations

import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from horustrace.adg import ADGNode, AgentDependencyGraph
from horustrace.pydantic_c03_candidate import (
    build_pydantic_conditional_source_candidate as build,
)
from horustrace.pydantic_c03_candidate import (
    verify_pydantic_conditional_candidate_rollback as verify,
)

SOURCE = """
def get_tools_for_level(level: int) -> list:
    if level == 1:
        return []
    elif level == 2:
        return [list_tables, describe_table]
    else:
        return [list_tables, describe_table, execute_query,
                get_current_date, get_stock_query_template]
"""
OUTER = """
class SQLQueryAgent:
    def __init__(self):
        tools = get_tools_for_level(self.demo_level)
        self._agent = BaseAgent(model="x", tools=tools)
"""
INNER = """
class BaseAgent:
    def __init__(self, tools):
        self.tools = tools or []
        for tool in self.tools:
            self._agent.tool(tool)
"""


def _repo(root: Path) -> None:
    (root / "agent").mkdir()
    for name, value in (
        ("agent/tools.py", SOURCE),
        ("agent/agent.py", OUTER),
        ("agent/base_agent.py", INNER),
    ):
        (root / name).write_text(value, encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(root), "add", "agent"], check=True)
    subprocess.run(["git", "-C", str(root), "-c", "user.name=Test",
                    "-c", "user.email=test@example.invalid",
                    "commit", "-qm", "fixture"], check=True)


def test_pydantic_source_branches_do_not_invent_runtime_level(tmp_path: Path) -> None:
    _repo(tmp_path)
    base = AgentDependencyGraph()
    before = deepcopy(base.as_dict())
    candidate = build(base, tmp_path)
    assert candidate == build(base, tmp_path)
    assert candidate["source_branches"] == {
        "level_1": [],
        "level_2": ["list_tables", "describe_table"],
        "else_branch_other_values": [
            "list_tables", "describe_table", "execute_query",
            "get_current_date", "get_stock_query_template",
        ],
    }
    assert candidate["differential"]["source_nodes_added"] == 8
    assert candidate["differential"]["source_edges_added"] == 7
    assert candidate["differential"]["effective_agent_can_call_edges_added"] == 0
    assert candidate["runtime_level_known"] is False
    assert candidate["certified_recall"] is None
    assert candidate["production_cutover_authorized"] is False
    assert candidate["candidate_adg"]["schema_version"] != 1
    assert base.as_dict() == before
    verify(base, candidate)


def test_unchanged_canonical_and_fail_closed_on_authority_tamper(
    tmp_path: Path,
) -> None:
    _repo(tmp_path)
    base = AgentDependencyGraph(nodes=[
        ADGNode(node_id="existing", kind="agent", name="deployed-unknown"),
    ])
    before = deepcopy(base.as_dict())
    candidate = build(base, tmp_path)
    changed = deepcopy(candidate)
    added = next(n for n in changed["candidate_adg"]["nodes"]
                 if n["id"].startswith("c03-pydantic-candidate:"))
    added["attributes"]["effective_authority"] = "allowed"
    with pytest.raises(ValueError):
        verify(base, changed)
    assert base.as_dict() == before


def test_uncommitted_source_does_not_become_candidate(tmp_path: Path) -> None:
    _repo(tmp_path)
    file = tmp_path / "agent/tools.py"
    file.write_text(SOURCE + "\n# modified\n", encoding="utf-8")
    with pytest.raises(ValueError, match="changed since Git HEAD"):
        build(AgentDependencyGraph(), tmp_path)


def test_dynamic_tool_selection_not_literal_source_scope(tmp_path: Path) -> None:
    _repo(tmp_path)
    file = tmp_path / "agent/tools.py"
    file.write_text(SOURCE.replace(
        "return [list_tables, describe_table]",
        "return load_tools(level)",
    ), encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "agent/tools.py"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "-c", "user.name=Test",
                    "-c", "user.email=test@example.invalid",
                    "commit", "-qm", "dynamic"], check=True)
    with pytest.raises(ValueError):
        build(AgentDependencyGraph(), tmp_path)


def test_mutated_registration_path_rejected(tmp_path: Path) -> None:
    _repo(tmp_path)
    file = tmp_path / "agent/base_agent.py"
    file.write_text(INNER.replace(
        "self._agent.tool(tool)", "self._agent.other(tool)",
    ), encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "agent/base_agent.py"],
                   check=True)
    subprocess.run(["git", "-C", str(tmp_path), "-c", "user.name=Test",
                    "-c", "user.email=test@example.invalid",
                    "commit", "-qm", "changed wrapper"], check=True)
    with pytest.raises(ValueError):
        build(AgentDependencyGraph(), tmp_path)



def test_even_resigned_runtime_claim_cannot_promote_conditional_candidate(
    tmp_path: Path,
) -> None:
    import hashlib
    import json

    _repo(tmp_path)
    base = AgentDependencyGraph()
    candidate = build(base, tmp_path)
    new = deepcopy(candidate)
    tool = next(row for row in new["candidate_adg"]["nodes"]
                if row["kind"] == "pydantic_source_tool_symbol")
    tool["attributes"]["runtime_registration_verified"] = True
    raw = json.dumps(new["candidate_adg"], sort_keys=True, separators=(",", ":"))
    new["candidate_snapshot_sha256"] = (
        "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()
    )
    with pytest.raises(ValueError, match="promoted"):
        verify(base, new)


def test_resigned_candidate_cannot_remap_branch_to_tool_witness(
    tmp_path: Path,
) -> None:
    import hashlib
    import json

    _repo(tmp_path)
    base = AgentDependencyGraph()
    candidate = build(base, tmp_path)
    changed = deepcopy(candidate)
    edge = next(row for row in changed["candidate_adg"]["edges"]
                if row["id"].endswith("edge:level_2:list_tables"))
    edge["target"] = "c03-pydantic-candidate:tool:execute_query"
    raw = json.dumps(changed["candidate_adg"], sort_keys=True,
                     separators=(",", ":"))
    changed["candidate_snapshot_sha256"] = (
        "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()
    )
    with pytest.raises(ValueError, match="witness remapped"):
        verify(base, changed)
    assert base.as_dict() == AgentDependencyGraph().as_dict()


def test_resigned_candidate_cannot_misstate_branch_selection(
    tmp_path: Path,
) -> None:
    _repo(tmp_path)
    base = AgentDependencyGraph()
    changed = deepcopy(build(base, tmp_path))
    changed["source_branches"]["level_1"] = ["list_tables"]
    with pytest.raises(ValueError, match="edge inventory changed"):
        verify(base, changed)
