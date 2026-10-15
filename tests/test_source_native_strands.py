"""Wave B04 Strands cross-module agent/tool composition source evidence."""
from __future__ import annotations

import json
from pathlib import Path

from horustrace.models import Graph
from horustrace.semantic_shadow import shadow_observation_report
from horustrace.source_native_strands import inspect_strands_tool_composition


MAIN = """
from strands import Agent
from agents import cfn_explorer, analysis_writer

def orchestrate_analysis():
    common_tools = [shell]
    agents = [cfn_explorer, analysis_writer]
    orchestrator = Agent(tools=common_tools + agents)
    return orchestrator
"""

WRAPPER = """
try:
    from strands import Agent, tool
except ImportError:
    def tool(fn):
        return fn

@tool
def {name}():
    agent = Agent(model=some_model)
    response = agent("perform task")
    return response
"""


def _fixture(root: Path) -> None:
    agents = root / "agents"
    agents.mkdir(parents=True)
    (root / "main.py").write_text(MAIN, encoding="utf-8")
    (agents / "__init__.py").write_text(
        "from .cfn_explorer import cfn_explorer\n"
        "from .analysis_writer import analysis_writer\n",
        encoding="utf-8",
    )
    for name in ("cfn_explorer", "analysis_writer"):
        (agents / f"{name}.py").write_text(
            WRAPPER.format(name=name), encoding="utf-8",
        )


def test_source_chain_preserves_separate_nested_agent_instances(
    tmp_path: Path,
) -> None:
    _fixture(tmp_path)
    doc = inspect_strands_tool_composition(tmp_path).as_dict()
    assert doc["schema_version"] == 2
    assert sum(e["kind"] == "agent" for e in doc["entities"]) == 3
    assert sum(e["kind"] == "tool" for e in doc["entities"]) == 2
    assert len(doc["bindings"]) == 4
    assert all(e["kind"] == "invokes" for e in doc["bindings"])
    assert all(e["resolution"] == "partial" for e in doc["bindings"])
    assert all(e["metadata"]["agent_callability"] == "not_adjudicated"
               for e in doc["bindings"])
    assert len({e["entity_id"] for e in doc["entities"]}) == 5
    by_id = {node["entity_id"]: node for node in doc["entities"]}
    entry = [e for e in doc["entities"] if e["name"] == "orchestrator"]
    assert len(entry) == 1
    first_hop = [
        edge for edge in doc["bindings"] if edge["source_id"] == entry[0]["entity_id"]
    ]
    assert {by_id[e["target_id"]]["name"] for e in first_hop} == {
        "cfn_explorer", "analysis_writer",
    }
    second_hop = [
        edge for edge in doc["bindings"]
        if by_id[edge["source_id"]]["kind"] == "tool"
    ]
    assert {by_id[e["target_id"]]["name"] for e in second_hop} == {
        "inner_agent:cfn_explorer", "inner_agent:analysis_writer",
    }
    assert not any(e["kind"] in ("agent_can_call", "exposes_tool", "delegates_to")
                   for e in doc["bindings"])
    assert str(tmp_path) not in json.dumps(doc)


def test_strands_qualifier_is_stable_between_checkouts(tmp_path: Path) -> None:
    a, b = tmp_path / "checkout-a", tmp_path / "checkout-b"
    a.mkdir()
    b.mkdir()
    _fixture(a)
    _fixture(b)
    assert inspect_strands_tool_composition(a).as_dict() == (
        inspect_strands_tool_composition(b).as_dict()
    )
    report = shadow_observation_report(Graph(), a)
    assert report["source_native_strands"]["bindings"] == (
        inspect_strands_tool_composition(a).as_dict()["bindings"]
    )
    assert report["comparison"]["graph_behavior_changed"] is False


def test_no_wrapper_import_or_decorator_means_no_agent_relationship(
    tmp_path: Path,
) -> None:
    _fixture(tmp_path)
    package = tmp_path / "agents" / "__init__.py"
    package.write_text(
        "from .unrelated import cfn_explorer\n",
        encoding="utf-8",
    )
    doc = inspect_strands_tool_composition(tmp_path).as_dict()
    assert doc["bindings"] == []

    _fixture(tmp_path / "second")
    wrapper = tmp_path / "second" / "agents" / "cfn_explorer.py"
    wrapper.write_text(
        "from strands import Agent\n"
        "def cfn_explorer():\n"
        "    agent = Agent()\n"
        "    return agent('x')\n",
        encoding="utf-8",
    )
    doc = inspect_strands_tool_composition(tmp_path / "second").as_dict()
    assert len(doc["bindings"]) == 2  # only analysis_writer remains


def test_shadowed_imported_wrapper_or_dynamic_tools_expression_is_not_linked(
    tmp_path: Path,
) -> None:
    _fixture(tmp_path)
    main = tmp_path / "main.py"
    main.write_text(
        MAIN.replace(
            "    orchestrator = Agent(tools=common_tools + agents)\n",
            "    cfn_explorer = lambda: None\n"
            "    orchestrator = Agent(tools=common_tools + agents)\n",
        ),
        encoding="utf-8",
    )
    report = inspect_strands_tool_composition(tmp_path).as_dict()
    assert len(report["bindings"]) == 2

    main.write_text(
        MAIN.replace(
            "tools=common_tools + agents",
            "tools=get_tools(agents)",
        ),
        encoding="utf-8",
    )
    assert inspect_strands_tool_composition(tmp_path).bindings == []


def test_wrapper_without_inner_agent_invocation_is_not_linked(
    tmp_path: Path,
) -> None:
    _fixture(tmp_path)
    wrapper = tmp_path / "agents" / "cfn_explorer.py"
    wrapper.write_text(
        WRAPPER.format(name="cfn_explorer").replace(
            '    response = agent("perform task")\n',
            '    response = "not an agent call"\n',
        ),
        encoding="utf-8",
    )
    report = inspect_strands_tool_composition(tmp_path).as_dict()
    assert len(report["bindings"]) == 2
