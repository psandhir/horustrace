"""FastAgent source-defined composite workflows never inflate agent inventory."""
from __future__ import annotations

from pathlib import Path

from horustrace.scanner import scan


def test_chain_and_evaluator_are_workflows_not_agent_instances(
    tmp_path: Path,
) -> None:
    (tmp_path / "source.py").write_text(
        """
from mcp_agent.core.fastagent import FastAgent
fast = FastAgent("Writers")

@fast.agent(name="concept_developer", servers=["narrative"])
async def first(): pass

@fast.agent(name="editor")
async def second(): pass

@fast.chain(name="writing_workflow", sequence=["concept_developer", "editor"])
async def chain(): pass

@fast.evaluator_optimizer(name="story_refinement",
                          generator="concept_developer", evaluator="editor")
async def refine(): pass
""", encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    assert {agent.name for agent in graph.agents} == {
        "concept_developer", "editor",
    }
    assert {(workflow.name, workflow.method) for workflow in graph.workflow_nodes} == {
        ("writing_workflow", "chain"),
        ("story_refinement", "evaluator_optimizer"),
    }
    assert all(w.metadata["runtime_instance_verified"] is False
               and w.metadata["runtime_effectiveness"] == "not_verified"
               for w in graph.workflow_nodes)
    assert graph.adg is not None
    nodes = graph.adg.nodes
    assert len([n for n in nodes if n.kind == "agent"]) == 2
    assert len([n for n in nodes if n.kind == "workflow_node"]) == 2
    edges = [e for e in graph.adg.edges if e.kind == "WORKFLOW_FLOWS_TO"]
    assert len(edges) == 4
    assert all(e.attributes.get("runtime_effectiveness") == "not_verified"
               for e in edges)
    assert not any(e.kind == "AGENT_CAN_CALL" for e in graph.adg.edges)


def test_unknown_workflow_member_is_not_synthesized_agent(
    tmp_path: Path,
) -> None:
    (tmp_path / "source.py").write_text(
        """
from fast_agent import FastAgent
fast = FastAgent("App")
@fast.agent(name="real")
async def real(): pass
@fast.chain(name="sequence", sequence=["real", "dynamic_not_declared"])
async def compose(): pass
""", encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    assert {a.name for a in graph.agents} == {"real"}
    assert graph.workflow_nodes[0].members == ["real", "dynamic_not_declared"]
    assert graph.adg is not None
    assert not any(n.kind == "agent" and n.name == "dynamic_not_declared"
                   for n in graph.adg.nodes)
    assert len([e for e in graph.adg.edges if e.kind == "WORKFLOW_FLOWS_TO"]) == 1


def test_plain_fastagent_manager_is_not_agent_object(
    tmp_path: Path,
) -> None:
    (tmp_path / "source.py").write_text(
        'from fast_agent import FastAgent\nfast = FastAgent("Manager")\n',
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    assert not graph.agents
    assert not graph.workflow_nodes


def test_routing_and_parallel_are_not_reclassified_by_this_bounded_fix(
    tmp_path: Path,
) -> None:
    (tmp_path / "source.py").write_text(
        """
from fast_agent import FastAgent
fast = FastAgent("Demo")
@fast.agent(name="worker")
async def worker(): pass
@fast.parallel(name="fanout", fan_out=["worker"])
async def fanout(): pass
@fast.router(name="router", agents=["worker"])
async def router(): pass
""", encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    assert {a.name for a in graph.agents} == {"worker", "fanout", "router"}
    assert not graph.workflow_nodes
