from pathlib import Path

from horustrace.scanner import scan


def test_deterministic_stategraph_is_marked_non_model_driven(tmp_path: Path) -> None:
    (tmp_path / "workflow.py").write_text(
        """
from langgraph.graph import END, START, StateGraph

def normalize(state):
    return {"value": state.get("value", 0)}

def transform(state):
    return {"value": state["value"] + 1}

workflow = StateGraph(dict)
workflow.add_node("normalize", normalize)
workflow.add_node("transform", transform)
workflow.add_edge(START, "normalize")
workflow.add_edge("normalize", "transform")
workflow.add_edge("transform", END)
graph = workflow.compile()
graph.invoke({})
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    workflow = next(
        agent
        for agent in graph.agents
        if agent.metadata.get("framework") == "langgraph"
    )
    assert workflow.metadata["model_driven_workflow"] is False
    assert workflow.metadata["workflow_roles"] == ["deterministic_transform"]


def test_model_stategraph_is_marked_model_driven(tmp_path: Path) -> None:
    (tmp_path / "workflow.py").write_text(
        """
from langgraph.graph import StateGraph

def chatbot(state):
    return llm.invoke(state["messages"])

workflow = StateGraph(dict)
workflow.add_node("chatbot", chatbot)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    workflow = next(
        agent
        for agent in graph.agents
        if agent.metadata.get("framework") == "langgraph"
    )
    assert workflow.metadata["model_driven_workflow"] is True
    assert workflow.metadata["workflow_roles"] == ["model_agent"]


def test_deterministic_workflow_capabilities_do_not_become_agent_findings(
    tmp_path: Path,
) -> None:
    (tmp_path / "workflow.py").write_text(
        """
from langgraph.graph import StateGraph

def transform(state):
    current = state.get("value")
    state.update({"value": current})
    return state

workflow = StateGraph(dict)
workflow.add_node("transform", transform)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)

    workflow = next(
        agent
        for agent in graph.agents
        if agent.metadata.get("framework") == "langgraph"
    )
    assert {"data.read", "data.write"} <= workflow.capabilities
    assert workflow.metadata["model_driven_workflow"] is False
    assert not any(finding.agent == workflow.name for finding in findings)
    assert graph.adg is not None
    assert any(
        node.kind == "agent" and node.name == workflow.name
        for node in graph.adg.nodes
    )
