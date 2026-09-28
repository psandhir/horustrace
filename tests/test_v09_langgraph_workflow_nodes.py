from pathlib import Path

from horustrace.scanner import scan


def test_langgraph_workflow_nodes_are_explicit_non_principal_topology(
    tmp_path: Path,
) -> None:
    (tmp_path / "workflow.py").write_text(
        """
from langgraph.graph import StateGraph
from langgraph.prebuilt import ToolNode


def normalize(state):
    return {"messages": state.get("messages", [])}


def chatbot(state):
    return llm.invoke(state["messages"])


def search(query):
    return query


tool_node = ToolNode([search])
workflow = StateGraph(dict)
workflow.add_node("normalize", normalize)
workflow.add_node("chatbot", chatbot)
workflow.add_node("tools", tool_node)
workflow.add_edge("normalize", "chatbot")
workflow.add_edge("chatbot", "tools")
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    assert [agent.name for agent in graph.agents if agent.metadata.get("framework") == "langgraph"] == [
        "workflow"
    ]
    roles = {node.name: node.role for node in graph.workflow_nodes}
    assert roles == {
        "normalize": "deterministic_transform",
        "chatbot": "model_agent",
        "tools": "tool_node",
    }

    # Legacy Tool projections remain available for finding/capability analysis,
    # but workflow registration alone must not become effective authority.
    agent = next(agent for agent in graph.agents if agent.name == "workflow")
    assert {tool.name for tool in agent.tools} == {
        "normalize",
        "chatbot",
        "tools",
        "search",
    }
    projected = [
        tool
        for tool in agent.tools
        if tool.metadata.get("authority_binding") == "workflow_projection"
    ]
    assert {tool.name for tool in projected} == {"normalize", "chatbot", "tools"}
    search = next(tool for tool in agent.tools if tool.name == "search")
    assert search.metadata["authority_binding"] == "direct"
    assert search.metadata["authority_binding_basis"] == "langgraph_tool_node_catalogue"

    assert graph.adg is not None
    workflow_nodes = {
        node.name: node
        for node in graph.adg.nodes
        if node.kind == "workflow_node"
    }
    assert set(workflow_nodes) == {"normalize", "chatbot", "tools"}
    assert workflow_nodes["normalize"].attributes["role"] == "deterministic_transform"
    assert workflow_nodes["chatbot"].attributes["role"] == "model_agent"
    assert workflow_nodes["tools"].attributes["role"] == "tool_node"

    contains = [edge for edge in graph.adg.edges if edge.kind == "CONTAINS"]
    assert len(contains) == 3

    projected_tool_nodes = {
        node.node_id
        for node in graph.adg.nodes
        if node.kind == "tool"
        and node.attributes.get("authority_binding") == "workflow_projection"
    }
    assert len(projected_tool_nodes) == 3
    assert not any(
        edge.kind == "INVOKES" and edge.target in projected_tool_nodes
        for edge in graph.adg.edges
    )

    node_ids = {node.node_id for node in workflow_nodes.values()}
    workflow_control = [
        edge
        for edge in graph.adg.edges
        if edge.kind == "WORKFLOW_FLOWS_TO"
        and edge.source in node_ids
        and edge.target in node_ids
    ]
    assert len(workflow_control) == 2
    assert all(edge.attributes["projection"] == "workflow" for edge in workflow_control)


def test_langgraph_factory_object_registered_as_node_is_model_agent(
    tmp_path: Path,
) -> None:
    (tmp_path / "workflow.py").write_text(
        """
from langgraph.graph import StateGraph
from langgraph.prebuilt import create_react_agent


def lookup(query):
    return query


researcher = create_react_agent("openai:gpt-5", tools=[lookup])
workflow = StateGraph(dict)
workflow.add_node("researcher", researcher)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    node = next(node for node in graph.workflow_nodes if node.name == "researcher")
    assert node.role == "model_agent"
    assert node.metadata["function"] == "researcher"


def test_langgraph_router_node_is_control_not_agent(tmp_path: Path) -> None:
    (tmp_path / "workflow.py").write_text(
        """
from langgraph.graph import StateGraph


def route(state):
    if state.get("ok"):
        return "left"
    return "right"


workflow = StateGraph(dict)
workflow.add_node("router", route)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    node = next(node for node in graph.workflow_nodes if node.name == "router")
    assert node.role == "control"
    assert not any(agent.name == "router" for agent in graph.agents)


def test_langgraph_toolnode_catalogue_binds_cross_file_tool_authority(
    tmp_path: Path,
) -> None:
    (tmp_path / "tools.py").write_text(
        """
import sqlite3
from langchain_core.tools import tool

@tool
def execute_sqlite_query(query: str):
    conn = sqlite3.connect("example.db")
    cursor = conn.cursor()
    cursor.execute(query)
    if query.strip().lower().startswith("select"):
        return cursor.fetchall()
    conn.commit()
    return "ok"
""",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        """
from langgraph.graph import StateGraph
from langgraph.prebuilt import ToolNode
from tools import execute_sqlite_query

tools = [execute_sqlite_query]
workflow = StateGraph(dict)
workflow.add_node("tools", ToolNode(tools))
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)

    agent = next(
        item for item in graph.agents
        if item.metadata.get("framework") == "langgraph"
    )
    tool = next(item for item in agent.tools if item.name == "execute_sqlite_query")

    assert tool.metadata["authority_binding"] == "direct"
    assert tool.metadata["repository_resolved"] is True
    assert "process.execute" not in tool.capabilities
    assert {"data.read", "data.write", "destructive.write"} <= tool.capabilities

    rule_ids = {finding.rule_id for finding in findings if finding.agent == agent.name}
    assert {"AGT021", "AGT022", "AGT040", "CAP005"} <= rule_ids
