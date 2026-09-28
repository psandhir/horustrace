from pathlib import Path

from horustrace.analysis import build_attack_paths
from horustrace.models import Agent, Graph, InputSource, MCPServer, SourceLocation
from horustrace.scanner import scan


def test_web_route_ingress_reaches_langgraph_destructive_tool(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        """
import sqlite3
from fastapi import APIRouter
from pydantic import BaseModel
from langchain_core.tools import tool
from langgraph.graph import StateGraph
from langgraph.prebuilt import ToolNode

router = APIRouter()

class RequestModel(BaseModel):
    query: str

@tool
def execute_sqlite_query(query: str):
    conn = sqlite3.connect("example.db")
    cursor = conn.cursor()
    cursor.execute(query)
    if query.strip().lower().startswith("select"):
        return cursor.fetchall()
    conn.commit()
    return "ok"

tools = [execute_sqlite_query]

def create_agent():
    builder = StateGraph(dict)
    builder.add_node("tools", ToolNode(tools))
    return builder.compile()

async def stream_agent_response(query: str):
    react_graph = create_agent()
    state = {"messages": [query]}
    return react_graph.invoke(state)

@router.post("/query")
async def chat_query(request: RequestModel):
    return await stream_agent_response(request.query)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)

    agent = next(item for item in graph.agents if item.name == "builder")
    assert agent.metadata["factory_function"] == "create_agent"
    assert any(source.trust == "untrusted" for source in agent.inputs)

    rule_ids = {finding.rule_id for finding in findings if finding.agent == agent.name}
    assert {"AGT021", "AGT022", "AGT040", "CAP005", "PATH002"} <= rule_ids


def test_untrusted_agent_input_can_reach_destructive_bound_mcp() -> None:
    location = SourceLocation(Path("agent.py"), line=10)
    server = MCPServer(
        name="plotting",
        transport="stdio",
        location=location,
        metadata={
            "discovered_tool_capabilities": [
                "data.write",
                "destructive.write",
            ]
        },
    )
    graph = Graph(
        agents=[
            Agent(
                name="agent",
                inputs=[
                    InputSource(
                        name="cli-input",
                        trust="untrusted",
                        kind="user",
                        location=location,
                    )
                ],
                mcp_servers=[server],
                location=location,
            )
        ]
    )

    paths = build_attack_paths(graph)

    path = next(item for item in paths if item.path_id == "PATH002")
    assert path.agent == "agent"
    assert path.nodes == [
        "cli-input",
        "agent",
        "plotting",
        "destructive.write",
    ]
