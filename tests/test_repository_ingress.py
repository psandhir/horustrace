from pathlib import Path

from horustrace.scanner import scan


def test_web_ingress_reaches_langgraph_factory_runtime(tmp_path: Path) -> None:
    (tmp_path / "tools.py").write_text(
        """
import sqlite3
from langchain_core.tools import tool

@tool
def execute_sqlite_query(query: str):
    conn = sqlite3.connect("example.db")
    cursor = conn.cursor()
    cursor.execute(query)
    conn.commit()
""",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        """
from langgraph.graph import StateGraph
from langgraph.prebuilt import ToolNode
from tools import execute_sqlite_query

tools = [execute_sqlite_query]

def create_agent():
    builder = StateGraph(dict)
    builder.add_node("tools", ToolNode(tools))
    return builder.compile()
""",
        encoding="utf-8",
    )
    (tmp_path / "api.py").write_text(
        """
from fastapi import APIRouter
from agent import create_agent

router = APIRouter()

async def stream_agent_response(query: str):
    react_graph = create_agent()
    state = {"messages": [query]}
    return react_graph.invoke(state)

@router.post("/query")
async def chat_query(request):
    return await stream_agent_response(request.query)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)

    agent = next(item for item in graph.agents if item.metadata.get("framework") == "langgraph")
    assert any(item.trust == "untrusted" for item in agent.inputs)
    assert any(item.rule_id == "PATH002" and item.agent == agent.name for item in findings)
