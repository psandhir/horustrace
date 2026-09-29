from pathlib import Path

from horustrace.scanner import scan


def _write_sql_database_module(tmp_path: Path) -> None:
    utils = tmp_path / "utils"
    utils.mkdir()
    (utils / "database.py").write_text(
        """
from langchain_community.utilities import SQLDatabase

db = SQLDatabase.from_uri("sqlite:///example.db")
""",
        encoding="utf-8",
    )


def test_imported_langchain_sql_database_dynamic_statement_widens_authority(
    tmp_path: Path,
) -> None:
    _write_sql_database_module(tmp_path)
    (tmp_path / "tools.py").write_text(
        """
from langchain_core.tools import tool
from utils.database import db

@tool
def execute_query(query: str):
    return db.run_no_throw(query)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    tool = next(item for item in graph.unbound_tools if item.name == "execute_query")

    assert {"data.read", "data.write", "destructive.write"} <= tool.capabilities
    assert "process.execute" not in tool.capabilities
    assert tool.metadata["sql_database_api"] == "SQLDatabase.run_no_throw"
    assert tool.metadata["sql_statement_scope"] == "unconstrained"
    assert tool.metadata["sql_dynamic_statement"] is True
    assert tool.metadata["sql_authority_basis"] == "source_proven_langchain_sql_database"


def test_langchain_sql_database_literal_select_stays_read_only(
    tmp_path: Path,
) -> None:
    _write_sql_database_module(tmp_path)
    (tmp_path / "tools.py").write_text(
        """
from langchain_core.tools import tool
from utils.database import db

@tool
def database_health():
    return db.run("SELECT 1")
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    tool = next(item for item in graph.unbound_tools if item.name == "database_health")

    assert "data.read" in tool.capabilities
    assert "data.write" not in tool.capabilities
    assert "destructive.write" not in tool.capabilities
    assert tool.metadata["sql_statement_scope"] == "read_only"


def test_unrelated_run_no_throw_is_not_database_authority(
    tmp_path: Path,
) -> None:
    (tmp_path / "tools.py").write_text(
        """
from langchain_core.tools import tool

class Runner:
    def run_no_throw(self, value):
        return value

runner = Runner()

@tool
def execute_query(query: str):
    return runner.run_no_throw(query)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    tool = next(item for item in graph.unbound_tools if item.name == "execute_query")

    assert "data.read" in tool.capabilities
    assert "data.write" not in tool.capabilities
    assert "destructive.write" not in tool.capabilities
    assert "sql_authority_basis" not in tool.metadata


def test_chainlit_langgraph_dynamic_sql_composes_ingress_to_database_authority(
    tmp_path: Path,
) -> None:
    _write_sql_database_module(tmp_path)
    function_tools = tmp_path / "function_tools"
    function_tools.mkdir()
    (function_tools / "db_tools.py").write_text(
        """
from langchain_core.tools import tool
from utils.database import db

@tool
def execute_query(query: str):
    return db.run_no_throw(query)
""",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        """
import chainlit as cl
from function_tools.db_tools import execute_query
from langgraph.graph import StateGraph
from langgraph.prebuilt import ToolNode

tool_node = ToolNode([execute_query])
workflow = StateGraph(dict)
workflow.add_node("action", tool_node)
app = workflow.compile()

@cl.on_message
async def on_message(message: cl.Message):
    return app.invoke({"messages": [message.content]})
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    agent = next(
        item
        for item in graph.agents
        if item.metadata.get("framework") == "langgraph"
        and item.name == "workflow"
    )
    tool = next(item for item in agent.tools if item.name == "execute_query")

    assert {"data.read", "data.write", "destructive.write"} <= tool.capabilities
    assert tool.metadata["repository_resolved"] is True
    assert tool.metadata["sql_statement_scope"] == "unconstrained"

    ingress = next(
        item
        for item in agent.inputs
        if item.metadata.get("basis") == "source_bound_runtime_ingress"
    )
    assert ingress.metadata["ingress_framework"] == "chainlit"

    path = next(
        item
        for item in graph.attack_paths
        if item.path_id == "PATH002"
        and item.agent == agent.name
        and item.nodes[-2] == "execute_query"
    )
    assert path.metadata["basis"] == "source_bound_ingress_authority"
    assert path.nodes[-1] == "destructive.write"
