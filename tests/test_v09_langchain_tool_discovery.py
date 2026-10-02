from pathlib import Path

from horustrace.adapters.registry import detect_python_frameworks
from horustrace.scanner import scan


def test_langchain_tool_decorator_is_discovered_without_granting_authority(
    tmp_path: Path,
) -> None:
    source = tmp_path / "tools.py"
    source.write_text(
        """
from langchain_core.tools import tool

@tool
def search_docs(query: str) -> str:
    return query
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    assert "langchain-tools" in detect_python_frameworks(source)
    assert graph.agents == []
    assert len(graph.unbound_tools) == 1
    tool = graph.unbound_tools[0]
    assert tool.name == "search_docs"
    assert tool.kind == "langchain_tool"
    assert "data.read" in tool.capabilities
    assert tool.metadata["binding_state"] == "unbound"

    assert graph.adg is not None
    node = next(
        item
        for item in graph.adg.nodes
        if item.kind == "tool" and item.name == "search_docs"
    )
    assert node.attributes["unbound"] is True
    assert not any(
        edge.kind == "INVOKES" and edge.target == node.node_id
        for edge in graph.adg.edges
    )


def test_langchain_tool_decorator_alias_and_explicit_name_are_supported(
    tmp_path: Path,
) -> None:
    (tmp_path / "tools.py").write_text(
        """
from langchain_core.tools import tool as lc_tool

@lc_tool("public_search")
def internal_search(query: str) -> str:
    return query
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    assert [tool.name for tool in graph.unbound_tools] == ["public_search"]
    assert graph.unbound_tools[0].metadata["definition_name"] == "internal_search"


def test_structured_tool_from_function_is_discovered(tmp_path: Path) -> None:
    (tmp_path / "tools.py").write_text(
        """
from langchain_core.tools import StructuredTool

def write_report(text: str) -> str:
    with open("report.txt", "w") as handle:
        handle.write(text)
    return "ok"

report_tool = StructuredTool.from_function(
    func=write_report,
    name="publish_report",
)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    tool = next(item for item in graph.unbound_tools if item.name == "publish_report")
    assert "data.write" in tool.capabilities
    assert tool.metadata["definition_name"] == "write_report"
    assert tool.metadata["discovery_source"] == "langchain_structured_tool"


def test_unrelated_tool_decorator_is_not_treated_as_langchain_tool(
    tmp_path: Path,
) -> None:
    source = tmp_path / "custom.py"
    source.write_text(
        """
def tool(fn):
    return fn

@tool
def custom_action(value):
    return value
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    assert "langchain-tools" not in detect_python_frameworks(source)
    assert graph.unbound_tools == []


def test_langchain_tool_import_without_decorated_definition_emits_no_tool(
    tmp_path: Path,
) -> None:
    (tmp_path / "helpers.py").write_text(
        """
from langchain_core.tools import tool

def ordinary_helper(value):
    return value
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    assert graph.unbound_tools == []


def test_sql_execute_tool_is_database_authority_not_process_execution(
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

    graph, findings = scan(tmp_path)
    tool = next(item for item in graph.unbound_tools if item.name == "execute_sqlite_query")

    assert "process.execute" not in tool.capabilities
    assert {"data.read", "data.write", "destructive.write"} <= tool.capabilities
    assert not any(
        finding.rule_id == "AGT020"
        and finding.location
        and finding.location.path.name == "tools.py"
        for finding in findings
    )


def test_execute_code_name_retains_process_execution_semantics(
    tmp_path: Path,
) -> None:
    (tmp_path / "tools.py").write_text(
        """
from langchain_core.tools import tool

@tool
def execute_code(source: str):
    return source
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    tool = next(item for item in graph.unbound_tools if item.name == "execute_code")

    assert "process.execute" in tool.capabilities


def test_langchain_sqldatabase_run_no_throw_exposes_unconstrained_sql_authority(
    tmp_path: Path,
) -> None:
    (tmp_path / "tools.py").write_text(
        """
from langchain_core.tools import tool
from langchain_community.utilities import SQLDatabase

db = SQLDatabase.from_uri("postgresql://user:pass@db.example/app")

@tool
def execute_query(query: str):
    return db.run_no_throw(query)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    tool = next(item for item in graph.unbound_tools if item.name == "execute_query")

    assert tool.metadata["binding_state"] == "unbound"
    assert "process.execute" not in tool.capabilities
    assert {"data.read", "data.write", "destructive.write"} <= tool.capabilities
    assert not any(finding.agent == "execute_query" for finding in findings)


def test_generic_run_method_does_not_become_sql_authority(
    tmp_path: Path,
) -> None:
    (tmp_path / "tools.py").write_text(
        """
from langchain_core.tools import tool

class Worker:
    def run(self, value):
        return value

worker = Worker()

@tool
def execute_report(query: str):
    return worker.run(query)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    tool = next(item for item in graph.unbound_tools if item.name == "execute_report")

    assert "process.execute" not in tool.capabilities
    assert "destructive.write" not in tool.capabilities
