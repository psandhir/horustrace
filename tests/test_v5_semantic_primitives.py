from pathlib import Path

from horustrace.scanner import scan


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_repository_sql_insert_is_write_authority(tmp_path: Path) -> None:
    _write(
        tmp_path / "tools.py",
        """
def add_task(description: str) -> str:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO tasks (description) VALUES (?)", (description,))
        conn.commit()
    return "ok"
""",
    )
    _write(
        tmp_path / "agent.py",
        """
from pydantic_ai import Agent
from tools import add_task

agent = Agent("openai:gpt-4o", tools=[add_task])
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    tool = next(item for item in agent.tools if item.name == "add_task")

    assert "data.write" in tool.capabilities
    assert "sql-write:insert" in tool.metadata["repository_effect_evidence"]


def test_pydantic_asyncio_to_thread_propagates_subprocess_effect(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "agent.py",
        """
import asyncio
import subprocess
from pydantic_ai import Agent

agent = Agent("openai:gpt-4o")

@agent.tool_plain
async def bash(command: str) -> dict:
    return await asyncio.to_thread(_run_bash_sync, command)

def _run_bash_sync(command: str) -> dict:
    result = subprocess.run(
        command,
        shell=True,
        check=False,
        capture_output=True,
        text=True,
    )
    return {"returncode": result.returncode}
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    tool = next(item for item in agent.tools if item.name == "bash")

    assert "process.execute" in tool.capabilities
    assert "process:subprocess.run" in tool.metadata["repository_effect_evidence"]


def test_imported_http_delete_is_destructive_external_write(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "positions.py",
        """
import httpx

def close_position(base_url: str, symbol: str):
    url = f"{base_url}/positions/{symbol}"
    return httpx.delete(url, timeout=20.0)
""",
    )
    _write(
        tmp_path / "agent.py",
        """
from pydantic_ai import Agent
from positions import close_position

agent = Agent("openai:gpt-4o", tools=[close_position])
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    tool = next(item for item in agent.tools if item.name == "close_position")

    assert {
        "network.external",
        "data.write",
        "external.write",
        "destructive.write",
    } <= tool.capabilities


def test_adk_named_mcp_toolset_in_tools_list_binds_as_mcp(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "agent.py",
        """
from google.adk.agents import Agent
from google.adk.tools.mcp_tool.mcp_toolset import MCPToolset, StdioConnectionParams
from mcp import StdioServerParameters

gitlab_mcp = MCPToolset(
    connection_params=StdioConnectionParams(
        server_params=StdioServerParameters(
            command="mcp-gitlab",
            args=[],
        )
    )
)

root_agent = Agent(
    name="incident_responder",
    model="gemini-2.5-flash",
    tools=[gitlab_mcp],
)
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "incident_responder")

    assert len(agent.mcp_servers) == 1
    server = agent.mcp_servers[0]
    assert server.name == "gitlab_mcp"
    assert server.transport == "stdio"
    assert server.command == "mcp-gitlab"


def test_adk_local_list_append_does_not_create_write_authority(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "agent.py",
        """
from google.adk.agents import Agent
from pathlib import Path

def tool_list_datalog_files() -> dict:
    rules = []
    for f in sorted(Path("rules").glob("*.dl")):
        rules.append({"name": f.name, "size_bytes": f.stat().st_size})

    facts = []
    for f in sorted(Path("facts").glob("*.facts")):
        facts.append({"name": f.name, "rows": 1})

    return {"rules": rules, "facts": facts}

root_agent = Agent(
    name="BinCodeQL",
    model="gemini-2.5-flash",
    tools=[tool_list_datalog_files],
)
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "BinCodeQL")
    tool = next(item for item in agent.tools if item.name == "tool_list_datalog_files")

    assert "data.write" not in tool.capabilities
    assert "destructive.write" not in tool.capabilities
