from pathlib import Path

from horustrace.scanner import scan


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_adk_literal_sql_insert_is_write_authority(tmp_path: Path) -> None:
    _write(
        tmp_path / "agent.py",
        """
import sqlite3
from google.adk.agents import Agent

def add_task(title: str) -> str:
    conn = sqlite3.connect("tasks.db")
    conn.execute("INSERT INTO tasks(title) VALUES (?)", (title,))
    conn.commit()
    return "ok"

root_agent = Agent(name="root", model="gemini-2.5-flash", tools=[add_task])
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "root")
    tool = next(item for item in agent.tools if item.name == "add_task")

    assert "data.write" in tool.capabilities
    assert "sql:execute" in tool.metadata["repository_effect_evidence"]


def test_pydantic_asyncio_to_thread_propagates_process_execution(
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
    return await _run_bash(command)

async def _run_bash(command: str) -> dict:
    return await asyncio.to_thread(_run_bash_sync, command)

def _run_bash_sync(command: str) -> dict:
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return {"returncode": result.returncode}
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    tool = next(item for item in agent.tools if item.name == "bash")

    assert "process.execute" in tool.capabilities
    assert any(
        evidence.startswith("process:subprocess.run")
        for evidence in tool.metadata["repository_effect_evidence"]
    )


def test_pydantic_http_post_is_external_write_but_search_post_is_not(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "agent.py",
        """
import requests
from pydantic_ai import Agent

agent = Agent("openai:gpt-4o")

@agent.tool_plain
def send_alert(message: str) -> str:
    requests.post("https://alerts.example.test/messages", json={"message": message})
    return "sent"

@agent.tool_plain
def search_catalog(query: str) -> dict:
    return requests.post("https://search.example.test/query", json={"q": query}).json()
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    send = next(item for item in agent.tools if item.name == "send_alert")
    search = next(item for item in agent.tools if item.name == "search_catalog")

    assert {"network.external", "external.write"} <= send.capabilities
    assert "network.external" in search.capabilities
    assert "external.write" not in search.capabilities


def test_http_delete_is_destructive_external_write(tmp_path: Path) -> None:
    _write(
        tmp_path / "agent.py",
        """
import httpx
from pydantic_ai import Agent

agent = Agent("openai:gpt-4o")

@agent.tool_plain
def delete_remote(item_id: str) -> None:
    httpx.delete(f"https://api.example.test/items/{item_id}")
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    tool = next(item for item in agent.tools if item.name == "delete_remote")

    assert {"network.external", "external.write", "destructive.write"} <= tool.capabilities


def test_adk_local_collection_mutation_is_not_persistent_write(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "agent.py",
        """
import sys
from google.adk.agents import Agent

def list_files() -> list[str]:
    sys.path.insert(0, ".")
    results = []
    results.append("one")
    return results

root_agent = Agent(name="root", model="gemini-2.5-flash", tools=[list_files])
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "root")
    tool = next(item for item in agent.tools if item.name == "list_files")

    assert "data.read" in tool.capabilities
    assert "data.write" not in tool.capabilities
    assert "destructive.write" not in tool.capabilities
