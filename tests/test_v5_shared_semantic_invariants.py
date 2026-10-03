from pathlib import Path

from horustrace.scanner import scan


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_adk_sqlite_literal_insert_is_persistent_write(tmp_path: Path) -> None:
    _write(
        tmp_path / "db.py",
        """
import sqlite3

def add_task(title: str) -> str:
    conn = sqlite3.connect("tasks.db")
    conn.execute("INSERT INTO tasks(title) VALUES (?)", (title,))
    conn.commit()
    return "created"
""",
    )
    _write(
        tmp_path / "agent.py",
        """
from google.adk.agents import Agent
from db import add_task

root_agent = Agent(
    name="task-agent",
    model="gemini-2.5-flash",
    tools=[add_task],
)
""",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "task-agent")
    tool = next(item for item in agent.tools if item.name == "add_task")

    assert "data.write" in tool.capabilities
    assert any(
        evidence == "database-sql:insert"
        for evidence in tool.metadata.get("repository_effect_evidence", [])
    )
    assert any(
        finding.agent == "task-agent"
        and finding.rule_id in {"AGT022", "AGT040"}
        for finding in findings
    )


def test_pydantic_same_module_to_thread_helper_propagates_process_execute(
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

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    tool = next(item for item in agent.tools if item.name == "bash")

    assert "process.execute" in tool.capabilities
    assert tool.metadata.get("repository_effect_resolved") is True
    assert any(
        evidence.startswith("process:subprocess.run")
        for evidence in tool.metadata.get("repository_effect_evidence", [])
    )
    assert any(
        finding.agent == "agent"
        and finding.rule_id in {"AGT020", "AGT040"}
        for finding in findings
    )


def test_openai_workspace_path_guard_suppresses_unconstrained_path_claim(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "agent.py",
        """
from pathlib import Path
from agents import Agent, function_tool

WORKDIR = Path("/workspace").resolve()

def _safe_path(path: str) -> Path:
    target = (WORKDIR / path).resolve()
    if target != WORKDIR and WORKDIR not in target.parents:
        raise ValueError("path escapes workspace")
    return target

@function_tool
def write(path: str, content: str) -> str:
    target = _safe_path(path)
    target.write_text(content)
    return "written"

agent = Agent(name="coder", tools=[write])
""",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "coder")
    tool = next(item for item in agent.tools if item.name == "write")

    assert tool.metadata.get("filesystem_path_constrained") is True
    assert tool.metadata.get("filesystem_control_basis") == "canonical_path_containment"
    assert any(
        resource.kind == "file"
        and resource.selector == "<source-constrained-workspace>"
        and resource.metadata.get("path_containment") == "source_proven"
        for resource in tool.resources
    )
    assert not any(
        resource.kind == "file"
        and resource.selector == "<model-selected-path>"
        for resource in tool.resources
    )
    assert not any(
        finding.agent == "coder" and finding.rule_id == "PATH012"
        for finding in findings
    )
