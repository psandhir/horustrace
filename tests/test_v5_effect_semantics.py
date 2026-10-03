from pathlib import Path

from horustrace.mcp_effective import effective_mcp_authority_report
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

    assert {"network.external", "data.write", "external.write"} <= send.capabilities
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

    assert {
        "network.external",
        "data.write",
        "external.write",
        "destructive.write",
    } <= tool.capabilities


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


def test_adk_operator_configured_request_alias_is_restricted(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "agent.py",
        """
import os
import urllib.request
from google.adk.agents import Agent

def _gitlab_get(path: str) -> str:
    base = os.environ.get("GITLAB_URL", "https://gitlab.com")
    url = f"{base}/api/v4{path}"
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req) as response:
        return response.read().decode()

def get_pipeline(project: str) -> str:
    return _gitlab_get(f"/projects/{project}/pipelines")

root_agent = Agent(
    name="incident_responder",
    model="gemini-2.5-flash",
    tools=[get_pipeline],
)
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "incident_responder")
    tool = next(item for item in agent.tools if item.name == "get_pipeline")

    assert "network.external" in tool.capabilities
    assert any(
        destination.restricted is True
        and destination.metadata.get("configuration_source") == "GITLAB_URL"
        for destination in tool.destinations
    ), [
        (destination.target, destination.restricted, destination.metadata)
        for destination in tool.destinations
    ]
    assert not any(
        destination.target == "<dynamic-url>"
        and destination.restricted is False
        for destination in tool.destinations
    )


def test_typed_config_base_url_is_operator_configured_destination(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "integration.py",
        """
from dataclasses import dataclass
import httpx

@dataclass
class AlpacaConfig:
    base_url: str

def create_order(cfg: AlpacaConfig, symbol: str):
    url = f"{cfg.base_url}/orders"
    return httpx.post(url, json={"symbol": symbol})
""",
    )
    _write(
        tmp_path / "agent.py",
        """
from pydantic_ai import Agent
from integration import create_order

agent = Agent("openai:gpt-4o", tools=[create_order])
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    tool = next(item for item in agent.tools if item.name == "create_order")

    assert {"network.external", "external.write"} <= tool.capabilities
    assert any(
        destination.restricted is True
        and destination.metadata.get("network_scope")
        == "operator_configured_destination"
        and destination.metadata.get("configuration_source") == "cfg.base_url"
        for destination in tool.destinations
    )


def test_pydantic_runtime_boolean_gate_is_a_guardrail(tmp_path: Path) -> None:
    _write(
        tmp_path / "agent.py",
        """
import requests
from dataclasses import dataclass
from pydantic_ai import Agent, RunContext

@dataclass
class Deps:
    allow_trading: bool

agent = Agent("openai:gpt-4o", deps_type=Deps)

@agent.tool
def create_order(ctx: RunContext[Deps], symbol: str) -> dict:
    if not ctx.deps.allow_trading:
        return {"ok": False, "reason": "trading disabled"}
    requests.post("https://broker.example.test/orders", json={"symbol": symbol})
    return {"ok": True}
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    tool = next(item for item in agent.tools if item.name == "create_order")

    assert tool.guardrails is True
    assert tool.metadata.get("authorization_gate") is True
    assert {"data.write", "external.write"} <= tool.capabilities


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
    assert (
        tool.metadata.get("filesystem_control_basis")
        == "canonical_path_containment"
    )
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



def test_adk_factory_returned_agent_preserves_local_mcp_binding(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "agent.py",
        """
from google.adk.agents import Agent
from google.adk.tools.mcp_tool.mcp_toolset import MCPToolset, StdioConnectionParams
from mcp import StdioServerParameters

def create_agent() -> Agent:
    gitlab_mcp = MCPToolset(
        connection_params=StdioConnectionParams(
            server_params=StdioServerParameters(
                command="mcp-gitlab",
                args=[],
            )
        )
    )
    return Agent(
        name="gitlab_incident_responder",
        model="gemini-2.5-flash",
        tools=[gitlab_mcp],
    )

root_agent = create_agent()
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(
        item for item in graph.agents
        if item.name == "gitlab_incident_responder"
    )

    assert len(agent.mcp_servers) == 1
    server = agent.mcp_servers[0]
    assert server.name == "gitlab_mcp"
    assert server.transport == "stdio"
    assert server.command == "mcp-gitlab"

    authority = effective_mcp_authority_report(graph)
    assert authority["summary"]["bound_relationships"] == 1
    assert authority["summary"]["unbound_servers"] == 0
    assert authority["authorities"][0]["agent"] == "gitlab_incident_responder"
    assert authority["authorities"][0]["server"] == "gitlab_mcp"
