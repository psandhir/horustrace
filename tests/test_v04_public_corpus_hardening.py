from pathlib import Path

from horustrace.adapters.registry import detect_python_frameworks
from horustrace.scanner import scan


def test_programmatic_mcp_stdio_client_is_discovered(tmp_path: Path) -> None:
    (tmp_path / "client.py").write_text(
        """
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

params = StdioServerParameters(command="python", args=["server.py"])

async def run():
    async with stdio_client(params) as streams:
        pass
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    servers = graph.all_mcp_servers()
    assert len(servers) == 1
    assert servers[0].transport == "stdio"
    assert servers[0].command == "python"
    assert servers[0].args == ["server.py"]


def test_fastmcp_server_and_tools_are_discovered(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        """
from fastmcp import FastMCP

mcp = FastMCP("demo")

@mcp.tool
def search(query: str):
    return query

if __name__ == "__main__":
    mcp.run(transport="sse")
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    assert any(server.name == "demo" and server.transport == "sse"
               for server in graph.all_mcp_servers())
    assert any(tool.name == "search" and tool.kind == "mcp_exposed_tool"
               for tool in graph.all_tools())


def test_framework_detected_but_not_normalized_is_incomplete(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        """
from agents import Agent

def unrelated():
    return "no agent constructed"
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    diagnostic = next(
        item for item in graph.coverage.diagnostics
        if item.kind == "framework_not_normalized"
    )
    assert diagnostic.diagnostic_id == "ARG-COV-015"
    assert diagnostic.details["framework"] == "openai-agents"


def test_notebook_code_cells_are_scanned_statically(tmp_path: Path) -> None:
    (tmp_path / "agent.ipynb").write_text(
        """{
  "cells": [
    {
      "cell_type": "code",
      "metadata": {},
      "source": [
        "from agents import Agent\\n",
        "agent = Agent(name='NotebookAgent', tools=[])\\n"
      ],
      "outputs": [],
      "execution_count": null
    }
  ],
  "metadata": {},
  "nbformat": 4,
  "nbformat_minor": 5
}""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    agent = next(agent for agent in graph.agents if agent.metadata.get("framework") == "openai-agents")
    assert agent.location is not None
    assert agent.location.path.name == "agent.ipynb"


def test_parse_diagnostic_contains_reason_details(tmp_path: Path) -> None:
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    graph, _ = scan(tmp_path)
    diagnostic = next(item for item in graph.coverage.diagnostics if item.kind == "parse_error")
    assert diagnostic.details["exception_type"] == "SyntaxError"
    assert diagnostic.details["reason"]


def test_openai_generic_agent_and_static_mcp_url_are_normalized(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from agents import Agent
from agents.mcp import MCPServerStreamableHttp

URL = "https://mcp.example.test/mcp"
agent = Agent[dict](name="starter", tools=[])
server = MCPServerStreamableHttp(
    params={
        "url": URL,
        "headers": {"Authorization": f"Bearer {token}"},
    }
)
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    assert any(agent.name == "starter" for agent in graph.agents)
    server = next(item for item in graph.all_mcp_servers() if item.name == "server")
    assert server.url == "https://mcp.example.test/mcp"
    assert server.authenticated is True


def test_notebook_non_python_cells_do_not_create_parse_failure(tmp_path: Path) -> None:
    (tmp_path / "mixed.ipynb").write_text(
        """{
  "cells": [
    {"cell_type": "code", "metadata": {}, "source": ["%%html\\n", "<h1>hello</h1>\\n"]},
    {"cell_type": "code", "metadata": {}, "source": ["pip install example-package\\n"]},
    {"cell_type": "code", "metadata": {}, "source": [
      "from agents import Agent\\n",
      "agent = Agent(name='NotebookAgent', tools=[])\\n"
    ]}
  ],
  "metadata": {},
  "nbformat": 4,
  "nbformat_minor": 5
}""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    assert any(agent.metadata.get("framework") == "openai-agents" for agent in graph.agents)
    assert not any(item.kind == "parse_error" for item in graph.coverage.diagnostics)
    skipped = [
        item for item in graph.coverage.diagnostics
        if item.kind == "notebook_non_python_cell"
    ]
    assert skipped
    assert all(item.incomplete is False for item in skipped)


def test_jinja_python_template_is_skipped_without_incomplete_parse_error(tmp_path: Path) -> None:
    (tmp_path / "template.py").write_text(
        """
from google.adk import Agent
{%- if cookiecutter.enabled %}
root_agent = Agent(name="root")
{%- endif %}
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    assert not any(item.kind == "parse_error" for item in graph.coverage.diagnostics)
    diagnostic = next(
        item for item in graph.coverage.diagnostics if item.kind == "templated_source"
    )
    assert diagnostic.incomplete is False


def test_context_managed_multiserver_mcp_client_is_discovered(tmp_path: Path) -> None:
    (tmp_path / "client.py").write_text(
        """
from langchain_mcp_adapters.client import MultiServerMCPClient

async def run():
    async with MultiServerMCPClient() as client:
        await client.connect_to_server(
            "slack",
            url="https://mcp.example.test/mcp",
        )
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    server = next(item for item in graph.all_mcp_servers() if item.name == "slack")
    assert server.transport == "streamable-http"
    assert server.url == "https://mcp.example.test/mcp"


def test_local_agents_package_does_not_trigger_openai_adapter(tmp_path: Path) -> None:
    path = tmp_path / "client.py"
    path.write_text(
        "from agents.mcp_agent import run_mcp_agent\n",
        encoding="utf-8",
    )
    assert "openai-agents" not in detect_python_frameworks(path)


def test_vertex_ai_rag_retrieval_is_recognized(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from google.adk.agents import Agent
from google.adk.tools.retrieval.vertex_ai_rag_retrieval import VertexAiRagRetrieval

rag_tool = VertexAiRagRetrieval(
    name="retrieve_documents",
    description="retrieve",
    rag_resources=[],
)
root_agent = Agent(name="rag", tools=[rag_tool])
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "rag")
    tool = next(item for item in agent.tools if item.name == "rag_tool")
    assert "data.read" in tool.capabilities
    assert "network.external" in tool.capabilities
    assert not any(item.kind == "unresolved_tool" for item in graph.coverage.diagnostics)


def test_temporal_activity_as_tool_is_recognized(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from datetime import timedelta
from agents import Agent
from temporalio.contrib import openai_agents as temporal_agents

def generate_pdf(value):
    return value

agent = Agent(
    name="pdf",
    tools=[
        temporal_agents.workflow.activity_as_tool(
            generate_pdf,
            start_to_close_timeout=timedelta(seconds=10),
        )
    ],
)
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "pdf")
    assert any(tool.kind == "temporal_activity_tool" for tool in agent.tools)
    assert not any(item.kind == "unresolved_tool" for item in graph.coverage.diagnostics)


def test_openai_agent_as_tool_is_delegated_tool(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from agents import Agent

worker = Agent(name="worker")
worker_tool = worker.as_tool(tool_name="worker_tool")
lead = Agent(name="lead", tools=[worker_tool])
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    lead = next(item for item in graph.agents if item.name == "lead")
    tool = next(item for item in lead.tools if item.name == "worker_tool")
    assert tool.kind == "delegated_agent"
    assert "agent.delegate" in tool.capabilities
    assert not any(item.kind == "unresolved_tool" for item in graph.coverage.diagnostics)


def test_imported_openai_tool_resolves_from_repository_evidence(tmp_path: Path) -> None:
    package = tmp_path / "app"
    tools_dir = package / "tools"
    tools_dir.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (tools_dir / "__init__.py").write_text(
        "from .emoji import add_emoji_reaction\n", encoding="utf-8"
    )
    (tools_dir / "emoji.py").write_text(
        """
from agents import function_tool

@function_tool
def add_emoji_reaction(value):
    return value
""",
        encoding="utf-8",
    )
    (package / "agent.py").write_text(
        """
from agents import Agent
from app.tools import add_emoji_reaction

agent = Agent(name="starter", tools=[add_emoji_reaction])
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "starter")
    tool = next(item for item in agent.tools if item.name == "add_emoji_reaction")
    assert tool.metadata.get("repository_resolved") is True
    assert not any(
        item.kind in {"unresolved_tool", "external_helper_semantics_unresolved"}
        for item in graph.coverage.diagnostics
    )


def test_static_mcp_http_without_headers_is_unauthenticated(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from langchain_mcp_adapters.client import MultiServerMCPClient

client = MultiServerMCPClient({
    "weather": {
        "url": "http://localhost:8000/mcp/",
        "transport": "streamable_http",
    }
})
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    server = next(item for item in graph.all_mcp_servers() if item.name == "weather")
    assert server.authenticated is False
    assert not any(
        item.kind == "authentication_unknown" for item in graph.coverage.diagnostics
    )


def test_python_runtime_command_is_resolved_for_mcp(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
import sys
from langchain_mcp_adapters.client import MultiServerMCPClient

python_path = sys.executable

async def main():
    async with MultiServerMCPClient() as client:
        await client.connect_to_server(
            "copywriter",
            command=python_path,
            args=["server.py"],
        )
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    server = next(item for item in graph.all_mcp_servers() if item.name == "copywriter")
    assert server.command == "<python-executable>"
    assert not any(
        item.kind == "dynamic_configuration" for item in graph.coverage.diagnostics
    )


def test_external_named_mcp_reference_remains_incomplete(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from agents import Agent

agent = Agent(
    name="configured-mcp",
    mcp_servers=["fetch", "filesystem"],
)
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    assert {server.name for server in graph.all_mcp_servers()} >= {"fetch", "filesystem"}
    assert any(
        item.kind == "dynamic_mcp_endpoint" for item in graph.coverage.diagnostics
    )


def test_output_heavy_notebook_can_exceed_normal_source_limit(tmp_path: Path) -> None:
    payload = "x" * (5 * 1024 * 1024 + 1024)
    notebook = {
        "cells": [
            {
                "cell_type": "markdown",
                "metadata": {},
                "source": [payload],
            },
            {
                "cell_type": "code",
                "metadata": {},
                "source": [
                    "from agents import Agent\n",
                    "agent = Agent(name='NotebookAgent', tools=[])\n",
                ],
            },
        ],
        "metadata": {},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    import json

    (tmp_path / "large.ipynb").write_text(
        json.dumps(notebook),
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    assert any(agent.metadata.get("framework") == "openai-agents" for agent in graph.agents)
    assert not any(
        item.kind == "unsupported_security_construct"
        for item in graph.coverage.diagnostics
    )


def test_bare_local_agents_import_without_sdk_symbols_is_not_openai(tmp_path: Path) -> None:
    path = tmp_path / "main.py"
    path.write_text(
        "from agents import judge_agent, mask_agent, sql_agent\n",
        encoding="utf-8",
    )
    assert "openai-agents" not in detect_python_frameworks(path)


def test_named_mcp_references_do_not_duplicate_unresolved_tool(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from agents import Agent

agent = Agent(
    name="configured",
    mcp_servers=["fetch", "filesystem"],
)
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    assert any(item.kind == "dynamic_mcp_endpoint" for item in graph.coverage.diagnostics)
    assert not any(item.kind == "unresolved_tool" for item in graph.coverage.diagnostics)


def test_invalid_python_in_explicit_snippets_directory_is_informational(tmp_path: Path) -> None:
    snippets = tmp_path / "resources" / "snippets_py"
    snippets.mkdir(parents=True)
    (snippets / "fragment.py").write_text(
        "this is intentionally not valid python !!!\n",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        """
from agents import Agent
agent = Agent(name="valid")
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    assert not any(item.kind == "parse_error" for item in graph.coverage.diagnostics)
    diagnostic = next(
        item for item in graph.coverage.diagnostics if item.kind == "source_fragment"
    )
    assert diagnostic.incomplete is False


def test_repository_adk_re_compile_is_not_process_execution(tmp_path: Path) -> None:
    """Regression from sondera-ai/trustworthy-adk frozen Cohort C."""
    (tmp_path / "agent.py").write_text(
        r"""
import re
from google.adk import Agent

def send_email(to: list[str]) -> dict:
    email_pattern = re.compile(r"^[^@]+@[^@]+\\.[^@]+$")
    if not all(email_pattern.match(address) for address in to):
        return {"status": "error"}
    return {"status": "sent"}

root_agent = Agent(name="mail", tools=[send_email])
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "mail")
    tool = next(item for item in agent.tools if item.name == "send_email")

    assert "process.execute" not in tool.capabilities
    assert not any(
        finding.rule_id == "AGT020" and finding.agent == "mail"
        for finding in findings
    )


def test_repository_adk_bare_eval_remains_process_execution(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from google.adk import Agent

def calculate(expression: str):
    return eval(expression)

root_agent = Agent(name="calculator", tools=[calculate])
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "calculator")
    tool = next(item for item in agent.tools if item.name == "calculate")

    assert "process.execute" in tool.capabilities
    assert any(
        finding.rule_id == "AGT020" and finding.agent == "calculator"
        for finding in findings
    )
