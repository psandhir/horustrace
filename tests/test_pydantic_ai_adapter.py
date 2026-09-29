from pathlib import Path

from horustrace.adapters.registry import detect_python_frameworks
from horustrace.scanner import scan


def test_pydantic_ai_decorator_tool_with_approval(tmp_path: Path) -> None:
    source = tmp_path / "agent.py"
    source.write_text(
        """
import subprocess
from pydantic_ai import Agent

agent = Agent("openai:gpt-5.2")

@agent.tool(requires_approval=True)
def run_command(command: str) -> str:
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    assert detect_python_frameworks(source) == ["pydantic-ai"]
    assert len(graph.agents) == 1
    assert graph.agents[0].metadata["framework"] == "pydantic-ai"

    tool = next(tool for tool in graph.agents[0].tools if tool.name == "run_command")
    assert "process.execute" in tool.capabilities
    assert tool.approval is True
    assert not any(f.rule_id == "AGT020" for f in findings)


def test_pydantic_ai_unapproved_process_tool_is_flagged(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
import subprocess
from pydantic_ai import Agent

agent = Agent("openai:gpt-5.2")

@agent.tool
def run_command(command: str) -> str:
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout
""",
        encoding="utf-8",
    )

    _, findings = scan(tmp_path)
    assert any(f.rule_id == "AGT020" and f.agent == "agent" for f in findings)


def test_pydantic_ai_conditional_approval_is_not_treated_as_universal(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
import subprocess
from pydantic_ai import Agent, ApprovalRequired

agent = Agent("openai:gpt-5.2")

@agent.tool
def run_command(command: str) -> str:
    if command.startswith("sudo"):
        raise ApprovalRequired
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    tool = next(tool for tool in graph.agents[0].tools if tool.name == "run_command")
    assert tool.metadata["conditional_approval"] is True
    assert tool.approval is not True
    assert any(f.rule_id == "AGT020" for f in findings)


def test_pydantic_ai_tool_wrapper_and_function_toolset_approval(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent, FunctionToolset, Tool

def write_record(value: str) -> str:
    return store.write(value)

wrapped = Tool(write_record, requires_approval=True)
toolset = FunctionToolset(tools=[write_record]).approval_required()
agent = Agent("openai:gpt-5.2", tools=[wrapped], toolsets=[toolset])
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = graph.agents[0]
    tool = next(tool for tool in agent.tools if tool.name == "write_record")
    assert "data.write" in tool.capabilities
    assert tool.approval is True
    assert not any(d.code == "unresolved_tool" for d in graph.coverage.diagnostics)


def test_pydantic_ai_remote_mcp_toolset_is_normalized(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent
from pydantic_ai.mcp import MCPToolset

mcp = MCPToolset("https://mcp.example.com/api")
agent = Agent("openai:gpt-5.2", toolsets=[mcp])
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    server = graph.agents[0].mcp_servers[0]
    assert server.url == "https://mcp.example.com/api"
    assert server.transport == "streamable-http"
    assert server.authenticated is False
    assert any(f.rule_id == "AGT030" for f in findings)
    assert any(f.rule_id == "AGT032" for f in findings)


def test_pydantic_ai_mcp_capability_and_harness_capabilities(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent
from pydantic_ai.capabilities import MCP, WebSearch
from pydantic_ai_harness import Coder

agent = Agent(
    "openai:gpt-5.2",
    capabilities=[
        Coder(),
        WebSearch(),
        MCP(url="https://mcp.example.com/api", native=True),
    ],
)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = graph.agents[0]
    assert {"process.execute", "data.read", "data.write", "network.external"} <= (
        agent.capabilities
    )
    assert any(source.trust == "untrusted" for source in agent.inputs)
    assert agent.mcp_servers[0].metadata["native"] is True
    assert any(f.rule_id == "CAP004" for f in findings)


def test_pydantic_ai_filesystem_scope_reaches_layer_four(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent
from pydantic_ai_harness import FileSystem

agent = Agent("openai:gpt-5.2", capabilities=[FileSystem("/")])
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    tool = next(tool for tool in graph.agents[0].tools if tool.name == "FileSystem")
    assert tool.resources[0].selector == "/"
    assert any(f.rule_id == "DATA001" for f in findings)


def test_pydantic_ai_dynamic_toolsets_are_visible_in_coverage(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent

def build_toolsets():
    return []

agent = Agent("openai:gpt-5.2", toolsets=build_toolsets())
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    assert graph.coverage.incomplete
    assert any(
        d.code == "dynamic_configuration"
        and "toolsets" in d.message.lower()
        for d in graph.coverage.diagnostics
    )


def test_plain_pydantic_model_is_not_detected_as_pydantic_ai(tmp_path: Path) -> None:
    source = tmp_path / "model.py"
    source.write_text(
        """
from pydantic import BaseModel

class Item(BaseModel):
    name: str
""",
        encoding="utf-8",
    )

    assert "pydantic-ai" not in detect_python_frameworks(source)


def test_pydantic_ai_direct_agent_tool_registration_is_authority(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent

def create_plan(value: str) -> str:
    return value

def read_file(path: str) -> str:
    return path

agent = Agent("openai:gpt-5.2")
agent.tool(create_plan)
agent.tool_plain(read_file)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = graph.agents[0]

    assert {tool.name for tool in agent.tools} == {"create_plan", "read_file"}
    assert {
        tool.metadata.get("binding_origin")
        for tool in agent.tools
    } == {"agent.tool", "agent.tool_plain"}

    assert graph.adg is not None
    invoked = {
        node.attributes.get("tool_name")
        for edge in graph.adg.edges
        if edge.kind == "INVOKES"
        for node in graph.adg.nodes
        if node.node_id == edge.target and node.kind == "tool"
    }
    assert {"create_plan", "read_file"} <= invoked


def test_pydantic_ai_cli_input_reaches_agent_run(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent

async def main():
    agent = Agent("openai:gpt-5.2")
    user_input = input("> ")
    return await agent.run(user_input)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = graph.agents[0]

    source = next(item for item in agent.inputs if item.name == "cli-input")
    assert source.trust == "untrusted"
    assert source.kind == "user"
    assert source.metadata["basis"] == "pydantic_ai_cli_input_to_run"


def test_pydantic_ai_local_stdio_resolves_in_repo_fastmcp_and_path002(
    tmp_path: Path,
) -> None:
    (tmp_path / "mcp_server.py").write_text(
        """
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Local Tools")

@mcp.tool()
def delete_record(record_id: str):
    return storage.delete(record_id)

if __name__ == "__main__":
    mcp.run()
""",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent
from pydantic_ai.mcp import MCPServerStdio

async def main():
    mcp_server = MCPServerStdio("python", ["mcp_server.py"])
    agent = Agent("openai:gpt-5.2", mcp_servers=[mcp_server])
    user_input = input("> ")
    return await agent.run(user_input)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)

    agent = next(item for item in graph.agents if item.name == "agent")
    assert len(agent.mcp_servers) == 1
    server = agent.mcp_servers[0]
    assert server.metadata["repository_resolved"] is True
    assert server.metadata["binding_origin"] == "local_stdio_script"
    assert server.metadata["implementation_name"] == "Local Tools"
    assert "destructive.write" in server.metadata["discovered_tool_capabilities"]
    assert not graph.unbound_mcp_servers
    assert any(
        finding.rule_id == "PATH002" and finding.agent == "agent"
        for finding in findings
    )


def test_pydantic_ai_local_stdio_does_not_guess_ambiguous_mcp_implementation(
    tmp_path: Path,
) -> None:
    (tmp_path / "mcp_server.py").write_text(
        """
from mcp.server.fastmcp import FastMCP

left = FastMCP("Left")
right = FastMCP("Right")

@left.tool()
def delete_left(record_id: str):
    return storage.delete(record_id)

@right.tool()
def delete_right(record_id: str):
    return storage.delete(record_id)
""",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent
from pydantic_ai.mcp import MCPServerStdio

mcp_server = MCPServerStdio("python", ["mcp_server.py"])
agent = Agent("openai:gpt-5.2", mcp_servers=[mcp_server])
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    agent = next(item for item in graph.agents if item.name == "agent")
    server = agent.mcp_servers[0]
    assert server.metadata.get("repository_resolved") is not True
    assert server.metadata["local_stdio_resolution"] == "ambiguous"
    assert server.metadata["local_stdio_candidate_count"] == 2
    assert len(graph.unbound_mcp_servers) == 2

def test_pydantic_ai_cross_file_click_input_reaches_imported_agent_state_write(
    tmp_path: Path,
) -> None:
    package = tmp_path / "ramon"
    package.mkdir()
    (package / "__init__.py").write_text(
        "from .agent import agent\n",
        encoding="utf-8",
    )
    (package / "agent.py").write_text(
        """
from pydantic_ai import Agent

agent = Agent("openai:gpt-5.2")

@agent.tool_plain
def update_record(record_id: str, value: str) -> str:
    return store.update(record_id, value)
""",
        encoding="utf-8",
    )
    (package / "cli.py").write_text(
        """
import click
from ramon import agent

def chat() -> None:
    prompt = click.prompt("", prompt_suffix="> ")
    agent.run_sync(prompt)
""",
        encoding="utf-8",
    )

    graph, findings = scan(package)
    agent = next(item for item in graph.agents if item.name == "agent")
    ingress = next(
        item
        for item in agent.inputs
        if item.metadata.get("basis")
        == "repository_pydantic_cli_input_to_run"
    )

    assert ingress.trust == "untrusted"
    assert ingress.metadata["runtime_invocation_proven"] is True
    assert "data.write" in next(
        tool for tool in agent.tools if tool.name == "update_record"
    ).capabilities

    path = next(
        item
        for item in graph.attack_paths
        if item.path_id == "PATH002"
        and item.metadata.get("basis") == "source_bound_ingress_authority"
    )
    assert path.agent == "agent"
    assert path.nodes[-2:] == ["update_record", "data.write"]
    assert path.metadata["ingress_basis"] == (
        "repository_pydantic_cli_input_to_run"
    )
    assert any(
        finding.rule_id == "PATH002" and finding.agent == "agent"
        for finding in findings
    )


def test_pydantic_ai_cross_file_click_input_requires_concrete_agent_run(
    tmp_path: Path,
) -> None:
    package = tmp_path / "ramon"
    package.mkdir()
    (package / "__init__.py").write_text(
        "from .agent import agent\n",
        encoding="utf-8",
    )
    (package / "agent.py").write_text(
        """
from pydantic_ai import Agent

agent = Agent("openai:gpt-5.2")

@agent.tool_plain
def update_record(record_id: str, value: str) -> str:
    return store.update(record_id, value)
""",
        encoding="utf-8",
    )
    (package / "cli.py").write_text(
        """
import click
from ramon import agent

def chat() -> None:
    prompt = click.prompt("", prompt_suffix="> ")
    print(prompt)
""",
        encoding="utf-8",
    )

    graph, findings = scan(package)
    agent = next(item for item in graph.agents if item.name == "agent")

    assert not any(
        item.metadata.get("basis") == "repository_pydantic_cli_input_to_run"
        for item in agent.inputs
    )
    assert not any(
        finding.rule_id == "PATH002" and finding.agent == "agent"
        for finding in findings
    )

