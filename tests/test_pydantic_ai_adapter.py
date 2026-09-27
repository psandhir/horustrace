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
