from pathlib import Path

from horustrace.flow import analyze_repository_flows
from horustrace.models import Agent, Graph, SourceLocation, Tool


def _write_flow_source(tmp_path: Path) -> Path:
    path = tmp_path / "tools.py"
    path.write_text(
        """
def dangerous_tool():
    value = input("command: ")
    return eval(value)
""",
        encoding="utf-8",
    )
    return path


def test_cross_file_name_only_binding_remains_unmapped(tmp_path: Path) -> None:
    source_path = _write_flow_source(tmp_path)
    declaration = tmp_path / "agent.py"
    declaration.write_text("# normalized agent declaration lives here\n", encoding="utf-8")

    graph = Graph(
        agents=[
            Agent(
                name="executor",
                tools=[
                    Tool(
                        name="dangerous_tool",
                        kind="function",
                        location=SourceLocation(declaration, 1, 1),
                    )
                ],
            ),
            Agent(
                name="observer",
                tools=[
                    Tool(
                        name="read_status",
                        kind="function",
                        location=SourceLocation(declaration, 2, 1),
                    )
                ],
            ),
        ]
    )

    flows = analyze_repository_flows(tmp_path, [source_path], graph)

    assert len(flows) == 1
    assert flows[0].agent is None
    assert flows[0].metadata["agent_binding"] is None
    assert flows[0].source_kind == "user_input"
    assert flows[0].sink_kind == "process_execute"


def test_cross_file_ambiguous_tool_binding_remains_unmapped(tmp_path: Path) -> None:
    source_path = _write_flow_source(tmp_path)
    declaration = tmp_path / "agent.py"
    declaration.write_text("# two agents expose the same imported tool\n", encoding="utf-8")

    graph = Graph(
        agents=[
            Agent(
                name="executor_a",
                tools=[
                    Tool(
                        name="dangerous_tool",
                        kind="function",
                        location=SourceLocation(declaration, 1, 1),
                    )
                ],
            ),
            Agent(
                name="executor_b",
                tools=[
                    Tool(
                        name="dangerous_tool",
                        kind="function",
                        location=SourceLocation(declaration, 2, 1),
                    )
                ],
            ),
        ]
    )

    flows = analyze_repository_flows(tmp_path, [source_path], graph)

    assert len(flows) == 1
    assert flows[0].agent is None




def test_single_agent_name_only_fallback_is_not_used(tmp_path: Path) -> None:
    source_path = _write_flow_source(tmp_path)
    declaration = tmp_path / "agent.py"
    declaration.write_text("# unrelated single agent\n", encoding="utf-8")

    graph = Graph(
        agents=[
            Agent(
                name="only_agent",
                tools=[
                    Tool(
                        name="unrelated_tool",
                        kind="function",
                        location=SourceLocation(declaration, 1, 1),
                    )
                ],
            )
        ]
    )

    flows = analyze_repository_flows(tmp_path, [source_path], graph)

    assert len(flows) == 1
    assert flows[0].agent is None
    assert flows[0].metadata["agent_binding"] is None

def test_frozen_corpus_style_openai_imported_tool_maps_flow(tmp_path: Path) -> None:
    """Mirrors the imported-tool/source->external-send shape seen in Cohort C."""
    tools_path = tmp_path / "tools.py"
    tools_path.write_text(
        """
import requests

def forward_external_result():
    response = requests.get("https://source.example/data")
    return requests.post("https://sink.example/events", json=response.json())
""",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        """
from agents import Agent
from tools import forward_external_result

agent = Agent(name="Orchestrator", tools=[forward_external_result])
""",
        encoding="utf-8",
    )

    from horustrace.scanner import scan

    graph, _ = scan(tmp_path)
    flows = [
        flow
        for flow in graph.flow_paths
        if flow.source_kind == "external_http_response"
        and flow.sink_kind == "external_send"
    ]

    assert flows
    assert {flow.agent for flow in flows} == {"Orchestrator"}
    assert {flow.metadata["agent_binding"]["basis"] for flow in flows} == {"source_function_key"}
    tool = next(t for t in graph.agents[0].tools if t.name == "forward_external_result")
    assert tool.metadata["source_function_key"] == "tools.forward_external_result"


def test_normalized_agent_tool_parameter_becomes_flow_source(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
import subprocess
from agents import Agent, function_tool

@function_tool
def run_command(command: str) -> str:
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout

agent = Agent(name="Executor", instructions="Run commands.", tools=[run_command])
""",
        encoding="utf-8",
    )

    from horustrace.scanner import scan

    graph, _ = scan(tmp_path)
    flows = [
        flow
        for flow in graph.flow_paths
        if flow.source_kind == "agent_tool_input"
        and flow.sink_kind == "process_execute"
    ]

    assert len(flows) == 1
    flow = flows[0]
    assert flow.agent == "Executor"
    assert flow.source_label == "run_command.command"
    assert flow.basis == "static_dataflow"
    assert flow.metadata["agent_binding"]["basis"] == "source_function_key"
    assert flow.metadata["agent_binding"]["function"] == "agent.run_command"


def test_agent_tool_parameter_flows_through_local_helper(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
import subprocess
from agents import Agent, function_tool

def execute(command: str) -> str:
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout

@function_tool
def run_command(command: str) -> str:
    return execute(command)

agent = Agent(name="Executor", instructions="Run commands.", tools=[run_command])
""",
        encoding="utf-8",
    )

    from horustrace.scanner import scan

    graph, _ = scan(tmp_path)
    flows = [
        flow
        for flow in graph.flow_paths
        if flow.source_kind == "agent_tool_input"
        and flow.sink_kind == "process_execute"
    ]

    assert len(flows) == 1
    assert flows[0].agent == "Executor"
    assert flows[0].metadata["agent_binding"]["basis"] == "source_function_key"
    assert flows[0].metadata["call_chain"] == [
        "agent.run_command",
        "agent.execute",
    ]


def test_plain_function_parameter_is_not_promoted_to_agent_tool_input(tmp_path: Path) -> None:
    source = tmp_path / "helper.py"
    source.write_text(
        """
import subprocess

def run_command(command: str) -> str:
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout
""",
        encoding="utf-8",
    )

    graph = Graph()
    flows = analyze_repository_flows(tmp_path, [source], graph)

    assert flows == []


def test_framework_context_parameter_is_not_promoted_to_agent_tool_input(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
import subprocess
from agents import Agent, function_tool

@function_tool
def run_command(ctx, command: str) -> str:
    subprocess.run(ctx, shell=True)
    return command

agent = Agent(name="Executor", instructions="Run commands.", tools=[run_command])
""",
        encoding="utf-8",
    )

    from horustrace.scanner import scan

    graph, _ = scan(tmp_path)

    assert not [
        flow
        for flow in graph.flow_paths
        if flow.source_kind == "agent_tool_input"
        and flow.source_label == "run_command.ctx"
    ]


def test_adk_agent_tool_parameter_becomes_flow_source(tmp_path: Path) -> None:
    """ADK function-tool parameters are treated as agent-controlled only after proven binding."""
    (tmp_path / "agent.py").write_text(
        """
import subprocess
from google.adk import Agent

def run_command(command: str) -> str:
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout

root_agent = Agent(
    name="ADK Executor",
    model="gemini-flash-latest",
    tools=[run_command],
)
""",
        encoding="utf-8",
    )

    from horustrace.scanner import scan

    graph, _ = scan(tmp_path)
    flows = [
        flow
        for flow in graph.flow_paths
        if flow.source_kind == "agent_tool_input"
        and flow.sink_kind == "process_execute"
    ]

    assert len(flows) == 1
    flow = flows[0]
    assert flow.agent == "ADK Executor"
    assert flow.source_label == "run_command.command"
    assert flow.basis == "static_dataflow"
    assert flow.metadata["agent_binding"]["basis"] == "source_function_key"
    assert flow.metadata["agent_binding"]["function"] == "agent.run_command"


def test_exact_source_function_shared_by_agents_emits_per_agent_flows(
    tmp_path: Path,
) -> None:
    source = tmp_path / "tools.py"
    source.write_text(
        """
class MemoryStore:
    def update_memory(self, agent_name, value):
        return None

memory_store = MemoryStore()

def update_agent_memory(agent_name: str, value: dict):
    return memory_store.update_memory(agent_name, value)
""",
        encoding="utf-8",
    )
    location = SourceLocation(source, 8, 1)
    shared_tool = lambda: Tool(
        name="update_agent_memory",
        kind="function",
        capabilities={"data.write"},
        location=location,
        metadata={"source_function_key": "tools.update_agent_memory"},
    )
    graph = Graph(
        agents=[
            Agent(name="Router", tools=[shared_tool()]),
            Agent(name="Gatherer", tools=[shared_tool()]),
        ]
    )

    flows = analyze_repository_flows(tmp_path, [source], graph)
    memory_flows = [
        flow
        for flow in flows
        if flow.source_kind == "agent_tool_input"
        and flow.sink_kind == "memory_write"
    ]

    assert {flow.agent for flow in memory_flows} == {"Router", "Gatherer"}
    assert all(
        flow.metadata["agent_binding"]["basis"] == "source_function_key"
        for flow in memory_flows
    )
