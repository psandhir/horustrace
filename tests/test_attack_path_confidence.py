import json
from pathlib import Path

from horustrace.analysis import build_attack_paths
from horustrace.cli import main
from horustrace.models import (
    Agent,
    AgentReachability,
    Confidence,
    FlowPath,
    FlowStep,
    Graph,
    InputSource,
    MCPServer,
    SourceLocation,
    Tool,
)
from horustrace.scanner import scan
from horustrace.suppressions import fingerprint


def _all_path_project(root: Path) -> None:
    (root / "horustrace.manifest.yaml").write_text(
        """
agents:
  - name: ops
    inputs: [{name: web, trust: untrusted}]
    data: [{name: records, classification: confidential}]
    tools:
      - {name: shell, capabilities: [process.execute]}
      - {name: delete, capabilities: [destructive.write]}
      - {name: secrets, capabilities: [secrets.read]}
      - {name: publish, capabilities: [external.write]}
""",
        encoding="utf-8",
    )


def test_all_path_findings_have_potential_confidence(tmp_path: Path) -> None:
    _all_path_project(tmp_path)
    _, findings = scan(tmp_path)
    paths = [finding for finding in findings if finding.rule_id.startswith("PATH")]
    assert {finding.rule_id for finding in paths} == {
        "PATH001", "PATH002", "PATH003", "PATH004", "PATH005", "PATH006",
    }
    assert all(finding.confidence is Confidence.POTENTIAL for finding in paths)
    assert not any(
        finding.confidence in {Confidence.AUTHORITY_CONFIRMED, Confidence.RUNTIME_VERIFIED}
        for finding in paths
    )


def test_confidence_does_not_change_existing_fingerprint(tmp_path: Path) -> None:
    _all_path_project(tmp_path)
    _, findings = scan(tmp_path)
    finding = next(item for item in findings if item.rule_id == "PATH001")
    original = fingerprint(finding, tmp_path)
    finding.confidence = Confidence.SUPPORTED
    assert fingerprint(finding, tmp_path) == original


def test_path_confidence_is_reported_in_console_json_and_sarif(tmp_path: Path, capsys) -> None:
    _all_path_project(tmp_path)
    assert main(["scan", str(tmp_path), "--format", "console", "--fail-on", "none"]) == 0
    assert "Confidence: potential" in capsys.readouterr().out

    assert main(["scan", str(tmp_path), "--format", "json", "--fail-on", "none"]) == 0
    report = json.loads(capsys.readouterr().out)
    finding = next(item for item in report["findings"] if item["rule_id"] == "PATH001")
    assert finding["confidence"] == "potential"

    assert main(["scan", str(tmp_path), "--format", "sarif", "--fail-on", "none"]) == 0
    sarif = json.loads(capsys.readouterr().out)
    result = next(item for item in sarif["runs"][0]["results"] if item["ruleId"] == "PATH001")
    assert result["properties"]["confidence"] == "potential"


def test_agent_tool_input_promotes_to_supported_static_attack_path(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
import subprocess
from agents import Agent, function_tool

@function_tool
def run_command(command: str) -> str:
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout

agent = Agent(name="Executor", tools=[run_command])
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)

    flow = next(
        item
        for item in graph.flow_paths
        if item.source_kind == "agent_tool_input"
        and item.sink_kind == "process_execute"
    )
    assert flow.agent_reachability is AgentReachability.PROVEN_AGENT_REACHABLE

    path = next(
        item
        for item in graph.attack_paths
        if item.path_id == "PATH001"
        and item.metadata.get("flow_id") == flow.flow_id
    )
    assert path.agent == "Executor"
    assert path.metadata["basis"] == "static_dataflow"
    assert path.metadata["source_kind"] == "agent_tool_input"
    assert path.metadata["sink_kind"] == "process_execute"
    assert path.metadata["agent_reachability"] == "proven_agent_reachable"

    finding = next(
        item
        for item in findings
        if item.rule_id == "PATH001"
        and any(evidence == f"flow_id={flow.flow_id}" for evidence in item.evidence)
    )
    assert finding.confidence is Confidence.SUPPORTED


def test_unknown_agent_flow_is_not_promoted_to_attack_path() -> None:
    graph = Graph(
        flow_paths=[
            FlowPath(
                flow_id="flow-v1:unknown",
                source_kind="agent_tool_input",
                sink_kind="process_execute",
                source_label="run_command.command",
                sink_label="subprocess.run",
                steps=[
                    FlowStep(kind="agent_tool_input", label="run_command.command"),
                    FlowStep(kind="process_execute", label="subprocess.run"),
                ],
                agent="Executor",
                confidence=Confidence.SUPPORTED,
                agent_reachability=AgentReachability.UNKNOWN,
            )
        ]
    )

    assert build_attack_paths(graph) == []


def test_static_dataflow_path_suppresses_duplicate_capability_path() -> None:
    graph = Graph(
        agents=[
            Agent(
                name="Executor",
                inputs=[InputSource(name="web", trust="untrusted")],
                tools=[
                    Tool(
                        name="run_command",
                        kind="function",
                        capabilities={"process.execute"},
                    )
                ],
            )
        ],
        flow_paths=[
            FlowPath(
                flow_id="flow-v1:proven",
                source_kind="agent_tool_input",
                sink_kind="process_execute",
                source_label="run_command.command",
                sink_label="subprocess.run",
                steps=[
                    FlowStep(kind="agent_tool_input", label="run_command.command"),
                    FlowStep(kind="process_execute", label="subprocess.run"),
                ],
                agent="Executor",
                confidence=Confidence.SUPPORTED,
                agent_reachability=AgentReachability.PROVEN_AGENT_REACHABLE,
            )
        ],
    )

    paths = [path for path in build_attack_paths(graph) if path.path_id == "PATH001"]
    assert len(paths) == 1
    assert paths[0].metadata["basis"] == "static_dataflow"
    assert paths[0].metadata["flow_id"] == "flow-v1:proven"


def test_untrusted_input_reaches_destructive_bound_mcp() -> None:
    location = SourceLocation(Path("agent.py"), line=10)
    server = MCPServer(
        name="plotting",
        transport="stdio",
        location=location,
        metadata={
            "discovered_tool_capabilities": [
                "data.write",
                "destructive.write",
            ],
        },
    )
    graph = Graph(
        agents=[
            Agent(
                name="agent",
                inputs=[
                    InputSource(
                        name="cli-input",
                        trust="untrusted",
                        kind="user",
                        location=location,
                    )
                ],
                mcp_servers=[server],
                location=location,
            )
        ]
    )

    paths = build_attack_paths(graph)

    path = next(item for item in paths if item.path_id == "PATH002")
    assert path.agent == "agent"
    assert path.nodes == [
        "cli-input",
        "agent",
        "plotting",
        "destructive.write",
    ]
    assert path.metadata["target_kind"] == "mcp_server"
