"""P0 source-backed developer path visibility: explicit positives and near misses."""
from pathlib import Path

from horustrace.developer_path_candidates import developer_path_candidates
from horustrace.models import (
    AgentReachability,
    Confidence,
    FlowExecutionContext,
    FlowPath,
    FlowStep,
    Graph,
)
from horustrace.scanner import scan
from horustrace.security_graph import build_agent_security_graph
from horustrace.visual_report import build_visual_report, render_visual_report_html


def _flow(root: Path, *, context: FlowExecutionContext, reachable=True, mode="shell"):
    source = root / "examples" / "agent.py"
    source.parent.mkdir(parents=True, exist_ok=True)
    command = "subprocess.run(command, shell=True)"
    if mode == "argv":
        command = "subprocess.run(['git', 'diff', command])"
    source.write_text("import subprocess\n\ndef shell(command):\n    " + command + "\n")
    from horustrace.models import SourceLocation

    return FlowPath(
        flow_id="flow-v1:" + mode,
        source_kind="agent_tool_input",
        sink_kind="process_execute",
        source_label="shell.command",
        sink_label="subprocess.run",
        steps=[
            FlowStep(kind="agent_tool_input", label="shell.command"),
            FlowStep(
                kind="process_execute",
                label="subprocess.run",
                location=SourceLocation(source, line=4),
            ),
        ],
        agent="Ops",
        confidence=Confidence.SUPPORTED,
        execution_context=context,
        agent_reachability=(
            AgentReachability.PROVEN_AGENT_REACHABLE
            if reachable else AgentReachability.UNKNOWN
        ),
    )


def test_example_shell_candidate_does_not_become_runtime_attack_path(tmp_path: Path):
    flow = _flow(tmp_path, context=FlowExecutionContext.EXAMPLE)
    graph = Graph(flow_paths=[flow])
    candidates = developer_path_candidates(graph, tmp_path)
    assert len(candidates) == 1
    assert candidates[0]["execution_mode"] == "shell_interpreter"
    assert candidates[0]["metadata"]["runtime_scope"] == "non_runtime_source"
    assert candidates[0]["metadata"]["exploitability"] == "not_verified"
    assert candidates[0]["location"]["path"] == "examples/agent.py"
    asg = build_agent_security_graph(graph, tmp_path).as_dict()
    assert asg["summary"]["attack_paths"] == 0
    assert asg["summary"]["developer_path_candidates"] == 1
    assert asg["developer_path_candidates"][0]["candidate_id"] == "developer:flow-v1:shell"
    assert not graph.attack_paths


def test_structured_subprocess_argument_is_near_miss_not_shell(tmp_path: Path):
    flow = _flow(tmp_path, context=FlowExecutionContext.EXAMPLE, mode="argv")
    candidates = developer_path_candidates(Graph(flow_paths=[flow]), tmp_path)
    assert len(candidates) == 1
    assert candidates[0]["execution_mode"] == "structured_argv"
    assert candidates[0]["metadata"]["review_status"] == "structured_argv_near_miss"


def test_unknown_reachability_is_not_promoted_to_candidate(tmp_path: Path):
    graph = Graph(flow_paths=[
        _flow(tmp_path, context=FlowExecutionContext.EXAMPLE, reachable=False)
    ])
    assert developer_path_candidates(graph, tmp_path) == []


def test_deployed_runtime_flow_is_not_double_counted(tmp_path: Path):
    graph = Graph(flow_paths=[_flow(tmp_path, context=FlowExecutionContext.RUNTIME)])
    assert developer_path_candidates(graph, tmp_path) == []


def test_unproven_dataflow_is_not_candidate(tmp_path: Path):
    flow = _flow(tmp_path, context=FlowExecutionContext.EXAMPLE)
    flow.confidence = Confidence.POTENTIAL
    assert developer_path_candidates(Graph(flow_paths=[flow]), tmp_path) == []


def test_report_separates_candidates_from_runnable_risk(tmp_path: Path):
    graph = Graph(flow_paths=[_flow(tmp_path, context=FlowExecutionContext.EXAMPLE)])
    report = build_visual_report(graph, [], tmp_path)
    assert report["security_graph"]["summary"]["developer_path_candidates"] == 1
    assert report["security_graph"]["summary"]["attack_paths"] == 0
    html = render_visual_report_html(graph, [], tmp_path)
    assert "Non-runtime developer-source candidates" in html
    assert "Source-blocked" in html


def test_runtime_source_viability_explicitly_not_assessed(tmp_path: Path):
    (tmp_path / "agent.py").write_text(
        "import subprocess\n"
        "from agents import Agent, function_tool\n"
        "@function_tool\n"
        "def shell(command: str):\n"
        "    return subprocess.run(command, shell=True)\n"
        "agent = Agent(name='Ops', tools=[shell])\n"
    )
    graph, _ = scan(tmp_path)
    paths = [p for p in graph.attack_paths if p.path_id == "PATH001"]
    assert paths
    assert all(p.metadata["runtime_viability"] == "not_assessed" for p in paths)
    asg = build_agent_security_graph(graph, tmp_path).as_dict()
    assert asg["summary"]["attack_paths_by_runtime_viability"]["not_assessed"] >= 1


def test_unbound_mcp_configuration_is_inventory_hygiene_not_agent_risk(tmp_path: Path):
    from horustrace.models import Agent, MCPServer

    declaration = MCPServer(name="Greptile", transport="sse")
    bound = MCPServer(name="Bound", transport="stdio", allowed_tools={"lookup"})
    graph = Graph(
        unbound_mcp_servers=[declaration],
        agents=[Agent(name="Ops", mcp_servers=[bound])],
    )
    report = build_visual_report(graph, [], tmp_path)
    by_name = {item["name"]: item for item in report["mcp_servers"]}
    assert by_name["Greptile"]["configuration_hygiene"] == "agent_binding_not_proven"
    assert by_name["Greptile"]["tool_scope_evidence"] == (
        "explicit_allow_or_deny_list_not_recovered"
    )
    assert by_name["Greptile"]["bound_agents"] == []
    assert by_name["Bound"]["configuration_hygiene"] == (
        "bound_configuration_requires_runtime_verification"
    )
    assert by_name["Bound"]["tool_scope_evidence"] == (
        "explicit_allow_or_deny_list_observed"
    )
    assert report["summary"]["findings"] == 0
