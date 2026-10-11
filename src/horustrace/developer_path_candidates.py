"""Additive source-backed developer candidates excluded from runtime attack paths.

This is deliberately not an AttackPath or Finding. It preserves reviewable source
evidence in example/test code without claiming deployment or proven exploitation.
"""
from __future__ import annotations

import ast
from pathlib import Path

from horustrace.models import (
    AgentReachability,
    Confidence,
    FlowExecutionContext,
    Graph,
)

_NON_RUNTIME = frozenset({
    FlowExecutionContext.EXAMPLE,
    FlowExecutionContext.TEST,
    FlowExecutionContext.TUTORIAL,
    FlowExecutionContext.NOTEBOOK,
    FlowExecutionContext.TEMPLATE_GENERATED,
})
_UNTRUSTED = frozenset({
    "user_input", "external_http_response", "web_retrieval",
    "mcp_response", "agent_tool_input",
})



def _process_execution_mode(root: Path, location) -> str:
    """Recognize explicit shell=True versus fixed-argv subprocess invocations.

    Unknown/dynamic options remain unresolved and never become 'shell proven'.
    """
    if location is None:
        return "unknown"
    path = location.path.resolve()
    try:
        path.relative_to(root.resolve())
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (ValueError, OSError, SyntaxError, UnicodeDecodeError):
        return "unknown"
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or node.lineno != location.line:
            continue
        if isinstance(node.func, ast.Attribute) and node.func.attr in {
            "run", "call", "check_call", "check_output", "Popen",
        }:
            shell = next((kw.value for kw in node.keywords if kw.arg == "shell"), None)
            if isinstance(shell, ast.Constant) and shell.value is True:
                return "shell_interpreter"
            if shell is not None and not (
                isinstance(shell, ast.Constant) and shell.value is False
            ):
                return "unknown"
            if node.args and isinstance(node.args[0], (ast.List, ast.Tuple)):
                return "structured_argv"
        elif isinstance(node.func, ast.Attribute) and node.func.attr in {
            "system", "popen", "create_subprocess_shell",
        }:
            return "shell_interpreter"
    return "unknown"


def developer_path_candidates(graph: Graph, root: Path) -> list[dict]:
    """Only emit verified static flow/binding in non-deployed source contexts."""
    candidates: list[dict] = []
    for flow in sorted(graph.flow_paths, key=lambda item: item.flow_id):
        if not (
            flow.agent
            and flow.agent_reachability is AgentReachability.PROVEN_AGENT_REACHABLE
            and flow.execution_context in _NON_RUNTIME
            and flow.basis == "static_dataflow"
            and flow.confidence is Confidence.SUPPORTED
            and flow.source_kind in _UNTRUSTED
            and flow.sink_kind == "process_execute"
        ):
            continue
        from horustrace.analysis import _bound_tool_for_flow

        bound_tool = _bound_tool_for_flow(graph, flow)
        constrained = (
            bound_tool is not None
            and bound_tool.metadata.get("process_execution_constrained") is True
        )
        location = flow.steps[-1].location if flow.steps else None
        if location is not None:
            try:
                relative = location.path.resolve().relative_to(root.resolve()).as_posix()
            except ValueError:
                relative = location.path.name
            place = {"path": relative, "line": location.line, "column": location.column}
        else:
            place = None
        execution_mode = _process_execution_mode(root, location)
        candidates.append({
            "candidate_id": "developer:" + flow.flow_id,
            "path_id": "PATH001",
            "title": "Source-backed command-execution path (non-runtime source)",
            "agent": flow.agent,
            "nodes": list(flow.nodes),
            "severity": "candidate",
            "execution_mode": execution_mode,
            "control_qualified": constrained,
            "rationale": (
                "A model/tool-controlled value reaches a process execution sink in "
                "example, test, notebook, or template code. Deployment and runtime "
                "execution have not been established."
            ),
            "location": place,
            "metadata": {
                "basis": "static_dataflow",
                "flow_id": flow.flow_id,
                "source_kind": flow.source_kind,
                "sink_kind": flow.sink_kind,
                "execution_context": flow.execution_context.value,
                "agent_reachability": flow.agent_reachability.value,
                "runtime_viability": "not_assessed",
                "runtime_scope": "non_runtime_source",
                "exploitability": "not_verified",
                "review_status": (
                    "structured_argv_near_miss"
                    if execution_mode == "structured_argv" or constrained
                    else "candidate_not_deployed_risk"
                ),
            },
        })
    return candidates
