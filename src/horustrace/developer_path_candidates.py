"""Additive source-backed developer candidates excluded from runtime attack paths.

This is deliberately not an AttackPath or Finding. It preserves reviewable source
evidence in example/test code without claiming deployment or proven exploitation.
"""
from __future__ import annotations

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
        if bound_tool is not None and bound_tool.metadata.get(
            "process_execution_constrained"
        ) is True:
            # Fixed executable/arguments and proved enforcement are near misses,
            # not unrestricted shell-path candidates.
            continue
        location = flow.steps[-1].location if flow.steps else None
        if location is not None:
            try:
                relative = location.path.resolve().relative_to(root.resolve()).as_posix()
            except ValueError:
                relative = location.path.name
            place = {"path": relative, "line": location.line, "column": location.column}
        else:
            place = None
        candidates.append({
            "candidate_id": "developer:" + flow.flow_id,
            "path_id": "PATH001",
            "title": "Source-backed command-execution path (non-runtime source)",
            "agent": flow.agent,
            "nodes": list(flow.nodes),
            "severity": "candidate",
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
                "review_status": "candidate_not_deployed_risk",
            },
        })
    return candidates
