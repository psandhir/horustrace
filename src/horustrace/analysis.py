from __future__ import annotations

from horustrace.heuristics import (
    HIGH_RISK_CAPABILITIES,
    UNTRUSTED_INPUT_KINDS,
)
from horustrace.models import AgentReachability, AttackPath, FlowPath, Graph, Severity

_UNTRUSTED_FLOW_SOURCES = {
    "user_input",
    "external_http_response",
    "web_retrieval",
    "mcp_response",
    "agent_tool_input",
}


def _path_metadata(*, basis: str, flow_id: str | None = None) -> dict:
    limitations = [
        "Runtime authorization and control effectiveness are not verified.",
    ]
    if basis == "static_dataflow":
        limitations.insert(
            0,
            "A supported static source-to-sink dependency was established; "
            "runtime exploitability is not verified.",
        )
    else:
        limitations.insert(
            0,
            "The scanner does not establish executable data flow between these nodes.",
        )
    return {
        "assessment": "potential_risk",
        "basis": basis,
        "exploitability": "not_verified",
        "flow_id": flow_id,
        "limitations": limitations,
    }


def _flow_path_metadata(flow: FlowPath) -> dict:
    return {
        **_path_metadata(basis="static_dataflow", flow_id=flow.flow_id),
        "source_kind": flow.source_kind,
        "sink_kind": flow.sink_kind,
        "agent_reachability": flow.agent_reachability.value,
        "execution_context": flow.execution_context.value,
    }


def _flow_backed_paths(graph: Graph) -> list[AttackPath]:
    paths: list[AttackPath] = []
    for flow in graph.flow_paths:
        if (
            not flow.agent
            or flow.agent_reachability is not AgentReachability.PROVEN_AGENT_REACHABLE
            or flow.basis != "static_dataflow"
            or flow.confidence.value != "supported"
        ):
            continue
        nodes = [step.label for step in flow.steps]
        if flow.source_kind in _UNTRUSTED_FLOW_SOURCES and flow.sink_kind == "process_execute":
            paths.append(
                AttackPath(
                    path_id="PATH001",
                    title="Potential untrusted-input path to command execution",
                    agent=flow.agent,
                    nodes=nodes,
                    severity=Severity.CRITICAL,
                    rationale=(
                        "A supported static data-flow path connects untrusted input to "
                        "a process/code execution sink."
                    ),
                    location=flow.steps[-1].location if flow.steps else None,
                    metadata=_flow_path_metadata(flow),
                )
            )
        elif flow.source_kind in _UNTRUSTED_FLOW_SOURCES and flow.sink_kind == "memory_write":
            paths.append(
                AttackPath(
                    path_id="PATH007",
                    title="Potential untrusted-input path to persistent memory write",
                    agent=flow.agent,
                    nodes=nodes,
                    severity=Severity.HIGH,
                    rationale=(
                        "A supported static data-flow path connects untrusted input to "
                        "an agent memory/checkpoint write sink."
                    ),
                    location=flow.steps[-1].location if flow.steps else None,
                    metadata=_flow_path_metadata(flow),
                )
            )
        elif flow.source_kind == "secret_value" and flow.sink_kind == "external_send":
            paths.append(
                AttackPath(
                    path_id="PATH003",
                    title="Potential sensitive-data path to an external destination",
                    agent=flow.agent,
                    nodes=nodes,
                    severity=Severity.CRITICAL,
                    rationale=(
                        "A supported static data-flow path connects a secret/credential "
                        "source to an external send sink."
                    ),
                    location=flow.steps[-1].location if flow.steps else None,
                    metadata=_flow_path_metadata(flow),
                )
            )
    return paths


def _resolve_delegated_agent(graph: Graph, target: str) -> object | None:
    leaf = target.split(".")[-1]
    candidates = [
        agent
        for agent in graph.agents
        if agent.name == target
        or str(agent.metadata.get("source_alias") or "") == target
    ]
    if not candidates and "." in target:
        candidates = [
            agent
            for agent in graph.agents
            if str(agent.metadata.get("source_alias") or "") == leaf
        ]
    return candidates[0] if len(candidates) == 1 else None


def _delegated_paths(graph: Graph) -> list[AttackPath]:
    paths: list[AttackPath] = []
    for agent in graph.agents:
        untrusted = [
            item
            for item in agent.inputs
            if item.trust == "untrusted" or item.kind in UNTRUSTED_INPUT_KINDS
        ]
        if not untrusted:
            continue
        for delegate_tool in agent.tools:
            if delegate_tool.kind != "delegated_agent":
                continue
            target_name = str(delegate_tool.metadata.get("delegate_target") or "")
            if not target_name:
                continue
            delegated = _resolve_delegated_agent(graph, target_name)
            if delegated is None:
                continue
            for tool in delegated.tools:
                privileged = sorted(tool.capabilities & HIGH_RISK_CAPABILITIES)
                if privileged and tool.approval is not True:
                    paths.append(
                        AttackPath(
                            path_id="PATH008",
                            title="Potential untrusted-input path through delegated agent to privileged action",
                            agent=agent.name,
                            nodes=[
                                untrusted[0].name,
                                agent.name,
                                f"delegate:{delegated.name}",
                                tool.name,
                                privileged[0],
                            ],
                            severity=Severity.HIGH,
                            rationale=(
                                "The normalized model shows untrusted input reaching an "
                                "agent that can delegate to another agent exposing a "
                                "high-risk capability without detected approval."
                            ),
                            location=tool.location or delegated.location or agent.location,
                            metadata={
                                **_path_metadata(basis="capability_cooccurrence"),
                                "delegate_target": delegated.name,
                                "delegate_tool": delegate_tool.name,
                            },
                        )
                    )

                outbound = {
                    "network.external",
                    "external.write",
                } & tool.capabilities
                destination_constrained = bool(
                    tool.destinations
                    and all(destination.restricted for destination in tool.destinations)
                ) or tool.metadata.get("network_scope") in {
                    "fixed_managed_service",
                    "explicit_destination",
                }
                if (
                    outbound
                    and not destination_constrained
                    and tool.approval is not True
                ):
                    paths.append(
                        AttackPath(
                            path_id="PATH009",
                            title="Potential untrusted-input path through delegated agent to unconstrained egress",
                            agent=agent.name,
                            nodes=[
                                untrusted[0].name,
                                agent.name,
                                f"delegate:{delegated.name}",
                                tool.name,
                                "unrestricted external destination",
                            ],
                            severity=Severity.MEDIUM,
                            rationale=(
                                "The normalized model shows untrusted input reaching an "
                                "agent that can delegate to external network/write "
                                "authority without a detected destination constraint."
                            ),
                            location=tool.location or delegated.location or agent.location,
                            metadata={
                                **_path_metadata(basis="capability_cooccurrence"),
                                "delegate_target": delegated.name,
                                "delegate_tool": delegate_tool.name,
                            },
                        )
                    )
    return paths


def build_attack_paths(graph: Graph) -> list[AttackPath]:
    paths: list[AttackPath] = [
        *_flow_backed_paths(graph),
        *_delegated_paths(graph),
    ]
    supported_rule_agents = {
        (path.path_id, path.agent)
        for path in paths
        if path.metadata.get("basis") == "static_dataflow"
    }

    for agent in graph.agents:
        untrusted = [
            item
            for item in agent.inputs
            if item.trust == "untrusted" or item.kind in UNTRUSTED_INPUT_KINDS
        ]
        sensitive = agent.sensitive_data_sources
        outbound = [
            tool
            for tool in agent.tools
            if {"network.external", "external.write"} & tool.capabilities
        ]
        unconstrained_outbound = [
            tool
            for tool in outbound
            if tool.metadata.get("network_scope")
            not in {"fixed_managed_service", "explicit_destination"}
            and not (
                tool.destinations
                and all(destination.restricted for destination in tool.destinations)
            )
        ]
        execution = [tool for tool in agent.tools if "process.execute" in tool.capabilities]
        destructive = [
            tool for tool in agent.tools if "destructive.write" in tool.capabilities
        ]
        secret_tools = [tool for tool in agent.tools if "secrets.read" in tool.capabilities]

        for tool in execution:
            if (
                untrusted
                and tool.approval is not True
                and ("PATH001", agent.name) not in supported_rule_agents
            ):
                paths.append(
                    AttackPath(
                        path_id="PATH001",
                        title="Potential untrusted-input path to command execution",
                        agent=agent.name,
                        nodes=[untrusted[0].name, agent.name, tool.name, "process.execute"],
                        severity=Severity.CRITICAL,
                        rationale=(
                            "The normalized agent model combines untrusted input and "
                            "process-execution capability without a detected approval requirement."
                        ),
                        location=tool.location or agent.location,
                        metadata=_path_metadata(basis="capability_cooccurrence"),
                    )
                )

        for tool in destructive:
            if untrusted and tool.approval is not True:
                paths.append(
                    AttackPath(
                        path_id="PATH002",
                        title="Potential untrusted-input path to destructive action",
                        agent=agent.name,
                        nodes=[untrusted[0].name, agent.name, tool.name, "destructive.write"],
                        severity=Severity.HIGH,
                        rationale=(
                            "The normalized agent model combines untrusted input and "
                            "destructive-write capability without a detected approval requirement."
                        ),
                        location=tool.location or agent.location,
                        metadata=_path_metadata(basis="capability_cooccurrence"),
                    )
                )

        for tool in outbound:
            if sensitive and tool.approval is not True:
                paths.append(
                    AttackPath(
                        path_id="PATH003",
                        title="Potential sensitive-data path to an external destination",
                        agent=agent.name,
                        nodes=[
                            sensitive[0].name,
                            agent.name,
                            tool.name,
                            "external destination",
                        ],
                        severity=Severity.CRITICAL,
                        rationale=(
                            "The normalized agent model combines sensitive-data access and "
                            "external write/egress capability without an approval requirement."
                        ),
                        location=tool.location or agent.location,
                        metadata=_path_metadata(basis="capability_cooccurrence"),
                    )
                )

        if untrusted and sensitive and execution:
            paths.append(
                AttackPath(
                    path_id="PATH004",
                    title="Potential combination of untrusted input, sensitive data and execution",
                    agent=agent.name,
                    nodes=[
                        untrusted[0].name,
                        agent.name,
                        sensitive[0].name,
                        execution[0].name,
                    ],
                    severity=Severity.CRITICAL,
                    rationale=(
                        "The agent combines untrusted input, sensitive data access and "
                        "arbitrary process execution."
                    ),
                    location=agent.location,
                    metadata=_path_metadata(basis="capability_cooccurrence"),
                )
            )

        if untrusted and secret_tools and unconstrained_outbound:
            paths.append(
                AttackPath(
                    path_id="PATH005",
                    title="Potential untrusted-input path to secret access and egress",
                    agent=agent.name,
                    nodes=[
                        untrusted[0].name,
                        agent.name,
                        secret_tools[0].name,
                        unconstrained_outbound[0].name,
                    ],
                    severity=Severity.HIGH,
                    rationale=(
                        "The normalized agent model combines untrusted input, secret-reading "
                        "capability and unconstrained outbound capability."
                    ),
                    location=agent.location,
                    metadata=_path_metadata(basis="capability_cooccurrence"),
                )
            )

        privileged = sorted(agent.capabilities & HIGH_RISK_CAPABILITIES)
        if len(privileged) >= 2 and untrusted:
            paths.append(
                AttackPath(
                    path_id="PATH006",
                    title="Potential untrusted-input exposure to multiple high-risk capabilities",
                    agent=agent.name,
                    nodes=[untrusted[0].name, agent.name, *privileged],
                    severity=Severity.HIGH,
                    rationale=(
                        "The same agent combines untrusted input with multiple "
                        "high-risk capabilities."
                    ),
                    location=agent.location,
                    metadata=_path_metadata(basis="capability_cooccurrence"),
                )
            )

    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    result: list[AttackPath] = []
    for path in paths:
        path.metadata.setdefault("assessment", "potential_risk")
        path.metadata.setdefault("basis", "capability_cooccurrence")
        path.metadata.setdefault("exploitability", "not_verified")
        path.metadata.setdefault(
            "limitations",
            _path_metadata(basis=path.metadata["basis"])["limitations"],
        )
        key = (path.path_id, path.agent, tuple(path.nodes))
        if key not in seen:
            seen.add(key)
            result.append(path)
    return result
