from __future__ import annotations

from horustrace.heuristics import (
    HIGH_RISK_CAPABILITIES,
    UNTRUSTED_INPUT_KINDS,
)
from horustrace.models import (
    AgentReachability,
    AttackPath,
    FlowExecutionContext,
    FlowPath,
    Graph,
    Severity,
    Tool,
)

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
    if basis in {"static_dataflow", "source_proven_tool_dataflow"}:
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


def _bound_tool_for_flow(graph: Graph, flow: FlowPath) -> Tool | None:
    if not flow.agent:
        return None
    binding = flow.metadata.get("agent_binding")
    if not isinstance(binding, dict):
        return None
    tool_name = binding.get("tool")
    function_key = binding.get("function")
    instance_key = binding.get("agent_instance_key")
    source_path = binding.get("agent_source_path")
    source_line = binding.get("agent_source_line")

    agents = [item for item in graph.agents if item.name == flow.agent]
    if isinstance(source_path, str) and source_path:
        agents = [
            item
            for item in agents
            if item.location is not None
            and item.location.path.as_posix().endswith(source_path)
            and (
                not isinstance(source_line, str)
                or str(item.location.line) == source_line
            )
        ]
    elif isinstance(instance_key, str) and instance_key:
        agents = [
            item
            for item in agents
            if str(item.metadata.get("instance_key") or "") == instance_key
        ]
    if len(agents) != 1:
        return None
    agent = agents[0]

    if isinstance(function_key, str):
        exact = [
            tool
            for tool in agent.tools
            if tool.metadata.get("source_function_key") == function_key
        ]
        if len(exact) == 1:
            return exact[0]

    if isinstance(tool_name, str):
        named = [tool for tool in agent.tools if tool.name == tool_name]
        if len(named) == 1:
            return named[0]
    return None

def _flow_backed_paths(graph: Graph) -> list[AttackPath]:
    paths: list[AttackPath] = []
    for flow in graph.flow_paths:
        if (
            not flow.agent
            or flow.agent_reachability is not AgentReachability.PROVEN_AGENT_REACHABLE
            or flow.execution_context
            in {
                FlowExecutionContext.TEST,
                FlowExecutionContext.EXAMPLE,
                FlowExecutionContext.TUTORIAL,
                FlowExecutionContext.NOTEBOOK,
                FlowExecutionContext.TEMPLATE_GENERATED,
            }
            or flow.basis != "static_dataflow"
            or flow.confidence.value != "supported"
        ):
            continue
        nodes = [step.label for step in flow.steps]
        bound_tool = _bound_tool_for_flow(graph, flow)
        if (
            flow.source_kind in _UNTRUSTED_FLOW_SOURCES
            and flow.sink_kind == "process_execute"
            and bound_tool is not None
            and bound_tool.metadata.get("process_execution_constrained") is True
        ):
            continue
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
        elif (
            flow.source_kind in _UNTRUSTED_FLOW_SOURCES
            and flow.sink_kind == "server_side_url_fetch"
        ):
            paths.append(
                AttackPath(
                    path_id="PATH011",
                    title="Potential untrusted-input path to server-side URL fetch",
                    agent=flow.agent,
                    nodes=nodes,
                    severity=Severity.HIGH,
                    rationale=(
                        "A supported static data-flow path connects a model-controlled "
                        "tool argument to a server-side URL-loading abstraction without "
                        "a detected destination restriction."
                    ),
                    location=flow.steps[-1].location if flow.steps else None,
                    metadata={
                        **_flow_path_metadata(flow),
                        "destination_provenance": "model_selected_url_argument",
                        "indirect_destination": False,
                        "network_abstraction": "url_loader",
                    },
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

                model_selected_url_fetch = (
                    tool.metadata.get("model_selected_url_fetch") is True
                    and tool.approval is not True
                )
                if model_selected_url_fetch:
                    dynamic_destinations = [
                        destination
                        for destination in tool.destinations
                        if destination.metadata.get("network_scope")
                        == "dynamic_destination"
                        or destination.metadata.get("source")
                        == "model_selected_url_argument"
                    ]
                    if dynamic_destinations:
                        paths.append(
                            AttackPath(
                                path_id="PATH011",
                                title=(
                                    "Potential untrusted-input path through delegated "
                                    "agent to server-side URL fetch"
                                ),
                                agent=agent.name,
                                nodes=[
                                    untrusted[0].name,
                                    agent.name,
                                    f"delegate:{delegated.name}",
                                    tool.name,
                                    "model-selected URL",
                                    dynamic_destinations[0].target,
                                ],
                                severity=Severity.HIGH,
                                rationale=(
                                    "The normalized model shows untrusted input reaching "
                                    "an agent that can delegate to a URL-context tool whose "
                                    "content target is model-selected and has no detected "
                                    "destination restriction."
                                ),
                                location=tool.location or delegated.location or agent.location,
                                metadata={
                                    **_path_metadata(
                                        basis="source_bound_delegated_authority"
                                    ),
                                    "delegate_target": delegated.name,
                                    "delegate_tool": delegate_tool.name,
                                    "destination_provenance": tool.metadata.get(
                                        "destination_provenance"
                                    ),
                                    "provider_network_scope": tool.metadata.get(
                                        "provider_network_scope"
                                    ),
                                    "network_abstraction": tool.metadata.get(
                                        "network_abstraction"
                                    ),
                                    "indirect_destination": False,
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
                    and not model_selected_url_fetch
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
            not in {
                "fixed_managed_service",
                "fixed_provider_network",
                "operator_configured_destination",
                "explicit_destination",
            }
            and not (
                tool.destinations
                and all(destination.restricted for destination in tool.destinations)
            )
        ]
        execution = [
            tool
            for tool in agent.tools
            if "process.execute" in tool.capabilities
            and tool.metadata.get("process_execution_constrained") is not True
        ]
        execution_mcp = [
            server
            for server in agent.mcp_servers
            if "process.execute"
            in set(server.metadata.get("discovered_tool_capabilities") or [])
        ]
        destructive = [
            tool
            for tool in agent.tools
            if "destructive.write" in tool.capabilities
            and tool.metadata.get("agent_internal_artifact") is not True
        ]
        runtime_bound_untrusted = [
            item
            for item in untrusted
            if item.metadata.get("runtime_invocation_proven") is True
            or item.metadata.get("basis") == "pydantic_ai_cli_input_to_run"
        ]
        state_changing = [
            tool
            for tool in agent.tools
            if "destructive.write" not in tool.capabilities
            and {"data.write", "external.write"} & tool.capabilities
            and tool.metadata.get("agent_internal_artifact") is not True
        ]
        destructive_mcp = [
            server
            for server in agent.mcp_servers
            if "destructive.write"
            in set(server.metadata.get("discovered_tool_capabilities") or [])
        ]
        state_changing_mcp = [
            server
            for server in agent.mcp_servers
            if (
                "destructive.write"
                not in set(server.metadata.get("discovered_tool_capabilities") or [])
                and {"data.write", "external.write"}
                & set(server.metadata.get("discovered_tool_capabilities") or [])
            )
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

        for server in execution_mcp:
            if (
                untrusted
                and server.approval is not True
                and not server.guardrails
            ):
                ingress = (
                    runtime_bound_untrusted[0]
                    if runtime_bound_untrusted
                    else untrusted[0]
                )
                basis = (
                    "source_bound_ingress_authority"
                    if runtime_bound_untrusted
                    else "capability_cooccurrence"
                )
                paths.append(
                    AttackPath(
                        path_id="PATH001",
                        title="Potential untrusted-input path to MCP command execution",
                        agent=agent.name,
                        nodes=[
                            ingress.name,
                            agent.name,
                            server.name,
                            "process.execute",
                        ],
                        severity=Severity.CRITICAL,
                        rationale=(
                            "The normalized agent model binds untrusted input to an MCP "
                            "server exposing process-execution capability without a "
                            "detected approval or guardrail requirement."
                        ),
                        location=server.location or agent.location,
                        metadata={
                            **_path_metadata(basis=basis),
                            "ingress_basis": ingress.metadata.get("basis"),
                            "target_kind": "mcp_server",
                        },
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

        for tool in state_changing:
            if runtime_bound_untrusted and tool.approval is not True:
                capability = (
                    "data.write"
                    if "data.write" in tool.capabilities
                    else "external.write"
                )
                ingress = runtime_bound_untrusted[0]
                paths.append(
                    AttackPath(
                        path_id="PATH002",
                        title="Potential untrusted-input path to state-changing action",
                        agent=agent.name,
                        nodes=[
                            ingress.name,
                            agent.name,
                            tool.name,
                            capability,
                        ],
                        severity=Severity.HIGH,
                        rationale=(
                            "Source analysis proves untrusted input reaches the "
                            "agent runtime invocation, and the effective authority model "
                            "binds a state-changing tool without a detected approval "
                            "requirement. Runtime model selection is not verified."
                        ),
                        location=tool.location or agent.location,
                        metadata={
                            **_path_metadata(
                                basis="source_bound_ingress_authority"
                            ),
                            "ingress_basis": ingress.metadata.get("basis"),
                            "authority_capability": capability,
                            "target_kind": "tool",
                        },
                    )
                )

        for server in state_changing_mcp:
            if (
                runtime_bound_untrusted
                and server.approval is not True
                and not server.guardrails
            ):
                capabilities = set(
                    server.metadata.get("discovered_tool_capabilities") or []
                )
                capability = (
                    "data.write"
                    if "data.write" in capabilities
                    else "external.write"
                )
                ingress = runtime_bound_untrusted[0]
                paths.append(
                    AttackPath(
                        path_id="PATH002",
                        title="Potential untrusted-input path to state-changing MCP action",
                        agent=agent.name,
                        nodes=[
                            ingress.name,
                            agent.name,
                            server.name,
                            capability,
                        ],
                        severity=Severity.HIGH,
                        rationale=(
                            "Source analysis proves untrusted input reaches the agent "
                            "runtime invocation, and the effective authority model binds "
                            "an MCP server exposing state-changing capability without a "
                            "detected approval or guardrail requirement."
                        ),
                        location=server.location or agent.location,
                        metadata={
                            **_path_metadata(
                                basis="source_bound_ingress_authority"
                            ),
                            "ingress_basis": ingress.metadata.get("basis"),
                            "authority_capability": capability,
                            "target_kind": "mcp_server",
                        },
                    )
                )

        for server in destructive_mcp:
            if (
                untrusted
                and server.approval is not True
                and not server.guardrails
            ):
                paths.append(
                    AttackPath(
                        path_id="PATH002",
                        title="Potential untrusted-input path to destructive MCP action",
                        agent=agent.name,
                        nodes=[
                            untrusted[0].name,
                            agent.name,
                            server.name,
                            "destructive.write",
                        ],
                        severity=Severity.HIGH,
                        rationale=(
                            "The normalized agent model combines untrusted input with "
                            "a bound MCP server exposing destructive-write capability "
                            "without a detected approval or guardrail requirement."
                        ),
                        location=server.location or agent.location,
                        metadata={
                            **_path_metadata(basis="capability_cooccurrence"),
                            "target_kind": "mcp_server",
                        },
                    )
                )

        for tool in agent.tools:
            if (
                untrusted
                and tool.metadata.get("file_read_external_transfer") is True
                and tool.metadata.get("filesystem_path_constrained") is not True
            ):
                sinks = list(tool.metadata.get("file_read_external_sinks") or [])
                parameters = list(
                    tool.metadata.get("model_selected_path_parameters") or []
                )
                paths.append(
                    AttackPath(
                        path_id="PATH010",
                        title="Potential untrusted-input local file read to external service",
                        agent=agent.name,
                        nodes=[
                            untrusted[0].name,
                            agent.name,
                            tool.name,
                            "model-selected local file",
                            sinks[0] if sinks else "external service",
                        ],
                        severity=Severity.HIGH,
                        rationale=(
                            "Source analysis proves a model-selected file path reaches "
                            "a local file-read sink and data derived from that read reaches "
                            "an external service call without a detected path-containment boundary."
                        ),
                        location=tool.location or agent.location,
                        metadata={
                            **_path_metadata(
                                basis="source_proven_tool_dataflow"
                            ),
                            "target_kind": "tool",
                            "path_parameters": parameters,
                            "external_sinks": sinks,
                            "path_containment": "not_detected",
                        },
                    )
                )

        for tool in agent.tools:
            direct_url_fetch = tool.metadata.get("model_selected_url_fetch") is True
            search_result_fetch = tool.metadata.get("search_result_url_fetch") is True
            if (
                runtime_bound_untrusted
                and (direct_url_fetch or search_result_fetch)
                and tool.approval is not True
            ):
                expected_scopes = (
                    {"dynamic_destination"}
                    if direct_url_fetch
                    else {"search_result_derived_destination"}
                )
                dynamic_destinations = [
                    destination
                    for destination in tool.destinations
                    if (
                        direct_url_fetch
                        and destination.metadata.get("source")
                        == "model_selected_url_argument"
                    )
                    or destination.metadata.get("network_scope")
                    in expected_scopes
                ]
                if dynamic_destinations:
                    ingress = runtime_bound_untrusted[0]
                    parameters = list(
                        tool.metadata.get("model_selected_url_parameters") or []
                    )
                    indirect = search_result_fetch and not direct_url_fetch
                    paths.append(
                        AttackPath(
                            path_id="PATH011",
                            title=(
                                "Potential untrusted-input path to search-derived server-side URL fetch"
                                if indirect
                                else "Potential untrusted-input path to server-side URL fetch"
                            ),
                            agent=agent.name,
                            nodes=[
                                ingress.name,
                                agent.name,
                                tool.name,
                                (
                                    "provider search-result URL"
                                    if indirect
                                    else "model-selected URL"
                                ),
                                dynamic_destinations[0].target,
                            ],
                            severity=Severity.MEDIUM if indirect else Severity.HIGH,
                            rationale=(
                                (
                                    "Source analysis proves untrusted input reaches the "
                                    "agent runtime, model-selected search terms influence "
                                    "provider results, and a returned URL is dereferenced "
                                    "by a server-side HTTP helper without a detected "
                                    "destination restriction. The model does not directly "
                                    "select the final URL."
                                )
                                if indirect
                                else (
                                    "Source analysis proves untrusted input reaches the "
                                    "agent runtime, and the effective tool accepts a "
                                    "model-selected URL that is passed to a direct "
                                    "server-side HTTP client without a detected "
                                    "destination restriction."
                                )
                            ),
                            location=tool.location or agent.location,
                            metadata={
                                **_path_metadata(
                                    basis="source_bound_ingress_authority"
                                ),
                                "ingress_basis": ingress.metadata.get("basis"),
                                "target_kind": "tool",
                                "url_parameters": parameters,
                                "follow_redirects": tool.metadata.get(
                                    "follow_redirects"
                                ),
                                "destination_provenance": tool.metadata.get(
                                    "destination_provenance"
                                ),
                                "indirect_destination": indirect,
                            },
                        )
                    )

        indirect_tool_content = [
            item
            for item in untrusted
            if item.metadata.get("basis") == "source_proven_tool_result_content"
            and item.metadata.get("indirect") is True
        ]
        unconstrained_filesystem_tools = [
            tool
            for tool in agent.tools
            if tool.metadata.get("model_selected_filesystem_path") is True
            and tool.metadata.get("filesystem_path_constrained") is not True
            and tool.metadata.get("filesystem_access")
        ]
        if indirect_tool_content and unconstrained_filesystem_tools:
            target = min(
                unconstrained_filesystem_tools,
                key=lambda item: (
                    "write" not in set(item.metadata.get("filesystem_access") or []),
                    item.name,
                ),
            )
            access_modes = list(target.metadata.get("filesystem_access") or [])
            access_label = (
                "filesystem write"
                if "write" in access_modes
                else "filesystem read"
            )
            source = indirect_tool_content[0]
            paths.append(
                AttackPath(
                    path_id="PATH012",
                    title="Potential indirect tool-content path to unconstrained filesystem access",
                    agent=agent.name,
                    nodes=[
                        source.name,
                        agent.name,
                        target.name,
                        access_label,
                    ],
                    severity=Severity.HIGH,
                    rationale=(
                        "Source analysis proves a bound tool returns local or repository "
                        "file content into the model context, while the same effective "
                        "agent can select filesystem paths that reach read/write sinks "
                        "without a detected containment boundary."
                    ),
                    location=target.location or source.location or agent.location,
                    metadata={
                        **_path_metadata(
                            basis="source_proven_indirect_tool_content"
                        ),
                        "source_tool": source.metadata.get("source_tool"),
                        "target_kind": "tool",
                        "filesystem_access": access_modes,
                        "path_parameters": list(
                            target.metadata.get(
                                "model_selected_path_parameters"
                            )
                            or []
                        ),
                        "path_containment": "not_detected",
                    },
                )
            )

        rag_directory_inputs = [
            item
            for item in untrusted
            if item.metadata.get("basis")
            == "source_proven_user_selected_rag_directory"
            and item.metadata.get("recursive_ingestion") is True
            and item.metadata.get("filesystem_path_constrained") is not True
        ]
        rag_retrieval_tools = [
            tool
            for tool in agent.tools
            if tool.metadata.get("rag_retrieval") is True
            and tool.metadata.get("rag_returns_indexed_content") is True
            and tool.metadata.get("rag_recursive_ingestion") is True
            and tool.metadata.get("filesystem_path_constrained") is not True
        ]
        if (
            rag_directory_inputs
            and rag_retrieval_tools
            and runtime_bound_untrusted
        ):
            directory_input = rag_directory_inputs[0]
            retrieval_tool = rag_retrieval_tools[0]
            paths.append(
                AttackPath(
                    path_id="PATH013",
                    title="Potential user-selected server directory exposure through RAG",
                    agent=agent.name,
                    nodes=[
                        directory_input.name,
                        "recursive server-side file ingestion",
                        "RAG index",
                        agent.name,
                        retrieval_tool.name,
                        "indexed file content in agent response",
                    ],
                    severity=Severity.HIGH,
                    rationale=(
                        "Source analysis proves a user-selected server-side directory "
                        "reaches recursive document ingestion without a detected "
                        "containment boundary, while source-bound chat input reaches "
                        "the same effective agent and a bound retrieval tool can return "
                        "the indexed document content."
                    ),
                    location=directory_input.location or retrieval_tool.location or agent.location,
                    metadata={
                        **_path_metadata(
                            basis="source_proven_rag_directory_retrieval"
                        ),
                        "ingress_basis": runtime_bound_untrusted[0].metadata.get(
                            "basis"
                        ),
                        "directory_basis": directory_input.metadata.get("basis"),
                        "sink_module": directory_input.metadata.get("sink_module"),
                        "sink_function": directory_input.metadata.get("sink_function"),
                        "path_containment": "not_detected",
                        "retrieval_tool": retrieval_tool.name,
                    },
                )
            )

        authorization_bypass_tools = [
            tool
            for tool in agent.tools
            if tool.metadata.get("object_authorization_boundary_bypass") is True
        ]
        if authorization_bypass_tools and runtime_bound_untrusted:
            target = authorization_bypass_tools[0]
            ingress = runtime_bound_untrusted[0]
            model_name = str(
                target.metadata.get("object_model") or "owner-scoped object"
            )
            identifier = str(
                target.metadata.get("object_id_parameter") or "object_id"
            )
            paths.append(
                AttackPath(
                    path_id="PATH014",
                    title="Potential model-driven cross-owner object mutation",
                    agent=agent.name,
                    nodes=[
                        ingress.name,
                        agent.name,
                        target.name,
                        f"model-selected {identifier}",
                        f"unscoped {model_name} mutation",
                    ],
                    severity=Severity.MEDIUM,
                    rationale=(
                        "Source analysis proves user-controlled application input "
                        "reaches the agent runtime, while a bound model-callable tool "
                        "can select and commit a mutation to an owner-scoped object "
                        "without carrying the repository's normal owner check into "
                        "the tool boundary."
                    ),
                    location=target.location or ingress.location or agent.location,
                    metadata={
                        **_path_metadata(
                            basis="source_proven_object_authorization_bypass"
                        ),
                        "ingress_basis": ingress.metadata.get("basis"),
                        "object_model": target.metadata.get("object_model"),
                        "object_id_parameter": target.metadata.get(
                            "object_id_parameter"
                        ),
                        "ownership_field": target.metadata.get("ownership_field"),
                        "authenticated_ingress": ingress.metadata.get(
                            "authenticated"
                        ),
                        "limitation": (
                            "Cross-owner impact requires a valid object identifier "
                            "outside the caller's authorized scope."
                        ),
                    },
                )
            )

        public_realtime_inputs = [
            item
            for item in runtime_bound_untrusted
            if item.metadata.get("basis")
            == "source_proven_public_realtime_capability"
            and item.metadata.get("authentication_detected") is False
        ]
        realtime_mutation_tools = [
            tool
            for tool in agent.tools
            if tool.metadata.get("mcp_backed") is True
            and {"data.write", "destructive.write"} & tool.capabilities
            and tool.approval is not True
        ]
        if public_realtime_inputs and realtime_mutation_tools:
            ingress = public_realtime_inputs[0]
            target = min(
                realtime_mutation_tools,
                key=lambda tool: (
                    "destructive.write" not in tool.capabilities,
                    tool.name not in {"transfer_funds", "create_account"},
                    tool.name,
                ),
            )
            backends = list(target.metadata.get("state_backends") or [])
            paths.append(
                AttackPath(
                    path_id="PATH015",
                    title="Potential unauthenticated realtime path to MCP-backed state mutation",
                    agent=agent.name,
                    nodes=[
                        "public session credential endpoint",
                        ingress.name,
                        agent.name,
                        target.name,
                        "MCP tool dispatch",
                        (
                            "local SQLite state mutation"
                            if "local_sqlite" in backends
                            else "state mutation"
                        ),
                    ],
                    severity=Severity.HIGH,
                    rationale=(
                        "Source analysis proves a web endpoint can mint a "
                        "publish-capable realtime session credential without a "
                        "detected authentication dependency; participant input "
                        "from that session reaches the model agent, whose bound "
                        "tool dispatches through MCP to a source-proven "
                        "state-changing repository backend without per-action approval."
                    ),
                    location=ingress.location or target.location or agent.location,
                    metadata={
                        **_path_metadata(
                            basis="source_proven_public_realtime_mcp_state_change"
                        ),
                        "ingress_basis": ingress.metadata.get("basis"),
                        "session_transport": ingress.metadata.get("session_transport"),
                        "session_capability": ingress.metadata.get("session_capability"),
                        "mcp_tool_name": target.metadata.get("mcp_tool_name"),
                        "state_backends": backends,
                        "state_scope": target.metadata.get("state_scope"),
                        "limitation": (
                            "The traced target is repository-local SQLite/demo state; "
                            "production banking impact is not asserted."
                            if "local_sqlite" in backends
                            else None
                        ),
                    },
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

        wrapped_execution = [
            tool
            for tool in execution
            if tool.metadata.get("source") == "tool_from_langchain"
            and tool.metadata.get("wrapped_tool")
        ]
        for tool in wrapped_execution:
            if not untrusted:
                break
            paths.append(
                AttackPath(
                    path_id="PATH001",
                    title="Potential untrusted-input path to wrapped code execution",
                    agent=agent.name,
                    nodes=[
                        untrusted[0].name,
                        agent.name,
                        tool.name,
                        "wrapped code execution",
                    ],
                    severity=Severity.CRITICAL,
                    rationale=(
                        "Source proves a user-facing Pydantic AI runtime binds a "
                        "third-party tool whose wrapped class provides code/process "
                        "execution without a detected approval boundary."
                    ),
                    location=tool.location or agent.location,
                    metadata={
                        **_path_metadata(
                            basis="source_bound_ingress_authority"
                        ),
                        "wrapped_framework": tool.metadata.get(
                            "wrapped_framework"
                        ),
                        "wrapped_tool": tool.metadata.get("wrapped_tool"),
                        "binding_adapter": tool.metadata.get(
                            "binding_adapter"
                        ),
                    },
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

        # PATH006 is a summary of *effective uncontrolled* high-risk
        # capabilities, not the raw capability union. Reuse the control-aware
        # classifications above so constrained shell execution and
        # agent-internal artifact deletion do not reappear as a generic path.
        effective_privileged: set[str] = set()
        if execution or execution_mcp:
            effective_privileged.add("process.execute")
        if destructive or destructive_mcp:
            effective_privileged.add("destructive.write")
        for tool in agent.tools:
            if tool.approval is True:
                continue
            effective_privileged.update(
                tool.capabilities & {"secrets.read", "identity.admin"}
            )
        for server in agent.mcp_servers:
            if server.approval is True or server.guardrails:
                continue
            effective_privileged.update(
                set(server.metadata.get("discovered_tool_capabilities") or [])
                & {"secrets.read", "identity.admin"}
            )
        privileged = sorted(effective_privileged)
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

    agents_by_name = {agent.name: agent for agent in graph.agents}
    auth_keys = (
        "authentication_detected",
        "authentication_mode",
        "public_default",
        "authentication_environment_variables",
    )
    for path in paths:
        agent = agents_by_name.get(path.agent)
        if agent is None:
            continue
        ingress = next(
            (
                item
                for item in agent.inputs
                if item.name == (path.nodes[0] if path.nodes else "")
                and any(key in item.metadata for key in auth_keys)
            ),
            None,
        )
        if ingress is None:
            ingress = next(
                (
                    item
                    for item in agent.inputs
                    if item.metadata.get("runtime_invocation_proven") is True
                    and any(key in item.metadata for key in auth_keys)
                ),
                None,
            )
        if ingress is None:
            continue
        for key in auth_keys:
            if key in ingress.metadata:
                path.metadata.setdefault(key, ingress.metadata[key])

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
