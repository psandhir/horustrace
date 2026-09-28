from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from horustrace.effective_authority import effective_authority_relationships
from horustrace.heuristics import (
    BROAD_OAUTH_SCOPES,
    PRIVILEGED_CAPABILITIES,
    destination_is_broad,
    matches_any,
    package_is_unpinned,
    permission_looks_wildcard,
    resource_is_broad,
    role_looks_admin,
)
from horustrace.models import Finding, Graph, Identity, NetworkDestination, Severity, SourceLocation


def _is_loopback_url(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _destination_is_broad_or_dynamic(destination: NetworkDestination) -> bool:
    if destination_is_broad(destination.target) or destination.target.startswith("<dynamic"):
        return True

    source = str(destination.metadata.get("source") or "")
    scope = str(destination.metadata.get("network_scope") or "")
    if source == "literal_url" or scope in {
        "fixed_literal_destination",
        "fixed_managed_service",
        "explicit_destination",
    }:
        return False
    if source == "dynamic_network_call" or scope == "dynamic_destination":
        return True

    # A bare unrestricted destination from policy/config remains broad unless
    # stronger provenance shows it is only an observed fixed literal.
    return not destination.restricted


def _identity_findings(identity: Identity, agent: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    declared_authority = identity.metadata.get("declared_authority")
    authority_is_declared = (
        isinstance(declared_authority, dict)
        and declared_authority.get("state") == "declared"
    )
    admin_roles = sorted(role for role in identity.roles if role_looks_admin(role))
    if admin_roles:
        evidence = ["roles=" + ",".join(admin_roles), f"provider={identity.provider}"]
        limitations: list[str] = []
        qualifier = ""
        if authority_is_declared:
            evidence.append("authority_state=declared")
            qualifier = " in declared Terraform authority evidence"
            limitations.append(
                "Declared Terraform IAM authority was not verified against live Google Cloud state."
            )
        findings.append(
            Finding(
                rule_id="IDN001",
                layer=3,
                severity=Severity.HIGH,
                title="Broad administrative identity role",
                message=(
                    f"Identity '{identity.name}' has one or more broad administrative roles"
                    f"{qualifier}."
                ),
                recommendation="Replace broad roles with workload-specific least-privilege roles and scope them to required resources.",
                location=identity.location,
                agent=agent,
                evidence=evidence,
                limitations=limitations,
            )
        )
    wildcard = sorted(p for p in identity.permissions if permission_looks_wildcard(p))
    if wildcard:
        findings.append(
            Finding(
                rule_id="IDN002",
                layer=3,
                severity=Severity.CRITICAL,
                title="Wildcard identity permission",
                message=f"Identity '{identity.name}' includes wildcard permissions.",
                recommendation="Enumerate the exact API actions required by the agent and remove wildcard permissions.",
                location=identity.location,
                agent=agent,
                evidence=["permissions=" + ",".join(wildcard), f"provider={identity.provider}"],
            )
        )
    broad_scopes = sorted(scope for scope in identity.oauth_scopes if scope in BROAD_OAUTH_SCOPES)
    if broad_scopes:
        findings.append(
            Finding(
                rule_id="IDN003",
                layer=3,
                severity=Severity.HIGH,
                title="Broad OAuth scope",
                message=f"Identity '{identity.name}' requests a broad OAuth scope.",
                recommendation="Use narrow OAuth scopes and resource-level authorization appropriate to the tool action.",
                location=identity.location,
                agent=agent,
                evidence=["oauth_scopes=" + ",".join(broad_scopes)],
            )
        )
    if identity.credential_source and identity.credential_source.lower() in {"hardcoded", "source", "plaintext", "file"}:
        findings.append(
            Finding(
                rule_id="IDN004",
                layer=3,
                severity=Severity.HIGH,
                title="Unsafe credential source",
                message=f"Identity '{identity.name}' uses credential source '{identity.credential_source}'.",
                recommendation="Use workload identity or a managed secret store; do not embed long-lived credentials in source/configuration.",
                location=identity.location,
                agent=agent,
                evidence=[f"credential_source={identity.credential_source}"],
            )
        )
    return findings


def evaluate(graph: Graph) -> list[Finding]:
    findings: list[Finding] = []
    authority_relationships = effective_authority_relationships(graph)
    authority_by_key = {
        (item.agent, item.target_kind, item.target_name): item
        for item in authority_relationships
    }
    mcp_authority_by_object: dict[int, object] = {}
    for authority_agent in graph.agents:
        for authority_server in authority_agent.mcp_servers:
            relationship = authority_by_key.get(
                (authority_agent.name, "mcp_server", authority_server.name)
            )
            if relationship is not None:
                mcp_authority_by_object[id(authority_server)] = relationship

    # Layer 1: agent/framework/MCP configuration controls.
    for agent in graph.agents:
        callbacks = agent.metadata.get("callbacks") or {}
        agent_tool_control = bool(agent.metadata.get("approval_plugin")) or bool(
            callbacks.get("before_tool_callback")
        )
        for tool in agent.tools:
            tool_authority = authority_by_key.get(
                (agent.name, "tool", tool.name)
            )
            if (
                "process.execute" in tool.capabilities
                and tool.approval is not True
                and tool.kind != "delegated_agent"
            ):
                findings.append(Finding("AGT020", Severity.HIGH, "Shell or process execution without approval", f"Tool '{tool.name}' can execute processes without an explicit approval requirement.", "Require approval for process execution and run the tool inside a constrained sandbox.", layer=1, location=tool.location, agent=agent.name, evidence=["capability=process.execute", f"approval={tool.approval}"]))
            if "destructive.write" in tool.capabilities and tool.approval is not True:
                findings.append(Finding("AGT021", Severity.HIGH, "Destructive action without human approval", f"Tool '{tool.name}' appears able to perform destructive writes without approval.", "Gate destructive operations with human approval and least-privilege authorization.", layer=1, location=tool.location, agent=agent.name, evidence=["capability=destructive.write", f"approval={tool.approval}"]))
            if "data.write" in tool.capabilities and tool.approval is not True and tool.kind in {"apply_patch", "generic", "function"}:
                findings.append(Finding("AGT022", Severity.MEDIUM, "State-changing tool without approval", f"Tool '{tool.name}' can modify state without explicit approval.", "Require approval for material state changes or constrain the tool to low-risk, reversible operations.", layer=1, location=tool.location, agent=agent.name, evidence=["capability=data.write", f"approval={tool.approval}"]))
            if (
                "computer.control" in tool.capabilities
                and tool.metadata.get("computer_control_custom")
                and tool.metadata.get("computer_control_mutating")
                and not tool.guardrails
                and tool.approval is not True
                and not agent_tool_control
            ):
                sink_location = tool.metadata.get("computer_control_sink_location")
                location = (
                    sink_location
                    if isinstance(sink_location, SourceLocation)
                    else tool.location
                )
                actions = ",".join(tool.metadata.get("computer_control_actions") or [])
                sinks = ",".join(tool.metadata.get("computer_control_sinks") or [])
                findings.append(
                    Finding(
                        "AGT023",
                        Severity.HIGH,
                        "Computer-control action lacks explicit boundary",
                        f"Tool '{tool.name}' can perform state-changing computer/browser actions without detected approval or guardrail controls.",
                        "Require confirmation or a policy guardrail before click, type, keypress, upload, or equivalent state-changing computer actions.",
                        layer=1,
                        location=location,
                        agent=agent.name,
                        evidence=[
                            "capability=computer.control",
                            f"actions={actions or 'dynamic'}",
                            f"sink={sinks or tool.name}",
                        ],
                    )
                )
            authority_has_control = (
                tool_authority is not None
                and tool_authority.dimensions.get("approval") == "resolved"
                and (
                    tool_authority.approval.get("required") is True
                    or bool(tool_authority.approval.get("guardrails"))
                    or bool(tool_authority.approval.get("inherited_control"))
                )
            )
            if (
                tool.capabilities & PRIVILEGED_CAPABILITIES
                and not tool.metadata.get("computer_control_custom")
                and not authority_has_control
                and not tool.guardrails
                and tool.approval is not True
                and not agent_tool_control
            ):
                evidence = ["capabilities=" + ",".join(sorted(tool.capabilities))]
                if tool_authority is not None:
                    evidence.extend(
                        [
                            f"authority_relationship={tool_authority.relationship_id}",
                            "approval_resolution="
                            + tool_authority.dimensions.get("approval", "unknown"),
                        ]
                    )
                findings.append(
                    Finding(
                        "AGT040",
                        Severity.MEDIUM,
                        "Privileged tool lacks explicit guardrail or approval",
                        f"Privileged tool '{tool.name}' has no detected guardrail or approval configuration.",
                        "Add tool input/output guardrails and/or explicit approval appropriate to the action.",
                        layer=1,
                        location=tool.location,
                        agent=agent.name,
                        evidence=evidence,
                        authority_relationship_id=(
                            tool_authority.relationship_id
                            if tool_authority is not None
                            else None
                        ),
                    )
                )

    # Google ADK framework-specific controls. These rules consume normalized
    # Tool metadata emitted by the first-class ADK Python/YAML adapters.
    for agent in graph.agents:
        if agent.metadata.get("framework") != "google-adk":
            continue
        callbacks = agent.metadata.get("callbacks") or {}
        safety_control = bool(agent.metadata.get("approval_plugin")) or bool(callbacks.get("before_tool_callback"))
        privileged_tools = [t for t in agent.tools if t.capabilities & PRIVILEGED_CAPABILITIES]
        if privileged_tools and not safety_control and all(t.approval is not True and not t.guardrails for t in privileged_tools):
            findings.append(Finding("ADK001", Severity.MEDIUM, "Privileged ADK agent has no detected tool-control callback/plugin", f"ADK agent '{agent.name}' exposes privileged capabilities without a before-tool control callback, action-control plugin, or per-tool confirmation.", "Add a before_tool_callback/action-control plugin and require confirmation for high-impact tools.", layer=1, location=agent.location, agent=agent.name, evidence=["privileged_tools=" + ",".join(t.name for t in privileged_tools)]))

        for tool in agent.tools:
            builtin = str(tool.metadata.get("adk_builtin") or "")
            executor = str(tool.metadata.get("code_executor") or "")
            if executor == "UnsafeLocalCodeExecutor" or (tool.kind == "adk_code_executor" and tool.metadata.get("sandboxed") is False):
                findings.append(Finding("ADK002", Severity.CRITICAL, "Unsafe local ADK code execution", f"Agent '{agent.name}' uses UnsafeLocalCodeExecutor or an explicitly unsandboxed executor.", "Use Agent Runtime/GKE/BuiltIn sandboxed execution and apply resource, timeout, network, and approval controls.", layer=1, location=tool.location, agent=agent.name, evidence=[f"executor={executor or tool.name}", "sandboxed=false"]))
            if builtin == "EnvironmentToolset" and tool.metadata.get("environment") == "LocalEnvironment":
                findings.append(Finding("ADK003", Severity.HIGH, "ADK LocalEnvironment exposes shell and file I/O", f"Agent '{agent.name}' uses EnvironmentToolset with LocalEnvironment, enabling local command execution and file operations.", "Run agent execution in a disposable sandbox/container, constrain working_dir, remove secrets from the environment, and gate mutating/execution actions.", layer=1, location=tool.location, agent=agent.name, evidence=[f"working_dir={tool.metadata.get('working_dir')}"]))
            if builtin == "ExecuteBashTool" and not tool.metadata.get("bash_policy_restrictive"):
                missing = []
                if not tool.metadata.get("bash_policy_present"):
                    missing.append("policy")
                if not tool.metadata.get("allowed_command_prefixes"):
                    missing.append("allowed_command_prefixes")
                if not tool.metadata.get("blocked_operators"):
                    missing.append("blocked_operators")
                findings.append(Finding("ADK004", Severity.HIGH, "ADK Bash tool lacks a restrictive policy", f"Agent '{agent.name}' uses ExecuteBashTool without both a command allowlist and blocked-command/operator controls.", "Configure BashToolPolicy with allowed command prefixes and blocked operators/commands; add timeout, resource, and approval controls for dangerous commands.", layer=1, location=tool.location, agent=agent.name, evidence=["missing=" + ",".join(missing)]))
            if (
                tool.kind == "adk_code_executor"
                and tool.metadata.get("sandboxed") is True
                and tool.metadata.get("sandbox_constraints_applicable", True) is not False
                and not tool.metadata.get("sandbox_constraints_complete")
            ):
                missing = []
                if not tool.metadata.get("sandbox_timeout_configured"):
                    missing.append("timeout")
                if not tool.metadata.get("sandbox_network_disabled"):
                    missing.append("network_restriction")
                if not tool.metadata.get("sandbox_filesystem_constrained"):
                    missing.append("filesystem_restriction")
                findings.append(Finding("ADK012", Severity.MEDIUM, "Sandboxed ADK executor lacks explicit limits", f"Agent '{agent.name}' uses a sandboxed executor without explicit static evidence for all timeout, network, and filesystem limits.", "Configure a positive timeout, disable or restrict network access, and constrain the executor workspace/allowed paths.", layer=1, location=tool.location, agent=agent.name, evidence=["missing=" + ",".join(missing)]))
            if builtin == "ComputerUseToolset" and tool.approval is not True and not tool.guardrails:
                findings.append(Finding("ADK005", Severity.HIGH, "Computer-use agent lacks an explicit action boundary", f"Agent '{agent.name}' can control a browser/computer without detected confirmation or guardrail controls.", "Add action confirmation/guardrails for navigation, typing, downloads, uploads and state-changing UI actions; isolate the browser profile.", layer=1, location=tool.location, agent=agent.name, evidence=["capability=computer.control"]))
            if builtin == "BigQueryToolset" and "data.write" in tool.capabilities:
                findings.append(Finding("ADK006", Severity.MEDIUM, "BigQuery toolset permits write-capable operation", f"Agent '{agent.name}' has a BigQueryToolset for which write operations are not statically blocked.", "Use BigQueryToolConfig(write_mode=WriteMode.BLOCKED) for read-only agents and least-privilege IAM on datasets/tables.", layer=1, location=tool.location, agent=agent.name, evidence=[f"write_mode={tool.metadata.get('write_mode')}"]))
            if builtin in {"GoogleApiToolset", "GmailToolset", "CalendarToolset", "DocsToolset", "SheetsToolset", "SlidesToolset", "YoutubeToolset", "APIHubToolset", "ApplicationIntegrationToolset", "OpenAPIToolset"} and not tool.metadata.get("tool_filter") and not tool.metadata.get("dynamic_tool_filter"):
                findings.append(Finding("ADK007", Severity.MEDIUM, "Broad ADK toolset surface", f"Agent '{agent.name}' attaches '{builtin}' without a detected tool filter.", "Restrict generated/available tools to the exact operations required by the agent and keep mutation endpoints out of read-only agents.", layer=1, location=tool.location, agent=agent.name, evidence=[f"toolset={builtin}"]))
            if tool.kind == "adk_agent_tool" and tool.metadata.get("include_plugins") is False:
                findings.append(Finding("ADK008", Severity.MEDIUM, "Delegated ADK AgentTool disables inherited plugins", f"AgentTool '{tool.name}' is configured with include_plugins=False, so parent safety/observability plugins may not apply to the delegated run.", "Ensure the child has equivalent security plugins/callbacks, or inherit parent plugins unless isolation is intentional and reviewed.", layer=1, location=tool.location, agent=agent.name, evidence=[f"delegate={tool.metadata.get('delegate_target')}", "include_plugins=false"]))
            if tool.kind == "adk_a2a_remote":
                card = str(tool.metadata.get("agent_card") or "")
                if card.startswith("http://"):
                    findings.append(Finding("ADK009", Severity.HIGH, "Remote A2A agent uses plaintext HTTP", f"Remote A2A agent '{agent.name}' resolves its agent card over plaintext HTTP.", "Use HTTPS with certificate validation and authenticate both card retrieval and A2A requests.", layer=1, location=tool.location, agent=agent.name, evidence=[f"agent_card={card}"]))
                if tool.metadata.get("authenticated") is not True:
                    findings.append(Finding("ADK010", Severity.HIGH, "Remote A2A agent has no detected authentication", f"Remote A2A agent '{agent.name}' has no detected auth_scheme/auth_credential configuration.", "Configure ADK A2A authentication and scope credentials to the intended remote agent/audience.", layer=1, location=tool.location, agent=agent.name, evidence=[f"agent_card={card or 'dynamic'}"]))

        if agent.metadata.get("a2a_exposed") and privileged_tools and not safety_control:
            findings.append(Finding("ADK011", Severity.HIGH, "Privileged ADK agent is exposed over A2A without detected safety control", f"Agent '{agent.name}' is exposed using A2A and has privileged capabilities, but no security callback/plugin was detected.", "Authenticate/authorize the A2A endpoint, validate remote input, and enforce tool-level policy before privileged actions.", layer=1, location=agent.location, agent=agent.name, evidence=["a2a_exposed=true", "privileged=" + ",".join(t.name for t in privileged_tools)]))

    for server in graph.all_mcp_servers():
        if server.url:
            parsed = urlparse(server.url)
            loopback = _is_loopback_url(server.url)
            if parsed.scheme.lower() == "http" and not loopback:
                findings.append(Finding("AGT031", Severity.HIGH, "Unencrypted remote MCP transport", f"MCP server '{server.name}' uses plaintext HTTP: {server.url}", "Use HTTPS/WSS with certificate validation for remote MCP connections.", layer=1, location=server.location, evidence=[f"url={server.url}"]))
            if server.authenticated is False and not loopback:
                findings.append(Finding("AGT030", Severity.HIGH, "Remote MCP server has no detected authentication", f"No recognized authentication mechanism was detected for remote MCP server '{server.name}'.", "Require authenticated MCP access using a scoped token/OAuth or workload identity.", layer=1, location=server.location, evidence=[f"url={server.url}", f"authenticated={server.authenticated}"]))
            server_authority = mcp_authority_by_object.get(id(server))
            tool_scope_resolved = (
                server_authority is not None
                and server_authority.dimensions.get("tool_scope") == "resolved"
                and server_authority.tool_scope is not None
                and server_authority.tool_scope.get("scope") == "explicit_allowlist"
            )
            if not tool_scope_resolved and not server.allowed_tools and not loopback:
                evidence = [f"url={server.url}", "allowed_tools=none"]
                if server_authority is not None:
                    evidence.extend(
                        [
                            f"authority_relationship={server_authority.relationship_id}",
                            "tool_scope_resolution="
                            + server_authority.dimensions.get("tool_scope", "unknown"),
                        ]
                    )
                findings.append(
                    Finding(
                        "AGT032",
                        Severity.MEDIUM,
                        "Remote MCP lacks an explicit tool allowlist",
                        f"Remote MCP server '{server.name}' has no detected explicit tool allowlist.",
                        "Use an explicit MCP tool allowlist for production agents, especially for privileged servers. A denylist alone cannot prove the remaining surface is safe.",
                        layer=1,
                        location=server.location,
                        evidence=evidence,
                        authority_relationship_id=(
                            server_authority.relationship_id
                            if server_authority is not None
                            else None
                        ),
                    )
                )
        elif (
            server.metadata.get("dynamic_mcp_endpoint") is True
            and server.transport in {"http", "sse", "streamable-http", "streamable_http"}
        ):
            # A dynamic endpoint is still a remote MCP surface. Its exact
            # scheme/destination cannot be assumed, so AGT031 remains
            # unresolved, but authentication and tool-scope controls can be
            # evaluated when source proves them independently of the URL.
            if server.authenticated is False:
                findings.append(
                    Finding(
                        "AGT030",
                        Severity.HIGH,
                        "Remote MCP server has no detected authentication",
                        f"No recognized authentication mechanism was detected for dynamic remote MCP server '{server.name}'.",
                        "Require authenticated MCP access using a scoped token/OAuth or workload identity.",
                        layer=1,
                        location=server.location,
                        evidence=["url=dynamic", f"authenticated={server.authenticated}"],
                    )
                )
            server_authority = mcp_authority_by_object.get(id(server))
            tool_scope_resolved = (
                server_authority is not None
                and server_authority.dimensions.get("tool_scope") == "resolved"
                and server_authority.tool_scope is not None
                and server_authority.tool_scope.get("scope") == "explicit_allowlist"
            )
            if not tool_scope_resolved and not server.allowed_tools:
                evidence = ["url=dynamic", "allowed_tools=none"]
                if server_authority is not None:
                    evidence.extend(
                        [
                            f"authority_relationship={server_authority.relationship_id}",
                            "tool_scope_resolution="
                            + server_authority.dimensions.get("tool_scope", "unknown"),
                        ]
                    )
                findings.append(
                    Finding(
                        "AGT032",
                        Severity.MEDIUM,
                        "Remote MCP lacks an explicit tool allowlist",
                        f"Dynamic remote MCP server '{server.name}' has no detected explicit tool allowlist.",
                        "Use an explicit MCP tool allowlist for production agents, especially for privileged servers. A denylist alone cannot prove the remaining surface is safe.",
                        layer=1,
                        location=server.location,
                        evidence=evidence,
                        authority_relationship_id=(
                            server_authority.relationship_id
                            if server_authority is not None
                            else None
                        ),
                    )
                )
        literal_credentials = list(
            server.metadata.get("literal_credential_sources") or []
        )
        if literal_credentials:
            findings.append(
                Finding(
                    "AGT051",
                    Severity.HIGH,
                    "Literal credential in MCP configuration",
                    f"MCP server '{server.name}' has credential material embedded directly in static configuration.",
                    "Remove committed credentials from MCP configuration and inject them through an environment variable, managed secret store, or workload identity.",
                    layer=1,
                    location=server.location,
                    evidence=[
                        "sources=" + ",".join(sorted(literal_credentials)),
                        "credential_values=redacted",
                    ],
                )
            )
        if server.metadata.get("broad_tool_surface"):
            findings.append(
                Finding(
                    "AGT052",
                    Severity.MEDIUM,
                    "MCP configured with broad tool surface",
                    f"MCP server '{server.name}' explicitly enables an unrestricted tool surface.",
                    "Restrict the MCP server to the smallest explicit tool allowlist required by the agent or developer workflow.",
                    layer=1,
                    location=server.location,
                    evidence=["tool_scope=all"],
                )
            )
        discovered_capabilities = set(
            server.metadata.get("discovered_tool_capabilities") or []
        )
        privileged_mcp_capabilities = discovered_capabilities & PRIVILEGED_CAPABILITIES
        server_authority = mcp_authority_by_object.get(id(server))
        if (
            privileged_mcp_capabilities
            and server.approval is not True
            and not server.guardrails
        ):
            findings.append(
                Finding(
                    "AGT053",
                    Severity.MEDIUM,
                    "MCP exposes privileged tools without an explicit action boundary",
                    f"MCP server '{server.name}' exposes privileged tool capabilities without detected approval or guardrail controls.",
                    "Add an MCP tool allowlist and require approval or equivalent policy controls for mutating, destructive, execution, or credential-access tools.",
                    layer=1,
                    location=server.location,
                    agent=(
                        server_authority.agent
                        if server_authority is not None
                        else None
                    ),
                    evidence=[
                        "capabilities="
                        + ",".join(sorted(privileged_mcp_capabilities)),
                        "approval="
                        + str(server.approval),
                        "guardrails="
                        + str(server.guardrails),
                    ],
                    authority_relationship_id=(
                        server_authority.relationship_id
                        if server_authority is not None
                        else None
                    ),
                )
            )
        if package_is_unpinned(server.command, server.args):
            findings.append(Finding("AGT050", Severity.MEDIUM, "Unpinned MCP package execution", f"MCP server '{server.name}' launches a package runner without an explicit package version.", "Pin MCP server packages to a reviewed version or immutable digest.", layer=1, location=server.location, evidence=[f"command={server.command}", "args=" + " ".join(server.args)]))
        if (
            server.transport == "stdio"
            and server.args
            and any(resource_is_broad(arg) for arg in server.args)
        ):
            findings.append(Finding("AGT001", Severity.MEDIUM, "Broad local MCP filesystem scope", f"MCP server '{server.name}' appears to receive a broad filesystem path.", "Restrict filesystem MCP access to the smallest application-specific directory.", layer=1, location=server.location, evidence=["args=" + " ".join(server.args)]))

    for tool in graph.unbound_tools:
        if "process.execute" in tool.capabilities and tool.approval is not True:
            findings.append(Finding("AGT020", Severity.HIGH, "Shell or process execution without approval", f"Unbound tool '{tool.name}' can execute processes without an explicit approval requirement.", "Require approval for process execution and run it inside a constrained sandbox.", layer=1, location=tool.location, evidence=["capability=process.execute", f"approval={tool.approval}"]))

    # Layer 2: capability/effective-authority analysis.
    for agent in graph.agents:
        caps = agent.capabilities
        policy = agent.policy
        if policy.required_capabilities:
            unexpected = sorted(caps - policy.required_capabilities)
            if unexpected:
                findings.append(Finding("CAP001", Severity.HIGH, "Agent exceeds declared capability budget", f"Agent '{agent.name}' has capabilities not declared as required.", "Remove unnecessary tools/capabilities or update the capability budget only after security review.", layer=2, location=agent.location, agent=agent.name, evidence=["required=" + ",".join(sorted(policy.required_capabilities)), "unexpected=" + ",".join(unexpected)]))
        denied = sorted(caps & policy.denied_capabilities)
        if denied:
            findings.append(Finding("CAP002", Severity.CRITICAL, "Agent has explicitly forbidden capability", f"Agent '{agent.name}' exposes capabilities denied by policy.", "Remove the tool/capability or change the policy through an explicit risk-acceptance process.", layer=2, location=agent.location, agent=agent.name, evidence=["denied=" + ",".join(denied)]))
        privileged = sorted(caps & PRIVILEGED_CAPABILITIES)
        max_priv = policy.max_privileged_capabilities if policy.max_privileged_capabilities is not None else 3
        if len(privileged) > max_priv:
            findings.append(Finding("CAP003", Severity.HIGH, "High aggregate agent authority", f"Agent '{agent.name}' combines {len(privileged)} privileged capability classes.", "Split duties across narrower agents/tools or introduce explicit control boundaries and approvals.", layer=2, location=agent.location, agent=agent.name, evidence=["privileged=" + ",".join(privileged), f"threshold={max_priv}"]))
        if "process.execute" in caps and "network.external" in caps:
            findings.append(Finding("CAP004", Severity.HIGH, "Command execution combined with external network access", f"Agent '{agent.name}' can execute processes and reach external networks.", "Sandbox execution and restrict egress to an explicit destination allowlist.", layer=2, location=agent.location, agent=agent.name, evidence=["process.execute", "network.external"]))
        agent_authorities = [
            item for item in authority_relationships if item.agent == agent.name
        ]
        read_authorities = [
            item for item in agent_authorities if "data.read" in item.capabilities
        ]
        write_authorities = [
            item
            for item in agent_authorities
            if {"data.write", "destructive.write"} & set(item.capabilities)
        ]
        authority_confirms_read_write = bool(read_authorities and write_authorities)
        legacy_read_write = (
            "data.read" in caps
            and ("data.write" in caps or "destructive.write" in caps)
        )
        if authority_confirms_read_write or legacy_read_write:
            linked = sorted(
                {
                    item.relationship_id
                    for item in [*read_authorities, *write_authorities]
                }
            )
            evidence = ["data.read", "data.write/destructive.write"]
            evidence.extend(f"authority_relationship={item}" for item in linked)
            findings.append(
                Finding(
                    "CAP005",
                    Severity.MEDIUM,
                    "Combined read and write authority",
                    f"Agent '{agent.name}' can both read and modify data.",
                    "Apply resource-level least privilege; separate read-only analysis from mutation where practical.",
                    layer=2,
                    location=agent.location,
                    agent=agent.name,
                    evidence=evidence,
                    authority_relationship_id=(linked[0] if len(linked) == 1 else None),
                )
            )
        for required_approval in sorted(policy.require_approval_for & caps):
            relevant = [t for t in agent.tools if required_approval in t.capabilities]
            if relevant and any(t.approval is not True for t in relevant):
                findings.append(Finding("CAP006", Severity.HIGH, "Policy-required approval is not configured on every tool", f"Agent '{agent.name}' uses '{required_approval}' without approval on every relevant tool.", "Enforce approval on each tool providing this capability.", layer=2, location=agent.location, agent=agent.name, evidence=[f"capability={required_approval}"]))

    # Layer 3: identity and permissions.
    seen_identity_keys: set[tuple[str, str, str | None]] = set()
    linked_identities = {
        (identity.name, identity.provider)
        for agent in graph.agents
        for identity in agent.identities
    }
    for identity in graph.identities:
        if (identity.name, identity.provider) in linked_identities:
            continue
        key = (identity.name, identity.provider, None)
        if key not in seen_identity_keys:
            seen_identity_keys.add(key)
            findings.extend(_identity_findings(identity))
    for agent in graph.agents:
        for identity in agent.identities:
            key = (identity.name, identity.provider, agent.name)
            if key not in seen_identity_keys:
                seen_identity_keys.add(key)
                findings.extend(_identity_findings(identity, agent.name))

    # Layer 4: data/resource/network reachability.
    for agent in graph.agents:
        sensitive = agent.sensitive_data_sources
        resources = agent.effective_resources
        destinations = agent.effective_destinations
        outbound_caps = bool({"network.external", "external.write"} & agent.capabilities)

        broad_resources = [r for r in resources if resource_is_broad(r.selector)]
        if broad_resources:
            findings.append(Finding("DATA001", Severity.HIGH, "Broad resource scope", f"Agent '{agent.name}' has broad resource selectors.", "Constrain files, data stores, buckets or records to the smallest resource scope required.", layer=4, location=agent.location, agent=agent.name, evidence=["resources=" + ",".join(r.selector for r in broad_resources)]))

        explicit_broad_destinations = [
            d for d in destinations if _destination_is_broad_or_dynamic(d)
        ]
        outbound_tools = [
            tool
            for tool in agent.tools
            if {"network.external", "external.write"} & tool.capabilities
        ]
        unconstrained_outbound_tools = [
            tool
            for tool in outbound_tools
            if tool.metadata.get("network_scope") != "fixed_managed_service"
        ]
        if explicit_broad_destinations:
            findings.append(Finding("NET001", Severity.HIGH, "Outbound reachability lacks a detected restriction", f"Agent '{agent.name}' has broad destinations or no detected restriction for a possible outbound destination.", "Use egress allowlists/proxies and restrict outbound connectivity to required hosts.", layer=4, location=agent.location, agent=agent.name, evidence=["destinations=" + ",".join(d.target for d in explicit_broad_destinations)]))
        else:
            outbound_authorities = [
                item
                for item in authority_relationships
                if item.agent == agent.name
                and {"network.external", "external.write"} & set(item.capabilities)
            ]
            unresolved_destination_authorities = [
                item
                for item in outbound_authorities
                if item.dimensions.get("destinations") != "resolved"
                and item.semantics.get("network")
                not in {"fixed_managed_service", "fixed_provider_network"}
            ]
            authority_destination_gap = bool(unresolved_destination_authorities)
            legacy_destination_gap = (
                outbound_caps and not destinations and unconstrained_outbound_tools
            )
            if authority_destination_gap or (
                not outbound_authorities and legacy_destination_gap
            ):
                linked = sorted(
                    item.relationship_id
                    for item in unresolved_destination_authorities
                )
                evidence = [
                    "capabilities="
                    + ",".join(
                        sorted(
                            agent.capabilities
                            & {"network.external", "external.write"}
                        )
                    )
                ]
                evidence.extend(
                    f"authority_relationship={item}" for item in linked
                )
                findings.append(
                    Finding(
                        "NET002",
                        Severity.MEDIUM,
                        "Outbound capability has no destination constraint",
                        f"Agent '{agent.name}' has external network/write capability but no explicit destination allowlist was detected.",
                        "Declare and enforce permitted destinations for outbound tools.",
                        layer=4,
                        location=agent.location,
                        agent=agent.name,
                        evidence=evidence,
                        authority_relationship_id=(
                            linked[0] if len(linked) == 1 else None
                        ),
                    )
                )

        if policy := agent.policy:
            if policy.allowed_resources:
                outside = sorted({r.selector for r in resources if not matches_any(r.selector, policy.allowed_resources)})
                if outside:
                    findings.append(Finding("DATA002", Severity.HIGH, "Resource access exceeds declared allowlist", f"Agent '{agent.name}' can reach resources outside its declared allowlist.", "Narrow tool/resource configuration to the declared resource boundary.", layer=4, location=agent.location, agent=agent.name, evidence=["outside=" + ",".join(outside)]))
            if policy.allowed_destinations:
                outside_dest = sorted({d.target for d in destinations if not matches_any(d.target, policy.allowed_destinations)})
                if outside_dest:
                    findings.append(Finding("NET003", Severity.HIGH, "Network destination exceeds declared allowlist", f"Agent '{agent.name}' can reach destinations outside its declared network allowlist.", "Restrict tool/MCP egress to the approved destination set.", layer=4, location=agent.location, agent=agent.name, evidence=["outside=" + ",".join(outside_dest)]))

        if sensitive and outbound_caps:
            outbound_tools = [t for t in agent.tools if {"network.external", "external.write"} & t.capabilities]
            if outbound_tools and any(t.approval is not True for t in outbound_tools):
                findings.append(Finding("AGT010", Severity.CRITICAL, "Potential sensitive-data exfiltration path", f"Agent '{agent.name}' combines sensitive-data access and outbound capability without an approval requirement detected on every outbound tool.", "Restrict outbound destinations, reduce data scope, or require human approval before sensitive information can leave the trust boundary.", layer=4, location=agent.location, agent=agent.name, evidence=["sensitive=" + ",".join(d.name for d in sensitive), "outbound=" + ",".join(t.name for t in outbound_tools)]))

        if sensitive and (
            explicit_broad_destinations
            or (outbound_caps and not destinations and unconstrained_outbound_tools)
        ):
            findings.append(Finding("DATA003", Severity.CRITICAL, "Sensitive data has broad egress reachability", f"Agent '{agent.name}' combines sensitive data access with broadly constrained or unconstrained outbound capability.", "Restrict outbound destinations and require approval/DLP controls before sensitive data can leave the trust boundary.", layer=4, location=agent.location, agent=agent.name, evidence=["sensitive=" + ",".join(d.name for d in sensitive)]))

    # Layer 5: attack paths generated by the graph analyser.
    for path in graph.attack_paths:
        findings.append(
            Finding(
                rule_id=path.path_id,
                layer=5,
                severity=path.severity,
                title=path.title,
                message=path.rationale,
                recommendation="Break the attack path by reducing privilege/reachability, validating untrusted input, sandboxing execution, or enforcing approval at the privileged action boundary.",
                location=path.location,
                agent=path.agent,
                evidence=[" -> ".join(path.nodes)] + (
                    [f"flow_id={path.metadata['flow_id']}"]
                    if path.metadata.get("flow_id") else []
                ),
            )
        )

    return _dedupe(findings)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple] = set()
    result: list[Finding] = []
    for finding in findings:
        loc = finding.location
        key = (
            finding.rule_id,
            finding.agent,
            str(loc.path) if loc else None,
            loc.line if loc else None,
            tuple(finding.evidence),
        )
        if key not in seen:
            seen.add(key)
            result.append(finding)
    return sorted(result, key=lambda f: (-int(f.severity), f.layer, f.rule_id, f.agent or ""))
