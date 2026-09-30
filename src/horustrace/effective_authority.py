"""Generic effective-authority reconstruction for normalized agent relationships.

The resolver is intentionally conservative: it emits only authority dimensions backed
by static evidence and leaves unknown dimensions explicit. Runtime effectiveness is
always reported as not_verified.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from horustrace.models import Agent, Graph, Identity, MCPServer, ResourceScope, Tool

EFFECTIVE_AUTHORITY_SCHEMA_VERSION = 1


def _agent_instance_key(agent: Agent) -> str:
    configured = agent.metadata.get("instance_key")
    if isinstance(configured, str) and configured:
        return configured
    if agent.location is not None:
        return (
            f"{agent.name}:{agent.location.path.resolve()}:"
            f"{agent.location.line}:{agent.location.column}"
        )
    return agent.name


def _stable_relationship_id(
    agent: str,
    target_kind: str,
    target_name: str,
) -> str:
    payload = f"{agent}\0{target_kind}\0{target_name}"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]
    return f"authority-v1:{digest}"


def _location(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    return {
        "path": str(value.path),
        "line": value.line,
        "column": value.column,
    }


def _resource(resource: ResourceScope) -> dict[str, Any]:
    return {
        "kind": resource.kind,
        "selector": resource.selector,
        "access": sorted(resource.access),
        "classification": resource.classification,
        "metadata": dict(resource.metadata),
        "location": _location(resource.location),
    }


def _identity(graph: Graph, agent: Agent, name: str | None) -> Identity | None:
    if not name:
        return None
    for identity in [*agent.identities, *graph.identities]:
        if identity.name == name:
            return identity
    return None


def _adg_evidence(
    graph: Graph,
    *,
    agent: str,
    target_kind: str,
    target_name: str,
) -> list[dict[str, Any]]:
    if graph.adg is None:
        return []
    result: list[dict[str, Any]] = []
    nodes = {node.node_id: node for node in graph.adg.nodes}
    for edge in graph.adg.edges:
        if edge.kind != "INVOKES":
            continue
        source = nodes.get(edge.source)
        target = nodes.get(edge.target)
        if source is None or target is None:
            continue
        if source.kind != "agent" or source.name != agent:
            continue
        expected_kind = "tool" if target_kind == "tool" else "mcp_server"
        if target.kind != expected_kind:
            continue
        if target_kind == "tool":
            matched = target.attributes.get("tool_name") == target_name
        else:
            matched = target.name.endswith(f":{target_name}")
        if not matched:
            continue
        result.append(
            {
                "edge_id": edge.edge_id,
                "kind": edge.kind,
                "source": edge.source,
                "target": edge.target,
                "location": edge.location,
            }
        )
    return sorted(result, key=lambda item: item["edge_id"])


def _resolution_status(unresolved: list[str], dimensions: dict[str, str]) -> str:
    if not unresolved:
        return "fully_resolved"
    resolved = sum(value == "resolved" for value in dimensions.values())
    return "partially_resolved" if resolved else "unknown"


@dataclass(frozen=True, slots=True)
class EffectiveAuthorityRelationship:
    relationship_id: str
    agent: str
    agent_instance_key: str
    target_kind: str
    target_name: str
    capabilities: tuple[str, ...]
    identity: dict[str, Any] | None
    approval: dict[str, Any]
    tool_scope: dict[str, Any] | None
    resources: tuple[dict[str, Any], ...]
    destinations: tuple[dict[str, Any], ...]
    semantics: dict[str, Any]
    dimensions: dict[str, str]
    unresolved: tuple[str, ...]
    evidence: tuple[dict[str, Any], ...]
    location: dict[str, Any] | None

    @property
    def resolution(self) -> str:
        return _resolution_status(list(self.unresolved), self.dimensions)

    def as_dict(self) -> dict[str, Any]:
        return {
            "relationship_id": self.relationship_id,
            "agent": self.agent,
            "target": {
                "kind": self.target_kind,
                "name": self.target_name,
            },
            "capabilities": list(self.capabilities),
            "identity": self.identity,
            "approval": self.approval,
            "tool_scope": self.tool_scope,
            "resources": list(self.resources),
            "destinations": list(self.destinations),
            "semantics": self.semantics,
            "resolution": self.resolution,
            "dimensions": self.dimensions,
            "unresolved": list(self.unresolved),
            "evidence": list(self.evidence),
            "runtime_effectiveness": "not_verified",
            "location": self.location,
        }


def _tool_relationship(
    graph: Graph,
    agent: Agent,
    tool: Tool,
) -> EffectiveAuthorityRelationship:
    identity = _identity(graph, agent, tool.identity)
    callbacks = agent.metadata.get("callbacks") or {}
    inherited_control = bool(agent.metadata.get("approval_plugin")) or bool(
        callbacks.get("before_tool_callback")
    )
    approval_resolved = (
        tool.approval is not None
        or tool.guardrails
        or inherited_control
    )
    unresolved: list[str] = []
    dimensions = {
        "target": "resolved",
        "capabilities": "resolved" if tool.capabilities else "unknown",
        "identity": "resolved" if identity is not None else "unknown",
        "approval": "resolved" if approval_resolved else "unknown",
        "resources": "resolved" if tool.resources else "unknown",
        "destinations": "resolved" if tool.destinations else "unknown",
    }
    if not tool.capabilities:
        unresolved.append("capabilities")
    if identity is None:
        unresolved.append("identity")
    if not approval_resolved:
        unresolved.append("approval")
    if not tool.resources:
        unresolved.append("resources")
    if not tool.destinations:
        unresolved.append("destinations")

    identity_doc = None
    if identity is not None:
        identity_doc = {
            "name": identity.name,
            "provider": identity.provider,
            "credential_source": identity.credential_source,
            "roles": sorted(identity.roles),
            "permissions": sorted(identity.permissions),
            "oauth_scopes": sorted(identity.oauth_scopes),
            "resource_scope": identity.resource_scope,
        }
        if identity.credential_source is None:
            unresolved.append("credential_source")
            dimensions["identity"] = "partially_resolved"

    destinations = tuple(
        {
            "target": destination.target,
            "direction": destination.direction,
            "restricted": destination.restricted,
            "metadata": dict(destination.metadata),
            "location": _location(destination.location),
        }
        for destination in tool.destinations
    )

    return EffectiveAuthorityRelationship(
        relationship_id=_stable_relationship_id(agent.name, "tool", tool.name),
        agent=agent.name,
        agent_instance_key=_agent_instance_key(agent),
        target_kind="tool",
        target_name=tool.name,
        capabilities=tuple(sorted(tool.capabilities)),
        identity=identity_doc,
        approval={
            "required": tool.approval,
            "guardrails": tool.guardrails,
            "inherited_control": inherited_control,
            "mechanism": (
                tool.metadata.get("approval_mechanism")
                or (
                    "agent_before_tool_control"
                    if inherited_control
                    else None
                )
            ),
        },
        tool_scope=None,
        resources=tuple(_resource(resource) for resource in tool.resources),
        destinations=destinations,
        semantics={
            "binding_origin": (
                tool.metadata.get("binding_origin")
                or tool.metadata.get("authority_binding_basis")
                or tool.metadata.get("source")
            ),
            "delegate_target": tool.metadata.get("delegate_target"),
            "mutation": tool.metadata.get("mutation_semantics"),
            "network": (
                tool.metadata.get("network_semantics")
                or tool.metadata.get("network_scope")
            ),
            "sensitive_write_domain": tool.metadata.get("sensitive_write_domain"),
            "required_authority": {
                "provider": tool.metadata.get("required_authority_provider"),
                "roles": list(tool.metadata.get("required_roles") or []),
                "permissions": list(
                    tool.metadata.get("required_permissions") or []
                ),
                "roles_complete": (
                    tool.metadata.get("required_roles_complete") is True
                ),
                "permissions_complete": (
                    tool.metadata.get("required_permissions_complete") is True
                ),
                "evidence": list(
                    tool.metadata.get("required_role_evidence") or []
                ),
            },
        },
        dimensions=dimensions,
        unresolved=tuple(sorted(set(unresolved))),
        evidence=tuple(
            _adg_evidence(
                graph,
                agent=agent.name,
                target_kind="tool",
                target_name=tool.name,
            )
        ),
        location=_location(tool.location),
    )


def _mcp_tool_scope(server: MCPServer) -> tuple[dict[str, Any], list[str], str]:
    unresolved: list[str] = []
    if server.allowed_tools:
        scope = "explicit_allowlist"
        status = "resolved"
    elif server.denied_tools:
        scope = "denylist_only"
        status = "partially_resolved"
        unresolved.append("tool_catalogue")
    elif server.metadata.get("dynamic_tool_filter"):
        scope = "dynamic_filter"
        status = "partially_resolved"
        unresolved.extend(["tool_catalogue", "tool_filter"])
    elif server.metadata.get("discovered_tools"):
        scope = "unrestricted_or_unknown"
        status = "partially_resolved"
        unresolved.append("tool_filter")
    else:
        scope = "unrestricted_or_unknown"
        status = "unknown"
        unresolved.append("tool_catalogue")
    result = {
        "scope": scope,
        "allowed": list(server.allowed_tools),
        "denied": list(server.denied_tools),
        "catalogue_known": bool(
            server.allowed_tools or server.metadata.get("discovered_tools")
        ),
    }
    discovered = list(server.metadata.get("discovered_tools") or [])
    if discovered:
        result["discovered"] = discovered
    return result, unresolved, status


def _mcp_relationship(
    graph: Graph,
    agent: Agent,
    server: MCPServer,
) -> EffectiveAuthorityRelationship:
    identity = _identity(graph, agent, server.identity)
    tool_scope, unresolved, tool_scope_status = _mcp_tool_scope(server)
    operator_configured_remote = (
        server.metadata.get("dynamic_mcp_endpoint_basis")
        == "operator_configuration"
    )
    dynamic_remote = bool(
        server.metadata.get("dynamic_mcp_endpoint")
        and server.transport in {"http", "sse", "streamable-http", "streamable_http"}
    )
    dimensions = {
        "target": "resolved",
        "capabilities": "resolved",
        "identity": "resolved" if identity is not None else "unknown",
        "approval": "resolved" if server.approval is not None or server.guardrails else "unknown",
        "resources": "resolved" if server.resources else "unknown",
        "destinations": (
            "resolved"
            if server.url or server.command or operator_configured_remote
            else "unknown"
        ),
        "tool_scope": tool_scope_status,
    }
    if identity is None:
        unresolved.append("identity")
    if server.approval is None and not server.guardrails:
        unresolved.append("approval")
    if not server.resources:
        unresolved.append("resources")
    if not server.url and not server.command and not operator_configured_remote:
        unresolved.append("destinations")

    identity_doc = None
    if identity is not None:
        identity_doc = {
            "name": identity.name,
            "provider": identity.provider,
            "credential_source": identity.credential_source,
            "roles": sorted(identity.roles),
            "permissions": sorted(identity.permissions),
            "oauth_scopes": sorted(identity.oauth_scopes),
            "resource_scope": identity.resource_scope,
        }
        if identity.credential_source is None:
            unresolved.append("credential_source")
            dimensions["identity"] = "partially_resolved"

    destinations: list[dict[str, Any]] = []
    if server.url:
        destinations.append(
            {
                "target": server.url,
                "direction": "outbound",
                "restricted": True,
                "kind": "fixed_remote_endpoint",
                "location": _location(server.location),
            }
        )
    elif operator_configured_remote:
        destinations.append(
            {
                "target": "<operator-configured-mcp>",
                "direction": "outbound",
                "restricted": True,
                "kind": "operator_configured_remote_endpoint",
                "configuration_source": server.metadata.get(
                    "configuration_source"
                ),
                "location": _location(server.location),
            }
        )
    elif server.command:
        destinations.append(
            {
                "target": server.command,
                "direction": "local",
                "restricted": True,
                "kind": "fixed_local_command",
                "args": list(server.args),
                "location": _location(server.location),
            }
        )

    base_capabilities = (
        {"mcp.remote", "network.external"}
        if server.url or dynamic_remote
        else {"mcp.local"}
    )
    capabilities = tuple(
        sorted(
            base_capabilities
            | set(server.metadata.get("discovered_tool_capabilities") or [])
        )
    )

    return EffectiveAuthorityRelationship(
        relationship_id=_stable_relationship_id(
            agent.name, "mcp_server", server.name
        ),
        agent=agent.name,
        agent_instance_key=_agent_instance_key(agent),
        target_kind="mcp_server",
        target_name=server.name,
        capabilities=capabilities,
        identity=identity_doc,
        approval={
            "required": server.approval,
            "guardrails": server.guardrails,
            "mechanism": server.metadata.get("approval_mechanism"),
        },
        tool_scope=tool_scope,
        resources=tuple(_resource(resource) for resource in server.resources),
        destinations=tuple(destinations),
        semantics={
            "binding_origin": (
                server.metadata.get("binding_origin")
                or "framework_agent_configuration"
            ),
            "transport": server.transport,
            "network": server.metadata.get("network_scope"),
            "dynamic_remote_mcp_catalogue": server.metadata.get(
                "dynamic_remote_mcp_catalogue"
            ),
            "per_call_approval": server.metadata.get("per_call_approval"),
            "authentication_state": (
                "authenticated"
                if server.authenticated is True
                else "unauthenticated"
                if server.authenticated is False
                else "unknown"
            ),
            "authentication_mechanism": (
                server.metadata.get("auth_mechanism") or "unknown"
            ),
            "discovered_tools": list(
                server.metadata.get("discovered_tools") or []
            ),
        },
        dimensions=dimensions,
        unresolved=tuple(sorted(set(unresolved))),
        evidence=tuple(
            _adg_evidence(
                graph,
                agent=agent.name,
                target_kind="mcp_server",
                target_name=server.name,
            )
        ),
        location=_location(server.location),
    )


def effective_authority_relationships(
    graph: Graph,
) -> list[EffectiveAuthorityRelationship]:
    result: list[EffectiveAuthorityRelationship] = []
    for agent in graph.agents:
        for tool in agent.tools:
            if tool.metadata.get("authority_binding") in {
                "workflow_projection",
                "delegation_projection",
            }:
                continue
            result.append(_tool_relationship(graph, agent, tool))
        for server in agent.mcp_servers:
            result.append(_mcp_relationship(graph, agent, server))
    return sorted(
        result,
        key=lambda item: (
            item.agent,
            item.target_kind,
            item.target_name,
            item.relationship_id,
        ),
    )


def effective_authority_report(graph: Graph) -> dict[str, Any]:
    relationships = effective_authority_relationships(graph)
    resolution_counts = {
        status: sum(item.resolution == status for item in relationships)
        for status in ("fully_resolved", "partially_resolved", "unknown")
    }
    target_counts = {
        kind: sum(item.target_kind == kind for item in relationships)
        for kind in ("tool", "mcp_server")
    }
    return {
        "schema_version": EFFECTIVE_AUTHORITY_SCHEMA_VERSION,
        "runtime_effectiveness": "not_verified",
        "summary": {
            "relationships": len(relationships),
            "tool_relationships": target_counts["tool"],
            "mcp_relationships": target_counts["mcp_server"],
            "fully_resolved_relationships": resolution_counts["fully_resolved"],
            "partially_resolved_relationships": resolution_counts["partially_resolved"],
            "unknown_relationships": resolution_counts["unknown"],
            "relationships_with_identity": sum(
                item.identity is not None for item in relationships
            ),
            "relationships_with_approval_evidence": sum(
                item.dimensions.get("approval") == "resolved"
                for item in relationships
            ),
            "relationships_with_destination_evidence": sum(
                item.dimensions.get("destinations") == "resolved"
                for item in relationships
            ),
            "relationships_with_resource_evidence": sum(
                item.dimensions.get("resources") == "resolved"
                for item in relationships
            ),
        },
        "relationships": [item.as_dict() for item in relationships],
    }


def render_effective_authority_console(graph: Graph, root: Path) -> str:
    report = effective_authority_report(graph)
    summary = report["summary"]
    lines = [
        "HorusTrace Effective Authority",
        "=" * 30,
        f"Target:                       {root}",
        f"Relationships:                {summary['relationships']}",
        f"Tool relationships:           {summary['tool_relationships']}",
        f"MCP relationships:            {summary['mcp_relationships']}",
        f"Fully resolved:               {summary['fully_resolved_relationships']}",
        f"Partially resolved:           {summary['partially_resolved_relationships']}",
        f"Unknown:                      {summary['unknown_relationships']}",
        f"Identity evidence:            {summary['relationships_with_identity']}",
        f"Approval evidence:            {summary['relationships_with_approval_evidence']}",
        f"Destination evidence:         {summary['relationships_with_destination_evidence']}",
        f"Resource evidence:            {summary['relationships_with_resource_evidence']}",
        "Runtime effectiveness:          NOT VERIFIED",
        "",
    ]
    if not report["relationships"]:
        lines.append("No effective agent authority relationships detected.")
        return "\n".join(lines)

    for item in report["relationships"]:
        target = item["target"]
        lines.append(
            f"{item['agent']} -> {target['kind']}:{target['name']} "
            f"[{item['resolution'].upper()}]"
        )
        capabilities = ", ".join(item["capabilities"]) or "unknown"
        lines.append(f"  capabilities: {capabilities}")
        if item["identity"]:
            identity = item["identity"]
            credential = identity["credential_source"] or "unknown"
            lines.append(
                f"  identity: {identity['name']} ({identity['provider']}); "
                f"credential={credential}"
            )
        else:
            lines.append("  identity: unknown")
        approval = item["approval"]
        lines.append(
            "  approval: "
            f"required={approval['required']}; guardrails={approval['guardrails']}; "
            f"mechanism={approval['mechanism'] or 'unknown'}"
        )
        if item["tool_scope"]:
            scope = item["tool_scope"]
            lines.append(
                f"  tool scope: {scope['scope']}; "
                f"allowed={', '.join(scope['allowed']) or 'unknown'}; "
                f"denied={', '.join(scope['denied']) or 'none'}"
            )
        if item["resources"]:
            resources = ", ".join(
                f"{resource['kind']}:{resource['selector']}"
                for resource in item["resources"]
            )
            lines.append(f"  resources: {resources}")
        else:
            lines.append("  resources: unknown")
        if item["destinations"]:
            destinations = ", ".join(
                destination["target"] for destination in item["destinations"]
            )
            lines.append(f"  destinations: {destinations}")
        else:
            lines.append("  destinations: unknown")
        lines.append(
            "  unresolved: "
            + (", ".join(item["unresolved"]) if item["unresolved"] else "none")
        )
        lines.append(
            f"  ADG invoke evidence: {len(item['evidence'])} edge(s)"
        )
        lines.append("")

    return "\n".join(lines).rstrip()
