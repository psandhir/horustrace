"""Deterministic framework-agnostic Agent Dependency Graph (ADG)."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from horustrace.inventory_semantics import (
    data_resource_attributes,
    model_inventory_attributes,
    network_destination_attributes,
)
from horustrace.limits import MAX_ADG_EDGES, MAX_ADG_NODES, ScanLimitError
from horustrace.models import Agent, FlowPath, Graph, ResourceScope, SourceLocation, Tool

ADG_SCHEMA_VERSION = 1


def _relative(location: SourceLocation | None, root: Path) -> str | None:
    if location is None:
        return None
    try:
        return location.path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return location.path.name


def _location(location: SourceLocation | None, root: Path) -> dict[str, Any] | None:
    path = _relative(location, root)
    if path is None or location is None:
        return None
    return {"path": path, "line": location.line, "column": location.column}


def _stable_id(kind: str, name: str, location: SourceLocation | None, root: Path) -> str:
    payload = "\0".join((kind, name, _relative(location, root) or ""))
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]
    return f"adg-v1:{digest}"


def _collision_id(
    kind: str,
    name: str,
    location: SourceLocation | None,
    root: Path,
) -> str:
    payload = "\0".join(
        (
            kind,
            name,
            _relative(location, root) or "",
            str(location.line if location else 0),
            str(location.column if location else 0),
        )
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]
    return f"adg-v1:{digest}"


def _edge_id(kind: str, source: str, target: str, attributes: dict[str, Any]) -> str:
    qualifier = json.dumps(attributes, sort_keys=True, separators=(",", ":"), default=str)
    payload = f"{kind}\0{source}\0{target}\0{qualifier}"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]
    return f"edge-v1:{digest}"


def _counts(values: list[str]) -> dict[str, int]:
    result: dict[str, int] = {}
    for value in values:
        result[value] = result.get(value, 0) + 1
    return dict(sorted(result.items()))


def _tool_topology_kind(tool: Tool) -> str:
    """Return the inventory node class for a bound authority object."""
    if tool.kind == "delegated_agent":
        return "delegation"
    if (
        tool.metadata.get("dynamic_authority") is True
        and tool.metadata.get("authority_dimension") == "capabilities"
    ):
        return "capability"
    return "tool"


@dataclass(frozen=True, slots=True)
class ADGNode:
    node_id: str
    kind: str
    name: str
    framework: str | None = None
    location: dict[str, Any] | None = None
    attributes: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.node_id,
            "kind": self.kind,
            "name": self.name,
            "framework": self.framework,
            "location": self.location,
            "attributes": self.attributes,
        }


@dataclass(frozen=True, slots=True)
class ADGEdge:
    edge_id: str
    kind: str
    source: str
    target: str
    location: dict[str, Any] | None = None
    attributes: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.edge_id,
            "kind": self.kind,
            "source": self.source,
            "target": self.target,
            "location": self.location,
            "attributes": self.attributes,
        }


@dataclass(slots=True)
class AgentDependencyGraph:
    nodes: list[ADGNode] = field(default_factory=list)
    edges: list[ADGEdge] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        nodes = sorted((node.as_dict() for node in self.nodes), key=lambda item: item["id"])
        edges = sorted((edge.as_dict() for edge in self.edges), key=lambda item: item["id"])
        return {
            "schema_version": ADG_SCHEMA_VERSION,
            "root": ".",
            "summary": {
                "nodes": len(nodes),
                "edges": len(edges),
                "node_kinds": _counts([item["kind"] for item in nodes]),
                "edge_kinds": _counts([item["kind"] for item in edges]),
            },
            "nodes": nodes,
            "edges": edges,
        }

    def canonical_digest(self) -> str:
        payload = json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


class _Builder:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.nodes: dict[str, ADGNode] = {}
        self.edges: dict[str, ADGEdge] = {}

    def node(
        self,
        kind: str,
        name: str,
        *,
        location: SourceLocation | None = None,
        framework: str | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> str:
        node_id = _stable_id(kind, name, location, self.root)
        existing = self.nodes.get(node_id)
        if existing is not None:
            incoming_location = _location(location, self.root)
            if existing.location == incoming_location:
                return node_id
            # Preserve stable IDs for the common case while keeping distinct
            # same-named declarations in one source file visible to topology.
            node_id = _collision_id(kind, name, location, self.root)
            if node_id in self.nodes:
                return node_id
        if len(self.nodes) >= MAX_ADG_NODES:
            raise ScanLimitError("Agent Dependency Graph exceeds the configured node limit")
        clean = {key: value for key, value in (attributes or {}).items() if value is not None}
        self.nodes[node_id] = ADGNode(
            node_id=node_id,
            kind=kind,
            name=name,
            framework=framework,
            location=_location(location, self.root),
            attributes=clean,
        )
        return node_id

    def edge(
        self,
        kind: str,
        source: str,
        target: str,
        *,
        location: SourceLocation | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> None:
        clean = {key: value for key, value in (attributes or {}).items() if value is not None}
        edge_id = _edge_id(kind, source, target, clean)
        if edge_id in self.edges:
            return
        if len(self.edges) >= MAX_ADG_EDGES:
            raise ScanLimitError("Agent Dependency Graph exceeds the configured edge limit")
        self.edges[edge_id] = ADGEdge(
            edge_id=edge_id,
            kind=kind,
            source=source,
            target=target,
            location=_location(location, self.root),
            attributes=clean,
        )


def _prompt_attributes(text: str) -> dict[str, Any]:
    return {
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "length": len(text),
        "content_included": False,
    }


def _framework(metadata: dict[str, Any]) -> str:
    return str(metadata.get("framework") or "generic")


def _add_flow_edges(builder: _Builder, flow: FlowPath) -> None:
    previous: str | None = None
    for index, step in enumerate(flow.steps):
        node_id = builder.node(
            "flow_step",
            f"{flow.flow_id}:{index}:{step.label}",
            location=step.location,
            attributes={"step_kind": step.kind, "label": step.label},
        )
        if previous is not None:
            builder.edge(
                "DATA_FLOWS_TO",
                previous,
                node_id,
                location=step.location,
                attributes={"flow_id": flow.flow_id, "basis": flow.basis},
            )
        previous = node_id


def _workflow_adg_node_id(
    builder: _Builder,
    agent: Agent,
    source_id: str,
    agent_ids_by_name: dict[str, list[str]],
    workflow_node_ids: dict[str, str],
    name: str,
) -> str:
    if name == "START":
        return source_id
    candidates = agent_ids_by_name.get(name, [])
    if len(candidates) == 1:
        return candidates[0]
    existing = workflow_node_ids.get(name)
    if existing is not None:
        return existing
    node_id = builder.node(
        "workflow_node",
        f"{agent.name}:{name}",
        location=agent.location,
        framework=_framework(agent.metadata),
        attributes={
            "workflow": agent.name,
            "node_name": name,
        },
    )
    workflow_node_ids[name] = node_id
    return node_id


def build_adg(graph: Graph, root: Path) -> AgentDependencyGraph:
    """Project the normalized scanner graph into ADG schema version 1."""
    builder = _Builder(root)
    identity_ids: dict[str, str] = {}
    agent_ids: dict[int, str] = {}
    agent_ids_by_name: dict[str, list[str]] = {}
    agent_ids_by_instance: dict[str, str] = {}
    tool_ids: dict[tuple[int, str], str] = {}

    identities = sorted(
        graph.all_identities(),
        key=lambda item: (
            item.name,
            item.provider,
            _relative(item.location, root) or "",
        ),
    )
    for identity in identities:
        identity_id = builder.node(
            "identity",
            identity.name,
            location=identity.location,
            framework=_framework(identity.metadata),
            attributes={
                "provider": identity.provider,
                "roles": sorted(identity.roles),
                "permissions": sorted(identity.permissions),
                "oauth_scopes": sorted(identity.oauth_scopes),
                "credential_source": identity.credential_source,
                "resource_scope": identity.resource_scope,
                "declared_authority": identity.metadata.get("declared_authority"),
            },
        )
        identity_ids.setdefault(identity.name, identity_id)

    def bound_identity_id(
        name: str | None,
        *,
        location: SourceLocation | None,
        framework: str,
    ) -> str | None:
        if not name:
            return None
        identity_id = identity_ids.get(name)
        if identity_id is not None:
            return identity_id
        identity_id = builder.node(
            "identity",
            name,
            location=location,
            framework=framework,
            attributes={
                "provider": "unknown",
                "credential_source": "unknown",
                "resolution": "unresolved_reference",
            },
        )
        identity_ids[name] = identity_id
        return identity_id

    for tool in graph.unbound_tools:
        if tool.metadata.get("topology_visible_unbound") is not True:
            continue
        builder.node(
            _tool_topology_kind(tool),
            tool.name,
            location=tool.location,
            framework=_framework(tool.metadata),
            attributes={
                "tool_name": tool.name,
                "tool_kind": tool.kind,
                "capabilities": sorted(tool.capabilities),
                "unbound": tool.metadata.get("binding_state") != "bound_via_mcp",
                "binding_state": tool.metadata.get("binding_state") or "unbound",
                "discovery_source": tool.metadata.get("discovery_source"),
            },
        )

    for skill in graph.unbound_skills:
        builder.node(
            "skill",
            skill.name,
            location=skill.location,
            framework=_framework(skill.metadata),
            attributes={
                "description": skill.description,
                "source": skill.source,
                "allowed_tools": sorted(skill.allowed_tools),
                "scripts": list(skill.scripts),
                "binding_state": "unbound",
                "has_scripts": skill.metadata.get("has_scripts"),
                "license": skill.metadata.get("license"),
                "compatibility": skill.metadata.get("compatibility"),
                "content_included": False,
            },
        )

    for server in graph.unbound_mcp_servers:
        if server.metadata.get("topology_visible_unbound") is not True:
            continue
        builder.node(
            "mcp_server",
            server.name,
            location=server.location,
            framework=_framework(server.metadata),
            attributes={
                "transport": server.transport,
                "url": server.url,
                "command": server.command,
                "authenticated": server.authenticated,
                "approval": server.approval,
                "allowed_tools": list(server.allowed_tools),
                "denied_tools": list(server.denied_tools),
                "unbound": True,
                "binding_state": server.metadata.get("binding_state") or "unbound",
                "discovery_source": server.metadata.get("discovery_source"),
                "binding_origin": server.metadata.get("binding_origin"),
            },
        )

    for agent in graph.agents:
        framework = _framework(agent.metadata)
        agent_id = builder.node(
            "agent",
            agent.name,
            location=agent.location,
            framework=framework,
            attributes={
                "agent_type": agent.metadata.get("agent_type"),
                "workflow": agent.metadata.get("workflow"),
                "discovery_basis": agent.metadata.get("discovery_basis"),
                "semantic_entity_id": agent.metadata.get("semantic_entity_id"),
                "semantic_entity_kind": agent.metadata.get("semantic_entity_kind"),
            },
        )
        agent_ids[id(agent)] = agent_id
        agent_ids_by_name.setdefault(agent.name, []).append(agent_id)
        instance_key = agent.metadata.get("instance_key")
        if instance_key:
            agent_ids_by_instance[str(instance_key)] = agent_id

        prompt = agent.metadata.get("instruction") or agent.metadata.get("instructions")
        if isinstance(prompt, str) and prompt:
            prompt_id = builder.node(
                "prompt",
                f"{agent.name}:system-prompt",
                location=agent.location,
                framework=framework,
                attributes=_prompt_attributes(prompt),
            )
            builder.edge("USES_PROMPT", agent_id, prompt_id, location=agent.location)

        model = agent.metadata.get("model")
        has_model_evidence = (
            isinstance(model, str)
            and bool(model)
        ) or any(
            agent.metadata.get(key) is not None
            for key in (
                "model_provider",
                "model_reference",
                "model_resolution",
                "model_provenance_limitation",
            )
        )
        if has_model_evidence:
            model_attributes = model_inventory_attributes(agent.metadata)
            model_name = (
                model
                if isinstance(model, str) and model
                else f"{agent.name}:model"
            )
            model_id = builder.node(
                "model",
                model_name,
                location=agent.location,
                framework=framework,
                attributes=model_attributes,
            )
            builder.edge(
                "USES_MODEL",
                agent_id,
                model_id,
                location=agent.location,
                attributes={
                    "model_key": model_attributes["model_key"],
                    "basis": "source_model_configuration",
                },
            )

        for memory in agent.metadata.get("memory") or []:
            if not isinstance(memory, dict):
                continue
            memory_name = str(memory.get("name") or f"{agent.name}:memory")
            memory_id = builder.node(
                "memory",
                memory_name,
                location=agent.location,
                framework=framework,
                attributes={
                    "persistent": memory.get("persistent"),
                    "backend": memory.get("backend"),
                },
            )
            builder.edge("READS_MEMORY", agent_id, memory_id, location=agent.location)
            if memory.get("writable", True):
                builder.edge("WRITES_MEMORY", agent_id, memory_id, location=agent.location)

        for source in agent.inputs:
            input_id = builder.node(
                "input",
                f"{agent.name}:{source.name}",
                location=source.location,
                framework=framework,
                attributes={"trust": source.trust, "input_kind": source.kind},
            )
            builder.edge(
                "RECEIVES_INPUT_FROM",
                agent_id,
                input_id,
                location=source.location,
            )

        for source in agent.data_sources:
            normalized_resource = ResourceScope(
                kind="data",
                selector=source.selector or source.name,
                access={source.capability},
                classification=source.classification,
                location=source.location,
                provenance=list(source.provenance),
            )
            resource_attributes = data_resource_attributes(normalized_resource)
            resource_id = builder.node(
                "data_resource",
                f"{agent.name}:{source.selector or source.name}",
                location=source.location,
                framework=framework,
                attributes=resource_attributes,
            )
            edge_kind = (
                "WRITES_TO"
                if {"data.write", "destructive.write"} & normalized_resource.access
                else "READS_FROM"
            )
            builder.edge(
                edge_kind,
                agent_id,
                resource_id,
                location=source.location,
                attributes={
                    "access": sorted(normalized_resource.access),
                    "resource_key": resource_attributes["resource_key"],
                    "basis": "agent_data_source",
                },
            )

        for identity in agent.identities:
            identity_id = identity_ids.get(identity.name)
            if identity_id is None:
                identity_id = builder.node(
                    "identity",
                    identity.name,
                    location=identity.location,
                    framework=_framework(identity.metadata),
                    attributes={"provider": identity.provider},
                )
                identity_ids[identity.name] = identity_id
            builder.edge("USES_IDENTITY", agent_id, identity_id, location=identity.location)

        for destination in agent.network:
            destination_attributes = network_destination_attributes(
                destination.target,
                restricted=destination.restricted,
                direction=destination.direction,
                metadata=destination.metadata,
            )
            destination_id = builder.node(
                "network_destination",
                destination.target,
                location=destination.location,
                framework=framework,
                attributes=destination_attributes,
            )
            builder.edge(
                "CONNECTS_TO",
                agent_id,
                destination_id,
                location=destination.location,
                attributes={
                    "destination_key": destination_attributes["destination_key"],
                    "basis": "agent_network_destination",
                },
            )

        for skill in agent.skills:
            skill_id = builder.node(
                "skill",
                skill.name,
                location=skill.location,
                framework=_framework(skill.metadata),
                attributes={
                    "description": skill.description,
                    "source": skill.source,
                    "allowed_tools": sorted(skill.allowed_tools),
                    "scripts": list(skill.scripts),
                    "binding_state": skill.metadata.get("binding_state") or "bound",
                    "binding_origin": skill.metadata.get("binding_origin"),
                    "has_scripts": skill.metadata.get("has_scripts"),
                    "license": skill.metadata.get("license"),
                    "compatibility": skill.metadata.get("compatibility"),
                    "content_included": False,
                },
            )
            builder.edge("USES_SKILL", agent_id, skill_id, location=skill.location)

        for server in agent.mcp_servers:
            server_id = builder.node(
                "mcp_server",
                f"{agent.name}:{server.name}",
                location=server.location,
                framework=framework,
                attributes={
                    "transport": server.transport,
                    "url": server.url,
                    "authenticated": server.authenticated,
                    "auth_mechanism": server.metadata.get("auth_mechanism"),
                    "approval": server.approval,
                    "allowed_tools": list(server.allowed_tools),
                    "denied_tools": list(server.denied_tools),
                    "binding_origin": server.metadata.get("binding_origin"),
                    "effective_agent": server.metadata.get("effective_agent"),
                },
            )
            builder.edge("INVOKES", agent_id, server_id, location=server.location)
            server_identity_id = bound_identity_id(
                server.identity,
                location=server.location,
                framework=framework,
            )
            if server.url:
                destination_attributes = network_destination_attributes(
                    server.url,
                    restricted=True,
                    direction="outbound",
                    metadata=server.metadata,
                )
                destination_id = builder.node(
                    "network_destination",
                    server.url,
                    location=server.location,
                    framework=framework,
                    attributes=destination_attributes,
                )
                builder.edge(
                    "CONNECTS_TO",
                    server_id,
                    destination_id,
                    location=server.location,
                    attributes={
                        "destination_key": destination_attributes["destination_key"],
                        "basis": "mcp_server_endpoint",
                    },
                )
                if server_identity_id is not None:
                    builder.edge(
                        "AUTHORIZES_CONNECTION_TO",
                        server_identity_id,
                        destination_id,
                        location=server.location,
                        attributes={
                            "via_kind": "mcp_server",
                            "via": server.name,
                            "basis": "bound_mcp_identity",
                        },
                    )
            if server_identity_id is not None:
                builder.edge(
                    "USES_IDENTITY",
                    server_id,
                    server_identity_id,
                    location=server.location,
                )
            for tool_name in server.allowed_tools:
                scope_id = builder.node(
                    "mcp_tool_scope",
                    f"{agent.name}:{server.name}:allow:{tool_name}",
                    location=server.location,
                    framework=framework,
                    attributes={"tool_name": tool_name, "effect": "allow"},
                )
                builder.edge(
                    "ALLOWS_TOOL",
                    server_id,
                    scope_id,
                    location=server.location,
                )
            for tool_name in server.denied_tools:
                scope_id = builder.node(
                    "mcp_tool_scope",
                    f"{agent.name}:{server.name}:deny:{tool_name}",
                    location=server.location,
                    framework=framework,
                    attributes={"tool_name": tool_name, "effect": "deny"},
                )
                builder.edge(
                    "DENIES_TOOL",
                    server_id,
                    scope_id,
                    location=server.location,
                )

            for resource in server.resources:
                resource_attributes = data_resource_attributes(resource)
                resource_id = builder.node(
                    "data_resource",
                    f"{agent.name}:{server.name}:{resource.kind}:{resource.selector}",
                    location=resource.location or server.location,
                    framework=framework,
                    attributes=resource_attributes,
                )
                if "data.read" in resource.access:
                    builder.edge(
                        "READS_FROM",
                        server_id,
                        resource_id,
                        location=resource.location or server.location,
                        attributes={
                            "access": sorted(resource.access),
                            "resource_key": resource_attributes["resource_key"],
                            "basis": "mcp_resource_scope",
                        },
                    )
                if {"data.write", "destructive.write"} & resource.access:
                    builder.edge(
                        "WRITES_TO",
                        server_id,
                        resource_id,
                        location=resource.location or server.location,
                        attributes={
                            "access": sorted(resource.access),
                            "resource_key": resource_attributes["resource_key"],
                            "basis": "mcp_resource_scope",
                        },
                    )
                if server_identity_id is not None:
                    builder.edge(
                        "AUTHORIZES_ACCESS_TO",
                        server_identity_id,
                        resource_id,
                        location=resource.location or server.location,
                        attributes={
                            "via_kind": "mcp_server",
                            "via": server.name,
                            "access": sorted(resource.access),
                            "basis": "bound_mcp_identity",
                        },
                    )

        for tool in agent.tools:
            tool_id = builder.node(
                _tool_topology_kind(tool),
                f"{agent.name}:{tool.name}",
                location=tool.location,
                framework=_framework(tool.metadata) if tool.metadata else framework,
                attributes={
                    "tool_name": tool.name,
                    "tool_kind": tool.kind,
                    "capabilities": sorted(tool.capabilities),
                    "approval": tool.approval,
                    "guardrails": tool.guardrails,
                    "mutation_semantics": tool.metadata.get("mutation_semantics"),
                    "network_semantics": tool.metadata.get("network_semantics"),
                    "sensitive_write_domain": tool.metadata.get("sensitive_write_domain"),
                    "computer_control_actions": tool.metadata.get("computer_control_actions"),
                    "computer_control_mutating": tool.metadata.get("computer_control_mutating"),
                    "computer_control_readonly": tool.metadata.get("computer_control_readonly"),
                    "computer_control_evidence": tool.metadata.get("computer_control_evidence"),
                    "authority_binding": tool.metadata.get("authority_binding"),
                    "authority_binding_basis": tool.metadata.get("authority_binding_basis"),
                },
            )
            tool_ids[(id(agent), tool.name)] = tool_id
            if tool.metadata.get("authority_binding") not in {
                "workflow_projection",
                "delegation_projection",
            }:
                builder.edge("INVOKES", agent_id, tool_id, location=tool.location)
            tool_identity_id = bound_identity_id(
                tool.identity,
                location=tool.location,
                framework=framework,
            )
            if tool_identity_id is not None:
                builder.edge(
                    "USES_IDENTITY",
                    tool_id,
                    tool_identity_id,
                    location=tool.location,
                )
            for resource in tool.resources:
                resource_attributes = data_resource_attributes(resource)
                resource_id = builder.node(
                    "data_resource",
                    f"{agent.name}:{resource.kind}:{resource.selector}",
                    location=resource.location,
                    framework=framework,
                    attributes=resource_attributes,
                )
                edge_kind = (
                    "WRITES_TO"
                    if {"data.write", "destructive.write"} & resource.access
                    else "READS_FROM"
                )
                builder.edge(
                    edge_kind,
                    tool_id,
                    resource_id,
                    location=resource.location,
                    attributes={
                        "access": sorted(resource.access),
                        "resource_key": resource_attributes["resource_key"],
                        "basis": "tool_resource_scope",
                    },
                )
                if tool_identity_id is not None:
                    builder.edge(
                        "AUTHORIZES_ACCESS_TO",
                        tool_identity_id,
                        resource_id,
                        location=resource.location or tool.location,
                        attributes={
                            "via_kind": "tool",
                            "via": tool.name,
                            "access": sorted(resource.access),
                            "basis": "bound_tool_identity",
                        },
                    )
            for destination in tool.destinations:
                destination_attributes = network_destination_attributes(
                    destination.target,
                    restricted=destination.restricted,
                    direction=destination.direction,
                    metadata=destination.metadata,
                )
                destination_id = builder.node(
                    "network_destination",
                    destination.target,
                    location=destination.location or tool.location,
                    framework=framework,
                    attributes=destination_attributes,
                )
                builder.edge(
                    "CONNECTS_TO",
                    tool_id,
                    destination_id,
                    location=tool.location,
                    attributes={
                        "destination_key": destination_attributes["destination_key"],
                        "basis": "tool_destination",
                    },
                )
                if tool_identity_id is not None:
                    builder.edge(
                        "AUTHORIZES_CONNECTION_TO",
                        tool_identity_id,
                        destination_id,
                        location=destination.location or tool.location,
                        attributes={
                            "via_kind": "tool",
                            "via": tool.name,
                            "basis": "bound_tool_identity",
                        },
                    )
            if "memory" in tool.name.lower():
                memory_id = builder.node(
                    "memory",
                    f"{agent.name}:{tool.name}:memory",
                    location=tool.location,
                    framework=framework,
                    attributes={"inferred": True},
                )
                if "data.read" in tool.capabilities:
                    builder.edge("READS_MEMORY", tool_id, memory_id, location=tool.location)
                if "data.write" in tool.capabilities:
                    builder.edge("WRITES_MEMORY", tool_id, memory_id, location=tool.location)

        policy = agent.policy
        has_policy = bool(
            policy.required_capabilities
            or policy.denied_capabilities
            or policy.allowed_resources
            or policy.allowed_destinations
            or policy.require_approval_for
            or policy.max_privileged_capabilities is not None
        )
        if has_policy:
            policy_id = builder.node(
                "policy_control",
                f"{agent.name}:policy",
                location=agent.location,
                framework=framework,
                attributes={
                    "required_capabilities": sorted(policy.required_capabilities),
                    "denied_capabilities": sorted(policy.denied_capabilities),
                    "allowed_resources": list(policy.allowed_resources),
                    "allowed_destinations": list(policy.allowed_destinations),
                    "require_approval_for": sorted(policy.require_approval_for),
                    "max_privileged_capabilities": policy.max_privileged_capabilities,
                },
            )
            builder.edge("GUARDED_BY", agent_id, policy_id, location=agent.location)

    for agent in graph.agents:
        source_id = agent_ids.get(id(agent))
        if source_id is None:
            continue
        for target_name in agent.metadata.get("delegates_to") or []:
            target_ids = agent_ids_by_name.get(str(target_name), [])
            if len(target_ids) == 1:
                builder.edge(
                    "DELEGATES_TO",
                    source_id,
                    target_ids[0],
                    location=agent.location,
                )

        # ADK 2.x Workflow graphs contain ordinary agents plus function/router
        # nodes. Preserve the graph topology even when a non-agent node has no
        # separate normalized Agent object.
        workflow_node_ids: dict[str, str] = {}

        for workflow_edge in agent.metadata.get("workflow_edges") or []:
            if not isinstance(workflow_edge, dict):
                continue
            source_name = workflow_edge.get("source")
            target_name = workflow_edge.get("target")
            if not isinstance(source_name, str) or not isinstance(target_name, str):
                continue
            builder.edge(
                "WORKFLOW_FLOWS_TO",
                _workflow_adg_node_id(
                    builder,
                    agent,
                    source_id,
                    agent_ids_by_name,
                    workflow_node_ids,
                    source_name,
                ),
                _workflow_adg_node_id(
                    builder,
                    agent,
                    source_id,
                    agent_ids_by_name,
                    workflow_node_ids,
                    target_name,
                ),
                location=agent.location,
                attributes={
                    "workflow": agent.name,
                    "route": workflow_edge.get("route"),
                },
            )

        for control_edge in agent.metadata.get("control_edges") or []:
            if not isinstance(control_edge, (tuple, list)) or len(control_edge) != 2:
                continue
            left = tool_ids.get((id(agent), str(control_edge[0])))
            right = tool_ids.get((id(agent), str(control_edge[1])))
            if left and right:
                builder.edge("CONTROL_FLOWS_TO", left, right, location=agent.location)

        for tool in agent.tools:
            protected_id = tool_ids.get((id(agent), tool.name))
            if not protected_id:
                continue

            gate_name = tool.metadata.get("approval_gated_by")
            if gate_name:
                gate_id = tool_ids.get((id(agent), str(gate_name)))
                if not gate_id:
                    continue
                control_id = builder.node(
                    "approval_control",
                    f"{agent.name}:{gate_name}:approval",
                    location=tool.location or agent.location,
                    framework=_framework(tool.metadata) if tool.metadata else _framework(agent.metadata),
                    attributes={
                        "mechanism": tool.metadata.get("approval_mechanism"),
                        "scope": tool.metadata.get("approval_scope"),
                        "mandatory": tool.metadata.get("approval_mandatory"),
                        "protects_tool": tool.name,
                    },
                )
                builder.edge(
                    "IMPLEMENTS_CONTROL",
                    gate_id,
                    control_id,
                    location=tool.location or agent.location,
                )
                builder.edge(
                    "GUARDED_BY",
                    protected_id,
                    control_id,
                    location=tool.location or agent.location,
                )
                continue

            if tool.approval is not True:
                continue

            mechanism = tool.metadata.get("approval_mechanism") or "explicit_approval"
            control_id = builder.node(
                "approval_control",
                f"{agent.name}:{tool.name}:approval",
                location=tool.location or agent.location,
                framework=_framework(tool.metadata) if tool.metadata else _framework(agent.metadata),
                attributes={
                    "mechanism": mechanism,
                    "scope": tool.metadata.get("approval_scope") or "execution_gate",
                    "mandatory": tool.metadata.get("approval_mandatory", True),
                    "protects_tool": tool.name,
                    "source_level": (
                        "inline"
                        if mechanism == "inline_confirmation"
                        else "tool"
                    ),
                },
            )
            builder.edge(
                "IMPLEMENTS_CONTROL",
                protected_id,
                control_id,
                location=tool.location or agent.location,
            )
            builder.edge(
                "GUARDED_BY",
                protected_id,
                control_id,
                location=tool.location or agent.location,
            )

    agents_by_name: dict[str, list[Agent]] = {}
    for agent in graph.agents:
        agents_by_name.setdefault(agent.name, []).append(agent)
    for parent in graph.agents:
        parent_id = agent_ids.get(id(parent))
        if parent_id is None:
            continue
        pending = [str(name) for name in parent.metadata.get("delegates_to") or []]
        visited = {parent.name}
        while pending:
            child_name = pending.pop()
            if child_name in visited:
                continue
            visited.add(child_name)
            candidates = agents_by_name.get(child_name, [])
            if len(candidates) != 1:
                continue
            child = candidates[0]
            for identity in child.identities:
                identity_id = identity_ids.get(identity.name)
                if identity_id:
                    builder.edge(
                        "CAN_REACH_AUTHORITY",
                        parent_id,
                        identity_id,
                        location=parent.location,
                        attributes={"via_agent": child.name},
                    )
            pending.extend(str(name) for name in child.metadata.get("delegates_to") or [])

    for flow in graph.flow_paths:
        _add_flow_edges(builder, flow)

    return AgentDependencyGraph(
        nodes=list(builder.nodes.values()),
        edges=list(builder.edges.values()),
    )
