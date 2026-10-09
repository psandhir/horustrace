"""Generic effective-authority reconstruction for normalized agent relationships.

The resolver is intentionally conservative: it emits only authority dimensions backed
by static evidence and leaves unknown dimensions explicit. Runtime effectiveness is
always reported as not_verified.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections import Counter
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from horustrace.models import (
    Agent,
    Graph,
    Identity,
    MCPServer,
    NetworkDestination,
    ResourceScope,
    Skill,
    Tool,
)
from horustrace.semantic_contract import (
    DataConnectionResolution,
    source_context,
    source_data_connection_resolution,
    tool_control_enforcing,
    tool_control_mechanism,
    tool_control_state,
)

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


def _resource_selector_status(resource: ResourceScope) -> str:
    resolution = source_data_connection_resolution(resource)
    if resolution is DataConnectionResolution.RESOLVED:
        return "resolved"
    if resolution in {
        DataConnectionResolution.MODEL_SELECTED,
        DataConnectionResolution.DYNAMIC,
    }:
        return "partially_resolved"
    return "unknown"


def _resource_scope_status(resources: list[ResourceScope]) -> str:
    if not resources:
        return "unknown"
    states = [_resource_selector_status(resource) for resource in resources]
    if all(state == "resolved" for state in states):
        return "resolved"
    if all(state == "unknown" for state in states):
        return "unknown"
    return "partially_resolved"


def _resource(resource: ResourceScope) -> dict[str, Any]:
    return {
        "kind": resource.kind,
        "selector": resource.selector,
        "selector_resolution": source_data_connection_resolution(resource).value,
        "selector_authority_status": _resource_selector_status(resource),
        "access": sorted(resource.access),
        "access_resolution": "declared" if resource.access else "unknown",
        "classification": resource.classification,
        "metadata": dict(resource.metadata),
        "provenance": [fact.as_dict() for fact in resource.provenance],
        "location": _location(resource.location),
    }


def _destination_target_status(target: str) -> str:
    """Classify static destination specificity, not runtime network enforcement."""
    normalized = target.strip().lower()
    if normalized in {"", "*", "<unknown>", "unknown"}:
        return "unknown"
    if (
        (normalized.startswith("<") and normalized.endswith(">"))
        or "${" in normalized
        or "{{" in normalized
        or "}}" in normalized
        or normalized.startswith("*.")
        or "://*." in normalized
    ):
        return "partially_resolved"
    return "resolved"


def _destination_scope_status(destinations: list[NetworkDestination]) -> str:
    if not destinations:
        return "unknown"
    statuses = [_destination_target_status(item.target) for item in destinations]
    if all(status == "resolved" for status in statuses):
        return "resolved"
    if all(status == "unknown" for status in statuses):
        return "unknown"
    return "partially_resolved"


def _destination(destination: NetworkDestination) -> dict[str, Any]:
    return {
        "target": destination.target,
        "direction": destination.direction,
        "restricted": destination.restricted,
        "target_authority_status": _destination_target_status(destination.target),
        "restriction_enforcement": "not_verified",
        "metadata": dict(destination.metadata),
        "provenance": [fact.as_dict() for fact in destination.provenance],
        "location": _location(destination.location),
    }


def _resolve_identity_binding(
    graph: Graph, agent: Agent, name: str | None
) -> tuple[Identity | None, str]:
    """Resolve an explicit identity reference without arbitrarily picking a match."""
    if not name:
        return None, "not_declared"
    # Agent-local definitions take precedence; do not fall back to global
    # definitions when a local reference is ambiguous.
    local = [item for item in agent.identities if item.name == name]
    if len(local) > 1:
        return None, "ambiguous_agent_local"
    if local:
        return local[0], "agent_local"
    global_matches = [item for item in graph.identities if item.name == name]
    if len(global_matches) > 1:
        return None, "ambiguous_graph_wide"
    if global_matches:
        return global_matches[0], "graph_wide"
    return None, "unresolved_reference"


def _identity(graph: Graph, agent: Agent, name: str | None) -> Identity | None:
    """Compatibility helper for consumers of the normalized identity lookup."""
    return _resolve_identity_binding(graph, agent, name)[0]


def _delegation_target_binding(graph: Graph, tool: Tool) -> dict[str, Any] | None:
    """Describe a source-declared agent handoff without inheriting child authority."""
    raw = tool.metadata.get("delegate_target")
    projected = tool.metadata.get("authority_binding") == "delegation_projection"
    if tool.kind != "delegated_agent" and not projected and raw is None:
        return None

    reference: str | None = None
    basis = "delegate_target"
    if isinstance(raw, str) and raw.strip():
        reference = raw.strip()
    elif projected and tool.name.startswith("delegate:"):
        reference = tool.name.removeprefix("delegate:").strip() or None
        basis = "projection_name"

    matches = [
        agent for agent in graph.agents
        if reference is not None and agent.name == reference
    ]
    resolution = (
        "unique_agent" if len(matches) == 1
        else "ambiguous_agent" if len(matches) > 1
        else "unresolved_agent" if reference is not None
        else "not_declared"
    )
    return {
        "target_reference": reference,
        "reference_basis": basis if reference is not None else "not_declared",
        "resolution": resolution,
        "agent_instance_key": (
            _agent_instance_key(matches[0]) if len(matches) == 1 else None
        ),
        # An edge proves potential invocation, never identity or IAM inheritance.
        "child_identity_inheritance": "not_proven",
        "child_permission_inheritance": "not_proven",
        "child_authority_promoted": False,
        "runtime_effectiveness": "not_verified",
    }


def _control_assurance(
    *,
    approval: bool | None,
    guardrails: bool,
    conditional_approval: bool = False,
    source_state: str | None = None,
    inherited_control: bool = False,
    per_call_approval: bool | None = None,
    input_guardrails: bool = False,
    output_guardrails: bool = False,
) -> dict[str, Any]:
    """Distinguish source-visible controls from runtime-enforcement evidence.

    Approval flags and guardrail registration are declarations, not proof that
    the controls executed at runtime. Canonical agent tool-control state can
    describe source-level enforcement while runtime behavior remains unverified.
    """
    approval_declaration = (
        "conditional"
        if conditional_approval
        else "required"
        if approval is True
        else "not_required"
        if approval is False
        else "unknown"
    )
    return {
        "approval_declaration": approval_declaration,
        "guardrails_declared": guardrails,
        "source_control_state": source_state or "not_exposed",
        "inherited_control_source": inherited_control,
        "per_call_approval_declaration": (
            "declared"
            if per_call_approval is True
            else "not_declared"
            if per_call_approval is False
            else "unknown"
        ),
        "input_guardrails_declared": input_guardrails,
        "output_guardrails_declared": output_guardrails,
        "runtime_approval_enforcement": "not_verified",
        "runtime_guardrail_enforcement": "not_verified",
    }


def _identity_authority_evidence(identity: Identity) -> dict[str, Any]:
    """Separate declared IAM constructs without inferring effective grants.

    Source-level role names do not prove their permission expansion, OAuth
    scopes are not IAM permissions, and a missing resource scope is unknown
    rather than global. Deployment-time authority is reconciled separately.
    """
    return {
        "declared_roles": sorted(identity.roles),
        "declared_permissions": sorted(identity.permissions),
        "declared_oauth_scopes": sorted(identity.oauth_scopes),
        "resource_scope": identity.resource_scope,
        "resource_scope_resolution": (
            "declared"
            if isinstance(identity.resource_scope, str) and identity.resource_scope.strip()
            else "unknown"
        ),
        "role_permission_expansion": (
            "unresolved" if identity.roles else "not_applicable"
        ),
        "oauth_scopes_are_iam_permissions": False,
        "runtime_effectiveness": "not_verified",
    }


def _identity_document(identity: Identity) -> dict[str, Any]:
    """Serialize only identity evidence actually present in the normalized graph."""
    return {
        "name": identity.name,
        "provider": identity.provider,
        "credential_source": identity.credential_source,
        "roles": sorted(identity.roles),
        "permissions": sorted(identity.permissions),
        "oauth_scopes": sorted(identity.oauth_scopes),
        "resource_scope": identity.resource_scope,
        "authority_evidence": _identity_authority_evidence(identity),
        "location": _location(identity.location),
        "provenance": [fact.as_dict() for fact in identity.provenance],
    }


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




def _skill_adg_evidence(
    graph: Graph,
    *,
    agent: str,
    skill: str,
) -> list[dict[str, Any]]:
    """Return source-proven ADG binding evidence for one Agent Skill."""
    if graph.adg is None:
        return []
    result: list[dict[str, Any]] = []
    nodes = {node.node_id: node for node in graph.adg.nodes}
    for edge in graph.adg.edges:
        if edge.kind != "USES_SKILL":
            continue
        source = nodes.get(edge.source)
        target = nodes.get(edge.target)
        if source is None or target is None:
            continue
        if source.kind != "agent" or source.name != agent:
            continue
        if target.kind != "skill" or target.name != skill:
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



def _repository_effect_evidence(tool: Tool) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []

    details = tool.metadata.get("repository_effect_evidence_details")
    if isinstance(details, list):
        for item in details:
            if not isinstance(item, dict):
                continue
            path = item.get("path")
            symbol = item.get("symbol")
            line = item.get("line")
            column = item.get("column")
            if not isinstance(path, str) or not isinstance(symbol, str):
                continue
            result.append(
                {
                    "kind": "SOURCE_METHOD",
                    "origin": "observed",
                    "symbol": symbol,
                    "location": {
                        "path": path,
                        "line": line,
                        "column": column,
                    },
                }
            )

    capability_evidence = tool.metadata.get(
        "repository_effect_capability_evidence"
    )
    if isinstance(capability_evidence, dict):
        for capability, items in sorted(capability_evidence.items()):
            if not isinstance(capability, str) or not isinstance(items, list):
                continue
            for item in items:
                if not isinstance(item, dict):
                    continue
                path = item.get("path")
                symbol = item.get("symbol")
                line = item.get("line")
                column = item.get("column")
                if not isinstance(path, str) or not isinstance(symbol, str):
                    continue
                result.append(
                    {
                        "kind": "SOURCE_EFFECT",
                        "origin": "observed",
                        "effect": "capability",
                        "capability": capability,
                        "symbol": symbol,
                        "location": {
                            "path": path,
                            "line": line,
                            "column": column,
                        },
                    }
                )

    for destination in tool.destinations:
        if not destination.metadata.get("repository_effect_summary"):
            continue
        result.append(
            {
                "kind": "SOURCE_EFFECT",
                "origin": "observed",
                "effect": "destination",
                "target": destination.target,
                "symbol": destination.metadata.get("source_symbol"),
                "location": _location(destination.location),
            }
        )

    def key(item: dict[str, Any]) -> tuple[str, str, str, str, int, int]:
        location = item.get("location") or {}
        return (
            str(item.get("kind") or ""),
            str(item.get("effect") or ""),
            str(item.get("capability") or item.get("target") or ""),
            str(location.get("path") or ""),
            int(location.get("line") or 0),
            int(location.get("column") or 0),
        )

    unique: dict[
        tuple[str, str, str, str, int, int],
        dict[str, Any],
    ] = {}
    for item in result:
        unique.setdefault(key(item), item)
    return [unique[item] for item in sorted(unique)]


def _source_effect_status(tool: Tool) -> str | None:
    resolution = tool.metadata.get("repository_effect_resolution")
    if not isinstance(resolution, str) or not resolution:
        return None
    if resolution == "resolved":
        return "resolved"
    if resolution == "partial":
        return "partially_resolved"
    return "unknown"

def _resolution_status(unresolved: list[str], dimensions: dict[str, str]) -> str:
    if not unresolved:
        return "fully_resolved"
    resolved = sum(value == "resolved" for value in dimensions.values())
    return "partially_resolved" if resolved else "unknown"


_CORE_DIMENSIONS_BY_TARGET = {
    "tool": ("target", "capabilities"),
    "mcp_server": ("target", "capabilities", "tool_scope"),
    "delegation": ("target", "capabilities"),
    "skill": ("target", "skills", "capabilities"),
    "skill_catalogue": ("target", "skills"),
}


def _core_dimension_names(
    target_kind: str,
    dimensions: dict[str, str],
) -> tuple[str, ...]:
    configured = list(
        _CORE_DIMENSIONS_BY_TARGET.get(
            target_kind,
            ("target", "capabilities"),
        )
    )
    if target_kind == "tool" and "source_effects" in dimensions:
        configured.append("source_effects")
    if target_kind in {"tool", "delegation"} and "delegation_target" in dimensions:
        configured.append("delegation_target")
    return tuple(name for name in configured if name in dimensions)


def _core_resolution_status(
    target_kind: str,
    dimensions: dict[str, str],
) -> str:
    names = _core_dimension_names(target_kind, dimensions)
    if not names:
        return "unknown"
    statuses = [dimensions.get(name, "unknown") for name in names]
    if all(status == "resolved" for status in statuses):
        return "fully_resolved"
    if any(
        status in {"resolved", "partially_resolved"}
        for status in statuses
    ):
        return "partially_resolved"
    return "unknown"


@dataclass(frozen=True, slots=True)
class EffectiveAuthorityRelationship:
    relationship_id: str
    agent: str
    agent_instance_key: str
    source_context: str
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

    @property
    def core_dimension_names(self) -> tuple[str, ...]:
        return _core_dimension_names(self.target_kind, self.dimensions)

    @property
    def core_resolution(self) -> str:
        return _core_resolution_status(self.target_kind, self.dimensions)

    @property
    def core_unresolved(self) -> tuple[str, ...]:
        return tuple(
            name
            for name in self.core_dimension_names
            if self.dimensions.get(name) != "resolved"
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "relationship_id": self.relationship_id,
            "agent": self.agent,
            "source_context": self.source_context,
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
            "detail_resolution": self.resolution,
            "core_resolution": self.core_resolution,
            "core_dimensions": {
                name: self.dimensions.get(name, "unknown")
                for name in self.core_dimension_names
            },
            "core_unresolved": list(self.core_unresolved),
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
    identity, identity_binding_resolution = _resolve_identity_binding(
        graph, agent, tool.identity
    )
    inherited_control = tool_control_enforcing(agent.metadata)
    conditional_approval = tool.metadata.get("conditional_approval") is True
    source_control_state = tool_control_state(agent.metadata)
    approval_resolved = tool.approval is not None or inherited_control
    dynamic_availability = (
        tool.metadata.get("availability_condition_unresolved") is True
    )
    source_effect_status = _source_effect_status(tool)
    source_effect_unresolved_calls = [
        str(item)
        for item in (
            tool.metadata.get("repository_effect_unresolved_calls") or []
        )
        if isinstance(item, str)
    ]
    unresolved: list[str] = []
    dimensions = {
        "target": "resolved",
        "capabilities": "resolved" if tool.capabilities else "unknown",
        "identity": "resolved" if identity is not None else "unknown",
        "approval": (
            "partially_resolved"
            if conditional_approval
            else "resolved"
            if approval_resolved
            else "unknown"
        ),
        "resources": _resource_scope_status(tool.resources),
        "destinations": _destination_scope_status(tool.destinations),
    }
    delegation_binding = _delegation_target_binding(graph, tool)
    if delegation_binding is not None:
        dimensions["delegation_target"] = (
            "resolved"
            if delegation_binding["resolution"] == "unique_agent"
            else "unknown"
        )
    if dynamic_availability:
        dimensions["availability"] = "partially_resolved"
    if tool.metadata.get("tool_catalogue_unresolved") is True:
        dimensions["tool_scope"] = "unknown"
        unresolved.append("tool_catalogue")
    if source_effect_status is not None:
        dimensions["source_effects"] = source_effect_status
    if not tool.capabilities:
        unresolved.append("capabilities")
    if delegation_binding is not None and dimensions["delegation_target"] != "resolved":
        unresolved.append("delegation_target")
    if identity is None:
        unresolved.append("identity")
    if conditional_approval:
        unresolved.append("approval_condition")
    elif not approval_resolved:
        unresolved.append("approval")
    if dynamic_availability:
        unresolved.append("availability")
    if source_effect_status in {"partially_resolved", "unknown"}:
        unresolved.append("source_effects")
    if not tool.resources:
        unresolved.append("resources")
    elif dimensions["resources"] != "resolved":
        unresolved.append("resource_selector")
    if not tool.destinations:
        unresolved.append("destinations")
    elif dimensions["destinations"] != "resolved":
        unresolved.append("destination_target")

    identity_doc = None
    if identity is not None:
        identity_doc = _identity_document(identity)
        if identity.credential_source is None:
            unresolved.append("credential_source")
            dimensions["identity"] = "partially_resolved"

    destinations = tuple(_destination(item) for item in tool.destinations)

    return EffectiveAuthorityRelationship(
        relationship_id=_stable_relationship_id(agent.name, "tool", tool.name),
        agent=agent.name,
        agent_instance_key=_agent_instance_key(agent),
        source_context=source_context(agent.metadata),
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
                    tool_control_mechanism(agent.metadata)
                    if inherited_control
                    else None
                )
            ),
            **(
                {
                    "conditional": True,
                    "scope": tool.metadata.get("approval_scope"),
                    "policy": tool.metadata.get("approval_policy"),
                    "policy_callable": tool.metadata.get(
                        "approval_policy_callable"
                    ),
                }
                if conditional_approval
                else {}
            ),
        },
        tool_scope=None,
        resources=tuple(_resource(resource) for resource in tool.resources),
        destinations=destinations,
        semantics={
            "identity_binding": {
                "reference": tool.identity,
                "resolution": identity_binding_resolution,
            },
            "control_assurance": _control_assurance(
                approval=tool.approval,
                guardrails=tool.guardrails,
                conditional_approval=conditional_approval,
                source_state=(
                    source_control_state.value
                    if source_control_state is not None else None
                ),
                inherited_control=inherited_control,
            ),
            **(
                {"delegation_boundary": delegation_binding}
                if delegation_binding is not None else {}
            ),
            "binding_origin": (
                tool.metadata.get("binding_origin")
                or tool.metadata.get("authority_binding_basis")
                or tool.metadata.get("source")
            ),
            "delegate_target": tool.metadata.get("delegate_target"),
            "dynamic_authority": tool.metadata.get("dynamic_authority"),
            "tool_catalogue_unresolved": tool.metadata.get(
                "tool_catalogue_unresolved"
            ),
            "capability_bundle": tool.metadata.get("capability_bundle"),
            "availability": (
                "conditional"
                if dynamic_availability
                else "disabled"
                if tool.metadata.get("tool_enabled") is False
                else "enabled"
                if tool.metadata.get("tool_enabled") is True
                else None
            ),
            "availability_policy_callable": tool.metadata.get(
                "tool_enablement_callable"
            ),
            "mutation": tool.metadata.get("mutation_semantics"),
            "network": (
                tool.metadata.get("network_semantics")
                or tool.metadata.get("network_scope")
            ),
            "sensitive_write_domain": tool.metadata.get("sensitive_write_domain"),
            "source_effect_resolution": (
                tool.metadata.get("repository_effect_resolution")
            ),
            "source_effect_partial": (
                tool.metadata.get("repository_effect_partial") is True
            ),
            "source_effect_unresolved_calls": source_effect_unresolved_calls,
            "source_effect_sources": list(
                tool.metadata.get("repository_effect_sources") or []
            ),
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
        evidence=(
            *_adg_evidence(
                graph,
                agent=agent.name,
                target_kind="tool",
                target_name=tool.name,
            ),
            *_repository_effect_evidence(tool),
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
    elif server.metadata.get("tool_catalogue_unresolved") is True:
        # Source proves a binding exists, but provides no evidence that the
        # runtime catalogue is broad or unrestricted. Preserve uncertainty
        # without upgrading it into an unrestricted-surface claim.
        scope = "unknown"
        status = "unknown"
        unresolved.append("tool_catalogue")
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
    identity, identity_binding_resolution = _resolve_identity_binding(
        graph, agent, server.identity
    )
    tool_scope, unresolved, tool_scope_status = _mcp_tool_scope(server)
    operator_configured_remote = (
        server.metadata.get("dynamic_mcp_endpoint_basis")
        == "operator_configuration"
    )
    environment_allowed_hosts = [
        str(item)
        for item in server.metadata.get("environment_allowed_hosts") or []
        if isinstance(item, str) and item
    ]
    environment_bounded_remote = bool(
        environment_allowed_hosts
        and server.metadata.get("network_scope") == "environment_allowlist"
    )
    dynamic_remote = bool(
        server.metadata.get("dynamic_mcp_endpoint")
        and server.transport in {"http", "sse", "streamable-http", "streamable_http"}
    )
    conditional_approval = server.metadata.get("conditional_approval") is True
    dimensions = {
        "target": "resolved",
        "capabilities": "resolved",
        "identity": "resolved" if identity is not None else "unknown",
        "approval": (
            "partially_resolved"
            if conditional_approval
            else "resolved"
            if server.approval is not None
            else "unknown"
        ),
        "resources": _resource_scope_status(server.resources),
        "destinations": (
            _destination_target_status(server.url)
            if server.url
            else "partially_resolved"
            if operator_configured_remote
            else _destination_scope_status(
                [
                    NetworkDestination(target=host)
                    for host in environment_allowed_hosts
                ]
            )
            if environment_bounded_remote
            else _destination_target_status(server.command)
            if server.command
            else "unknown"
        ),
        "tool_scope": tool_scope_status,
    }
    if identity is None:
        unresolved.append("identity")
    if conditional_approval:
        unresolved.append("approval_condition")
    elif server.approval is None:
        unresolved.append("approval")
    if not server.resources:
        unresolved.append("resources")
    elif dimensions["resources"] != "resolved":
        unresolved.append("resource_selector")
    if dimensions["destinations"] == "unknown":
        unresolved.append("destinations")
    elif dimensions["destinations"] == "partially_resolved":
        unresolved.append("destination_target")

    identity_doc = None
    if identity is not None:
        identity_doc = _identity_document(identity)
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
                "target_authority_status": _destination_target_status(server.url),
                "restriction_enforcement": "not_verified",
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
                "target_authority_status": "partially_resolved",
                "restriction_enforcement": "not_verified",
                "configuration_source": server.metadata.get(
                    "configuration_source"
                ),
                "location": _location(server.location),
            }
        )
    elif environment_bounded_remote:
        destinations.extend(
            {
                "target": target,
                "direction": "outbound",
                "restricted": True,
                "kind": "environment_allowed_host",
                "target_authority_status": _destination_target_status(target),
                "restriction_enforcement": "not_verified",
                "constraint_basis": "managed_environment_allowed_hosts",
                "location": _location(server.location),
            }
            for target in environment_allowed_hosts
        )
    elif server.command:
        destinations.append(
            {
                "target": server.command,
                "direction": "local",
                "restricted": True,
                "kind": "fixed_local_command",
                "target_authority_status": _destination_target_status(server.command),
                "restriction_enforcement": "not_verified",
                "args": list(server.args),
                "location": _location(server.location),
            }
        )

    base_capabilities = (
        {"mcp.remote", "network.external"}
        if (
            server.url
            or dynamic_remote
            or operator_configured_remote
            or environment_bounded_remote
        )
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
        source_context=str(agent.metadata.get("source_context") or "unknown"),
        target_kind="mcp_server",
        target_name=server.name,
        capabilities=capabilities,
        identity=identity_doc,
        approval={
            "required": server.approval,
            "guardrails": server.guardrails,
            "mechanism": server.metadata.get("approval_mechanism"),
            **(
                {
                    "conditional": True,
                    "scope": server.metadata.get("approval_scope"),
                    "policy": server.metadata.get("approval_policy"),
                }
                if conditional_approval
                else {}
            ),
        },
        tool_scope=tool_scope,
        resources=tuple(_resource(resource) for resource in server.resources),
        destinations=tuple(destinations),
        semantics={
            "identity_binding": {
                "reference": server.identity,
                "resolution": identity_binding_resolution,
            },
            "control_assurance": _control_assurance(
                approval=server.approval,
                guardrails=server.guardrails,
                conditional_approval=conditional_approval,
                per_call_approval=server.metadata.get("per_call_approval"),
                input_guardrails=bool(server.metadata.get("tool_input_guardrails")),
                output_guardrails=bool(server.metadata.get("tool_output_guardrails")),
            ),
            "destination_binding_resolution": (
                "fixed_endpoint"
                if server.url and dimensions["destinations"] == "resolved"
                else "dynamic_endpoint"
                if server.url
                else "operator_configured"
                if operator_configured_remote
                else "host_allowlist"
                if environment_bounded_remote
                else "local_command"
                if server.command
                else "dynamic_endpoint"
                if dynamic_remote
                else "unknown"
            ),
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
            "tool_input_guardrails": list(
                server.metadata.get("tool_input_guardrails") or []
            ),
            "tool_output_guardrails": list(
                server.metadata.get("tool_output_guardrails") or []
            ),
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


def _skill_relationship(
    graph: Graph,
    agent: Agent,
    skill: Skill,
) -> EffectiveAuthorityRelationship:
    """Expose a source-proven Skill binding without promoting declarations to authority."""
    capability_status = "resolved" if skill.capabilities else "unknown"
    resource_status = _resource_scope_status(skill.resources)
    destination_status = _destination_scope_status(skill.destinations)
    unresolved: list[str] = []
    if skill.allowed_tools and not skill.capabilities:
        unresolved.append("skill_effective_capabilities")
    if skill.resources and resource_status != "resolved":
        unresolved.append("resource_selector")
    if skill.destinations and destination_status != "resolved":
        unresolved.append("destination_target")

    return EffectiveAuthorityRelationship(
        relationship_id=_stable_relationship_id(agent.name, "skill", skill.name),
        agent=agent.name,
        agent_instance_key=_agent_instance_key(agent),
        source_context=str(agent.metadata.get("source_context") or "unknown"),
        target_kind="skill",
        target_name=skill.name,
        capabilities=tuple(sorted(skill.capabilities)),
        identity=None,
        approval={},
        tool_scope=None,
        resources=tuple(_resource(resource) for resource in skill.resources),
        destinations=tuple(_destination(item) for item in skill.destinations),
        semantics={
            "control_assurance": _control_assurance(
                approval=None,
                guardrails=False,
            ),
            "binding_origin": skill.metadata.get("binding_origin"),
            "binding_source_path": skill.metadata.get("binding_source_path"),
            "source": skill.source,
            "instructions_sha256": skill.metadata.get("instructions_sha256"),
            "declared_allowed_tools": sorted(skill.allowed_tools),
            "declared_tool_authority_promoted": False,
            "has_scripts": skill.metadata.get("has_scripts"),
            "script_count": skill.metadata.get("script_count"),
            "llm_security_semantics": skill.metadata.get(
                "llm_security_semantics"
            ),
        },
        dimensions={
            "target": "resolved",
            "skills": "resolved",
            "capabilities": capability_status,
            "resources": resource_status,
            "destinations": destination_status,
        },
        unresolved=tuple(sorted(set(unresolved))),
        evidence=tuple(
            _skill_adg_evidence(graph, agent=agent.name, skill=skill.name)
        ),
        location=_location(skill.location),
    )


def _skill_catalogue_relationships(
    agent: Agent,
) -> list[EffectiveAuthorityRelationship]:
    """Represent source-proven but non-enumerable Skill catalogues as unresolved."""
    result: list[EffectiveAuthorityRelationship] = []

    def add(name: str, semantics: dict[str, Any]) -> None:
        result.append(
            EffectiveAuthorityRelationship(
                relationship_id=_stable_relationship_id(
                    agent.name, "skill_catalogue", name
                ),
                agent=agent.name,
                agent_instance_key=_agent_instance_key(agent),
                source_context=str(
                    agent.metadata.get("source_context") or "unknown"
                ),
                target_kind="skill_catalogue",
                target_name=name,
                capabilities=(),
                identity=None,
                approval={},
                tool_scope=None,
                resources=(),
                destinations=(),
                semantics=semantics,
                dimensions={"target": "resolved", "skills": "unknown"},
                unresolved=("skills",),
                evidence=(),
                location=_location(agent.location),
            )
        )

    if agent.metadata.get("dynamic_skill_sources") is True:
        add(
            "<dynamic-skill-catalogue>",
            {"catalogue_resolution": "dynamic", "enumerated": False},
        )

    remote_sources = agent.metadata.get("remote_skill_sources")
    if isinstance(remote_sources, list):
        for index, source in enumerate(remote_sources, start=1):
            detail = dict(source) if isinstance(source, dict) else {"source": str(source)}
            add(
                f"<remote-skill-catalogue:{index}>",
                {
                    "catalogue_resolution": "remote",
                    "enumerated": False,
                    "source": detail,
                },
            )
    return result


def _delegation_relationship(
    graph: Graph,
    agent: Agent,
    tool: Tool,
) -> EffectiveAuthorityRelationship:
    """Expose source-proven delegated reachability as first-class authority."""
    base = _tool_relationship(graph, agent, tool)
    boundary = base.semantics.get("delegation_boundary") or {}
    target = boundary.get("target_reference") or "<unresolved-delegation>"
    return EffectiveAuthorityRelationship(
        relationship_id=_stable_relationship_id(
            agent.name, "delegation", target
        ),
        agent=base.agent,
        agent_instance_key=base.agent_instance_key,
        source_context=base.source_context,
        target_kind="delegation",
        target_name=target,
        capabilities=base.capabilities,
        identity=base.identity,
        approval=base.approval,
        tool_scope=base.tool_scope,
        resources=base.resources,
        destinations=base.destinations,
        semantics={
            **base.semantics,
            "delegation_projection": True,
            "transitive": tool.metadata.get("transitive") is True,
            "transitive_authority_verified": False,
        },
        dimensions=base.dimensions,
        unresolved=base.unresolved,
        evidence=base.evidence,
        location=base.location,
    )


def _unique_portable_relationship_ids(
    graph: Graph,
    relationships: list[EffectiveAuthorityRelationship],
) -> list[EffectiveAuthorityRelationship]:
    """Disambiguate source occurrences without changing singleton IDs.

    A relationship's public ID previously hashed only (agent name, target
    kind, target name), silently colliding across same-named agent instances.
    Retain legacy IDs when unique; add a deterministic workspace-relative
    qualifier only for collisions. Never hash an absolute source path.
    """
    counts = Counter(item.relationship_id for item in relationships)
    if all(count == 1 for count in counts.values()):
        return relationships

    paths = [
        loc.path.resolve()
        for loc in (
            [agent.location for agent in graph.agents]
            + [item.location for item in relationships if item.location is not None]
        )
        if loc is not None
    ]
    # Each path's parent, not the complete filename, forms the scan-local base.
    # This works when a scanner runs against an equivalent checked-out repo
    # under a different absolute workspace directory.
    base = Path(os.path.commonpath([str(path.parent) for path in paths])) if paths else None
    agents_by_key: dict[str, list[Agent]] = {}
    for agent in graph.agents:
        agents_by_key.setdefault(_agent_instance_key(agent), []).append(agent)

    def loc_key(location: Any) -> tuple[str, int, int]:
        if location is None:
            return ("<unknown>", 0, 0)
        path = Path(location.path).resolve()
        relative = path.relative_to(base).as_posix() if base else path.name
        return (relative, location.line or 0, location.column or 0)

    used: dict[str, int] = {}
    output: list[EffectiveAuthorityRelationship] = []
    for item in relationships:
        if counts[item.relationship_id] == 1:
            output.append(item)
            continue
        owner = agents_by_key.get(item.agent_instance_key, [])
        owner_key = loc_key(owner[0].location) if len(owner) == 1 else ("<ambiguous-agent>", 0, 0)
        discriminator = {
            "agent": item.agent,
            "source": owner_key,
            "target": (item.target_kind, item.target_name),
            "location": loc_key(
                # Relationship locations are already serialized. Reconstruct
                # without attaching an absolute workspace address to the ID.
                SourceLocation(
                    path=Path(item.location["path"]),
                    line=item.location.get("line"),
                    column=item.location.get("column"),
                ) if item.location else None
            ),
        }
        payload = json.dumps(discriminator, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
        candidate = f"{item.relationship_id}:{digest}"
        occurrence = used.get(candidate, 0)
        used[candidate] = occurrence + 1
        if occurrence:
            candidate = f"{candidate}:{occurrence + 1}"
        output.append(replace(item, relationship_id=candidate))
    return output


def effective_authority_relationships(
    graph: Graph,
) -> list[EffectiveAuthorityRelationship]:
    result: list[EffectiveAuthorityRelationship] = []
    for agent in graph.agents:
        for tool in agent.tools:
            authority_binding = tool.metadata.get("authority_binding")
            if authority_binding == "workflow_projection":
                continue
            if authority_binding == "delegation_projection":
                result.append(_delegation_relationship(graph, agent, tool))
                continue
            result.append(_tool_relationship(graph, agent, tool))
        for skill in agent.skills:
            result.append(_skill_relationship(graph, agent, skill))
        result.extend(_skill_catalogue_relationships(agent))
        for server in agent.mcp_servers:
            result.append(_mcp_relationship(graph, agent, server))
    ordered = sorted(
        result,
        key=lambda item: (
            item.agent,
            item.target_kind,
            item.target_name,
            item.relationship_id,
        ),
    )
    return _unique_portable_relationship_ids(graph, ordered)


def _counter(values: list[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _dimension_diagnostics(
    relationships: list[EffectiveAuthorityRelationship],
) -> dict[str, dict[str, int]]:
    """Count only dimensions emitted by applicable source-visible constructs."""
    dimensions: dict[str, list[str]] = {}
    for relationship in relationships:
        for dimension, status in relationship.dimensions.items():
            dimensions.setdefault(dimension, []).append(status)
    return {
        dimension: _counter(statuses)
        for dimension, statuses in sorted(dimensions.items())
    }


def _authority_completeness_diagnostics(
    graph: Graph,
    relationships: list[EffectiveAuthorityRelationship],
) -> dict[str, Any]:
    """Explain attribution and uncertainty, not actual runtime permission reachability."""
    keys = [_agent_instance_key(agent) for agent in graph.agents]
    key_counts = _counter(keys)
    ambiguous_keys = {
        key for key, count in key_counts.items() if count > 1
    }
    relationship_groups: dict[str, list[EffectiveAuthorityRelationship]] = {}
    for relation in relationships:
        relationship_groups.setdefault(relation.agent_instance_key, []).append(relation)

    agents: list[dict[str, Any]] = []
    framework_agent_counts: dict[str, int] = {}
    framework_relationships: dict[str, list[EffectiveAuthorityRelationship]] = {}
    matched_relationships: set[int] = set()
    for index, agent in enumerate(graph.agents):
        key = keys[index]
        # Identical instance keys cannot justify allocating authority evidence
        # to either agent. Preserve the ambiguity explicitly.
        matches = (
            relationship_groups.get(key, [])
            if key not in ambiguous_keys
            else []
        )
        matched_relationships.update(id(item) for item in matches)
        framework = agent.metadata.get("framework")
        if not isinstance(framework, str) or not framework.strip():
            framework = "unknown"
        framework_agent_counts[framework] = framework_agent_counts.get(framework, 0) + 1
        framework_relationships.setdefault(framework, []).extend(matches)
        agents.append(
            {
                "agent": agent.name,
                "agent_index": index,
                # Keep the internal source-qualified key for fail-closed
                # relationship attribution, but never export absolute workspace
                # paths: graph digests and exported reports must be portable.
                "agent_instance_key": f"report-agent:{index}",
                "agent_instance_key_basis": "report_local_index",
                "framework": framework,
                "source_context": source_context(agent.metadata),
                "grouping_resolution": (
                    "ambiguous_instance_key"
                    if key in ambiguous_keys else "unique_instance_key"
                ),
                "relationship_inventory": (
                    "ambiguous_attribution"
                    if key in ambiguous_keys else
                    "observed" if matches else "not_observed"
                ),
                "relationships": len(matches),
                "relationship_ids": [item.relationship_id for item in matches],
                "by_target_kind": _counter([item.target_kind for item in matches]),
                "core_resolution": _counter([item.core_resolution for item in matches]),
                "detail_resolution": _counter([item.resolution for item in matches]),
                "dimensions": _dimension_diagnostics(matches),
                "unresolved_reasons": _counter(
                    [reason for item in matches for reason in item.unresolved]
                ),
                "runtime_effectiveness": "not_verified",
            }
        )

    frameworks = {
        framework: {
            "agents": framework_agent_counts[framework],
            "attributed_relationships": len(framework_relationships[framework]),
            "dimensions": _dimension_diagnostics(framework_relationships[framework]),
            "unresolved_reasons": _counter([
                reason
                for item in framework_relationships[framework]
                for reason in item.unresolved
            ]),
        }
        for framework in sorted(framework_agent_counts)
    }

    return {
        "scope": "source_derived_effective_authority",
        "enforcement": "measurement_only",
        "runtime_effectiveness": "not_verified",
        "interpretation": (
            "Dimension counts describe source-backed reporting completeness, "
            "not verified permissions or proof that unobserved authority is absent."
        ),
        "summary": {
            "agents": len(graph.agents),
            "agent_instances_with_relationships": sum(
                item["relationship_inventory"] == "observed" for item in agents
            ),
            "agent_instances_without_relationships": sum(
                item["relationship_inventory"] == "not_observed" for item in agents
            ),
            "agent_instances_with_ambiguous_attribution": sum(
                item["grouping_resolution"] == "ambiguous_instance_key"
                for item in agents
            ),
            "relationships": len(relationships),
            "relationships_not_attributed_to_unique_agent": sum(
                id(item) not in matched_relationships for item in relationships
            ),
            "core_resolution": _counter([
                item.core_resolution for item in relationships
            ]),
            "detail_resolution": _counter([
                item.resolution for item in relationships
            ]),
            "dimensions": _dimension_diagnostics(relationships),
            "unresolved_reasons": _counter([
                reason for item in relationships for reason in item.unresolved
            ]),
        },
        "by_framework": frameworks,
        "agents": agents,
    }


def effective_authority_report(graph: Graph) -> dict[str, Any]:
    relationships = effective_authority_relationships(graph)
    resolution_counts = {
        status: sum(item.resolution == status for item in relationships)
        for status in ("fully_resolved", "partially_resolved", "unknown")
    }
    core_resolution_counts = {
        status: sum(item.core_resolution == status for item in relationships)
        for status in ("fully_resolved", "partially_resolved", "unknown")
    }
    target_counts = {
        kind: sum(item.target_kind == kind for item in relationships)
        for kind in ("tool", "mcp_server", "delegation", "skill", "skill_catalogue")
    }
    source_context_counts: dict[str, int] = {}
    for item in relationships:
        source_context_counts[item.source_context] = (
            source_context_counts.get(item.source_context, 0) + 1
        )
    return {
        "schema_version": EFFECTIVE_AUTHORITY_SCHEMA_VERSION,
        "runtime_effectiveness": "not_verified",
        "summary": {
            "relationships": len(relationships),
            "runtime_relationships": source_context_counts.get("runtime", 0),
            "non_runtime_relationships": sum(
                count
                for context, count in source_context_counts.items()
                if context not in {"runtime", "unknown"}
            ),
            "unknown_source_context_relationships": source_context_counts.get(
                "unknown", 0
            ),
            "relationships_by_source_context": dict(
                sorted(source_context_counts.items())
            ),
            "tool_relationships": target_counts["tool"],
            "mcp_relationships": target_counts["mcp_server"],
            "delegation_relationships": target_counts["delegation"],
            "skill_relationships": target_counts["skill"],
            "unresolved_skill_catalogues": target_counts["skill_catalogue"],
            "fully_resolved_relationships": resolution_counts["fully_resolved"],
            "partially_resolved_relationships": resolution_counts["partially_resolved"],
            "unknown_relationships": resolution_counts["unknown"],
            "core_fully_resolved_relationships": core_resolution_counts[
                "fully_resolved"
            ],
            "core_partially_resolved_relationships": core_resolution_counts[
                "partially_resolved"
            ],
            "core_unknown_relationships": core_resolution_counts["unknown"],
            "core_fully_resolved_ratio": (
                round(
                    core_resolution_counts["fully_resolved"]
                    / len(relationships),
                    6,
                )
                if relationships
                else 1.0
            ),
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
        "authority_completeness": _authority_completeness_diagnostics(
            graph, relationships
        ),
    }


def render_effective_authority_console(graph: Graph, root: Path) -> str:
    report = effective_authority_report(graph)
    summary = report["summary"]
    diagnostics = report["authority_completeness"]
    lines = [
        "HorusTrace Effective Authority",
        "=" * 30,
        f"Target:                       {root}",
        f"Relationships:                {summary['relationships']}",
        f"Runtime relationships:        {summary['runtime_relationships']}",
        f"Non-runtime relationships:    {summary['non_runtime_relationships']}",
        f"Tool relationships:           {summary['tool_relationships']}",
        f"MCP relationships:            {summary['mcp_relationships']}",
        f"Skill relationships:          {summary['skill_relationships']}",
        f"Unresolved skill catalogues:  {summary['unresolved_skill_catalogues']}",
        f"Core fully resolved:          {summary['core_fully_resolved_relationships']}",
        f"Core partially resolved:      {summary['core_partially_resolved_relationships']}",
        f"Core unknown:                 {summary['core_unknown_relationships']}",
        f"Detail fully resolved:        {summary['fully_resolved_relationships']}",
        f"Detail partially resolved:    {summary['partially_resolved_relationships']}",
        f"Detail unknown:               {summary['unknown_relationships']}",
        f"Identity evidence:            {summary['relationships_with_identity']}",
        f"Approval evidence:            {summary['relationships_with_approval_evidence']}",
        f"Destination evidence:         {summary['relationships_with_destination_evidence']}",
        f"Resource evidence:            {summary['relationships_with_resource_evidence']}",
        "Runtime effectiveness:          NOT VERIFIED",
        "",
        "Authority completeness (source evidence only):",
        (
            "  Agent instances:             "
            f"{diagnostics['summary']['agents']}"
        ),
        (
            "  With observed relationships: "
            f"{diagnostics['summary']['agent_instances_with_relationships']}"
        ),
        (
            "  Without observed relationships: "
            f"{diagnostics['summary']['agent_instances_without_relationships']}"
        ),
        (
            "  Ambiguous attribution:       "
            f"{diagnostics['summary']['agent_instances_with_ambiguous_attribution']}"
        ),
        "",
    ]
    for agent in diagnostics["agents"]:
        lines.append(
            "  "
            f"{agent['agent']} [{agent['framework']}] "
            f"inventory={agent['relationship_inventory']}; "
            f"relationships={agent['relationships']}; "
            f"runtime=not_verified"
        )
        if agent["unresolved_reasons"]:
            lines.append(
                "    unresolved: "
                + ", ".join(
                    f"{name}={count}"
                    for name, count in agent["unresolved_reasons"].items()
                )
            )
    lines.append("")
    if not report["relationships"]:
        lines.append("No effective agent authority relationships detected.")
        return "\n".join(lines)

    for item in report["relationships"]:
        target = item["target"]
        lines.append(
            f"{item['agent']} -> {target['kind']}:{target['name']} "
            f"[CORE={item['core_resolution'].upper()}; "
            f"DETAIL={item['detail_resolution'].upper()}] "
            f"source={item['source_context']}"
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
            f"required={approval.get('required')}; "
            f"guardrails={approval.get('guardrails')}; "
            f"mechanism={approval.get('mechanism') or 'unknown'}"
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
            "  core unresolved: "
            + (
                ", ".join(item["core_unresolved"])
                if item["core_unresolved"]
                else "none"
            )
        )
        lines.append(
            "  detail unresolved: "
            + (", ".join(item["unresolved"]) if item["unresolved"] else "none")
        )
        lines.append(
            f"  ADG invoke evidence: {len(item['evidence'])} edge(s)"
        )
        lines.append("")

    return "\n".join(lines).rstrip()
