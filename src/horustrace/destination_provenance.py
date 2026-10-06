from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from horustrace.models import Graph, NetworkDestination, ResourceScope

CONSTRAINED_NETWORK_SCOPES = frozenset({
    "fixed_literal_destination",
    "fixed_managed_service",
    "fixed_provider_network",
    "fixed_domain_allowlist",
    "fixed_local_service",
    "operator_configured_destination",
    "explicit_destination",
    "environment_allowlist",
})


def destination_constraint_is_bounded(destination: NetworkDestination) -> bool:
    metadata = destination.metadata
    return (
        destination.restricted
        and (
            metadata.get("constraint_state") == "bounded"
            or str(metadata.get("network_scope") or "") in CONSTRAINED_NETWORK_SCOPES
            or str(metadata.get("source") or "") in {"literal_url", "fixed_url_origin"}
        )
    )


def _host_from_target(target: str) -> str | None:
    value = target.strip()
    if not value or value.startswith("<"):
        return None
    parsed = urlparse(value if "://" in value else f"//{value}")
    return parsed.hostname


def _is_local_host(host: str | None) -> bool:
    if not host:
        return False
    lowered = host.lower().rstrip(".")
    if lowered == "localhost" or lowered.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(lowered).is_loopback
    except ValueError:
        return False


def _normalize_destination(destination: NetworkDestination) -> None:
    metadata = destination.metadata
    source = str(metadata.get("source") or "")
    scope = str(metadata.get("network_scope") or "")

    if source == "fixed_url_origin" or scope in {
        "fixed_managed_service",
        "fixed_provider_network",
        "fixed_domain_allowlist",
        "operator_configured_destination",
        "explicit_destination",
    }:
        destination.restricted = True
        metadata.setdefault("destination_constraint_basis", source or scope)

    host = _host_from_target(destination.target)
    if destination.restricted and _is_local_host(host):
        metadata["network_scope"] = "fixed_local_service"
        metadata.setdefault("destination_constraint_basis", "fixed_local_endpoint")
        metadata["local_service"] = True


def _dynamic_destination_evidence(destination: NetworkDestination) -> bool:
    metadata = destination.metadata
    return (
        str(metadata.get("source") or "") in {
            "dynamic_network_call",
            "model_selected_url_argument",
        }
        or str(metadata.get("network_scope") or "") in {
            "dynamic_destination",
            "dynamic_search_results",
            "search_result_derived_destination",
        }
        or destination.target.startswith(("<dynamic", "<model-selected"))
    )


def _normalize_owner_destinations(
    destinations: list[NetworkDestination],
) -> None:
    for destination in destinations:
        _normalize_destination(destination)

    # A literal observed on one branch of a caller/model-selected expression
    # does not constrain the other branch. Only promote literal evidence to a
    # fixed boundary when the owner has no source-visible dynamic destination.
    if any(_dynamic_destination_evidence(item) for item in destinations):
        return

    for destination in destinations:
        metadata = destination.metadata
        source = str(metadata.get("source") or "")
        scope = str(metadata.get("network_scope") or "")
        if source != "literal_url" and scope != "fixed_literal_destination":
            continue
        if _host_from_target(destination.target) is None:
            continue
        destination.restricted = True
        metadata.setdefault("destination_constraint_basis", "fixed_literal_endpoint")
        if _is_local_host(_host_from_target(destination.target)):
            metadata["network_scope"] = "fixed_local_service"
            metadata["local_service"] = True


def _normalize_resource(resource: ResourceScope) -> None:
    selector = resource.selector.strip()
    if not selector or selector in {"*", "**", "<dynamic>", "<unknown>"}:
        return

    source = str(resource.metadata.get("source") or "")
    if source.startswith("literal_") or selector.startswith(("arn:", "s3://")):
        resource.metadata.setdefault("resource_constraint_basis", "fixed_source_selector")
        resource.metadata.setdefault("constraint_state", "bounded")


def _environment_destinations(agent: object) -> list[NetworkDestination]:
    metadata = getattr(agent, "metadata", {}) or {}
    if str(metadata.get("networking_type") or "").lower() != "limited":
        return []

    raw_hosts = metadata.get("allowed_hosts")
    if not isinstance(raw_hosts, list):
        return []

    sources = {
        str(item)
        for item in metadata.get("allowed_host_sources") or []
        if isinstance(item, str)
    }
    destinations: list[NetworkDestination] = []
    for raw in raw_hosts:
        if not isinstance(raw, str) or not raw:
            continue

        target = raw
        destination_metadata: dict[str, object] = {
            "source": "managed_environment_allowed_hosts",
            "network_scope": "environment_allowlist",
            "destination_constraint_basis": "explicit_environment_allowlist",
            "constraint_state": "bounded",
        }
        if raw.startswith("<configured-host:") and raw.endswith(">"):
            source = raw[len("<configured-host:") : -1]
            destination_metadata.update(
                {
                    "source": "operator_configuration",
                    "network_scope": "operator_configured_destination",
                    "configuration_source": source,
                    "destination_constraint_basis": "environment_operator_configuration",
                }
            )
        elif raw.startswith("<dynamic-host:"):
            # A dynamic expression with no stable configuration root is not an
            # enforceable source-visible host boundary.
            continue
        else:
            host = _host_from_target(raw)
            if _is_local_host(host):
                destination_metadata["network_scope"] = "fixed_local_service"
                destination_metadata["local_service"] = True

        destinations.append(
            NetworkDestination(
                target=target,
                restricted=True,
                location=getattr(agent, "location", None),
                metadata=destination_metadata,
            )
        )

    if destinations:
        metadata["destination_constraint_basis"] = "managed_environment_allowed_hosts"
        metadata["destination_constraints_resolved"] = True
        if sources:
            metadata["allowed_host_sources"] = sorted(sources)
    return destinations


def _apply_environment_constraint(agent: object) -> None:
    constraints = _environment_destinations(agent)
    if not constraints:
        return

    agent_network = getattr(agent, "network", None)
    if isinstance(agent_network, list):
        existing = {(item.target, item.direction) for item in agent_network}
        for constraint in constraints:
            key = (constraint.target, constraint.direction)
            if key not in existing:
                agent_network.append(constraint)
                existing.add(key)

    allowed_targets = [item.target for item in constraints]
    for tool in getattr(agent, "tools", []) or []:
        if "network.external" not in getattr(tool, "capabilities", set()):
            continue
        for destination in tool.destinations:
            _normalize_destination(destination)
            if not destination_constraint_is_bounded(destination):
                destination.restricted = True
                destination.metadata["constraint_state"] = "bounded"
                destination.metadata["constrained_by"] = "environment_allowed_hosts"
                destination.metadata["allowed_targets"] = list(allowed_targets)
        if not tool.destinations:
            tool.destinations.extend(
                NetworkDestination(
                    target=item.target,
                    restricted=True,
                    location=item.location,
                    metadata=dict(item.metadata),
                )
                for item in constraints
            )
        tool.metadata["network_scope"] = "environment_allowlist"
        tool.metadata["destination_constraint_basis"] = "managed_environment_allowed_hosts"
        tool.metadata["allowed_destinations"] = list(allowed_targets)

    for server in getattr(agent, "mcp_servers", []) or []:
        server.metadata["environment_allowed_hosts"] = list(allowed_targets)
        server.metadata["destination_constraint_basis"] = "managed_environment_allowed_hosts"
        if server.url is None and server.metadata.get("dynamic_mcp_endpoint") is True:
            server.metadata["network_scope"] = "environment_allowlist"
            server.metadata["dynamic_mcp_endpoint_basis"] = "environment_allowlist"


def normalize_destination_resource_provenance(graph: Graph) -> None:
    """Normalize source-proven destination/resource constraints across adapters.

    This pass never invents an endpoint. It only strengthens the representation
    when source already proves a fixed/provider/configured destination or an
    explicit managed-runtime host allowlist.
    """
    for agent in graph.agents:
        _normalize_owner_destinations(agent.network)
        for tool in agent.tools:
            _normalize_owner_destinations(tool.destinations)
            for resource in tool.resources:
                _normalize_resource(resource)
        for skill in agent.skills:
            _normalize_owner_destinations(skill.destinations)
            for resource in skill.resources:
                _normalize_resource(resource)
        for server in agent.mcp_servers:
            for resource in server.resources:
                _normalize_resource(resource)
        _apply_environment_constraint(agent)

    for tool in graph.unbound_tools:
        _normalize_owner_destinations(tool.destinations)
        for resource in tool.resources:
            _normalize_resource(resource)
    for server in graph.unbound_mcp_servers:
        for resource in server.resources:
            _normalize_resource(resource)
