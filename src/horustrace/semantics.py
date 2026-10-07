from __future__ import annotations

import re

from horustrace.models import Graph, Tool

_PERSISTENT_WRITE_MARKERS = {
    "database", "db", "redis", "sql", "firestore", "storage", "store",
    "persist", "persistent", "checkpoint",
}
_SESSION_WRITE_MARKERS = {
    "state", "session", "context", "cache", "scratch", "temporary", "temp",
}
_SENSITIVE_WRITE_MARKERS = {
    "payment", "transfer", "transaction", "billing", "account", "identity",
    "iam", "credential", "permission", "role", "security", "policy", "access",
}


def _tokens(tool: Tool) -> set[str]:
    raw = f"{tool.name} {tool.kind}".lower()
    return {token for token in re.split(r"[^a-z0-9]+", raw) if token}


def _mutation_semantics(tool: Tool) -> str | None:
    caps = tool.capabilities
    tokens = _tokens(tool)

    if "destructive.write" in caps:
        return "destructive_write"
    if "external.write" in caps:
        return "external_side_effect"
    if "data.write" not in caps:
        return None
    if tokens & _PERSISTENT_WRITE_MARKERS:
        return "persistent_internal_write"
    if tokens & _SESSION_WRITE_MARKERS:
        return "local_session_state_write"
    return "internal_write_unspecified"


def _network_semantics(tool: Tool) -> str | None:
    if "network.external" not in tool.capabilities:
        return None

    scope = tool.metadata.get("network_scope")
    if scope in {"fixed_managed_service", "explicit_destination"}:
        return "fixed_provider_network"
    if tool.destinations and all(destination.restricted for destination in tool.destinations):
        return "fixed_provider_network"
    if "external.write" in tool.capabilities:
        return "arbitrary_egress"
    return "arbitrary_internet_retrieval"


def _sensitive_write_domain(tool: Tool) -> str | None:
    if not ({"data.write", "external.write", "destructive.write"} & tool.capabilities):
        return None
    if _tokens(tool) & _SENSITIVE_WRITE_MARKERS:
        return "financial_identity_or_security"
    return None


def annotate_risk_semantics(graph: Graph) -> None:
    """Add orthogonal risk semantics without changing public capability IDs."""
    for tool in graph.all_tools():
        mutation = _mutation_semantics(tool)
        network = _network_semantics(tool)
        sensitive_domain = _sensitive_write_domain(tool)
        if mutation:
            tool.metadata.setdefault("mutation_semantics", mutation)
        if network:
            tool.metadata["network_semantics"] = network
        if sensitive_domain:
            tool.metadata["sensitive_write_domain"] = sensitive_domain
