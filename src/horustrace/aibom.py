"""Agent Bill of Materials generation from the Agent Dependency Graph."""
from __future__ import annotations

import hashlib
import json
from typing import Any

from horustrace.adg import AgentDependencyGraph

AIBOM_SCHEMA_VERSION = 1
AIBOM_KINDS = {
    "agent",
    "model",
    "prompt",
    "skill",
    "tool",
    "mcp_server",
    "memory",
    "identity",
    "data_resource",
    "network_destination",
    "policy_control",
}


def build_aibom(adg: AgentDependencyGraph) -> dict[str, Any]:
    """Build a deterministic inventory without embedding prompt contents or secrets."""
    inventory: dict[str, list[dict[str, Any]]] = {
        kind: [] for kind in sorted(AIBOM_KINDS)
    }
    for node in sorted(adg.nodes, key=lambda item: item.node_id):
        if node.kind not in AIBOM_KINDS:
            continue
        inventory[node.kind].append(
            {
                "id": node.node_id,
                "name": node.name,
                "framework": node.framework,
                "location": node.location,
                "attributes": node.attributes,
            }
        )

    relationships = [
        {
            "id": edge.edge_id,
            "kind": edge.kind,
            "source": edge.source,
            "target": edge.target,
            "attributes": edge.attributes,
        }
        for edge in sorted(adg.edges, key=lambda item: item.edge_id)
    ]
    document: dict[str, Any] = {
        "schema_version": AIBOM_SCHEMA_VERSION,
        "adg_schema_version": 1,
        "inventory": inventory,
        "relationships": relationships,
        "summary": {
            "components": sum(len(items) for items in inventory.values()),
            "relationships": len(relationships),
            "by_kind": {kind: len(items) for kind, items in inventory.items()},
        },
    }
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"))
    document["digest"] = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return document
