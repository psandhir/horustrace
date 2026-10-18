"""Wave C01a: deterministic shadow-only typed-edge and instance reconciliation.

This reconciles the existing public Graph with the semantic-discovery sidecar.
It is NOT a second graph implementation or source-truth/authority verifier.
No third-party target is executed and no output is projected into production.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from horustrace.models import Graph
from horustrace.semantic_discovery import (
    SemanticBindingKind,
    SemanticDiscovery,
    SemanticEntityKind,
    SemanticResolution,
)
from horustrace.source_context import SOURCE_CONTEXTS


# Validate only contracts whose endpoint kinds are unambiguous. INVOKES,
# DISPATCHES_TO, ROUTES_TO etc. legitimately span different construct kinds.
_TYPED_ENDPOINTS: dict[
    SemanticBindingKind, tuple[SemanticEntityKind, SemanticEntityKind]
] = {
    SemanticBindingKind.BINDS_MCP: (
        SemanticEntityKind.AGENT, SemanticEntityKind.MCP_SERVER
    ),
    SemanticBindingKind.AGENT_BINDS_CLIENT: (
        SemanticEntityKind.AGENT, SemanticEntityKind.MCP_CLIENT
    ),
    SemanticBindingKind.CLIENT_CONNECTS_TO_SERVER: (
        SemanticEntityKind.MCP_CLIENT, SemanticEntityKind.MCP_SERVER
    ),
    SemanticBindingKind.EXPOSES_TOOL: (
        SemanticEntityKind.MCP_SERVER, SemanticEntityKind.TOOL
    ),
    SemanticBindingKind.AGENT_CAN_CALL: (
        SemanticEntityKind.AGENT, SemanticEntityKind.TOOL
    ),
    SemanticBindingKind.DELEGATES_TO: (
        SemanticEntityKind.AGENT, SemanticEntityKind.AGENT
    ),
    SemanticBindingKind.USES_SKILL: (
        SemanticEntityKind.AGENT, SemanticEntityKind.SKILL
    ),
    SemanticBindingKind.USES_IDENTITY: (
        SemanticEntityKind.AGENT, SemanticEntityKind.IDENTITY
    ),
}

_LEGACY_MEMBER_COUNTS = {
    SemanticBindingKind.INVOKES: "tools",
    SemanticBindingKind.BINDS_MCP: "mcp_servers",
    SemanticBindingKind.USES_SKILL: "skills",
    SemanticBindingKind.USES_IDENTITY: "identities",
}


def _context(entity: Any) -> str:
    value = entity.metadata.get("source_context")
    return value if isinstance(value, str) and value in SOURCE_CONTEXTS else "unknown"


def _source_site(entity: Any) -> tuple[str, str, int] | None:
    location = entity.location
    if location is None:
        return None
    # The shadow builder has already converted this to a checkout-portable
    # source-relative path. No raw user metadata or secrets are serialized.
    return entity.name, location.path.as_posix(), location.line


def reconcile_shadow_projection(
    graph: Graph, discovery: SemanticDiscovery
) -> dict[str, Any]:
    """Produce reproducible, bounded-evidence diagnostics, not a new Graph.

    The legacy Graph is the *observed-membership* comparator, never an
    independent source reference. A difference is not labelled FP or FN.
    """
    discovery.validate()
    entities = discovery.entity_map()
    by_kind = Counter(edge.kind.value for edge in discovery.bindings)
    expected = {
        kind.value: sum(len(getattr(agent, attr)) for agent in graph.agents)
        for kind, attr in _LEGACY_MEMBER_COUNTS.items()
    }
    member_deltas = {
        kind: {
            "legacy_occurrences": count,
            "distinct_shadow_edges": by_kind.get(kind, 0),
            "occurrence_difference_unadjudicated": (
                count - by_kind.get(kind, 0)
            ),
        }
        for kind, count in sorted(expected.items())
    }

    type_violations: list[dict[str, Any]] = []
    cross_context: list[dict[str, str]] = []
    legacy_authority_promotions: list[str] = []
    typed_edge_lineage: list[dict[str, str]] = []
    for edge in discovery.bindings:
        src = entities[edge.source_id]
        dst = entities[edge.target_id]
        expected_pair = _TYPED_ENDPOINTS.get(edge.kind)
        if expected_pair is not None:
            typed_edge_lineage.append({
                "binding_id": edge.binding_id,
                "kind": edge.kind.value,
                "source_id": edge.source_id,
                "target_id": edge.target_id,
                "resolution": edge.resolution.value,
                "source_context": _context(src),
                "target_context": _context(dst),
            })
            if (src.kind, dst.kind) != expected_pair:
                type_violations.append({
                    "binding_id": edge.binding_id,
                    "kind": edge.kind.value,
                    "actual": [src.kind.value, dst.kind.value],
                    "required": [part.value for part in expected_pair],
                })
            if _context(src) != _context(dst):
                cross_context.append({
                    "binding_id": edge.binding_id,
                    "source_context": _context(src),
                    "target_context": _context(dst),
                    "status": "needs_source_scope_review_not_invalid_by_default",
                })
            if (
                edge.kind == SemanticBindingKind.AGENT_CAN_CALL
                and edge.resolution == SemanticResolution.PROVEN
                and edge.metadata.get("origin")
                == "legacy_graph_projection_not_independently_adjudicated"
            ):
                legacy_authority_promotions.append(edge.binding_id)

    # A legacy Graph may have multiple agents named alike, including genuine
    # distinct instances at one source line. Group these, never merge them.
    agent_sites: dict[tuple[str, str, int], list[str]] = defaultdict(list)
    for entity in discovery.entities:
        site = _source_site(entity)
        if entity.kind == SemanticEntityKind.AGENT and site is not None:
            agent_sites[site].append(entity.entity_id)
    identity_collisions = [
        {
            "name": name,
            "source_path": path,
            "line": line,
            "entity_ids": sorted(entity_ids),
            "status": "distinct_shadow_entities_identity_unresolved",
        }
        for (name, path, line), entity_ids in sorted(agent_sites.items())
        if len(entity_ids) > 1
    ]

    unresolved_entities = sorted({
        observation.entity_id
        for observation in discovery.observations
        if observation.resolution == SemanticResolution.UNRESOLVED
    })
    unresolved_edges = sorted(
        edge.binding_id for edge in discovery.bindings
        if edge.resolution == SemanticResolution.UNRESOLVED
    )
    return {
        "schema_version": 1,
        "mode": "shadow_diagnostics_no_graph_cutover",
        "comparator": "legacy_graph_not_independent_source_truth",
        "graph_behavior_changed": False,
        "source_precision": None,
        "source_recall": None,
        "legacy_member_reconciliation": member_deltas,
        "typed_edge_lineage": sorted(
            typed_edge_lineage, key=lambda row: row["binding_id"]
        ),
        "endpoint_type_violations": sorted(
            type_violations, key=lambda row: row["binding_id"]
        ),
        "cross_source_context_edges": sorted(
            cross_context, key=lambda row: row["binding_id"]
        ),
        "unresolved_entity_ids": unresolved_entities,
        "unresolved_binding_ids": unresolved_edges,
        "same_source_agent_identity_collisions": identity_collisions,
        "unsupported_legacy_authority_promotions": sorted(
            legacy_authority_promotions
        ),
        "exposes_tool_edges_do_not_imply_agent_can_call": True,
        "source_adjudicated": False,
        "production_projection_authorized": False,
    }
