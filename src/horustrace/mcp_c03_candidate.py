"""Wave C C03a: reversible, quarantined MCP source-only ADG candidate.

This is a deliberate *candidate* construction, not production build_adg,
AGENT_CAN_CALL, findings or attack-path input. Only attested source
declarations can be projected. No independent reviewer is simulated.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from horustrace.adg import ADGEdge, ADGNode, AgentDependencyGraph
from horustrace.limits import MAX_ADG_EDGES, MAX_ADG_NODES, ScanLimitError
from horustrace.source_shadow_attestation import verify_mcp_source_shadow
from horustrace.source_shadow_html import validate_source_shadow

_MODE = "c03a_mcp_source_candidate_not_authoritative"
_NAMESPACE = "c03-candidate:"
_KINDS = frozenset({
    "mcp_client_configuration",
    "mcp_source_implementation",
    "mcp_source_tool",
})
_EDGES = frozenset({
    "CONFIG_RESOLVES_TO_SOURCE_IMPLEMENTATION",
    "EXPOSES_TOOL",
})


def _digest(snapshot: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(
        json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def build_mcp_adg_candidate(
    base: AgentDependencyGraph,
    evidence: dict[str, Any],
    root: Path,
) -> dict[str, Any]:
    """Build a fully isolated ADG-shaped migration preview and deterministic diff.

    A v2 attestation only demonstrates same-revision source consistency,
    not correctness of source semantics, runtime deployment or authorization.
    The returned candidate has an INCOMPATIBLE schema marker so accidental
    use as a production schema-v1 ADG is rejected by versioned consumers.
    """
    if not isinstance(base, AgentDependencyGraph):
        raise TypeError("candidate requires an existing canonical ADG")
    if not isinstance(evidence, dict):
        raise TypeError("source evidence must be a mapping")
    verify_mcp_source_shadow(evidence, root)
    source_nodes, source_edges = validate_source_shadow(evidence)
    if not source_nodes or not source_edges:
        raise ValueError("empty source relationships cannot enter C03 candidate")
    if any(node["kind"] not in _KINDS for node in source_nodes):
        raise ValueError("unsupported source node kind")
    if any(edge["kind"] not in _EDGES for edge in source_edges):
        raise ValueError("unsupported source edge kind")

    base_snapshot = base.as_dict()
    baseline_digest = base.canonical_digest()
    base_node_ids = {node["id"] for node in base_snapshot["nodes"]}
    base_edge_ids = {edge["id"] for edge in base_snapshot["edges"]}
    if len(base_node_ids) != len(base_snapshot["nodes"]):
        raise ValueError("canonical ADG has duplicate node identities")
    if len(base_edge_ids) != len(base_snapshot["edges"]):
        raise ValueError("canonical ADG has duplicate edge identities")
    if any(edge["source"] not in base_node_ids
           or edge["target"] not in base_node_ids
           for edge in base_snapshot["edges"]):
        raise ValueError("canonical ADG contains dangling edges")
    if any(identifier.startswith(_NAMESPACE)
           for identifier in (*base_node_ids, *base_edge_ids)):
        raise ValueError("canonical ADG already contains candidate-only IDs")

    proposed_nodes: list[ADGNode] = []
    proposed_edges: list[ADGEdge] = []
    for node in source_nodes:
        location = node["location"]
        proposed_nodes.append(ADGNode(
            node_id=_NAMESPACE + node["id"],
            kind=node["kind"],
            name=node["name"],
            framework="mcp",
            location={"path": location["path"], "line": location["line"],
                      "column": None},
            attributes={
                "source_only": True,
                "deployment_verified": False,
                "effective_authority": "unknown",
                "projection_state": "c03_candidate_only",
                "source_agent_context": (
                    node["agent"] if node["kind"] == "mcp_client_configuration"
                    else None
                ),
                "source_witness_id": node["id"],
                "source_commit_sha": evidence["source_revision"]["commit_sha"],
            },
        ))
    for edge in source_edges:
        proposed_edges.append(ADGEdge(
            edge_id=_NAMESPACE + edge["id"],
            kind=edge["kind"],
            source=_NAMESPACE + edge["source"],
            target=_NAMESPACE + edge["target"],
            attributes={
                "source_only": True,
                "projection_state": "c03_candidate_only",
                "runtime_tool_catalogue_verified": False,
                "effective_agent_can_call": None,
                "source_witness_id": edge["id"],
                "source_commit_sha": evidence["source_revision"]["commit_sha"],
            },
        ))
    if (len(base.nodes) + len(proposed_nodes) > MAX_ADG_NODES
            or len(base.edges) + len(proposed_edges) > MAX_ADG_EDGES):
        raise ScanLimitError("C03 candidate exceeds canonical ADG budget")
    candidate_ids = {n.node_id for n in proposed_nodes}
    candidate_edge_ids = {e.edge_id for e in proposed_edges}
    if (len(candidate_ids) != len(proposed_nodes)
            or len(candidate_edge_ids) != len(proposed_edges)
            or base_node_ids & candidate_ids or base_edge_ids & candidate_edge_ids):
        raise ValueError("C03 candidate identity collision")

    candidate = AgentDependencyGraph(
        nodes=[*base.nodes, *proposed_nodes],
        edges=[*base.edges, *proposed_edges],
    )
    snapshot = candidate.as_dict()
    if (base.as_dict() != base_snapshot
            or base.canonical_digest() != baseline_digest):
        raise RuntimeError("C03 preview mutated the production ADG")
    if len(snapshot["nodes"]) != len(base_snapshot["nodes"]) + len(source_nodes):
        raise ValueError("C03 candidate lost source nodes")
    if len(snapshot["edges"]) != len(base_snapshot["edges"]) + len(source_edges):
        raise ValueError("C03 candidate lost source edges")

    # This is intentionally not ADG_SCHEMA_VERSION=1. It cannot be silently
    # mistaken for the canonical production Graph/ADG by a versioned loader.
    snapshot["schema_version"] = "c03_preview_only_incompatible_with_adg_v1"
    snapshot["mode"] = _MODE
    snapshot["production_cutover_authorized"] = False
    source_edge_counts = {
        kind: sum(edge.kind == kind for edge in proposed_edges)
        for kind in sorted(_EDGES)
    }
    report = {
        "schema_version": 1,
        "mode": _MODE,
        "source_commit_sha": evidence["source_revision"]["commit_sha"],
        "source_claims_sha256": evidence["source_revision"]["claims_sha256"],
        "baseline_adg_digest": baseline_digest,
        "candidate_snapshot_sha256": _digest(snapshot),
        "baseline": {"nodes": len(base.nodes), "edges": len(base.edges)},
        "differential": {
            "added_source_node_ids": sorted(candidate_ids),
            "added_source_edge_ids": sorted(candidate_edge_ids),
            "removed_canonical_node_ids": [],
            "removed_canonical_edge_ids": [],
            "changed_canonical_nodes": [],
            "changed_canonical_edges": [],
            "added_source_edge_kinds": source_edge_counts,
            "effective_agent_can_call_edges_added": 0,
            "findings_changed": False,
            "attack_paths_changed": False,
        },
        "candidate_adg": snapshot,
        "canonical_adg_unchanged": True,
        "rollback_digest": baseline_digest,
        "rollback_mechanism": "discard_candidate_and_use_existing_canonical_adg",
        "runtime_authority_verified": False,
        "independently_adjudicated": False,
        "certified_precision": None,
        "certified_recall": None,
        "production_cutover_authorized": False,
    }
    if any(key not in ("CONFIG_RESOLVES_TO_SOURCE_IMPLEMENTATION", "EXPOSES_TOOL")
           for key in report["differential"]["added_source_edge_kinds"]):
        raise ValueError("unsafe source relationship kind in candidate")
    return report


def verify_mcp_candidate_rollback(
    base: AgentDependencyGraph,
    candidate: dict[str, Any],
) -> None:
    """Prove an exact discard rollback, not just self-asserted summary flags."""
    if not isinstance(base, AgentDependencyGraph):
        raise TypeError("rollback base must be a canonical ADG")
    if (not isinstance(candidate, dict) or candidate.get("mode") != _MODE
            or candidate.get("production_cutover_authorized") is not False
            or candidate.get("canonical_adg_unchanged") is not True
            or candidate.get("baseline_adg_digest") != base.canonical_digest()
            or candidate.get("rollback_digest") != base.canonical_digest()):
        raise ValueError("candidate rollback cannot be demonstrated")
    snapshot = candidate.get("candidate_adg")
    if not isinstance(snapshot, dict):
        raise TypeError("candidate ADG snapshot must be a mapping")
    if snapshot.get("schema_version") != (
        "c03_preview_only_incompatible_with_adg_v1"
    ) or snapshot.get("production_cutover_authorized") is not False:
        raise ValueError("candidate can be confused with canonical ADG")
    if (candidate.get("candidate_snapshot_sha256") != _digest(snapshot)
            or snapshot.get("mode") != _MODE):
        raise ValueError("candidate graph changed after differential recording")
    nodes = snapshot.get("nodes")
    edges = snapshot.get("edges")
    if not isinstance(nodes, list) or not isinstance(edges, list):
        raise TypeError("candidate nodes/edges must be lists")
    if any(not isinstance(x, dict) for x in (*nodes, *edges)):
        raise ValueError("candidate contains malformed nodes or edges")
    if (len({n.get("id") for n in nodes}) != len(nodes)
            or len({e.get("id") for e in edges}) != len(edges)):
        raise ValueError("candidate contains identity collisions")
    base_snapshot = base.as_dict()
    canonical_nodes = {
        n["id"]: n for n in base_snapshot["nodes"]
    }
    canonical_edges = {
        e["id"]: e for e in base_snapshot["edges"]
    }
    preview_nodes = {n["id"]: n for n in nodes}
    preview_edges = {e["id"]: e for e in edges}
    if (any(preview_nodes.get(k) != v for k, v in canonical_nodes.items())
            or any(preview_edges.get(k) != v for k, v in canonical_edges.items())):
        raise ValueError("candidate has changed or removed canonical elements")
    new_nodes = set(preview_nodes) - set(canonical_nodes)
    new_edges = set(preview_edges) - set(canonical_edges)
    differential = candidate.get("differential", {})
    if not isinstance(differential, dict):
        raise TypeError("candidate differential must be a mapping")
    kinds = differential.get("added_source_edge_kinds")
    if (sorted(new_nodes) != differential.get("added_source_node_ids")
            or sorted(new_edges) != differential.get("added_source_edge_ids")
            or not isinstance(kinds, dict)
            or kinds != {
                kind: sum(preview_edges[edge_id]["kind"] == kind
                          for edge_id in new_edges)
                for kind in sorted(_EDGES)
            }
            or differential.get("removed_canonical_node_ids") != []
            or differential.get("removed_canonical_edge_ids") != []
            or differential.get("changed_canonical_nodes") != []
            or differential.get("changed_canonical_edges") != []
            or differential.get("effective_agent_can_call_edges_added") != 0
            or differential.get("findings_changed") is not False
            or differential.get("attack_paths_changed") is not False):
        raise ValueError("candidate differential/rollback claims are inconsistent")
    for identifier in new_nodes:
        node = preview_nodes[identifier]
        attrs = node.get("attributes")
        if (not identifier.startswith(_NAMESPACE)
                or node.get("kind") not in _KINDS
                or not isinstance(attrs, dict)
                or attrs.get("source_only") is not True
                or attrs.get("deployment_verified") is not False
                or attrs.get("effective_authority") != "unknown"
                or attrs.get("projection_state") != "c03_candidate_only"):
            raise ValueError("candidate contains promoted source nodes")
    for identifier in new_edges:
        edge = preview_edges[identifier]
        attrs = edge.get("attributes")
        if (not identifier.startswith(_NAMESPACE)
                or edge.get("kind") not in _EDGES
                or edge.get("source") not in new_nodes
                or edge.get("target") not in new_nodes
                or not isinstance(attrs, dict)
                or attrs.get("source_only") is not True
                or attrs.get("effective_agent_can_call") is not None
                or attrs.get("projection_state") != "c03_candidate_only"):
            raise ValueError("candidate contains promoted source edges")
