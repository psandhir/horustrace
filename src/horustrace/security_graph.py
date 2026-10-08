"""Versioned Agent Security Graph projection.

ASG v1 is an additive security contract over HorusTrace's normalized graph. It keeps
the existing ADG topology intact while co-locating effective authority, data-flow,
attack-path, and analysis-resolution evidence in one deterministic document.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from horustrace.adg import build_adg
from horustrace.effective_authority import effective_authority_report
from horustrace.models import AttackPath, FlowPath, Graph, SourceLocation

AGENT_SECURITY_GRAPH_SCHEMA_VERSION = 1
AGENT_SECURITY_GRAPH_MODEL = "horustrace.agent_security_graph"


def _relative_path(value: str, root: Path) -> str:
    path = Path(value)
    if not path.is_absolute():
        return path.as_posix()
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def _relative_location(location: dict[str, Any] | None, root: Path) -> dict[str, Any] | None:
    if location is None:
        return None
    result = dict(location)
    path = result.get("path")
    if isinstance(path, str):
        result["path"] = _relative_path(path, root)
    return result


def _relativize_locations(value: Any, root: Path) -> Any:
    if isinstance(value, list):
        return [_relativize_locations(item, root) for item in value]
    if isinstance(value, tuple):
        return [_relativize_locations(item, root) for item in value]
    if not isinstance(value, dict):
        return value

    result: dict[str, Any] = {}
    for key, item in value.items():
        if key == "location" and (item is None or isinstance(item, dict)):
            result[key] = _relative_location(item, root)
        else:
            result[key] = _relativize_locations(item, root)
    return result


def _location(location: SourceLocation | None, root: Path) -> dict[str, Any] | None:
    if location is None:
        return None
    return {
        "path": _relative_path(str(location.path), root),
        "line": location.line,
        "column": location.column,
    }


def _flow(flow: FlowPath, root: Path) -> dict[str, Any]:
    return _relativize_locations(flow.as_dict(), root)


def _attack_path(path: AttackPath, root: Path) -> dict[str, Any]:
    return {
        "path_id": path.path_id,
        "title": path.title,
        "agent": path.agent,
        "nodes": list(path.nodes),
        "severity": path.severity.label(),
        "rationale": path.rationale,
        "location": _location(path.location, root),
        "metadata": _relativize_locations(dict(path.metadata), root),
    }



def validate_security_graph_document(document: dict[str, Any]) -> None:
    """Enforce referential integrity and non-inflated ASG summary counters.

    A discovered object is not a bound relationship. This contract protects
    downstream reporting from dangling topology edges and stale summary counts.
    """
    topology = document["topology"]
    nodes = topology["nodes"]
    edges = topology["edges"]
    node_ids = [node["id"] for node in nodes]
    edge_ids = [edge["id"] for edge in edges]
    if len(set(node_ids)) != len(node_ids):
        raise ValueError("ASG topology contains duplicate node IDs")
    if len(set(edge_ids)) != len(edge_ids):
        raise ValueError("ASG topology contains duplicate edge IDs")
    known_nodes = set(node_ids)
    for edge in edges:
        if edge["source"] not in known_nodes or edge["target"] not in known_nodes:
            raise ValueError(
                f"ASG topology edge {edge['id']!r} has a dangling reference"
            )
    summary = document["summary"]
    topology_summary = topology["summary"]
    expected_counts = {
        "topology_nodes": len(nodes),
        "topology_edges": len(edges),
        "authority_relationships": len(
            document["effective_authority"].get("relationships", [])
        ),
        "flows": len(document["flows"]),
        "attack_paths": len(document["attack_paths"]),
    }
    for key, expected in expected_counts.items():
        if summary[key] != expected:
            raise ValueError(f"ASG {key} counter disagrees with emitted objects")
    if topology_summary["nodes"] != len(nodes) or topology_summary["edges"] != len(edges):
        raise ValueError("ASG topology summary disagrees with emitted nodes or edges")
    for relationship in document["effective_authority"].get("relationships", []):
        if relationship.get("runtime_effectiveness") != "not_verified":
            raise ValueError(
                "Static authority relationships must not claim verified runtime execution"
            )


@dataclass(frozen=True, slots=True)
class AgentSecurityGraph:
    document: dict[str, Any]

    def canonical_digest(self) -> str:
        payload = json.dumps(
            self.document,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def as_dict(self) -> dict[str, Any]:
        return {
            **self.document,
            "digest": self.canonical_digest(),
        }


def build_agent_security_graph(graph: Graph, root: Path) -> AgentSecurityGraph:
    """Build ASG v1 without mutating the normalized scanner graph."""
    root = root.resolve()
    topology = graph.adg or build_adg(graph, root)
    authority = _relativize_locations(effective_authority_report(graph), root)
    flows = [_flow(flow, root) for flow in sorted(graph.flow_paths, key=lambda item: item.flow_id)]
    attack_paths = [
        _attack_path(path, root)
        for path in sorted(graph.attack_paths, key=lambda item: item.path_id)
    ]

    authority_relationships = authority.get("relationships", [])
    unresolved_relationships = sum(
        item.get("resolution") != "fully_resolved"
        for item in authority_relationships
    )
    reachability = (
        graph.coverage.resolution.get("flows", {}).get("agent_reachability", {})
    )

    document = {
        "schema_version": AGENT_SECURITY_GRAPH_SCHEMA_VERSION,
        "model": AGENT_SECURITY_GRAPH_MODEL,
        "root": ".",
        "summary": {
            "topology_nodes": len(topology.nodes),
            "topology_edges": len(topology.edges),
            "authority_relationships": len(authority_relationships),
            "authority_relationships_not_fully_resolved": unresolved_relationships,
            "flows": len(flows),
            "attack_paths": len(attack_paths),
            "flow_agent_reachability": dict(sorted(reachability.items())),
            "analysis_incomplete": graph.coverage.incomplete,
        },
        "topology": topology.as_dict(),
        "effective_authority": authority,
        "flows": flows,
        "attack_paths": attack_paths,
        "resolution": {
            "coverage_incomplete": graph.coverage.incomplete,
            "coverage": _relativize_locations(graph.coverage.as_dict(), root),
        },
    }
    validate_security_graph_document(document)
    return AgentSecurityGraph(document)
