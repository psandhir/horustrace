"""Wave C C03b: read-only exact-source-site crosswalk for quarantined MCP ADG.

This does NOT equate source declarations with deployed authority or alter the
canonical ADG. Candidate-to-canonical correspondence is a source-site witness,
not a proof that the nodes represent the same runtime entity.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from typing import Any

from horustrace.adg import AgentDependencyGraph
from horustrace.mcp_c03_candidate import verify_mcp_candidate_rollback

_NAMESPACE = "c03-candidate:"
_EXPECTED_KINDS = frozenset({
    "mcp_client_configuration", "mcp_source_implementation", "mcp_source_tool",
})
_EXPECTED_EDGES = frozenset({
    "CONFIG_RESOLVES_TO_SOURCE_IMPLEMENTATION", "EXPOSES_TOOL",
})


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()


def _site(node: dict[str, Any]) -> tuple[str, int, str] | None:
    loc = node.get("location")
    if not isinstance(loc, dict):
        return None
    path, line, name = loc.get("path"), loc.get("line"), node.get("name")
    if (not isinstance(path, str) or not path.strip()
            or path.startswith(("/", "./")) or "\\" in path
            or ".." in path.split("/") or type(line) is not int or line <= 0
            or not isinstance(name, str) or not name.strip()):
        return None
    return (path, line, name)


def build_mcp_source_crosswalk(
    base: AgentDependencyGraph,
    preview: dict[str, Any],
) -> dict[str, Any]:
    """Produce a deterministic witness-level match report; never mutate ADG.

    Matching strictly requires same source path, line and displayed name.
    Distinct ontology kinds remain identified; a match is a *source site
    correlation only*. Ambiguous matches are never silently chosen.
    """
    verify_mcp_candidate_rollback(base, preview)
    before = base.as_dict()
    digest = base.canonical_digest()
    candidate = preview["candidate_adg"]
    nodes = candidate["nodes"]
    edges = candidate["edges"]
    canonical_nodes = {
        n["id"]: n for n in before["nodes"]
    }
    canonical_edges = {
        e["id"]: e for e in before["edges"]
    }
    site_index: dict[tuple[str, int, str], list[dict[str, Any]]] = {}
    for row in canonical_nodes.values():
        site = _site(row)
        if site is not None:
            site_index.setdefault(site, []).append(row)

    projected = [n for n in nodes if n["id"].startswith(_NAMESPACE)]
    node_records: list[dict[str, Any]] = []
    for node in sorted(projected, key=lambda x: x["id"]):
        if node["kind"] not in _EXPECTED_KINDS:
            raise ValueError("unexpected source candidate node kind")
        site = _site(node)
        if site is None:
            raise ValueError("source candidate lacks valid path/line/name witness")
        matches = sorted(site_index.get(site, []), key=lambda x: x["id"])
        state = ("candidate_only" if not matches else
                 "corroborated_source_site" if len(matches) == 1
                 else "ambiguous_source_site")
        node_records.append({
            "candidate_id": node["id"],
            "candidate_kind": node["kind"],
            "name": node["name"],
            "source_site": {
                "path": site[0], "line": site[1], "name": site[2],
            },
            "status": state,
            "canonical_source_site_matches": [
                {"id": m["id"], "kind": m["kind"]} for m in matches
            ],
            "semantic_identity_verified": False,
            "runtime_identity_verified": False,
            "effective_authority_verified": False,
        })

    node_states = {r["candidate_id"]: r for r in node_records}
    edge_records: list[dict[str, Any]] = []
    for edge in sorted(
        (e for e in edges if e["id"].startswith(_NAMESPACE)),
        key=lambda x: x["id"],
    ):
        if edge["kind"] not in _EXPECTED_EDGES:
            raise ValueError("unexpected candidate edge kind")
        src = node_states.get(edge["source"])
        dst = node_states.get(edge["target"])
        if src is None or dst is None:
            raise ValueError("source candidate edge has invalid endpoints")
        src_ids = {m["id"] for m in src["canonical_source_site_matches"]}
        dst_ids = {m["id"] for m in dst["canonical_source_site_matches"]}
        # This is an exact kind-and-endpoint relation witness, NOT authority.
        correspondences = sorted(
            e["id"] for e in canonical_edges.values()
            if e["kind"] == edge["kind"]
            and e["source"] in src_ids and e["target"] in dst_ids
        )
        state = ("same_kind_endpoint_source_correspondence"
                 if len(correspondences) == 1 else
                 "ambiguous_edge_correspondence"
                 if len(correspondences) > 1 else "candidate_source_edge_only")
        edge_records.append({
            "candidate_id": edge["id"],
            "kind": edge["kind"],
            "source": edge["source"],
            "target": edge["target"],
            "status": state,
            "canonical_same_kind_endpoint_edge_ids": correspondences,
            "runtime_callability_verified": False,
            "effective_agent_can_call": None,
        })
    node_counts = dict(sorted(Counter(x["status"] for x in node_records).items()))
    edge_counts = dict(sorted(Counter(x["status"] for x in edge_records).items()))
    if base.canonical_digest() != digest or base.as_dict() != before:
        raise RuntimeError("crosswalk mutated the canonical ADG")
    body = {
        "schema_version": 1,
        "mode": "c03b_exact_source_site_crosswalk_not_production_adg",
        "baseline_adg_digest": digest,
        "preview_snapshot_sha256": preview["candidate_snapshot_sha256"],
        "source_commit_sha": preview["source_commit_sha"],
        "source_claims_sha256": preview["source_claims_sha256"],
        "node_correspondences": node_records,
        "edge_correspondences": edge_records,
        "node_status_counts": node_counts,
        "edge_status_counts": edge_counts,
        "canonical_adg_unchanged": True,
        "semantic_identity_verified": False,
        "runtime_authority_verified": False,
        "independent_review_verified": False,
        "certified_precision": None,
        "certified_recall": None,
        "production_cutover_authorized": False,
    }
    return {**body, "crosswalk_sha256": _digest(body)}
