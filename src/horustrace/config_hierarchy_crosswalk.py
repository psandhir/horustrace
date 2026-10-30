"""Wave C C03f: read-only source-config to canonical ADG witness crosswalk.

Same display name and exact edge endpoints are *correlations*, never
proof of deployed agent identity, effective callability or tool-group export.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from horustrace.adg import AgentDependencyGraph
from horustrace.config_hierarchy_shadow import build_configured_hierarchy_source_shadow


def _sha(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def build_configured_hierarchy_source_crosswalk(
    canonical: AgentDependencyGraph,
    shadow: dict[str, Any],
    checkout: Path,
) -> dict[str, Any]:
    """Rebuild pinned source before comparing; leave actual canonical ADG inert."""
    if not isinstance(canonical, AgentDependencyGraph):
        raise TypeError("canonical AgentDependencyGraph is required")
    if not isinstance(shadow, dict) or not isinstance(shadow.get("source_revision"), dict):
        raise TypeError("attested configuration source shadow required")
    relative = shadow["source_revision"].get("path")
    # Re-attestation rejects untracked, stale and dirty source, altered
    # declarations, bogus status claims, or a mismatched source revision.
    actual = build_configured_hierarchy_source_shadow(checkout, relative)
    if actual != shadow:
        raise ValueError("configured source shadow differs from attested Git source")
    before = canonical.as_dict()
    digest = canonical.canonical_digest()
    existing = before["nodes"]
    existing_edges = before["edges"]
    ids = {row["id"] for row in existing}
    edge_ids = {row["id"] for row in existing_edges}
    if (len(ids) != len(existing) or len(edge_ids) != len(existing_edges)
            or any(row["source"] not in ids or row["target"] not in ids
                   for row in existing_edges)):
        raise ValueError("canonical ADG has duplicate/dangling identities")
    canonical_by_name: dict[str, list[dict[str, Any]]] = {}
    for node in existing:
        if node["kind"] == "agent":
            canonical_by_name.setdefault(node["name"], []).append(node)

    source_by_id = {n["id"]: n for n in shadow["nodes"]}
    if len(source_by_id) != len(shadow["nodes"]):
        raise ValueError("duplicate source node identities")
    agent_rows = []
    for node in shadow["nodes"]:
        if node["kind"] != "configured_agent":
            continue
        matches = sorted(
            canonical_by_name.get(node["name"], []), key=lambda n: n["id"]
        )
        role_labels = [m.get("attributes", {}).get("agent_type") for m in matches]
        status = (
            "configured_only" if not matches else
            "ambiguous_same_display_name" if len(matches) > 1 else
            "single_display_name_correlation"
        )
        role_status = (
            "no_canonical_agent" if not matches else
            "ambiguous" if len(matches) > 1 else
            "same_source_role_label" if role_labels[0] == node["role"] else
            "role_not_established" if role_labels[0] is None else
            "different_role_label"
        )
        agent_rows.append({
            "source_id": node["id"], "name": node["name"],
            "source_role": node["role"], "source_pointer": node["json_pointer"],
            "status": status, "role_label_status": role_status,
            "canonical_display_name_matches": [m["id"] for m in matches],
            "semantic_identity_verified": False,
            "deployed_instance_verified": False,
        })
    by_agent = {r["source_id"]: r for r in agent_rows}
    edge_rows = []
    for row in shadow["edges"]:
        owner = by_agent.get(row["source"])
        target = source_by_id.get(row["target"])
        if owner is None or target is None:
            raise ValueError("invalid configured edge endpoints")
        canonical_edges = []
        status = "configured_only"
        if row["kind"] == "CONFIG_DECLARES_CHILD":
            other = by_agent.get(row["target"])
            if other is None:
                raise ValueError("configured child target not an agent")
            ids_a = owner["canonical_display_name_matches"]
            ids_b = other["canonical_display_name_matches"]
            if len(ids_a) > 1 or len(ids_b) > 1:
                status = "ambiguous_agent_identity"
            elif len(ids_a) == 1 and len(ids_b) == 1:
                canonical_edges = sorted(
                    e["id"] for e in existing_edges
                    if e["kind"] == "DELEGATES_TO"
                    and e["source"] == ids_a[0] and e["target"] == ids_b[0]
                )
                status = (
                    "typed_delegation_name_endpoint_correlated"
                    if len(canonical_edges) == 1 else
                    "ambiguous_duplicate_typed_delegation"
                    if len(canonical_edges) > 1 else "configured_only"
                )
        elif row["kind"] == "CONFIG_DECLARES_TOOL_GROUP":
            if target["kind"] != "declared_tool_group":
                raise ValueError("configured tool group target has wrong kind")
            ids_a = owner["canonical_display_name_matches"]
            if len(ids_a) > 1:
                status = "ambiguous_agent_identity"
            elif len(ids_a) == 1:
                # INVOKES labels are diagnostic candidates, NOT a gateway
                # group identity or individual MCP tool export.
                target_by_id = {n["id"]: n for n in existing}
                canonical_edges = sorted(
                    e["id"] for e in existing_edges
                    if e["kind"] == "INVOKES" and e["source"] == ids_a[0]
                    and target_by_id[e["target"]]["kind"] in {"tool", "mcp_server"}
                    and (
                        target_by_id[e["target"]].get("attributes", {}).get("tool_name")
                        or target_by_id[e["target"]]["name"].removeprefix(
                            owner["name"] + ":"
                        )
                    ) == target["name"]
                )
                if canonical_edges:
                    status = "tool_group_label_candidate_not_semantic_equivalence"
        else:
            raise ValueError("unexpected declarative configuration edge kind")
        edge_rows.append({
            "source_pointer": row["json_pointer"],
            "source_kind": row["kind"],
            "source": row["source"], "target": row["target"],
            "status": status,
            "canonical_relation_candidates": canonical_edges,
            "runtime_relationship_verified": False,
            "effective_agent_can_call": None,
        })
    if canonical.as_dict() != before or canonical.canonical_digest() != digest:
        raise RuntimeError("C03f crosswalk mutated canonical ADG")
    body = {
        "schema_version": 1,
        "mode": "c03f_configured_source_crosswalk_not_canonical_adg",
        "source_revision": shadow["source_revision"],
        "source_snapshot_sha256": _sha(shadow),
        "baseline_adg_digest": digest,
        "source_agent_records": agent_rows,
        "source_edge_records": edge_rows,
        "agent_status_counts": dict(sorted(Counter(
            row["status"] for row in agent_rows
        ).items())),
        "edge_status_counts": dict(sorted(Counter(
            row["status"] for row in edge_rows
        ).items())),
        "canonical_adg_unchanged": True,
        "source_only": True,
        "runtime_authority_verified": False,
        "independently_adjudicated": False,
        "certified_precision": None,
        "certified_recall": None,
        "production_cutover_authorized": False,
    }
    return {**body, "crosswalk_sha256": _sha(body)}
