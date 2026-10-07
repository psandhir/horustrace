"""Audit-grade Agent Bill of Materials generation from the ADG."""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from horustrace.adg import ADGEdge, ADGNode, AgentDependencyGraph
from horustrace.git_snapshot import GitSnapshotError, git_root, remote_origin, resolve_commit

AIBOM_SCHEMA_VERSION = 2
AIBOM_DELTA_SCHEMA_VERSION = 1
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

_UNKNOWN_POSTURE = {
    "authority_contract": "unknown",
    "organisation_policy": "unknown",
    "security": "unknown",
    "coverage": "unknown",
}


@dataclass(frozen=True, slots=True)
class AIBOMContext:
    repository_id: str
    project: str | None = None
    revision: str | None = None
    owner: str | None = None
    team: str | None = None
    business_service: str | None = None
    environment: str | None = None
    lifecycle: str | None = None
    discovery_source: str = "repository_static_analysis"
    source_identity_resolution: str = "resolved"
    observed_at: str | None = None


def _canonical_digest(document: Mapping[str, Any]) -> str:
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _normalize_repository_id(remote: str) -> str | None:
    value = remote.strip()
    if not value:
        return None

    host: str | None = None
    path: str | None = None
    if "://" in value:
        parsed = urlparse(value)
        host = parsed.hostname
        path = parsed.path
    else:
        match = re.match(r"^(?:[^@]+@)?([^:]+):(.+)$", value)
        if match:
            host, path = match.groups()

    if host and path:
        clean_path = path.strip("/")
        clean_path = clean_path.removesuffix(".git")
        return f"{host.lower()}/{clean_path}" if clean_path else host.lower()

    # Non-network remotes are intentionally not emitted verbatim because they
    # can contain workstation-specific absolute paths.
    return None


def repository_aibom_context(
    root: Path,
    *,
    repository_id: str | None = None,
    project: str | None = None,
    owner: str | None = None,
    team: str | None = None,
    business_service: str | None = None,
    environment: str | None = None,
    lifecycle: str | None = None,
    revision: str | None = None,
    observed_at: str | None = None,
) -> AIBOMContext:
    """Build aggregation context from explicit metadata plus safe Git evidence."""
    scan_root = root.resolve()
    git_repository: Path | None = None
    discovered_revision = revision
    discovered_repository_id = repository_id.strip() if repository_id else None
    identity_resolution = "configured" if discovered_repository_id else "unknown"

    try:
        git_repository = git_root(scan_root)
    except GitSnapshotError:
        git_repository = None

    if git_repository is not None:
        if discovered_revision is None:
            try:
                discovered_revision = resolve_commit(git_repository, "HEAD")
            except GitSnapshotError:
                discovered_revision = None
        if discovered_repository_id is None:
            remote = remote_origin(git_repository)
            discovered_repository_id = (
                _normalize_repository_id(remote) if remote is not None else None
            )
            if discovered_repository_id is not None:
                identity_resolution = "git_remote"

    project_name = project or (
        git_repository.name if git_repository is not None else scan_root.name
    )
    if discovered_repository_id is None:
        # Local-only identity is deterministic for a project name but explicitly
        # qualified so an aggregator never silently treats it as globally unique.
        discovered_repository_id = f"local:{project_name or 'repository'}"
        identity_resolution = "local_only"

    return AIBOMContext(
        repository_id=discovered_repository_id,
        project=project_name or None,
        revision=discovered_revision,
        owner=owner,
        team=team,
        business_service=business_service,
        environment=environment,
        lifecycle=lifecycle,
        source_identity_resolution=identity_resolution,
        observed_at=observed_at,
    )


def _asset_identity_payload(context: AIBOMContext, node: ADGNode) -> str:
    location = (node.location or {}).get("path") or ""
    semantic_id = node.attributes.get("semantic_entity_id") or ""
    return "\0".join(
        (
            context.repository_id,
            node.kind,
            node.framework or "",
            node.name,
            str(location),
            str(semantic_id),
        )
    )


def _asset_id(context: AIBOMContext, node: ADGNode, *, collision: bool = False) -> str:
    payload = _asset_identity_payload(context, node)
    if collision:
        payload += f"\0{node.node_id}"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]
    return f"asset-v1:{digest}"


def _relationship_id(
    context: AIBOMContext,
    edge: ADGEdge,
    source_asset_id: str,
    target_asset_id: str,
    *,
    collision: bool = False,
) -> str:
    payload = (
        f"{context.repository_id}\0{edge.kind}\0"
        f"{source_asset_id}\0{target_asset_id}"
    )
    if collision:
        payload += f"\0{edge.edge_id}"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]
    return f"relationship-v1:{digest}"


def _annotation(
    annotations: Mapping[str, Mapping[str, Any]] | None,
    node_id: str,
) -> Mapping[str, Any]:
    if annotations is None:
        return {}
    value = annotations.get(node_id)
    return value if isinstance(value, Mapping) else {}


def _ownership(
    context: AIBOMContext,
    annotation: Mapping[str, Any],
) -> dict[str, Any]:
    supplied = annotation.get("ownership")
    override = supplied if isinstance(supplied, Mapping) else {}
    return {
        "owner": override.get("owner", context.owner),
        "team": override.get("team", context.team),
        "business_service": override.get(
            "business_service",
            context.business_service,
        ),
    }


def _posture(annotation: Mapping[str, Any]) -> dict[str, Any]:
    posture = dict(_UNKNOWN_POSTURE)
    supplied = annotation.get("posture")
    if isinstance(supplied, Mapping):
        for key in posture:
            if key in supplied:
                posture[key] = supplied[key]
    return posture


def build_aibom(
    adg: AgentDependencyGraph,
    *,
    context: AIBOMContext | None = None,
    annotations: Mapping[str, Mapping[str, Any]] | None = None,
    coverage: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build audit-grade inventory while retaining the schema-v1 local fields."""
    context = context or AIBOMContext(
        repository_id="local:unknown",
        source_identity_resolution="unknown",
    )

    nodes = [
        node
        for node in sorted(adg.nodes, key=lambda item: item.node_id)
        if node.kind in AIBOM_KINDS
    ]

    provisional: dict[str, list[ADGNode]] = {}
    for node in nodes:
        provisional.setdefault(_asset_id(context, node), []).append(node)

    local_to_asset: dict[str, str] = {}
    identity_resolution: dict[str, str] = {}
    for candidate, grouped in provisional.items():
        if len(grouped) == 1:
            local_to_asset[grouped[0].node_id] = candidate
            identity_resolution[grouped[0].node_id] = "stable"
            continue
        for node in grouped:
            local_to_asset[node.node_id] = _asset_id(
                context,
                node,
                collision=True,
            )
            identity_resolution[node.node_id] = "collision_qualified"

    inventory: dict[str, list[dict[str, Any]]] = {
        kind: [] for kind in sorted(AIBOM_KINDS)
    }
    for node in nodes:
        annotation = _annotation(annotations, node.node_id)
        unresolved = annotation.get("unresolved")
        unresolved_values = (
            sorted({str(item) for item in unresolved})
            if isinstance(unresolved, (list, tuple, set))
            else []
        )
        inventory[node.kind].append(
            {
                "id": node.node_id,
                "name": node.name,
                "framework": node.framework,
                "location": node.location,
                "attributes": node.attributes,
                "asset_id": local_to_asset[node.node_id],
                "asset_type": node.kind,
                "identity_resolution": identity_resolution[node.node_id],
                "ownership": _ownership(context, annotation),
                "environment": annotation.get(
                    "environment",
                    context.environment or "unknown",
                ),
                "lifecycle": annotation.get(
                    "lifecycle",
                    context.lifecycle or "unknown",
                ),
                "posture": _posture(annotation),
                "resolution": annotation.get("resolution", "unknown"),
                "unresolved": unresolved_values,
                "provenance": {
                    "discovery_source": annotation.get(
                        "discovery_source",
                        node.attributes.get("discovery_source")
                        or context.discovery_source,
                    ),
                    "source_revision": context.revision,
                    "evidence": [
                        {
                            "kind": "adg_node",
                            "id": node.node_id,
                            "location": node.location,
                        }
                    ],
                },
            }
        )

    edges = sorted(adg.edges, key=lambda item: item.edge_id)
    relationship_candidates: dict[str, list[ADGEdge]] = {}
    edge_endpoints: dict[str, tuple[str, str]] = {}
    for edge in edges:
        source_asset_id = local_to_asset.get(edge.source)
        target_asset_id = local_to_asset.get(edge.target)
        if source_asset_id is None or target_asset_id is None:
            continue
        edge_endpoints[edge.edge_id] = (source_asset_id, target_asset_id)
        candidate = _relationship_id(
            context,
            edge,
            source_asset_id,
            target_asset_id,
        )
        relationship_candidates.setdefault(candidate, []).append(edge)

    relationship_ids: dict[str, str] = {}
    for candidate, grouped in relationship_candidates.items():
        if len(grouped) == 1:
            relationship_ids[grouped[0].edge_id] = candidate
            continue
        for edge in grouped:
            source_asset_id, target_asset_id = edge_endpoints[edge.edge_id]
            relationship_ids[edge.edge_id] = _relationship_id(
                context,
                edge,
                source_asset_id,
                target_asset_id,
                collision=True,
            )

    relationships: list[dict[str, Any]] = []
    for edge in edges:
        endpoints = edge_endpoints.get(edge.edge_id)
        if endpoints is None:
            continue
        source_asset_id, target_asset_id = endpoints
        relationships.append(
            {
                "id": edge.edge_id,
                "kind": edge.kind,
                "source": edge.source,
                "target": edge.target,
                "attributes": edge.attributes,
                "relationship_id": relationship_ids[edge.edge_id],
                "source_asset_id": source_asset_id,
                "target_asset_id": target_asset_id,
                "location": edge.location,
                "resolution": "resolved",
                "unresolved": [],
                "provenance": {
                    "discovery_source": context.discovery_source,
                    "source_revision": context.revision,
                    "evidence": [
                        {
                            "kind": "adg_edge",
                            "id": edge.edge_id,
                            "location": edge.location,
                        }
                    ],
                },
            }
        )

    document: dict[str, Any] = {
        "schema_version": AIBOM_SCHEMA_VERSION,
        "migration": {
            "from_schema_version": 1,
            "compatibility": "v1_fields_retained",
        },
        "adg_schema_version": 1,
        "source": {
            "repository_id": context.repository_id,
            "project": context.project,
            "revision": context.revision,
            "discovery_source": context.discovery_source,
            "identity_resolution": context.source_identity_resolution,
        },
        "ownership": {
            "owner": context.owner,
            "team": context.team,
            "business_service": context.business_service,
        },
        "snapshot": {
            "scan_digest": adg.canonical_digest(),
            "observed_at": context.observed_at,
            "first_seen": None,
            "last_seen": None,
            "aggregation_timestamp_semantics": (
                "first_seen/last_seen are assigned by the aggregation boundary"
            ),
        },
        "coverage": dict(coverage or {}),
        "inventory": inventory,
        "relationships": relationships,
        "summary": {
            "components": sum(len(items) for items in inventory.values()),
            "relationships": len(relationships),
            "by_kind": {kind: len(items) for kind, items in inventory.items()},
            "assets_with_unresolved_evidence": sum(
                bool(item["unresolved"])
                or item["resolution"] in {
                    "unknown",
                    "unresolved",
                    "partially_resolved",
                }
                for items in inventory.values()
                for item in items
            ),
        },
    }
    document["digest"] = _canonical_digest(document)
    return document


def _assets_by_id(document: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    inventory = document.get("inventory")
    if not isinstance(inventory, Mapping):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for items in inventory.values():
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            identifier = item.get("asset_id") or item.get("id")
            if isinstance(identifier, str):
                result[identifier] = item
    return result


def _relationships_by_id(
    document: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    values = document.get("relationships")
    if not isinstance(values, list):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for item in values:
        if not isinstance(item, dict):
            continue
        identifier = item.get("relationship_id") or item.get("id")
        if isinstance(identifier, str):
            result[identifier] = item
    return result


def _semantic_asset(item: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in item.items()
        if key not in {"id", "provenance"}
    }


def _semantic_relationship(item: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in item.items()
        if key not in {"id", "source", "target", "provenance"}
    }


def diff_aibom(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
) -> dict[str, Any]:
    """Return deterministic added, removed and changed inventory semantics."""
    before_assets = _assets_by_id(before)
    after_assets = _assets_by_id(after)
    before_relationships = _relationships_by_id(before)
    after_relationships = _relationships_by_id(after)

    added_asset_ids = sorted(after_assets.keys() - before_assets.keys())
    removed_asset_ids = sorted(before_assets.keys() - after_assets.keys())
    common_asset_ids = sorted(before_assets.keys() & after_assets.keys())
    changed_assets = [
        {
            "asset_id": identifier,
            "before": before_assets[identifier],
            "after": after_assets[identifier],
        }
        for identifier in common_asset_ids
        if _semantic_asset(before_assets[identifier])
        != _semantic_asset(after_assets[identifier])
    ]

    added_relationship_ids = sorted(
        after_relationships.keys() - before_relationships.keys()
    )
    removed_relationship_ids = sorted(
        before_relationships.keys() - after_relationships.keys()
    )
    common_relationship_ids = sorted(
        before_relationships.keys() & after_relationships.keys()
    )
    changed_relationships = [
        {
            "relationship_id": identifier,
            "before": before_relationships[identifier],
            "after": after_relationships[identifier],
        }
        for identifier in common_relationship_ids
        if _semantic_relationship(before_relationships[identifier])
        != _semantic_relationship(after_relationships[identifier])
    ]

    delta: dict[str, Any] = {
        "schema_version": AIBOM_DELTA_SCHEMA_VERSION,
        "repository_id": (
            (after.get("source") or {}).get("repository_id")
            if isinstance(after.get("source"), Mapping)
            else None
        ),
        "before": {
            "revision": (
                (before.get("source") or {}).get("revision")
                if isinstance(before.get("source"), Mapping)
                else None
            ),
            "digest": before.get("digest"),
        },
        "after": {
            "revision": (
                (after.get("source") or {}).get("revision")
                if isinstance(after.get("source"), Mapping)
                else None
            ),
            "digest": after.get("digest"),
        },
        "assets": {
            "added": [after_assets[item] for item in added_asset_ids],
            "removed": [before_assets[item] for item in removed_asset_ids],
            "changed": changed_assets,
        },
        "relationships": {
            "added": [
                after_relationships[item] for item in added_relationship_ids
            ],
            "removed": [
                before_relationships[item] for item in removed_relationship_ids
            ],
            "changed": changed_relationships,
        },
        "summary": {
            "assets_added": len(added_asset_ids),
            "assets_removed": len(removed_asset_ids),
            "assets_changed": len(changed_assets),
            "relationships_added": len(added_relationship_ids),
            "relationships_removed": len(removed_relationship_ids),
            "relationships_changed": len(changed_relationships),
        },
    }
    delta["digest"] = _canonical_digest(delta)
    return delta
