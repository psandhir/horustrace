"""Audit-grade Agent Bill of Materials generation from the ADG."""
from __future__ import annotations

import hashlib
import json
import re
import uuid
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


def _lineage_index(
    adg: AgentDependencyGraph,
    local_to_asset: Mapping[str, str],
    relationship_ids: Mapping[str, str],
) -> dict[str, Any]:
    """Build audit-oriented model, resource and destination reachability indexes."""
    nodes = {node.node_id: node for node in adg.nodes}

    invokers: dict[str, set[str]] = {}
    identities_by_owner: dict[str, set[str]] = {}
    authorization_edges: dict[tuple[str, str, str], str] = {}
    for edge in adg.edges:
        source = nodes.get(edge.source)
        target = nodes.get(edge.target)
        if source is None or target is None:
            continue
        if edge.kind == "INVOKES" and source.kind == "agent":
            invokers.setdefault(edge.target, set()).add(edge.source)
        elif edge.kind == "USES_IDENTITY":
            identities_by_owner.setdefault(edge.source, set()).add(edge.target)
        elif edge.kind in {"AUTHORIZES_ACCESS_TO", "AUTHORIZES_CONNECTION_TO"}:
            authorization_edges[(edge.kind, edge.source, edge.target)] = (
                relationship_ids.get(edge.edge_id, edge.edge_id)
            )

    model_groups: dict[str, dict[str, Any]] = {}
    for edge in adg.edges:
        if edge.kind != "USES_MODEL":
            continue
        agent = nodes.get(edge.source)
        model = nodes.get(edge.target)
        if agent is None or model is None or agent.kind != "agent" or model.kind != "model":
            continue
        model_key = str(model.attributes.get("model_key") or model.name)
        group = model_groups.setdefault(
            model_key,
            {
                "model_key": model_key,
                "model_identifier": model.attributes.get("model_identifier", model.name),
                "provider": model.attributes.get("model_provider", "unknown"),
                "family": model.attributes.get("model_family", "unknown"),
                "version": model.attributes.get("model_version", "unknown"),
                "hosting": model.attributes.get("model_hosting", "unknown"),
                "model_asset_ids": set(),
                "agents": {},
            },
        )
        model_asset_id = local_to_asset.get(model.node_id)
        agent_asset_id = local_to_asset.get(agent.node_id)
        if model_asset_id:
            group["model_asset_ids"].add(model_asset_id)
        if agent_asset_id:
            group["agents"][agent_asset_id] = {
                "asset_id": agent_asset_id,
                "name": agent.name,
                "relationship_id": relationship_ids.get(edge.edge_id, edge.edge_id),
                "evidence": edge.location,
            }

    def principals_for(source_id: str) -> list[str]:
        source = nodes.get(source_id)
        if source is None:
            return []
        if source.kind == "agent":
            return [source_id]
        return sorted(invokers.get(source_id, set()))

    resource_groups: dict[str, dict[str, Any]] = {}
    destination_groups: dict[str, dict[str, Any]] = {}
    for edge in adg.edges:
        if edge.kind not in {"READS_FROM", "WRITES_TO", "CONNECTS_TO"}:
            continue
        target = nodes.get(edge.target)
        source = nodes.get(edge.source)
        if target is None or source is None:
            continue
        principal_ids = principals_for(edge.source)
        if not principal_ids:
            continue

        identity_ids = sorted(identities_by_owner.get(edge.source, set()))
        identities = [
            {
                "asset_id": local_to_asset.get(identity_id),
                "name": nodes[identity_id].name,
                "authorization_relationship_id": authorization_edges.get(
                    (
                        "AUTHORIZES_CONNECTION_TO"
                        if edge.kind == "CONNECTS_TO"
                        else "AUTHORIZES_ACCESS_TO",
                        identity_id,
                        edge.target,
                    )
                ),
            }
            for identity_id in identity_ids
            if identity_id in nodes
        ]
        via_asset_id = local_to_asset.get(source.node_id)

        if target.kind == "data_resource" and edge.kind in {"READS_FROM", "WRITES_TO"}:
            resource_key = str(
                target.attributes.get("resource_key")
                or target.attributes.get("selector")
                or target.name
            )
            group = resource_groups.setdefault(
                resource_key,
                {
                    "resource_key": resource_key,
                    "selector": target.attributes.get("selector", target.name),
                    "connection_type": target.attributes.get("connection_type", "unknown"),
                    "provider": target.attributes.get("provider", "unknown"),
                    "classification": target.attributes.get("classification", "unknown"),
                    "resource_asset_ids": set(),
                    "access_paths": [],
                },
            )
            target_asset_id = local_to_asset.get(target.node_id)
            if target_asset_id:
                group["resource_asset_ids"].add(target_asset_id)
            for principal_id in principal_ids:
                principal = nodes.get(principal_id)
                principal_asset_id = local_to_asset.get(principal_id)
                if principal is None or principal_asset_id is None:
                    continue
                group["access_paths"].append(
                    {
                        "agent": {
                            "asset_id": principal_asset_id,
                            "name": principal.name,
                        },
                        "via": (
                            None
                            if source.kind == "agent"
                            else {
                                "asset_id": via_asset_id,
                                "kind": source.kind,
                                "name": source.name,
                            }
                        ),
                        "identities": identities,
                        "access": edge.attributes.get("access")
                        or target.attributes.get("access")
                        or [],
                        "relationship_id": relationship_ids.get(
                            edge.edge_id,
                            edge.edge_id,
                        ),
                        "evidence": edge.location,
                    }
                )

        if target.kind == "network_destination" and edge.kind == "CONNECTS_TO":
            destination_key = str(
                target.attributes.get("destination_key") or target.name
            )
            group = destination_groups.setdefault(
                destination_key,
                {
                    "destination_key": destination_key,
                    "target": target.name,
                    "provider": target.attributes.get("provider", "unknown"),
                    "restricted": target.attributes.get("restricted"),
                    "destination_asset_ids": set(),
                    "access_paths": [],
                },
            )
            target_asset_id = local_to_asset.get(target.node_id)
            if target_asset_id:
                group["destination_asset_ids"].add(target_asset_id)
            for principal_id in principal_ids:
                principal = nodes.get(principal_id)
                principal_asset_id = local_to_asset.get(principal_id)
                if principal is None or principal_asset_id is None:
                    continue
                group["access_paths"].append(
                    {
                        "agent": {
                            "asset_id": principal_asset_id,
                            "name": principal.name,
                        },
                        "via": (
                            None
                            if source.kind == "agent"
                            else {
                                "asset_id": via_asset_id,
                                "kind": source.kind,
                                "name": source.name,
                            }
                        ),
                        "identities": identities,
                        "relationship_id": relationship_ids.get(
                            edge.edge_id,
                            edge.edge_id,
                        ),
                        "evidence": edge.location,
                    }
                )

    models = []
    for key in sorted(model_groups):
        group = model_groups[key]
        group["model_asset_ids"] = sorted(group["model_asset_ids"])
        group["agents"] = [
            group["agents"][asset_id]
            for asset_id in sorted(group["agents"])
        ]
        models.append(group)

    resources = []
    for key in sorted(resource_groups):
        group = resource_groups[key]
        group["resource_asset_ids"] = sorted(group["resource_asset_ids"])
        group["access_paths"].sort(
            key=lambda item: (
                item["agent"]["name"],
                str((item.get("via") or {}).get("name") or ""),
                str(item["relationship_id"]),
            )
        )
        resources.append(group)

    destinations = []
    for key in sorted(destination_groups):
        group = destination_groups[key]
        group["destination_asset_ids"] = sorted(group["destination_asset_ids"])
        group["access_paths"].sort(
            key=lambda item: (
                item["agent"]["name"],
                str((item.get("via") or {}).get("name") or ""),
                str(item["relationship_id"]),
            )
        )
        destinations.append(group)

    return {
        "models": models,
        "data_resources": resources,
        "external_destinations": destinations,
    }


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
                "resolution": annotation.get("resolution", "resolved"),
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
        "lineage": _lineage_index(
            adg,
            local_to_asset,
            relationship_ids,
        ),
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



_CYCLONEDX_COMPONENT_TYPES = {
    "agent": "application",
    "model": "machine-learning-model",
    "prompt": "file",
    "skill": "library",
    "tool": "library",
    "mcp_server": "application",
    "memory": "data",
    "identity": "application",
    "data_resource": "data",
    "network_destination": "application",
    "policy_control": "application",
}


def _cyclonedx_property(name: str, value: Any) -> dict[str, str] | None:
    if value is None:
        return None
    if isinstance(value, str):
        rendered = value
    elif isinstance(value, (bool, int, float)):
        rendered = str(value).lower() if isinstance(value, bool) else str(value)
    else:
        rendered = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return {"name": name, "value": rendered}


def _cyclonedx_component(
    item: Mapping[str, Any],
    *,
    source: Mapping[str, Any],
    relationship_evidence: list[Mapping[str, Any]],
) -> dict[str, Any]:
    asset_type = str(item.get("asset_type") or item.get("kind") or "component")
    attributes = item.get("attributes")
    attributes = attributes if isinstance(attributes, Mapping) else {}
    posture = item.get("posture")
    posture = posture if isinstance(posture, Mapping) else {}
    ownership = item.get("ownership")
    ownership = ownership if isinstance(ownership, Mapping) else {}
    provenance = item.get("provenance")
    provenance = provenance if isinstance(provenance, Mapping) else {}

    properties = [
        _cyclonedx_property("horustrace:asset-type", asset_type),
        _cyclonedx_property("horustrace:framework", item.get("framework")),
        _cyclonedx_property("horustrace:resolution", item.get("resolution")),
        _cyclonedx_property("horustrace:unresolved", item.get("unresolved") or []),
        _cyclonedx_property("horustrace:environment", item.get("environment")),
        _cyclonedx_property("horustrace:lifecycle", item.get("lifecycle")),
        _cyclonedx_property("horustrace:ownership", ownership),
        _cyclonedx_property("horustrace:posture", posture),
        _cyclonedx_property("horustrace:attributes", attributes),
        _cyclonedx_property(
            "horustrace:discovery-source",
            provenance.get("discovery_source"),
        ),
        _cyclonedx_property("horustrace:source-revision", source.get("revision")),
        _cyclonedx_property(
            "horustrace:evidence",
            provenance.get("evidence") or [],
        ),
        _cyclonedx_property(
            "horustrace:relationships",
            relationship_evidence,
        ),
    ]

    component: dict[str, Any] = {
        "type": _CYCLONEDX_COMPONENT_TYPES.get(asset_type, "application"),
        "bom-ref": str(item.get("asset_id") or item.get("id")),
        "name": str(item.get("name") or item.get("asset_id") or item.get("id")),
        "properties": [value for value in properties if value is not None],
    }

    version = (
        attributes.get("model_version")
        or attributes.get("version")
        or attributes.get("revision")
    )
    if isinstance(version, str) and version:
        component["version"] = version

    if component["type"] == "machine-learning-model":
        model_parameters: dict[str, Any] = {}
        task = attributes.get("task")
        architecture_family = attributes.get("architecture_family")
        architecture = attributes.get("architecture")
        if isinstance(task, str) and task:
            model_parameters["task"] = task
        if isinstance(architecture_family, str) and architecture_family:
            model_parameters["architectureFamily"] = architecture_family
        if isinstance(architecture, str) and architecture:
            model_parameters["modelArchitecture"] = architecture
        if model_parameters:
            component["modelCard"] = {
                "modelParameters": model_parameters,
            }

    return component


def to_cyclonedx_1_6(document: Mapping[str, Any]) -> dict[str, Any]:
    """Map an AI-BOM v2 document to a conservative CycloneDX 1.6 JSON BOM.

    CycloneDX carries the interoperable component/dependency view. HorusTrace
    authority, posture, provenance and relationship evidence remain available as
    namespaced component properties so the export does not silently discard
    security semantics that have no direct CycloneDX equivalent.
    """
    inventory = document.get("inventory")
    inventory = inventory if isinstance(inventory, Mapping) else {}
    relationships = document.get("relationships")
    relationships = relationships if isinstance(relationships, list) else []
    source = document.get("source")
    source = source if isinstance(source, Mapping) else {}
    snapshot = document.get("snapshot")
    snapshot = snapshot if isinstance(snapshot, Mapping) else {}

    assets: list[Mapping[str, Any]] = []
    for items in inventory.values():
        if isinstance(items, list):
            assets.extend(item for item in items if isinstance(item, Mapping))

    relationship_by_source: dict[str, list[Mapping[str, Any]]] = {}
    dependency_targets: dict[str, set[str]] = {}
    for relationship in relationships:
        source_asset = relationship.get("source_asset_id")
        target_asset = relationship.get("target_asset_id")
        if not isinstance(source_asset, str) or not isinstance(target_asset, str):
            continue
        relationship_by_source.setdefault(source_asset, []).append(
            {
                "relationship_id": relationship.get("relationship_id"),
                "kind": relationship.get("kind"),
                "target_asset_id": target_asset,
                "resolution": relationship.get("resolution"),
                "unresolved": relationship.get("unresolved") or [],
                "provenance": relationship.get("provenance") or {},
            }
        )
        dependency_targets.setdefault(source_asset, set()).add(target_asset)

    components = [
        _cyclonedx_component(
            item,
            source=source,
            relationship_evidence=sorted(
                relationship_by_source.get(
                    str(item.get("asset_id") or item.get("id")),
                    [],
                ),
                key=lambda value: (
                    str(value.get("kind") or ""),
                    str(value.get("target_asset_id") or ""),
                ),
            ),
        )
        for item in sorted(
            assets,
            key=lambda value: str(value.get("asset_id") or value.get("id")),
        )
    ]

    component_refs = {
        str(item.get("bom-ref"))
        for item in components
        if isinstance(item.get("bom-ref"), str)
    }
    dependencies = [
        {
            "ref": ref,
            "dependsOn": sorted(
                target
                for target in dependency_targets.get(ref, set())
                if target in component_refs
            ),
        }
        for ref in sorted(component_refs)
    ]

    repository_id = str(source.get("repository_id") or "local:unknown")
    digest = str(document.get("digest") or snapshot.get("scan_digest") or "")
    serial = uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"horustrace:{repository_id}:{digest}",
    )

    metadata_properties = [
        _cyclonedx_property("horustrace:aibom-schema-version", document.get("schema_version")),
        _cyclonedx_property("horustrace:repository-id", source.get("repository_id")),
        _cyclonedx_property("horustrace:project", source.get("project")),
        _cyclonedx_property("horustrace:source-revision", source.get("revision")),
        _cyclonedx_property("horustrace:scan-digest", snapshot.get("scan_digest")),
        _cyclonedx_property("horustrace:aibom-digest", document.get("digest")),
    ]

    result: dict[str, Any] = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "properties": [
                value for value in metadata_properties if value is not None
            ],
        },
        "components": components,
        "dependencies": dependencies,
    }
    observed_at = snapshot.get("observed_at")
    if isinstance(observed_at, str) and observed_at:
        result["metadata"]["timestamp"] = observed_at
    return result
