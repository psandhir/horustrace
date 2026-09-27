"""Deterministic graph projection for repository-declared deployed authority."""
from __future__ import annotations

import hashlib
import json
from typing import Any

from horustrace.deployed_authority import deployed_authority_relationships
from horustrace.deployed_identity import deployed_identity_relationships
from horustrace.deployment_evidence import DeploymentEvidenceBundle
from horustrace.models import Graph

DEPLOYMENT_GRAPH_SCHEMA_VERSION = 1
DEPLOYMENT_GRAPH_MODEL = "horustrace.deployment_authority_graph"


def _stable_id(kind: str, *parts: str) -> str:
    payload = "\0".join((kind, *parts))
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]
    return f"deployment-v1:{digest}"


def _edge_id(kind: str, source: str, target: str, attributes: dict[str, Any]) -> str:
    payload = "\0".join(
        (
            kind,
            source,
            target,
            json.dumps(attributes, sort_keys=True, separators=(",", ":"), default=str),
        )
    )
    return "deployment-edge-v1:" + hashlib.sha256(
        payload.encode("utf-8")
    ).hexdigest()[:20]


def build_deployment_authority_graph(
    graph: Graph,
    bundle: DeploymentEvidenceBundle,
) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}

    def node(kind: str, name: str, *identity: str, **attributes: Any) -> str:
        node_id = _stable_id(kind, *(identity or (name,)))
        nodes.setdefault(
            node_id,
            {
                "id": node_id,
                "kind": kind,
                "name": name,
                "attributes": {
                    key: value
                    for key, value in attributes.items()
                    if value is not None
                },
            },
        )
        return node_id

    def edge(
        kind: str,
        source: str,
        target: str,
        **attributes: Any,
    ) -> None:
        clean = {
            key: value
            for key, value in attributes.items()
            if value is not None
        }
        edge_id = _edge_id(kind, source, target, clean)
        edges.setdefault(
            edge_id,
            {
                "id": edge_id,
                "kind": kind,
                "source": source,
                "target": target,
                "attributes": clean,
            },
        )

    identities = deployed_identity_relationships(graph, bundle)
    authorities = deployed_authority_relationships(graph, bundle)
    authority_by_identity = {
        item.deployed_identity_relationship_id: item
        for item in authorities
    }

    for relationship in identities:
        agent_id = node("agent", relationship.agent, relationship.agent)
        workload_id = node(
            "workload",
            relationship.workload_name,
            relationship.workload_id,
            workload_id=relationship.workload_id,
            workload_kind=relationship.workload_kind,
            project=relationship.project,
            region=relationship.region,
            provider=relationship.provider,
        )
        identity_id = node(
            "identity",
            relationship.identity,
            relationship.provider,
            relationship.identity,
            provider=relationship.provider,
        )
        edge(
            "DEPLOYED_AS",
            agent_id,
            workload_id,
            binding_basis=relationship.binding_basis,
            evidence_source=relationship.evidence_source,
            resolution=relationship.resolution,
            runtime_effectiveness="not_verified",
        )
        edge(
            "RUNS_AS",
            workload_id,
            identity_id,
            evidence_source=relationship.evidence_source,
            resolution=relationship.resolution,
            runtime_effectiveness="not_verified",
        )

        authority = authority_by_identity.get(relationship.relationship_id)
        if authority is None:
            continue
        for binding in authority.bindings:
            role = str(binding["role"])
            scope = binding.get("scope") or {}
            scope_kind = str(scope.get("kind") or "unknown")
            scope_name = str(scope.get("name") or "unknown")
            role_id = node(
                "role",
                role,
                relationship.provider,
                role,
                scope_kind,
                scope_name,
                provider=relationship.provider,
                scope={"kind": scope_kind, "name": scope_name},
            )
            condition = binding.get("condition")
            edge(
                "CONDITIONALLY_GRANTED_ROLE" if condition is not None else "GRANTED_ROLE",
                identity_id,
                role_id,
                condition=condition,
                inherited=binding.get("inherited"),
                inherited_from=binding.get("inherited_from"),
                evidence_source=authority.evidence_source,
                runtime_effectiveness="not_verified",
            )
            scope_id = node(
                "resource_scope",
                f"{scope_kind}:{scope_name}",
                relationship.provider,
                scope_kind,
                scope_name,
                provider=relationship.provider,
                scope_kind=scope_kind,
            )
            edge("SCOPED_TO", role_id, scope_id)

            for permission in binding.get("permissions") or []:
                permission_id = node(
                    "permission",
                    str(permission),
                    relationship.provider,
                    str(permission),
                    provider=relationship.provider,
                )
                edge("GRANTS_PERMISSION", role_id, permission_id)

    node_docs = sorted(nodes.values(), key=lambda item: item["id"])
    edge_docs = sorted(edges.values(), key=lambda item: item["id"])
    return {
        "schema_version": DEPLOYMENT_GRAPH_SCHEMA_VERSION,
        "model": DEPLOYMENT_GRAPH_MODEL,
        "provider": bundle.provider,
        "runtime_effectiveness": "not_verified",
        "summary": {
            "nodes": len(node_docs),
            "edges": len(edge_docs),
            "node_kinds": {
                kind: sum(item["kind"] == kind for item in node_docs)
                for kind in sorted({item["kind"] for item in node_docs})
            },
            "edge_kinds": {
                kind: sum(item["kind"] == kind for item in edge_docs)
                for kind in sorted({item["kind"] for item in edge_docs})
            },
        },
        "nodes": node_docs,
        "edges": edge_docs,
    }
