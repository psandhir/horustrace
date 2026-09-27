"""Reconstruct deployed cloud authority from normalized deployment evidence.

This module does not query Google Cloud. It correlates workload identities with an
explicit snapshot of IAM bindings and role-to-permission expansion supplied by the user.
Conditional bindings remain visible and make applicability partially resolved.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from horustrace.deployed_identity import (
    DeployedIdentityRelationship,
    deployed_identity_relationships,
)
from horustrace.deployment_evidence import DeploymentEvidenceBundle, IAMBindingEvidence
from horustrace.models import Graph
from horustrace.principals import canonical_principal

DEPLOYED_AUTHORITY_SCHEMA_VERSION = 1


def _stable_id(identity_relationship_id: str) -> str:
    digest = hashlib.sha256(identity_relationship_id.encode("utf-8")).hexdigest()[:20]
    return f"deployed-authority-v1:{digest}"


def _matching_bindings(
    relationship: DeployedIdentityRelationship,
    bundle: DeploymentEvidenceBundle,
) -> list[IAMBindingEvidence]:
    target = canonical_principal(bundle.provider, relationship.identity)
    if target is None:
        return []
    result: list[IAMBindingEvidence] = []
    for binding in bundle.iam_bindings:
        principal = canonical_principal(bundle.provider, binding.principal)
        if principal == target:
            result.append(binding)
    return sorted(
        result,
        key=lambda item: (
            item.scope_kind,
            item.scope_name,
            item.role,
            item.inherited_from_kind or "",
            item.inherited_from_name or "",
        ),
    )


@dataclass(frozen=True, slots=True)
class DeployedAuthorityRelationship:
    relationship_id: str
    deployed_identity_relationship_id: str
    agent: str
    provider: str
    workload_id: str
    identity: str
    roles: tuple[str, ...]
    conditional_roles: tuple[str, ...]
    permissions: tuple[str, ...]
    conditional_permissions: tuple[str, ...]
    scopes: tuple[dict[str, str], ...]
    inherited_from: tuple[dict[str, str], ...]
    bindings: tuple[dict[str, Any], ...]
    unresolved_roles: tuple[str, ...]
    resolution: str
    unresolved: tuple[str, ...]
    evidence_source: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "relationship_id": self.relationship_id,
            "deployed_identity_relationship_id": self.deployed_identity_relationship_id,
            "agent": self.agent,
            "provider": self.provider,
            "workload_id": self.workload_id,
            "identity": self.identity,
            "roles": list(self.roles),
            "conditional_roles": list(self.conditional_roles),
            "permissions": list(self.permissions),
            "conditional_permissions": list(self.conditional_permissions),
            "scopes": list(self.scopes),
            "inherited_from": list(self.inherited_from),
            "bindings": list(self.bindings),
            "unresolved_roles": list(self.unresolved_roles),
            "resolution": self.resolution,
            "unresolved": list(self.unresolved),
            "evidence_source": self.evidence_source,
            "runtime_effectiveness": "not_verified",
        }


def _binding_permissions(
    binding: IAMBindingEvidence,
    bundle: DeploymentEvidenceBundle,
) -> tuple[set[str], bool]:
    permissions = set(binding.permissions)
    mapped = bundle.role_permissions.get(binding.role)
    if mapped:
        permissions.update(mapped)
    return permissions, bool(binding.permissions or mapped)


def _authority_relationship(
    identity_relationship: DeployedIdentityRelationship,
    bundle: DeploymentEvidenceBundle,
) -> DeployedAuthorityRelationship:
    bindings = _matching_bindings(identity_relationship, bundle)
    roles: set[str] = set()
    conditional_roles: set[str] = set()
    permissions: set[str] = set()
    conditional_permissions: set[str] = set()
    scopes: set[tuple[str, str]] = set()
    inherited: set[tuple[str, str]] = set()
    unresolved_roles: set[str] = set()
    binding_docs: list[dict[str, Any]] = []
    unresolved: set[str] = set(identity_relationship.unresolved)

    if not bindings:
        unresolved.add("iam_bindings")

    for binding in bindings:
        scopes.add((binding.scope_kind, binding.scope_name))
        if binding.inherited:
            inherited.add(
                (
                    binding.inherited_from_kind or "unknown",
                    binding.inherited_from_name or "unknown",
                )
            )
        expanded, permission_resolved = _binding_permissions(binding, bundle)
        if not permission_resolved:
            unresolved_roles.add(binding.role)
            unresolved.add("permissions")

        if binding.condition is not None:
            conditional_roles.add(binding.role)
            conditional_permissions.update(expanded)
            unresolved.add("iam_condition_applicability")
        else:
            roles.add(binding.role)
            permissions.update(expanded)

        binding_docs.append(
            {
                "principal": binding.principal,
                "role": binding.role,
                "scope": {
                    "kind": binding.scope_kind,
                    "name": binding.scope_name,
                },
                "inherited": binding.inherited,
                "inherited_from": (
                    {
                        "kind": binding.inherited_from_kind,
                        "name": binding.inherited_from_name,
                    }
                    if binding.inherited
                    else None
                ),
                "condition": binding.condition,
                "permissions": sorted(expanded),
            }
        )

    resolution = "fully_resolved" if not unresolved else "partially_resolved"
    return DeployedAuthorityRelationship(
        relationship_id=_stable_id(identity_relationship.relationship_id),
        deployed_identity_relationship_id=identity_relationship.relationship_id,
        agent=identity_relationship.agent,
        provider=identity_relationship.provider,
        workload_id=identity_relationship.workload_id,
        identity=identity_relationship.identity,
        roles=tuple(sorted(roles)),
        conditional_roles=tuple(sorted(conditional_roles)),
        permissions=tuple(sorted(permissions)),
        conditional_permissions=tuple(sorted(conditional_permissions)),
        scopes=tuple(
            {"kind": kind, "name": name}
            for kind, name in sorted(scopes)
        ),
        inherited_from=tuple(
            {"kind": kind, "name": name}
            for kind, name in sorted(inherited)
        ),
        bindings=tuple(binding_docs),
        unresolved_roles=tuple(sorted(unresolved_roles)),
        resolution=resolution,
        unresolved=tuple(sorted(unresolved)),
        evidence_source=bundle.source,
    )


def deployed_authority_relationships(
    graph: Graph,
    bundle: DeploymentEvidenceBundle,
) -> list[DeployedAuthorityRelationship]:
    return [
        _authority_relationship(item, bundle)
        for item in deployed_identity_relationships(graph, bundle)
    ]


def deployed_authority_report(
    graph: Graph,
    bundle: DeploymentEvidenceBundle,
) -> dict[str, Any]:
    relationships = deployed_authority_relationships(graph, bundle)
    return {
        "schema_version": DEPLOYED_AUTHORITY_SCHEMA_VERSION,
        "provider": bundle.provider,
        "evidence_source": bundle.source,
        "runtime_effectiveness": "not_verified",
        "summary": {
            "relationships": len(relationships),
            "fully_resolved_relationships": sum(
                item.resolution == "fully_resolved" for item in relationships
            ),
            "partially_resolved_relationships": sum(
                item.resolution != "fully_resolved" for item in relationships
            ),
            "roles": sum(len(item.roles) for item in relationships),
            "conditional_roles": sum(
                len(item.conditional_roles) for item in relationships
            ),
            "permissions": sum(len(item.permissions) for item in relationships),
            "conditional_permissions": sum(
                len(item.conditional_permissions) for item in relationships
            ),
            "inherited_authority_relationships": sum(
                bool(item.inherited_from) for item in relationships
            ),
        },
        "relationships": [item.as_dict() for item in relationships],
    }
