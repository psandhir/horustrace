"""Resolve deployment workload evidence to normalized HorusTrace agents.

Bindings are conservative. A workload is associated with an agent only through an
explicit `agent` field in deployment evidence or an exact deployment hint on the
normalized agent. Name similarity alone is never sufficient.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from horustrace.principals import canonical_principal
from horustrace.deployment_evidence import DeploymentEvidenceBundle, DeploymentWorkloadEvidence
from horustrace.models import Agent, Graph

DEPLOYED_IDENTITY_SCHEMA_VERSION = 1


def _stable_id(agent: str, workload_id: str, identity: str) -> str:
    payload = f"{agent}\0{workload_id}\0{identity}"
    return "deployed-identity-v1:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]


def _deployment_hints(agent: Agent) -> set[str]:
    result: set[str] = set()
    for key in ("deployment_workload", "deployment_name", "workload_id"):
        value = agent.metadata.get(key)
        if isinstance(value, str) and value.strip():
            result.add(value.strip())
    return result


def _matches(agent: Agent, workload: DeploymentWorkloadEvidence) -> tuple[bool, str | None]:
    if workload.agent is not None:
        return workload.agent == agent.name, "explicit_agent" if workload.agent == agent.name else None
    hints = _deployment_hints(agent)
    if workload.workload_id in hints:
        return True, "agent_workload_id"
    if workload.name in hints:
        return True, "agent_deployment_name"
    return False, None


@dataclass(frozen=True, slots=True)
class DeployedIdentityRelationship:
    relationship_id: str
    agent: str
    provider: str
    workload_id: str
    workload_kind: str
    workload_name: str
    identity: str
    project: str | None
    region: str | None
    binding_basis: str
    evidence_source: str
    resolution: str
    unresolved: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "relationship_id": self.relationship_id,
            "agent": self.agent,
            "provider": self.provider,
            "workload": {
                "id": self.workload_id,
                "kind": self.workload_kind,
                "name": self.workload_name,
                "project": self.project,
                "region": self.region,
            },
            "identity": self.identity,
            "binding_basis": self.binding_basis,
            "evidence_source": self.evidence_source,
            "resolution": self.resolution,
            "unresolved": list(self.unresolved),
            "runtime_effectiveness": "not_verified",
        }


def _relationship(
    agent: Agent,
    workload: DeploymentWorkloadEvidence,
    bundle: DeploymentEvidenceBundle,
    basis: str,
) -> DeployedIdentityRelationship:
    unresolved: list[str] = []
    identity = workload.identity
    canonical = canonical_principal(bundle.provider, identity)
    if canonical is None:
        unresolved.append("identity")
    else:
        identity = canonical
    resolution = "fully_resolved" if not unresolved else "partially_resolved"
    return DeployedIdentityRelationship(
        relationship_id=_stable_id(agent.name, workload.workload_id, identity),
        agent=agent.name,
        provider=bundle.provider,
        workload_id=workload.workload_id,
        workload_kind=workload.kind,
        workload_name=workload.name,
        identity=identity,
        project=workload.project,
        region=workload.region,
        binding_basis=basis,
        evidence_source=bundle.source,
        resolution=resolution,
        unresolved=tuple(sorted(unresolved)),
    )


def deployed_identity_relationships(
    graph: Graph,
    bundle: DeploymentEvidenceBundle,
) -> list[DeployedIdentityRelationship]:
    result: list[DeployedIdentityRelationship] = []
    for agent in graph.agents:
        for workload in bundle.workloads:
            matched, basis = _matches(agent, workload)
            if not matched or basis is None:
                continue
            result.append(_relationship(agent, workload, bundle, basis))
    return sorted(
        result,
        key=lambda item: (item.agent, item.workload_id, item.relationship_id),
    )


def deployed_identity_report(
    graph: Graph,
    bundle: DeploymentEvidenceBundle,
) -> dict[str, Any]:
    relationships = deployed_identity_relationships(graph, bundle)
    mapped_agents = {item.agent for item in relationships}
    return {
        "schema_version": DEPLOYED_IDENTITY_SCHEMA_VERSION,
        "provider": bundle.provider,
        "evidence_source": bundle.source,
        "runtime_effectiveness": "not_verified",
        "summary": {
            "workloads": len(bundle.workloads),
            "relationships": len(relationships),
            "agents_with_deployment": len(mapped_agents),
            "unresolved_relationships": sum(
                item.resolution != "fully_resolved" for item in relationships
            ),
        },
        "relationships": [item.as_dict() for item in relationships],
    }
