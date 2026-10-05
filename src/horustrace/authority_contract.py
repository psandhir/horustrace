"""Evaluate Effective Authority Relationship v1 against Authority Contract v1.

The evaluator is deliberately evidence-sensitive. A constrained authority dimension with
insufficient static evidence is reported as unresolved rather than silently passing or
being converted into a policy violation.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from horustrace.effective_authority import (
    EffectiveAuthorityRelationship,
    effective_authority_relationships,
)
from horustrace.heuristics import matches_any
from horustrace.models import Agent, AuthorityContract, AuthorityScope, Graph, MCPToolContract

AUTHORITY_CONTRACT_EVALUATION_SCHEMA_VERSION = 1


def _stable_result_id(
    status: str,
    relationship_id: str,
    clause: str,
    reason: str,
) -> str:
    # Result identifiers intentionally exclude observed/expected authority values.
    # Those values can include credentials, principals, tokens, or other sensitive
    # policy evidence and should never become hash inputs merely to fingerprint a
    # finding. Relationship + clause + reason is sufficient for stable identity.
    payload = json.dumps(
        {
            "status": status,
            "relationship_id": relationship_id,
            "clause": clause,
            "reason": reason,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]
    prefix = "contract-violation-v1" if status == "violation" else "contract-unresolved-v1"
    return f"{prefix}:{digest}"


@dataclass(frozen=True, slots=True)
class AuthorityContractResult:
    result_id: str
    status: str
    authority_relationship_id: str
    agent: str
    target_kind: str
    target_name: str
    clause: str
    dimension: str
    reason: str
    expected: tuple[str, ...]
    observed: tuple[str, ...]
    relationship_location: dict[str, Any] | None
    contract_location: dict[str, Any] | None
    explanation: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "result_id": self.result_id,
            "status": self.status,
            "authority_relationship_id": self.authority_relationship_id,
            "agent": self.agent,
            "target": {"kind": self.target_kind, "name": self.target_name},
            "clause": self.clause,
            "dimension": self.dimension,
            "reason": self.reason,
            "expected": list(self.expected),
            "observed": list(self.observed),
            "runtime_effectiveness": "not_verified",
            "relationship_location": self.relationship_location,
            "contract_location": self.contract_location,
            "explanation": self.explanation,
        }


def _location_dict(location: Any) -> dict[str, Any] | None:
    if location is None:
        return None
    return {
        "path": str(location.path),
        "line": location.line,
        "column": location.column,
    }


def _contract_location(
    contract: AuthorityContract,
    clause: str,
) -> dict[str, Any] | None:
    exact = contract.clause_locations.get(clause)
    return _location_dict(exact or contract.location)


def _sorted_documents(values: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        (dict(value) for value in values),
        key=lambda item: json.dumps(item, sort_keys=True, default=str),
    )


def _explanation(
    relationship: EffectiveAuthorityRelationship,
    contract: AuthorityContract,
    *,
    clause: str,
    dimension: str,
    expected: tuple[str, ...],
    observed: tuple[str, ...],
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "policy": {
            "clause": clause,
            "dimension": dimension,
            "location": _contract_location(contract, clause),
            "expected": list(expected),
        },
        "authority": {
            "relationship_id": relationship.relationship_id,
            "agent": relationship.agent,
            "target": {
                "kind": relationship.target_kind,
                "name": relationship.target_name,
            },
            "location": relationship.location,
            "resolution": relationship.resolution,
            "dimensions": dict(sorted(relationship.dimensions.items())),
            "observed": list(observed),
        },
        "identity": dict(relationship.identity) if relationship.identity else None,
        "control": dict(relationship.approval),
        "resources": _sorted_documents(relationship.resources),
        "destinations": _sorted_documents(relationship.destinations),
        "mcp_tool_scope": (
            dict(relationship.tool_scope)
            if relationship.tool_scope is not None
            else None
        ),
        "source_evidence": _sorted_documents(relationship.evidence),
        "unresolved_dimensions": sorted(relationship.unresolved),
        "runtime_effectiveness": "not_verified",
    }


def _result(
    *,
    status: str,
    relationship: EffectiveAuthorityRelationship,
    contract: AuthorityContract,
    clause: str,
    dimension: str,
    reason: str,
    expected: Iterable[str],
    observed: Iterable[str],
) -> AuthorityContractResult:
    expected_values = tuple(sorted(set(expected)))
    observed_values = tuple(sorted(set(observed)))
    return AuthorityContractResult(
        result_id=_stable_result_id(
            status,
            relationship.relationship_id,
            clause,
            reason,
        ),
        status=status,
        authority_relationship_id=relationship.relationship_id,
        agent=relationship.agent,
        target_kind=relationship.target_kind,
        target_name=relationship.target_name,
        clause=clause,
        dimension=dimension,
        reason=reason,
        expected=expected_values,
        observed=observed_values,
        relationship_location=relationship.location,
        contract_location=_contract_location(contract, clause),
        explanation=_explanation(
            relationship,
            contract,
            clause=clause,
            dimension=dimension,
            expected=expected_values,
            observed=observed_values,
        ),
    )


def _constrained(scope: AuthorityScope, dimension: str) -> set[str]:
    return set(getattr(scope, dimension))


def _evaluate_string_dimension(
    relationship: EffectiveAuthorityRelationship,
    contract: AuthorityContract,
    *,
    dimension: str,
    observed: Iterable[str] | None,
    evidence_status: str,
) -> list[AuthorityContractResult]:
    allowed = _constrained(contract.allow, dimension)
    denied = _constrained(contract.deny, dimension)
    if not allowed and not denied:
        return []

    if evidence_status == "unknown" or observed is None:
        results: list[AuthorityContractResult] = []
        if allowed:
            results.append(
                _result(
                    status="unresolved",
                    relationship=relationship,
                    contract=contract,
                    clause=f"allow.{dimension}",
                    dimension=dimension,
                    reason=f"{dimension}_evidence_unknown",
                    expected=allowed,
                    observed=[],
                )
            )
        if denied:
            results.append(
                _result(
                    status="unresolved",
                    relationship=relationship,
                    contract=contract,
                    clause=f"deny.{dimension}",
                    dimension=dimension,
                    reason=f"{dimension}_evidence_unknown",
                    expected=denied,
                    observed=[],
                )
            )
        return results

    values = sorted(set(observed))
    results = []
    denied_values = [value for value in values if matches_any(value, sorted(denied))]
    if denied_values:
        results.append(
            _result(
                status="violation",
                relationship=relationship,
                contract=contract,
                clause=f"deny.{dimension}",
                dimension=dimension,
                reason=f"denied_{dimension}_observed",
                expected=denied,
                observed=denied_values,
            )
        )
    if allowed:
        outside = [value for value in values if not matches_any(value, sorted(allowed))]
        if outside:
            results.append(
                _result(
                    status="violation",
                    relationship=relationship,
                    contract=contract,
                    clause=f"allow.{dimension}",
                    dimension=dimension,
                    reason=f"{dimension}_outside_allowlist",
                    expected=allowed,
                    observed=outside,
                )
            )
    return results


def _identity_results(
    relationship: EffectiveAuthorityRelationship,
    contract: AuthorityContract,
) -> list[AuthorityContractResult]:
    constrained_dimensions = (
        "identities",
        "iam_roles",
        "permissions",
        "oauth_scopes",
    )
    if not any(
        _constrained(contract.allow, dimension) or _constrained(contract.deny, dimension)
        for dimension in constrained_dimensions
    ):
        return []

    identity_status = relationship.dimensions.get("identity", "unknown")
    if relationship.identity is None or identity_status == "unknown":
        results: list[AuthorityContractResult] = []
        for dimension in constrained_dimensions:
            results.extend(
                _evaluate_string_dimension(
                    relationship,
                    contract,
                    dimension=dimension,
                    observed=None,
                    evidence_status="unknown",
                )
            )
        return results

    identity = relationship.identity
    mapping = {
        "identities": [str(identity.get("name"))] if identity.get("name") else [],
        "iam_roles": list(identity.get("roles") or []),
        "permissions": list(identity.get("permissions") or []),
        "oauth_scopes": list(identity.get("oauth_scopes") or []),
    }
    results = []
    for dimension, values in mapping.items():
        results.extend(
            _evaluate_string_dimension(
                relationship,
                contract,
                dimension=dimension,
                observed=values,
                evidence_status="resolved",
            )
        )
    return results


def _approval_results(
    relationship: EffectiveAuthorityRelationship,
    contract: AuthorityContract,
) -> list[AuthorityContractResult]:
    required = set(relationship.capabilities) & contract.require_approval_for
    if not required:
        return []

    approval = relationship.approval or {}
    state = approval.get("required")
    if state is True:
        return []
    if state is False:
        return [
            _result(
                status="violation",
                relationship=relationship,
                contract=contract,
                clause="require_approval_for",
                dimension="approval",
                reason="required_approval_explicitly_disabled",
                expected=required,
                observed=["approval=false"],
            )
        ]
    return [
        _result(
            status="unresolved",
            relationship=relationship,
            contract=contract,
            clause="require_approval_for",
            dimension="approval",
            reason="required_approval_not_proven",
            expected=required,
            observed=[],
        )
    ]


def _skill_results(
    relationship: EffectiveAuthorityRelationship,
    contract: AuthorityContract,
) -> list[AuthorityContractResult]:
    """Evaluate only the source-proven Skill binding dimension.

    A SKILL.md allowed-tools declaration is intentionally not promoted into
    effective capabilities. Dynamic/remote catalogues remain unresolved when a
    contract constrains the Skill surface.
    """
    if relationship.target_kind == "skill":
        return _evaluate_string_dimension(
            relationship,
            contract,
            dimension="skills",
            observed=[relationship.target_name],
            evidence_status="resolved",
        )
    if relationship.target_kind == "skill_catalogue":
        return _evaluate_string_dimension(
            relationship,
            contract,
            dimension="skills",
            observed=None,
            evidence_status="unknown",
        )
    return []


def _mcp_server_results(
    relationship: EffectiveAuthorityRelationship,
    contract: AuthorityContract,
) -> list[AuthorityContractResult]:
    if relationship.target_kind != "mcp_server":
        return []
    return _evaluate_string_dimension(
        relationship,
        contract,
        dimension="mcp_servers",
        observed=[relationship.target_name],
        evidence_status="resolved",
    )


def _mcp_tool_contract(
    contract: AuthorityContract,
    server: str,
) -> MCPToolContract | None:
    return next((item for item in contract.mcp_tools if item.server == server), None)


def _mcp_tool_results(
    relationship: EffectiveAuthorityRelationship,
    contract: AuthorityContract,
) -> list[AuthorityContractResult]:
    if relationship.target_kind != "mcp_server":
        return []
    policy = _mcp_tool_contract(contract, relationship.target_name)
    if policy is None:
        return []

    scope = relationship.tool_scope or {}
    scope_kind = str(scope.get("scope") or "unknown")
    observed_allowed = set(scope.get("allowed") or [])
    observed_denied = set(scope.get("denied") or [])
    results: list[AuthorityContractResult] = []

    if policy.allowed_tools:
        if scope_kind == "explicit_allowlist":
            outside = sorted(observed_allowed - policy.allowed_tools)
            if outside:
                results.append(
                    _result(
                        status="violation",
                        relationship=relationship,
                        contract=contract,
                        clause=f"mcp_tools.{policy.server}.allow",
                        dimension="mcp_tools",
                        reason="mcp_tools_outside_allowlist",
                        expected=policy.allowed_tools,
                        observed=outside,
                    )
                )
        elif scope_kind in {"unrestricted_or_unknown", "denylist_only"}:
            results.append(
                _result(
                    status="violation",
                    relationship=relationship,
                    contract=contract,
                    clause=f"mcp_tools.{policy.server}.allow",
                    dimension="mcp_tools",
                    reason="mcp_explicit_allowlist_not_enforced",
                    expected=policy.allowed_tools,
                    observed=[scope_kind],
                )
            )
        else:
            results.append(
                _result(
                    status="unresolved",
                    relationship=relationship,
                    contract=contract,
                    clause=f"mcp_tools.{policy.server}.allow",
                    dimension="mcp_tools",
                    reason="mcp_tool_filter_dynamic_or_unknown",
                    expected=policy.allowed_tools,
                    observed=[scope_kind],
                )
            )

    if policy.denied_tools:
        if observed_allowed & policy.denied_tools:
            results.append(
                _result(
                    status="violation",
                    relationship=relationship,
                    contract=contract,
                    clause=f"mcp_tools.{policy.server}.deny",
                    dimension="mcp_tools",
                    reason="denied_mcp_tool_explicitly_allowed",
                    expected=policy.denied_tools,
                    observed=observed_allowed & policy.denied_tools,
                )
            )
        elif scope_kind == "explicit_allowlist" or policy.denied_tools <= observed_denied:
            pass
        else:
            results.append(
                _result(
                    status="unresolved",
                    relationship=relationship,
                    contract=contract,
                    clause=f"mcp_tools.{policy.server}.deny",
                    dimension="mcp_tools",
                    reason="denied_mcp_tool_absence_not_proven",
                    expected=policy.denied_tools,
                    observed=observed_denied,
                )
            )
    return results


def evaluate_relationship(
    relationship: EffectiveAuthorityRelationship,
    contract: AuthorityContract,
) -> list[AuthorityContractResult]:
    results: list[AuthorityContractResult] = []
    if relationship.target_kind in {"skill", "skill_catalogue"}:
        results.extend(_skill_results(relationship, contract))
        return sorted(
            results,
            key=lambda item: (
                item.status,
                item.clause,
                item.reason,
                item.result_id,
            ),
        )


    results.extend(
        _evaluate_string_dimension(
            relationship,
            contract,
            dimension="capabilities",
            observed=relationship.capabilities,
            evidence_status=relationship.dimensions.get("capabilities", "unknown"),
        )
    )
    results.extend(_identity_results(relationship, contract))
    results.extend(
        _evaluate_string_dimension(
            relationship,
            contract,
            dimension="resources",
            observed=[str(item.get("selector")) for item in relationship.resources],
            evidence_status=relationship.dimensions.get("resources", "unknown"),
        )
    )
    results.extend(
        _evaluate_string_dimension(
            relationship,
            contract,
            dimension="destinations",
            observed=[str(item.get("target")) for item in relationship.destinations],
            evidence_status=relationship.dimensions.get("destinations", "unknown"),
        )
    )
    results.extend(_mcp_server_results(relationship, contract))
    results.extend(_approval_results(relationship, contract))
    results.extend(_mcp_tool_results(relationship, contract))

    return sorted(
        results,
        key=lambda item: (
            item.status,
            item.clause,
            item.reason,
            item.result_id,
        ),
    )


def authority_contract_report(graph: Graph) -> dict[str, Any]:
    agents: dict[str, Agent] = {agent.name: agent for agent in graph.agents}
    relationships = effective_authority_relationships(graph)
    results: list[AuthorityContractResult] = []
    relationship_evaluations: list[dict[str, Any]] = []

    for relationship in relationships:
        agent = agents.get(relationship.agent)
        contract = agent.policy.authority if agent is not None else None
        if contract is None:
            continue
        relationship_results = evaluate_relationship(relationship, contract)
        results.extend(relationship_results)
        violations = sum(item.status == "violation" for item in relationship_results)
        unresolved = sum(item.status == "unresolved" for item in relationship_results)
        status = "violation" if violations else "unresolved" if unresolved else "compliant"
        relationship_evaluations.append(
            {
                "authority_relationship_id": relationship.relationship_id,
                "agent": relationship.agent,
                "target": {
                    "kind": relationship.target_kind,
                    "name": relationship.target_name,
                },
                "status": status,
                "violations": violations,
                "unresolved": unresolved,
                "runtime_effectiveness": "not_verified",
            }
        )

    results = sorted(
        results,
        key=lambda item: (
            item.agent,
            item.target_kind,
            item.target_name,
            item.status,
            item.clause,
            item.result_id,
        ),
    )
    relationship_evaluations = sorted(
        relationship_evaluations,
        key=lambda item: (
            item["agent"],
            item["target"]["kind"],
            item["target"]["name"],
            item["authority_relationship_id"],
        ),
    )
    violations = [item for item in results if item.status == "violation"]
    unresolved = [item for item in results if item.status == "unresolved"]
    return {
        "schema_version": AUTHORITY_CONTRACT_EVALUATION_SCHEMA_VERSION,
        "runtime_effectiveness": "not_verified",
        "summary": {
            "agents_with_contract": sum(
                agent.policy.authority is not None for agent in graph.agents
            ),
            "relationships_evaluated": len(relationship_evaluations),
            "compliant_relationships": sum(
                item["status"] == "compliant" for item in relationship_evaluations
            ),
            "violation_relationships": sum(
                item["status"] == "violation" for item in relationship_evaluations
            ),
            "unresolved_relationships": sum(
                item["status"] == "unresolved" for item in relationship_evaluations
            ),
            "violations": len(violations),
            "unresolved": len(unresolved),
        },
        "relationships": relationship_evaluations,
        "violations": [item.as_dict() for item in violations],
        "unresolved": [item.as_dict() for item in unresolved],
    }
