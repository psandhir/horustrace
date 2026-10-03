"""Normalized assurance output shared by HorusTrace report surfaces."""

from __future__ import annotations

from collections import Counter
from typing import Any

from horustrace.models import Finding

ASSURANCE_SCHEMA_VERSION = 1
ASSURANCE_MODEL = "horustrace.assurance"


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(item.severity.label() for item in findings)
    return {
        level: counts[level]
        for level in ("critical", "high", "medium", "low", "info")
    }


def build_assurance_report(
    findings: list[Finding],
    authority_contract: dict[str, Any],
    owasp_agentic: dict[str, Any],
) -> dict[str, Any]:
    """Build the stable cross-renderer assurance summary.

    organization_policy summarizes enabled HorusTrace rules whose assessment is
    policy_violation. It is deliberately distinct from the repository-local
    Authority Contract and does not imply a separate central policy service.
    """

    policy_findings = [
        finding for finding in findings if finding.assessment == "policy_violation"
    ]
    contract_summary = authority_contract.get("summary", {})
    owasp_summary = owasp_agentic.get("summary", {})

    agents_with_contract = int(contract_summary.get("agents_with_contract") or 0)
    contract_violations = int(contract_summary.get("violations") or 0)
    contract_unresolved = int(contract_summary.get("unresolved") or 0)
    if contract_violations:
        contract_status = "violation"
    elif contract_unresolved:
        contract_status = "unresolved"
    elif agents_with_contract:
        contract_status = "compliant"
    else:
        contract_status = "not_declared"

    categories_with_findings = int(owasp_summary.get("categories_with_findings") or 0)
    categories_not_assessed = int(owasp_summary.get("categories_not_assessed") or 0)
    categories_with_detectors = int(
        owasp_summary.get("categories_with_mapped_detectors") or 0
    )
    if categories_with_findings:
        owasp_status = "finding"
    elif categories_with_detectors:
        owasp_status = "no_mapped_findings"
    else:
        owasp_status = "not_assessed"

    return {
        "schema_version": ASSURANCE_SCHEMA_VERSION,
        "model": ASSURANCE_MODEL,
        "security": {
            "status": "finding" if findings else "no_findings",
            "findings": len(findings),
            "severity": _severity_counts(findings),
            "affected_agents": sorted(
                {finding.agent for finding in findings if finding.agent}
            ),
        },
        "organization_policy": {
            "scope": "configured_horustrace_policy_rules",
            "status": "violation" if policy_findings else "no_violations",
            "violations": len(policy_findings),
            "severity": _severity_counts(policy_findings),
            "rule_ids": sorted({finding.rule_id for finding in policy_findings}),
            "affected_agents": sorted(
                {finding.agent for finding in policy_findings if finding.agent}
            ),
        },
        "authority_contract": {
            "status": contract_status,
            "agents_with_contract": agents_with_contract,
            "relationships_evaluated": int(
                contract_summary.get("relationships_evaluated") or 0
            ),
            "compliant_relationships": int(
                contract_summary.get("compliant_relationships") or 0
            ),
            "violation_relationships": int(
                contract_summary.get("violation_relationships") or 0
            ),
            "unresolved_relationships": int(
                contract_summary.get("unresolved_relationships") or 0
            ),
            "violations": contract_violations,
            "unresolved": contract_unresolved,
        },
        "owasp_agentic": {
            "standard": owasp_agentic.get("standard"),
            "status": owasp_status,
            "categories": int(owasp_summary.get("categories") or 0),
            "categories_with_mapped_detectors": categories_with_detectors,
            "categories_with_findings": categories_with_findings,
            "categories_with_runtime_findings": int(
                owasp_summary.get("categories_with_runtime_findings") or 0
            ),
            "categories_not_assessed": categories_not_assessed,
            "mapped_findings": int(owasp_summary.get("mapped_findings") or 0),
            "runtime_mapped_findings": int(
                owasp_summary.get("runtime_mapped_findings") or 0
            ),
        },
    }
