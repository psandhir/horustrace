from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from horustrace.assurance import build_assurance_report
from horustrace.authority_contract import authority_contract_report
from horustrace.models import Finding, Graph, Severity
from horustrace.owasp import build_owasp_agentic_summary
from horustrace.provenance import control_observations

LAYER_NAMES = {
    1: "Agent configuration",
    2: "Capability analysis",
    3: "Identity & permissions",
    4: "Data & network reachability",
    5: "Attack-path analysis",
}


def render(
    graph: Graph,
    findings: list[Finding],
    root: Path,
    authority_contract: dict[str, Any] | None = None,
) -> str:
    counts = Counter(f.severity for f in findings)
    layer_counts = Counter(f.layer for f in findings)
    source_context_counts = Counter(f.source_context for f in findings)
    excluded_source_context_counts = graph.configuration_audit.get(
        "excluded_findings_by_source_context",
        {},
    )
    flow_resolution = graph.coverage.resolution.get("flows", {})
    flow_reachability = flow_resolution.get("agent_reachability", {})
    contract_report = authority_contract or authority_contract_report(graph)
    contract_summary = contract_report["summary"]
    owasp_report = build_owasp_agentic_summary(
        findings,
        disabled_rules=graph.configuration_audit.get("disabled_rules", []),
    )
    assurance = build_assurance_report(findings, contract_report, owasp_report)
    lines = [
        "HorusTrace Security Scan",
        "=" * 23,
        f"Target:        {root}",
        f"Agents:        {len(graph.agents)}",
        f"Tools:         {len(graph.all_tools())}",
        f"Skills:        {len(graph.all_skills())} "
        f"(bound={sum(len(agent.skills) for agent in graph.agents)}, "
        f"unbound={len(graph.unbound_skills)})",
        f"MCP servers:   {len(graph.all_mcp_servers())}",
        f"Identities:    {len(graph.all_identities())}",
        f"Flows:         {len(graph.flow_paths)}",
        (
            "  Reachability: "
            f"agent={flow_reachability.get('proven_agent_reachable', 0)}, "
            f"non-agent={flow_reachability.get('proven_non_agent', 0)}, "
            f"unknown={flow_reachability.get('unknown', 0)}"
        ),
        (
            "  Attribution gaps: "
            f"{flow_resolution.get('agent_attribution_gaps', 0)}"
        ),
        f"Attack paths:  {len(graph.attack_paths)}",
        "",
        "Findings",
        f"  Critical: {counts[Severity.CRITICAL]}",
        f"  High:     {counts[Severity.HIGH]}",
        f"  Medium:   {counts[Severity.MEDIUM]}",
        f"  Low:      {counts[Severity.LOW]}",
        "",
        "Findings by analysis layer",
    ]
    for layer in range(1, 6):
        lines.append(f"  L{layer} {LAYER_NAMES[layer]}: {layer_counts[layer]} finding(s)")
    lines.extend(["", "Findings by source context"])
    for source_context in (
        "runtime",
        "test",
        "example",
        "tutorial",
        "notebook",
        "template-generated",
        "unknown",
    ):
        lines.append(
            f"  {source_context}: {source_context_counts[source_context]} finding(s)"
        )
    if excluded_source_context_counts:
        lines.append(
            "  Excluded by source-context filter: "
            + ", ".join(
                f"{context}={count}"
                for context, count in sorted(excluded_source_context_counts.items())
            )
        )
    lines.append("")

    policy = assurance["organization_policy"]
    lines.extend([
        "Organisation policy assessment",
        f"  Status: {policy['status']}",
        f"  Policy violations: {policy['violations']}",
        (
            "  Triggered policy rules: "
            + (", ".join(policy["rule_ids"]) if policy["rule_ids"] else "none")
        ),
        (
            "  Affected agents: "
            + (
                ", ".join(policy["affected_agents"])
                if policy["affected_agents"]
                else "none"
            )
        ),
        "  Scope: configured HorusTrace rules classified as policy_violation",
        "",
    ])

    contract_assurance = assurance["authority_contract"]
    lines.extend([
        "Authority Contract assessment",
        f"  Status: {contract_assurance['status']}",
        f"  Agents with contract: {contract_summary['agents_with_contract']}",
        f"  Relationships evaluated: {contract_summary['relationships_evaluated']}",
        f"  Compliant relationships: {contract_summary['compliant_relationships']}",
        f"  Violation relationships: {contract_summary['violation_relationships']}",
        f"  Unresolved relationships: {contract_summary['unresolved_relationships']}",
        f"  Violations: {contract_summary['violations']}",
        f"  Unresolved clauses: {contract_summary['unresolved']}",
        "  Runtime effectiveness: not_verified",
    ])
    for item in contract_report["violations"]:
        lines.append(
            "  VIOLATION "
            f"agent={item['agent']} "
            f"target={item['target']['kind']}:{item['target']['name']} "
            f"clause={item['clause']} reason={item['reason']}"
        )
    for item in contract_report["unresolved"]:
        lines.append(
            "  UNRESOLVED "
            f"agent={item['agent']} "
            f"target={item['target']['kind']}:{item['target']['name']} "
            f"clause={item['clause']} reason={item['reason']}"
        )
    lines.append("")

    lines.extend([
        "OWASP Agentic Top 10 status",
        (
            "  Categories with findings: "
            f"{owasp_report['summary']['categories_with_findings']} / "
            f"{owasp_report['summary']['categories']}"
        ),
        (
            "  Categories with runtime findings: "
            f"{owasp_report['summary']['categories_with_runtime_findings']}"
        ),
        f"  Categories not assessed: {owasp_report['summary']['categories_not_assessed']}",
    ])
    for item in owasp_report["categories"]:
        status = str(item["runtime_status"]).replace("_", " ").upper()
        detail = (
            f"; runtime={item['runtime_finding_count']}; total={item['finding_count']}"
            if item["finding_count"]
            else ""
        )
        lines.append(f"  {item['id']} {item['title']}: {status}{detail}")
    lines.append("")

    if graph.suppressed_findings or graph.suppression_diagnostics:
        lines.append("Suppressions")
        lines.append(f"  Findings suppressed: {len(graph.suppressed_findings)}")
        for diagnostic in graph.suppression_diagnostics:
            suffix = f" ({diagnostic.get('matches', 0)} match(es))" if "matches" in diagnostic else ""
            lines.append(f"  {diagnostic['id']}: {diagnostic['status']}{suffix}; "
                         f"expires {diagnostic['expires']}; reason: {diagnostic['reason']}")
        lines.append("")

    coverage = graph.coverage
    lines.extend([
        "Scan coverage",
        f"  Files considered: {coverage.files_considered}",
        (f"  Files scanned: {coverage.files_scanned}; skipped: {coverage.files_skipped}; "
         f"failed: {coverage.files_failed}"),
        "  Analysis status: " + ("incomplete" if coverage.incomplete else "no detected gaps"),
    ])
    for diagnostic in coverage.diagnostics:
        location = diagnostic.location
        prefix = f"{location.path}:{location.line}: " if location else ""
        lines.append(f"  {diagnostic.code}: {prefix}{diagnostic.message}")
    lines.append("")

    controls = control_observations(graph)
    if controls:
        lines.append("Control observations (runtime effectiveness not verified)")
        for control in controls:
            lines.append(f"  {control['subject']}: {control['control']} "
                         f"{control['configuration']}")
        lines.append("")

    if not findings:
        if graph.suppressed_findings:
            lines.append(
                f"No active findings; {len(graph.suppressed_findings)} finding(s) suppressed."
            )
        else:
            lines.append("No findings detected by the current rule set.")
        return "\n".join(lines)

    for finding in findings:
        location = ""
        if finding.location:
            location = f"{finding.location.path}:{finding.location.line}"
        lines.extend(
            [
                f"[{finding.severity.name}] L{finding.layer} {finding.rule_id} — {finding.title}",
                f"Location: {location or 'n/a'}",
                f"Agent:    {finding.agent or 'n/a'}",
                f"Assessment: {finding.assessment}",
                f"Fingerprint: {finding.fingerprint or 'n/a'}",
                finding.message,
            ]
        )
        owasp_agentic = finding.standards.get("owasp_agentic", [])
        if owasp_agentic:
            lines.append("OWASP Agentic: " + ", ".join(owasp_agentic))
        if finding.confidence is not None:
            lines.append(f"Confidence: {finding.confidence.value}")
        if finding.evidence:
            lines.append("Evidence: " + " | ".join(finding.evidence))
        if finding.provenance:
            counts = Counter(fact.origin for fact in finding.provenance)
            lines.append("Evidence origins: " + ", ".join(
                f"{origin} ({count})" for origin, count in sorted(counts.items())
            ))
        for limitation in finding.limitations:
            lines.append("Limit: " + limitation)
        lines.append("Fix: " + finding.recommendation)
        lines.append("")
    return "\n".join(lines).rstrip()
