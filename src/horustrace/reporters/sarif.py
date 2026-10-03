from __future__ import annotations

from horustrace.assurance import build_assurance_report
from horustrace.models import Finding, FlowPath, ScanCoverage
from horustrace.owasp import build_owasp_agentic_summary
from horustrace.rule_registry import get_rule_metadata

LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _flow_id(finding: Finding) -> str | None:
    for evidence in finding.evidence:
        if evidence.startswith("flow_id="):
            return evidence.split("=", 1)[1]
    return None


def _sarif_code_flow(flow: FlowPath) -> dict | None:
    locations = []
    for step in flow.steps:
        if step.location is None:
            continue
        locations.append(
            {
                "location": {
                    "physicalLocation": {
                        "artifactLocation": {"uri": str(step.location.path)},
                        "region": {
                            "startLine": max(1, step.location.line),
                            "startColumn": max(1, step.location.column),
                        },
                    },
                    "message": {"text": f"{step.kind}: {step.label}"},
                }
            }
        )
    if len(locations) < 2:
        return None
    return {"threadFlows": [{"locations": locations}]}


def render(
    findings: list[Finding],
    coverage: ScanCoverage | None = None,
    controls: list[dict] | None = None,
    suppressed: list[Finding] | None = None,
    suppression_diagnostics: list[dict] | None = None,
    flow_paths: list[FlowPath] | None = None,
    disabled_rules: list[str] | None = None,
    authority_contract: dict | None = None,
) -> dict:
    rules: dict[str, dict] = {}
    results: list[dict] = []
    flows_by_id = {flow.flow_id: flow for flow in flow_paths or []}
    contract_report = authority_contract or {
        "summary": {
            "agents_with_contract": 0,
            "relationships_evaluated": 0,
            "compliant_relationships": 0,
            "violation_relationships": 0,
            "unresolved_relationships": 0,
            "violations": 0,
            "unresolved": 0,
        }
    }
    owasp_report = build_owasp_agentic_summary(
        findings,
        disabled_rules=disabled_rules or [],
    )
    assurance = build_assurance_report(findings, contract_report, owasp_report)

    for finding in findings:
        rules.setdefault(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "shortDescription": {"text": finding.title},
                "help": {"text": finding.recommendation},
                "properties": {"standards": finding.standards},
            },
        )
        try:
            default_severity = get_rule_metadata(finding.rule_id).default_severity.label()
        except KeyError:
            default_severity = finding.severity.label()
        result = {
            "ruleId": finding.rule_id,
            "level": LEVELS[finding.severity.label()],
            "message": {"text": finding.message},
            "properties": {
                "horustraceLayer": finding.layer,
                "default_severity": default_severity,
                "effective_severity": finding.severity.label(),
                "agent": finding.agent,
                "evidence": finding.evidence,
                "standards": finding.standards,
                "assessment": finding.assessment,
                "provenance": [fact.as_dict() for fact in finding.provenance],
                "limitations": finding.limitations,
                "fingerprint": finding.fingerprint,
                "confidence": finding.confidence.value if finding.confidence else None,
            },
        }
        if finding.fingerprint:
            result["partialFingerprints"] = {
                "horustrace/v1": finding.fingerprint,
            }
        if finding.location:
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": str(finding.location.path)},
                        "region": {
                            "startLine": max(1, finding.location.line),
                            "startColumn": max(1, finding.location.column),
                        },
                    }
                }
            ]
        flow_id = _flow_id(finding)
        if flow_id and flow_id in flows_by_id:
            code_flow = _sarif_code_flow(flows_by_id[flow_id])
            if code_flow:
                result["codeFlows"] = [code_flow]
        results.append(result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "HorusTrace",
                        "informationUri": "https://github.com/psandhir/horustrace",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                **({
                    "properties": {
                        "coverage": coverage.as_dict(),
                        "assurance": assurance,
                        "owasp_agentic": owasp_report,
                        "control_observations": controls or [],
                        "authority_contract": contract_report,
                        "flow_paths": [flow.as_dict() for flow in flow_paths or []],
                        "suppressions": {
                            "suppressed_findings": [f.as_dict() for f in suppressed or []],
                            "diagnostics": suppression_diagnostics or [],
                        },
                    },
                    "invocations": [{
                        "executionSuccessful": not coverage.incomplete,
                        "toolExecutionNotifications": [
                            {
                                "descriptor": {"id": d.diagnostic_id},
                                "level": "warning",
                                "message": {"text": d.message},
                                "properties": {
                                    "diagnostic_id": d.diagnostic_id,
                                    "kind": d.kind,
                                    "incomplete": d.incomplete,
                                },
                            }
                            for d in coverage.diagnostics
                        ],
                    }],
                } if coverage is not None else {}),
            }
        ],
    }
