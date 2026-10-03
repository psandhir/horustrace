from horustrace.assurance import ASSURANCE_MODEL, build_assurance_report
from horustrace.models import Finding, Severity


def _contract(*, agents: int = 1, violations: int = 0, unresolved: int = 0) -> dict:
    return {
        "summary": {
            "agents_with_contract": agents,
            "relationships_evaluated": 2,
            "compliant_relationships": 1,
            "violation_relationships": violations,
            "unresolved_relationships": unresolved,
            "violations": violations,
            "unresolved": unresolved,
        }
    }


def _owasp() -> dict:
    return {
        "standard": "OWASP Top 10 for Agentic Applications 2026",
        "summary": {
            "categories": 10,
            "categories_with_mapped_detectors": 7,
            "categories_with_findings": 2,
            "categories_with_runtime_findings": 1,
            "categories_not_assessed": 3,
            "mapped_findings": 3,
            "runtime_mapped_findings": 2,
        },
    }


def test_assurance_separates_policy_contract_and_owasp_posture() -> None:
    findings = [
        Finding(
            rule_id="CAP002",
            severity=Severity.CRITICAL,
            title="Denied capability",
            message="process.execute is denied",
            recommendation="Remove process execution.",
            agent="ops",
            assessment="policy_violation",
            standards={"owasp_agentic": ["ASI02"]},
        ),
        Finding(
            rule_id="AGT020",
            severity=Severity.HIGH,
            title="Process execution",
            message="Process execution lacks approval",
            recommendation="Require approval.",
            agent="ops",
            assessment="static_configuration",
            standards={"owasp_agentic": ["ASI05"]},
        ),
    ]

    report = build_assurance_report(
        findings,
        _contract(violations=1),
        _owasp(),
    )

    assert report["model"] == ASSURANCE_MODEL
    assert report["security"]["findings"] == 2
    assert report["organization_policy"]["status"] == "violation"
    assert report["organization_policy"]["violations"] == 1
    assert report["organization_policy"]["rule_ids"] == ["CAP002"]
    assert report["organization_policy"]["affected_agents"] == ["ops"]
    assert report["authority_contract"]["status"] == "violation"
    assert report["authority_contract"]["violations"] == 1
    assert report["owasp_agentic"]["status"] == "finding"
    assert report["owasp_agentic"]["categories_with_findings"] == 2
    assert report["owasp_agentic"]["categories_not_assessed"] == 3


def test_assurance_reports_contract_not_declared_separately() -> None:
    report = build_assurance_report(
        [],
        _contract(agents=0),
        {
            "standard": "OWASP Top 10 for Agentic Applications 2026",
            "summary": {
                "categories": 10,
                "categories_with_mapped_detectors": 7,
                "categories_with_findings": 0,
                "categories_with_runtime_findings": 0,
                "categories_not_assessed": 3,
                "mapped_findings": 0,
                "runtime_mapped_findings": 0,
            },
        },
    )

    assert report["organization_policy"]["status"] == "no_violations"
    assert report["authority_contract"]["status"] == "not_declared"
    assert report["owasp_agentic"]["status"] == "no_mapped_findings"
