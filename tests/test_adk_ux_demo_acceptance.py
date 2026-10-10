"""Acceptance checks for the offline UX on a genuine vulnerable Google ADK scan."""

import json
from pathlib import Path

from scripts.run_adk_ux_demo import produce_report


def test_adk_vulnerable_demo_populates_interactive_security_report(tmp_path: Path) -> None:
    output = tmp_path / "review-artifacts"
    report, failures = produce_report(output)

    # A failure here indicates missing expected scanner evidence or report regressions,
    # not a reason to invent/fill in counts in the UX.
    assert not failures, (
        "The vulnerable ADK demo failed acceptance checks: " + ", ".join(failures)
    )
    projection = json.loads(
        (output / "adk-security-projection.json").read_text(encoding="utf-8")
    )
    metrics = json.loads(
        (output / "adk-acceptance-metrics.json").read_text(encoding="utf-8")
    )
    html = (output / "adk-security-workbench.html").read_text(encoding="utf-8")
    summary = (output / "adk-acceptance-summary.md").read_text(encoding="utf-8")

    assert projection == report
    assert projection["model"] == "horustrace.visual_report"
    assert metrics["attack_paths"] > 0
    assert metrics["mcp_servers"] > 0
    assert metrics["owasp_categories_with_runtime_findings"] > 0

    # The upgraded interface links to the actual scanner projection.
    assert "function severityChart(s)" in html
    assert "function authorityResolutionChart(agents)" in html
    assert "function owaspAssessmentChart(categories)" in html
    assert "function routeDrill(action)" in html
    assert "function renderOwasp(risk=" in html
    assert "function renderGraph(a)" in html
    assert "function renderAttack()" in html

    # HTML remains portable and offline; data is not fetched from a service.
    assert "default-src 'none'" in html
    assert "<script src=" not in html
    assert "<link rel=" not in html
    assert "## Acceptance checks" in summary
    assert "## Findings by severity" in summary
    assert "## Authority-resolution evidence" in summary
    assert "| Severity | Findings | Distribution |" in summary
    assert "| Status | Relationships |" in summary
