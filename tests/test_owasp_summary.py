import json
from pathlib import Path

from horustrace.cli import main
from horustrace.models import Finding, Severity
from horustrace.owasp import build_owasp_agentic_summary, render_owasp_agentic_console


def _category(report: dict, risk_id: str) -> dict:
    return next(item for item in report["categories"] if item["id"] == risk_id)


def _finding(*, rule_id: str, risk_id: str, source_context: str, agent: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=Severity.HIGH,
        title="test",
        message="test",
        recommendation="test",
        source_context=source_context,
        agent=agent,
        standards={"owasp_agentic": [risk_id]},
    )


def test_owasp_summary_distinguishes_findings_no_findings_and_not_assessed(
    tmp_path: Path,
    capsys,
) -> None:
    (tmp_path / "agent.py").write_text(
        "from agents import Agent, ShellTool\n"
        "agent = Agent(name='ops', tools=[ShellTool()])\n",
        encoding="utf-8",
    )

    assert main(["owasp", str(tmp_path), "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)

    assert report["standard"] == "OWASP Top 10 for Agentic Applications 2026"
    assert _category(report, "ASI05")["status"] == "finding"
    assert _category(report, "ASI05")["runtime_status"] == "no_runtime_findings"
    assert "AGT020" in _category(report, "ASI05")["finding_rule_ids"]
    assert _category(report, "ASI06")["status"] == "no_mapped_findings"
    assert _category(report, "ASI06")["runtime_status"] == "no_mapped_findings"
    assert "PATH007" in _category(report, "ASI06")["mapped_rules"]
    assert _category(report, "ASI08")["status"] == "not_assessed"
    assert _category(report, "ASI08")["runtime_status"] == "not_assessed"
    assert _category(report, "ASI09")["status"] == "no_mapped_findings"
    assert _category(report, "ASI09")["runtime_status"] == "no_mapped_findings"
    assert "SKL020" in _category(report, "ASI09")["mapped_rules"]
    assert _category(report, "ASI10")["status"] == "no_mapped_findings"
    assert _category(report, "ASI10")["runtime_status"] == "no_mapped_findings"
    assert "SKL021" in _category(report, "ASI10")["mapped_rules"]


def test_owasp_summary_breaks_down_runtime_and_non_runtime_findings() -> None:
    findings = [
        _finding(
            rule_id="AGT020",
            risk_id="ASI05",
            source_context="runtime",
            agent="runtime-agent",
        ),
        _finding(
            rule_id="ADK003",
            risk_id="ASI05",
            source_context="test",
            agent="test-agent",
        ),
        _finding(
            rule_id="ADK004",
            risk_id="ASI05",
            source_context="example",
            agent="example-agent",
        ),
        _finding(
            rule_id="ADK012",
            risk_id="ASI05",
            source_context="unknown",
            agent="unknown-agent",
        ),
    ]

    report = build_owasp_agentic_summary(findings)
    asi05 = _category(report, "ASI05")

    assert asi05["status"] == "finding"
    assert asi05["runtime_status"] == "finding"
    assert asi05["finding_count"] == 4
    assert asi05["runtime_finding_count"] == 1
    assert asi05["non_runtime_finding_count"] == 2
    assert asi05["unknown_source_context_finding_count"] == 1
    assert asi05["source_contexts"]["runtime"] == 1
    assert asi05["source_contexts"]["test"] == 1
    assert asi05["source_contexts"]["example"] == 1
    assert asi05["source_contexts"]["unknown"] == 1
    assert asi05["runtime_finding_rule_ids"] == ["AGT020"]
    assert asi05["runtime_affected_agents"] == ["runtime-agent"]
    assert report["summary"]["mapped_findings"] == 4
    assert report["summary"]["runtime_mapped_findings"] == 1
    assert report["summary"]["categories_with_runtime_findings"] == 1


def test_owasp_summary_marks_non_runtime_only_category_without_hiding_findings() -> None:
    finding = _finding(
        rule_id="AGT050",
        risk_id="ASI04",
        source_context="notebook",
        agent="notebook-agent",
    )

    report = build_owasp_agentic_summary([finding])
    asi04 = _category(report, "ASI04")

    assert asi04["status"] == "finding"
    assert asi04["runtime_status"] == "no_runtime_findings"
    assert asi04["finding_count"] == 1
    assert asi04["runtime_finding_count"] == 0
    assert asi04["source_contexts"]["notebook"] == 1
    assert report["summary"]["categories_with_only_non_runtime_or_unknown_findings"] == 1

    console = render_owasp_agentic_console([finding])
    assert "ASI04  Agentic Supply Chain Vulnerabilities: NO RUNTIME FINDINGS" in console
    assert "Source contexts: notebook=1" in console


def test_owasp_summary_treats_fully_disabled_category_as_not_assessed() -> None:
    report = build_owasp_agentic_summary(
        [],
        disabled_rules=["AGT050", "AGT051", "SKL029"],
    )
    asi04 = _category(report, "ASI04")

    assert asi04["status"] == "not_assessed"
    assert asi04["runtime_status"] == "not_assessed"
    assert asi04["mapped_rules"] == []
    assert asi04["disabled_mapped_rules"] == ["AGT050", "AGT051", "SKL029"]
    assert asi04["available_mapped_rules"] == ["AGT050", "AGT051", "SKL029"]


def test_scan_json_includes_owasp_summary(tmp_path: Path, capsys) -> None:
    (tmp_path / "agent.py").write_text(
        "from agents import Agent, ShellTool\n"
        "agent = Agent(name='ops', tools=[ShellTool()])\n",
        encoding="utf-8",
    )

    assert main(["scan", str(tmp_path), "--format", "json", "--fail-on", "none"]) == 0
    report = json.loads(capsys.readouterr().out)

    assert report["owasp_agentic"]["summary"]["categories"] == 10
    assert "runtime_mapped_findings" in report["owasp_agentic"]["summary"]
    assert _category(report["owasp_agentic"], "ASI05")["status"] == "finding"
    asi05 = _category(report["owasp_agentic"], "ASI05")
    assert sum(asi05["source_contexts"].values()) == asi05["finding_count"]


def test_scan_console_shows_owasp_mapping_on_finding(tmp_path: Path, capsys) -> None:
    (tmp_path / "agent.py").write_text(
        "from agents import Agent, ShellTool\n"
        "agent = Agent(name='ops', tools=[ShellTool()])\n",
        encoding="utf-8",
    )

    assert main(["scan", str(tmp_path), "--fail-on", "none"]) == 0
    output = capsys.readouterr().out

    assert "OWASP Agentic: ASI05" in output


def test_sarif_run_properties_include_owasp_summary(tmp_path: Path, capsys) -> None:
    (tmp_path / "agent.py").write_text(
        "from agents import Agent, ShellTool\n"
        "agent = Agent(name='ops', tools=[ShellTool()])\n",
        encoding="utf-8",
    )

    assert main(["scan", str(tmp_path), "--format", "sarif", "--fail-on", "none"]) == 0
    sarif = json.loads(capsys.readouterr().out)
    report = sarif["runs"][0]["properties"]["owasp_agentic"]

    assert _category(report, "ASI05")["status"] == "finding"
    assert _category(report, "ASI05")["runtime_status"] == "no_runtime_findings"
    assert _category(report, "ASI08")["status"] == "not_assessed"
