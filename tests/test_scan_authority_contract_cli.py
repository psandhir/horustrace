import json
from pathlib import Path

from horustrace import cli
from horustrace.models import (
    Agent,
    AgentPolicy,
    AuthorityContract,
    AuthorityScope,
    Graph,
    Tool,
)


def _violation_graph() -> Graph:
    return Graph(
        agents=[
            Agent(
                name="support",
                tools=[
                    Tool(
                        name="shell",
                        kind="function",
                        capabilities={"process.execute"},
                        approval=True,
                    )
                ],
                policy=AgentPolicy(
                    authority=AuthorityContract(
                        deny=AuthorityScope(capabilities={"process.execute"}),
                    )
                ),
            )
        ]
    )


def _missing_contract_graph() -> Graph:
    return Graph(agents=[Agent(name="unmanaged")])


def _unresolved_graph() -> Graph:
    return Graph(
        agents=[
            Agent(
                name="support",
                tools=[
                    Tool(
                        name="read",
                        kind="function",
                        capabilities={"data.read"},
                        approval=True,
                    )
                ],
                policy=AgentPolicy(
                    authority=AuthorityContract(
                        allow=AuthorityScope(identities={"support-bot"}),
                    )
                ),
            )
        ]
    )


def test_scan_json_includes_separate_authority_contract_assessment(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    monkeypatch.setattr(cli, "scan", lambda *_args, **_kwargs: (_violation_graph(), []))

    result = cli.main(
        [
            "scan",
            str(tmp_path),
            "--format",
            "json",
            "--fail-on",
            "none",
        ]
    )

    assert result == 0
    report = json.loads(capsys.readouterr().out)
    assert report["findings"] == []
    assert report["authority_contract"]["summary"]["agents_with_contract"] == 1
    assert report["authority_contract"]["summary"]["violations"] == 1
    assert report["authority_contract"]["violations"][0]["clause"] == "deny.capabilities"
    assert report["summary"]["authority_contract_violations"] == 1
    assert report["assurance"]["authority_contract"]["status"] == "violation"
    assert report["assurance"]["organization_policy"]["status"] == "no_violations"
    assert report["assurance"]["owasp_agentic"]["categories"] == 10


def test_scan_policy_violation_gate_is_independent_of_finding_severity(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(cli, "scan", lambda *_args, **_kwargs: (_violation_graph(), []))

    result = cli.main(
        [
            "scan",
            str(tmp_path),
            "--fail-on",
            "none",
            "--fail-on-policy-violation",
        ]
    )

    assert result == 2


def test_scan_policy_violation_gate_is_opt_in(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(cli, "scan", lambda *_args, **_kwargs: (_violation_graph(), []))

    result = cli.main(
        [
            "scan",
            str(tmp_path),
            "--fail-on",
            "none",
        ]
    )

    assert result == 0


def test_scan_policy_gate_does_not_treat_unresolved_as_violation(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    monkeypatch.setattr(cli, "scan", lambda *_args, **_kwargs: (_unresolved_graph(), []))

    result = cli.main(
        [
            "scan",
            str(tmp_path),
            "--format",
            "json",
            "--fail-on",
            "none",
            "--fail-on-policy-violation",
        ]
    )

    assert result == 0
    report = json.loads(capsys.readouterr().out)
    assert report["authority_contract"]["summary"]["violations"] == 0
    assert report["authority_contract"]["summary"]["unresolved"] == 1


def test_scan_console_renders_contract_as_separate_assessment(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    monkeypatch.setattr(cli, "scan", lambda *_args, **_kwargs: (_violation_graph(), []))

    result = cli.main(
        [
            "scan",
            str(tmp_path),
            "--fail-on",
            "none",
        ]
    )

    assert result == 0
    output = capsys.readouterr().out
    assert "Organisation policy assessment" in output
    assert "Authority Contract assessment" in output
    assert "OWASP Agentic Top 10 status" in output
    assert "ASI01 Agent Goal Hijack" in output
    assert "Violations: 1" in output
    assert "VIOLATION agent=support target=tool:shell" in output


def test_scan_sarif_carries_authority_contract_metadata(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    monkeypatch.setattr(cli, "scan", lambda *_args, **_kwargs: (_violation_graph(), []))

    result = cli.main(
        [
            "scan",
            str(tmp_path),
            "--format",
            "sarif",
            "--fail-on",
            "none",
        ]
    )

    assert result == 0
    report = json.loads(capsys.readouterr().out)
    properties = report["runs"][0]["properties"]
    assert properties["authority_contract"]["summary"]["violations"] == 1
    assert properties["assurance"]["authority_contract"]["status"] == "violation"
    assert properties["assurance"]["organization_policy"]["status"] == "no_violations"
    assert properties["assurance"]["owasp_agentic"]["categories"] == 10



def test_require_authority_contract_fails_independently_of_findings(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    monkeypatch.setattr(
        cli,
        "scan",
        lambda *_args, **_kwargs: (_missing_contract_graph(), []),
    )

    result = cli.main(
        [
            "scan",
            str(tmp_path),
            "--format",
            "json",
            "--fail-on",
            "none",
            "--require-authority-contract",
        ]
    )

    assert result == 2
    report = json.loads(capsys.readouterr().out)
    summary = report["authority_contract"]["summary"]
    assert summary["agents_without_contract"] == 1
    assert summary["contract_coverage_percent"] == 0.0
    assert report["authority_contract"]["missing_contracts"][0] == {
        "agent": "unmanaged",
        "status": "not_declared",
        "reason": "authority_contract_missing",
        "location": None,
    }


def test_missing_authority_contract_gate_is_opt_in(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        cli,
        "scan",
        lambda *_args, **_kwargs: (_missing_contract_graph(), []),
    )

    result = cli.main(
        [
            "scan",
            str(tmp_path),
            "--fail-on",
            "none",
        ]
    )

    assert result == 0

