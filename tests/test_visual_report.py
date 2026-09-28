from pathlib import Path

from horustrace.adg import build_adg
from horustrace.cli import main
from horustrace.models import (
    Agent,
    AgentPolicy,
    AuthorityContract,
    AuthorityScope,
    Finding,
    Graph,
    Identity,
    ResourceScope,
    Severity,
    SourceLocation,
    Tool,
)
from horustrace.visual_report import (
    VISUAL_REPORT_MODEL,
    build_visual_report,
    render_visual_report_html,
)


def _graph(root: Path) -> tuple[Graph, list[Finding]]:
    location = SourceLocation(root / "agent.py", line=7)
    identity = Identity(
        name="support-service",
        provider="gcp",
        credential_source="workload_identity",
        roles={"roles/viewer"},
        location=location,
    )
    tool = Tool(
        name="update_ticket",
        kind="function",
        capabilities={"data.write"},
        resources=[
            ResourceScope(
                kind="ticket",
                selector="support/*",
                access={"data.write"},
                location=location,
            )
        ],
        identity=identity.name,
        approval=True,
        location=location,
    )
    agent = Agent(
        name="support",
        tools=[tool],
        identities=[identity],
        policy=AgentPolicy(
            authority=AuthorityContract(
                allow=AuthorityScope(capabilities={"data.read"}),
                location=SourceLocation(root / "horustrace.manifest.yaml", line=8),
            )
        ),
        location=location,
        metadata={"framework": "openai-agents"},
    )
    graph = Graph(agents=[agent])
    graph.adg = build_adg(graph, root)
    findings = [
        Finding(
            rule_id="TEST001",
            severity=Severity.HIGH,
            title="Test finding",
            message="Evidence-backed test finding.",
            recommendation="Reduce authority.",
            agent="support",
            location=location,
            evidence=["support can update tickets"],
        )
    ]
    return graph, findings


def test_visual_report_projects_effective_agency_and_contract(tmp_path: Path) -> None:
    graph, findings = _graph(tmp_path)

    report = build_visual_report(graph, findings, tmp_path)

    assert report["schema_version"] == 1
    assert report["model"] == VISUAL_REPORT_MODEL
    assert report["summary"]["agents"] == 1
    assert report["summary"]["authority_relationships"] == 1
    assert report["summary"]["write_capable_relationships"] == 1
    assert report["summary"]["contract_violations"] == 1
    assert report["summary"]["findings"] == 1

    agent = report["agents"][0]
    assert agent["name"] == "support"
    assert agent["summary"]["contract_status"] == "violation"
    assert agent["summary"]["contract_violations"] == 1
    assert agent["resources"] == ["support/*"]
    assert agent["identities"] == ["support-service"]
    assert agent["effective_authority"][0]["target"]["name"] == "update_ticket"
    assert agent["contract"]["violations"][0]["clause"] == "allow.capabilities"
    assert agent["findings"][0]["rule_id"] == "TEST001"

    encoded = str(report)
    assert str(tmp_path) not in encoded


def test_visual_report_preserves_declared_contract_without_relationships(
    tmp_path: Path,
) -> None:
    graph = Graph(
        agents=[
            Agent(
                name="contract-only",
                policy=AgentPolicy(
                    authority=AuthorityContract(
                        allow=AuthorityScope(capabilities={"data.read"}),
                        location=SourceLocation(
                            tmp_path / "horustrace.manifest.yaml",
                            line=4,
                        ),
                    )
                ),
            )
        ]
    )
    graph.adg = build_adg(graph, tmp_path)

    report = build_visual_report(graph, [], tmp_path)

    agent = report["agents"][0]
    assert agent["contract"]["declared"] is not None
    assert agent["summary"]["contract_status"] == "declared"
    assert agent["contract"]["relationships"] == []


def test_visual_report_escapes_embedded_script_data(tmp_path: Path) -> None:
    graph = Graph(agents=[Agent(name="</script><script>alert(1)</script>")])
    graph.adg = build_adg(graph, tmp_path)

    html = render_visual_report_html(graph, [], tmp_path)

    assert "</script><script>alert(1)</script>" not in html
    assert "\\u003c/script\\u003e\\u003cscript\\u003ealert(1)" in html


def test_visual_report_dashboard_has_contextual_drilldowns(tmp_path: Path) -> None:
    graph, findings = _graph(tmp_path)

    html = render_visual_report_html(graph, findings, tmp_path)

    assert '"agents:all"' in html
    assert '"findings:high"' in html
    assert '"contracts:violation"' in html
    assert '"agents:write"' in html
    assert "data-drill" in html
    assert 'function routeDrill(action)' in html
    assert 'function agentMatchesFilter(a,mode)' in html


def test_visual_report_html_is_self_contained(tmp_path: Path) -> None:
    graph, findings = _graph(tmp_path)

    html = render_visual_report_html(graph, findings, tmp_path)

    assert "<!doctype html>" in html
    assert VISUAL_REPORT_MODEL in html
    assert "Effective Agency Report" in html
    assert "Agency map" in html
    assert "Agent contracts" in html
    assert "Scan evidence" in html
    assert "default-src 'none'" in html
    assert "<script src=" not in html
    assert "<link rel=" not in html
    assert str(tmp_path) not in html


def _project(root: Path) -> None:
    (root / "agent.py").write_text(
        """from agents import Agent, function_tool

@function_tool
def lookup(query: str) -> str:
    return query

agent = Agent(
    name="research",
    instructions="Research support requests.",
    tools=[lookup],
)
""",
        encoding="utf-8",
    )


def test_visual_report_cli_writes_default_html(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _project(project)
    monkeypatch.chdir(tmp_path)

    assert main(["report", str(project)]) == 0

    output = tmp_path / "horustrace-report.html"
    assert output.exists()
    html = output.read_text(encoding="utf-8")
    assert "HorusTrace" in html
    assert "research" in html
    assert "<script src=" not in html


def test_visual_report_cli_accepts_explicit_output(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _project(project)
    output = tmp_path / "artifacts" / "report.html"
    output.parent.mkdir()

    assert main(["report", str(project), "--output", str(output)]) == 0

    assert output.exists()
    assert "Security assessment" in output.read_text(encoding="utf-8")
