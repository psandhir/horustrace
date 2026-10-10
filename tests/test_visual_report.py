import re
import shutil
import subprocess
from pathlib import Path
from html.parser import HTMLParser

import pytest

from horustrace.adg import build_adg
from horustrace.cli import main
from horustrace.models import (
    Agent,
    AgentPolicy,
    AttackPath,
    AuthorityContract,
    AuthorityScope,
    EvidenceFact,
    Finding,
    Graph,
    Identity,
    NetworkDestination,
    ResourceScope,
    Severity,
    Skill,
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
            assessment="policy_violation",
            standards={"owasp_agentic": ["ASI02"]},
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
    assert report["summary"]["policy_violations"] == 1
    assert report["summary"]["owasp_categories_with_findings"] == 1
    assert report["assurance"]["organization_policy"]["status"] == "violation"
    assert report["assurance"]["authority_contract"]["status"] == "violation"
    assert report["assurance"]["owasp_agentic"]["status"] == "finding"

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



def test_visual_report_summarises_source_local_provenance_without_losing_facts(
    tmp_path: Path,
) -> None:
    graph, findings = _graph(tmp_path)
    location = SourceLocation(tmp_path / "agent.py", line=14)
    findings[0].location = location
    facts = [
        EvidenceFact("run_shell", "capability=network.external", "observed", location),
        EvidenceFact("run_shell", "capability=process.execute", "observed", location),
        EvidenceFact("run_shell", "approval_configuration=True", "observed", location),
        EvidenceFact("run_shell", "guardrail_hook_detected=True", "observed", location),
        EvidenceFact(
            "another_tool", "capability=data.write", "observed",
            SourceLocation(tmp_path / "agent.py", line=15),
        ),
        EvidenceFact(
            "agent_policy", "denied=process.execute", "declared",
            SourceLocation(tmp_path / "horustrace.manifest.yaml", line=1),
        ),
    ]
    findings[0].provenance = facts

    report = build_visual_report(graph, findings, tmp_path)
    finding = report["findings"][0]
    digest = finding["provenance_digest"]
    assert digest["additional_contexts"] == 0
    assert digest["items"] == [{
        "subject": "run_shell",
        "origin": "observed",
        "location": {"path": "agent.py", "line": 14, "column": 1},
        "summary": (
            "Capabilities: external network access, process execution; "
            "Controls: approval configured, guardrail hook detected"
        ),
    }]
    assert len(finding["provenance"]) == len(facts)
    assert any(item["fact"] == "denied=process.execute" for item in finding["provenance"])
    html = render_visual_report_html(graph, findings, tmp_path)
    assert "Source context" in html
    assert "Full provenance (" in html
    assert "static evidence, not verified enforcement" in html


def test_visual_report_provenance_separates_subjects_and_preserves_unknowns(
    tmp_path: Path,
) -> None:
    graph, findings = _graph(tmp_path)
    location = findings[0].location
    assert location is not None
    findings[0].provenance = [
        EvidenceFact("tool_a", "approval_configuration=None", "observed", location),
        EvidenceFact("tool_a", "guardrail_hook_detected=False", "inferred", location),
        EvidenceFact("tool_b", "capability=data.write", "observed", location),
        EvidenceFact("tool_c", "capability=network.external", "observed", location),
        EvidenceFact("unrelated", "capability=process.execute", "observed",
                     SourceLocation(tmp_path / "other.py", line=3)),
    ]

    digest = build_visual_report(graph, findings, tmp_path)["findings"][0][
        "provenance_digest"
    ]
    assert len(digest["items"]) == 2
    assert digest["additional_contexts"] == 1
    assert len({item["subject"] for item in digest["items"]}) == 2
    by_subject = {item["subject"]: item["summary"] for item in digest["items"]}
    assert "approval configuration unresolved" in by_subject["tool_a"]
    assert "guardrail hook not detected" in by_subject["tool_a"]
    assert next(item for item in digest["items"] if item["subject"] == "tool_a")[
        "origin"
    ] == "observed + inferred"
    assert "unrelated" not in str(digest)


def test_visual_report_does_not_promote_unrelated_provenance_to_source_context(
    tmp_path: Path,
) -> None:
    graph, findings = _graph(tmp_path)
    findings[0].provenance = [
        EvidenceFact("other", "capability=process.execute", "observed",
                     SourceLocation(tmp_path / "other.py", line=50))
    ]
    report = build_visual_report(graph, findings, tmp_path)
    assert report["findings"][0]["provenance_digest"] == {
        "items": [], "additional_contexts": 0,
    }
    assert len(report["findings"][0]["provenance"]) == 1



def test_visual_report_cross_file_finding_evidence_and_agent_inventory(
    tmp_path: Path,
) -> None:
    graph, findings = _graph(tmp_path)
    findings[0].title = "Process execution"
    findings[0].evidence = ["denied=process.execute"]
    policy = EvidenceFact(
        "support", "denied=process.execute", "declared",
        SourceLocation(tmp_path / "horustrace.manifest.yaml", line=1),
    )
    observed = EvidenceFact(
        "run_shell", "capability=process.execute", "observed",
        SourceLocation(tmp_path / "agent.py", line=14),
    )
    findings[0].provenance = [policy, observed]
    graph.agents[0].tools[0].provenance = [observed]

    report = build_visual_report(graph, findings, tmp_path)
    digest = report["findings"][0]["provenance_digest"]
    assert {
        (item["location"]["path"], item["location"]["line"])
        for item in digest["items"]
    } == {("agent.py", 14), ("horustrace.manifest.yaml", 1)}
    assert report["agents"][0]["provenance_inventory"] == [{
        **observed.as_dict(),
        "location": {"path": "agent.py", "line": 14, "column": 1},
    }]
    html = render_visual_report_html(graph, findings, tmp_path)
    assert "Full agent evidence inventory" in html
    assert "source facts" in html


def test_visual_report_surfaces_bound_and_unbound_skills(tmp_path: Path) -> None:
    bound_location = SourceLocation(tmp_path / "skills" / "review" / "SKILL.md")
    unbound_location = SourceLocation(tmp_path / "skills" / "unused" / "SKILL.md")
    graph = Graph(
        agents=[
            Agent(
                name="reviewer",
                skills=[
                    Skill(
                        name="review",
                        description="Review changes",
                        allowed_tools={"Read"},
                        location=bound_location,
                        metadata={"binding_origin": "framework_skill_reference"},
                    )
                ],
            )
        ],
        unbound_skills=[
            Skill(
                name="unused",
                description="Unused skill",
                location=unbound_location,
            )
        ],
    )
    graph.adg = build_adg(graph, tmp_path)

    report = build_visual_report(graph, [], tmp_path)
    html = render_visual_report_html(graph, [], tmp_path)

    assert report["summary"]["skills"] == 2
    assert report["summary"]["bound_skills"] == 1
    assert report["summary"]["unbound_skills"] == 1
    assert report["agents"][0]["summary"]["skills"] == 1
    by_name = {item["name"]: item for item in report["skills"]}
    assert by_name["review"]["binding_state"] == "bound"
    assert by_name["review"]["bound_agents"] == ["reviewer"]
    assert by_name["unused"]["binding_state"] == "unbound"
    assert "Skill inventory" in html
    assert "unused" in html


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


def test_visual_report_has_interactive_severity_chart(tmp_path: Path) -> None:
    graph, findings = _graph(tmp_path)

    html = render_visual_report_html(graph, findings, tmp_path)
    report = build_visual_report(graph, findings, tmp_path)

    assert 'function severityChart(s)' in html
    assert 'aria-label="Findings by scanner severity"' in html
    assert 'class="severity-chart-row" data-tone="\'+key+\'"' in html
    assert 'data-drill="findings:' in html
    assert '["low","Low"],["info","Info"]' in html
    assert 'filters=["all","critical","high","medium","low","info"]' in html
    assert "Filled bars represent detected findings; exploitability is not verified." in html
    assert report["summary"]["severity"] == {
        "critical": 0,
        "high": 1,
        "medium": 0,
        "low": 0,
        "info": 0,
    }


def test_visual_report_authority_resolution_and_coverage_states(tmp_path: Path) -> None:
    graph, findings = _graph(tmp_path)
    before = build_visual_report(graph, findings, tmp_path)

    html = render_visual_report_html(graph, findings, tmp_path)
    after = build_visual_report(graph, findings, tmp_path)

    assert before == after
    assert 'function authorityResolutionChart(agents)' in html
    assert 'aria-label="Effective authority resolution"' in html
    assert 'data-drill="agents:' in html
    assert '["fully_resolved","Fully resolved"]' in html
    assert '["partially_resolved","Partially resolved"]' in html
    assert '["unknown","Unknown"]' in html
    assert 'some(r=>r.resolution===mode)' in html
    assert 'if(el.tagName!=="BUTTON")' in html
    assert 'function scanCoverageStatus(incomplete)' in html
    assert 'No reported coverage gaps' in html
    assert 'Coverage incomplete' in html
    assert 'Not available (no files considered)' in html
    assert 'Resolution does not imply least privilege' in html
    assert 'No effective-authority relationships were reconstructed' in html
    assert 'default-src &#39;none&#39;' not in html


def test_visual_report_inline_javascript_is_syntactically_valid(tmp_path: Path) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is not available to validate offline report JavaScript")

    graph, findings = _graph(tmp_path)
    html = render_visual_report_html(graph, findings, tmp_path)
    class InlineScripts(HTMLParser):
        def __init__(self) -> None:
            super().__init__()
            self.scripts: list[str] = []
            self.in_script = False

        def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
            if tag == "script":
                self.scripts.append("")
                self.in_script = True

        def handle_data(self, data: str) -> None:
            if self.in_script:
                self.scripts[-1] += data

        def handle_endtag(self, tag: str) -> None:
            if tag == "script":
                self.in_script = False

    parser = InlineScripts()
    parser.feed(html)
    assert len(parser.scripts) == 2  # JSON payload and standalone application script.
    check = subprocess.run(
        [node, "--check"],
        input=parser.scripts[-1],
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )
    assert check.returncode == 0, check.stderr


def test_visual_report_owasp_assessment_status_chart(tmp_path: Path) -> None:
    graph, findings = _graph(tmp_path)
    before = build_visual_report(graph, findings, tmp_path)
    html = render_visual_report_html(graph, findings, tmp_path)

    assert 'function owaspAssessmentChart(categories)' in html
    assert 'aria-label="OWASP Agentic Top 10 assessment states"' in html
    assert 'data-drill="owasp:status.' in html
    assert '["finding","Runtime findings"]' in html
    assert '["no_runtime_findings","Mapped findings (none runtime-classified)"]' in html
    assert '["no_mapped_findings","No mapped findings"]' in html
    assert '["not_assessed","Not assessed"]' in html
    assert 'const shownCategories=statusMode?categories.filter(' in html
    assert 'scope+\'<div class="panel flush table-wrap">' in html
    assert 'Detector coverage is not proof of security' in html
    assert 'Not assessed means no enabled mapped detector' in html
    assert before == build_visual_report(graph, findings, tmp_path)


def test_visual_report_supports_accessible_light_and_dark_themes(tmp_path: Path) -> None:
    graph, findings = _graph(tmp_path)
    expected = build_visual_report(graph, findings, tmp_path)

    html = render_visual_report_html(graph, findings, tmp_path)

    assert '<html lang="en" data-theme="light">' in html
    assert 'role="group" aria-label="Report color theme"' in html
    assert 'data-theme-choice="light" aria-pressed="true"' in html
    assert 'data-theme-choice="dark" aria-pressed="false"' in html
    assert 'function setTheme(choice)' in html
    assert 'document.documentElement.setAttribute("data-theme",next)' in html
    assert 'btn.setAttribute("aria-pressed",String(btn.dataset.themeChoice===next))' in html
    assert 'window.localStorage.getItem(THEME_STORAGE_KEY)' in html
    assert 'window.localStorage.setItem(THEME_STORAGE_KEY,next)' in html
    assert 'initialTheme="light"' in html
    assert 'try{' in html and 'catch(_error){' in html
    assert 'html[data-theme="light"] .assessment-banner' in html
    assert 'html[data-theme="light"] .node.agent rect' in html
    assert 'html[data-theme="light"] .finding p' in html
    assert 'html[data-theme="light"] pre' in html
    assert 'default-src &#39;none&#39;' not in html
    assert "default-src 'none'" in html
    assert "<script src=" not in html
    assert "<link rel=" not in html
    assert expected == build_visual_report(graph, findings, tmp_path)


def test_visual_report_light_palette_text_contrast(tmp_path: Path) -> None:
    """Guard legibility of the light palette; non-color labels still indicate risk."""
    import re

    graph, findings = _graph(tmp_path)
    html = render_visual_report_html(graph, findings, tmp_path)
    match = re.search(r'html\[data-theme="light"\]\{([^}]+)\}', html)
    assert match is not None
    colors = dict(re.findall(r'--([\w-]+):(#(?:[0-9a-fA-F]{6}));', match.group(1)))

    def luminance(value: str) -> float:
        channels = [int(value[i:i + 2], 16) / 255 for i in (1, 3, 5)]
        linear = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
        return sum(a * b for a, b in zip(linear, (0.2126, 0.7152, 0.0722)))

    def contrast(left: str, right: str) -> float:
        high, low = sorted((luminance(left), luminance(right)), reverse=True)
        return (high + 0.05) / (low + 0.05)

    for foreground in (
        "text", "muted", "muted2", "accent", "critical", "high",
        "medium", "low", "ok", "warn", "unknown",
    ):
        assert contrast(colors[foreground], colors["surface"]) >= 4.5, foreground


def test_visual_report_light_theme_pastel_bars_are_presentation_only(
    tmp_path: Path,
) -> None:
    graph, findings = _graph(tmp_path)
    before = build_visual_report(graph, findings, tmp_path)

    html = render_visual_report_html(graph, findings, tmp_path)
    after = build_visual_report(graph, findings, tmp_path)

    assert before == after
    # Pastels are used only for graphical fills. Severity text keeps the
    # stronger contrast-safe foreground colors already tested above.
    for token, color in (
        ("risk", "#EFB5C2"), ("warning", "#F6D4C8"),
        ("good", "#B9DECD"), ("unknown", "#CED9E4"),
    ):
        assert f"--bar-{token}:{color}" in html

    for selector, token in (
        (".severity-chart-fill.critical", "risk"),
        (".severity-chart-fill.high", "warning"),
        (".severity-chart-fill.medium", "warning"),
        (".severity-chart-fill.low", "good"),
        (".severity-chart-fill.info", "unknown"),
        (".authority-chart-row .severity-chart-fill.fully_resolved", "good"),
        (".authority-chart-row .severity-chart-fill.partially_resolved", "warning"),
        (".authority-chart-row .severity-chart-fill.unknown", "unknown"),
        (".owasp-chart-row .severity-chart-fill.finding", "risk"),
        (".owasp-chart-row .severity-chart-fill.no_runtime_findings", "warning"),
        (".owasp-chart-row .severity-chart-fill.no_mapped_findings", "good"),
        (".owasp-chart-row .severity-chart-fill.not_assessed", "unknown"),
        (".coverage-fill", "good"),
        (".coverage-fill.incomplete", "warning"),
    ):
        assert f'html[data-theme="light"] {selector}' in html
        assert f"background:var(--bar-{token})" in html

    assert '<div class="coverage-fill \'+(c.incomplete?' in html
    assert "c.incomplete?'incomplete':''" in html
    assert "data-tone=\"'+key+'\"" in html
    assert "data-present=\"'+(count>0)+'\"" in html
    assert 'html[data-theme="light"] .severity-chart-track' in html
    assert 'height:14px' in html
    assert 'html[data-theme="light"] .severity-chart-label::before' in html
    assert 'html[data-theme="light"] .badge.critical' in html
    assert 'html[data-theme="light"] .badge.unresolved' in html
    # No brown/ochre semantic ink in the light theme.
    for old_ink in ("#994718", "#855900", "#785209"):
        assert old_ink not in html
    assert "--high:#244068;--medium:#244068" in html
    assert "--warn:#244068" in html
    assert "--bg:#f8fafc" in html
    assert 'Coloured markers identify severity even when a count is zero' in html
    # The original dark semantic colors are unaffected.
    assert "--critical:#ff707a" in html
    assert "--high:#ff9e66" in html
    assert "--ok:#63d6a0" in html


def test_visual_report_uses_offline_semantic_icon_design_system(tmp_path: Path) -> None:
    graph, findings = _graph(tmp_path)
    before = build_visual_report(graph, findings, tmp_path)

    html = render_visual_report_html(graph, findings, tmp_path)
    after = build_visual_report(graph, findings, tmp_path)

    assert before == after
    assert "const ICONS=Object.freeze" in html
    assert "function uiIcon(name)" in html
    assert "Object.prototype.hasOwnProperty.call(ICONS,name)" in html
    assert "aria-hidden=\"true\"" in html
    for name in (
        "overview", "agents", "findings", "policy", "owasp", "attack",
        "contracts", "evidence",
    ):
        assert f'data-icon="{name}"' in html
    assert "uiIcon(btn.dataset.icon)" in html
    assert "uiIcon(ICON_FOR_METRIC[label]" in html
    assert "uiIcon(ICON_FOR_SECTION[title])" in html
    assert 'class="metric-top"' in html
    assert 'class="metric-icon"' in html
    assert 'class="report-context"' in html
    assert "Agent Security Workbench" in html
    assert "<script src=" not in html
    assert "<link rel=" not in html
    assert "default-src 'none'" in html


def test_visual_report_projects_attack_path_chain(tmp_path: Path) -> None:
    location = SourceLocation(tmp_path / "agent.py", line=10)
    agent = Agent(name="Slack Agent", location=location)
    graph = Graph(
        agents=[agent],
        attack_paths=[
            AttackPath(
                path_id="PATH005",
                title="Potential untrusted-input path to secret access and egress",
                agent="Slack Agent",
                nodes=[
                    "slack_message",
                    "Slack Agent",
                    "read_secret",
                    "http_post",
                ],
                severity=Severity.HIGH,
                rationale="Untrusted input, secret access and unconstrained egress coexist.",
                location=location,
                metadata={
                    "basis": "capability_cooccurrence",
                    "exploitability": "not_verified",
                },
            )
        ],
    )
    graph.adg = build_adg(graph, tmp_path)

    report = build_visual_report(graph, [], tmp_path)

    path = report["agents"][0]["path_views"][0]
    assert path["edge_style"] == "dashed"
    assert path["evidence_strength"] == "potential_capability_cooccurrence"
    assert [step["role"] for step in path["steps"]] == [
        "Untrusted input",
        "Agent",
        "Reads secrets",
        "Outbound tool",
        "Destination constraint",
    ]
    assert path["steps"][-1]["label"] == "Unrestricted external destination"


def test_visual_report_exposes_production_review_workflows(tmp_path: Path) -> None:
    graph, findings = _graph(tmp_path)

    html = render_visual_report_html(graph, findings, tmp_path)

    assert "Priority review queue" in html
    assert "Assessment signal" in html
    assert 'aria-label="Report sections"' in html
    assert 'data-agent-filter=' in html
    assert 'data-finding-filter=' in html
    assert "Search rule, title, agent, message or file" in html
    assert "Trust & provenance" in html
    assert "Organisation policy" in html
    assert "OWASP Top 10" in html
    assert "OWASP Agentic Top 10" in html
    assert 'data-view="policy"' in html
    assert 'data-view="owasp"' in html
    assert "function renderPolicy()" in html
    assert "function renderOwasp(" in html
    assert "prefers-reduced-motion" in html
    assert "</style></style>" not in html
    assert '<script id="horus-data"<script' not in html


def test_visual_report_has_expandable_map_controls(tmp_path: Path) -> None:
    graph, findings = _graph(tmp_path)

    html = render_visual_report_html(graph, findings, tmp_path)

    assert "Expand map" in html
    assert 'id="map-zoom-in"' in html
    assert 'id="map-zoom-out"' in html
    assert 'id="map-fit"' in html
    assert 'id="map-toggle-groups"' in html
    assert "Find tool, MCP, identity, resource or destination" in html
    assert "Attack paths" in html
    assert "Supported static data flow" in html
    assert "Potential capability path" in html


def test_visual_report_html_is_self_contained(tmp_path: Path) -> None:
    graph, findings = _graph(tmp_path)

    html = render_visual_report_html(graph, findings, tmp_path)

    assert "<!doctype html>" in html
    assert VISUAL_REPORT_MODEL in html
    assert "Agent Security Workbench" in html
    assert "Agency map" in html
    assert "Agent contracts" in html
    assert "Organisation policy" in html
    assert "OWASP Top 10" in html
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



def test_visual_report_exposes_csharp_source_effect_evidence(
    tmp_path: Path,
) -> None:
    binding = SourceLocation(tmp_path / "Program.cs", line=20)
    destination_location = SourceLocation(
        tmp_path / "Tools" / "CurrencyConverterTool.cs",
        line=18,
        column=39,
    )
    tool = Tool(
        name="ConvertCurrency",
        kind="function",
        capabilities={"network.external"},
        destinations=[
            NetworkDestination(
                target="https://open.er-api.com/v6/",
                location=destination_location,
                metadata={
                    "source": "csharp_class_base_address",
                    "repository_effect_summary": True,
                    "source_symbol": (
                        "CurrencyConverterTool.ConvertCurrency"
                    ),
                },
            )
        ],
        location=binding,
        metadata={
            "framework": "microsoft-agent-framework-dotnet",
            "repository_effect_resolution": "resolved",
            "repository_effect_partial": False,
            "repository_effect_unresolved_calls": [],
            "repository_effect_sources": [
                "Tools/CurrencyConverterTool.cs"
            ],
            "repository_effect_evidence_details": [
                {
                    "path": "Tools/CurrencyConverterTool.cs",
                    "line": 34,
                    "column": 5,
                    "symbol": (
                        "CurrencyConverterTool.ConvertCurrency"
                    ),
                    "kind": "csharp_method",
                }
            ],
            "repository_effect_capability_evidence": {
                "network.external": [
                    {
                        "path": "Tools/CurrencyConverterTool.cs",
                        "line": 43,
                        "column": 35,
                        "symbol": (
                            "CurrencyConverterTool.ConvertCurrency"
                        ),
                        "kind": "csharp_effect",
                    }
                ]
            },
        },
    )
    graph = Graph(
        agents=[
            Agent(
                name="ItineraryPlannerAgent",
                tools=[tool],
                location=binding,
                metadata={
                    "framework": "microsoft-agent-framework-dotnet"
                },
            )
        ]
    )
    graph.adg = build_adg(graph, tmp_path)

    report = build_visual_report(graph, [], tmp_path)
    relationship = report["agents"][0]["effective_authority"][0]

    assert any(
        item["kind"] == "SOURCE_EFFECT"
        and item.get("capability") == "network.external"
        and item["location"]["path"] == "Tools/CurrencyConverterTool.cs"
        for item in relationship["evidence"]
    )
    assert relationship["semantics"]["source_effect_resolution"] == "resolved"

    html = render_visual_report_html(graph, [], tmp_path)
    assert "SOURCE_EFFECT" in html
    assert "Tools/CurrencyConverterTool.cs" in html
    assert str(tmp_path) not in html
