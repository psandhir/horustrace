#!/usr/bin/env python3
"""Real-browser smoke test of the offline vulnerable ADK security report.

CI installs Playwright's Chromium. This test fails when a report is syntactically
valid but has empty content, JavaScript exceptions, broken navigation, or
nonfunctional drilldowns. The report is opened via file://; no live ADK code runs.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from playwright.sync_api import sync_playwright


def check_report(html_file: Path) -> dict[str, object]:
    html_file = html_file.resolve()
    if not html_file.is_file():
        raise AssertionError(f"Report is missing: {html_file}")

    checks: list[str] = []
    page_errors: list[str] = []

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            page = browser.new_page(viewport={"width": 1440, "height": 900})
            page.on("pageerror", lambda error: page_errors.append(str(error)))
            page.goto(html_file.as_uri(), wait_until="load")

            page.locator("#dashboard .metric").first.wait_for(timeout=15000)
            assert page.locator("#dashboard .metric").count() >= 6
            assert page.locator("#dashboard .severity-chart-row").count() >= 5
            assert page.locator("#dashboard .authority-chart-row").count() >= 3
            checks.append("Dashboard contains metrics and real scanner charts")

            tabs = (
                ("agents", "#agents .row-title"),
                ("components", "#components #inventory-table"),
                ("supply", "#supply .supply-diagram"),
                ("findings", "#findings .finding"),
                ("policy", "#policy .panel"),
                ("owasp", "#owasp tbody tr"),
                ("attack", "#attack .path-card"),
                ("contracts", "#contracts .panel"),
                ("evidence", "#evidence .panel"),
            )
            for section, content_selector in tabs:
                page.locator(f'nav.nav button[data-view="{section}"]').click()
                assert page.locator(f"#{section}").evaluate(
                    "(el) => el.classList.contains('active')"
                ), f"Navigation did not activate {section}"
                assert page.locator(content_selector).count() > 0, (
                    f"{section} is empty after navigation"
                )
                checks.append(f"Navigation renders nonempty {section} section")

            # Keyboard navigation must work without a pointer.
            evidence_nav = page.locator('nav.nav button[data-view="evidence"]')
            evidence_nav.focus()
            evidence_nav.press("Enter")
            assert page.locator("#evidence.active").count() == 1
            checks.append("Keyboard navigation selects Scan evidence")

            page.locator('nav.nav button[data-view="dashboard"]').click()
            page.locator('#dashboard [data-drill="findings:critical"]').first.click()
            assert page.locator("#findings.active").count() == 1
            assert page.locator("#findings .finding").count() > 0
            checks.append("Clickable severity bar drills into actual findings")

            page.locator('nav.nav button[data-view="agents"]').click()
            page.locator("#agents [data-agent]").first.click()
            assert page.locator("#agent-detail.active").count() == 1
            assert page.locator("#agent-detail").inner_text().strip()
            checks.append("Clicking an agent opens an evidence-filled profile")

            # OWASP category → affected agent → scoped finding evidence → category.
            page.locator('nav.nav button[data-view="owasp"]').click()
            categories = page.locator("#owasp tbody tr[data-owasp]")
            selected_risk = None
            for index in range(categories.count()):
                risk_id = categories.nth(index).get_attribute("data-owasp")
                categories.nth(index).click()
                if page.locator("#owasp-detail [data-owasp-agent]").count():
                    selected_risk = risk_id
                    break
            assert selected_risk, "No mapped OWASP category has an attributable agent"
            assert page.locator("#owasp-detail .finding").count() > 0
            agent_row = page.locator("#owasp-detail [data-owasp-agent]").first
            agent_row.focus()
            agent_row.press("Enter")
            assert page.locator("#agent-detail.active").count() == 1
            assert page.locator("#tab-findings.active .finding").count() > 0
            for finding in page.locator("#tab-findings.active .finding").all():
                assert f"OWASP {selected_risk}" in finding.inner_text()
            page.locator("#back-agents").click()
            assert page.locator("#owasp.active #owasp-detail").count() == 1
            checks.append("OWASP category opens attributable agent and scoped findings")

            # Dashboard metrics must open a real component inventory, not a filtered agent list.
            page.locator('nav.nav button[data-view="dashboard"]').click()
            page.locator('#dashboard [data-drill="components:tools"]').click()
            assert page.locator('#components.active [data-inventory-kind="tools"].active').count() == 1

            # Entire component rows are clickable by mouse and keyboard. Search and
            # binding filters must survive opening/closing a detail profile.
            assert page.locator('#components [data-drill="components:mcp"]').count() == 1
            page.locator('#components [data-drill="components:mcp"]').click()
            assert page.locator('#components.active [data-inventory-kind="mcp"].active').count() == 1
            page.locator('#components [data-drill="components:unresolved"]').click()
            assert page.locator('#components.active [data-inventory-filter="unresolved_reference"].active').count() == 1
            page.locator('#components [data-inventory-kind="tools"]').click()
            first_name = page.locator('#components [data-inventory-row] .row-title').first.inner_text()
            page.locator('#inventory-search').fill(first_name)
            first_row = page.locator('#components [data-inventory-row]').first
            first_row.focus()
            first_row.press("Enter")
            assert page.locator('#components.active #inventory-detail').count() == 1
            assert page.locator('#inventory-search').input_value() == first_name
            page.locator('#inventory-clear').click()
            assert page.locator('#inventory-search').input_value() == first_name
            page.locator('#inventory-search').fill("")
            page.locator('#components [data-inventory-row] .row-title').first.click()
            assert page.locator('#components.active #inventory-detail').count() == 1
            page.locator('#inventory-clear').click()
            checks.append("Component card, full-row click and keyboard drilldowns preserve filters")

            # Explicit detail action, source evidence, agent security, and return route.
            assert page.locator('#components [data-inventory-open]').count() > 0
            first_tool = page.locator('#components [data-inventory-open]').first
            first_tool.focus()
            first_tool.press("Enter")
            assert page.locator('#components.active #inventory-detail').count() == 1
            assert page.locator('#inventory-detail').get_attribute("tabindex") == "-1"
            assert "Configuration and source evidence" in page.locator('#inventory-detail').inner_text()
            assert "Supply chain context" in page.locator('#inventory-detail').inner_text()
            assert "Connected agents and security review" in page.locator('#inventory-detail').inner_text()

            # Some tools are unbound; find one with a proven agent binding.
            if not page.locator('#inventory-detail [data-inventory-agent]').count():
                page.locator("#inventory-clear").click()
                for index in range(page.locator('#components [data-inventory-open]').count()):
                    page.locator('#components [data-inventory-open]').nth(index).click()
                    if page.locator('#inventory-detail [data-inventory-agent]').count():
                        break
                    page.locator("#inventory-clear").click()
            assert page.locator('#inventory-detail [data-inventory-agent]').count() > 0
            page.locator('#inventory-detail [data-inventory-agent-findings]').first.click()
            assert page.locator('#agent-detail.active #tab-findings.active').count() == 1
            page.locator("#back-agents").click()
            assert page.locator('#components.active #inventory-detail').count() == 1
            checks.append("Component details and scoped agent security navigation work")

            # MCP detail should work independently of the Tools view.
            page.locator('#components [data-inventory-kind="mcp"]').click()
            assert page.locator('#components [data-inventory-open]').count() > 0
            page.locator('#components [data-inventory-row]').first.click()
            assert page.locator('#components.active #inventory-detail').count() == 1
            assert "Transport" in page.locator('#inventory-detail').inner_text()
            assert "Allowed tools" in page.locator('#inventory-detail').inner_text()
            page.locator("#inventory-clear").click()
            assert page.locator('#components #inventory-detail').count() == 0
            checks.append("MCP inventory opens and closes configuration detail")

            # Skill tab and explicit drilldown are tested when skills are present.
            page.locator('#components [data-inventory-kind="skills"]').click()
            skill_count = page.locator('#components [data-inventory-open]').count()
            if not skill_count:
                # The ADK demo contains no packaged skills; exercise the UI with
                # a clearly synthetic in-browser record, not a scanner claim.
                page.evaluate("""() => {
                    DATA.skills.push({
                        id: "skill-ui-test", name: "synthetic-ui-skill",
                        description: "UI navigation regression fixture",
                        source: "test-only", binding_state: "unbound",
                        bound_agents: [], allowed_tools: ["safe.read"],
                        scripts: [], capabilities: [], resources: [],
                        destinations: [], location: {path: "SKILL.md", line: 1}
                    });
                    renderComponents("skills");
                }""")
            page.locator('#components [data-inventory-row]').first.click()
            assert page.locator('#components.active #inventory-detail').count() == 1
            assert "Skill source" in page.locator('#inventory-detail').inner_text()
            page.locator('#inventory-clear').click()
            checks.append("Skill inventory opens and closes detail, including synthetic UI fixture if needed")

            # Every agent exposes first-class routes into its own component inventory.
            page.locator('nav.nav button[data-view="agents"]').click()
            page.locator('#agents [data-agent]').first.click()
            assert page.locator('#agent-detail.active [data-agent-inventory="tools"]').count() == 1
            page.locator('#agent-detail [data-agent-inventory="tools"]').click()
            assert page.locator('#components.active #inventory-scope-back').count() == 1
            assert "Components connected to" in page.locator('#components').inner_text()
            page.locator('#inventory-scope-back').click()
            assert page.locator('#agent-detail.active').count() == 1
            checks.append("Agent-to-components filtered drilldown and return navigation work")

            # Canonical ADG supply chain is navigable without graph reconstruction.
            page.locator('nav.nav button[data-view="supply"]').click()
            assert page.locator("#supply.active .supply-diagram").count() == 1
            assert page.locator("#supply [data-supply-node]").count() > 0
            assert page.locator("#supply [data-supply-edge]").count() > 0
            # Verify the five-lane information-flow layout using actual ADG
            # nodes and edge references, not just a textual heading.
            input_layout = page.evaluate("""() => {
                const nodes = [...document.querySelectorAll('#supply [data-supply-node]')];
                const byId = new Map(nodes.map(n => [n.dataset.supplyNode, n]));
                const x = n => Number(n.getAttribute('transform').split('(')[1].split(',')[0]);
                const inputs = nodes.filter(n => n.dataset.kind === 'input');
                const agents = nodes.filter(n => n.dataset.kind === 'agent');
                const endpoints = nodes.filter(n => ['data_resource','network_destination'].includes(n.dataset.kind));
                const inputEdges = [...document.querySelectorAll('#supply [data-edge-kind="RECEIVES_INPUT_FROM"]')];
                const canonical = new Map(DATA.security_graph.topology.edges.map(e => [e.id, e]));
                return {
                    headings: [...document.querySelectorAll('#supply .supply-col-title')].map(n => n.textContent),
                    inputs: inputs.length,
                    agents: agents.length,
                    inputLeft: inputs.length > 0 && agents.length > 0 &&
                        Math.max(...inputs.map(x)) < Math.min(...agents.map(x)),
                    destinationsRight: endpoints.length > 0 &&
                        endpoints.every(n => x(n) > Math.max(...agents.map(x))),
                    inboundArrows: inputEdges.length,
                    arrowsCorrect: inputEdges.length > 0 && inputEdges.every(path => {
                        const edge = canonical.get(path.dataset.supplyEdge);
                        const from = byId.get(path.dataset.diagramFrom);
                        const to = byId.get(path.dataset.diagramTo);
                        return edge && from && to &&
                            DATA.security_graph.topology.nodes.find(n => n.id === edge.source)?.kind === 'agent' &&
                            DATA.security_graph.topology.nodes.find(n => n.id === edge.target)?.kind === 'input' &&
                            path.dataset.diagramFrom === edge.target &&
                            path.dataset.diagramTo === edge.source &&
                            x(from) < x(to);
                    })
                };
            }""")
            assert input_layout["headings"] == [
                "Inputs & sources", "Agents & workflow",
                "Tools / MCP / models / skills", "Identities & controls",
                "Data & destinations",
            ], input_layout
            assert input_layout["inputLeft"], input_layout
            assert input_layout["destinationsRight"], input_layout
            assert input_layout["arrowsCorrect"], input_layout
            # No node or relationship disappears when selecting, searching or
            # switching lenses; only emphasis classes and inspector details change.
            page.evaluate("""() => {
                DATA.security_graph.topology.nodes.push({
                    id: "synthetic-unrelated-ui-test", name: "synthetic-unrelated-ui-test",
                    kind: "tool", attributes: {}, location: null
                });
                renderSupplyChain();
            }""")
            baseline = page.evaluate("""() => ({
                nodes: document.querySelectorAll('#supply [data-supply-node]').length,
                edges: document.querySelectorAll('#supply [data-supply-edge]').length,
                canonicalNodes: DATA.security_graph.topology.nodes.length,
                canonicalEdges: DATA.security_graph.topology.edges.length,
                muted: document.querySelectorAll('#supply .is-muted').length
            })""")
            assert baseline["nodes"] == baseline["canonicalNodes"], baseline
            assert baseline["edges"] == baseline["canonicalEdges"], baseline
            assert baseline["muted"] == 0, baseline
            assert page.locator('#supply .has-emphasis').count() == 0

            def unchanged_topology():
                counts = page.evaluate("""() => ({
                    nodes: document.querySelectorAll('#supply [data-supply-node]').length,
                    edges: document.querySelectorAll('#supply [data-supply-edge]').length,
                    mutedCanary: document.querySelector(
                        '#supply [data-supply-node="synthetic-unrelated-ui-test"]'
                    )?.classList.contains('is-muted')
                })""")
                assert counts["nodes"] == baseline["nodes"], counts
                assert counts["edges"] == baseline["edges"], counts
                assert counts["mutedCanary"], counts

            page.locator('#supply [data-edge-kind="RECEIVES_INPUT_FROM"]').first.click()
            unchanged_topology()
            assert "Input → agent" in page.locator("#supply-inspector").inner_text()
            page.locator('#supply [data-supply-node][data-kind="input"]').first.click()
            unchanged_topology()
            assert "Input semantics" in page.locator("#supply-inspector").inner_text()
            checks.append("Input sources render left of agents; inbound arrows preserve canonical ADG")

            agent_node = page.locator('#supply [data-supply-node][data-kind="agent"]').first
            agent_node.focus()
            agent_node.press("Enter")
            unchanged_topology()
            assert page.locator("#supply-inspector").inner_text().strip()
            assert page.locator("#supply-open-agent").count() == 1
            page.locator("#supply-open-agent").click()
            assert page.locator("#agent-detail.active").count() == 1
            page.locator("#back-agents").click()
            assert page.locator("#supply.active .supply-diagram").count() == 1
            page.locator('#supply [data-supply-layer="execution"]').click()
            assert page.locator("#supply.active .supply-diagram").count() == 1
            unchanged_topology()
            page.locator('#supply-search').fill("privileged_worker")
            unchanged_topology()
            page.locator("#supply-clear-focus").click()
            assert page.locator('#supply .is-muted').count() == 0
            assert page.locator('#supply .has-emphasis').count() == 0
            assert page.locator('#supply [data-supply-edge]').count() == baseline["edges"]
            checks.append("Supply chain selection dims unrelated nodes and retains full topology")
            checks.append("Supply chain graph supports keyboard, source inspection, layers and agent return")

            page.locator('[data-theme-choice="dark"]').click()
            assert page.locator("html").get_attribute("data-theme") == "dark"
            page.locator('[data-theme-choice="light"]').click()
            assert page.locator("html").get_attribute("data-theme") == "light"
            checks.append("Light/dark theme switch responds to clicks")

            # Evaluate at narrow width after the full navigation pass.
            page.set_viewport_size({"width": 390, "height": 844})
            page.locator('nav.nav button[data-view="findings"]').click()
            assert page.locator("#findings.active .finding").count() > 0
            checks.append("Mobile-width navigation still renders findings")

            assert not page_errors, "Browser JavaScript errors: " + "; ".join(page_errors)
            checks.append("No unhandled browser JavaScript errors")
        finally:
            browser.close()

    return {
        "result": "PASS",
        "report": html_file.name,
        "checks": checks,
        "page_errors": page_errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--report", type=Path, default=Path("adk-ux-report/adk-security-workbench.html"),
    )
    args = parser.parse_args()
    try:
        result = check_report(args.report)
    except Exception as exc:
        print(json.dumps({"result": "FAIL", "message": str(exc)}, indent=2))
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
