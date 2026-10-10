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

            note = page.locator("#findings .source-context .source-note").first
            assert note.count() == 1, "Concise provenance notes are missing"
            assert note.inner_text().strip()
            raw = page.locator("#findings details").filter(
                has_text="Full provenance ("
            ).first
            assert raw.count() == 1, "Full finding provenance is missing"
            assert raw.get_attribute("open") is None
            raw.locator("summary").click()
            assert raw.get_attribute("open") is not None
            assert raw.locator("li").count() > 0
            checks.append("Concise source evidence and raw finding audit disclosure work")

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

            # Component inventory works offline, including component-to-agent navigation.
            page.locator('nav.nav button[data-view="components"]').click()
            page.locator('#components [data-inventory-kind="tools"]').click()
            assert page.locator('#components [data-inventory-row]').count() > 0
            assert page.locator('#components [data-inventory-kind="skills"]').count() == 1
            rows = page.locator('#components [data-inventory-row]')
            bound_component = False
            for index in range(rows.count()):
                rows.nth(index).focus()
                rows.nth(index).press("Enter")
                assert page.locator('#components #inventory-detail').count() == 1
                if page.locator('#components [data-inventory-agent]').count():
                    bound_component = True
                    break
            assert bound_component, "No bound tools found in the vulnerable ADK report"
            page.locator('#components [data-inventory-agent]').first.click()
            assert page.locator("#agent-detail.active").count() == 1
            page.locator("#back-agents").click()
            assert page.locator("#components.active #inventory-detail").count() == 1
            checks.append("Component inventory opens bound tool and returns from agent")
            page.locator('#components [data-inventory-kind="mcp"]').click()
            assert page.locator('#components [data-inventory-row]').count() > 0
            checks.append("MCP inventory and skill tab accessible in offline report")

            # Canonical ADG supply chain is navigable without graph reconstruction.
            page.locator('nav.nav button[data-view="supply"]').click()
            assert page.locator("#supply.active .supply-diagram").count() == 1
            assert page.locator("#supply [data-supply-node]").count() > 0
            assert page.locator("#supply [data-supply-edge]").count() > 0
            agent_node = page.locator('#supply [data-supply-node][data-kind="agent"]').first
            agent_node.focus()
            agent_node.press("Enter")
            assert page.locator("#supply-inspector").inner_text().strip()
            assert page.locator("#supply-open-agent").count() == 1
            page.locator("#supply-open-agent").click()
            assert page.locator("#agent-detail.active").count() == 1
            page.locator("#back-agents").click()
            assert page.locator("#supply.active .supply-diagram").count() == 1
            page.locator('#supply [data-supply-layer="execution"]').click()
            assert page.locator("#supply.active .supply-diagram").count() == 1
            page.locator("#supply-focus").select_option("all")
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
