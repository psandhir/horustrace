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

            # PR #495: a finding shows concise source-local context without
            # forcing reviewers through every raw provenance entry.
            note = page.locator("#findings .source-context .source-note").first
            assert note.count() == 1, "No inline source-local provenance is visible"
            assert note.inner_text().strip(), "Source-local provenance summary is empty"
            raw = page.locator("#findings details").filter(
                has_text="Full provenance ("
            ).first
            assert raw.count() == 1, "Raw audit provenance disclosure is missing"
            assert raw.get_attribute("open") is None, (
                "Raw provenance should be collapsed by default"
            )
            raw.locator("summary").click()
            assert raw.get_attribute("open") is not None
            assert raw.locator("li").count() > 0
            checks.append("Source-local digest and expandable raw provenance work")

            page.locator('nav.nav button[data-view="agents"]').click()
            page.locator("#agents [data-agent]").first.click()
            assert page.locator("#agent-detail.active").count() == 1
            assert page.locator("#agent-detail").inner_text().strip()
            checks.append("Clicking an agent opens an evidence-filled profile")

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
