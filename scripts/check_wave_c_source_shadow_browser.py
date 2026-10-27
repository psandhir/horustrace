"""Real Chromium smoke test for Wave C source-only MCP supply-chain explorer.

Unlike text-only HTML tests, verifies actual click/keyboard drilldowns and
defocus/recovery. Requires playwright and local installed Chromium in CI.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from playwright.sync_api import sync_playwright


def check_report(path: Path) -> dict[str, object]:
    path = path.resolve()
    if not path.is_file():
        raise ValueError("offline source report missing")
    errors: list[str] = []
    checks: list[str] = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            page = browser.new_page(viewport={"width": 1440, "height": 900})
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(path.as_uri(), wait_until="load")
            assert page.locator(".node-card.server").count() == 3
            assert page.locator(".node-card.tool").count() == 25
            assert page.locator(".node-card.client").count() >= 3
            calculators = page.locator(".node-card.server").filter(
                has_text="Calculator"
            )
            assert calculators.count() == 2
            sites = [
                calculators.nth(index).locator(".node-site").inner_text()
                for index in range(calculators.count())
            ]
            assert len(set(sites)) == 2
            checks.append("All source nodes and same-name server identities render")

            first = calculators.first
            first.click()
            assert first.get_attribute("aria-pressed") == "true"
            assert page.locator(".node-card.selected").count() == 1
            assert page.locator(".node-card.dimmed").count() > 0
            assert "source configuration bindings" in page.locator(
                "#selection-detail"
            ).inner_text()
            assert page.locator(".node-card.server.dimmed").count() >= 1
            checks.append("Click highlights one source component, dims unrelated nodes")

            first.click()
            assert page.locator(".node-card.selected").count() == 0
            assert page.locator(".node-card.dimmed").count() == 0
            checks.append("Click same node restores complete source supply chain")

            # Keyboard focus, Enter selection, reset restores everything.
            first.focus()
            first.press("Enter")
            assert first.get_attribute("aria-pressed") == "true"
            page.locator("#reset-selection").click()
            assert page.locator(".node-card.dimmed").count() == 0
            assert page.locator(".node-card.selected").count() == 0
            checks.append("Keyboard selection and Show all reset both work")

            page.set_viewport_size({"width": 390, "height": 844})
            assert page.locator(".node-card.tool").count() == 25
            assert page.locator("h1").is_visible()
            checks.append("Small viewport retains all source identities")

            assert "No runtime catalogue" in page.locator(".warning").inner_text()
            assert not errors, "Browser JavaScript errors: " + repr(errors)
            checks.append("Runtime caveat visible and no browser JavaScript errors")
        finally:
            browser.close()
    return {
        "checks": checks, "passed": len(checks),
        "mode": "offline_source_only_html_browser_smoke",
        "production_cutover_authorized": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(check_report(args.report), sort_keys=True))


if __name__ == "__main__":
    main()
