"""Pinned Playwright smoke: optional MCP evidence tab in the real Workbench.

Confirm source-only overlay navigation and inspectability, while the canonical
supply chain and standard report interactions continue to work unchanged.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from playwright.sync_api import sync_playwright


def check_report(path: Path) -> dict[str, object]:
    path = path.resolve(strict=True)
    errors: list[str] = []
    checks: list[str] = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            page = browser.new_page(viewport={"width": 1440, "height": 900})
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(path.as_uri(), wait_until="load")
            navigation = page.locator('.nav button[data-view="mcp-source-evidence"]')
            assert navigation.count() == 1
            navigation.click()
            root = page.locator("#mcp-source-evidence.active")
            assert root.count() == 1
            assert root.locator(
                '.mcp-evidence-node[data-kind="mcp_source_implementation"]'
            ).count() == 3
            assert root.locator(
                '.mcp-evidence-node[data-kind="mcp_source_tool"]'
            ).count() == 25
            assert root.locator(".mcp-evidence-agent").count() >= 3
            checks.append("Opt-in source tab renders 3 local servers and 25 tools")
            server = root.locator(
                '.mcp-evidence-node[data-kind="mcp_source_implementation"]'
            ).filter(has_text="Calculator")
            assert server.count() == 2
            assert len({
                item.locator(".mcp-evidence-site").inner_text()
                for item in server.all()
            }) == 2
            checks.append("Distinct same-name servers retain separate source sites")

            first = server.first
            first.click()
            assert first.get_attribute("aria-pressed") == "true"
            assert root.locator(".mcp-evidence-node.selected").count() == 1
            assert root.locator(".mcp-evidence-node.dimmed").count() > 0
            assert root.locator(".mcp-evidence-node").count() >= 28
            assert "Source agent contexts:" in root.locator(
                "#mcp-evidence-description"
            ).inner_text()
            checks.append("Source focus retains other nodes but defocuses unrelated")

            first.click()
            assert root.locator(".mcp-evidence-node.dimmed").count() == 0
            first.focus()
            first.press("Enter")
            assert first.get_attribute("aria-pressed") == "true"
            root.locator("[data-mcp-evidence-reset]").click()
            assert root.locator(".mcp-evidence-node.selected").count() == 0
            assert root.locator(".mcp-evidence-node.dimmed").count() == 0
            checks.append("Keyboard focus and Show all restore original graph")

            assert "effective AGENT_CAN_CALL" in root.inner_text()
            page.locator('.nav button[data-view="supply"]').click()
            assert page.locator("#supply.active .supply-diagram").count() > 0
            page.locator('.nav button[data-view="mcp-source-evidence"]').click()
            assert page.locator("#mcp-source-evidence.active").count() == 1
            checks.append("Canonical supply-chain navigation and source-only caveat intact")

            page.set_viewport_size({"width": 390, "height": 844})
            assert root.locator(
                '.mcp-evidence-node[data-kind="mcp_source_tool"]'
            ).count() == 25
            assert not errors, repr(errors)
            checks.append("Mobile viewport retains evidence; no JavaScript errors")
        finally:
            browser.close()
    return {
        "passed": len(checks), "checks": checks,
        "source_only": True, "production_cutover_authorized": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(check_report(args.report), sort_keys=True))


if __name__ == "__main__":
    main()
