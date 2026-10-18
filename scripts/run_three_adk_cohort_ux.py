#!/usr/bin/env python3
"""Produce three pinned, static-only Google ADK cohort HTML security workbenches.

External targets are cloned at frozen Full-60 SHAs and only read as source text.
No application imports, dependency installs, agent starts, or MCP connections.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import subprocess
import tempfile
import traceback
from pathlib import Path

from horustrace.scanner import scan
from horustrace.visual_report import build_visual_report, render_visual_report_html

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "research" / "full-framework-60-20261005" / "cohort.json"
SELECTED = (
    ("ff60-google-adk-09", "voiceover"),
    ("ff60-google-adk-10", "gitlab-incident-agent"),
    ("ff60-google-adk-08", "jarvis-adk-voice-agent"),
)


def run_git(*args: str, timeout: int = 900) -> str:
    proc = subprocess.run(
        ["git", *args], capture_output=True, text=True, timeout=timeout, check=False
    )
    if proc.returncode:
        raise RuntimeError(f"Git command failed ({proc.returncode}): {proc.stderr[-2500:]}")
    return proc.stdout.strip()


def checkout_pinned(case: dict, destination: Path) -> Path:
    run_git("init", "-q", str(destination))
    run_git("-C", str(destination), "remote", "add", "origin",
            f"https://github.com/{case['repo']}.git")
    run_git("-C", str(destination), "fetch", "--quiet", "--depth=1",
            "--filter=blob:none", "origin", case["sha"], timeout=1800)
    run_git("-C", str(destination), "checkout", "--quiet", "--detach", "FETCH_HEAD")
    actual = run_git("-C", str(destination), "rev-parse", "HEAD")
    if actual != case["sha"]:
        raise RuntimeError(f"Frozen source mismatch: expected {case['sha']}, got {actual}")
    base = destination.resolve()
    source = (base / (case.get("application_path") or ".")).resolve()
    if not source.is_relative_to(base) or not source.exists():
        raise RuntimeError("Unsafe or missing application source path")
    return source


def select_cases() -> list[tuple[dict, str]]:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    cases = {entry["case_id"]: entry for entry in manifest["cases"]}
    selected = []
    for case_id, slug in SELECTED:
        case = cases[case_id]
        if case["framework"] != "google-adk" or len(case["sha"]) != 40:
            raise ValueError(f"Invalid frozen ADK source entry: {case_id}")
        selected.append((case, slug))
    return selected


def generate(output_dir: Path) -> int:
    output_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict] = []
    failures = 0

    for case, slug in select_cases():
        directory = output_dir / slug
        directory.mkdir(parents=True, exist_ok=True)
        try:
            with tempfile.TemporaryDirectory(prefix=f"horustrace-{slug}-") as tmp:
                source = checkout_pinned(case, Path(tmp) / "target")
                graph, findings = scan(source)
                projection = build_visual_report(graph, findings, source)
                report_html = render_visual_report_html(graph, findings, source)

            if "<script src=" in report_html or "<link rel=" in report_html:
                raise AssertionError("Security workbench must be self-contained")
            if "default-src 'none'" not in report_html:
                raise AssertionError("Security workbench must preserve offline CSP")

            (directory / "security-workbench.html").write_text(
                report_html, encoding="utf-8"
            )
            (directory / "projection.json").write_text(
                json.dumps(projection, indent=2, default=str) + "\n", encoding="utf-8"
            )

            summary = projection.get("summary", {})
            row = {
                "case_id": case["case_id"],
                "repo": case["repo"],
                "target_sha": case["sha"],
                "scanner_sha": os.environ.get("GITHUB_SHA", "local"),
                "source_signal": case.get("source_signal"),
                "status": "ok",
                "agents": summary.get("agents", 0),
                "tools": summary.get("tools", 0),
                "mcp_servers": summary.get("mcp_servers", 0),
                "findings": summary.get("findings", 0),
                "attack_paths": summary.get("attack_paths", 0),
                "authority_relationships": summary.get("authority_relationships", 0),
                "coverage_incomplete": summary.get("analysis_incomplete", None),
            }
            (directory / "metadata.json").write_text(
                json.dumps(row, indent=2) + "\n", encoding="utf-8"
            )
            print(json.dumps(row))
        except Exception as exc:
            failures += 1
            row = {
                "case_id": case["case_id"],
                "repo": case["repo"],
                "target_sha": case["sha"],
                "status": "error",
                "error": f"{type(exc).__name__}: {exc}",
            }
            (directory / "error.json").write_text(
                json.dumps({**row, "traceback": traceback.format_exc()}, indent=2)
                + "\n", encoding="utf-8"
            )
            print(json.dumps(row))
        rows.append(row)

    (output_dir / "comparison.json").write_text(
        json.dumps(
            {"study": "frozen-full-60-adk-ux-three", "scanner_ref": "current branch",
             "static_source_only": True, "cases": rows},
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )

    lines = [
        "# Google ADK: three real-repository security workbench reports",
        "",
        "Pinned source from `research/full-framework-60-20261005/cohort.json`; "
        "scanner from the action's checked-out HorusTrace commit.",
        "",
        "**Source-only static inspection.** No target code or MCP server was executed, "
        "no runtime controls or permissions were independently verified, and "
        "findings/paths are not proof of exploitability.",
        "",
        "| Case | Repository | Agents | Tools | MCP | Authority links | Findings | Paths | Coverage |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for row in rows:
        if row["status"] == "ok":
            coverage = "incomplete" if row["coverage_incomplete"] else "not flagged incomplete"
            lines.append(
                f"| {row['case_id']} | {row['repo']} | {row['agents']} | "
                f"{row['tools']} | {row['mcp_servers']} | "
                f"{row['authority_relationships']} | {row['findings']} | "
                f"{row['attack_paths']} | {coverage} |"
            )
        else:
            lines.append(f"| {row['case_id']} | {row['repo']} | ERROR | — | — | — | — | — | — |")
    lines.extend([
        "",
        "## Open the HTML reports",
        "",
        "Download the `adk-cohort-ux-three` artifact from this workflow run. "
        "Open `index.html` or any repository's `security-workbench.html` locally.",
        "",
        "Each report includes the main assessment, agent views, components, supply chain, "
        "findings, OWASP mapping, paths, and evidence. Empty sections remain "
        "explicitly empty rather than being populated with invented claims.",
        "",
        "The reports are source-based security signals, not independent accuracy adjudication.",
        "",
    ])
    (output_dir / "summary.md").write_text("\n".join(lines), encoding="utf-8")

    trs = []
    for row, (_, slug) in zip(rows, SELECTED):
        if row["status"] == "ok":
            link = (
                f'<a href="{html.escape(slug)}/security-workbench.html">'
                "Open interactive report</a>"
            )
            counts = (
                f"{row['agents']} agents · {row['tools']} tools · "
                f"{row['mcp_servers']} MCP · {row['findings']} findings · "
                f"{row['attack_paths']} paths"
            )
        else:
            link = "Scan failed; inspect error.json"
            counts = html.escape(row["error"])
        trs.append(
            "<tr><td>" + html.escape(row["repo"]) + "</td><td>"
            + html.escape(row["case_id"]) + "</td><td>"
            + html.escape(counts) + "</td><td>" + link + "</td></tr>"
        )
    index = """<!doctype html><html lang="en"><meta charset="utf-8">
<title>HorusScan · ADK cohort reports</title><meta name="viewport"
content="width=device-width,initial-scale=1">
<style>body{font:16px system-ui;background:#f7f9fc;color:#213047;margin:3rem auto;
max-width:1150px;padding:0 1.3rem}h1{letter-spacing:-.03em}p{line-height:1.6}
table{width:100%;border-collapse:collapse;background:white}th,td{text-align:left;
border-bottom:1px solid #e0e6ed;padding:1rem}a{color:#1865a9}
small{color:#5a6774}</style>
<h1>Google ADK — three real-world security assessments</h1>
<p>Source-only scans of pinned public repositories from the Full-60 cohort,
using the current HorusTrace scanner. No target applications or MCP servers were run.</p>
<table><thead><tr><th>Repository</th><th>Case</th><th>Observed inventory</th>
<th>Offline report</th></tr></thead><tbody>""" + "\n".join(trs) + """</tbody></table>
<p><small>Findings and paths require source adjudication. Unknown authority must not
be read as an absence of risk. Full projections and pinned SHAs accompany each report.
</small></p></html>"""
    (output_dir / "index.html").write_text(index, encoding="utf-8")
    return 1 if failures else 0


def verify_browser(output_dir: Path) -> int:
    from playwright.sync_api import sync_playwright

    outcomes: list[dict] = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            for _, slug in SELECTED:
                filepath = (output_dir / slug / "security-workbench.html").resolve()
                errors: list[str] = []
                page = browser.new_page(viewport={"width": 1440, "height": 900})
                page.on("pageerror", lambda error: errors.append(str(error)))
                page.goto(filepath.as_uri(), wait_until="load")
                page.locator("#dashboard .metric").first.wait_for(timeout=20000)
                if page.locator("#dashboard .metric").count() < 6:
                    raise AssertionError(f"{slug}: dashboard metrics missing")
                page.screenshot(path=str(output_dir / slug / "dashboard.png"), full_page=True)
                for view in ("agents", "components", "supply", "findings", "owasp", "attack"):
                    page.locator(f'nav.nav button[data-view="{view}"]').click()
                    if page.locator(f"#{view}.active").count() != 1:
                        raise AssertionError(f"{slug}: navigation failed for {view}")
                if page.locator("#agents [data-agent]").count():
                    page.locator('nav.nav button[data-view="agents"]').click()
                    page.locator("#agents [data-agent]").first.click()
                    if page.locator("#agent-detail.active").count() != 1:
                        raise AssertionError(f"{slug}: agent drilldown failed")
                page.locator('nav.nav button[data-view="supply"]').click()
                if page.locator("#supply .supply-diagram").count():
                    page.screenshot(
                        path=str(output_dir / slug / "supply-chain.png"),
                        full_page=True,
                    )
                page.locator('[data-theme-choice="dark"]').click()
                if page.locator("html").get_attribute("data-theme") != "dark":
                    raise AssertionError(f"{slug}: theme toggle failed")
                if errors:
                    raise AssertionError(f"{slug}: browser JS errors: {errors}")
                outcomes.append({"report": slug, "status": "PASS", "javascript_errors": []})
                page.close()
        finally:
            browser.close()
    (output_dir / "browser-acceptance.json").write_text(
        json.dumps(outcomes, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(outcomes, indent=2))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/adk-cohort-ux-three"))
    parser.add_argument("--verify-browser", action="store_true")
    args = parser.parse_args()
    if args.verify_browser:
        return verify_browser(args.output_dir)
    return generate(args.output_dir)


if __name__ == "__main__":
    raise SystemExit(main())
