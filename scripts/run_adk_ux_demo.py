#!/usr/bin/env python3
"""Generate an offline UX acceptance report from the known-vulnerable Google ADK fixture.

The fixture is copied to a standalone application scan root before analysis.
Scanning under examples/ classifies the source as non-runtime and would not
exercise runtime OWASP drilldowns. The scanner never executes the application.
"""

from __future__ import annotations

import argparse
import json
import shutil
import tempfile
from pathlib import Path

from horustrace.scanner import scan
from horustrace.visual_report import build_visual_report, render_visual_report_html

REPO = Path(__file__).resolve().parents[1]
FIXTURE = REPO / "examples" / "google-adk-vulnerable"


def produce_report(output_dir: Path) -> tuple[dict, list[str]]:
    """Return the real report projection and explicit acceptance failures."""
    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="horustrace-ux-adk-") as temp:
        root = Path(temp) / "service"
        root.mkdir()
        for name in ("agent.py", "horustrace.manifest.yaml"):
            shutil.copyfile(FIXTURE / name, root / name)

        # Static scan: Google ADK and MCP packages are never imported or run.
        graph, findings = scan(root)
        report = build_visual_report(graph, findings, root)
        html = render_visual_report_html(graph, findings, root)

    (output_dir / "adk-security-workbench.html").write_text(html, encoding="utf-8")
    (output_dir / "adk-security-projection.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    summary = report["summary"]
    names = {agent["name"] for agent in report["agents"]}
    owasp = report["owasp_agentic"]
    mapped = [
        item for item in owasp["categories"] if item["runtime_status"] == "finding"
    ]
    results = {
        "agents": summary["agents"],
        "tools": summary["tools"],
        "mcp_servers": summary["mcp_servers"],
        "identities": summary["identities"],
        "resources": summary["resources"],
        "destinations": summary["destinations"],
        "effective_authority_relationships": summary["authority_relationships"],
        "attack_paths": summary["attack_paths"],
        "findings": summary["findings"],
        "owasp_categories_with_runtime_findings": len(mapped),
        "owasp_risk_categories": [f"{item['id']}: {item['title']}" for item in mapped],
        "policy_violations": summary["policy_violations"],
        "contract_violations": summary["contract_violations"],
        "coverage_incomplete": summary["analysis_incomplete"],
        "agent_names": sorted(names),
    }
    (output_dir / "adk-acceptance-metrics.json").write_text(
        json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    checks = {
        "coordinator and delegated worker": {
            "pass": {"adk_coordinator", "privileged_worker"} <= names,
            "observed": sorted(names),
        },
        "tool discovery": {"pass": summary["tools"] >= 3, "observed": summary["tools"]},
        "MCP inventory": {
            "pass": summary["mcp_servers"] >= 1,
            "observed": summary["mcp_servers"],
        },
        "attack paths": {
            "pass": summary["attack_paths"] >= 1,
            "observed": summary["attack_paths"],
        },
        "active findings": {
            "pass": summary["findings"] >= 1,
            "observed": summary["findings"],
        },
        "runtime OWASP-mapped findings": {
            "pass": len(mapped) >= 1,
            "observed": [item["id"] for item in mapped],
        },
        "source evidence in findings": {
            "pass": any(
                f.get("source_context") == "runtime" and f.get("location")
                for f in report["findings"]
            ),
            "observed": sorted(
                {f.get("source_context") or "unknown" for f in report["findings"]}
            ),
        },
        "HTML is standalone": {
            "pass": (
                "<script src=" not in html
                and "<link rel=" not in html
                and "default-src 'none'" in html
            ),
            "observed": "offline HTML + inline CSP",
        },
        "projection count parity": {
            "pass": (
                summary["findings"] == len(report["findings"])
                and summary["attack_paths"] == len(graph.attack_paths)
                and summary["agents"] == len(report["agents"])
            ),
            "observed": {
                "findings": summary["findings"],
                "paths": summary["attack_paths"],
                "agents": summary["agents"],
            },
        },
    }
    failures = [label for label, value in checks.items() if not value["pass"]]
    lines = [
        "# ADK security workbench — end-to-end acceptance",
        "",
        "Source: existing examples/google-adk-vulnerable copied into a clean "
        "runtime-application scan root.",
        "",
        "**Static source inspection only.** No ADK agent, MCP server, shell command, "
        "BigQuery operation or external endpoint was executed.",
        "",
        "| Dimension | Observed |",
        "| --- | ---: |",
    ]
    for label in (
        "agents", "tools", "mcp_servers", "identities", "resources",
        "destinations", "effective_authority_relationships", "findings",
        "attack_paths", "owasp_categories_with_runtime_findings",
        "policy_violations", "contract_violations",
    ):
        lines.append(f"| {label.replace('_', ' ').capitalize()} | {results[label]} |")
    lines.extend(["", "## OWASP risk categories with runtime-mapped findings", ""])
    lines.extend(f"- {name}" for name in results["owasp_risk_categories"])
    if not results["owasp_risk_categories"]:
        lines.append("- None detected (acceptance failure)")
    lines.extend([
        "",
        "OWASP mappings describe detector findings, not independent certification "
        "or a formal OWASP violation. Policy and Authority Contract violations "
        "are distinct counts.",
        "",
        "## Acceptance checks",
        "",
        "| Check | Result | Observed |",
        "| --- | --- | --- |",
    ])
    for label, state in checks.items():
        observed = json.dumps(state["observed"], sort_keys=True)
        lines.append(
            f"| {label} | {'PASS' if state['pass'] else 'FAIL'} | "
            f"{observed.replace('|', '/')} |"
        )
    lines.extend([
        "",
        f"**Outcome:** {'PASS' if not failures else 'FAIL'}",
        "",
        "The HTML report must also be opened in a browser to review chart "
        "drilldowns, keyboard access, layouts and evidence navigation. "
        "CLI checks do not substitute for that manual UX step.",
        "",
    ])
    (output_dir / "adk-acceptance-summary.md").write_text(
        "\n".join(lines), encoding="utf-8"
    )
    return report, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir", type=Path, default=Path("adk-ux-report"),
        help="Destination for standalone HTML, report projection and summary",
    )
    args = parser.parse_args()
    _, failures = produce_report(args.output_dir)
    print((args.output_dir / "adk-acceptance-summary.md").read_text(encoding="utf-8"))
    if failures:
        print("FAILED: " + ", ".join(failures))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
