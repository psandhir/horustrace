from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, date, datetime
from pathlib import Path

from horustrace import __version__
from horustrace.adapters.manifest import ManifestError
from horustrace.adapters.registry import adapter_catalogue
from horustrace.aibom import build_aibom
from horustrace.assurance import build_assurance_report
from horustrace.authority_contract import authority_contract_report
from horustrace.authority_query import (
    query_effective_authority,
    render_authority_query_console,
)
from horustrace.authority_resolution import authority_resolution_summary
from horustrace.benchmark import BenchmarkError
from horustrace.benchmark import render_console as render_benchmark_console
from horustrace.benchmark import render_json as render_benchmark_json
from horustrace.benchmark import run as run_benchmark
from horustrace.change_analysis import build_git_diff
from horustrace.change_analysis import render_console as render_diff_console
from horustrace.change_analysis import render_markdown as render_diff_markdown
from horustrace.config import ConfigError, load_config
from horustrace.deployment_discovery import (
    DeploymentDiscoveryError,
    discover_repository_deployment_evidence,
)
from horustrace.deployment_evidence import DeploymentEvidenceError, load_deployment_evidence
from horustrace.deployment_report import (
    build_deployment_security_report,
    render_deployment_security_console,
)
from horustrace.deployment_requirements import enrich_cross_layer_required_authority
from horustrace.effective_authority import (
    effective_authority_report,
    render_effective_authority_console,
)
from horustrace.git_snapshot import GitSnapshotError
from horustrace.limits import ScanLimitError
from horustrace.llm_semantics import LLMSemanticConfig
from horustrace.mcp_effective import effective_mcp_authority_report
from horustrace.models import Severity
from horustrace.owasp import build_owasp_agentic_summary, render_owasp_agentic_console
from horustrace.policy_proposal import (
    build_authority_policy_proposal,
    render_authority_policy_json,
    render_authority_policy_yaml,
)
from horustrace.provenance import control_observations
from horustrace.reporters.console import render as render_console
from horustrace.reporters.sarif import render as render_sarif
from horustrace.rule_registry import iter_rule_metadata
from horustrace.scanner import ScannerError, scan
from horustrace.security_graph import build_agent_security_graph
from horustrace.source_context import SOURCE_CONTEXTS
from horustrace.suppressions import SuppressionError, write_baseline
from horustrace.visual_report import render_visual_report_html


def _parse_excluded_source_contexts(values: list[str]) -> set[str]:
    contexts = {
        item.strip().lower().replace("_", "-")
        for value in values
        for item in value.split(",")
        if item.strip()
    }
    invalid = sorted(contexts - set(SOURCE_CONTEXTS))
    if invalid:
        raise ValueError(
            "unknown source context(s): "
            + ", ".join(invalid)
            + "; expected one of: "
            + ", ".join(SOURCE_CONTEXTS)
        )
    return contexts


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="horustrace", description="Security analysis for AI agents")
    parser.add_argument("--version", action="version", version=f"horustrace {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_parser = sub.add_parser("scan", help="Scan an agent project")
    scan_parser.add_argument("path", nargs="?", default=".")
    scan_parser.add_argument("--format", choices=["console", "json", "sarif"], default="console")
    scan_parser.add_argument("--output", type=Path)
    scan_parser.add_argument("--config", type=Path, help="Repository scanner configuration YAML file.")
    scan_parser.add_argument(
        "--authority-source",
        type=Path,
        help="Checked-out Terraform repository containing declared IAM bindings.",
    )
    scan_parser.add_argument("--suppressions", type=Path,
                             help="Explicit suppression YAML file.")
    scan_parser.add_argument(
        "--semantic-llm-provider",
        choices=["openai", "google", "gemini", "copilot"],
        help="Opt in to bounded LLM semantic escalation for unresolved source-backed gaps.",
    )
    scan_parser.add_argument(
        "--semantic-llm-model",
        help="Model used by --semantic-llm-provider.",
    )
    scan_parser.add_argument(
        "--semantic-llm-max-candidates",
        type=int,
        default=6,
        metavar="N",
        help="Maximum semantic gaps escalated to the LLM (default: 6).",
    )
    scan_parser.add_argument(
        "--semantic-llm-max-slice-chars",
        type=int,
        default=12000,
        metavar="N",
        help="Maximum source characters per semantic slice (default: 12000).",
    )
    scan_parser.add_argument(
        "--semantic-llm-max-total-chars",
        type=int,
        default=48000,
        metavar="N",
        help="Maximum source characters sent across the scan (default: 48000).",
    )
    scan_parser.add_argument(
        "--semantic-llm-min-confidence",
        type=float,
        default=0.75,
        metavar="P",
        help="Minimum confidence required to project inferred semantics (default: 0.75).",
    )
    scan_parser.add_argument(
        "--semantic-llm-cache",
        type=Path,
        help="Optional JSON cache for structured semantic results keyed by source slice hash.",
    )
    scan_parser.add_argument(
        "--exclude-source-context",
        "--exclude-source-role",
        dest="exclude_source_context",
        action="append",
        default=[],
        metavar="CONTEXTS",
        help=(
            "Comma-separated finding source contexts to exclude from active reporting "
            "and fail-on evaluation. Coverage is not suppressed."
        ),
    )
    scan_parser.add_argument("--strict", action="store_true",
                             help="Return exit code 1 when analysis is incomplete.")
    scan_parser.add_argument(
        "--max-unresolved-authority",
        type=int,
        metavar="N",
        help=(
            "Return exit code 1 when more than N effective-authority relationships "
            "have unresolved detail dimensions. Core resolution does not weaken "
            "this strict completeness gate."
        ),
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=["none", "low", "medium", "high", "critical"],
        default="high",
        help="Return exit code 2 when a finding at or above this severity is present.",
    )
    scan_parser.add_argument(
        "--fail-on-policy-violation",
        action="store_true",
        help=(
            "Return exit code 2 when the current scan proves an Authority Contract "
            "violation. Unresolved contract assessments do not fail this gate."
        ),
    )
    baseline_parser = sub.add_parser("baseline", help="Create expiring suppressions for current findings")
    baseline_parser.add_argument("path", nargs="?", default=".")
    baseline_parser.add_argument("--output", type=Path,
                                 default=Path(".horustrace.suppressions.yaml"))
    baseline_parser.add_argument("--reason", required=True)
    baseline_parser.add_argument("--expires", required=True,
                                 help="Required expiry date in YYYY-MM-DD format.")
    baseline_parser.add_argument("--force", action="store_true",
                                 help="Replace an existing output file.")
    benchmark_parser = sub.add_parser("benchmark", help="Run a reviewed expectation corpus")
    benchmark_parser.add_argument("manifest", nargs="?", type=Path,
                                  default=Path("benchmarks/cases.yaml"))
    benchmark_parser.add_argument("--format", choices=["console", "json"], default="console")
    benchmark_parser.add_argument("--output", type=Path)
    rules_parser = sub.add_parser("rules", help="List the built-in security rule catalogue")
    rules_parser.add_argument("--format", default="console", metavar="FORMAT")
    rules_parser.add_argument("--output", type=Path)
    adapters_parser = sub.add_parser(
        "adapters",
        help="List built-in framework adapters and their contract version",
    )
    adapters_parser.add_argument(
        "--format",
        choices=["console", "json"],
        default="console",
    )
    adapters_parser.add_argument("--output", type=Path)
    owasp_parser = sub.add_parser(
        "owasp",
        help="Summarize OWASP Agentic Top 10 detector coverage",
    )
    owasp_parser.add_argument("path", nargs="?", default=".")
    owasp_parser.add_argument(
        "--format",
        choices=["console", "json"],
        default="console",
    )
    owasp_parser.add_argument("--output", type=Path)
    owasp_parser.add_argument("--config", type=Path)
    graph_parser = sub.add_parser("graph", help="Export the Agent Dependency Graph")
    graph_parser.add_argument("path", nargs="?", default=".")
    graph_parser.add_argument("--output", type=Path)
    graph_parser.add_argument("--config", type=Path)
    graph_parser.add_argument(
        "--authority-source",
        type=Path,
        help="Checked-out Terraform repository containing declared IAM bindings.",
    )
    security_graph_parser = sub.add_parser(
        "security-graph",
        help="Export the versioned Agent Security Graph",
    )
    security_graph_parser.add_argument("path", nargs="?", default=".")
    security_graph_parser.add_argument("--output", type=Path)
    security_graph_parser.add_argument("--config", type=Path)
    security_graph_parser.add_argument(
        "--authority-source",
        type=Path,
        help="Checked-out Terraform repository containing declared IAM bindings.",
    )
    report_parser = sub.add_parser(
        "report",
        help="Generate a self-contained interactive HTML security report",
    )
    report_parser.add_argument("path", nargs="?", default=".")
    report_parser.add_argument(
        "--output",
        type=Path,
        default=Path("horustrace-report.html"),
        help="HTML output path (default: horustrace-report.html).",
    )
    report_parser.add_argument("--config", type=Path)
    report_parser.add_argument(
        "--authority-source",
        type=Path,
        help="Checked-out Terraform repository containing declared IAM bindings.",
    )
    authority_parser = sub.add_parser(
        "authority",
        help="Show effective agent-to-MCP authority relationships",
    )
    authority_parser.add_argument("path", nargs="?", default=".")
    authority_parser.add_argument(
        "--format",
        choices=["console", "json"],
        default="console",
    )
    authority_parser.add_argument("--output", type=Path)
    authority_parser.add_argument("--config", type=Path)
    policy_parser = sub.add_parser(
        "policy",
        help="Generate a reviewable Authority Contract proposal from observed authority",
    )
    policy_parser.add_argument("path", nargs="?", default=".")
    policy_parser.add_argument(
        "--format",
        choices=["yaml", "json"],
        default="yaml",
    )
    policy_parser.add_argument("--output", type=Path)
    policy_parser.add_argument("--config", type=Path)
    policy_parser.add_argument(
        "--authority-source",
        type=Path,
        help="Checked-out Terraform repository containing declared IAM bindings.",
    )
    query_parser = sub.add_parser(
        "query",
        help="Query effective authority and delegated reachability",
    )
    query_parser.add_argument("path", nargs="?", default=".")
    query_parser.add_argument("--agent", help="Filter principal agent name (glob supported).")
    query_parser.add_argument(
        "--capability",
        help="Filter effective capability (glob supported).",
    )
    query_parser.add_argument(
        "--target",
        help="Filter tool/MCP target name or kind:name (glob supported).",
    )
    query_parser.add_argument(
        "--destination",
        help="Filter network destination (glob supported).",
    )
    query_parser.add_argument(
        "--identity",
        help="Filter effective identity name (glob supported).",
    )
    query_parser.add_argument(
        "--resolution",
        choices=["fully_resolved", "partially_resolved", "unknown"],
        help="Filter strict detail-completeness resolution status.",
    )
    query_parser.add_argument(
        "--core-resolution",
        choices=["fully_resolved", "partially_resolved", "unknown"],
        help="Filter core target/capability resolution status.",
    )
    query_parser.add_argument(
        "--format",
        choices=["console", "json"],
        default="console",
    )
    query_parser.add_argument("--output", type=Path)
    query_parser.add_argument("--config", type=Path)
    query_parser.add_argument(
        "--authority-source",
        type=Path,
        help="Checked-out Terraform repository containing declared IAM bindings.",
    )
    reconcile_parser = sub.add_parser(
        "reconcile",
        help="Reconcile source authority with deployed cloud IAM evidence",
    )
    reconcile_parser.add_argument("path", nargs="?", default=".")
    reconcile_parser.add_argument(
        "--deployment-evidence",
        type=Path,
        help="Normalized v1 JSON/YAML deployment and IAM evidence snapshot.",
    )
    reconcile_parser.add_argument(
        "--deployment-source",
        type=Path,
        help=(
            "Checked-out Terraform/Kubernetes repository or directory from which "
            "literal deployment and IAM/RBAC evidence is discovered."
        ),
    )
    reconcile_parser.add_argument(
        "--deployment-provider",
        choices=["gcp", "aws", "azure", "kubernetes"],
        help=(
            "Provider bundle to use with --deployment-source. Required only when "
            "the source contains evidence for multiple providers."
        ),
    )
    reconcile_parser.add_argument(
        "--baseline-deployment-evidence",
        type=Path,
        help="Optional prior deployment evidence snapshot for drift analysis.",
    )
    reconcile_parser.add_argument(
        "--format",
        choices=["console", "json"],
        default="console",
    )
    reconcile_parser.add_argument("--output", type=Path)
    reconcile_parser.add_argument("--config", type=Path)
    reconcile_parser.add_argument(
        "--authority-source",
        type=Path,
        help="Optional checked-out Terraform repository containing declared IAM bindings.",
    )
    reconcile_parser.add_argument(
        "--fail-on-excess-authority",
        action="store_true",
        help="Return exit code 2 when supported excess deployed authority is found.",
    )
    reconcile_parser.add_argument(
        "--fail-on-deployed-policy-violation",
        action="store_true",
        help="Return exit code 2 when deployed authority violates an Authority Contract.",
    )
    reconcile_parser.add_argument(
        "--fail-on-deployment-regression",
        action="store_true",
        help="Return exit code 2 when deployment drift introduces excess or unresolved authority.",
    )
    aibom_parser = sub.add_parser("aibom", help="Generate an Agent Bill of Materials")
    aibom_parser.add_argument("path", nargs="?", default=".")
    aibom_parser.add_argument("--output", type=Path)
    aibom_parser.add_argument("--config", type=Path)
    aibom_parser.add_argument(
        "--authority-source",
        type=Path,
        help="Checked-out Terraform repository containing declared IAM bindings.",
    )
    diff_parser = sub.add_parser(
        "diff",
        help="Compare findings and effective authority across two Git revisions",
    )
    diff_parser.add_argument(
        "revision_range",
        metavar="BASE..HEAD",
        help="Two Git revisions separated by '..', for example origin/main..HEAD.",
    )
    diff_parser.add_argument(
        "--repo",
        type=Path,
        default=Path("."),
        help="Path inside the Git repository to compare (default: current directory).",
    )
    diff_parser.add_argument(
        "--format",
        choices=["console", "json", "markdown"],
        default="console",
    )
    diff_parser.add_argument("--output", type=Path)
    diff_parser.add_argument(
        "--strict",
        action="store_true",
        help="Return exit code 1 when either revision has incomplete analysis.",
    )
    diff_parser.add_argument(
        "--fail-on",
        choices=["none", "low", "medium", "high", "critical"],
        default="high",
        help=(
            "Return exit code 2 when an introduced finding meets the severity threshold."
        ),
    )
    diff_parser.add_argument(
        "--fail-on-authority-regression",
        action="store_true",
        help=(
            "Return exit code 1 when the head revision has more relationships "
            "with unresolved detail dimensions than the base revision."
        ),
    )
    diff_parser.add_argument(
        "--fail-on-policy-violation",
        action="store_true",
        help=(
            "Return exit code 2 when the head revision introduces a new "
            "Authority Contract violation or weakens the contract."
        ),
    )
    return parser


def _rule_catalogue_json() -> str:
    return json.dumps(
        {
            "schema_version": 1,
            "rules": [
                {
                    "rule_id": rule.rule_id,
                    "layer": rule.layer,
                    "title": rule.title,
                    "default_severity": rule.default_severity.label(),
                    "category": rule.category,
                    "assessment": rule.assessment,
                    "rationale": rule.rationale,
                    "remediation": rule.remediation,
                    "references": list(rule.references),
                    "owasp_agentic": list(rule.owasp_agentic),
                }
                for rule in iter_rule_metadata()
            ],
        },
        indent=2,
    )


def _adapter_catalogue_console() -> str:
    lines = ["HorusTrace Adapter Catalogue", "=" * 32, ""]
    for item in adapter_catalogue():
        lines.append(
            f"{item['name']}  contract=v{item['contract_version']}  "
            f"language={item['language']}  execution={item['execution_model']}"
        )
    return "\n".join(lines).rstrip()


def _rule_catalogue_console() -> str:
    lines = ["HorusTrace Rule Catalogue", "=" * 30, ""]
    for rule in iter_rule_metadata():
        lines.extend(
            [
                f"{rule.rule_id}  L{rule.layer}  {rule.default_severity.label()}  {rule.title}",
                f"  Category: {rule.category}; assessment: {rule.assessment}",
                f"  Rationale: {rule.rationale}",
                f"  Remediation: {rule.remediation}",
                "",
            ]
        )
    return "\n".join(lines).rstrip()


def _parse_revision_range(value: str) -> tuple[str, str]:
    if "..." in value or value.count("..") != 1:
        raise ValueError("revision range must use BASE..HEAD")
    base_ref, head_ref = (item.strip() for item in value.split("..", 1))
    if not base_ref or not head_ref:
        raise ValueError("revision range must include both BASE and HEAD")
    return base_ref, head_ref


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "adapters":
        report = {
            "schema_version": 1,
            "adapters": adapter_catalogue(),
        }
        output = (
            json.dumps(report, indent=2)
            if args.format == "json"
            else _adapter_catalogue_console()
        )
        if args.output:
            args.output.write_text(output + "\n", encoding="utf-8")
        else:
            print(output)
        return 0
    if args.command == "rules":
        if args.format not in {"console", "json"}:
            print(
                "horustrace: rules --format must be one of: console, json",
                file=sys.stderr,
            )
            return 1
        output = _rule_catalogue_json() if args.format == "json" else _rule_catalogue_console()
        if args.output:
            args.output.write_text(output + "\n", encoding="utf-8")
        else:
            print(output)
        return 0
    if args.command == "benchmark":
        try:
            report = run_benchmark(args.manifest)
        except BenchmarkError as exc:
            print(f"horustrace: {exc}", file=sys.stderr)
            return 1
        output = (render_benchmark_json(report) if args.format == "json"
                  else render_benchmark_console(report))
        if args.output:
            args.output.write_text(output + "\n", encoding="utf-8")
        else:
            print(output)
        summary = report["summary"]
        return 0 if summary["passed"] == summary["cases"] else 1
    if args.command == "diff":
        try:
            base_ref, head_ref = _parse_revision_range(args.revision_range)
            report = build_git_diff(args.repo, base_ref, head_ref)
        except (
            ValueError,
            GitSnapshotError,
            ConfigError,
            ManifestError,
            ScannerError,
            SuppressionError,
            ScanLimitError,
        ) as exc:
            print(f"horustrace: {exc}", file=sys.stderr)
            return 1

        if args.format == "json":
            output = json.dumps(report, indent=2)
        elif args.format == "markdown":
            output = render_diff_markdown(report)
        else:
            output = render_diff_console(report)
        if args.output:
            args.output.write_text(output + "\n", encoding="utf-8")
        else:
            print(output)

        if args.strict and (
            report["base"]["analysis_incomplete"]
            or report["head"]["analysis_incomplete"]
        ):
            return 1
        if args.fail_on_authority_regression and report["authority_resolution"]["regressed"]:
            return 1
        if args.fail_on_policy_violation and (
            report["authority_policy_delta"]["introduced_violations"]
            or report["authority_policy_delta"]["contract_weakenings"]
        ):
            return 2
        if args.fail_on != "none":
            threshold = Severity.parse(args.fail_on)
            introduced_at_threshold = any(
                Severity.parse(item["severity"]) >= threshold
                for item in report["findings"]["introduced"]
            )
            worsened_at_threshold = any(
                Severity.parse(item["after"]["severity"]) >= threshold
                for item in report["findings"]["worsened"]
            )
            if introduced_at_threshold or worsened_at_threshold:
                return 2
        return 0
    excluded_source_contexts: set[str] = set()
    if args.command == "scan":
        try:
            excluded_source_contexts = _parse_excluded_source_contexts(
                args.exclude_source_context
            )
        except ValueError as exc:
            print(f"horustrace: {exc}", file=sys.stderr)
            return 1

    target = Path(args.path)
    if not target.exists():
        print(f"horustrace: target does not exist: {target}", file=sys.stderr)
        return 1

    if args.command == "reconcile":
        try:
            root = target if target.is_dir() else target.parent
            config = load_config(root, args.config)
            graph, _ = scan(
                target,
                config=config,
                authority_source=args.authority_source,
            )
            if bool(args.deployment_evidence) == bool(args.deployment_source):
                raise DeploymentEvidenceError(
                    "provide exactly one of --deployment-evidence or --deployment-source"
                )
            if args.deployment_evidence is not None:
                if args.deployment_provider is not None:
                    raise DeploymentEvidenceError(
                        "--deployment-provider is only valid with --deployment-source"
                    )
                deployment_evidence = load_deployment_evidence(args.deployment_evidence)
            else:
                discovery = discover_repository_deployment_evidence(
                    args.deployment_source
                )
                bundles = list(discovery.bundles)
                if args.deployment_provider is not None:
                    bundles = [
                        item
                        for item in bundles
                        if item.provider == args.deployment_provider
                    ]
                    if not bundles:
                        raise DeploymentEvidenceError(
                            "deployment source contains no evidence for provider "
                            f"{args.deployment_provider}"
                        )
                if len(bundles) != 1:
                    providers = ", ".join(item.provider for item in bundles) or "none"
                    raise DeploymentEvidenceError(
                        "deployment source must resolve to exactly one provider bundle; "
                        f"found: {providers}. Use --deployment-provider when needed."
                    )
                deployment_evidence = bundles[0]
                graph.coverage.resolution["deployment_discovery"] = discovery.as_dict()
            if args.authority_source is not None:
                deployment_requirements = enrich_cross_layer_required_authority(
                    graph,
                    target,
                    args.authority_source,
                    deployment_evidence,
                )
                graph.coverage.resolution["deployment_requirements"] = (
                    deployment_requirements.as_dict()
                )
            baseline_evidence = (
                load_deployment_evidence(args.baseline_deployment_evidence)
                if args.baseline_deployment_evidence
                else None
            )
            if args.fail_on_deployment_regression and baseline_evidence is None:
                raise DeploymentEvidenceError(
                    "--fail-on-deployment-regression requires "
                    "--baseline-deployment-evidence"
                )
            report = build_deployment_security_report(
                graph,
                deployment_evidence,
                baseline=baseline_evidence,
                source_root=target,
            )
        except (
            ConfigError,
            ManifestError,
            ScannerError,
            SuppressionError,
            ScanLimitError,
            DeploymentEvidenceError,
            DeploymentDiscoveryError,
        ) as exc:
            print(f"horustrace: {exc}", file=sys.stderr)
            return 1

        output = (
            json.dumps(report, indent=2)
            if args.format == "json"
            else render_deployment_security_console(report, target)
        )
        if args.output:
            args.output.write_text(output + "\n", encoding="utf-8")
        else:
            print(output)

        summary = report["summary"]
        if (
            args.fail_on_excess_authority
            and summary["excess_authority_agents"]
        ):
            return 2
        if (
            args.fail_on_deployed_policy_violation
            and summary["deployed_policy_violations"]
        ):
            return 2
        if (
            args.fail_on_deployment_regression
            and summary["deployment_regressed_agents"]
        ):
            return 2
        return 0

    if args.command in {"graph", "security-graph", "report", "aibom", "authority", "policy", "query", "owasp"}:
        try:
            root = target if target.is_dir() else target.parent
            config = load_config(root, args.config)
            graph, findings = scan(
                target,
                config=config,
                authority_source=getattr(args, "authority_source", None),
                use_default_suppressions=args.command != "owasp",
            )
        except (ConfigError, ManifestError, ScannerError, SuppressionError, ScanLimitError) as exc:
            print(f"horustrace: {exc}", file=sys.stderr)
            return 1

        if args.command == "report":
            output = render_visual_report_html(graph, findings, root)
        elif args.command == "authority":
            report = effective_authority_report(graph)
            output = (
                json.dumps(report, indent=2)
                if args.format == "json"
                else render_effective_authority_console(graph, target)
            )
        elif args.command == "policy":
            report = build_authority_policy_proposal(graph)
            output = (
                render_authority_policy_json(report)
                if args.format == "json"
                else render_authority_policy_yaml(report)
            )
            if report["diagnostics"] and args.format == "yaml":
                print(
                    "horustrace: policy proposal contains unresolved authority; "
                    "review JSON diagnostics before enforcement",
                    file=sys.stderr,
                )
        elif args.command == "query":
            try:
                report = query_effective_authority(
                    graph,
                    root,
                    agent=args.agent,
                    capability=args.capability,
                    target=args.target,
                    destination=args.destination,
                    identity=args.identity,
                    resolution=args.resolution,
                    core_resolution=args.core_resolution,
                )
            except ValueError as exc:
                print(f"horustrace: {exc}", file=sys.stderr)
                return 1
            output = (
                json.dumps(report, indent=2)
                if args.format == "json"
                else render_authority_query_console(report)
            )
        elif args.command == "owasp":
            disabled_rules = graph.configuration_audit.get("disabled_rules", [])
            report = build_owasp_agentic_summary(
                findings,
                disabled_rules=disabled_rules,
            )
            output = (
                json.dumps(report, indent=2)
                if args.format == "json"
                else render_owasp_agentic_console(
                    findings,
                    disabled_rules=disabled_rules,
                )
            )
        elif args.command == "security-graph":
            document = build_agent_security_graph(graph, root).as_dict()
            output = json.dumps(document, indent=2)
        else:
            if graph.adg is None:
                print("horustrace: Agent Dependency Graph was not generated", file=sys.stderr)
                return 1
            document = (
                graph.adg.as_dict()
                if args.command == "graph"
                else build_aibom(graph.adg)
            )
            output = json.dumps(document, indent=2)

        if args.output:
            args.output.write_text(output + "\n", encoding="utf-8")
        else:
            print(output)
        return 0

    try:
        if args.command == "baseline":
            if not args.reason.strip():
                print("horustrace: --reason must not be blank", file=sys.stderr)
                return 1
            try:
                expiry = date.fromisoformat(args.expires)
            except ValueError:
                print("horustrace: --expires must be YYYY-MM-DD", file=sys.stderr)
                return 1
            if expiry < datetime.now(tz=UTC).date():
                print("horustrace: --expires must not be in the past", file=sys.stderr)
                return 1
            if args.output.exists() and not args.force:
                print("horustrace: baseline output exists; use --force to replace it",
                      file=sys.stderr)
                return 1
            graph, findings = scan(target, use_default_suppressions=False)
            if graph.coverage.incomplete:
                print("horustrace: baseline refused because analysis is incomplete",
                      file=sys.stderr)
                return 1
            baseline_root = target.resolve() if target.is_dir() else target.resolve().parent
            write_baseline(findings, baseline_root, args.output, args.reason.strip(), expiry)
            print(f"Wrote {len(findings)} expiring suppressions to {args.output}")
            return 0
        config = load_config(target if target.is_dir() else target.parent, args.config)
        llm_semantic_config = None
        if args.semantic_llm_provider or args.semantic_llm_model:
            if not args.semantic_llm_provider or not args.semantic_llm_model:
                print(
                    "horustrace: --semantic-llm-provider and --semantic-llm-model "
                    "must be provided together",
                    file=sys.stderr,
                )
                return 1
            try:
                llm_semantic_config = LLMSemanticConfig(
                    provider=args.semantic_llm_provider,
                    model=args.semantic_llm_model,
                    max_candidates=args.semantic_llm_max_candidates,
                    max_slice_chars=args.semantic_llm_max_slice_chars,
                    max_total_chars=args.semantic_llm_max_total_chars,
                    min_confidence=args.semantic_llm_min_confidence,
                    cache_path=args.semantic_llm_cache,
                )
                llm_semantic_config.validate()
            except ValueError as exc:
                print(f"horustrace: {exc}", file=sys.stderr)
                return 1
        graph, findings = scan(
            target,
            suppressions_path=args.suppressions,
            config=config,
            authority_source=args.authority_source,
            llm_semantic_config=llm_semantic_config,
        )
        disabled_rules = graph.configuration_audit.get("disabled_rules", [])
        authority_resolution = authority_resolution_summary(graph)
        authority_contract = authority_contract_report(graph)
        source_context_counts_before = {
            context: sum(
                finding.source_context == context for finding in findings
            )
            for context in SOURCE_CONTEXTS
            if any(finding.source_context == context for finding in findings)
        }
        excluded_source_context_counts = {
            context: sum(
                finding.source_context == context for finding in findings
            )
            for context in sorted(excluded_source_contexts)
            if any(finding.source_context == context for finding in findings)
        }
        if excluded_source_contexts:
            findings = [
                finding
                for finding in findings
                if finding.source_context not in excluded_source_contexts
            ]
        source_context_counts_after = {
            context: sum(
                finding.source_context == context for finding in findings
            )
            for context in SOURCE_CONTEXTS
            if any(finding.source_context == context for finding in findings)
        }
        graph.configuration_audit.update(
            {
                "excluded_source_contexts": sorted(excluded_source_contexts),
                "excluded_findings_by_source_context": dict(
                    sorted(excluded_source_context_counts.items())
                ),
                "source_context_counts_before_filter": dict(
                    sorted(source_context_counts_before.items())
                ),
                "source_context_counts_after_filter": dict(
                    sorted(source_context_counts_after.items())
                ),
            }
        )
        owasp_agentic = build_owasp_agentic_summary(
            findings,
            disabled_rules=disabled_rules,
        )
        assurance = build_assurance_report(
            findings,
            authority_contract,
            owasp_agentic,
        )
    except (ConfigError, ManifestError, ScannerError, SuppressionError, ScanLimitError) as exc:
        print(f"horustrace: {exc}", file=sys.stderr)
        return 1
    if args.format == "console":
        output = render_console(graph, findings, target, authority_contract)
    elif args.format == "json":
        output = json.dumps(
            {
                "version": __version__,
                "coverage": graph.coverage.as_dict(),
                "skills": {
                    "bound": [
                        {
                            "agent": agent.name,
                            "name": skill.name,
                            "description": skill.description,
                            "allowed_tools": sorted(skill.allowed_tools),
                            "scripts": list(skill.scripts),
                            "source": skill.source,
                            "location": (
                                {
                                    "path": str(skill.location.path),
                                    "line": skill.location.line,
                                    "column": skill.location.column,
                                }
                                if skill.location
                                else None
                            ),
                            "binding_origin": skill.metadata.get("binding_origin"),
                        }
                        for agent in graph.agents
                        for skill in agent.skills
                    ],
                    "unbound": [
                        {
                            "name": skill.name,
                            "description": skill.description,
                            "allowed_tools": sorted(skill.allowed_tools),
                            "scripts": list(skill.scripts),
                            "source": skill.source,
                            "location": (
                                {
                                    "path": str(skill.location.path),
                                    "line": skill.location.line,
                                    "column": skill.location.column,
                                }
                                if skill.location
                                else None
                            ),
                        }
                        for skill in graph.unbound_skills
                    ],
                },
                "control_observations": control_observations(graph),
                "mcp_authority": effective_mcp_authority_report(graph),
                "effective_authority": effective_authority_report(graph),
                "authority_resolution": authority_resolution,
                "assurance": assurance,
                "authority_contract": authority_contract,
                "owasp_agentic": owasp_agentic,
                "configuration": {
                    "path": str(config.source_path) if config.source_path else None,
                    "repository": {"strict": config.strict},
                    "cli_overrides": {
                        "strict": bool(args.strict),
                        "exclude_source_contexts": sorted(excluded_source_contexts),
                    },
                    "effective": {
                        "strict": bool(args.strict or config.strict),
                        "exclude_source_contexts": sorted(excluded_source_contexts),
                    },
                    "disabled_rules": disabled_rules,
                    "rule_overrides": {
                        rule_id: {
                            "enabled": override.enabled,
                            "severity": (
                                override.severity.label()
                                if override.severity
                                else None
                            ),
                        }
                        for rule_id, override in config.rules.items()
                    },
                },
                "suppressions": {
                    "suppressed_findings": [f.as_dict() for f in graph.suppressed_findings],
                    "diagnostics": graph.suppression_diagnostics,
                },
                "summary": {
                    "agents": len(graph.agents),
                    "tools": len(graph.all_tools()),
                    "skills": len(graph.all_skills()),
                    "bound_skills": sum(len(agent.skills) for agent in graph.agents),
                    "unbound_skills": len(graph.unbound_skills),
                    "mcp_servers": len(graph.all_mcp_servers()),
                    "identities": len(graph.all_identities()),
                    "flow_paths": len(graph.flow_paths),
                    "flow_execution_contexts": (
                        graph.coverage.resolution.get("flows", {}).get(
                            "execution_contexts",
                            {},
                        )
                    ),
                    "flow_agent_reachability": (
                        graph.coverage.resolution.get("flows", {}).get(
                            "agent_reachability",
                            {},
                        )
                    ),
                    "flow_agent_attribution_gaps": (
                        graph.coverage.resolution.get("flows", {}).get(
                            "agent_attribution_gaps",
                            0,
                        )
                    ),
                    "attack_paths": len(graph.attack_paths),
                    "adg_nodes": len(graph.adg.nodes) if graph.adg else 0,
                    "adg_edges": len(graph.adg.edges) if graph.adg else 0,
                    "findings": len(findings),
                    "policy_violations": assurance["organization_policy"]["violations"],
                    "owasp_categories_with_findings": assurance["owasp_agentic"][
                        "categories_with_findings"
                    ],
                    "owasp_categories_not_assessed": assurance["owasp_agentic"][
                        "categories_not_assessed"
                    ],
                    "authority_contract_violations": authority_contract["summary"]["violations"],
                    "authority_contract_unresolved": authority_contract["summary"]["unresolved"],
                    "authority_contract_relationships": authority_contract["summary"][
                        "relationships_evaluated"
                    ],
                    "suppressed_findings": len(graph.suppressed_findings),
                    "findings_by_source_context": dict(
                        sorted(source_context_counts_after.items())
                    ),
                    "findings_by_source_context_before_filter": dict(
                        sorted(source_context_counts_before.items())
                    ),
                    "excluded_findings": sum(
                        excluded_source_context_counts.values()
                    ),
                    "excluded_findings_by_source_context": dict(
                        sorted(excluded_source_context_counts.items())
                    ),
                    "findings_by_layer": {
                        str(layer): sum(1 for finding in findings if finding.layer == layer)
                        for layer in range(1, 6)
                    },
                },
                "flow_paths": [flow.as_dict() for flow in graph.flow_paths],
                "adg": {
                    "schema_version": 1,
                    "digest": graph.adg.canonical_digest() if graph.adg else None,
                    "summary": graph.adg.as_dict()["summary"] if graph.adg else None,
                },
                "attack_paths": [
                    {
                        "path_id": path.path_id,
                        "title": path.title,
                        "agent": path.agent,
                        "severity": path.severity.label(),
                        "nodes": path.nodes,
                        "rationale": path.rationale,
                        "assessment": path.metadata.get("assessment", "potential_risk"),
                        "basis": path.metadata.get("basis", "capability_cooccurrence"),
                        "flow_id": path.metadata.get("flow_id"),
                        "exploitability": "not_verified",
                        "confidence": next(
                            (
                                finding.confidence.value
                                for finding in findings
                                if finding.rule_id == path.path_id
                                and finding.agent == path.agent
                                and finding.confidence is not None
                            ),
                            None,
                        ),
                        "limitations": path.metadata.get("limitations", []),
                    }
                    for path in graph.attack_paths
                ],
                "findings": [f.as_dict() for f in findings],
            },
            indent=2,
        )
    else:
        output = json.dumps(render_sarif(
            findings, graph.coverage, control_observations(graph),
            graph.suppressed_findings, graph.suppression_diagnostics,
            graph.flow_paths, disabled_rules, authority_contract,
        ), indent=2)

    if args.output:
        args.output.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)

    if args.max_unresolved_authority is not None:
        if args.max_unresolved_authority < 0:
            print("horustrace: --max-unresolved-authority must be >= 0", file=sys.stderr)
            return 1
        if authority_resolution["unresolved_relationships"] > args.max_unresolved_authority:
            print(
                "horustrace: unresolved effective-authority relationship budget exceeded: "
                f"{authority_resolution['unresolved_relationships']} > "
                f"{args.max_unresolved_authority}",
                file=sys.stderr,
            )
            return 1

    expired_suppression = any(d["status"] == "expired" for d in graph.suppression_diagnostics)
    if (args.strict or config.strict) and (graph.coverage.incomplete or expired_suppression):
        return 1

    if args.fail_on_policy_violation and authority_contract["summary"]["violations"]:
        return 2

    if args.fail_on != "none":
        threshold = Severity.parse(args.fail_on)
        if any(f.severity >= threshold for f in findings):
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
