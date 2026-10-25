"""C02q: exact-source scanner ↔ provisional model judge discrepancy study.

Only static HorusTrace source scanning; no target repository imports, installs,
runtime invocations or trusted-source accuracy claims. Candidate differences
are review queues, never certified TP/FP/FN/TN.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

from horustrace.adg import build_adg
from horustrace.effective_authority import effective_authority_report
from horustrace.scanner import scan
from horustrace.source_truth_llm_judge import adjudicate_pinned_ledger_opinions
from horustrace.source_truth_oracle import validate_reference

PINS = {
    "rw-005": (
        "Ojas-Patil26/VeriQ",
        "067cb330ab943279b4b8ea13c91c9042bdd9f421",
        "agent.py",
        "research/wave-c-c02g-real-source/rw-005-source-candidates.json",
        "research/wave-c-c02m-rw005/model-reviewed-provisional-reference.json",
    ),
    "rw-080": (
        "Amlan66/SSEEnabledMCPAgent",
        "11531239e71b123f25b3c6103ee36a9d614d0032",
        "agent.py",
        "research/wave-c-c02i-rw080/mcp-source-candidates.json",
        "research/wave-c-c02p-mcp-judge/rw-080-model-opinions.json",
    ),
}
SOURCE_AGENTS = {
    "ingestion": ("agent.py", 17),
    "anomaly": ("agent.py", 44),
    "cause": ("agent.py", 70),
    "report": ("agent.py", 106),
    "coordinator": ("agent.py", 134),
}
AGENT_CLAIMS = {
    "source_declared_agent:ingestion_constructor": "ingestion",
    "source_declared_agent:anomaly_constructor": "anomaly",
    "source_declared_agent:cause_constructor": "cause",
    "source_declared_agent:report_constructor": "report",
    "source_declared_agent:coordinator_constructor": "coordinator",
}
SUBAGENT_CLAIMS = {
    "declared_subagent:root_to_ingestion": "ingestion",
    "declared_subagent:root_to_anomaly": "anomaly",
    "declared_subagent:root_to_cause": "cause",
    "declared_subagent:root_to_report": "report",
}
TOOL_CLAIMS = {
    "declared_direct_tool_listing:ingestion_list_metrics": ("ingestion", "list_metrics"),
    "declared_direct_tool_listing:ingestion_timeseries": (
        "ingestion", "get_metric_timeseries",
    ),
    "declared_direct_tool_listing:ingestion_lineage": ("ingestion", "get_metric_lineage"),
    "declared_direct_tool_listing:anomaly_timeseries": (
        "anomaly", "get_metric_timeseries",
    ),
    "declared_direct_tool_listing:anomaly_detect": (
        "anomaly", "detect_metric_anomalies",
    ),
    "declared_direct_tool_listing:cause_schema": ("cause", "get_metric_schema"),
    "declared_direct_tool_listing:cause_lineage": ("cause", "get_metric_lineage"),
    "declared_direct_tool_listing:cause_changes": ("cause", "get_recent_changes"),
}
MCP_SERVER_CLAIMS = {
    "source_mcp_server:server1_FastMCP_declaration": ("mcp_server_1.py", 33),
    "source_mcp_server:server2_FastMCP_declaration": ("mcp_server_2.py", 28),
    "source_mcp_server:server3_FastMCP_declaration": ("mcp_server_3.py", 209),
    "source_mcp_server:telegram_FastMCP_declaration": (
        "mcp_telegram_server.py", 27,
    ),
}
MCP_EXPORT_CLAIMS = {
    "source_edge:server1_declares_mcp_tool_decorator": "mcp_server_1.py",
    "source_edge:server2_declares_mcp_tool_decorator": "mcp_server_2.py",
    "source_edge:server3_declares_mcp_tool_decorator": "mcp_server_3.py",
    "source_edge:telegram_declares_mcp_tool_decorator": "mcp_telegram_server.py",
}
APP_CONTEXTS = ("application", "repository")


def _check_git(root: Path, *args: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True, check=True, timeout=40,
    )
    return result.stdout


def _repo_path(item: Any) -> str:
    path = item
    if not isinstance(path, str) or not path or path.startswith(("/", "./")):
        raise ValueError("invalid source relative path")
    if "//" in path or "\\" in path or ".." in path.split("/"):
        raise ValueError("unsafe source relative path")
    return path


def verify_git_source_witnesses(
    source: Path, ledger: dict[str, Any], *,
    expected_commit: str, expected_repo: str,
) -> dict[str, Any]:
    """Require every model source anchor to match exact committed Git bytes."""
    if (ledger.get("pinned_commit_sha"), ledger.get("repository")) != (
        expected_commit, expected_repo
    ):
        raise ValueError("source candidate ledger not bound to selected repo/SHA")
    if _check_git(source, "rev-parse", "HEAD").decode().strip() != expected_commit:
        raise ValueError("source checkout HEAD differs from immutable source revision")
    observations = ledger.get("observations")
    if not isinstance(observations, list) or not observations:
        raise ValueError("no pinned source witnesses")
    paths: dict[str, tuple[str, list[str]]] = {}
    visited = set()
    for row in observations:
        path = _repo_path(row["path"])
        sha = row["blob_sha"]
        if path not in paths:
            info = _check_git(source, "ls-tree", "HEAD", "--", path).decode().strip()
            if info != f"100644 blob {sha}\t{path}":
                raise ValueError(f"source Git blob mismatch: {path}")
            raw = _check_git(source, "cat-file", "blob", sha)
            digest = hashlib.sha1(
                b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw
            ).hexdigest()
            if digest != sha:
                raise ValueError("corrupted pinned Git blob bytes")
            paths[path] = sha, raw.decode("utf-8").splitlines()
        else:
            if paths[path][0] != sha:
                raise ValueError(f"conflicting source blob: {path}")
        start = row.get("line_start", row.get("line"))
        end = row.get("line_end", row.get("line"))
        if (type(start) is not int or type(end) is not int
                or start < 1 or end < start or end > len(paths[path][1])):
            raise ValueError(f"invalid pinned source line witness: {path}")
        expression = row.get("source_expression", row.get("expression"))
        if not isinstance(expression, str) or not expression.strip():
            raise ValueError("empty source expression")
        # These archived witnesses are one-line source syntax anchors.
        if start != end or paths[path][1][start - 1].strip() != expression.strip():
            raise ValueError(f"source text differs from pinned witness: {path}:{start}")
        witness = path, sha, start, end
        if witness in visited:
            raise ValueError("duplicate source witness")
        visited.add(witness)
    return {
        "source_revision_verified": True,
        "exact_source_blob_lines_checked": len(visited),
        "exact_source_blobs_checked": len(paths),
        "source_repo": expected_repo,
        "source_sha": expected_commit,
        "semantic_truth_independently_verified": False,
    }


def _at(row: dict[str, Any], file: str, line: int, *, delta: int = 0) -> bool:
    loc = row.get("location")
    if not isinstance(loc, dict):
        return False
    path, number = loc.get("path"), loc.get("line")
    if not isinstance(path, str) or type(number) is not int:
        return False
    return (
        path.replace("\\", "/").lstrip("./").split("/")[-1] == file.split("/")[-1]
        and abs(number - line) <= delta
    )


def compare_adg_with_model_opinions(
    case_id: str, reference: dict[str, Any], adg: dict[str, Any],
) -> dict[str, Any]:
    """Evaluate ONLY explicitly mapped source constructs; preserve the rest.

    No scanner inventory field is silently translated into a C02 V2 claim.
    Source line and edge checks are candidate alignment hints, not source truth.
    """
    validate_reference(reference)
    if case_id not in PINS or any(
        s["case_id"] != case_id
        or s["review_method"] != "model_reviewed"
        or s["positive_complete"] is not False
        or s["negative_complete"] is not False
        for s in reference["scopes"]
    ):
        raise ValueError("provisional model reference or pinned case mismatch")
    nodes = adg.get("nodes")
    edges = adg.get("edges")
    if not isinstance(nodes, list) or not isinstance(edges, list):
        raise ValueError("ADG requires complete nodes and edges")
    node_map = {n["id"]: n for n in nodes}
    if len(node_map) != len(nodes):
        raise ValueError("duplicate ADG node IDs")
    if any(e.get("source") not in node_map or e.get("target") not in node_map
           for e in edges):
        raise ValueError("ADG edge references missing source or target")
    agents = [n for n in nodes if n["kind"] == "agent"]
    servers = [n for n in nodes if n["kind"] == "mcp_server"]

    def found_agent(symbol: str) -> list[dict[str, Any]]:
        path, line = SOURCE_AGENTS[symbol]
        return [n for n in agents if _at(n, path, line)]

    def tool_projection(symbol: str, name: str) -> list[dict[str, Any]]:
        owners = {x["id"] for x in found_agent(symbol)}
        return [
            e for e in edges
            if e["kind"] == "INVOKES"
            and e["source"] in owners
            and node_map[e["target"]]["attributes"].get("tool_name") == name
        ]

    def delegated(child: str) -> list[dict[str, Any]]:
        roots = {x["id"] for x in found_agent("coordinator")}
        targets = {x["id"] for x in found_agent(child)}
        return [
            e for e in edges if e["kind"] == "DELEGATES_TO"
            and e["source"] in roots and e["target"] in targets
        ]

    comparisons = []
    counts: Counter[str] = Counter()
    for label in reference["labels"]:
        claim = label["claim_id"]
        truth = label["truth"]
        matched: list[dict[str, Any]] | None = None
        matcher = None
        if case_id == "rw-005":
            if claim in AGENT_CLAIMS:
                matcher = "constructor_source_site"
                matched = found_agent(AGENT_CLAIMS[claim])
            elif claim in SUBAGENT_CLAIMS:
                matcher = "typed_declared_delegation_edge"
                matched = delegated(SUBAGENT_CLAIMS[claim])
            elif claim in TOOL_CLAIMS:
                matcher = "owner_scoped_source_tool_invokes_projection"
                matched = tool_projection(*TOOL_CLAIMS[claim])
            elif claim == "source_declared_agent:package_export_new_constructor":
                matcher = "package_import_false_constructor"
                matched = [x for x in agents if _at(x, "__init__.py", 1)]
            elif claim == "source_declared_agent:api_alias_new_constructor":
                matcher = "api_alias_false_constructor"
                matched = [x for x in agents if _at(x, "api.py", 51)]
            elif claim == "declared_direct_tool_listing:report_agent_nonempty":
                matcher = "report_agent_false_direct_tool_binding"
                owners = {x["id"] for x in found_agent("report")}
                matched = [
                    e for e in edges
                    if e["kind"] == "INVOKES" and e["source"] in owners
                ]
            elif claim == "declared_direct_tool_listing:root_list_metrics_inherited_from_child":
                matcher = "root_inherited_child_false_direct_tool_binding"
                matched = tool_projection("coordinator", "list_metrics")
        elif case_id == "rw-080":
            if claim in MCP_SERVER_CLAIMS:
                matcher = "server_constructor_source_site"
                path, line = MCP_SERVER_CLAIMS[claim]
                matched = [x for x in servers if _at(x, path, line)]
            elif claim in MCP_EXPORT_CLAIMS:
                matcher = "server_source_file_exposes_tool"
                path = MCP_EXPORT_CLAIMS[claim]
                server_ids = {n["id"] for n in servers if _at(
                    n, path, {"mcp_server_1.py": 33,
                              "mcp_server_2.py": 28,
                              "mcp_server_3.py": 209,
                              "mcp_telegram_server.py": 27}[path]
                )}
                matched = [
                    e for e in edges
                    if e["kind"] == "EXPOSES_TOOL" and e["source"] in server_ids
                ]
            elif claim == "source_edge:resource_decorator_is_mcp_tool_decorator":
                matcher = "resource_falsely_exported_as_tool"
                matched = [
                    e for e in edges
                    if e["kind"] == "EXPOSES_TOOL"
                    and _at(node_map[e["target"]], "mcp_server_1.py", 245, delta=3)
                ]
        if truth == "unknown":
            category = "source_model_runtime_unknown"
            matched = None  # Even source detection cannot resolve runtime authority.
        elif matched is None:
            category = "not_mapped_to_legacy_adg_ontology"
        elif truth == "positive":
            category = (
                "candidate_source_declaration_projected"
                if matched else "candidate_positive_not_projected"
            )
        else:
            category = (
                "candidate_invalid_projection_for_review"
                if matched else "candidate_negative_not_projected_no_truth_proof"
            )
        counts[category] += 1
        comparisons.append({
            "claim_id": claim,
            "construct": next(s["construct"] for s in reference["scopes"]
                              if s["scope_id"] == label["scope_id"]),
            "model_opinion": truth,
            "source": label["source"],
            "matcher": matcher,
            "category": category,
            "adg_matches": sorted({x["id"] for x in matched}) if matched else [],
            "independent_source_truth_verified": False,
            "scanner_accuracy_assessable": False,
        })
    return {
        "case_id": case_id,
        "mode": "exact_source_current_scanner_vs_provisional_llm_differential",
        "rows": comparisons,
        "counts": dict(sorted(counts.items())),
        "adg_agents": len(agents),
        "adg_mcp_servers": len(servers),
        "adg_nodes": len(nodes),
        "adg_edges": len(edges),
        "model_review_independent": False,
        "positive_source_universe_complete": False,
        "negative_source_universe_complete": False,
        "runtime_effective_authority_verified": False,
        "certified_tp": None,
        "certified_fp": None,
        "certified_fn": None,
        "certified_tn": None,
        "certified_precision": None,
        "certified_recall": None,
        "production_cutover_authorized": False,
    }


def run_case(case_id: str, checkout: Path, project_root: Path, output: Path) -> dict:
    if case_id not in PINS:
        raise ValueError("unknown frozen case")
    repository, sha, app, ledger_path, opinion_path = PINS[case_id]
    ledger_bytes = (project_root / ledger_path).read_bytes()
    ledger = json.loads(ledger_bytes)
    witness = verify_git_source_witnesses(
        checkout, ledger, expected_commit=sha, expected_repo=repository,
    )
    if case_id == "rw-080":
        review = adjudicate_pinned_ledger_opinions(
            ledger_bytes, json.loads((project_root / opinion_path).read_text())
        )
        reference = review["reference"]
    else:
        reference = validate_reference(json.loads((project_root / opinion_path).read_text()))
    expected = {
        (o["path"], o["blob_sha"],
         o.get("line_start", o.get("line")), o.get("line_end", o.get("line")))
        for o in ledger["observations"]
    }
    if any((
        label["source"]["path"], label["source"]["blob_sha"],
        label["source"]["line_start"], label["source"]["line_end"]
    ) not in expected for label in reference["labels"]):
        raise ValueError("LLM opinion cites source not in pinned Git witness census")
    output.mkdir(parents=True, exist_ok=True)
    scopes: dict[str, Any] = {}
    for context, target in (
        ("application", checkout / app),
        ("repository", checkout),
    ):
        if not target.exists():
            raise ValueError(f"pinned scanner target missing: {context}")
        graph, findings = scan(target)
        adg = graph.adg.as_dict() if graph.adg is not None else build_adg(
            graph, target if target.is_dir() else target.parent
        ).as_dict()
        (output / f"{context}-adg.json").write_text(
            json.dumps(adg, indent=2, sort_keys=True) + "\n", encoding="utf-8",
        )
        diff = compare_adg_with_model_opinions(case_id, reference, adg)
        scopes[context] = {
            "scanner_coverage_incomplete": graph.coverage.incomplete,
            "findings": len(findings),
            "potential_attack_paths": len(graph.attack_paths),
            "effective_authority": {
                "source_only": True,
                "runtime_verified": False,
                "static_relationships": len(
                    effective_authority_report(graph).get("relationships", [])
                ),
            },
            **diff,
        }
    result = {
        "schema_version": 1,
        "study": "wave_c_c02q_pinned_source_current_scanner_vs_model",
        "case_id": case_id,
        "repository": repository,
        "source_commit_sha": sha,
        "scanner_commit_sha": _check_git(project_root, "rev-parse", "HEAD").decode().strip(),
        "application_path": app,
        "verified_git_source": witness,
        "model_review_method": "model_reviewed_unblinded",
        "real_scanner_executed": True,
        "target_code_executed": False,
        "source_scopes": scopes,
        "certified_precision": None,
        "certified_recall": None,
        "effective_authority_verified": False,
        "source_truth_independently_adjudicated": False,
        "production_cutover_authorized": False,
    }
    (output / "result.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case-id", choices=sorted(PINS), required=True)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--project-root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run_case(
        args.case_id, args.checkout.resolve(),
        args.project_root.resolve(), args.output.resolve(),
    )
    print(json.dumps({
        "case_id": result["case_id"],
        "source_commit_sha": result["source_commit_sha"],
        "witnesses": result["verified_git_source"]["exact_source_blob_lines_checked"],
        "scopes": {
            context: {
                "agents": data["adg_agents"],
                "mcp_servers": data["adg_mcp_servers"],
                "differential": data["counts"],
            } for context, data in result["source_scopes"].items()
        },
        "certified_precision": None,
        "production_cutover_authorized": False,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
