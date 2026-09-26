"""Execute and score HorusTrace against the frozen real-world study cohort.

The cohort and independent source reference must already be locked. Targets are fetched
at exact SHAs and are never installed, imported, or executed. The scanner binary is
provided by the workflow. Baseline mode enforces the preregistered scanner SHA; postfix mode evaluates a candidate SHA.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import shutil
import subprocess
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

STUDY = "real-world-agent-security-2026"
CLONE_TIMEOUT = 180
SCAN_TIMEOUT = 300


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected object")
    return value


def run(command: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
    )


def fetch_case(
    workspace: Path,
    case: dict[str, Any],
    *,
    tier_c: bool,
) -> tuple[Path | None, str | None]:
    target = workspace / case["case_id"]
    target.mkdir(parents=True, exist_ok=True)
    for command in (
        ["git", "init", "-q", str(target)],
        ["git", "-C", str(target), "remote", "add", "origin",
         f"https://github.com/{case['repo']}.git"],
        ["git", "-C", str(target), "fetch", "--quiet", "--depth=1",
         "--filter=blob:none", "origin", case["sha"]],
    ):
        result = run(command, timeout=CLONE_TIMEOUT)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()[-1000:]
            return None, f"fetch_failed:{detail}"

    application = Path(case["application_path"])
    if not tier_c:
        sparse = application if application.suffix == "" else application.parent
        pattern = sparse.as_posix() if sparse.as_posix() not in {"", "."} else "/*"
        init = run(
            ["git", "-C", str(target), "sparse-checkout", "init", "--no-cone"],
            timeout=60,
        )
        if init.returncode == 0:
            selected = run(
                ["git", "-C", str(target), "sparse-checkout", "set", "--no-cone", pattern],
                timeout=60,
            )
            if selected.returncode != 0:
                run(["git", "-C", str(target), "sparse-checkout", "disable"], timeout=60)
    checkout = run(
        ["git", "-C", str(target), "checkout", "--quiet", "--detach", "FETCH_HEAD"],
        timeout=CLONE_TIMEOUT,
    )
    if checkout.returncode != 0:
        detail = (checkout.stderr or checkout.stdout).strip()[-1000:]
        return None, f"checkout_failed:{detail}"
    rev = run(["git", "-C", str(target), "rev-parse", "HEAD"], timeout=30)
    if rev.returncode != 0 or rev.stdout.strip() != case["sha"]:
        return None, "frozen_sha_mismatch"

    chosen = target / application
    if not chosen.exists():
        return None, f"application_path_missing:{case['application_path']}"
    scope = chosen if chosen.is_dir() else chosen.parent
    return scope, None


def parse_json_output(result: subprocess.CompletedProcess[str], label: str) -> tuple[dict[str, Any] | None, str | None]:
    if result.returncode not in {0, 2}:
        detail = (result.stderr or result.stdout).strip()[-2000:]
        return None, f"{label}_exit_{result.returncode}:{detail}"
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None, f"{label}_invalid_json"
    if not isinstance(value, dict):
        return None, f"{label}_non_object_json"
    return value, None


def norm(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def fact_aliases(fact: dict[str, Any]) -> set[str]:
    raw = [fact.get("name"), fact.get("variable"), *(fact.get("aliases") or [])]
    return {norm(item) for item in raw if item}


def location(item: dict[str, Any]) -> tuple[str, int] | None:
    raw = item.get("location")
    if not isinstance(raw, dict):
        return None
    path = raw.get("path")
    line = raw.get("line")
    if isinstance(path, str) and isinstance(line, int):
        return path, line
    return None


def fact_location(fact: dict[str, Any]) -> tuple[str, int] | None:
    path, line = fact.get("path"), fact.get("line")
    if isinstance(path, str) and isinstance(line, int):
        return path, line
    return None


def path_match(left: str, right: str) -> bool:
    return left == right or left.endswith("/" + right) or right.endswith("/" + left)


def predicted_entity_name(node: dict[str, Any], dimension: str) -> str:
    attrs = node.get("attributes") if isinstance(node.get("attributes"), dict) else {}
    if dimension == "tools":
        return str(attrs.get("tool_name") or str(node.get("name", "")).split(":")[-1])
    if dimension == "mcp_servers":
        name = str(node.get("name", ""))
        return name.split(":", 1)[1] if ":" in name else name
    return str(node.get("name", ""))


def match_entities(
    truth: list[dict[str, Any]],
    predicted: list[dict[str, Any]],
    dimension: str,
) -> tuple[int, int, list[int], list[int]]:
    matched_truth: set[int] = set()
    matched_pred: set[int] = set()

    # First pass: declared/variable name aliases.
    for ti, fact in enumerate(truth):
        aliases = fact_aliases(fact)
        for pi, node in enumerate(predicted):
            if pi in matched_pred:
                continue
            if norm(predicted_entity_name(node, dimension)) in aliases:
                matched_truth.add(ti)
                matched_pred.add(pi)
                break

    # Second pass: same source location when names are framework-normalized differently.
    for ti, fact in enumerate(truth):
        if ti in matched_truth:
            continue
        floc = fact_location(fact)
        if floc is None:
            continue
        for pi, node in enumerate(predicted):
            if pi in matched_pred:
                continue
            ploc = location(node)
            if ploc is None:
                continue
            if path_match(floc[0], ploc[0]) and abs(floc[1] - ploc[1]) <= 6:
                matched_truth.add(ti)
                matched_pred.add(pi)
                break
    return (
        len(matched_truth),
        len(truth) - len(matched_truth),
        sorted(matched_truth),
        sorted(matched_pred),
    )


def canonical_truth_name(value: str, truth_agents: list[dict[str, Any]]) -> str:
    wanted = norm(value)
    for fact in truth_agents:
        if wanted in fact_aliases(fact):
            return norm(fact.get("name"))
    return wanted


def delegation_metrics(
    truth_edges: list[dict[str, Any]],
    predicted_edges: list[dict[str, Any]],
    nodes_by_id: dict[str, dict[str, Any]],
    truth_agents: list[dict[str, Any]],
) -> tuple[int, int, int]:
    predicted_pairs: list[tuple[str, str]] = []
    for edge in predicted_edges:
        if edge.get("kind") != "DELEGATES_TO":
            continue
        left = nodes_by_id.get(str(edge.get("source")))
        right = nodes_by_id.get(str(edge.get("target")))
        if not left or not right:
            continue
        predicted_pairs.append(
            (
                canonical_truth_name(str(left.get("name")), truth_agents),
                canonical_truth_name(str(right.get("name")), truth_agents),
            )
        )
    truth_pairs = [
        (
            canonical_truth_name(str(edge.get("source")), truth_agents),
            canonical_truth_name(str(edge.get("target")), truth_agents),
        )
        for edge in truth_edges
    ]
    remaining = list(predicted_pairs)
    tp = 0
    for pair in truth_pairs:
        if pair in remaining:
            tp += 1
            remaining.remove(pair)
    return tp, len(truth_pairs) - tp, len(remaining)


def canonical_observed_agent_name(
    value: str,
    truth_agents: list[dict[str, Any]],
    topology_nodes: list[dict[str, Any]],
) -> str:
    direct = canonical_truth_name(value, truth_agents)
    wanted = norm(value)
    if direct != wanted:
        return direct

    candidates = [
        node
        for node in topology_nodes
        if node.get("kind") == "agent" and norm(node.get("name")) == wanted
    ]
    matches: set[str] = set()
    for node in candidates:
        ploc = location(node)
        if ploc is None:
            continue
        for fact in truth_agents:
            floc = fact_location(fact)
            if floc is None:
                continue
            if path_match(floc[0], ploc[0]) and abs(floc[1] - ploc[1]) <= 6:
                matches.add(norm(fact.get("name")))
    if len(matches) == 1:
        return next(iter(matches))
    return wanted


def authority_metrics(
    truth_doc: dict[str, Any],
    observed: dict[str, Any],
    topology_nodes: list[dict[str, Any]],
) -> dict[str, int]:
    tier_b = truth_doc.get("tier_b") or {}
    expected = tier_b.get("authority_relationships") or []
    predicted = observed.get("relationships") or []
    truth_agents = truth_doc.get("tier_a", {}).get("agent_roots") or []

    expected_keys = []
    for item in expected:
        expected_keys.append(
            (
                canonical_truth_name(str(item.get("agent")), truth_agents),
                norm(item.get("target_kind")),
                norm(item.get("target_name")),
            )
        )
    predicted_keys = []
    for item in predicted:
        target = item.get("target") if isinstance(item.get("target"), dict) else {}
        predicted_keys.append(
            (
                canonical_observed_agent_name(
                    str(item.get("agent")),
                    truth_agents,
                    topology_nodes,
                ),
                norm(target.get("kind")),
                norm(target.get("name")),
            )
        )
    remaining = list(predicted_keys)
    tp = 0
    for key in expected_keys:
        if key in remaining:
            tp += 1
            remaining.remove(key)
    return {
        "truth": len(expected_keys),
        "predicted": len(predicted_keys),
        "tp": tp,
        "fn": len(expected_keys) - tp,
        "fp_if_complete": len(remaining),
    }


def attack_path_support(
    truth_doc: dict[str, Any],
    attack_paths: list[dict[str, Any]],
) -> dict[str, int]:
    tier_b = truth_doc.get("tier_b") or {}
    reference = tier_b.get("attack_path_reference") or {}
    pairs = reference.get("source_supported_authority_pairs") or []
    truth_agents = truth_doc.get("tier_a", {}).get("agent_roots") or []
    supported = 0
    adjudicable = 0
    for path in attack_paths:
        agent = canonical_truth_name(str(path.get("agent")), truth_agents)
        node_text = norm(" ".join(str(x) for x in path.get("nodes") or []))
        relevant = [
            pair for pair in pairs
            if canonical_truth_name(str(pair.get("agent")), truth_agents) == agent
        ]
        if not relevant:
            continue
        adjudicable += 1
        if any(norm(pair.get("target_name")) in node_text for pair in relevant):
            supported += 1
    return {
        "reported": len(attack_paths),
        "adjudicable": adjudicable,
        "source_supported": supported,
        "unsupported_within_reference": max(0, adjudicable - supported),
    }


def tier_c_identity_metrics(
    truth_doc: dict[str, Any],
    topology_nodes: list[dict[str, Any]],
) -> dict[str, int]:
    tier_c = truth_doc.get("tier_c") or {}
    expected = {
        norm(item.get("identity"))
        for item in tier_c.get("workload_or_deployer_identities") or []
        if item.get("identity")
    }
    predicted = {
        norm(node.get("name"))
        for node in topology_nodes
        if node.get("kind") == "identity" and node.get("name")
    }
    return {
        "truth": len(expected),
        "predicted": len(predicted),
        "tp": len(expected & predicted),
        "fn": len(expected - predicted),
        "unadjudicated_predicted": len(predicted - expected),
    }


def predicted_nodes_for_dimension(
    nodes: list[dict[str, Any]],
    dimension: str,
) -> list[dict[str, Any]]:
    kinds = {
        "agent_entities": {"agent", "workflow_node"},
        "tools": {"tool"},
        "mcp_servers": {"mcp_server"},
    }
    if dimension not in kinds:
        raise ValueError(f"unknown structural dimension: {dimension}")
    return [node for node in nodes if node.get("kind") in kinds[dimension]]


def scan_one(
    case: dict[str, Any],
    truth: dict[str, Any],
    workspace: Path,
    scanner: str,
    tier_c: bool,
) -> dict[str, Any]:
    scope, fetch_error = fetch_case(workspace, case, tier_c=tier_c)
    if fetch_error or scope is None:
        return {
            "case_id": case["case_id"],
            "repo": case["repo"],
            "framework": case["framework_stratum"],
            "previously_studied": case["previously_studied"],
            "status": "fetch_error",
            "error": fetch_error,
        }

    base = [scanner]
    scan_command = [*base, "scan", str(scope), "--format", "json", "--fail-on", "none"]
    graph_command = [*base, "security-graph", str(scope)]
    if tier_c:
        # Repository-declared IaC is used only for the four preselected Tier C cases.
        repo_root = workspace / case["case_id"]
        scan_command.extend(["--authority-source", str(repo_root)])
        graph_command.extend(["--authority-source", str(repo_root)])

    try:
        scan_result = run(scan_command, timeout=SCAN_TIMEOUT)
        graph_result = run(graph_command, timeout=SCAN_TIMEOUT)
    except subprocess.TimeoutExpired as exc:
        return {
            "case_id": case["case_id"],
            "repo": case["repo"],
            "framework": case["framework_stratum"],
            "previously_studied": case["previously_studied"],
            "status": "timeout",
            "error": f"{exc.cmd[1] if isinstance(exc.cmd, list) and len(exc.cmd) > 1 else 'scan'} timeout",
        }

    scan_doc, scan_error = parse_json_output(scan_result, "scan")
    graph_doc, graph_error = parse_json_output(graph_result, "security_graph")
    if scan_error or graph_error or scan_doc is None or graph_doc is None:
        return {
            "case_id": case["case_id"],
            "repo": case["repo"],
            "framework": case["framework_stratum"],
            "previously_studied": case["previously_studied"],
            "status": "scanner_error",
            "error": scan_error or graph_error,
        }

    topology = graph_doc.get("topology") if isinstance(graph_doc.get("topology"), dict) else {}
    nodes = topology.get("nodes") if isinstance(topology.get("nodes"), list) else []
    edges = topology.get("edges") if isinstance(topology.get("edges"), list) else []
    truth_a = truth.get("tier_a") or {}
    complete = truth_a.get("reference_completeness") or {}

    comparisons: dict[str, Any] = {}
    kind_map = {
        "agent_entities": "agent_roots",
        "tools": "tools",
        "mcp_servers": "mcp_servers",
    }
    for dimension, truth_key in kind_map.items():
        truth_items = truth_a.get(truth_key) or []
        predicted = predicted_nodes_for_dimension(nodes, dimension)
        tp, fn, _, matched_pred = match_entities(truth_items, predicted, truth_key if truth_key != "agent_roots" else "agent_entities")
        comparisons[dimension] = {
            "truth": len(truth_items),
            "predicted": len(predicted),
            "tp": tp,
            "fn": fn,
            "precision_eligible": bool(complete.get(dimension)),
            "precision_tp": len(matched_pred) if complete.get(dimension) else 0,
            "fp": (len(predicted) - len(matched_pred)) if complete.get(dimension) else 0,
            "unadjudicated_predicted": 0 if complete.get(dimension) else len(predicted) - len(matched_pred),
        }

    nodes_by_id = {str(node.get("id")): node for node in nodes}
    dtp, dfn, dfp = delegation_metrics(
        truth_a.get("delegation_edges") or [],
        edges,
        nodes_by_id,
        truth_a.get("agent_roots") or [],
    )
    predicted_delegations = sum(edge.get("kind") == "DELEGATES_TO" for edge in edges)
    comparisons["delegation_edges"] = {
        "truth": len(truth_a.get("delegation_edges") or []),
        "predicted": predicted_delegations,
        "tp": dtp,
        "fn": dfn,
        "precision_eligible": bool(complete.get("delegation_edges")),
        "precision_tp": dtp if complete.get("delegation_edges") else 0,
        "fp": dfp if complete.get("delegation_edges") else 0,
        "unadjudicated_predicted": 0 if complete.get("delegation_edges") else dfp,
    }

    authority = graph_doc.get("effective_authority") if isinstance(graph_doc.get("effective_authority"), dict) else {}
    auth = authority_metrics(truth, authority, nodes) if truth.get("tier_b") else None
    if auth is not None:
        authority_complete = bool(
            complete.get("agent_entities")
            and complete.get("tools")
            and complete.get("mcp_servers")
        )
        auth["precision_eligible"] = authority_complete
        auth["precision_tp"] = auth["tp"] if authority_complete else 0
        auth["fp"] = auth["fp_if_complete"] if authority_complete else 0
        auth["unadjudicated_predicted"] = 0 if authority_complete else auth["fp_if_complete"]
        comparisons["effective_authority"] = auth

    attack_paths = graph_doc.get("attack_paths") if isinstance(graph_doc.get("attack_paths"), list) else []
    if truth.get("tier_b"):
        comparisons["attack_paths"] = attack_path_support(truth, attack_paths)

    if truth.get("tier_c"):
        comparisons["tier_c_identity"] = tier_c_identity_metrics(truth, nodes)

    findings = scan_doc.get("findings") if isinstance(scan_doc.get("findings"), list) else []
    finding_counts = Counter(str(item.get("rule_id") or "unknown") for item in findings if isinstance(item, dict))
    severity_counts = Counter(str(item.get("severity") or "unknown") for item in findings if isinstance(item, dict))
    confidence_counts = Counter(str(item.get("confidence") or "unknown") for item in findings if isinstance(item, dict))

    relationships = authority.get("relationships") if isinstance(authority.get("relationships"), list) else []
    resolution_counts = Counter(str(item.get("resolution") or "unknown") for item in relationships if isinstance(item, dict))
    dynamic_reference = any(
        "dynamic_source_constructs_detected" in str(item)
        for item in truth_a.get("unresolved") or []
    )
    full_on_dynamic = (
        sum(item.get("resolution") == "fully_resolved" for item in relationships)
        if dynamic_reference else 0
    )

    coverage = scan_doc.get("coverage") if isinstance(scan_doc.get("coverage"), dict) else {}
    return {
        "case_id": case["case_id"],
        "repo": case["repo"],
        "framework": case["framework_stratum"],
        "previously_studied": case["previously_studied"],
        "status": "success",
        "comparisons": comparisons,
        "observed": {
            "summary": scan_doc.get("summary") or {},
            "analysis_incomplete": bool(coverage.get("incomplete")),
            "findings": len(findings),
            "findings_by_rule": dict(sorted(finding_counts.items())),
            "findings_by_severity": dict(sorted(severity_counts.items())),
            "findings_by_confidence": dict(sorted(confidence_counts.items())),
            "authority_resolution": dict(sorted(resolution_counts.items())),
            "fully_resolved_on_dynamic_reference": full_on_dynamic,
            "attack_paths": len(attack_paths),
        },
    }


def ratio(num: int, den: int) -> float | None:
    return round(num / den, 4) if den else None


def aggregate_dimension(cases: list[dict[str, Any]], key: str) -> dict[str, Any]:
    truth = predicted = tp = fn = p_tp = fp = unadj = p_cases = 0
    for case in cases:
        item = (case.get("comparisons") or {}).get(key)
        if not isinstance(item, dict):
            continue
        truth += int(item.get("truth", 0))
        predicted += int(item.get("predicted", 0))
        tp += int(item.get("tp", 0))
        fn += int(item.get("fn", 0))
        if item.get("precision_eligible"):
            p_cases += 1
            p_tp += int(item.get("precision_tp", 0))
            fp += int(item.get("fp", 0))
        unadj += int(item.get("unadjudicated_predicted", 0))
    return {
        "truth": truth,
        "predicted": predicted,
        "tp": tp,
        "fn": fn,
        "recall": ratio(tp, tp + fn),
        "precision_complete_cases": p_cases,
        "precision_tp": p_tp,
        "fp": fp,
        "precision": ratio(p_tp, p_tp + fp),
        "unadjudicated_predicted": unadj,
    }


def aggregate(
    cases: list[dict[str, Any]],
    scanner_sha: str,
    cohort: dict[str, Any],
    *,
    execution_mode: str = "baseline",
) -> dict[str, Any]:
    success = [case for case in cases if case.get("status") == "success"]
    failures = [case for case in cases if case.get("status") != "success"]
    dimensions = {
        key: aggregate_dimension(success, key)
        for key in ("agent_entities", "tools", "mcp_servers", "delegation_edges", "effective_authority")
    }

    attack_reported = attack_adj = attack_supported = 0
    tier_c_truth = tier_c_tp = tier_c_fn = tier_c_pred = 0
    total_findings = total_attack_paths = full_dynamic = 0
    incomplete_cases = 0
    rules: Counter[str] = Counter()
    severities: Counter[str] = Counter()
    confidences: Counter[str] = Counter()
    resolution: Counter[str] = Counter()

    for case in success:
        observed = case.get("observed") or {}
        total_findings += int(observed.get("findings", 0))
        total_attack_paths += int(observed.get("attack_paths", 0))
        incomplete_cases += int(bool(observed.get("analysis_incomplete")))
        full_dynamic += int(observed.get("fully_resolved_on_dynamic_reference", 0))
        rules.update(observed.get("findings_by_rule") or {})
        severities.update(observed.get("findings_by_severity") or {})
        confidences.update(observed.get("findings_by_confidence") or {})
        resolution.update(observed.get("authority_resolution") or {})

        attack = (case.get("comparisons") or {}).get("attack_paths") or {}
        attack_reported += int(attack.get("reported", 0))
        attack_adj += int(attack.get("adjudicable", 0))
        attack_supported += int(attack.get("source_supported", 0))

        identity = (case.get("comparisons") or {}).get("tier_c_identity") or {}
        tier_c_truth += int(identity.get("truth", 0))
        tier_c_pred += int(identity.get("predicted", 0))
        tier_c_tp += int(identity.get("tp", 0))
        tier_c_fn += int(identity.get("fn", 0))

    per_framework: dict[str, Any] = {}
    frameworks = sorted({str(case.get("framework")) for case in cases})
    for framework in frameworks:
        subset = [case for case in success if case.get("framework") == framework]
        per_framework[framework] = {
            "cases": sum(case.get("framework") == framework for case in cases),
            "successful": len(subset),
            "agent_entities": aggregate_dimension(subset, "agent_entities"),
            "tools": aggregate_dimension(subset, "tools"),
            "mcp_servers": aggregate_dimension(subset, "mcp_servers"),
            "effective_authority": aggregate_dimension(subset, "effective_authority"),
            "findings": sum(int((case.get("observed") or {}).get("findings", 0)) for case in subset),
            "attack_paths": sum(int((case.get("observed") or {}).get("attack_paths", 0)) for case in subset),
        }

    unseen = [case for case in success if not case.get("previously_studied")]
    studied = [case for case in success if case.get("previously_studied")]
    generalization = {
        "previously_unseen_cases": len(unseen),
        "previously_studied_cases": len(studied),
        "unseen_agent_entities": aggregate_dimension(unseen, "agent_entities"),
        "studied_agent_entities": aggregate_dimension(studied, "agent_entities"),
        "unseen_effective_authority": aggregate_dimension(unseen, "effective_authority"),
        "studied_effective_authority": aggregate_dimension(studied, "effective_authority"),
    }

    thresholds = {
        "agent_root_precision": {"threshold": 0.95, "value": dimensions["agent_entities"]["precision"]},
        "agent_root_recall": {"threshold": 0.90, "value": dimensions["agent_entities"]["recall"]},
        "authority_edge_precision": {"threshold": 0.90, "value": dimensions["effective_authority"]["precision"]},
        "authority_edge_recall": {"threshold": 0.80, "value": dimensions["effective_authority"]["recall"]},
        "attack_path_structural_support_precision": {
            "threshold": 0.80,
            "value": ratio(attack_supported, attack_adj),
            "note": "proxy over source-adjudicable reported paths; not runtime exploitability",
        },
    }
    for item in thresholds.values():
        value = item.get("value")
        threshold = item.get("threshold")
        item["meets_threshold"] = bool(value is not None and threshold is not None and value >= threshold)

    return {
        "schema_version": 1,
        "study": STUDY,
        "scanner_sha": scanner_sha,
        "baseline_scanner_sha": cohort.get("scanner_freeze_sha"),
        "execution_mode": execution_mode,
        "cohort_cases": len(cases),
        "reference_method": cohort.get("ground_truth_reference") or {},
        "summary": {
            "successful_cases": len(success),
            "failed_cases": len(failures),
            "analysis_incomplete_cases": incomplete_cases,
            "findings": total_findings,
            "attack_paths": total_attack_paths,
        },
        "execution_failures": [
            {
                "case_id": case.get("case_id"),
                "repo": case.get("repo"),
                "framework": case.get("framework"),
                "status": case.get("status"),
                "error": case.get("error"),
            }
            for case in failures
        ],
        "metrics": dimensions,
        "attack_paths": {
            "reported_tier_b": attack_reported,
            "source_adjudicable": attack_adj,
            "source_supported": attack_supported,
            "structural_support_precision": ratio(attack_supported, attack_adj),
            "runtime_exploitability": "not_verified",
            "known_path_recall": None,
            "known_path_recall_reason": "automated source reference does not establish an exhaustive valid-path catalogue",
        },
        "findings": {
            "total": total_findings,
            "by_rule": dict(rules.most_common()),
            "by_severity": dict(sorted(severities.items())),
            "by_confidence": dict(sorted(confidences.items())),
            "assertion_precision": None,
            "assertion_recall": None,
            "reason": "source reference is not exhaustive enough to independently adjudicate all rule semantics",
        },
        "uncertainty": {
            "authority_resolution": dict(sorted(resolution.items())),
            "fully_resolved_relationships_on_dynamic_reference_cases": full_dynamic,
            "unsupported_certainty_rate": None,
            "reason": "automated source reference cannot prove that every scanner-resolved dimension is unsupported",
        },
        "tier_c": {
            "selected_cases": len(cohort.get("tier_c_case_ids") or []),
            "preregistered_target": 25,
            "reference_identities": tier_c_truth,
            "observed_identities": tier_c_pred,
            "matched_reference_identities": tier_c_tp,
            "missed_reference_identities": tier_c_fn,
            "identity_recall": ratio(tier_c_tp, tier_c_tp + tier_c_fn),
            "identity_precision": None,
            "runtime_effectiveness": "not_verified",
            "note": "reference includes repository-declared workload/deployer identities, not verified live runtime bindings",
        },
        "thresholds": thresholds,
        "generalization": generalization,
        "per_framework": per_framework,
        "cases": cases,
    }


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    metrics = report["metrics"]
    lines = [
        "# HorusTrace Real-World Agent Security 2026 — Frozen Baseline",
        "",
        f"- Frozen scanner SHA: \`{report['scanner_sha']}\`",
        f"- Cohort: {report['cohort_cases']} exact-SHA repositories",
        f"- Successful scans: {summary['successful_cases']}",
        f"- Execution/fetch failures: {summary['failed_cases']}",
        f"- Analysis-incomplete cases: {summary['analysis_incomplete_cases']}",
        "- Target applications were not installed, imported, or executed.",
        "- Runtime effectiveness remains not verified.",
        "",
        "## Structural and authority metrics",
        "",
        "| Dimension | Precision* | Recall | Truth | Predicted |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for key, label in (
        ("agent_entities", "Agent/workflow entities"),
        ("tools", "Tools"),
        ("mcp_servers", "MCP servers"),
        ("delegation_edges", "Delegation edges"),
        ("effective_authority", "Explicit effective authority"),
    ):
        item = metrics[key]
        p = "n/a" if item["precision"] is None else f"{item['precision']:.3f}"
        r = "n/a" if item["recall"] is None else f"{item['recall']:.3f}"
        lines.append(f"| {label} | {p} | {r} | {item['truth']} | {item['predicted']} |")
    lines.extend([
        "",
        "\\* Precision is computed only on cases where the independent reference explicitly marks the relevant dimension complete. Extra predictions on incomplete cases remain unadjudicated, not false positives.",
        "",
        "## Attack paths",
        "",
        f"- Tier-B reported paths: {report['attack_paths']['reported_tier_b']}",
        f"- Source-adjudicable reported paths: {report['attack_paths']['source_adjudicable']}",
        f"- Source-supported: {report['attack_paths']['source_supported']}",
        f"- Structural support precision: {report['attack_paths']['structural_support_precision']}",
        "- Known-path recall: not measured; the automated reference does not establish an exhaustive valid-path catalogue.",
        "",
        "## Findings",
        "",
        f"- Findings: {report['findings']['total']}",
        f"- By severity: \`{json.dumps(report['findings']['by_severity'], sort_keys=True)}\`",
        "- Finding assertion precision/recall are not claimed from this automated reference.",
        "",
        "## Tier C",
        "",
        f"- Defensible Tier-C cases: {report['tier_c']['selected_cases']} / target {report['tier_c']['preregistered_target']}",
        f"- Repository-declared identity recall: {report['tier_c']['identity_recall']}",
        "- Runtime deployment effectiveness is not verified.",
        "",
        "## Pre-registered threshold checks available from this reference",
        "",
        "| Metric | Value | Threshold | Meets |",
        "| --- | ---: | ---: | --- |",
    ])
    for name, item in report["thresholds"].items():
        value = "n/a" if item["value"] is None else f"{item['value']:.3f}"
        lines.append(
            f"| {name} | {value} | {item['threshold']:.2f} | "
            f"{'yes' if item['meets_threshold'] else 'no'} |"
        )
    lines.extend([
        "",
        "## Reference limitation",
        "",
        "Ground truth was built by an independent automated dual-pass source reference (structural parser plus lexical cross-check) before scanner execution. It is not represented as an independent human dual-review panel. Dynamic constructs are unresolved, precision is restricted to completeness-marked cases, and finding semantics / exhaustive attack-path recall remain outside the claims supported by this baseline.",
        "",
    ])
    return "\n".join(lines)


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, default=Path("research/real-world-agent-security-2026"))
    p.add_argument("--scanner", default="horustrace")
    p.add_argument("--scanner-sha", required=True)
    p.add_argument(
        "--mode",
        choices=["baseline", "postfix"],
        default="baseline",
        help=(
            "baseline enforces the preregistered scanner SHA; postfix evaluates an "
            "explicit candidate SHA against the unchanged frozen cohort."
        ),
    )
    p.add_argument("--workers", type=int, default=8)
    p.add_argument("--output-json", type=Path, required=True)
    p.add_argument("--output-markdown", type=Path, required=True)
    return p


def main() -> int:
    args = parser().parse_args()
    cohort = load_json(args.root / "cohort.json")
    if cohort.get("cohort_frozen") is not True:
        raise SystemExit("study error: cohort must be frozen")
    if cohort.get("ground_truth_locked") is not True:
        raise SystemExit("study error: ground truth must be locked before baseline execution")
    frozen_scanner_sha = cohort.get("scanner_freeze_sha")
    if args.mode == "baseline" and frozen_scanner_sha != args.scanner_sha:
        raise SystemExit("study error: scanner SHA does not match preregistration")
    if not re.fullmatch(r"[0-9a-f]{40}", args.scanner_sha):
        raise SystemExit(
            "study error: scanner SHA must be an exact lowercase 40-character SHA"
        )
    cases = cohort.get("cases") or []
    tier_c_ids = set(cohort.get("tier_c_case_ids") or [])
    truths: dict[str, dict[str, Any]] = {}
    for case in cases:
        path = args.root / str(case["ground_truth"])
        truth = load_json(path)
        lock = truth.get("truth_lock") or {}
        if lock.get("horustrace_output_seen") is not False or lock.get("reviewed") is not True:
            raise SystemExit(f"study error: truth not independently locked for {case['case_id']}")
        truths[case["case_id"]] = truth

    workspace = Path(tempfile.mkdtemp(prefix="horustrace-real-world-baseline-"))
    results: list[dict[str, Any]] = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
            futures = [
                executor.submit(
                    scan_one,
                    case,
                    truths[case["case_id"]],
                    workspace,
                    args.scanner,
                    case["case_id"] in tier_c_ids,
                )
                for case in cases
            ]
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())
    finally:
        shutil.rmtree(workspace, ignore_errors=True)

    order = {case["case_id"]: index for index, case in enumerate(cases)}
    results.sort(key=lambda item: order.get(str(item.get("case_id")), 999999))
    report = aggregate(
        results,
        args.scanner_sha,
        cohort,
        execution_mode=args.mode,
    )
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_markdown.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.output_markdown.write_text(render_markdown(report) + "\n", encoding="utf-8")
    print(json.dumps(report["summary"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
