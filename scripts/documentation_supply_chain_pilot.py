#!/usr/bin/env python3
"""Standalone, documentation-first supply-chain comparison pilot.

Target code is read and statically scanned, never imported or executed.
This experiment is intentionally independent of Wave C C02 and its oracle.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

from horustrace.config_hierarchy_shadow import build_configured_hierarchy_source_shadow
from horustrace.scanner import scan


def _git(checkout: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(checkout), *args],
        check=True, capture_output=True, text=True, timeout=45,
    ).stdout.strip()


def validate_source(checkout: Path, reference: dict[str, Any]) -> None:
    """Fail closed if a different source, document or architecture is supplied."""
    if _git(checkout, "rev-parse", "HEAD") != reference["source_sha"]:
        raise ValueError("source revision does not match frozen reference")
    expected = reference["source_documents"]
    if set(expected) != {"docs/architecture.md", "src/agents/hierarchy.json"}:
        raise ValueError("source evidence document set changed")
    for name, blob in expected.items():
        if _git(checkout, "rev-parse", "HEAD:" + name) != blob:
            raise ValueError("source/document Git blob changed: " + name)
    doc = (checkout / "docs/architecture.md").read_text(encoding="utf-8")
    if "hierarchy.json" not in doc or "Agent composition" not in doc:
        raise ValueError("architecture guide no longer describes hierarchy")

    hierarchy = json.loads(
        (checkout / "src/agents/hierarchy.json").read_text(encoding="utf-8")
    )
    if not isinstance(hierarchy, dict):
        raise ValueError("hierarchy must be an object")
    actual_agents = {(name, item["type"]) for name, item in hierarchy.items()}
    actual_edges = {
        (name, child)
        for name, item in hierarchy.items()
        for child in item.get("children", [])
    }
    actual_bindings = {
        (name, tool)
        for name, item in hierarchy.items()
        for tool in item.get("tools", [])
    }
    expected_agents = {(x["name"], x["role"]) for x in reference["agents"]}
    expected_edges = {
        (x["source"], x["target"]) for x in reference["delegation_edges"]
    }
    expected_bindings = {
        (x["source"], x["tool_group"]) for x in reference["tool_group_bindings"]
    }
    if (len(expected_agents) != len(reference["agents"])
            or len(expected_edges) != len(reference["delegation_edges"])
            or len(expected_bindings) != len(reference["tool_group_bindings"])):
        raise ValueError("reference contains duplicate claims")
    if (actual_agents != expected_agents or actual_edges != expected_edges
            or actual_bindings != expected_bindings):
        raise ValueError("frozen reference differs from pinned hierarchy")
    if reference["scope"]["negative_scope"] != "not_established":
        raise ValueError("experiment must not silently assert a negative universe")
    if reference["scope"]["release_eligible"] is not False:
        raise ValueError("pilot is not a production release oracle")
    if reference["scope"]["independent_human_adjudication"] is not False:
        raise ValueError("no independent human attestation has occurred")


def _names(pairs: set[tuple[str, str]]) -> list[dict[str, str]]:
    return [{"source": source, "target": target} for source, target in sorted(pairs)]


def compare(reference: dict[str, Any], adg: dict[str, Any]) -> dict[str, Any]:
    """Compare precisely typed claims without equating tool groups with tools."""
    if adg.get("schema_version") != 1:
        raise ValueError("unsupported scanner ADG schema")
    nodes = adg["nodes"]
    edges = adg["edges"]
    node_by_id = {node["id"]: node for node in nodes}
    if len(node_by_id) != len(nodes):
        raise ValueError("scanner contains duplicate ADG node IDs")

    agent_nodes: dict[str, list[dict[str, Any]]] = {}
    for node in nodes:
        if node["kind"] == "agent":
            agent_nodes.setdefault(node["name"], []).append(node)
    expected = {row["name"]: row["role"] for row in reference["agents"]}
    matched_agents = sorted(
        name for name in expected if len(agent_nodes.get(name, [])) == 1
    )
    missing_agents = sorted(name for name in expected if not agent_nodes.get(name))
    ambiguous_agents = sorted(
        name for name in expected if len(agent_nodes.get(name, [])) > 1
    )
    unexpected_agents = sorted(set(agent_nodes) - set(expected))
    observed_types = {
        name: agent_nodes[name][0].get("attributes", {}).get("agent_type")
        for name in matched_agents
    }
    type_confirmed = sorted(
        name for name in matched_agents if observed_types[name] == expected[name]
    )
    type_unresolved = sorted(
        name for name in matched_agents
        if observed_types[name] is None or observed_types[name] not in {
            "frontend", "orchestrator", "worker"
        }
    )
    type_mismatch = sorted(
        name for name in matched_agents
        if name not in type_confirmed and name not in type_unresolved
    )

    # Only a typed agent-to-agent DELEGATES_TO edge can satisfy a child link.
    observed_delegations: set[tuple[str, str]] = set()
    for edge in edges:
        if edge["kind"] != "DELEGATES_TO":
            continue
        source = node_by_id.get(edge["source"])
        target = node_by_id.get(edge["target"])
        if source and target and source["kind"] == "agent" and target["kind"] == "agent":
            if (len(agent_nodes.get(source["name"], [])) == 1
                    and len(agent_nodes.get(target["name"], [])) == 1):
                observed_delegations.add((source["name"], target["name"]))
    expected_delegations = {
        (row["source"], row["target"]) for row in reference["delegation_edges"]
    }

    # Tool group names are categories for gateway targets, not individual MCP
    # tool exports. Exact-labelled INVOKES matches are candidates only.
    observed_group_labels: set[tuple[str, str]] = set()
    for edge in edges:
        if edge["kind"] != "INVOKES":
            continue
        source = node_by_id.get(edge["source"])
        target = node_by_id.get(edge["target"])
        if not source or not target or source["kind"] != "agent":
            continue
        if len(agent_nodes.get(source["name"], [])) != 1:
            continue
        if target["kind"] not in {"tool", "mcp_server"}:
            continue
        label = target.get("attributes", {}).get("tool_name")
        if not isinstance(label, str) or not label:
            label = target["name"].removeprefix(source["name"] + ":")
        observed_group_labels.add((source["name"], label))
    expected_groups = {
        (row["source"], row["tool_group"])
        for row in reference["tool_group_bindings"]
    }

    return {
        "agents": {
            "documented": len(expected),
            "matched_unique": matched_agents,
            "not_detected": missing_agents,
            "ambiguous": ambiguous_agents,
            "scanner_only_unreviewed": unexpected_agents,
            "role_exact_matches": type_confirmed,
            "role_unresolved": type_unresolved,
            "role_conflicts_for_review": type_mismatch,
            "documented_recovery_fraction": len(matched_agents) / len(expected),
        },
        "delegations": {
            "documented": len(expected_delegations),
            "matched": _names(observed_delegations & expected_delegations),
            "not_detected": _names(expected_delegations - observed_delegations),
            "scanner_only_unreviewed": _names(
                observed_delegations - expected_delegations
            ),
            "documented_recovery_fraction": (
                len(observed_delegations & expected_delegations)
                / len(expected_delegations)
            ),
        },
        "tool_groups": {
            "documented_bindings": len(expected_groups),
            "exact_label_candidates": _names(
                observed_group_labels & expected_groups
            ),
            "not_exactly_aligned": _names(
                expected_groups - observed_group_labels
            ),
            "status": "diagnostic_only_not_equivalent_to_individual_mcp_tools",
        },
        "accuracy": {
            "certified_precision": None,
            "certified_recall": None,
            "certified_false_positives": None,
            "certified_false_negatives": None,
            "negative_universe_complete": False,
            "runtime_authority_verified": False,
            "independent_human_review_verified": False,
            "production_cutover_authorized": False,
        },
        "scanner_adg": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "node_kinds": dict(sorted(Counter(
                node["kind"] for node in nodes
            ).items())),
            "edge_kinds": dict(sorted(Counter(
                edge["kind"] for edge in edges
            ).items())),
        },
    }



def compare_configured_source(
    reference: dict[str, Any], shadow: dict[str, Any],
) -> dict[str, Any]:
    """Compare a second parser's declarations, not production detection truth."""
    if (shadow.get("source_only") is not True
            or shadow.get("runtime_authority_verified") is not False
            or shadow.get("production_cutover_authorized") is not False
            or shadow.get("certified_precision") is not None):
        raise ValueError("source shadow promoted beyond declarative evidence")
    nodes = {row["id"]: row for row in shadow["nodes"]}
    actual_agents = {
        (row["name"], row["role"]) for row in nodes.values()
        if row["kind"] == "configured_agent"
    }
    expected_agents = {
        (row["name"], row["role"]) for row in reference["agents"]
    }
    actual_children = {
        (nodes[row["source"]]["name"], nodes[row["target"]]["name"])
        for row in shadow["edges"] if row["kind"] == "CONFIG_DECLARES_CHILD"
    }
    expected_children = {
        (row["source"], row["target"]) for row in reference["delegation_edges"]
    }
    actual_groups = {
        (nodes[row["source"]]["name"], nodes[row["target"]]["name"])
        for row in shadow["edges"] if row["kind"] == "CONFIG_DECLARES_TOOL_GROUP"
    }
    expected_groups = {
        (row["source"], row["tool_group"])
        for row in reference["tool_group_bindings"]
    }

    def records(actual: set[tuple[str, str]], expected: set[tuple[str, str]]) -> dict:
        return {
            "documented_count": len(expected),
            "exact_declaration_match_count": len(actual & expected),
            "documented_but_not_declared": sorted(expected - actual),
            "declared_but_not_documented": sorted(actual - expected),
        }

    return {
        "mode": "source_document_declaration_alignment_not_scanner_recall",
        "agents": records(actual_agents, expected_agents),
        "child_links": records(actual_children, expected_children),
        "tool_groups": records(actual_groups, expected_groups),
        "source_commit_sha": shadow["source_revision"]["commit_sha"],
        "source_only": True,
        "runtime_authority_verified": False,
        "independent_human_review_verified": False,
        "certified_precision": None,
        "certified_recall": None,
        "production_cutover_authorized": False,
    }


def markdown(result: dict[str, Any]) -> str:
    agents = result["comparison"]["agents"]
    edges = result["comparison"]["delegations"]
    groups = result["comparison"]["tool_groups"]
    # Legacy unit callers may request the original scanner-only summary.
    # Keep source-shadow output opt-in until a separate candidate is supplied.
    source_candidate = result.get("source_candidate")
    if source_candidate is None:
        source_lines = []
    else:
        source_lines = [
            "## Source-only hierarchy reader (NOT canonical scanner)", "",
            "| Declared construct | Published reference | Verified source JSON |",
            "| --- | ---: | ---: |",
            f"| Configured agent identities | {result['source_candidate']['agents']['documented_count']} | "
            f"{result['source_candidate']['agents']['exact_declaration_match_count']} |",
            f"| Explicit child links | {result['source_candidate']['child_links']['documented_count']} | "
            f"{result['source_candidate']['child_links']['exact_declaration_match_count']} |",
            f"| Tool-group labels (not MCP exports) | {result['source_candidate']['tool_groups']['documented_count']} | "
            f"{result['source_candidate']['tool_groups']['exact_declaration_match_count']} |",
            "",
            "This only corroborates declarations in the SAME source configuration that",
            "underlies the published reference. It is not independent ground truth,",
            "canonical scanner recovery, instantiated agents or verified callability.",
            "",
        ]
    lines = [
        "# Documentation-backed agent supply chain pilot", "",
        f"Repository: `{result['repository']}`",
        f"Pinned source: `{result['source_sha']}`",
        "",
        "**Outcome:** Evidence integrity passed; architecture gaps are diagnostics.",
        "No release accuracy certification or production cutover is authorised.",
        "",
        "| Bounded dimension | Documented | Exact matched | Not detected / unmatched |",
        "| --- | ---: | ---: | ---: |",
        f"| Agent identities | {agents['documented']} | "
        f"{len(agents['matched_unique'])} | {len(agents['not_detected'])} |",
        f"| Directed delegation links | {edges['documented']} | "
        f"{len(edges['matched'])} | {len(edges['not_detected'])} |",
        f"| Gateway tool-group bindings (label only) | {groups['documented_bindings']} | "
        f"{len(groups['exact_label_candidates'])} | "
        f"{len(groups['not_exactly_aligned'])} |",
        "",
        *source_lines,
        "## Important distinctions", "",
        "- The reference is complete only for the three explicit hierarchy.json "
        "construct types, not all agents/MCP exports/runtime permissions.",
        "- A documented item not detected is a gap candidate, not a certified false negative.",
        "- Scanner-only items are not automatically false positives; they may be "
        "real constructs outside the documented slice.",
        "- Gateway tool groups must not be equated with individual tool exports.",
        "- Roles, authority, findings and attack paths are not certified by this pilot.",
        "",
        "## Unmatched documented agents", "",
        *([f"- `{name}`" for name in agents["not_detected"]] or ["- None"]),
        "", "## Unmatched documented delegation edges", "",
        *([f"- `{r['source']}` → `{r['target']}`"
           for r in edges["not_detected"]] or ["- None"]),
        "", "Full evidence and scanner graph are in this run's uploaded artifact.",
        "",
    ]
    return "\n".join(lines)


def run(checkout: Path, reference_path: Path, output: Path) -> dict[str, Any]:
    reference = json.loads(reference_path.read_text(encoding="utf-8"))
    if reference.get("schema_version") != 1:
        raise ValueError("unsupported reference schema")
    validate_source(checkout, reference)
    graph, findings = scan(checkout)
    if graph.adg is None:
        raise ValueError("scanner did not produce an ADG")
    adg = graph.adg.as_dict()
    comparison = compare(reference, adg)
    # This is a separate source declaration inventory, NOT a replacement
    # for the original scanner baseline or a release-accuracy score.
    source_shadow = build_configured_hierarchy_source_shadow(
        checkout, "src/agents/hierarchy.json",
    )
    if graph.adg.as_dict() != adg:
        raise ValueError("source-only inventory modified canonical scanner ADG")
    source_candidate = compare_configured_source(reference, source_shadow)
    result = {
        "schema_version": 1,
        "mode": "documentation_supply_chain_experiment_not_release_truth",
        "reference_id": reference["reference_id"],
        "repository": reference["repository"],
        "source_sha": reference["source_sha"],
        "source_documents": reference["source_documents"],
        "comparison": comparison,
        "source_candidate": source_candidate,
        "scanner_finding_count_unreviewed": len(findings),
        "integrity": "passed",
        "documentation_scope_only": True,
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "reference.json").write_text(
        json.dumps(reference, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output / "scanner-adg.json").write_text(
        json.dumps(adg, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output / "configured-source-shadow.json").write_text(
        json.dumps(source_shadow, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output / "comparison.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output / "summary.md").write_text(markdown(result), encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.checkout.resolve(), args.reference.resolve(), args.output.resolve())
    print(markdown(result))


if __name__ == "__main__":
    main()
