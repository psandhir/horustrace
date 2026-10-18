"""Wave B WAB-01..05: pinned source-ledger vs current Graph/ADG witness queue.

The report is a **source-claim discrepancy queue**, not a TP/FP/FN scorer.
A missing source-native candidate is not a proven false negative; a Graph
relationship without the required control evidence is not effective authority.
Target repositories are never imported, installed or executed.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from horustrace.adg import build_adg
from horustrace.effective_authority import effective_authority_report
from horustrace.scanner import scan
from horustrace.semantic_shadow import shadow_observation_report

PINS: dict[str, tuple[str, str, str]] = {
    "gen-pyd-001": (
        "newsbubbles/pharmiq", "c69949739647a47ec8339b473bdf578c8cf8bfd9", "."
    ),
    "ff60-microsoft-04": (
        "qmatteoq/agent365-demos", "937f8c12421b6eebfbff764dbafbdbe13cc72f68",
        "dotnet-agent-teammate",
    ),
    "gen-mcp-003": (
        "couchbase/mcp-server-couchbase",
        "df5d9ceb013f57143171f65ec3ba033ace06aa9a", "."
    ),
    "ff60-amazon-04": (
        "aws-samples/sample-multi-agent-region-expansion-planner",
        "30d03d7c9f6512e5bf10601879382fac9c3a16b1", "src"
    ),
    "gen-mcp-001": (
        "stickerdaniel/linkedin-mcp-server",
        "f1425029ca426e850dc9f52b0097f0fff1aa7b3d", "."
    ),
}


def _source_location(obj: Any, repository_root: Path) -> tuple[str, int] | None:
    loc = getattr(obj, "location", None)
    if loc is None or not isinstance(loc.line, int) or loc.line < 1:
        return None
    try:
        rel = loc.path.resolve().relative_to(repository_root.resolve()).as_posix()
    except ValueError:
        return None
    return rel, loc.line


def _source_native_tools(data: dict[str, Any], slot: str) -> set[str]:
    return {
        str(e["name"])
        for e in data.get(slot, {}).get("entities", [])
        if isinstance(e, dict) and e.get("kind") == "tool"
        and isinstance(e.get("name"), str)
    }


def source_evidence_report(
    *, case_id: str, repo: str, source_sha: str, application_path: str,
    ledger: dict[str, Any], graph: Any, shadow: dict[str, Any],
    adg: dict[str, Any], authority: dict[str, Any], findings: list[Any],
    repository_root: Path,
) -> dict[str, Any]:
    """Fail on source identity / runtime promotion; report evidence gaps."""
    if case_id not in PINS:
        raise ValueError("unknown WAB case")
    expected_repo, expected_sha, expected_root = PINS[case_id]
    if (repo, source_sha, application_path) != (
        expected_repo, expected_sha, expected_root
    ):
        raise ValueError(f"case repository/SHA/application scope drift: {case_id}")
    if shadow.get("source_edge_adjudicated") is not False:
        raise ValueError("legacy shadow was incorrectly marked as source adjudicated")
    if shadow.get("runtime_effectiveness") != "not_verified":
        raise ValueError("shadow is claiming effective runtime authority")
    if shadow.get("comparison", {}).get("graph_behavior_changed") is not False:
        raise ValueError("shadow unexpectedly changes Graph behavior")
    for b in shadow.get("bindings", []):
        if b.get("kind") == "agent_can_call":
            raise ValueError("legacy Graph membership was promoted to AGENT_CAN_CALL")

    for relation in authority.get("relationships", []):
        if relation.get("runtime_effectiveness") != "not_verified":
            raise ValueError("static relationship claims executed authority")

    native_count: int | None = None
    native_observed: set[str] = set()
    native_missing: list[str] = []
    confirmed_source_witnesses = 0
    constructor_sites: list[dict[str, Any]] = []
    source = ledger.get("cases", {}).get(case_id)
    if case_id != "gen-mcp-001":
        if not isinstance(source, dict) or (
            source.get("repo"), source.get("sha")
        ) != (repo, source_sha):
            raise ValueError("source-ledger case identity mismatch")

    if case_id in {"gen-pyd-001", "gen-mcp-003"}:
        edges = source["tool_edges"]
        if case_id == "gen-pyd-001":
            native_observed = _source_native_tools(shadow, "source_native")
        else:
            native_observed = _source_native_tools(shadow, "source_native_toolsets")
        wanted = [x["tool"] for x in edges]
        if any(x.get("agent_can_call") != "unresolved" for x in edges):
            raise ValueError("conditional source exposure promoted to call authority")
        # Couchbase tool symbols are server-qualified: repeat-name functions
        # across servers are source-distinct and cannot prove runtime multiplicity.
        native_count = len(native_observed)
        native_missing = sorted(set(wanted) - native_observed)
        confirmed_source_witnesses = len(edges)
        if case_id == "gen-mcp-003" and graph.agents:
            raise ValueError("provider-only Couchbase source became an agent")

    elif case_id == "ff60-microsoft-04":
        servers = source["server_edges"]
        if len(servers) != 2 or source.get("catalogue_state") != "unresolved_remote":
            raise ValueError("pinned Microsoft dynamic registry census changed")
        if any(e.get("tool_names") or e.get("agent_can_call") != "unresolved"
               for e in servers):
            raise ValueError("dynamic ListToolsAsync was interpreted as static tools")
        confirmed_source_witnesses = 2

    elif case_id == "ff60-amazon-04":
        sites = source["constructor_sites"]
        if len(sites) != 10 or len(source["orchestrator_tool_membership"]) != 9:
            raise ValueError("source constructor/wrapper census changed")
        observed_sites = Counter(
            loc for a in graph.agents
            if (loc := _source_location(a, repository_root)) is not None
        )
        for site in sites:
            witness = site["source_witness"]
            expected_loc = witness["path"], witness["line"]
            match = observed_sites.get(expected_loc, 0)
            constructor_sites.append({
                "symbol": site["symbol"], "path": expected_loc[0],
                "line": expected_loc[1], "legacy_graph_source_sites": match,
                "runtime_instance": site["runtime_instance"],
                "live_delegation": "unresolved",
            })
        confirmed_source_witnesses = len(sites)
        native_observed = _source_native_tools(shadow, "source_native_strands")
        native_count = len(native_observed)
        native_missing = sorted({
            w["definition_symbol"]
            for w in source["orchestrator_tool_membership"]
            if w["nested_constructor_link_status"] == "source_visible_deferred_two_hop"
        } - native_observed)

    else:
        # Verified separately against 124 source-qualified unbound MCP sites
        # by scripts/verify_wave_b540_wab05_source_context.py.
        inventory = shadow.get("inventory_partition", {}).get(
            "observations_by_role", {}
        ).get("unbound_mcp_inventory", {})
        if not isinstance(inventory, dict):
            raise ValueError("WAB-05 role-partition evidence unavailable")
        if graph.agents:
            raise ValueError("LinkedIn MCP provider fixture became an agent")
        confirmed_source_witnesses = 124
        native_count = sum(inventory.values())
        if inventory.get("test") != 121 or inventory.get("runtime") != 3:
            raise ValueError("WAB-05 source-role partition drift")

    find_rows = []
    for finding in findings:
        data = finding.as_dict()
        find_rows.append({
            "rule_id": data["rule_id"],
            "severity": data["severity"],
            "source_context": data["source_context"],
            "assessment": data["assessment"],
            "has_source_anchor": bool(data.get("location")),
            "has_provenance": bool(data.get("provenance")),
            "provenance_origins": sorted({
                x.get("origin") for x in data.get("provenance", [])
                if isinstance(x, dict) and isinstance(x.get("origin"), str)
            }),
            "limitations": data.get("limitations", []),
            "fingerprint": data.get("fingerprint"),
            "agent": data.get("agent"),
            "source_location": data.get("location"),
            "evidence_text": data.get("evidence", []),
            "provenance_witnesses": [
                {"subject": fact.get("subject"), "fact": fact.get("fact"),
                 "origin": fact.get("origin"), "location": fact.get("location")}
                for fact in data.get("provenance", [])
                if isinstance(fact, dict)
            ],
        })
    attack_paths = [
        {"path_id": p.path_id, "agent": p.agent, "severity": p.severity.label(),
         "source_anchored": p.location is not None,
         "source_location": (
             {"path": str(p.location.path), "line": p.location.line}
             if p.location is not None else None
         ),
         "path_nodes": list(p.nodes),
         "rationale": p.rationale,
         "metadata": p.metadata,
         "runtime_effectiveness": "not_verified",
         "source_only_potential_path": True}
        for p in getattr(graph, "attack_paths", [])
    ]
    adg_nodes = adg.get("nodes")
    adg_edges = adg.get("edges")
    if not isinstance(adg_nodes, list) or not isinstance(adg_edges, list):
        raise ValueError("missing ADG nodes/edges in current scanner")
    return {
        "schema_version": 1,
        "scope": "five_pilot_source_to_current_scanner_differential_noncertified",
        "case_id": case_id, "repo": repo,
        "source_sha": source_sha, "application_path": application_path,
        "expected_source_witnesses": confirmed_source_witnesses,
        "scanner": {
            "agent_count": len(graph.agents),
            "agent_sources": [
                {"name": a.name, "location": _source_location(a, repository_root)}
                for a in graph.agents
            ],
            "unbound_mcp_count": len(graph.unbound_mcp_servers),
            "unresolved_mcp_count": len(graph.unresolved_mcp_references),
            "authority_relationships": len(authority.get("relationships", [])),
            "adg_nodes": len(adg_nodes), "adg_edges": len(adg_edges),
            "findings_count": len(find_rows),
            "potential_attack_paths": len(attack_paths),
        },
        "adg_typed_edge_witnesses": [
            {"kind": row.get("kind"), "source_id": row.get("source"),
             "target_id": row.get("target"), "source_location": row.get("location"),
             "attributes": row.get("attributes", {})}
            for row in adg_edges
        ],
        "authority_relationship_witnesses": [
            {"relationship_id": row.get("relationship_id"), "agent": row.get("agent"),
             "target": row.get("target"), "location": row.get("location"),
             "capabilities": row.get("capabilities", []),
             "dimensions": row.get("dimensions", {}),
             "unresolved": row.get("unresolved", []),
             "runtime_effectiveness": row.get("runtime_effectiveness")}
            for row in authority.get("relationships", [])
        ],
        "native_candidate_tool_count": native_count,
        "source_native_candidate_missing": native_missing,
        "amazon_constructor_source_diff": constructor_sites,
        "finding_witness_queue": find_rows,
        "potential_path_queue": attack_paths,
        "incomplete_finding_source_anchors": sum(
            not x["has_source_anchor"] for x in find_rows
        ),
        "incomplete_finding_provenance": sum(
            not x["has_provenance"] for x in find_rows
        ),
        "positive_source_ledger_independent": False,
        "exhaustive_negative_label_universe": False,
        "runtime_effectiveness_verified": False,
        "source_precision": None, "source_recall": None,
        "finding_precision": None, "attack_path_precision": None,
        "wave_b_go": False, "wave_c_go": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case-id", choices=sorted(PINS), required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    repo, source_sha, app = PINS[args.case_id]
    root = args.source.resolve()
    application = (root / app).resolve()
    if not application.is_relative_to(root) or not application.exists():
        raise ValueError("pinned application directory absent or escapes checkout")
    graph, findings = scan(application)
    shadow = shadow_observation_report(graph, application)
    adg = build_adg(graph, application).as_dict()
    authority = effective_authority_report(graph)
    report = source_evidence_report(
        case_id=args.case_id, repo=repo, source_sha=source_sha,
        application_path=app,
        ledger=json.loads(args.ledger.read_text(encoding="utf-8")),
        graph=graph, shadow=shadow, adg=adg, authority=authority,
        findings=findings, repository_root=root,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    print(json.dumps({
        "case_id": args.case_id,
        "agents": report["scanner"]["agent_count"],
        "source_native_missing": len(report["source_native_candidate_missing"]),
        "findings": report["scanner"]["findings_count"],
        "potential_paths": report["scanner"]["potential_attack_paths"],
        "wave_b_go": False,
    }))


if __name__ == "__main__":
    main()
