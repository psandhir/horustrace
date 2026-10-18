"""Pinned WAB-05 source-context / MCP instance partition acceptance witness.

Source-only static scan. Does not install, import or execute the target repo.
Test fixtures are retained as evidence but not classified as deployed MCPs.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from collections import Counter
from pathlib import Path

from horustrace.scanner import scan
from horustrace.semantic_shadow import shadow_observation_report
from horustrace.source_context import classify_source_context

UPSTREAM_SHA = "f1425029ca426e850dc9f52b0097f0fff1aa7b3d"
SOURCE_PINS = {
    "linkedin_mcp_server/server.py": "2bc6f86e8696baea6a4d1f9ef88fccb862fa7153",
    "tests/test_server.py": "84f6bea4c5e2e22fc794898214a9489fd287e979",
}


def verify_frozen_sources(root: Path) -> None:
    for name, expected in SOURCE_PINS.items():
        raw = (root / name).read_bytes()
        digest = hashlib.sha1(
            b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw
        ).hexdigest()
        if digest != expected:
            raise ValueError(f"pinned WAB-05 source changed: {name}")

    # Distinguish a runtime *factory declaration* from a deliberately
    # synthetic owner in a test. Neither establishes a live instance.
    production = ast.parse(
        (root / "linkedin_mcp_server/server.py").read_text(encoding="utf-8")
    )
    tests = ast.parse((root / "tests/test_server.py").read_text(encoding="utf-8"))
    factory = next(
        (node for node in production.body
         if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
         and node.name == "create_mcp_server"),
        None,
    )
    assert factory is not None
    assert any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "FastMCP"
        for node in ast.walk(factory)
    ), "runtime source factory must be source visible"
    owner = next(
        (node for node in tests.body
         if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
         and node.name == "_owner_serving"),
        None,
    )
    assert owner is not None
    assert any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "FastMCP"
        for node in ast.walk(owner)
    ), "test-only owner fixture must be source visible"


def inventory_source_records(graph: object, root: Path) -> dict[str, object]:
    records: list[dict[str, object]] = []
    for server in graph.unbound_mcp_servers:
        location = server.location
        if location is None:
            records.append({
                "name": server.name, "path": None, "line": None,
                "context": "unknown", "resolution": "unresolved_source_location",
            })
            continue
        source_path = location.path
        try:
            rel = source_path.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            records.append({
                "name": server.name, "path": None, "line": location.line,
                "context": "unknown", "resolution": "source_outside_scan_root",
            })
            continue
        context = classify_source_context(source_path, root)
        records.append({
            "name": server.name, "path": rel, "line": location.line,
            "context": context, "resolution": "source_observed_not_deployed",
        })

    by_role = dict(sorted(Counter(r["context"] for r in records).items()))
    sites = Counter(
        (r["path"], r["line"], r["name"])
        for r in records if r["path"] is not None
    )
    # Same-name test providers at different files/lines are different source
    # observations. Same *source site* repeated by scanner is a separate
    # ambiguity, never grounds for another deployed server.
    ambiguous = [
        {"path": p, "line": l, "name": n, "observations": count}
        for (p, l, n), count in sorted(sites.items())
        if count > 1
    ]
    return {
        "case_id": "gen-mcp-001",
        "repo": "stickerdaniel/linkedin-mcp-server",
        "target_sha": UPSTREAM_SHA,
        "source_context_counts": by_role,
        "unbound_observation_count": len(records),
        "qualified_source_site_count": len(sites),
        "ambiguous_same_source_site": ambiguous,
        "records": sorted(
            records, key=lambda r: (
                str(r["path"]), r["line"] or 0, str(r["name"])
            ),
        ),
        "source_context_is_not_deployment_proof": True,
        "agent_callability_adjudicated": False,
        "independent_precision": None,
        "independent_recall": None,
    }


def validate(root: Path) -> dict[str, object]:
    verify_frozen_sources(root)
    graph, _ = scan(root)
    source = inventory_source_records(graph, root)
    shadow = shadow_observation_report(graph, root)
    partition = shadow["inventory_partition"]
    derived = partition["observations_by_role"].get("unbound_mcp_inventory", {})
    if derived != source["source_context_counts"]:
        raise ValueError(
            "legacy unbound MCP source observations lost/mispartitioned in shadow: "
            f"scanner={source['source_context_counts']} shadow={derived}"
        )
    if sum(derived.values()) != source["unbound_observation_count"]:
        raise ValueError("silent drop or duplicate source observation")
    if source["source_context_counts"].get("test", 0) < 1:
        raise ValueError("pinned test-only MCP fixture was not source-qualified")
    if source["source_context_counts"].get("runtime", 0) < 1:
        raise ValueError("pinned runtime-source MCP factory was not source-qualified")
    # Scan scope is a standalone MCP provider, not agent-application proof.
    # If an agent detector claims a source agent, it needs separate positive
    # witness before this source-only pilot can certify absence of inflation.
    if graph.agents:
        raise ValueError("unexpected Agent instance in provider-only source scan")
    if any(
        e["kind"] == "agent_can_call" for e in shadow["bindings"]
    ):
        raise ValueError("test provider source was promoted to agent callability")
    source["historical_wave_a_unbound_mcp"] = {
        "total": 124, "paths_under_tests": 121,
        "note": "prior-run diagnostic comparison only, not a release count floor",
    }
    source["current_shadow_graph_mutated"] = shadow["comparison"][
        "graph_behavior_changed"
    ]
    return source


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = validate(args.source.resolve())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({
        key: result[key] for key in (
            "case_id", "target_sha", "source_context_counts",
            "unbound_observation_count", "qualified_source_site_count",
            "ambiguous_same_source_site", "independent_precision",
            "independent_recall",
        )
    }, sort_keys=True))


if __name__ == "__main__":
    main()
