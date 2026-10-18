"""WAB-05: every ADG exposed-tool edge must expose its source role.

A source @mcp.tool declaration is evidence of source exposure only, not a
deployed provider, granted AGENT_CAN_CALL or verified network authority.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from horustrace.adg import build_adg
from horustrace.scanner import scan
from horustrace.source_context import classify_source_context
from scripts.verify_wave_b540_wab05_source_context import (
    UPSTREAM_SHA, verify_frozen_sources,
)


def check_wab05_adg_edges(adg: dict[str, Any], root: Path) -> dict[str, Any]:
    edges = adg.get("edges")
    nodes = adg.get("nodes")
    if not isinstance(edges, list) or not isinstance(nodes, list):
        raise ValueError("missing ADG source edge evidence")
    if any(node.get("kind") == "agent" for node in nodes):
        raise ValueError("provider-only source became a runtime agent")
    node_by_id = {n.get("id"): n for n in nodes}
    if len(node_by_id) != len(nodes):
        raise ValueError("duplicate ADG source entity")
    exposed = [edge for edge in edges if edge.get("kind") == "EXPOSES_TOOL"]
    if not exposed:
        raise ValueError("source-decorated MCP catalogue silently dropped")
    contexts: Counter[str] = Counter()
    for edge in exposed:
        attrs = edge.get("attributes")
        if not isinstance(attrs, dict):
            raise ValueError("exposure missing source metadata")
        loc = edge.get("location")
        if not isinstance(loc, dict) or not isinstance(loc.get("path"), str):
            raise ValueError("exposure missing relative source location")
        source_path = (root / loc["path"]).resolve()
        if not source_path.is_relative_to(root.resolve()):
            raise ValueError("source path escapes pinned provider root")
        actual = classify_source_context(source_path, root=root)
        if attrs.get("source_context") != actual:
            raise ValueError("ADG tool exposure source role mismatch")
        if (attrs.get("authority_verified") is not False
            or attrs.get("deployment_verified") is not False
            or attrs.get("agent_binding") != "unbound"
            or attrs.get("basis") != "source_proven_mcp_decorator"):
            raise ValueError("unbound source exposure promoted to live authority")
        server = node_by_id.get(edge.get("source"))
        tool = node_by_id.get(edge.get("target"))
        if not server or not tool:
            raise ValueError("dangling source exposure ADG edge")
        if (server.get("kind") != "mcp_server"
            or tool.get("kind") not in {"tool", "mcp_tool"}):
            raise ValueError("source exposure mismatched object type")
        server_attrs = server.get("attributes") or {}
        tool_attrs = tool.get("attributes") or {}
        if (server_attrs.get("source_context") !=
                attrs.get("server_source_context")
            or tool_attrs.get("source_context") != actual):
            raise ValueError("source role lost between edge and entity")
        if (server_attrs.get("deployment_verified") is not False
            or tool_attrs.get("deployment_verified") is not False):
            raise ValueError("source candidate labeled deployed")
        contexts[actual] += 1
    return {
        "schema_version": 1,
        "case_id": "gen-mcp-001",
        "target_sha": UPSTREAM_SHA,
        "scope": "source_qualified_unbound_adg_exposures_not_live_permissions",
        "exposes_tool_source_edges": len(exposed),
        "source_context_counts": dict(sorted(contexts.items())),
        "agent_can_call_verified": False,
        "deployment_verified": False,
        "independent_ground_truth": False,
        "precision": None,
        "recall": None,
        "wave_b_go": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.source.resolve()
    verify_frozen_sources(root)
    graph, _ = scan(root)
    if graph.agents:
        raise ValueError("source-only WAB-05 provider claims agent instances")
    report = check_wab05_adg_edges(build_adg(graph, root).as_dict(), root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "source_exposures": report["exposes_tool_source_edges"],
        "source_context_counts": report["source_context_counts"],
        "wave_b_go": False,
    }))


if __name__ == "__main__":
    main()
