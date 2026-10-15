"""Pinned WAB-04 source-only chain verification, not independent source truth."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from horustrace.source_native_strands import inspect_strands_tool_composition

PINS = {
    "src/main.py": "e9f374cf99d80460602c633de8470a043c991c9a",
    "src/agents/__init__.py": "5f7114f83152fc73ee0b84cd5a4c56a550d5ceb1",
    "src/agents/cfn_explorer.py": "b52551548200e06c797c670a06a5fca8ef3fdebf",
}
EXPECTED = {
    "cfn_explorer", "cloudtrail_explorer", "waypoint_explorer",
    "analysis_writer", "multi_region_expansion_planner",
    "planning_report_generator", "report_writer",
}


def validate(root: Path) -> dict[str, object]:
    for path, digest in PINS.items():
        payload = (root / path).read_bytes()
        actual = hashlib.sha1(
            b"blob " + str(len(payload)).encode("ascii") + b"\0" + payload
        ).hexdigest()
        if actual != digest:
            raise ValueError(f"pinned source blob changed: {path}")
    result = inspect_strands_tool_composition(root / "src").as_dict()
    entities = {e["entity_id"]: e for e in result["entities"]}
    wrappers = {
        e["name"] for e in result["entities"] if e["kind"] == "tool"
    }
    if wrappers != EXPECTED:
        raise ValueError(
            f"source wrapper candidate mismatch; expected {sorted(EXPECTED)},"
            f" observed {sorted(wrappers)}"
        )
    edges = result["bindings"]
    if len(edges) != 2 * len(EXPECTED):
        raise ValueError("wrong number of source-candidate two-hop links")
    if any(e["kind"] != "invokes" or e["resolution"] != "partial" for e in edges):
        raise ValueError("unverified effective delegation inferred")
    if not any(n["name"] == "orchestrator" for n in entities.values()):
        raise ValueError("orchestrator source instance not found")
    return {
        "case_id": "ff60-amazon-04",
        "review_status": "pinned_source_hypothesis_not_independent_truth",
        "source_wrapper_candidates": sorted(wrappers),
        "source_nested_agent_candidates": len(EXPECTED),
        "source_candidate_edges": len(edges),
        "unresolved_names": [
            "pricing_explorer: not re-exported by agents/__init__.py",
            "tech_analysis_writer: indirect handler invocation unresolved",
        ],
        "historic_consolidation_10_to_2_adjudicated": False,
        "graph_mutated": False,
        "effective_authority_proven": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(validate(args.source), indent=2))
