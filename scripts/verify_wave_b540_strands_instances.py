"""WAB-04: verify exact Strands source constructors survive production normalization.

This is a pinned source/inventory witness, not independent TP/FP/FN adjudication.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from horustrace.scanner import scan

EXPECTED = {
    ("main.py", 56),
    ("agents/planning_report_generator.py", 102),
    ("agents/multi_region_expansion_planner.py", 104),
    ("agents/tech_analysis.py", 140),
    ("agents/cloudtrail_explorer.py", 68),
    ("agents/analysis_writer.py", 72),
    ("agents/report_writer.py", 74),
    ("agents/waypoint_explorer.py", 78),
    ("agents/pricing_explorer.py", 89),
    ("agents/cfn_explorer.py", 92),
}


def verify(root: Path) -> dict[str, object]:
    source = root / "src"
    graph, _ = scan(source)
    locations: list[tuple[str, int]] = []
    for agent in graph.agents:
        if agent.location is None:
            raise ValueError(f"agent without source instance: {agent.name}")
        location = agent.location
        try:
            rel = location.path.resolve().relative_to(source.resolve()).as_posix()
        except ValueError as exc:
            raise ValueError("non-local agent instance source") from exc
        locations.append((rel, location.line))
    distinct = set(locations)
    construction_scope = {}
    for agent in graph.agents:
        location = agent.location
        assert location is not None
        key = location.path.resolve().relative_to(source.resolve()).as_posix()
        role = agent.metadata.get("construction_scope")
        construction_scope[key] = role
        if key.startswith("agents/"):
            if role != "tool_wrapper_deferred_invocation":
                raise ValueError(f"nested agent lacks deferred tool wrapper role: {key}")
            if agent.metadata.get("source_tool_wrapper") is not True:
                raise ValueError(f"nested agent lacks source tool decorator: {key}")
        elif key == "main.py" and role != "function_local_conditional":
            raise ValueError("orchestrator constructor is not module instantiated")
    missing = EXPECTED - distinct
    extra = distinct - EXPECTED
    if missing or extra or len(locations) != len(EXPECTED):
        raise ValueError(
            f"expected exactly 10 source constructors; "
            f"missing={sorted(missing)}, extra={sorted(extra)}, "
            f"total={len(locations)}"
        )
    # Imported specialist wrappers are tools passed to the orchestrator,
    # not source-proven eagerly instantiated Agent delegation targets.
    orchestrators = [agent for agent in graph.agents if agent.name == "orchestrator"]
    if len(orchestrators) != 1:
        raise ValueError("source orchestrator identity unresolved")
    expected_wrappers = {
        "cfn_explorer",
        "cloudtrail_explorer",
        "waypoint_explorer",
        "analysis_writer",
        "multi_region_expansion_planner",
        "planning_report_generator",
        "report_writer",
        "tech_analysis_writer",
    }
    bound_wrappers = {
        tool.name for tool in orchestrators[0].tools
        if tool.kind == "strands_tool_wrapper"
    }
    if bound_wrappers != expected_wrappers:
        raise ValueError(
            f"expected source-decorated callable wrapper tools "
            f"{sorted(expected_wrappers)} but observed {sorted(bound_wrappers)}"
        )
    if any(
        tool.kind == "delegated_agent" and tool.name == "agent"
        for tool in orchestrators[0].tools
    ):
        raise ValueError("ambiguous nested Agent promoted to live delegation")
    return {
        "case": "ff60-amazon-04",
        "source": "aws-samples/sample-multi-agent-region-expansion-planner@30d03d7c9f6512e5bf10601879382fac9c3a16b1",
        "historic_stage_delta": {"discovered": 10, "after_consolidation": 2},
        "new_final_source_instances": sorted(
            [{"file": file, "line": line} for file, line in distinct],
            key=lambda row: (row["file"], row["line"]),
        ),
        "new_final_agent_count": len(locations),
        "orchestrator_source_callable_wrappers": sorted(bound_wrappers),
        "pricing_explorer_import": "unresolved_module_vs_decorated_callable",
        "construction_scope_counts": {
            "tool_wrapper_deferred_invocation": sum(
                value == "tool_wrapper_deferred_invocation"
                for value in construction_scope.values()
            ),
            "function_local_conditional": sum(
                value == "function_local_conditional"
                for value in construction_scope.values()
            ),
        },
        "source_location_preservation_verified": True,
        "runtime_instances_verified": False,
        "deferred_source_authority_truth": True,
        "blind_precision_recall_adjudicated": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.source), indent=2))
