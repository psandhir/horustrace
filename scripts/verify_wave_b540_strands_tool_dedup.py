"""Exact-SHA WAB-04 proof that an imported @tool has one production identity.

Static source claims only: no target execution or runtime invocation proof.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from horustrace.effective_authority import effective_authority_report
from horustrace.scanner import scan

CASE = "ff60-amazon-07"
SOURCE = "garystafford/aws-strands-agents-mcp-demo@324988770122a2302163fc12cdda0f1d805bf407"


def verify(root: Path) -> dict[str, object]:
    graph, _ = scan(root)
    orchestrators = [a for a in graph.agents if a.name == "orchestrator_agent"]
    if len(orchestrators) != 1:
        raise ValueError("expected one source orchestrator")
    orchestrator = orchestrators[0]
    wrappers = [t for t in orchestrator.tools if t.name == "weather_assistant"]
    if len(wrappers) != 1:
        raise ValueError(
            f"same decorated source callable is present {len(wrappers)} times"
        )
    tool = wrappers[0]
    if tool.kind != "strands_tool_wrapper":
        raise ValueError("decorated tool lost its canonical Strands wrapper kind")
    metadata = tool.metadata
    if (
        metadata.get("source_function_key")
        != "agent_stdio_multi_agent.weather_assistant"
        or metadata.get("source_line") != 80
        or Path(str(metadata.get("source_path") or "")).resolve()
        != (root / "agent_stdio_multi_agent.py").resolve()
    ):
        raise ValueError("Strands wrapper does not match exact source declaration")
    if metadata.get("nested_agent_execution") != "deferred_until_wrapper_invocation":
        raise ValueError("nested Agent was incorrectly treated as eager")
    if len(orchestrator.tools) != 3:
        raise ValueError(f"orchestrator tool count regression: {len(orchestrator.tools)}")
    if len(graph.agents) != 2:
        raise ValueError(f"agent source identity regression: {len(graph.agents)}")

    authority = effective_authority_report(graph)
    relationships = authority["summary"]["relationships"]
    if relationships != 5:
        raise ValueError(
            f"phantom or missing authority edge: expected 5, got {relationships}"
        )
    return {
        "case": CASE,
        "source": SOURCE,
        "agents": len(graph.agents),
        "orchestrator_tools": len(orchestrator.tools),
        "source_decorated_wrappers": len(wrappers),
        "authority_relationships": relationships,
        "nested_agent_execution": metadata["nested_agent_execution"],
        "runtime_invocation_verified": False,
        "independent_truth_review": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.source), indent=2))
