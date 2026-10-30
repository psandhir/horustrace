"""WAB-04: verify exact Strands source constructors survive production normalization.

This is a pinned source/inventory witness, not independent TP/FP/FN adjudication.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from horustrace.effective_authority import effective_authority_relationships
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
    graph, findings = scan(source)
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

    # Provenance of the third-party import must be pinned to source. The
    # catalogue's capability labels are inferred, not proof that a package
    # revision executed or that deployed approval/egress controls are absent.
    writers = [
        agent for agent in graph.agents
        if agent.location is not None
        and agent.location.path.resolve() == (source / "agents/analysis_writer.py").resolve()
    ]
    if len(writers) != 1:
        raise ValueError("expected one source-qualified analysis_writer Agent")
    shells = [
        tool for tool in writers[0].tools
        if tool.kind == "strands_vended_tool" and tool.name == "shell"
    ]
    if len(shells) != 1:
        raise ValueError("expected one source-bound Strands shell import")
    shell = shells[0]
    if shell.location is None or shell.location.line != 18:
        raise ValueError("source-import witness moved or lost")
    if not any(
        fact.fact == "source_import=strands_tools.shell"
        and fact.origin == "observed"
        and fact.location == shell.location
        for fact in shell.provenance
    ):
        raise ValueError("observed source import missing from Strands shell tool")
    if not any(
        fact.fact == "capability=process.execute"
        and fact.origin == "inferred"
        and fact.location == shell.location
        for fact in shell.provenance
    ):
        raise ValueError("inferred shell capability lost source attribution")
    if any(
        fact.fact.startswith("capability=") and fact.origin == "observed"
        or "allowlist" in fact.fact or "approval_configuration" in fact.fact
        for fact in shell.provenance
    ):
        raise ValueError("fabricated observed effect or deployed control fact")
    # A CAP005 claim combines two independent capability dimensions.
    # The evidence may be inferred from a third-party Strands import, but
    # never promotes source evidence to a verified runtime authority edge.
    combined = [finding for finding in findings if finding.rule_id == "CAP005"]
    if len(combined) != 10:
        raise ValueError(
            f"pinned Strands CAP005 source count changed: {len(combined)}"
        )
    for finding in combined:
        facts = finding.provenance
        kinds = {fact.fact for fact in facts}
        if len(facts) != 2 or "capability=data.read" not in kinds or not (
            {"capability=data.write", "capability=destructive.write"} & kinds
        ):
            raise ValueError(
                f"CAP005 missing dual source witness at {finding.location}"
            )
        if any(
            fact.location is None or fact.location.path.resolve().is_relative_to(source.resolve()) is False
            for fact in facts
        ):
            raise ValueError("CAP005 witness outside frozen source tree")
        if any(
            fact.origin not in {"observed", "inferred", "declared"}
            for fact in facts
        ):
            raise ValueError("CAP005 witness has unverified origin label")

    # Exact relationship identity is available in the source-derived
    # authority report, but is not runtime authorization or a negative
    # assertion that deployed approval/guardrails are absent.
    relationships = {
        item.relationship_id: item
        for item in effective_authority_relationships(graph)
    }
    privileged = [finding for finding in findings if finding.rule_id == "AGT040"]
    if len(privileged) != 28:
        raise ValueError(
            f"pinned Strands AGT040 source count changed: {len(privileged)}"
        )
    for finding in privileged:
        references = [
            item.split("=", 1)[1]
            for item in finding.evidence
            if item.startswith("authority_relationship=")
        ]
        if len(references) != 1:
            raise ValueError("AGT040 lacks a unique authority relationship reference")
        relation = relationships.get(references[0])
        if relation is None or relation.target_kind != "tool":
            raise ValueError("AGT040 relationship not resolved to one source tool")
        expected_import = "source_import=strands_tools." + relation.target_name
        import_facts = [
            fact for fact in finding.provenance
            if fact.fact.startswith("source_import=")
        ]
        if len(import_facts) != 1 or not (
            import_facts[0].fact == expected_import
            and import_facts[0].origin == "observed"
            and import_facts[0].subject == relation.target_name
        ):
            raise ValueError(
                f"AGT040 wrong/absent source-import witness: {references[0]}"
            )
        caps = {
            cap for evidence in finding.evidence
            if evidence.startswith("capabilities=")
            for cap in evidence.split("=", 1)[1].split(",") if cap
        }
        capability_facts = [
            fact for fact in finding.provenance
            if fact.fact.startswith("capability=")
        ]
        if not caps or {f.fact.split("=", 1)[1] for f in capability_facts} != caps:
            raise ValueError("AGT040 capabilities copied from wrong source tool")
        if any(f.origin != "inferred" for f in capability_facts):
            raise ValueError("AGT040 inferred package capability promoted to observation")
        if len(finding.provenance) != 1 + len(caps):
            raise ValueError("AGT040 copied unrelated source or control facts")
        if any(
            fact.location is None
            or relation.location is None
            or str(fact.location.path) != relation.location["path"]
            or fact.location.line != relation.location["line"]
            or fact.location.column != relation.location["column"]
            for fact in finding.provenance
        ):
            raise ValueError("AGT040 witness lost exact relationship location")
    # There is no observed deployment or authorization evidence in this
    # imported-source test. Identity and approval stay unknown.
    if any(
        relation.approval.get("required") is not None
        for relation in relationships.values()
        if relation.target_kind == "tool"
    ):
        raise ValueError("AGT040 source proof gained invented runtime approval")

    return {
        "case": "ff60-amazon-04",
        "source": "aws-samples/sample-multi-agent-region-expansion-planner@30d03d7c9f6512e5bf10601879382fac9c3a16b1",
        "historic_stage_delta": {"discovered": 10, "after_consolidation": 2},
        "new_final_source_instances": sorted(
            [{"file": file, "line": line} for file, line in distinct],
            key=lambda row: (row["file"], row["line"]),
        ),
        "new_final_agent_count": len(locations),
        "cap005_with_paired_source_witness": len(combined),
        "agt040_with_unique_source_tool_witness": len(privileged),
        "agt040_runtime_authority_verified": False,
        "cap005_runtime_effects_verified": False,
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
        "strands_tool_import_source_verified": True,
        "tool_capability_effects_runtime_verified": False,
        "strands_tool_dependency_version_verified": False,
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
