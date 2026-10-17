"""Fail-closed source-truth audit for the immutable Wave B Amazon pilot.

This is an evidence overlay, not a tool-effect contract verifier or an accuracy
score. A package import and a name-based capability heuristic never prove the
installed tool version, control enforcement, runtime reachability or execution.
"""
from __future__ import annotations

import argparse
import json
import re
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any

PINNED_CASE = "amazon-hold-004"
PINNED_REPOSITORY = "aws-samples/sample-multi-agent-region-expansion-planner"
PINNED_SHA = "30d03d7c9f6512e5bf10601879382fac9c3a16b1"
_DEP = re.compile(r"^strands-agents-tools(?:\[[^\]]+\])?\s*(.*)$", re.IGNORECASE)


def dependency_declaration(requirements: str) -> str:
    """Report only what a declared dependency can prove, not installed bytes."""
    specs: list[str] = []
    for line in requirements.splitlines():
        stripped = line.partition("#")[0].strip()
        match = _DEP.fullmatch(stripped)
        if match is not None:
            specs.append(match.group(1).split(";")[0].strip())
    if len(specs) != 1:
        return "missing_or_ambiguous"
    spec = specs[0]
    if not spec:
        return "unversioned"
    if re.fullmatch(r"==\s*\d+\.\d+(?:\.\d+)?(?:\.\d+)?", spec):
        return "exact_declared_version_not_installed_attestation"
    return "range_or_dynamic_not_installed_attestation"


def audit_imported_tool_truth(
    result: dict[str, Any], requirements: str
) -> dict[str, Any]:
    """Validate immutable case identity; identify unsupported effect attestation."""
    if (
        result.get("case_id") != PINNED_CASE
        or result.get("repo") != PINNED_REPOSITORY
        or result.get("sha") != PINNED_SHA
        or result.get("application_path") != "src"
    ):
        raise ValueError("wrong source-pinned case or application root")
    agents = result.get("agent_inventory")
    findings = result.get("findings")
    authority = result.get("authority_relationships")
    if not isinstance(agents, list) or not agents:
        raise ValueError("missing agent inventory")
    if not isinstance(findings, list) or not isinstance(authority, list):
        raise ValueError("missing finding/authority evidence")
    if len(agents) != result.get("counts", {}).get("agents"):
        raise ValueError("agent count mismatch")
    if len(findings) != result.get("counts", {}).get("findings"):
        raise ValueError("finding count mismatch")
    if len(authority) != result.get("counts", {}).get("authority_relationships"):
        raise ValueError("authority count mismatch")

    imported: Counter[str] = Counter()
    imports_by_factory: dict[str, list[str]] = {}
    deferred = 0
    for agent in agents:
        metadata = agent.get("metadata")
        tools = agent.get("tools")
        if not isinstance(metadata, dict) or not isinstance(tools, list):
            raise ValueError("unreviewable agent or tool metadata")
        if metadata.get("construction_scope") == "tool_wrapper_deferred_invocation":
            deferred += 1
        factory = str(metadata.get("source_factory") or agent.get("name") or "")
        if factory in imports_by_factory:
            raise ValueError("duplicate source factory identity")
        tool_names: list[str] = []
        for tool in tools:
            if not isinstance(tool, dict):
                raise ValueError("unreviewable tool")
            if tool.get("kind") != "strands_vended_tool":
                continue
            meta = tool.get("metadata")
            if not isinstance(meta, dict) or meta.get("source_symbol_origin") != "import_statement":
                raise ValueError("vended tool lacks an explicit imported symbol witness")
            if meta.get("source_module") != "strands_tools":
                raise ValueError("vended tool source is not the pinned import surface")
            name = tool.get("name")
            if not isinstance(name, str) or not name:
                raise ValueError("vended tool with no imported name")
            imported[name] += 1
            tool_names.append(name)
        imports_by_factory[factory] = sorted(tool_names)

    origins: Counter[str] = Counter()
    rules: Counter[str] = Counter()
    for finding in findings:
        if not isinstance(finding, dict) or not isinstance(finding.get("provenance"), list):
            raise ValueError("finding has no reviewable provenance array")
        rule = finding.get("rule_id")
        if not isinstance(rule, str):
            raise ValueError("finding lacks a rule")
        rules[rule] += 1
        for fact in finding["provenance"]:
            if not isinstance(fact, dict) or fact.get("origin") not in {"observed", "inferred", "declared"}:
                raise ValueError("unknown provenance origin")
            origins[fact["origin"]] += 1

    status = dependency_declaration(requirements)
    if status != "unversioned":
        # Different inputs must not reuse the pinned case's unversioned attestation.
        # The audit remains NO-GO for runtime truth even if an exact range exists.
        pass
    return {
        "schema_version": 1,
        "scope": "source_only_imported_tool_contract_audit",
        "case_id": PINNED_CASE,
        "source_sha": PINNED_SHA,
        "application_root": "src",
        "source_dependency_declaration": status,
        "imported_vended_tool_occurrences": sum(imported.values()),
        "imported_vended_tool_names": dict(sorted(imported.items())),
        "source_factories": imports_by_factory,
        "deferred_agent_constructors": deferred,
        "finding_count": len(findings),
        "finding_rules": dict(sorted(rules.items())),
        "provenance_fact_origins": dict(sorted(origins.items())),
        "authority_relationship_count": len(authority),
        "installed_tool_implementation_verified": False,
        "external_tool_effects_verified": False,
        "runtime_approval_controls_verified": False,
        "independent_ground_truth": False,
        "precision": None,
        "recall": None,
        "wave_c_go": False,
        "limitations": [
            "Imported tool symbols are source-visible but their implementation is outside the pinned application.",
            "A declared dependency version, when present, is not a proof of installed or executed package bytes.",
            "Name-derived capabilities and inferred provenance are candidates, not observed runtime effects.",
            "A deferred @tool wrapper constructor is not proof its nested agent executes.",
            "MCP @latest catalogues are not immutable source-pinned tool registries.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    case_input = parser.add_mutually_exclusive_group(required=True)
    case_input.add_argument("--case-zip", type=Path)
    case_input.add_argument("--case-json", type=Path)
    parser.add_argument("--requirements", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.case_zip is not None:
        with zipfile.ZipFile(args.case_zip) as archive:
            result = json.loads(archive.read("result.json"))
    else:
        result = json.loads(args.case_json.read_text(encoding="utf-8"))
    report = audit_imported_tool_truth(
        result, args.requirements.read_text(encoding="utf-8")
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "source": report["source_sha"],
        "imported_vended_tool_occurrences": report["imported_vended_tool_occurrences"],
        "dependency": report["source_dependency_declaration"],
        "wave_c_go": False,
    }))


if __name__ == "__main__":
    main()
