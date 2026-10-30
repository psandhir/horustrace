"""WAB-01/02 finding-only exact-source evidence verification on pinned targets.

Source endpoint declarations are positively witnessable. Neither absence of an
allowlist nor deployed MCP effects can be certified from a checked-out manifest.
CAP005 without both independent read/write witnesses stays POTENTIAL.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from horustrace.scanner import scan

CASES = {
    "gen-pyd-001": {
        "repo": "newsbubbles/pharmiq",
        "sha": "c69949739647a47ec8339b473bdf578c8cf8bfd9",
        "application_path": ".",
    },
    "ff60-microsoft-04": {
        "repo": "qmatteoq/agent365-demos",
        "sha": "937f8c12421b6eebfbff764dbafbdbe13cc72f68",
        "application_path": "dotnet-agent-teammate",
    },
}
UNKNOWN_DEPLOYMENT = "the deployed MCP tool catalogue and effective filters are unverified"


def adjudicate_finding_source(case_id: str, graph: Any, findings: list[Any],
                              root: Path) -> dict[str, Any]:
    if case_id not in CASES:
        raise ValueError("unknown frozen finding case")
    evaluated: list[dict[str, Any]] = []
    if case_id == "ff60-microsoft-04":
        target = [finding for finding in findings if finding.rule_id == "AGT032"]
        if len(target) != 2:
            raise ValueError("pinned manifest MCP allowlist finding census changed")
        for finding in target:
            facts = finding.provenance
            if len(facts) != 1:
                raise ValueError("AGT032 missing exactly one declared endpoint fact")
            fact = facts[0]
            if (fact.location is None or finding.location is None
                or fact.location != finding.location
                or fact.origin != "declared" or not fact.fact.startswith("url=")
                or fact.fact not in finding.evidence
                or UNKNOWN_DEPLOYMENT not in " ".join(finding.limitations)):
                raise ValueError("AGT032 manifest evidence is not exact and bounded")
            servers = [
                x for x in graph.all_mcp_servers()
                if x.name == fact.subject and x.location == fact.location
                and x.url is not None and "url=" + x.url == fact.fact
            ]
            if len(servers) != 1:
                raise ValueError("AGT032 fact does not uniquely identify source server")
            if any("allowlist=" in x.fact or "tool_catalogue=" in x.fact
                   for x in facts):
                raise ValueError("source absence claimed as verified deployment fact")
            evaluated.append({
                "rule_id": finding.rule_id,
                "source_server": fact.subject,
                "configured_url": servers[0].url,
                "source_file": str(fact.location.path.relative_to(root)),
                "source_line": fact.location.line,
                "source_witness": "declared_endpoint_only",
                "effective_allowlist": "unresolved",
                "runtime_catalogue": "unresolved",
            })
        if {x["source_server"] for x in evaluated} != {
            "mcp_MailTools", "mcp_CalendarTools"
        }:
            raise ValueError("wrong manifest server identities")
    else:
        target = [finding for finding in findings if finding.rule_id == "CAP005"]
        if len(target) != 1:
            raise ValueError("pinned Pharmiq combined authority finding census changed")
        finding = target[0]
        if (finding.provenance or finding.assessment != "heuristic_risk"
            or finding.confidence is None
            or finding.confidence.value != "potential"
            or "Separate source-backed read and write" not in
                " ".join(finding.limitations)):
            raise ValueError("unverified read/write authority promoted")
        evaluated.append({
            "rule_id": "CAP005",
            "source_witness": "dual_read_write_witness_absent",
            "source_agent": finding.agent,
            "authority_relation_present_in_evidence": any(
                s.startswith("authority_relationship=") for s in finding.evidence
            ),
            "execution_verified": False,
            "assessment": "heuristic_risk",
            "confidence": "potential",
        })
    return {
        "schema_version": 1,
        "case_id": case_id,
        "repo": CASES[case_id]["repo"],
        "source_sha": CASES[case_id]["sha"],
        "scope": "bounded_source_finding_differential_not_independent_accuracy",
        "claims": evaluated,
        "claim_count": len(evaluated),
        "source_precision": None, "source_recall": None,
        "deployed_controls_verified": False,
        "independent_negative_truth": False,
        "wave_b_go": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case-id", required=True, choices=sorted(CASES))
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    case = CASES[args.case_id]
    root = args.source.resolve()
    application = (root / case["application_path"]).resolve()
    if not application.is_relative_to(root) or not application.is_dir():
        raise ValueError("case application scope missing/escaping pinned source")
    graph, findings = scan(application)
    report = adjudicate_finding_source(args.case_id, graph, findings, root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    print(json.dumps({"case": report["case_id"], "claims": report["claim_count"],
                      "wave_b_go": False}))


if __name__ == "__main__":
    main()
