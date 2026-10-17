"""Same-case, same-ontology source-anchored agent inventory comparison.

Uses exact scanner results for both revisions, not aggregated historical scores.
Original source reference and post-hoc overlay remain immutable inputs. Missing
coverage and unsettled client ontology are UNKNOWN, not automatically FP.
This is a diagnostic, NOT an independently blinded production accuracy gate.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

EXPECTED_SOURCE_SHA = "418db4e29798a7d25df686dd7bccfd9fefa225bd"
EXPECTED_CANDIDATE_SHA = "9d3f05f8e26308f1777e649e30bb62a3e44bef3f"


def read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: not a JSON object")
    return value


def canonical_path(value: Any) -> str:
    return str(value or "").replace("\\", "/").lstrip("./")


def same_path(left: Any, right: Any) -> bool:
    a, b = canonical_path(left), canonical_path(right)
    return bool(a and b and (a == b or a.endswith("/" + b) or b.endswith("/" + a)))


def canonical_name(value: Any) -> str:
    return "".join(ch for ch in str(value or "").lower() if ch.isalnum())


def node_location(node: dict[str, Any]) -> tuple[str, int]:
    loc = node.get("location")
    if not isinstance(loc, dict) or not isinstance(loc.get("path"), str) or not isinstance(loc.get("line"), int):
        raise ValueError("agent inventory witness missing source path/line")
    return loc["path"], loc["line"]


def scope_report(report: dict[str, Any], cohort: dict[str, Any], label: str) -> dict[str, dict[str, Any]]:
    if report.get("study") != "real-world-agent-security-2026":
        raise ValueError(f"{label}: unexpected study")
    if label == "baseline" and report.get("scanner_sha") != EXPECTED_SOURCE_SHA:
        raise ValueError("historical baseline scanner SHA changed")
    if label == "candidate" and report.get("scanner_sha") != EXPECTED_CANDIDATE_SHA:
        raise ValueError("candidate is not pinned to already verified same-head source audit")
    if report.get("execution_mode") != "postfix" or report.get("cohort_cases") != 145:
        raise ValueError(f"{label}: same postfix scanner invocation and 145 cases required")
    cases = report.get("cases")
    if not isinstance(cases, list) or len(cases) != 145:
        raise ValueError(f"{label}: incomplete pinned source cohort")
    original = {x["case_id"]: x for x in cohort["cases"]}
    expected = {key for key, x in original.items() if x.get("framework_stratum") != "langgraph"}
    if len(original) != 180 or len(expected) != 145:
        raise ValueError("original source scope drift")
    observed = {}
    for case in cases:
        cid = case["case_id"]
        ref = original.get(cid)
        if cid not in expected or cid in observed or case.get("repo") != ref["repo"] or case.get("framework") != ref["framework_stratum"]:
            raise ValueError(f"{label}: duplicate, excluded, or identity/source mismatch: {cid}")
        if case.get("sha") is not None and case["sha"] != ref["sha"]:
            raise ValueError(f"{label}: source revision mismatch: {cid}")
        observed[cid] = case
    if set(observed) != expected:
        raise ValueError(f"{label}: missing source case")
    return observed


def strict_source_matches(
    truth: list[dict[str, Any]], agents: list[dict[str, Any]],
) -> set[int]:
    """One-to-one, source-scoped matches, unlike historical global name matching."""
    paired = set()
    for expected in truth:
        path = expected.get("path")
        line = expected.get("line")
        names = {canonical_name(x) for x in (expected.get("name"), expected.get("variable"), *(expected.get("aliases") or [])) if x}
        candidates = []
        for i, node in enumerate(agents):
            if i in paired:
                continue
            np, nl = node_location(node)
            if same_path(path, np):
                alias = canonical_name(node.get("name")) in names
                near = isinstance(line, int) and abs(nl - line) <= 6
                if alias or near:
                    # Prefer nearest source site to an alias with wrong location.
                    candidates.append((0 if near else 1, abs(nl-line) if isinstance(line, int) else 999999, i))
        if candidates:
            paired.add(min(candidates)[2])
    return paired


def classify(
    result: dict[str, Any],
    truth: dict[str, Any],
    overlay: list[dict[str, Any]],
    bridges: list[dict[str, Any]],
) -> dict[str, Any]:
    a = (result.get("comparisons") or {}).get("agent_entities")
    if not isinstance(a, dict):
        raise ValueError("success case lacks source-locked agent comparator")
    nodes = result.get("agent_node_audit")
    if not isinstance(nodes, list) or len(nodes) != a.get("predicted"):
        raise ValueError("both scanner revisions must emit complete agent_node_audit")
    agent_nodes = [n for n in nodes if n.get("kind") == "agent"]
    metadata_excluded = 0
    agents = []
    for node in agent_nodes:
        np, nl = node_location(node)
        if any(dec["decision"] == "metadata_only" and dec["observed"]["name"] == node.get("name") and same_path(dec["observed"]["path"],np) and dec["observed"]["line"] == nl for dec in bridges):
            metadata_excluded += 1
        else:
            agents.append(node)
    workflow_nodes = [n for n in nodes if n.get("kind") == "workflow_node"]
    if len(agents)+metadata_excluded+len(workflow_nodes) != len(nodes):
        raise ValueError("unexpected Graph node kind in agent precision")
    for n in agents:
        node_location(n)
    truth_agents = (truth.get("tier_a") or {}).get("agent_roots") or []
    matched = strict_source_matches(truth_agents, agents)
    used_overlay: set[int] = set()
    supported_overlay = disputed_overlay = supported_crossfile = 0
    for i, n in enumerate(agents):
        if i in matched:
            continue
        np, nl = node_location(n)
        matches = []
        for j, item in enumerate(overlay):
            if j in used_overlay:
                continue
            if item["node_kind"] != "agent" or not same_path(item["source_path"],np):
                continue
            if canonical_name(item["node_name"]) == canonical_name(n.get("name")) and item["source_line"] == nl:
                matches.append(j)
        if len(matches) > 1:
            raise ValueError("duplicate posthoc source identity for one Graph agent")
        if matches:
            ix = matches[0]
            used_overlay.add(ix)
            cls = overlay[ix]["classification"]
            if cls == "source_supported_agent":
                supported_overlay += 1
            elif cls == "taxonomy_unresolved":
                disputed_overlay += 1
            else:
                raise ValueError("workflow-step label attached to agent")
    # Original source reference selected instantiation in cli.py/app.py;
    # modern scanner instead anchors the identical class implementation in
    # agent.py. Treat those separately reviewed import/instance bridges as
    # one source-supported agent, not a new false-positive entity.
    for i, node in enumerate(agents):
        if i in matched:
            continue
        np, nl = node_location(node)
        for dec in bridges:
            if dec["decision"] != "implementation_instance_bridge":
                continue
            observed = dec["observed"]
            if observed["name"] == node.get("name") and same_path(observed["path"], np) and observed["line"] == nl:
                if any(
                    same_path(ref.get("path"), dec["locked_truth"]["path"])
                    and ref.get("line") == dec["locked_truth"]["line"]
                    and canonical_name(ref.get("name")) == canonical_name(dec["locked_truth"]["name"])
                    for ref in truth_agents
                ):
                    supported_crossfile += 1
                else:
                    raise ValueError("cross-file bridge lacks expected pinned source truth")
    unresolved = len(agents)-len(matched)-supported_overlay-disputed_overlay-supported_crossfile
    if unresolved < 0:
        raise ValueError("negative unknown source candidates")
    return {
        "agents": len(agents), "workflow_nodes_excluded": len(workflow_nodes),
        "metadata_only_nodes_excluded": metadata_excluded,
        "matched_locked_source": len(matched), "matched_posthoc_source": supported_overlay,
        "matched_crossfile_implementation": supported_crossfile,
        "taxonomy_unresolved": disputed_overlay, "unadjudicated": unresolved,
        "locked_truth_agents": len(truth_agents),
        "locked_truth_matches": len(matched),
        "locked_truth_misses": len(truth_agents)-len(matched),
    }


def compare(baseline: dict[str, Any], candidate: dict[str, Any],
            cohort: dict[str, Any], overlay: dict[str, Any],
            bridges: dict[str, Any], truth_root: Path) -> dict[str, Any]:
    if cohort.get("cohort_frozen") is not True or cohort.get("ground_truth_locked") is not True:
        raise ValueError("source lock removed")
    if overlay.get("reference_type") != "posthoc_source_adjudication_overlay" or overlay.get("scope") != "non-langgraph-145":
        raise ValueError("unsupported adjudication source provenance")
    if (bridges.get("type") != "posthoc_source_verified_identity_bridge_v1"
            or bridges.get("scope") != "non-langgraph-145"
            or bridges.get("original_locked_truth_preserved") is not True):
        raise ValueError("invalid cross-file source review provenance")
    source_index = {item["case_id"]: item for item in cohort["cases"]}
    bridged_cases: dict[str, list[dict[str, Any]]] = {}
    for decision in bridges.get("decisions", []):
        src = source_index.get(decision["case_id"])
        if src is None or src["repo"] != decision.get("repo") or src["sha"] != decision.get("sha"):
            raise ValueError("cross-file reviewed identity source SHA mismatch")
        if decision.get("decision") not in {"metadata_only", "implementation_instance_bridge"} or not decision.get("source_basis"):
            raise ValueError("cross-file decision lacks source basis")
        bridged_cases.setdefault(decision["case_id"], []).append(decision)
    if len(bridges.get("decisions", [])) != 3:
        raise ValueError("missing exact source-verified cross-file cases")
    b = scope_report(baseline, cohort, "baseline")
    c = scope_report(candidate, cohort, "candidate")
    overlay_cases = {}
    for item in overlay.get("classifications", []):
        cid = item["case_id"]
        source = source_index.get(cid)
        if source is None or source.get("repo") != item.get("repository") or source.get("sha") != item.get("source_sha"):
            raise ValueError("review source pin no longer matches cohort")
        overlay_cases.setdefault(cid, []).append(item)
    if len(overlay["classifications"]) != 31:
        raise ValueError("unreviewed candidate outlier or changed overlay count")
    common = sorted(cid for cid in b if b[cid].get("status")=="success" and c[cid].get("status")=="success")
    if not common:
        raise ValueError("no paired successful samples")
    output = []
    totals = {label: Counter() for label in ("baseline", "candidate")}
    for cid in common:
        source = source_index[cid]
        truth = read(truth_root / source["ground_truth"])
        if truth["source_reference"]["sha"] != source["sha"] or truth["source_reference"]["repo"] != source["repo"]:
            raise ValueError(f"{cid}: evidence source SHA does not match frozen cohort")
        complete = bool((truth.get("tier_a") or {}).get("reference_completeness",{}).get("agent_entities"))
        rec = {"case_id": cid, "repo": source["repo"], "precision_eligible": complete}
        for label, report in (("baseline", b[cid]), ("candidate", c[cid])):
            scored = classify(report, truth, overlay_cases.get(cid,[]),bridged_cases.get(cid,[]))
            rec[label] = scored
            if complete:
                totals[label].update(scored)
        output.append(rec)

    # Source-backed candidates are post-hoc, not blinded. All unknown agents
    # stay explicit, and all percentages are conditional support bounds.
    metrics = {}
    for label, values in totals.items():
        validated = (values["matched_locked_source"] + values["matched_posthoc_source"]
                     + values["matched_crossfile_implementation"])
        unknown = values["taxonomy_unresolved"] + values["unadjudicated"]
        total = values["agents"]
        if validated + unknown != total:
            raise ValueError(f"{label}: classified agent total does not reconcile")
        metrics[label] = {
            **dict(values),
            "supported_if_original_matches_valid": validated,
            "unresolved_total": unknown,
            "conditional_lower_if_all_unresolved_invalid": round(validated/total,4) if total else None,
            "conditional_upper_if_all_unresolved_valid": 1.0 if total else None,
            "certified_precision": False,
        }
    return {
        "study": "same-case-same-ontology-agent-precision-v1",
        "scope": "non-langgraph-145", "locked_source_preserved": True,
        "original_reference": "two automated non-blinded source passes",
        "posthoc_review": "source-inspected after observing scanner predictions; not independent holdout",
        "baseline_sha": baseline["scanner_sha"], "candidate_sha": candidate["scanner_sha"],
        "both_invocations_postfix": True, "common_success_cases": len(common),
        "baseline_success": sum(v.get("status")=="success" for v in b.values()),
        "candidate_success": sum(v.get("status")=="success" for v in c.values()),
        "precision_eligible_common_cases": sum(row["precision_eligible"] for row in output),
        "metrics": metrics, "cases": output,
        "release_gate": "NOT_EVALUATED: source labels incomplete and overlay posthoc",
        "limitations": [
            "Unadjudicated predictions, including disputed custom clients, are not certified false positives.",
            "This same-cohort sensitivity report does not prove runtime existence or generalisable precision.",
            "Full release precision requires new independent, source-blinded and negative-labelled claims.",
        ],
    }


def markdown(result: dict[str, Any]) -> str:
    lines = [
        "# Wave B same-case same-ontology agent precision",
        "", f"- Baseline scanner: {result['baseline_sha']}",
        f"- Candidate scanner: {result['candidate_sha']}",
        f"- Both successful: {result['common_success_cases']}/145",
        f"- Source-complete common cases: {result['precision_eligible_common_cases']}",
        "- Both scanner invocations: postfix",
        "",
        "| Metric | Historical scanner | Current scanner |",
        "|---|---:|---:|",
    ]
    for label, key in (("Strict Graph agent-kind nodes","agents"),
                       ("Excluded configuration metadata pretending to be agents","metadata_only_nodes_excluded"),
                       ("Excluded workflow-node-kind records","workflow_nodes_excluded"),
                       ("Matched original source agents","matched_locked_source"),
                       ("Post-hoc source-supported agents","matched_posthoc_source"),
                       ("Verified imported implementation-to-instance bridges","matched_crossfile_implementation"),
                       ("Unresolved client taxonomy","taxonomy_unresolved"),
                       ("Other unadjudicated predictions","unadjudicated"),
                       ("Conditional lower support ratio","conditional_lower_if_all_unresolved_invalid")):
        values=[result["metrics"][name].get(key) for name in ("baseline","candidate")]
        lines.append(f"| {label} | {values[0]} | {values[1]} |")
    lines += [
        "", "**No corrected release precision claimed.** This explicitly distinguishes source-backed candidate coverage from unadjudicated candidates. The overlay is post-hoc and some frozen labels are incomplete. Production accuracy still needs source-independent adjudication.", "",
    ]
    return "\n".join(lines)


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("baseline","candidate","cohort","overlay","crossfile-review","truth-root","output-json","output-markdown"):
        p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args()
    result=compare(read(a.baseline),read(a.candidate),read(a.cohort),read(a.overlay),read(a.crossfile_review),a.truth_root)
    a.output_json.parent.mkdir(parents=True,exist_ok=True)
    a.output_json.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    a.output_markdown.write_text(markdown(result),encoding="utf-8")
    print(markdown(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
