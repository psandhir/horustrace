"""Create *provisional* reviewer-vs-scanner alignment, never self-adjudicated FP/FN.

This is Phase B only. It refuses to open scanner artifacts unless two independent
source-blind model outputs are validated and locked with the SAME prompt and
source hashes. Outputs candidate matches and all unmatched records for manual
source-grounded adjudication. It does NOT publish precision or recall.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from scripts.frozen180_llm_review import validate_review

RULE_HINTS = {
    "approval_gap": {"AGT020", "AGT021", "AGT022", "AGT040", "ADK001", "CAP006"},
    "privileged_execution": {"AGT020", "ADK002", "ADK003", "ADK004", "PATH001"},
    "destructive_write": {"AGT021", "PATH002"},
    "state_changing_tool": {"AGT022", "AGT040"},
    "computer_control": {"AGT023", "ADK005"},
    "unsafe_mcp": {"AGT030", "AGT031", "AGT032", "AGT052", "AGT053", "AGT054"},
    "mcp_authentication": {"AGT030"},
    "mcp_transport": {"AGT031", "ADK009"},
    "mcp_allowlist": {"AGT032", "AGT052"},
    "mcp_privileged_surface": {"AGT053", "AGT054"},
    "credential_exposure": {"AGT051", "IDN004"},
    "policy_violation": {"CAP001", "CAP002", "CAP006", "DATA002", "NET003"},
    "authority_excess": {"CAP003", "CAP004", "CAP005", "IDN001", "IDN002", "IDN003"},
    "network_egress": {"NET001", "NET002", "NET003"},
    "model_selected_url": {"NET004", "PATH011"},
    "filesystem_escape": {"PATH010", "PATH012", "PATH013"},
    "cross_owner_mutation": {"DATA004", "PATH014"},
    "sensitive_data_exposure": {"AGT010", "DATA001", "DATA003", "PATH003", "PATH005"},
    "sensitive_data_to_external": {"DATA003", "PATH003", "PATH005", "PATH010"},
    "untrusted_input_to_execution": {"PATH001", "PATH004"},
    "prompt_injection": {"PATH004", "PATH006", "SKL025"},
    "skill_instruction_abuse": {"SKL020", "SKL021", "SKL022", "SKL023", "SKL024", "SKL025",
                                "SKL026", "SKL027", "SKL028", "SKL029", "SKL030"},
    "memory_poisoning": {"PATH007", "SKL026"},
    "unsafe_delegation": {"PATH008", "PATH009"},
    "delegation_control_bypass": {"ADK008", "PATH008"},
    "unsafe_remote_agent": {"ADK009", "ADK010", "ADK011"},
    "persistence_or_stealth": {"SKL026", "SKL027"},
    "execution_and_egress": {"CAP004", "PATH004"},
}
PATH_HINTS = {
    "code_execute": {"PATH001", "PATH004"},
    "process_execute": {"PATH001", "PATH004"},
    "destructive_write": {"PATH002"},
    "state_mutation": {"PATH002", "PATH014", "PATH015"},
    "filesystem_read": {"PATH010", "PATH012", "PATH013"},
    "filesystem_write": {"PATH012", "PATH013"},
    "network_egress": {"PATH003", "PATH005", "PATH009", "PATH010", "PATH015"},
    "server_side_fetch": {"PATH011"},
    "credential_read": {"PATH005"},
    "memory_persistence": {"PATH007"},
    "cross_owner_write": {"PATH014"},
}


def _same_source(a: str, b: str) -> bool:
    a = str(a or "").replace("\\", "/").lstrip("./")
    b = str(b or "").replace("\\", "/").lstrip("./")
    return bool(a and b and (a == b or a.endswith("/" + b) or b.endswith("/" + a)))


def _entity_names(review: dict) -> dict[str, str]:
    return {e["id"]: e["name"] for e in review["entities"]}


def _scanner_source_path(row: dict) -> str:
    return str(row.get("source_path") or
               (row.get("path") or {}).get("location", {}).get("path") or "")


def _candidate_matches(item: dict, scanner_rows: list[dict], *,
                       path_mode: bool, names: dict[str, str]) -> list[dict]:
    hints = PATH_HINTS.get(item.get("sink_kind"), set()) if path_mode else (
        RULE_HINTS.get(item.get("issue_type"), set())
    )
    cited = item["evidence"]
    agent = names.get(item.get("agent_id"), "").casefold()
    matches: list[dict] = []
    for row in scanner_rows:
        scanner_path = row["path"] if path_mode else row
        scanner_rule = scanner_path.get("path_id") if path_mode else row.get("rule")
        direct_paths = [
            _scanner_source_path(row),
        ]
        if path_mode:
            direct_paths.extend(
                str(step.get("path") or "") for step in
                scanner_path.get("metadata", {}).get("source_locations", [])
                if isinstance(step, dict)
            )
        path_match = any(_same_source(e["path"], p) for e in cited for p in direct_paths)
        ref_line = (
            ((scanner_path.get("location") or {}).get("line"))
            if path_mode else row.get("line")
        )
        anchor_match = bool(path_match and isinstance(ref_line, int) and any(
            e["line_start"] - 8 <= ref_line <= e["line_end"] + 8
            for e in cited))
        rule_match = bool(scanner_rule in hints)
        scanner_agent = str(scanner_path.get("agent") or "").casefold() if path_mode else ""
        agent_match = bool(agent and scanner_agent and agent == scanner_agent)
        # Evidence matching is most important; rule family is advisory and
        # cannot establish correctness or an actual semantic path match alone.
        if not (path_match or (path_mode and rule_match and agent_match)):
            continue
        signals = {
            "same_source_file": path_match,
            "nearby_line": anchor_match,
            "rule_family_compatible": rule_match,
            "agent_name_compatible": agent_match,
        }
        matches.append({
            "scanner_index": row["index"] if path_mode else row["scanner_finding_index"],
            "scanner_rule_or_path_id": scanner_rule,
            "signals": signals,
            "matching_status": "unresolved_pending_adjudication",
        })
    return sorted(matches, key=lambda r: (
        -int(r["signals"]["nearby_line"]),
        -int(r["signals"]["same_source_file"]),
        -int(r["signals"]["rule_family_compatible"]),
        r["scanner_index"],
    ))[:8]


def compare_case(review_a: dict, review_b: dict,
                 findings: list[dict], paths: list[dict]) -> dict:
    entries = []
    for review, judge in ((review_a, "a"), (review_b, "b")):
        names = _entity_names(review)
        for kind, pool, is_path in (
            ("finding", findings, False), ("attack_path", paths, True),
        ):
            for candidate in review["attack_paths" if is_path else "findings"]:
                entries.append({
                    "reviewer": judge,
                    "candidate_type": kind,
                    "candidate_id": candidate["id"],
                    "source_support_claim": candidate["support_status"],
                    "source_anchors": candidate["evidence"],
                    "provisional_scanner_matches": _candidate_matches(
                        candidate, pool, path_mode=is_path, names=names),
                    "source_adjudication": "pending_independent_resolution",
                    "scanner_match_adjudication": "pending_manual_reveal_review",
                })
    return {
        "case_id": review_a["case_id"],
        "candidates": entries,
        "scanner_paths": [{
            "index": r["index"], "scanner_path_id": r["path"]["path_id"],
            "verdict": "unreviewed", "reviewer_evidence": [],
        } for r in paths],
        "scanner_findings": [{
            "index": r["scanner_finding_index"], "rule_id": r["rule"],
            "verdict": "unreviewed", "reviewer_evidence": [],
        } for r in findings],
        "candidate_deduplication": "not_performed",
        "attack_path_false_negatives": None,
        "attack_path_false_positives": None,
        "finding_false_negatives": None,
        "finding_false_positives": None,
    }


def _load_review_and_attestation(review_root: Path, judge: str, case_id: str,
                                 source_root: Path, schema: dict) -> tuple[dict, dict]:
    folder = review_root / judge
    data_path = folder / f"{case_id}.json"
    env_path = folder / f"{case_id}.reviewer.json"
    data = json.loads(data_path.read_text())
    env = json.loads(env_path.read_text())
    source_dir = source_root / case_id
    manifest = json.loads((source_dir / "source-manifest.json").read_text())
    source = (source_dir / "source-only.txt").read_text()
    validate_review(data, manifest, source, schema)
    expected = hashlib.sha256((json.dumps(
        data, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode()).hexdigest()
    if (env["review_sha256"] != expected or
            env["case_id"] != case_id or
            env["source_revision"] != data["sha"] or
            env["source_pack_sha256"] != manifest["source_pack_sha256"] or
            env["scanner_output_seen"] is not False or
            env["independent_review"] is not True or
            env["locked"] is not True):
        raise ValueError(f"{judge}/{case_id}: invalid blind review attestation")
    return data, env


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--source-root", type=Path, required=True)
    p.add_argument("--review-root", type=Path, required=True)
    p.add_argument("--scanner-findings", type=Path, required=True)
    p.add_argument("--scanner-paths", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--case-id", action="append", required=True)
    p.add_argument("--schema", type=Path, default=Path(
        "research/frozen180-llm-differential-20261008/source-review.schema.json"))
    args = p.parse_args()
    schema = json.loads(args.schema.read_text())
    all_findings = json.loads(args.scanner_findings.read_text())
    all_paths = json.loads(args.scanner_paths.read_text())
    if len(all_findings["rows"]) != 267 or len(all_paths) != 45:
        raise SystemExit("expected untouched frozen 180 scanner evidence: 267 findings/45 paths")
    f_by_case = defaultdict(list)
    p_by_case = defaultdict(list)
    for row in all_findings["rows"]:
        f_by_case[row["case_id"]].append(row)
    for row in all_paths:
        p_by_case[row["case_id"]].append(row)
    report = []
    for case in sorted(set(args.case_id)):
        a, aa = _load_review_and_attestation(args.review_root, "source-judge-a",
                                              case, args.source_root, schema)
        b, bb = _load_review_and_attestation(args.review_root, "source-judge-b",
                                              case, args.source_root, schema)
        if (aa["execution_id"] == bb["execution_id"] or
                aa["provider"] == bb["provider"] or
                aa["prompt_sha256"] != bb["prompt_sha256"] or
                aa["source_pack_sha256"] != bb["source_pack_sha256"]):
            raise SystemExit(f"{case}: independence/prompt/source mismatch")
        report.append(compare_case(a, b, f_by_case[case], p_by_case[case]))
    result = {
        "study": "frozen180-llm-source-review-20261008",
        "phase": "phase_b_provisional_alignment_not_adjudication",
        "quality_release": "blocked",
        "all_scanner_paths_reviewed": False,
        "all_high_critical_findings_reviewed": False,
        "independent_consensus_locked": False,
        "accuracy_metrics": None,
        "cases": report,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(f"Produced provisional side-by-side alignment for {len(report)} cases; no TP/FP/FN claims")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
