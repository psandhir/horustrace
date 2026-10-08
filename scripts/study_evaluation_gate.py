#!/usr/bin/env python3
"""Fail-closed evidence gates for independent HorusScan source-cohort studies.

The gate validates *bookkeeping and provenance*, not the semantic correctness of a
judge. Source-backed truth still requires independent adjudication. No API calls.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path, PurePosixPath

SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
VERDICTS = {"valid", "invalid", "unresolved"}
OUTCOMES = {"matched", "partial", "missed", "invalid", "unresolved"}
FINDING_VERDICTS = {"supported", "partial", "unsupported", "unresolved"}


class GateError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GateError(message)


def load(path: Path) -> dict:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise GateError(f"{path}: invalid/unavailable JSON: {exc}") from exc
    require(isinstance(obj, dict), f"{path}: expected JSON object")
    return obj


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def timestamp(value: object, label: str) -> datetime:
    require(isinstance(value, str), f"{label}: ISO timestamp required")
    try:
        t = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GateError(f"{label}: invalid timestamp") from exc
    require(t.tzinfo is not None, f"{label}: timestamp must have timezone")
    return t


def safe_path(value: object, label: str) -> bool:
    require(isinstance(value, str) and bool(value), f"{label}: nonempty path required")
    p = PurePosixPath(value)
    require(not p.is_absolute() and ".." not in p.parts, f"{label}: unsafe path")
    return True


def unique_rows(rows: object, key: str, label: str) -> dict[str, dict]:
    require(isinstance(rows, list), f"{label}: list required")
    out: dict[str, dict] = {}
    for row in rows:
        require(isinstance(row, dict), f"{label}: invalid row")
        ident = row.get(key)
        require(isinstance(ident, str) and bool(ident), f"{label}: missing {key}")
        require(ident not in out, f"{label}: duplicate {key}={ident}")
        out[ident] = row
    return out


def validate_cohort(doc: dict) -> dict[str, dict]:
    require(doc.get("schema_version") == 1, "cohort: expected schema_version=1")
    require(isinstance(doc.get("study"), str) and doc["study"], "cohort: study required")
    require(doc.get("locked_at"), "cohort: locked_at required")
    selection = doc.get("selection") or {}
    require(isinstance(selection, dict), "cohort: selection object required")
    require(isinstance(selection.get("method"), str) and bool(selection["method"]),
            "cohort: source-independent selection method required")
    require(selection.get("current_main_output_used_for_selection") is False,
            "cohort: selection must be independent of current scanner output")
    cases = unique_rows(doc.get("cases"), "case_id", "cohort.cases")
    require(len(cases) > 0, "cohort: no cases")
    require(selection.get("target_repositories") == len(cases),
            "cohort: target_repositories must equal frozen case count")
    repos = set()
    for case_id, case in cases.items():
        repo = case.get("repo")
        require(isinstance(repo, str) and re.fullmatch(r"[^/\s]+/[^/\s]+", repo) is not None,
                f"{case_id}: invalid repository")
        require(repo not in repos, f"{case_id}: reused repository {repo}")
        repos.add(repo)
        require(isinstance(case.get("sha"), str) and SHA40.fullmatch(case["sha"]) is not None,
                f"{case_id}: invalid commit SHA")
        require(isinstance(case.get("framework"), str) and bool(case["framework"]),
                f"{case_id}: missing framework")
        safe_path(case.get("application_path"), f"{case_id}.application_path")
    return cases


def read_results(root: Path, cohort: dict, cases: dict[str, dict]) -> tuple[dict, list[str]]:
    require(root.is_dir(), f"results: missing directory {root}")
    errors = list(root.rglob("error.json"))
    require(not errors, f"results: {len(errors)} case error(s) present")
    result_files = list(root.rglob("result.json"))
    require(len(result_files) == len(cases),
            f"results: expected {len(cases)} result.json, found {len(result_files)}")
    results = {}
    warnings = []
    revisions = {"scanner_sha": set(), "harness_sha": set()}
    for path in result_files:
        item = load(path)
        case_id = item.get("case_id")
        require(case_id in cases and case_id not in results,
                f"results: unknown/duplicate case {case_id}")
        case = cases[case_id]
        for field in ("study", "repo", "sha", "framework", "application_path"):
            expected = cohort["study"] if field == "study" else case[field]
            require(item.get(field) == expected,
                    f"{case_id}: {field} mismatch between result and frozen cohort")
        counts = item.get("counts")
        require(isinstance(counts, dict), f"{case_id}: counts missing")
        for field in ("findings", "attack_paths", "agents", "diagnostics"):
            require(isinstance(counts.get(field), int) and counts[field] >= 0,
                    f"{case_id}: missing/noninteger count {field}")
        for kind, count in (("findings", "findings"), ("attack_paths", "attack_paths")):
            require(isinstance(item.get(kind), list) and len(item[kind]) == counts[count],
                    f"{case_id}: {kind} count does not match evidence")
        for revision in revisions:
            value = item.get(revision)
            require(isinstance(value, str) and SHA40.fullmatch(value) is not None,
                    f"{case_id}: missing full {revision}")
            revisions[revision].add(value)
        source_file = path.with_name("source-pack.txt")
        require(source_file.is_file(), f"{case_id}: missing source pack")
        source_chars = len(source_file.read_text(encoding="utf-8"))
        require(source_chars > 0 and source_chars == item.get("source_pack_chars"),
                f"{case_id}: source pack is empty or inconsistent")
        if source_chars >= 230000 or "...[truncated]..." in source_file.read_text(encoding="utf-8"):
            warnings.append(f"{case_id}: source pack may be incomplete; review must qualify scope")
        for filename, field in (("scan.json", "findings"),
                                ("security-graph.json", "attack_paths")):
            doc_path = path.with_name(filename)
            require(doc_path.is_file(), f"{case_id}: missing {filename}")
            doc = load(doc_path)
            require(isinstance(doc.get(field), list)
                    and len(doc[field]) == len(item[field]),
                    f"{case_id}: {filename} differs from reported {field}")
        for filename in ("effective-authority.json", "authority-contract.json"):
            doc_path = path.with_name(filename)
            require(doc_path.is_file(), f"{case_id}: missing {filename}")
            load(doc_path)
        results[case_id] = item
    for revision, values in revisions.items():
        require(len(values) == 1, f"results: inconsistent {revision} across cases")
    require(set(results) == set(cases), "results: case IDs do not match cohort")
    return results, warnings


def evidence(entries: object, label: str) -> None:
    require(isinstance(entries, list) and bool(entries), f"{label}: source evidence required")
    for entry in entries:
        require(isinstance(entry, dict), f"{label}: malformed evidence")
        safe_path(entry.get("path"), f"{label}.path")
        require(isinstance(entry.get("line"), int) and entry["line"] > 0,
                f"{label}: positive source line required")


def review_phase_a(doc: dict, cohort: dict, cases: dict[str, dict], cohort_sha: str) -> dict:
    require(doc.get("study") == cohort["study"], "phase A: wrong study")
    require(doc.get("cohort_sha256") == cohort_sha, "phase A: cohort digest mismatch")
    require(doc.get("scanner_output_seen") is False, "phase A: scanner-blind source review required")
    lock = timestamp(doc.get("locked_at"), "phase A lock")
    judges = unique_rows(doc.get("reviewers"), "reviewer_id", "phase A reviewers")
    require(len(judges) >= 2, "phase A: at least two independent reviewers required")
    for ident, judge in judges.items():
        for field in ("provider", "model", "execution_id", "prompt_version"):
            require(isinstance(judge.get(field), str) and bool(judge[field]),
                    f"phase A judge {ident}: {field} required")
        require(SHA256.fullmatch(str(judge.get("prompt_sha256") or "")) is not None,
                f"phase A judge {ident}: prompt SHA256 required")
        require(judge.get("independent_review") is True and judge.get("locked") is True
                and judge.get("scanner_output_seen") is False,
                f"phase A judge {ident}: must be locked and independently blinded")
        require(timestamp(judge.get("locked_at"), f"judge {ident} lock") <= lock,
                f"phase A judge {ident}: judge lock after packet lock")
    execution_ids = [j["execution_id"] for j in judges.values()]
    require(len(set(execution_ids)) == len(execution_ids),
            "phase A: reviewer execution IDs must be distinct")
    reviewed_cases = unique_rows(doc.get("cases"), "case_id", "phase A cases")
    require(set(reviewed_cases) == set(cases), "phase A: must review every frozen case")
    for case_id, row in reviewed_cases.items():
        require(row.get("sha") == cases[case_id]["sha"], f"{case_id}: review source SHA mismatch")
        require(row.get("source_coverage") in {"complete", "qualified", "insufficient"},
                f"{case_id}: explicit source coverage required")
        if row["source_coverage"] != "complete":
            require(bool(row.get("source_limitations")), f"{case_id}: source limitations required")
        reviews = unique_rows(row.get("reviews"), "reviewer_id", f"{case_id}.reviews")
        require(set(reviews) == set(judges), f"{case_id}: each judge must review this case")
        proposed_ids = set()
        for rid, review in reviews.items():
            require(review.get("locked") is True and review.get("scanner_output_seen") is False,
                    f"{case_id}: {rid} review not locked and blinded")
            evidence(review.get("source_evidence"), f"{case_id}.{rid}.source_evidence")
            require(isinstance(review.get("candidate_paths"), list),
                    f"{case_id}.{rid}: candidate_paths must be list (empty is valid)")
            require(review.get("coverage_assertion") in
                    {"enumerated_candidates", "reviewed_no_qualifying_chains"},
                    f"{case_id}.{rid}: explicit positive/negative coverage assertion required")
            if not review["candidate_paths"]:
                require(review["coverage_assertion"] == "reviewed_no_qualifying_chains",
                        f"{case_id}.{rid}: empty review needs a negative-control assertion")
            for path in review["candidate_paths"]:
                require(isinstance(path, dict) and bool(path.get("candidate_id")),
                        f"{case_id}.{rid}: path needs stable candidate_id")
                require(path.get("verdict") in VERDICTS,
                        f"{case_id}.{rid}: candidate reviewer verdict required")
                require(bool(path.get("rationale")),
                        f"{case_id}.{rid}: candidate rationale required")
                proposed_ids.add(path["candidate_id"])
                evidence(path.get("evidence"), f"{case_id}.{rid}.{path['candidate_id']}")
        consensus = unique_rows(row.get("consensus_paths"), "candidate_id",
                                f"{case_id}.consensus_paths")
        require(set(consensus) == proposed_ids,
                f"{case_id}: all judge candidates must be independently adjudicated")
        for pid, finding in consensus.items():
            require(finding.get("verdict") in VERDICTS,
                    f"{case_id}.{pid}: valid|invalid|unresolved verdict required")
            require(finding.get("review_status") in {"agreement", "escalated", "pending"},
                    f"{case_id}.{pid}: review status required")
            evidence(finding.get("evidence"), f"{case_id}.{pid}.consensus")
            require(bool(finding.get("rationale")), f"{case_id}.{pid}: rationale required")
            if finding["review_status"] == "agreement":
                opinions = [next((p["verdict"] for p in r["candidate_paths"]
                                 if p["candidate_id"] == pid), None)
                            for r in reviews.values()]
                require(all(v == finding["verdict"] for v in opinions),
                        f"{case_id}.{pid}: claimed agreement without both judge verdicts")
            if finding["review_status"] == "escalated":
                escalation = finding.get("escalation_review") or {}
                require(escalation.get("independent_review") is True and
                        escalation.get("scanner_output_seen") is False and
                        escalation.get("locked") is True and
                        escalation.get("verdict") == finding["verdict"] and
                        escalation.get("reviewer_id") not in judges and
                        bool(escalation.get("reviewer_id")),
                        f"{case_id}.{pid}: third independent escalation required")
                evidence(escalation.get("evidence"), f"{case_id}.{pid}.escalation")
    return reviewed_cases


def review_phase_b(doc: dict, cohort: dict, cases: dict, results: dict,
                   phase_a: dict, phase_a_sha: str, lock_time: str) -> dict:
    require(doc.get("study") == cohort["study"], "phase B: wrong study")
    require(doc.get("phase_a_sha256") == phase_a_sha,
            "phase B: phase A lock digest mismatch")
    require(doc.get("scanner_sha") and SHA40.fullmatch(str(doc["scanner_sha"])),
            "phase B: full scanner commit SHA required")
    require(timestamp(doc.get("revealed_at"), "phase B reveal") >
            timestamp(lock_time, "phase A lock"), "phase B: scanner revealed before phase A lock")
    require({item["scanner_sha"] for item in results.values()} == {doc["scanner_sha"]},
            "phase B: scanner SHA differs from executed cases")
    reviewed = unique_rows(doc.get("cases"), "case_id", "phase B cases")
    require(set(reviewed) == set(cases), "phase B: must cover every case")
    counts = Counter()
    by_framework: dict[str, Counter] = defaultdict(Counter)
    for case_id, row in reviewed.items():
        expected = phase_a[case_id]["consensus_paths"]
        consensus = unique_rows(expected, "candidate_id", f"{case_id}.A.consensus")
        matches = unique_rows(row.get("candidate_assessments"), "candidate_id",
                              f"{case_id}.B.candidates")
        require(set(matches) == set(consensus),
                f"{case_id}: every LLM candidate must be compared to scanner output")
        scanner_paths = results[case_id]["attack_paths"]
        for pid, comparison in matches.items():
            verdict = consensus[pid]["verdict"]
            state = comparison.get("outcome")
            require(state in OUTCOMES, f"{case_id}.{pid}: invalid comparison outcome")
            require(bool(comparison.get("rationale")),
                    f"{case_id}.{pid}: comparison rationale required")
            if verdict == "valid":
                require(state in {"matched", "partial", "missed"},
                        f"{case_id}.{pid}: valid chain must have coverage outcome")
            else:
                require(state == ("invalid" if verdict == "invalid" else "unresolved"),
                        f"{case_id}.{pid}: invalid/unresolved reviewer case misclassified")
            indices = comparison.get("scanner_path_indexes") or []
            require(isinstance(indices, list), f"{case_id}.{pid}: indexes must be list")
            for index in indices:
                require(isinstance(index, int) and 0 <= index < len(scanner_paths),
                        f"{case_id}.{pid}: scanner path index out of range")
            if state in {"matched", "partial"}:
                require(bool(indices), f"{case_id}.{pid}: claimed coverage without scanner path")
            if state == "missed":
                require(not indices, f"{case_id}.{pid}: missed path cannot have scanner match")
            counts[state] += 1
            by_framework[cases[case_id]["framework"]][state] += 1
        # Precision direction: every scanner-emitted attack path must be
        # independently reviewed, including paths absent from judge discovery.
        path_reviews = row.get("scanner_attack_path_reviews")
        require(isinstance(path_reviews, list),
                f"{case_id}: scanner_attack_path_reviews list required")
        reviewed_path_indexes = set()
        for path_review in path_reviews:
            require(isinstance(path_review, dict),
                    f"{case_id}: malformed scanner attack path review")
            index = path_review.get("index")
            require(isinstance(index, int) and 0 <= index < len(scanner_paths)
                    and index not in reviewed_path_indexes,
                    f"{case_id}: invalid/duplicate scanner attack path index {index}")
            require(path_review.get("verdict") in FINDING_VERDICTS,
                    f"{case_id}.scanner_path[{index}]: verdict required")
            require(bool(path_review.get("rationale")),
                    f"{case_id}.scanner_path[{index}]: rationale required")
            evidence(path_review.get("evidence"), f"{case_id}.scanner_path[{index}]")
            path_judges = unique_rows(path_review.get("reviewer_attestations"),
                                     "reviewer_id", f"{case_id}.scanner_path[{index}].judges")
            require(len(path_judges) >= 2,
                    f"{case_id}.scanner_path[{index}]: two independent reviewers required")
            path_execution_ids = []
            for judge_id, opinion in path_judges.items():
                require(opinion.get("independent_review") is True and
                        opinion.get("rule_metadata_seen") is False and
                        opinion.get("locked") is True and
                        opinion.get("verdict") == path_review["verdict"],
                        f"{case_id}.scanner_path[{index}]: reviewer verdict mismatch")
                require(bool(opinion.get("execution_id")) and
                        bool(opinion.get("model")) and bool(opinion.get("provider")),
                        f"{case_id}.scanner_path[{index}]: missing reviewer provenance")
                path_execution_ids.append(opinion["execution_id"])
                evidence(opinion.get("evidence"),
                         f"{case_id}.scanner_path[{index}].{judge_id}")
            require(len(set(path_execution_ids)) == len(path_execution_ids),
                    f"{case_id}.scanner_path[{index}]: duplicate reviewer execution IDs")
            reviewed_path_indexes.add(index)
            counts["scanner_paths_reviewed"] += 1
            counts["scanner_paths_" + path_review["verdict"]] += 1
        require(len(reviewed_path_indexes) == len(scanner_paths),
                f"{case_id}: every scanner-emitted attack path must be adjudicated")
        findings = results[case_id]["findings"]
        finding_reviews = row.get("finding_reviews")
        require(isinstance(finding_reviews, list),
                f"{case_id}: finding_reviews required (empty if scanner has no findings)")
        seen = {}
        strata = defaultdict(list)
        for index, finding in enumerate(findings):
            kind = (str(finding.get("rule_id") or "unknown"),
                    str(finding.get("severity") or "unknown").lower())
            strata[kind].append(index)
        for review in finding_reviews:
            require(isinstance(review, dict), f"{case_id}: malformed finding review")
            index = review.get("index")
            require(isinstance(index, int) and 0 <= index < len(findings)
                    and index not in seen, f"{case_id}: invalid/duplicate finding index {index}")
            require(review.get("verdict") in FINDING_VERDICTS,
                    f"{case_id}[{index}]: finding verdict required")
            require(bool(review.get("rationale")), f"{case_id}[{index}]: rationale required")
            evidence(review.get("evidence"), f"{case_id}[{index}].evidence")
            attestations = unique_rows(review.get("reviewer_attestations"),
                                       "reviewer_id", f"{case_id}[{index}].reviewers")
            require(len(attestations) >= 2,
                    f"{case_id}[{index}]: two blinded independent finding judges required")
            run_ids = []
            for judge_id, attestation in attestations.items():
                require(attestation.get("independent_review") is True and
                        attestation.get("rule_metadata_seen") is False and
                        attestation.get("locked") is True and
                        attestation.get("verdict") == review["verdict"],
                        f"{case_id}[{index}]: independent blinded finding verdict mismatch")
                require(bool(attestation.get("execution_id")) and
                        bool(attestation.get("model")) and bool(attestation.get("provider")),
                        f"{case_id}[{index}]: missing reviewer provenance")
                run_ids.append(attestation["execution_id"])
                evidence(attestation.get("evidence"),
                         f"{case_id}[{index}].{judge_id}.evidence")
            require(len(set(run_ids)) == len(run_ids),
                    f"{case_id}[{index}]: duplicate finding execution IDs")
            seen[index] = review
            counts["findings_reviewed"] += 1
            counts["findings_" + review["verdict"]] += 1
            if review["verdict"] == "unsupported":
                counts["unsupported_findings"] += 1
        for (rule, severity), indices in strata.items():
            required = (len(indices) if severity in {"critical", "high"}
                        else max(1, math.ceil(len(indices) * 0.25)))
            actual = len(set(indices) & set(seen))
            require(actual >= required,
                    f"{case_id}: insufficient finding sample for {rule}/{severity}: "
                    f"{actual} < {required}")
        if phase_a[case_id]["source_coverage"] == "insufficient":
            counts["insufficient_source_cases"] += 1
        if any(p["review_status"] == "pending"
               for p in phase_a[case_id]["consensus_paths"]):
            counts["pending_escalations"] += 1
    return {
        "counts": dict(sorted(counts.items())),
        "by_framework": {k: dict(sorted(v.items())) for k, v in sorted(by_framework.items())},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cohort", type=Path, required=True)
    parser.add_argument("--results", type=Path, help="Directory with per-case result.json and source-pack.txt")
    parser.add_argument("--phase-a", type=Path, help="Locked scanner-blind reviewer JSON")
    parser.add_argument("--phase-b", type=Path, help="Scanner-revealed alignment and precision review JSON")
    parser.add_argument("--output", type=Path, help="Evidence gate report JSON")
    args = parser.parse_args()
    cohort = load(args.cohort)
    cases = validate_cohort(cohort)
    report: dict = {
        "schema_version": 1, "study": cohort["study"], "cohort_sha256": digest(args.cohort),
        "case_count": len(cases), "selection_gate": "passed", "execution_gate": "not_run",
        "adjudication_gate": "not_run", "release_gate": "blocked", "warnings": [],
    }
    if args.results is not None:
        results, warnings = read_results(args.results, cohort, cases)
        report["execution_gate"] = "passed"
        report["warnings"].extend(warnings)
        report["scanner_paths"] = sum(len(x["attack_paths"]) for x in results.values())
        report["scanner_findings"] = sum(len(x["findings"]) for x in results.values())
        if args.phase_a and args.phase_b:
            phase_a = load(args.phase_a)
            phase_a_cases = review_phase_a(phase_a, cohort, cases, digest(args.cohort))
            truncated_case_ids = {
                warning.split(":", 1)[0] for warning in warnings
            }
            for case_id in truncated_case_ids:
                review = phase_a_cases[case_id]
                if review["source_coverage"] == "complete":
                    require(review.get("supplementary_source_checked") is True,
                            f"{case_id}: claimed complete review of truncated source pack "
                            "without supplementary source inspection")
                    evidence(review.get("supplementary_source_evidence"),
                             f"{case_id}.supplementary_source_evidence")
            outcome = review_phase_b(load(args.phase_b), cohort, cases, results,
                                     phase_a_cases, digest(args.phase_a), phase_a["locked_at"])
            report["adjudication_gate"] = "passed"
            report.update(outcome)
            counts = outcome["counts"]
            blockers = {
                "confirmed_candidate_misses": counts.get("missed", 0),
                "partial_valid_path_coverage": counts.get("partial", 0),
                "unsupported_scanner_paths": counts.get("scanner_paths_unsupported", 0),
                "partial_scanner_paths": counts.get("scanner_paths_partial", 0),
                "unresolved_scanner_paths": counts.get("scanner_paths_unresolved", 0),
                "unsupported_sampled_findings": counts.get("findings_unsupported", 0),
                "partial_sampled_findings": counts.get("findings_partial", 0),
                "unresolved_sampled_findings": counts.get("findings_unresolved", 0),
                "pending_escalations": counts.get("pending_escalations", 0),
                "insufficient_source_cases": counts.get("insufficient_source_cases", 0),
            }
            report["blocking_reasons"] = blockers
            report["release_gate"] = (
                "passed" if not any(blockers.values()) else "blocked"
            )
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    if args.results and report["release_gate"] != "passed":
        return 2
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (GateError, OSError) as exc:
        print(f"STUDY_GATE_FAILED: {exc}", file=sys.stderr)
        sys.exit(2)
