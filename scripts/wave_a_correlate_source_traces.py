"""Correlate reviewed source-assertion anchors with passive graph observations.

A file/line correlation is not a detection proof. This intentionally cannot
label TP, FP or FN; absence of a trace event is a source-review candidate.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path, PurePosixPath

from scripts.verify_accuracy_wave_a_assertions import DIRECTORY, audit_assertions
from scripts.verify_accuracy_wave_a_baseline import BaselineError


def _scan_relative_path(original: str, application_path: str) -> str:
    root = PurePosixPath(application_path)
    path = PurePosixPath(original)
    if application_path in {".", ""}:
        return path.as_posix()
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def correlate(inputs: Path, *, root: Path = DIRECTORY) -> dict:
    validated = audit_assertions(
        ledger_path=root / "source-assertions.json",
        cohort_path=root / "cohort.json",
    )
    cohort = json.loads((root / "cohort.json").read_text(encoding="utf-8"))
    rows = json.loads((root / "source-assertions.json").read_text(encoding="utf-8"))["assertions"]
    cases = {c["case_id"]: c for c in cohort["cases"]}
    scans = {}
    for path in sorted(inputs.rglob("result.json")):
        result = json.loads(path.read_text(encoding="utf-8"))
        case_id = result.get("case_id")
        if case_id not in cases or case_id in scans:
            raise BaselineError(f"unknown or duplicate trace result case {case_id}")
        if any(result.get(field) != cases[case_id].get(field) for field in
               ("repo", "sha", "framework", "application_path")):
            raise BaselineError(f"{case_id}: frozen identity mismatch")
        trace_file = path.with_name("trace.json")
        trace = json.loads(trace_file.read_text(encoding="utf-8"))
        if trace.get("events_truncated") or len(trace.get("stages", [])) != 11:
            raise BaselineError(f"{case_id}: partial trace is not admissible")
        scans[case_id] = trace
    missing = set(cases) - set(scans)
    if missing:
        raise BaselineError("missing case traces: " + ", ".join(sorted(missing)))

    projections = []
    for assertion in rows:
        case_id = assertion["case_id"]
        case = cases[case_id]
        evidence = assertion["evidence"]
        expected_file = _scan_relative_path(
            evidence["path"], case["application_path"]
        )
        exact_events = []
        for event in scans[case_id].get("events", []):
            if event.get("action") != "added":
                continue
            observation = event.get("observation") or {}
            source = observation.get("source") or {}
            if source.get("path") == expected_file:
                exact_events.append(event)
        close = [
            event for event in exact_events
            if type((event.get("observation", {}).get("source") or {}).get("line")) is int
            and abs(event["observation"]["source"]["line"] - evidence["line"]) <= 3
        ]
        first_stage = exact_events[0]["stage"] if exact_events else None
        projections.append({
            "assertion_id": assertion["assertion_id"],
            "case_id": case_id,
            "expected": assertion["expected"],
            "claim_unit": assertion["claim_unit"],
            "semantic_kind": assertion["semantic_kind"],
            "source": {"file": expected_file, "line": evidence["line"]},
            "file_observation_events": len(exact_events),
            "near_line_events": len(close),
            "observed_kinds": dict(sorted(Counter(
                e["observation"]["kind"] for e in exact_events
            ).items())),
            "first_observed_stage": first_stage,
            "correlation_status": (
                "source_file_event_present_semantics_unverified"
                if exact_events else "no_file_event_review_needed"
            ),
            "accuracy_verdict": None,
        })
    return {
        "schema_version": 1,
        "purpose": "source_to_passive_trace_correlation_not_precision_or_recall",
        "cases_indexed": len(scans),
        "assertions_indexed": len(projections),
        "source_references_validated": validated["source_observations"],
        "correlations": projections,
        "counts": dict(sorted(Counter(
            p["correlation_status"] for p in projections
        ).items())),
        "accuracy": None,
        "independent_adjudication": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("wave-a-correlations"))
    args = parser.parse_args()
    report = correlate(args.inputs)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "correlations.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    lines = [
        "# Wave A — source/trace correlations",
        "",
        f"Frozen cases: {report['cases_indexed']}",
        f"Source anchors: {report['assertions_indexed']}",
        "",
        "| Result | Count |",
        "|---|---:|",
    ]
    lines.extend(
        f"| {key} | {count} |" for key, count in report["counts"].items()
    )
    lines += [
        "", "Neither a file correlation nor an absent graph observation",
        "establishes TP, FP, FN or full source coverage.",
        "Review exact typed edges and control context before adjudication.",
    ]
    (args.output_dir / "correlations.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
