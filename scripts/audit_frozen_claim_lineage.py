"""Offline, source-pinned cohort claim-lineage audit.

Historical labels may prioritize review, but are not independent ground truth.
Recall and TN require a separate, independently labeled *scanner-blind* claim set.
No target code or model is executed.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from zipfile import ZipFile

from horustrace.evaluation.calibration import summarize_calibration


def _load_bundle(path: Path) -> tuple[dict, str]:
    if path.suffix == ".zip":
        with ZipFile(path) as archive:
            names = archive.namelist()
            def read(name: str) -> bytes:
                matches = [item for item in names if item == name or item.endswith("/" + name)]
                if len(matches) != 1:
                    raise ValueError(f"{path}: expected one {name}, got {len(matches)}")
                return archive.read(matches[0])
            return json.loads(read("result.json")), hashlib.sha256(read("source-pack.txt")).hexdigest()
    if path.is_dir():
        return (
            json.loads((path / "result.json").read_text(encoding="utf-8")),
            hashlib.sha256((path / "source-pack.txt").read_bytes()).hexdigest(),
        )
    raise ValueError(f"Unsupported bundle: {path}")


def _case_bundles(directory: Path, cases: dict[str, dict]) -> dict[str, tuple[dict, str]]:
    found: dict[str, tuple[dict, str]] = {}
    for path in sorted(directory.iterdir()):
        if not (path.is_dir() or path.suffix == ".zip"):
            continue
        row, source_sha = _load_bundle(path)
        case_id = row.get("case_id")
        if case_id not in cases or case_id in found:
            raise ValueError(f"Unexpected/duplicate cohort case {case_id!r}")
        for field in ("repo", "sha", "framework"):
            if row.get(field) != cases[case_id][field]:
                raise ValueError(f"{case_id}: drift in pinned {field}")
        if row.get("counts", {}).get("findings") != len(row.get("findings", [])):
            raise ValueError(f"{case_id}: inconsistent finding count")
        found[case_id] = (row, source_sha)
    missing = set(cases) - set(found)
    if missing:
        raise ValueError(f"Missing pinned cohort cases: {sorted(missing)}")
    return found


def _source_location(finding: dict) -> tuple[str, int]:
    loc = finding.get("location") or {}
    raw = str(loc.get("path") or "").replace("\\", "/")
    if "/target/" in raw:
        raw = raw.rsplit("/target/", 1)[1]
    if raw.startswith("target/"):
        raw = raw[len("target/"):]
    line = loc.get("line")
    if not raw or type(line) is not int or line < 1:
        raise ValueError("Finding lacks trustworthy relative source location")
    if Path(raw).is_absolute() or ".." in Path(raw).parts:
        raise ValueError("Unsafe source path")
    return raw, line


def _identity(finding: dict) -> tuple[str, str, str, int]:
    path, line = _source_location(finding)
    rule = finding.get("rule_id", finding.get("path_id"))
    if not isinstance(rule, str) or not rule:
        raise ValueError("Finding or path lacks a rule identifier")
    return (rule, str(finding.get("agent") or ""), path, line)


def _labels(path: Path) -> dict[tuple[str, int], dict]:
    with path.open(newline="", encoding="utf-8") as file:
        rows = list(csv.DictReader(file))
    seen = set()
    output = {}
    for row in rows:
        key = (row["case_id"], int(row["finding_index"]))
        if key in seen:
            raise ValueError(f"duplicate historical review key {key}")
        seen.add(key)
        if row["verdict"] not in {"true_positive", "false_positive", "partial", "unresolved"}:
            raise ValueError("Unknown review verdict")
        output[key] = row
    return output


def audit(
    cohort: dict, old: dict, new: dict, historical: dict,
    *, blind_reviews: list[dict] | None = None,
) -> dict:
    cases = {item["case_id"]: item for item in cohort["cases"]}
    if len(cases) != len(cohort["cases"]):
        raise ValueError("duplicate case in frozen manifest")
    if set(old) != set(cases) or set(new) != set(cases):
        raise ValueError("both studies must cover the identical frozen manifest")
    lineage = []
    source_pins = {}
    added = []
    for case_id in sorted(cases):
        earlier, before_source = old[case_id]
        current, after_source = new[case_id]
        if before_source != after_source:
            raise ValueError(f"{case_id}: source-pack digest changed between scans")
        source_pins[case_id] = before_source
        remaining = defaultdict(list)
        for entry in current["findings"]:
            remaining[_identity(entry)].append(entry)
        for index, entry in enumerate(earlier["findings"]):
            key = _identity(entry)
            matched = remaining[key].pop(0) if remaining[key] else None
            label = historical.get((case_id, index))
            lineage.append({
                "case_id": case_id, "old_index": index,
                "rule_id": key[0], "agent": key[1],
                "source_path": key[2], "source_line": key[3],
                "status": "retained" if matched else "removed",
                "new_index": matched["index"] if matched is not None else None,
                "historical_verdict": label["verdict"] if label else "unreviewed",
                "historical_reason": label["reason_category"] if label else None,
                "label_provenance": "historical_scanner_visible_single_reviewer",
            })
        for duplicates in remaining.values():
            for item in duplicates:
                path, line = _source_location(item)
                added.append({
                    "case_id": case_id, "new_index": item["index"],
                    "rule_id": item["rule_id"], "agent": item.get("agent"),
                    "source_path": path, "source_line": line,
                    "review_status": "unadjudicated_new_claim",
                })
    tally = Counter((item["status"], item["historical_verdict"]) for item in lineage)
    accuracy = {
        "status": "not_measured_no_independent_scanner_blind_references",
        "false_positives": None, "false_negatives": None,
        "true_negatives": None, "precision": None, "recall": None,
    }
    if blind_reviews is not None:
        rows = []
        ids = set()
        for claim in blind_reviews:
            required = {
                "claim_id", "case_id", "rule_id", "agent", "source_path",
                "source_line", "claim_kind", "framework", "language", "family",
                "reference", "reviewer_id", "independent", "scanner_blinded",
                "partition",
            }
            if set(claim) != required:
                raise ValueError("source-first review missing mandatory metadata")
            if claim["claim_id"] in ids:
                raise ValueError("duplicate source-first claim")
            ids.add(claim["claim_id"])
            if claim["case_id"] not in cases:
                raise ValueError("source-first claim belongs to unpinned case")
            if claim["independent"] is not True or claim["scanner_blinded"] is not True:
                raise ValueError("source-first reviewers must be independent and scanner-blind")
            if not claim["reviewer_id"] or claim["reference"] not in {
                "supported", "partial", "unsupported", "unresolved",
            }:
                raise ValueError("invalid source-first label")
            case_id = claim["case_id"]
            if claim["framework"] != cases[case_id]["framework"]:
                raise ValueError("source-first framework disagrees with pinned manifest")
            key = (claim["rule_id"], claim["agent"], claim["source_path"], claim["source_line"])
            if claim["claim_kind"] == "path":
                observed = new[case_id][0].get("attack_paths", [])
            else:
                observed = new[case_id][0]["findings"]
            predicted = "supported" if key in {
                _identity(x) for x in observed
            } else "refuted"
            rows.append({
                "case_id": claim["claim_id"],
                "repository": cases[case_id]["repo"],
                "framework": claim["framework"], "language": claim["language"],
                "family": claim["family"], "claim_kind": claim["claim_kind"],
                "partition": claim["partition"], "reference": claim["reference"],
                "predicted": predicted,
                "label_provenance": "independent_source_first_scanner_blinded",
            })
        accuracy = {
            "status": "caller_supplied_source_first_reference_calibration",
            "warning": "Independence asserted by review metadata, not independently verified by software",
            "calibration": summarize_calibration(rows),
        }
    return {
        "schema_version": 1,
        "cohort_size": len(cases),
        "source_pack_sha256_by_case": source_pins,
        "prior_claims": len(lineage),
        "current_claims": sum(len(r[0]["findings"]) for r in new.values()),
        "retained_by_prior_verdict": {
            key[1]: count for key, count in sorted(tally.items())
            if key[0] == "retained"
        },
        "removed_by_prior_verdict": {
            key[1]: count for key, count in sorted(tally.items())
            if key[0] == "removed"
        },
        "new_claims": added,
        "historical_lineage": lineage,
        "independent_accuracy": accuracy,
        "limitations": [
            "Source identity matching is conservative: refactoring and binding changes need review",
            "Historical single-reviewer labels cannot establish true current FP/FN counts",
            "Missing scanner claims are not automatically false negatives",
            "Runtime exploitability is not established by static findings or paths",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cohort", required=True, type=Path)
    parser.add_argument(
        "--exclude-framework", action="append", default=[],
        help="Exclude a framework from a frozen source manifest, e.g. langgraph for Fresh16",
    )
    parser.add_argument("--old-dir", required=True, type=Path)
    parser.add_argument("--new-dir", required=True, type=Path)
    parser.add_argument("--historical-csv", required=True, type=Path)
    parser.add_argument("--source-first-review", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    cohort = json.loads(args.cohort.read_text(encoding="utf-8"))
    if args.exclude_framework:
        cohort["cases"] = [
            row for row in cohort["cases"]
            if row["framework"] not in set(args.exclude_framework)
        ]
    cases = {row["case_id"]: row for row in cohort["cases"]}
    if len(cases) != len(cohort["cases"]):
        raise ValueError("duplicate case in frozen cohort")
    old = _case_bundles(args.old_dir, cases)
    new = _case_bundles(args.new_dir, cases)
    review = (json.loads(args.source_first_review.read_text(encoding="utf-8"))
              if args.source_first_review else None)
    result = audit(
        cohort, old, new, _labels(args.historical_csv),
        blind_reviews=review,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Audited {result['cohort_size']} pinned cases; "
          f"{result['prior_claims']} old claims → {result['current_claims']} current. "
          f"Independent accuracy: {result['independent_accuracy']['status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
