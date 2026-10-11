"""Produce scanner-blind pinned source-review packets for independent reviewers.

Never includes scanner output, findings, attack paths or the historical review CSV.
No live execution, repository download, target import or model API call.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from zipfile import ZipFile


def _source_from_case(path: Path) -> tuple[dict, bytes]:
    if path.suffix == ".zip":
        with ZipFile(path) as archive:
            names = archive.namelist()
            def read(name: str) -> bytes:
                matches = [entry for entry in names if entry == name or entry.endswith("/" + name)]
                if len(matches) != 1:
                    raise ValueError(f"{path}: expected exactly one {name}")
                return archive.read(matches[0])
            return json.loads(read("result.json")), read("source-pack.txt")
    if path.is_dir():
        return (
            json.loads((path / "result.json").read_text(encoding="utf-8")),
            (path / "source-pack.txt").read_bytes(),
        )
    raise ValueError("Only a case ZIP or extracted case directory is supported")


def build_packets(
    cohort: dict, bundle_root: Path, out: Path, *,
    exclude_frameworks: frozenset[str] = frozenset(),
) -> dict:
    if out.exists():
        raise ValueError("Review packet output already exists; source locks are immutable")
    selected = [row for row in cohort["cases"]
                if row["framework"] not in exclude_frameworks]
    cases = {row["case_id"]: row for row in selected}
    if len(cases) != len(selected):
        raise ValueError("Duplicate case ID in source manifest")
    payloads = {}
    for path in sorted(bundle_root.iterdir()):
        if not (path.is_dir() or path.suffix == ".zip"):
            continue
        metadata, source = _source_from_case(path)
        case_id = metadata.get("case_id")
        if case_id not in cases or case_id in payloads:
            raise ValueError(f"Unexpected or duplicate case: {case_id}")
        for field in ("repo", "framework", "sha"):
            if metadata.get(field) != cases[case_id][field]:
                raise ValueError(f"{case_id}: frozen {field} changed")
        if not source:
            raise ValueError(f"{case_id}: empty source packet")
        payloads[case_id] = source
    if set(payloads) != set(cases):
        raise ValueError("Missing exact frozen source cases")

    rows = []
    for case_id in sorted(payloads):
        source = payloads[case_id]
        row = cases[case_id]
        rows.append({
            "case_id": case_id, "repository": row["repo"],
            "source_revision": row["sha"], "framework": row["framework"],
            "source_sha256": hashlib.sha256(source).hexdigest(),
            "packet_name": f"{case_id}.source.txt",
            "review_state": "source_first_unreviewed",
        })
    lock = {
        "schema_version": 1,
        "review_protocol": "scanner_blind_source_first_v1",
        "scanner_output_present": False,
        "independence_verified": False,
        "source_packets": rows,
        "adjudication": "not_started",
    }
    out.mkdir(parents=True)
    for row in rows:
        (out / row["packet_name"]).write_bytes(payloads[row["case_id"]])
    (out / "lock.json").write_text(
        json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out / "REVIEWER_GUIDE.md").write_text(
        "# Scanner-blind source review\n\n"
        "Review the pinned source files without seeing HorusScan findings, "
        "attack paths, earlier label CSV, or current cohort comparisons.\n\n"
        "Enumerate independently supported source claims **and near misses**, "
        "including source-reachable sinks absent from scanner output. "
        "Record exact rule, agent, source file/line, scope and blockers.\n\n"
        "Use independent reviewers and reconcile disagreement *before* "
        "revealing the scanner output. Reviewer independence is an external "
        "process assertion, not automatically proven by this package.\n\n"
        "Only then format locked assertions for "
        "scripts/audit_frozen_claim_lineage.py --source-first-review.\n",
        encoding="utf-8",
    )
    return lock


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cohort", type=Path, required=True)
    parser.add_argument("--bundles", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--exclude-framework", action="append", default=[])
    args = parser.parse_args(argv)
    cohort = json.loads(args.cohort.read_text(encoding="utf-8"))
    lock = build_packets(
        cohort, args.bundles, args.output,
        exclude_frameworks=frozenset(args.exclude_framework),
    )
    print(f"Prepared {len(lock['source_packets'])} scanner-blind source packets. "
          "No accuracy metrics or adjudication yet.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
