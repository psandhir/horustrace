"""Deterministic source-pinned Wave B case comparison; never guesses TP/FP/FN.

Runs offline on exported GitHub Actions case ZIP artifacts (result.json,
scan.json, effective-authority.json). A cohort passing is *not* ground truth.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any

MAX_ZIP_MEMBERS = 40
MAX_JSON_BYTES = 12_000_000
REQUIRED = ("result.json", "scan.json")
AUTHORITY_FILE = "effective-authority.json"


def _json(zipped: zipfile.ZipFile, filename: str) -> dict[str, Any]:
    member = zipped.getinfo(filename)
    if member.file_size > MAX_JSON_BYTES:
        raise ValueError(f"oversized artifact: {filename}")
    data = json.loads(zipped.read(filename))
    if not isinstance(data, dict):
        raise ValueError(f"invalid object: {filename}")
    return data


def _source_path(raw: str | None) -> str:
    if not isinstance(raw, str) or not raw:
        return "unlocated"
    # The pinned scanner checks out a source tree in a fresh temporary
    # directory on every run. Never compare machine-dependent temp prefixes.
    normalized = raw.replace("\\", "/")
    if "/target/src/" in normalized:
        return normalized.split("/target/src/", 1)[-1]
    if "/src/" in normalized:
        return normalized.rsplit("/src/", 1)[-1]
    return normalized.lstrip("./")


def _finding_key(case_id: str, item: dict[str, Any]) -> str:
    loc = item.get("location") or {}
    if not isinstance(loc, dict):
        loc = {}
    claim = {
        "case": case_id,
        "rule": item.get("rule_id"),
        "message": item.get("message"),
        "agent": item.get("agent"),
        "source_path": _source_path(loc.get("path")),
        "source_line": loc.get("line"),
    }
    return hashlib.sha256(
        json.dumps(claim, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:20]


def _findings(case_id: str, items: list[dict[str, Any]]) -> Counter[str]:
    return Counter(_finding_key(case_id, row) for row in items)


def _load_case(path: Path, *, allow_missing_authority: bool = False) -> dict[str, Any]:
    with zipfile.ZipFile(path) as archive:
        if len(archive.infolist()) > MAX_ZIP_MEMBERS:
            raise ValueError(f"too many artifact members: {path.name}")
        if any(name not in archive.namelist() for name in REQUIRED):
            raise ValueError(f"missing required data: {path.name}")
        result = _json(archive, "result.json")
        scan = _json(archive, "scan.json")
        authority_present = AUTHORITY_FILE in archive.namelist()
        if not authority_present and not allow_missing_authority:
            raise ValueError(f"missing required authority data: {path.name}")
        authority = _json(archive, AUTHORITY_FILE) if authority_present else {}
    case_id = result.get("case_id")
    source_sha = result.get("sha")
    if not isinstance(case_id, str) or not case_id:
        raise ValueError(f"unknown case identity: {path.name}")
    if not isinstance(source_sha, str) or len(source_sha) != 40:
        raise ValueError(f"unverified source revision: {path.name}")
    items = scan.get("findings")
    if not isinstance(items, list) or not all(isinstance(x, dict) for x in items):
        raise ValueError(f"missing findings: {path.name}")
    summary = scan.get("summary", {})
    effective = authority.get("summary", {})
    if not isinstance(summary, dict) or not isinstance(effective, dict):
        raise ValueError(f"invalid summary: {path.name}")
    return {
        "case_id": case_id,
        "repo": result.get("repo"),
        "source_sha": source_sha,
        "application_path": result.get("application_path"),
        "artifact_structure_valid": True,
        "authority_evidence_present": authority_present,
        "metrics": {
            "agents": summary.get("agents"),
            "tools": summary.get("tools"),
            "mcp_servers": summary.get("mcp_servers"),
            "skills": summary.get("skills"),
            "findings": summary.get("findings"),
            "attack_paths": summary.get("attack_paths"),
            "authority_relationships": effective.get("relationships"),
            "unresolved_authority": effective.get("unknown_relationships"),
        },
        "findings": _findings(case_id, items),
        "source_anchor_gaps": sum(
            not isinstance((f.get("location") or {}).get("line"), int)
            or (f.get("location") or {}).get("line", 0) < 1
            for f in items
        ),
        "source_line_one_findings": sum(
            isinstance(f.get("location"), dict)
            and f["location"].get("line") == 1
            for f in items
        ),
    }


def _cohort(
    directory: Path, *, allow_missing_authority: bool = False,
) -> dict[str, dict[str, Any]]:
    if not directory.is_dir():
        raise ValueError(f"cohort artifact directory not found: {directory}")
    result: dict[str, dict[str, Any]] = {}
    for archive in sorted(directory.glob("*.zip")):
        case = _load_case(archive, allow_missing_authority=allow_missing_authority)
        cid = case["case_id"]
        if cid in result:
            raise ValueError(f"duplicate case identity: {cid}")
        result[cid] = case
    if not result:
        raise ValueError(f"empty cohort: {directory}")
    return result


def compare(
    before: Path,
    after: Path,
    *,
    expected_cases: int,
    adjudications: dict[str, Any] | None = None,
    allow_missing_authority: bool = False,
) -> dict[str, Any]:
    old = _cohort(before, allow_missing_authority=allow_missing_authority)
    fresh = _cohort(after, allow_missing_authority=allow_missing_authority)
    if set(old) != set(fresh) or len(old) != expected_cases:
        raise ValueError(
            f"cohort mismatch: before={len(old)} after={len(fresh)} "
            f"missing_after={sorted(set(old) - set(fresh))} "
            f"missing_before={sorted(set(fresh) - set(old))}"
        )
    reviewed = adjudications or {}
    approvals = reviewed.get("claims", {})
    if not isinstance(approvals, dict):
        raise ValueError("invalid review document")
    cases: list[dict[str, Any]] = []
    gaps: list[str] = []
    for cid in sorted(old):
        past = old[cid]
        now = fresh[cid]
        for immutable in ("source_sha", "repo", "application_path"):
            if past[immutable] != now[immutable]:
                raise ValueError(f"not a pinned-source comparison: {cid}/{immutable}")
        new = now["findings"] - past["findings"]
        removed = past["findings"] - now["findings"]
        changed = sorted(set(new) | set(removed))
        statuses: dict[str, str] = {}
        for fid in changed:
            review = approvals.get(f"{cid}:{fid}", {})
            status = review.get("status") if isinstance(review, dict) else None
            if (
                status not in {"source_confirmed", "false_positive", "unresolved"}
                or not isinstance(review.get("source_witness"), str)
                or not review["source_witness"].strip()
                or not isinstance(review.get("reviewer"), str)
                or not review["reviewer"].strip()
            ):
                statuses[fid] = "not_independently_reviewed"
                gaps.append(f"{cid}:{fid}")
            else:
                statuses[fid] = status
                if status == "unresolved":
                    gaps.append(f"{cid}:{fid}")
        measures = {
            k: {
                "before": past["metrics"][k],
                "after": now["metrics"][k],
                "delta": (
                    now["metrics"][k] - past["metrics"][k]
                    if all(
                        isinstance(v, int) for v in (
                            past["metrics"][k], now["metrics"][k]
                        )
                    ) else None
                ),
            }
            for k in past["metrics"]
        }
        cases.append({
            "case_id": cid,
            "source_sha": now["source_sha"],
            "measures": measures,
            "added_findings": sum(new.values()),
            "removed_findings": sum(removed.values()),
            "claim_review": statuses,
            "before_source_line_one_findings": past["source_line_one_findings"],
            "after_source_line_one_findings": now["source_line_one_findings"],
            "before_missing_source_anchors": past["source_anchor_gaps"],
            "after_missing_source_anchors": now["source_anchor_gaps"],
        })
    # Reviewing differences alone cannot establish recall of missing source
    # objects; a separate exhaustive/blinded truth ledger is required.
    return {
        "schema_version": 1,
        "scope": "pinned_case_delta_and_claim_review_only",
        "case_count": len(cases),
        "cases": cases,
        "unreviewed_or_unresolved_claims": gaps,
        "case_source_claims_reviewed": not gaps,
        "authority_evidence_missing_cases": sorted(
            c["case_id"] for c in cases
            if not (old[c["case_id"]]["authority_evidence_present"]
                    and fresh[c["case_id"]]["authority_evidence_present"])
        ),
        "external_cohort_pipeline_integrity_required": True,
        "independent_exhaustive_ground_truth": False,
        "precision": None,
        "recall": None,
        "wave_c_go": False,
        "wave_c_go_reason": "independent exhaustive source truth and full Wave B acceptance still required",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--before-dir", type=Path, required=True)
    parser.add_argument("--after-dir", type=Path, required=True)
    parser.add_argument("--expected-cases", type=int, required=True)
    parser.add_argument("--adjudications", type=Path)
    parser.add_argument(
        "--allow-missing-authority", action="store_true",
        help="For legacy scan-only cohorts, retain missing authority as unknown, never zero.",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    review = (
        json.loads(args.adjudications.read_text(encoding="utf-8"))
        if args.adjudications else None
    )
    report = compare(
        args.before_dir, args.after_dir,
        expected_cases=args.expected_cases, adjudications=review,
        allow_missing_authority=args.allow_missing_authority,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "cases": report["case_count"],
        "needs_review": len(report["unreviewed_or_unresolved_claims"]),
        "wave_c_go": report["wave_c_go"],
    }))


if __name__ == "__main__":
    main()
