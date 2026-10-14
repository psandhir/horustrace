"""Validate the retrospective Wave-A case manifest against existing pinned cohorts.

This validates identities and source freeze only. It does NOT report accuracy or
register historical scanner-visible cases as an independent blind study.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
DEFAULT = Path("research/accuracy-wave-a-retrospective-20261014/cohort.json")


class BaselineError(ValueError):
    pass


def _git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def audit(manifest_path: Path, repo_root: Path) -> dict:
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    if document.get("schema_version") != 1 or document.get("status") != "retrospective_diagnostic_not_blind":
        raise BaselineError("baseline must be explicitly retrospective, not blind quality truth")
    selection = document["selection"]
    cases = document.get("cases")
    if not isinstance(cases, list) or len(cases) != selection.get("target_repositories"):
        raise BaselineError("baseline case count differs from selection")
    source_manifest_blobs = selection["source_manifest_blobs"]
    sources = {}
    for name, expected_sha in source_manifest_blobs.items():
        path = repo_root / name
        if path.resolve() == manifest_path.resolve():
            raise BaselineError("baseline cannot pin itself as an independent source")
        raw = path.read_bytes()
        if _git_blob_sha(raw) != expected_sha:
            raise BaselineError(f"frozen upstream cohort blob changed: {name}")
        original = json.loads(raw)
        sources[name] = {case["case_id"]: case for case in original["cases"]}
    ids, repos, counts = set(), set(), {}
    for case in cases:
        ident, repo, source = case["case_id"], case["repo"], case["source_manifest"]
        if ident in ids or repo in repos:
            raise BaselineError("duplicate case or repository in baseline")
        ids.add(ident)
        repos.add(repo)
        if source not in sources or ident not in sources[source]:
            raise BaselineError(f"case not in referenced frozen cohort: {ident}")
        original = sources[source][ident]
        for field in ("repo", "sha", "framework", "evidence_path"):
            if case[field] != original[field]:
                raise BaselineError(f"{ident}: pinned {field} drift")
        if case["application_path"] != (original.get("application_path") or "."):
            raise BaselineError(f"{ident}: pinned application root drift")
        for field in ("application_path", "evidence_path"):
            part = PurePosixPath(case[field])
            if part.is_absolute() or ".." in part.parts:
                raise BaselineError(f"{ident}: unsafe {field}")
        if case.get("review_status") not in {
            "legacy_claim_visible", "existing_scanner_visible_source_signal"
        }:
            raise BaselineError(f"{ident}: unsupported review provenance")
        counts[case["framework"]] = counts.get(case["framework"], 0) + 1
    if selection["frozen_fresh_cases"] != sum(x["case_id"].startswith("gen-") for x in cases):
        raise BaselineError("Fresh-16 frozen denominator mismatch")
    if selection["targeted_full60_cases"] != sum(x["case_id"].startswith("ff60-") for x in cases):
        raise BaselineError("Full-60 diagnostic denominator mismatch")
    return {
        "status": "valid_retrospective_source_manifest",
        "cases": len(cases),
        "framework_counts": dict(sorted(counts.items())),
        "accuracy_validated": False,
        "independent_blind_reference": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cohort", type=Path, default=DEFAULT)
    args = parser.parse_args()
    print(json.dumps(audit(ROOT / args.cohort, ROOT), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
