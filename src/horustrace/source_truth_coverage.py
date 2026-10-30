"""Wave C C02f: source-review scope coverage and release NO-GO matrix.

Unlike a cherry-picked score, this uses an explicit expected-scope universe.
External completeness and reviewer independence are intentionally NOT inferred
from manifests or labels; no output from this module authorizes cutover.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from typing import Any

from horustrace.source_truth_oracle import CONSTRUCTS, SOURCE_ROLES, validate_reference
from horustrace.source_truth_witness import verify_reference_witnesses

_SHA = re.compile(r"[a-fA-F0-9]{40}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/#@+-]*\Z")
_REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")


def _expected_scopes(manifest: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema_version", "manifest_ref", "expected_scopes",
    }:
        raise ValueError("expected scope manifest schema mismatch")
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
        raise ValueError("unsupported expected scope manifest version")
    if not isinstance(manifest["manifest_ref"], str) or not manifest["manifest_ref"].strip():
        raise ValueError("expected scope manifest needs provenance reference")
    if not isinstance(manifest["expected_scopes"], list):
        raise TypeError("expected_scopes must be a list")
    rows = {}
    for item in manifest["expected_scopes"]:
        if not isinstance(item, dict) or set(item) != {
            "scope_id", "case_id", "repository", "commit_sha",
            "framework", "construct", "source_role",
        }:
            raise ValueError("expected scope row schema mismatch")
        scope_id, case_id = item["scope_id"], item["case_id"]
        if any(not isinstance(x, str) or not _ID.fullmatch(x)
               for x in (scope_id, case_id, item["framework"])):
            raise ValueError("expected scope needs portable identity and framework")
        if (not isinstance(item["repository"], str)
                or not _REPO.fullmatch(item["repository"])):
            raise ValueError("expected scope repository must be owner/name")
        if (not isinstance(item["commit_sha"], str)
                or _SHA.fullmatch(item["commit_sha"]) is None
                or item["commit_sha"] == "0" * 40):
            raise ValueError("expected scope needs pinned 40-hex Git commit")
        if item["construct"] not in CONSTRUCTS or item["source_role"] not in SOURCE_ROLES:
            raise ValueError("unsupported expected construct/source role")
        if scope_id in rows:
            raise ValueError("duplicate expected scope ID")
        rows[scope_id] = item
    if not rows:
        raise ValueError("empty expected cohort cannot have coverage")
    return rows


def source_truth_coverage(
    expected_manifest: Any, reference: Any, checkouts: Any,
) -> dict[str, Any]:
    """Audit all declared expected scopes; source verification is not truth review."""
    expected = _expected_scopes(expected_manifest)
    oracle = validate_reference(reference)
    source_scopes = {row["scope_id"]: row for row in oracle["scopes"]}
    extras = sorted(set(source_scopes) - set(expected))
    if extras:
        raise ValueError("source reference contains unexpected cohort scopes")
    for scope_id, row in source_scopes.items():
        want = expected[scope_id]
        if any(
            str(row[field]).lower() != str(want[field]).lower()
            for field in ("case_id", "repository", "commit_sha", "construct", "source_role")
        ):
            raise ValueError("reference scope differs from expected pinned source")
    verify_reference_witnesses(oracle, checkouts)
    labels: dict[str, Counter[str]] = defaultdict(Counter)
    for item in oracle["labels"]:
        labels[item["scope_id"]][item["truth"]] += 1
    results: list[dict[str, Any]] = []
    group: dict[tuple[str, str, str], Counter[str]] = defaultdict(Counter)
    for scope_id in sorted(expected):
        row = expected[scope_id]
        ref = source_scopes.get(scope_id)
        counts = labels[scope_id]
        blockers = []
        if ref is None:
            blockers.append("missing_reference_scope")
        else:
            if not ref["positive_complete"]:
                blockers.append("positive_universe_open")
            if not ref["negative_complete"]:
                blockers.append("negative_universe_open")
            if not counts["positive"]:
                blockers.append("no_source_positive_labels")
            if not counts["negative"]:
                blockers.append("no_source_hard_negative_labels")
            if counts["unknown"]:
                blockers.append("unresolved_source_labels")
            if ref["review_method"] != "independent_blind" or not ref["scanner_blind"]:
                blockers.append("review_not_declared_independent_blind")
        # Even a self-declared independent review cannot establish external
        # independence or whether the entire expected cohort is exhaustive.
        blockers.extend([
            "external_review_independence_not_verified",
            "expected_cohort_completeness_not_externally_verified",
        ])
        item = {
            "scope_id": scope_id,
            "case_id": row["case_id"],
            "repository": row["repository"],
            "commit_sha": row["commit_sha"].lower(),
            "framework": row["framework"],
            "construct": row["construct"],
            "source_role": row["source_role"],
            "reference_present": ref is not None,
            "positive_labels": counts["positive"],
            "negative_labels": counts["negative"],
            "unknown_labels": counts["unknown"],
            "source_witnesses_git_verified": ref is not None and sum(counts.values()) > 0,
            "blockers": blockers,
            "certified_accuracy_assessable": False,
        }
        results.append(item)
        agg = group[(row["framework"], row["construct"], row["source_role"])]
        agg["expected_scopes"] += 1
        agg["referenced_scopes"] += int(ref is not None)
        agg["missing_scopes"] += int(ref is None)
        agg["positive_labels"] += counts["positive"]
        agg["hard_negative_labels"] += counts["negative"]
        agg["unknown_labels"] += counts["unknown"]
    return {
        "schema_version": 1,
        "mode": "source_truth_coverage_diagnostic_not_certification",
        "expected_manifest_ref": expected_manifest["manifest_ref"],
        "expected_scope_count": len(expected),
        "referenced_scope_count": len(source_scopes),
        "missing_scope_count": len(expected) - len(source_scopes),
        "framework_construct_context": [{
            "framework": fw, "construct": kind, "source_role": context,
            **dict(sorted(counts.items())),
        } for (fw, kind, context), counts in sorted(group.items())],
        "scopes": results,
        "independent_review_externally_verified": False,
        "expected_cohort_completeness_externally_verified": False,
        "certified_precision": None,
        "certified_recall": None,
        "production_cutover_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Report missing V2 source-truth reference scopes by framework"
    )
    parser.add_argument("--expected", required=True)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--checkouts", required=True)
    args = parser.parse_args()

    def read(path: str) -> Any:
        with open(path, encoding="utf-8") as stream:
            return json.load(stream)

    print(json.dumps(
        source_truth_coverage(
            read(args.expected), read(args.reference), read(args.checkouts),
        ), indent=2, sort_keys=True,
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
