"""Validate source-anchored Wave A assertions without promoting them to truth.

The ledger references pinned upstream file blob SHAs captured by source inspection.
CI validates schema, source-cohort linkage and provenance, not upstream runtime.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path, PurePosixPath

from scripts.verify_accuracy_wave_a_baseline import BaselineError, audit

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / "research/accuracy-wave-a-retrospective-20261014"
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
ALLOWED_UNITS = {"entity", "edge", "qualified_effect", "finding_scope", "path"}
ALLOWED_EXPECTED = {"supported", "not_supported", "unresolved"}
PROVENANCE = "source_inspected_in_chat_not_independent_blind"


def audit_assertions(
    ledger_path: Path = DIRECTORY / "source-assertions.json",
    cohort_path: Path = DIRECTORY / "cohort.json",
    repo_root: Path = ROOT,
) -> dict:
    cohort_check = audit(cohort_path, repo_root)
    cases = {
        item["case_id"]: item
        for item in json.loads(cohort_path.read_text(encoding="utf-8"))["cases"]
    }
    doc = json.loads(ledger_path.read_text(encoding="utf-8"))
    if (doc.get("schema_version") != 1
            or doc.get("blind_review_completed") is not False
            or doc.get("purpose") != "diagnostic_source_assertions_not_independent_accuracy_labels"):
        raise BaselineError("assertion ledger must not claim independent ground truth")
    claims = doc.get("assertions")
    if not isinstance(claims, list) or not claims:
        raise BaselineError("nonempty source assertion ledger required")
    seen, strata = set(), Counter()
    for row in claims:
        identifier, case_id = row.get("assertion_id"), row.get("case_id")
        if not isinstance(identifier, str) or identifier in seen:
            raise BaselineError("missing or duplicate source assertion ID")
        seen.add(identifier)
        if case_id not in cases:
            raise BaselineError(f"{identifier}: unknown frozen case")
        if row.get("claim_unit") not in ALLOWED_UNITS:
            raise BaselineError(f"{identifier}: unsupported claim unit")
        if row.get("expected") not in ALLOWED_EXPECTED:
            raise BaselineError(f"{identifier}: unsupported source assertion verdict")
        if (row.get("provenance") != PROVENANCE
                or row.get("review_status") != "initial_source_observation_requires_locked_independent_review"):
            raise BaselineError(f"{identifier}: missing reviewer qualification")
        if not row.get("semantic_kind") or not row.get("rationale"):
            raise BaselineError(f"{identifier}: semantic kind and rationale required")
        evidence = row.get("evidence")
        if not isinstance(evidence, dict):
            raise BaselineError(f"{identifier}: source evidence required")
        path = evidence.get("path")
        if not isinstance(path, str) or not path:
            raise BaselineError(f"{identifier}: missing source file")
        source = PurePosixPath(path)
        if source.is_absolute() or ".." in source.parts:
            raise BaselineError(f"{identifier}: source path escapes pinned repository")
        if not isinstance(evidence.get("line"), int) or evidence["line"] <= 0:
            raise BaselineError(f"{identifier}: positive source line required")
        if not isinstance(evidence.get("source_git_blob_sha"), str) or not SHA40.fullmatch(
            evidence["source_git_blob_sha"]
        ):
            raise BaselineError(f"{identifier}: immutable Git file blob required")
        if not isinstance(evidence.get("anchor"), str) or not evidence["anchor"]:
            raise BaselineError(f"{identifier}: matching source code anchor required")
        strata[(cases[case_id]["framework"], row["claim_unit"], row["expected"])] += 1
    unreviewed_cases = sorted(set(cases) - {
        item["case_id"] for item in claims
    })
    if unreviewed_cases:
        raise BaselineError(
            "baseline cases without source-anchored observations: "
            + ", ".join(unreviewed_cases)
        )
    return {
        "status": "valid_historical_source_assertion_schema",
        "cases_in_baseline": cohort_check["cases"],
        "source_observations": len(claims),
        "framework_case_groups_with_assertions": len({k[0] for k in strata}),
        "cases_with_assertions": len(cases),
        "coverage_scope": "one_or_more_source_observations_not_exhaustive_entities_or_edges",
        "strata": [
            {"framework": f, "unit": unit, "expected": expected, "count": count}
            for (f, unit, expected), count in sorted(strata.items())
        ],
        "independent_blind_review": False,
        "measured_accuracy": None,
    }


if __name__ == "__main__":
    print(json.dumps(audit_assertions(), indent=2, sort_keys=True))
