from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "deployment_identity_study.py"
SPEC = importlib.util.spec_from_file_location("deployment_identity_study", SCRIPT)
assert SPEC and SPEC.loader
mod = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mod
SPEC.loader.exec_module(mod)


def test_frozen_v011_cohort_validates() -> None:
    root = Path(__file__).resolve().parents[1]
    cohort = root / "research" / "deployment-identity-v011" / "cohort.yaml"
    cases = mod.load_cohort(cohort)

    assert len(cases) == 20
    assert {case.provider for case in cases} == {
        "gcp",
        "aws",
        "azure",
        "kubernetes",
    }
    for case in cases:
        relationships = mod.load_truth(case.truth_path, case)
        assert relationships


def test_score_preserves_relationship_multiset() -> None:
    case = mod.StudyCase(
        case_id="x",
        provider="gcp",
        infrastructure=mod.RepoPin(repo="o/r", sha="a" * 40, path="."),
        truth_path=Path("unused"),
    )
    truth = [
        mod.ExpectedRelationship("gcp", "w1", "i1", None),
        mod.ExpectedRelationship("gcp", "w2", "i2", None),
    ]

    score = mod.score_case(case, truth, [("w1", "i1"), ("w3", "i3")])

    assert score["tp"] == 1
    assert score["fn"] == 1
    assert score["fp"] == 1
    assert score["missing"] == [{"workload_key": "w2", "identity_key": "i2"}]
    assert score["extra"] == [{"workload_key": "w3", "identity_key": "i3"}]


def test_truth_rejects_results_seen_before_freeze(tmp_path: Path) -> None:
    truth_path = tmp_path / "truth.json"
    truth_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "case_id": "x",
                "provider": "gcp",
                "reviewed": True,
                "horustrace_results_seen": True,
                "relationships": [
                    {"workload_key": "w", "identity_key": "i"}
                ],
            }
        ),
        encoding="utf-8",
    )
    case = mod.StudyCase(
        case_id="x",
        provider="gcp",
        infrastructure=mod.RepoPin(repo="o/r", sha="a" * 40, path="."),
        truth_path=truth_path,
    )

    try:
        mod.load_truth(truth_path, case)
    except mod.StudyError as exc:
        assert "locked before HorusTrace output" in str(exc)
    else:
        raise AssertionError("truth contamination was not rejected")
