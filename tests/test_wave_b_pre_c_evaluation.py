"""Wave B pre-C evaluator: pinned sources, case completeness and truth gates."""
from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from scripts.evaluate_wave_b_pre_c import compare


def _archive(
    directory: Path, case: str, sha: str,
    *,
    agents: int = 2, findings: list[dict] | None = None,
    source: str = "src",
) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    findings = findings if findings is not None else []
    result = {
        "case_id": case,
        "repo": "pinned/repo",
        "sha": sha,
        "application_path": source,
    }
    scan = {
        "summary": {
            "agents": agents, "tools": 4, "mcp_servers": 2,
            "skills": 0, "findings": len(findings), "attack_paths": 0,
        },
        "findings": findings,
    }
    authority = {"summary": {"relationships": 3, "unknown_relationships": 1}}
    with zipfile.ZipFile(directory / f"{case}.zip", "w") as zipped:
        for name, document in (
            ("result.json", result),
            ("scan.json", scan),
            ("effective-authority.json", authority),
        ):
            zipped.writestr(name, json.dumps(document))


SHA = "a" * 40


def _finding(line: int, root: str = "temp-a") -> dict:
    return {
        "rule_id": "AGT040",
        "message": "Privileged tool lacks approval",
        "agent": "agent",
        "location": {
            "path": f"/tmp/{root}/target/src/agents/worker.py",
            "line": line,
        },
    }


def test_claim_deltas_are_review_needed_without_guessing_accuracy(
    tmp_path: Path,
) -> None:
    before, after = tmp_path / "before", tmp_path / "after"
    _archive(before, "case-1", SHA, findings=[_finding(4)])
    _archive(after, "case-1", SHA, agents=10,
             findings=[_finding(4, "temp-b"), _finding(8, "temp-b")])
    report = compare(before, after, expected_cases=1)
    case = report["cases"][0]
    assert case["measures"]["agents"]["delta"] == 8
    assert case["added_findings"] == 1
    assert case["removed_findings"] == 0
    assert report["unreviewed_or_unresolved_claims"]
    assert report["independent_exhaustive_ground_truth"] is False
    assert report["precision"] is None
    assert report["recall"] is None
    assert report["wave_c_go"] is False


def test_review_requires_explicit_witness_and_reviewer(tmp_path: Path) -> None:
    before, after = tmp_path / "before", tmp_path / "after"
    _archive(before, "case-1", SHA)
    _archive(after, "case-1", SHA, findings=[_finding(9)])
    initial = compare(before, after, expected_cases=1)
    key = initial["unreviewed_or_unresolved_claims"][0]
    incomplete = compare(
        before, after, expected_cases=1,
        adjudications={"claims": {key: {"status": "source_confirmed"}}},
    )
    assert incomplete["unreviewed_or_unresolved_claims"] == [key]
    reviewed = compare(
        before, after, expected_cases=1,
        adjudications={"claims": {key: {
            "status": "source_confirmed",
            "source_witness": "src/agents/worker.py:9",
            "reviewer": "independent-reviewer",
        }}},
    )
    assert reviewed["case_source_claims_reviewed"] is True
    assert reviewed["wave_c_go"] is False  # completeness still unproven


def test_source_sha_mismatch_refuses_fake_accuracy_comparison(
    tmp_path: Path,
) -> None:
    before, after = tmp_path / "before", tmp_path / "after"
    _archive(before, "case-1", SHA)
    _archive(after, "case-1", "b" * 40)
    with pytest.raises(ValueError, match="not a pinned-source comparison"):
        compare(before, after, expected_cases=1)


def test_missing_case_and_duplicate_case_are_fail_closed(tmp_path: Path) -> None:
    before, after = tmp_path / "before", tmp_path / "after"
    _archive(before, "case-1", SHA)
    _archive(after, "case-2", SHA)
    with pytest.raises(ValueError, match="cohort mismatch"):
        compare(before, after, expected_cases=1)
    _archive(after, "case-1", SHA)
    _archive(after, "case-2", SHA)
    with pytest.raises(ValueError, match="cohort mismatch"):
        compare(before, after, expected_cases=1)


def test_missing_artifact_file_is_never_silently_complete(tmp_path: Path) -> None:
    before, after = tmp_path / "before", tmp_path / "after"
    _archive(before, "case-1", SHA)
    _archive(after, "case-1", SHA)
    path = after / "case-1.zip"
    with zipfile.ZipFile(path, "w") as zipped:
        zipped.writestr("result.json", "{}")
    with pytest.raises(ValueError, match="missing required data"):
        compare(before, after, expected_cases=1)


def test_legacy_fresh16_missing_authority_is_unknown_not_zero(
    tmp_path: Path,
) -> None:
    before, after = tmp_path / "before", tmp_path / "after"
    _archive(before, "gen-pyd-001", SHA, agents=2, findings=[_finding(4)])
    _archive(after, "gen-pyd-001", SHA, agents=3,
             findings=[_finding(4), _finding(7)])
    for root in (before, after):
        path = root / "gen-pyd-001.zip"
        with zipfile.ZipFile(path) as archive:
            kept = {
                name: archive.read(name)
                for name in archive.namelist()
                if name != "effective-authority.json"
            }
        with zipfile.ZipFile(path, "w") as archive:
            for name, content in kept.items():
                archive.writestr(name, content)

    with pytest.raises(ValueError, match="missing required authority data"):
        compare(before, after, expected_cases=1)

    report = compare(
        before, after, expected_cases=1, allow_missing_authority=True,
    )
    assert report["case_count"] == 1
    assert report["authority_evidence_missing_cases"] == ["gen-pyd-001"]
    assert report["cases"][0]["measures"]["authority_relationships"] == {
        "before": None, "after": None, "delta": None,
    }
    assert report["cases"][0]["added_findings"] == 1
    assert report["wave_c_go"] is False
