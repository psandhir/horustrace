import csv
import json
import subprocess
import sys
from pathlib import Path

SCRIPT = (
    Path(__file__).parents[1]
    / "research"
    / "full-framework-60-post-remediation-20261006"
    / "compare.py"
)
COUNT_KEYS = (
    "agents",
    "findings",
    "attack_paths",
    "authority_relationships",
    "partially_resolved_authority",
    "unknown_authority",
    "diagnostics",
    "unbound_skills",
)


def _write_baseline(path: Path, case_ids: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=("case_id", "framework", *COUNT_KEYS),
        )
        writer.writeheader()
        for case_id in case_ids:
            writer.writerow(
                {
                    "case_id": case_id,
                    "framework": "google-adk",
                    **{key: 0 for key in COUNT_KEYS},
                }
            )


def _write_result(
    root: Path,
    case_id: str,
    *,
    agents: int = 1,
    core_resolution: str = "fully_resolved",
) -> None:
    case = root / case_id
    case.mkdir(parents=True)
    counts = {key: 0 for key in COUNT_KEYS}
    counts.update(
        {
            "agents": agents,
            "authority_relationships": 1,
            "unknown_authority": int(core_resolution == "unknown"),
        }
    )
    relationship = {
        "core_resolution": core_resolution,
        "detail_resolution": "partially_resolved",
        "source_context": "runtime",
        "destinations": [],
    }
    (case / "result.json").write_text(
        json.dumps(
            {
                "case_id": case_id,
                "framework": "google-adk",
                "counts": counts,
                "authority_relationships": [relationship],
                "findings": [],
                "attack_paths": [],
            }
        ),
        encoding="utf-8",
    )


def _write_gate(path: Path, *, ratio: float = 1.0) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "gate": {
                    "expected_cases": 2,
                    "max_missing_cases": 0,
                    "max_zero_agent_cases": 0,
                    "max_core_unknown": 0,
                    "min_total_agents": 2,
                    "min_total_authority_relationships": 2,
                    "min_core_fully_resolved_ratio": ratio,
                    "framework_minimums": {
                        "google-adk": {
                            "agents": 2,
                            "authority_relationships": 2,
                        }
                    },
                },
            }
        ),
        encoding="utf-8",
    )


def _run(tmp_path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--input",
            str(tmp_path / "results"),
            "--baseline",
            str(tmp_path / "baseline.csv"),
            "--output",
            str(tmp_path / "output"),
            "--scanner-revision",
            "scanner",
            "--harness-revision",
            "harness",
            "--gate-baseline",
            str(tmp_path / "gate.json"),
        ],
        text=True,
        capture_output=True,
        check=False,
    )


def test_frozen_regression_gate_passes_healthy_complete_cohort(
    tmp_path: Path,
) -> None:
    _write_baseline(tmp_path / "baseline.csv", ["case-1", "case-2"])
    _write_gate(tmp_path / "gate.json")
    _write_result(tmp_path / "results", "case-1")
    _write_result(tmp_path / "results", "case-2")

    result = _run(tmp_path)

    assert result.returncode == 0, result.stderr
    report = json.loads(
        (tmp_path / "output" / "comparison.json").read_text(encoding="utf-8")
    )
    assert report["regression_gate"]["passed"] is True
    assert report["regression_gate"]["failures"] == []


def test_frozen_regression_gate_fails_zero_agent_and_core_unknown(
    tmp_path: Path,
) -> None:
    _write_baseline(tmp_path / "baseline.csv", ["case-1", "case-2"])
    _write_gate(tmp_path / "gate.json")
    _write_result(tmp_path / "results", "case-1")
    _write_result(
        tmp_path / "results",
        "case-2",
        agents=0,
        core_resolution="unknown",
    )

    result = _run(tmp_path)

    assert result.returncode == 1
    report = json.loads(
        (tmp_path / "output" / "comparison.json").read_text(encoding="utf-8")
    )
    failures = report["regression_gate"]["failures"]
    assert any("zero-agent" in item for item in failures)
    assert any("core-unknown" in item for item in failures)
