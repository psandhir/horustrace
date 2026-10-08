"""Enforce reusable evidence gate adoption for new registered research studies.

Historical research directories are intentionally out of scope. New studies must
live under research/studies/<study_id> with cohort.json and study.json.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from scripts.study_evaluation_gate import GateError, load, require, validate_cohort

STUDY_ROOT = Path("research/studies")
GATE = "./.github/workflows/reusable-study-quality-gate.yml"
CALL_PATTERN = re.compile(
    r"^\s*uses:\s*\./\.github/workflows/reusable-study-quality-gate\.yml\s*$",
    re.MULTILINE,
)


def check(repo: Path) -> list[str]:
    root = repo / STUDY_ROOT
    if not root.is_dir():
        return []
    checked: list[str] = []
    for directory in sorted(root.iterdir()):
        if not directory.is_dir() or directory.name.startswith("."):
            continue
        manifest = directory / "study.json"
        require(manifest.is_file(), f"{directory}: missing study.json registry record")
        descriptor = load(manifest)
        name = descriptor.get("study")
        require(isinstance(name, str) and bool(name), f"{manifest}: study name required")
        cohort_path = descriptor.get("cohort_path")
        required_cohort_path = f"research/studies/{directory.name}/cohort.json"
        require(cohort_path == required_cohort_path,
                f"{manifest}: cohort_path must be {required_cohort_path}")
        path = repo / cohort_path
        require(path.is_file(), f"{manifest}: missing cohort.json")
        cohort = load(path)
        require(cohort.get("study") == name,
                f"{manifest}: study identity mismatches frozen cohort")
        validate_cohort(cohort)
        require(descriptor.get("quality_gate_required") is True,
                f"{manifest}: fail-closed quality gate required")
        workflow_path = descriptor.get("workflow_path")
        require(isinstance(workflow_path, str) and
                re.fullmatch(r"\.github/workflows/[a-zA-Z0-9_.-]+\.ya?ml",
                             workflow_path) is not None,
                f"{manifest}: valid workflow path required")
        workflow_file = repo / workflow_path
        require(workflow_file.is_file(), f"{manifest}: workflow does not exist")
        workflow = workflow_file.read_text(encoding="utf-8")
        require(CALL_PATTERN.search(workflow) is not None,
                f"{manifest}: workflow must call reusable study quality gate")
        require(re.search(r"^\s*cohort_path:\s*" +
                          re.escape(required_cohort_path) + r"\s*$",
                          workflow, re.MULTILINE) is not None,
                f"{manifest}: workflow quality gate must name the frozen cohort")
        require("aggregate_artifact:" in workflow and
                "phase_a_artifact:" in workflow and "phase_b_artifact:" in workflow,
                f"{manifest}: aggregate and both review phase artifacts required")
        checked.append(name)
    return checked


if __name__ == "__main__":
    try:
        studies = check(Path("."))
        print(json.dumps({"registered_studies": studies, "validated": len(studies)}))
    except (OSError, GateError) as exc:
        print(f"STUDY_REGISTRY_FAILED: {exc}", file=sys.stderr)
        sys.exit(2)
