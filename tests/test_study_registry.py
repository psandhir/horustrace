from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.check_study_registry import check
from scripts.study_evaluation_gate import GateError


class StudyRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        self.study_dir = self.repo / "research/studies/test-01"
        self.study_dir.mkdir(parents=True)
        self.workflow_dir = self.repo / ".github/workflows"
        self.workflow_dir.mkdir(parents=True)
        self.cohort = {
            "schema_version": 1, "study": "test-01", "locked_at": "2026-10-08",
            "selection": {
                "method": "Independent source-only holdout",
                "target_repositories": 1,
                "current_main_output_used_for_selection": False,
            },
            "cases": [{
                "case_id": "case-01", "repo": "example/agent",
                "sha": "a" * 40, "framework": "anthropic",
                "application_path": ".",
            }],
        }
        self.descriptor = {
            "study": "test-01",
            "cohort_path": "research/studies/test-01/cohort.json",
            "workflow_path": ".github/workflows/test-01.yml",
            "quality_gate_required": True,
        }
        self.workflow = """
name: Test study
jobs:
  quality:
    uses: ./.github/workflows/reusable-study-quality-gate.yml
    with:
      cohort_path: research/studies/test-01/cohort.json
      case_artifact_pattern: case-*
      aggregate_artifact: cohort-aggregate
      phase_a_artifact: blind-judges
      phase_b_artifact: revealed-scores
"""
        self.save()

    def save(self):
        (self.study_dir / "cohort.json").write_text(json.dumps(self.cohort))
        (self.study_dir / "study.json").write_text(json.dumps(self.descriptor))
        (self.workflow_dir / "test-01.yml").write_text(self.workflow)

    def test_registered_study_uses_release_gate(self):
        self.assertEqual(check(self.repo), ["test-01"])

    def test_missing_reusable_gate_rejected(self):
        self.workflow = self.workflow.replace(
            "    uses: ./.github/workflows/reusable-study-quality-gate.yml",
            "    runs-on: ubuntu-latest",
        )
        self.save()
        with self.assertRaisesRegex(GateError, "must call reusable"):
            check(self.repo)

    def test_cohort_must_be_pinned_and_independent(self):
        self.cohort["cases"][0]["sha"] = "main"
        self.save()
        with self.assertRaisesRegex(GateError, "invalid commit"):
            check(self.repo)

    def test_study_cannot_hide_under_unregistered_subfolder(self):
        (self.study_dir / "study.json").unlink()
        with self.assertRaisesRegex(GateError, "missing study.json"):
            check(self.repo)

    def test_must_reference_correct_cohort(self):
        self.workflow = self.workflow.replace(
            "cohort_path: research/studies/test-01/cohort.json",
            "cohort_path: research/studies/other/cohort.json",
        )
        self.save()
        with self.assertRaisesRegex(GateError, "name the frozen cohort"):
            check(self.repo)


if __name__ == "__main__":
    unittest.main()
