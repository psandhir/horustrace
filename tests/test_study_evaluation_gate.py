from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import study_evaluation_gate as gate


SHA = "a" * 40
SCANNER_SHA = "b" * 40
PROMPT_SHA = "c" * 64


class StudyEvaluationGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cohort = {
            "schema_version": 1,
            "study": "fresh-test",
            "locked_at": "2026-10-08",
            "selection": {
                "method": "Independent source-only discovery",
                "current_main_output_used_for_selection": False,
                "target_repositories": 1,
            },
            "cases": [{
                "case_id": "case-01", "repo": "some/repo", "sha": SHA,
                "framework": "anthropic", "application_path": ".",
            }],
        }
        self.cohort_file = self.write("cohort.json", self.cohort)
        self.result = {
            "schema_version": 1, "study": "fresh-test", "case_id": "case-01",
            "repo": "some/repo", "sha": SHA, "framework": "anthropic",
            "application_path": ".", "source_pack_chars": 13,
            "scanner_sha": SCANNER_SHA, "harness_sha": SCANNER_SHA,
            "counts": {"agents": 1, "findings": 1, "attack_paths": 1, "diagnostics": 0},
            "attack_paths": [{"path_id": "PATH001", "nodes": ["input", "bash"]}],
            "findings": [{"rule_id": "AGT040", "severity": "high"}],
        }
        self.results_dir = self.root / "results" / "case-01"
        self.results_dir.mkdir(parents=True)
        (self.results_dir / "source-pack.txt").write_text("source\nagent\n", encoding="utf-8")
        (self.results_dir / "result.json").write_text(
            json.dumps(self.result), encoding="utf-8"
        )
        for filename, doc in (
            ("scan.json", {"findings": self.result["findings"]}),
            ("security-graph.json", {"attack_paths": self.result["attack_paths"]}),
            ("effective-authority.json", {"summary": {}}),
            ("authority-contract.json", {"summary": {}}),
        ):
            (self.results_dir / filename).write_text(json.dumps(doc), encoding="utf-8")
        self.judges = [{
            "reviewer_id": key,
            "provider": "openai" if key == "judge-1" else "google",
            "model": "model-v1",
            "execution_id": "run-" + key,
            "prompt_version": "v1", "prompt_sha256": PROMPT_SHA,
            "independent_review": True, "scanner_output_seen": False,
            "locked": True, "locked_at": "2026-10-08T11:00:00Z",
        } for key in ("judge-1", "judge-2")]
        self.phase_a = {
            "study": "fresh-test", "cohort_sha256": gate.digest(self.cohort_file),
            "scanner_output_seen": False, "locked_at": "2026-10-08T11:10:00Z",
            "reviewers": self.judges,
            "cases": [{
                "case_id": "case-01", "sha": SHA, "source_coverage": "complete",
                "reviews": [{
                    "reviewer_id": judge["reviewer_id"], "locked": True,
                    "scanner_output_seen": False,
                    "source_evidence": [{"path": "agent.py", "line": 1}],
                    "coverage_assertion": "enumerated_candidates",
                    "candidate_paths": [{
                        "verdict": "valid", "rationale": "Source-to-sink provenance",
                        "candidate_id": "candidate-1",
                        "evidence": [{"path": "agent.py", "line": 3}],
                    }],
                } for judge in self.judges],
                "consensus_paths": [{
                    "candidate_id": "candidate-1", "verdict": "valid",
                    "review_status": "agreement",
                    "rationale": "A supported source-backed path",
                    "evidence": [{"path": "agent.py", "line": 3}],
                }],
            }],
        }
        self.phase_a_file = self.write("phase-a.json", self.phase_a)
        self.phase_b = {
            "study": "fresh-test", "phase_a_sha256": gate.digest(self.phase_a_file),
            "scanner_sha": SCANNER_SHA,
            "revealed_at": "2026-10-08T11:20:00Z",
            "cases": [{
                "case_id": "case-01",
                "candidate_assessments": [{
                    "candidate_id": "candidate-1", "outcome": "matched",
                    "scanner_path_indexes": [0],
                    "rationale": "Same supported path",
                }],
                "finding_reviews": [{
                    "index": 0, "verdict": "supported",
                    "independent_review": True,
                    "reviewer_attestations": [
                        {
                            "reviewer_id": j["reviewer_id"],
                            "provider": j["provider"], "model": j["model"],
                            "execution_id": "finding-" + j["execution_id"],
                            "verdict": "supported", "independent_review": True,
                            "rule_metadata_seen": False, "locked": True,
                            "evidence": [{"path": "agent.py", "line": 4}],
                        } for j in self.judges
                    ],
                    "rationale": "Observed action and control",
                    "evidence": [{"path": "agent.py", "line": 4}],
                }],
            }],
        }
        self.phase_b_file = self.write("phase-b.json", self.phase_b)

    def write(self, name: str, obj: dict) -> Path:
        path = self.root / name
        path.write_text(json.dumps(obj), encoding="utf-8")
        return path

    def validate(self):
        cases = gate.validate_cohort(self.cohort)
        results, _ = gate.read_results(self.root / "results", self.cohort, cases)
        pa = gate.review_phase_a(
            self.phase_a, self.cohort, cases, gate.digest(self.cohort_file)
        )
        return gate.review_phase_b(
            self.phase_b, self.cohort, cases, results, pa,
            gate.digest(self.phase_a_file), self.phase_a["locked_at"],
        )

    def test_complete_source_adjudication_passes(self):
        self.assertEqual(self.validate()["counts"]["matched"], 1)

    def test_new_study_must_not_select_from_scanner(self):
        self.cohort["selection"]["current_main_output_used_for_selection"] = True
        with self.assertRaisesRegex(gate.GateError, "independent"):
            gate.validate_cohort(self.cohort)

    def test_duplicate_repository_rejected(self):
        case2 = dict(self.cohort["cases"][0], case_id="case-02")
        self.cohort["cases"].append(case2)
        self.cohort["selection"]["target_repositories"] = 2
        with self.assertRaisesRegex(gate.GateError, "reused repository"):
            gate.validate_cohort(self.cohort)

    def test_result_study_must_match(self):
        self.result["study"] = "old-frozen-60"
        (self.results_dir / "result.json").write_text(json.dumps(self.result))
        with self.assertRaisesRegex(gate.GateError, "study mismatch"):
            gate.read_results(self.root / "results", self.cohort, gate.validate_cohort(self.cohort))

    def test_missing_case_result_rejected(self):
        (self.results_dir / "result.json").unlink()
        with self.assertRaisesRegex(gate.GateError, "expected 1 result"):
            gate.read_results(self.root / "results", self.cohort, gate.validate_cohort(self.cohort))

    def test_source_pack_must_match(self):
        (self.results_dir / "source-pack.txt").write_text("tiny")
        with self.assertRaisesRegex(gate.GateError, "source pack"):
            gate.read_results(self.root / "results", self.cohort, gate.validate_cohort(self.cohort))

    def test_unblinded_judge_rejected(self):
        self.phase_a["reviewers"][0]["scanner_output_seen"] = True
        with self.assertRaisesRegex(gate.GateError, "independently blinded"):
            self.validate()

    def test_independent_execution_ids_required(self):
        self.phase_a["reviewers"][1]["execution_id"] = "run-judge-1"
        with self.assertRaisesRegex(gate.GateError, "execution IDs"):
            self.validate()

    def test_missing_source_line_rejected(self):
        del self.phase_a["cases"][0]["reviews"][1]["source_evidence"][0]["line"]
        with self.assertRaisesRegex(gate.GateError, "positive source line"):
            self.validate()

    def test_every_judge_candidate_must_be_adjudicated(self):
        self.phase_a["cases"][0]["consensus_paths"] = []
        with self.assertRaisesRegex(gate.GateError, "all judge candidates"):
            self.validate()

    def test_missing_source_requires_limitation(self):
        self.phase_a["cases"][0]["source_coverage"] = "qualified"
        with self.assertRaisesRegex(gate.GateError, "source limitations"):
            self.validate()

    def test_scanner_reveal_must_follow_lock(self):
        self.phase_b["revealed_at"] = "2026-10-08T11:00:00Z"
        with self.assertRaisesRegex(gate.GateError, "before phase A"):
            self.validate()

    def test_phase_a_hash_must_match_locked_file(self):
        self.phase_b["phase_a_sha256"] = "0" * 64
        with self.assertRaisesRegex(gate.GateError, "digest mismatch"):
            self.validate()

    def test_cannot_claim_matched_when_no_scanner_path(self):
        self.phase_b["cases"][0]["candidate_assessments"][0]["scanner_path_indexes"] = []
        with self.assertRaisesRegex(gate.GateError, "without scanner path"):
            self.validate()

    def test_missed_path_cannot_have_scanner_match(self):
        row = self.phase_b["cases"][0]["candidate_assessments"][0]
        row["outcome"] = "missed"
        with self.assertRaisesRegex(gate.GateError, "cannot have scanner match"):
            self.validate()

    def test_unreviewed_high_finding_rejected(self):
        self.phase_b["cases"][0]["finding_reviews"] = []
        with self.assertRaisesRegex(gate.GateError, "insufficient finding sample"):
            self.validate()

    def test_invalid_path_verdict_not_counted_as_miss(self):
        self.phase_a["cases"][0]["consensus_paths"][0]["verdict"] = "invalid"
        for r in self.phase_a["cases"][0]["reviews"]:
            r["candidate_paths"][0]["verdict"] = "invalid"
        self.phase_b["cases"][0]["candidate_assessments"][0].update(
            outcome="invalid", scanner_path_indexes=[]
        )
        self.assertEqual(self.validate()["counts"]["invalid"], 1)

    def test_g1_reports_pass_but_blocks_quality(self):
        out = self.root / "report.json"
        with patch.object(sys, "argv", [
            "study_evaluation_gate.py", "--cohort", str(self.cohort_file),
            "--results", str(self.root / "results"), "--output", str(out),
        ]), contextlib.redirect_stdout(io.StringIO()):
            exit_code = gate.main()
        report = gate.load(out)
        self.assertEqual(exit_code, 2)
        self.assertEqual(report["execution_gate"], "passed")
        self.assertEqual(report["release_gate"], "blocked")
        self.assertEqual(report["adjudication_gate"], "not_run")

    def test_g3_passes_with_review_and_evidence(self):
        out = self.root / "report.json"
        with patch.object(sys, "argv", [
            "study_evaluation_gate.py", "--cohort", str(self.cohort_file),
            "--results", str(self.root / "results"),
            "--phase-a", str(self.phase_a_file),
            "--phase-b", str(self.phase_b_file),
            "--output", str(out),
        ]), contextlib.redirect_stdout(io.StringIO()):
            exit_code = gate.main()
        report = gate.load(out)
        self.assertEqual(exit_code, 0)
        self.assertEqual(report["release_gate"], "passed")

    def test_false_consensus_is_rejected(self):
        self.phase_a["cases"][0]["reviews"][1]["candidate_paths"][0]["verdict"] = "invalid"
        with self.assertRaisesRegex(gate.GateError, "claimed agreement"):
            self.validate()

    def test_finding_requires_two_independent_judges(self):
        self.phase_b["cases"][0]["finding_reviews"][0]["reviewer_attestations"].pop()
        with self.assertRaisesRegex(gate.GateError, "two blinded independent"):
            self.validate()

    def test_missing_security_graph_rejected(self):
        (self.results_dir / "security-graph.json").unlink()
        with self.assertRaisesRegex(gate.GateError, "security-graph.json"):
            gate.read_results(self.root / "results", self.cohort, gate.validate_cohort(self.cohort))

    def test_missing_scanner_revision_rejected(self):
        del self.result["scanner_sha"]
        (self.results_dir / "result.json").write_text(json.dumps(self.result))
        with self.assertRaisesRegex(gate.GateError, "scanner_sha"):
            gate.read_results(self.root / "results", self.cohort, gate.validate_cohort(self.cohort))

    def test_partial_valid_path_blocks_quality(self):
        self.phase_b["cases"][0]["candidate_assessments"][0]["outcome"] = "partial"
        self.write("phase-b.json", self.phase_b)
        out = self.root / "report.json"
        with patch.object(sys, "argv", [
            "study_evaluation_gate.py", "--cohort", str(self.cohort_file),
            "--results", str(self.root / "results"),
            "--phase-a", str(self.phase_a_file),
            "--phase-b", str(self.phase_b_file),
            "--output", str(out),
        ]), contextlib.redirect_stdout(io.StringIO()):
            exit_code = gate.main()
        self.assertEqual(exit_code, 2)
        self.assertEqual(gate.load(out)["blocking_reasons"]["partial_valid_path_coverage"], 1)

    def test_source_valid_miss_blocks_quality(self):
        self.phase_b["cases"][0]["candidate_assessments"][0].update(
            outcome="missed", scanner_path_indexes=[]
        )
        self.write("phase-b.json", self.phase_b)
        out = self.root / "report.json"
        with patch.object(sys, "argv", [
            "study_evaluation_gate.py", "--cohort", str(self.cohort_file),
            "--results", str(self.root / "results"),
            "--phase-a", str(self.phase_a_file),
            "--phase-b", str(self.phase_b_file),
            "--output", str(out),
        ]), contextlib.redirect_stdout(io.StringIO()):
            exit_code = gate.main()
        self.assertEqual(exit_code, 2)
        self.assertEqual(gate.load(out)["blocking_reasons"]["confirmed_candidate_misses"], 1)


if __name__ == "__main__":
    unittest.main()
