"""Exact source-pinned historical/current agent-node differential tests."""
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from real_world_agent_node_delta import HISTORICAL_SHA, analyze, assess_source_study_completion

COHORT = ROOT / "research" / "real-world-agent-security-2026" / "cohort.json"


def sample():
    cohort = json.loads(COHORT.read_text(encoding="utf-8"))
    rows = [x for x in cohort["cases"] if x["framework_stratum"] != "langgraph"]
    assert len(rows) == 145
    cases = [
        {
            "case_id": x["case_id"], "repo": x["repo"], "sha": x["sha"],
            "framework": x["framework_stratum"], "status": "success",
            "comparisons": {"agent_entities": {"predicted": 0}},
            "agent_node_audit": [],
        }
        for x in rows
    ]
    hist = {"study": "real-world-agent-security-2026", "scanner_sha": HISTORICAL_SHA,
            "cohort_cases": 145, "cases": copy.deepcopy(cases)}
    candidate = {"study": "real-world-agent-security-2026", "scanner_sha": "a" * 40,
                 "cohort_cases": 145, "cases": copy.deepcopy(cases)}
    return cohort, hist, candidate


def node(kind, name, path, line):
    return {"kind": kind, "name": name, "location": {"path": path, "line": line}}


class NodeDeltaTests(unittest.TestCase):
    def test_exact_same_pinned_panel_no_delta(self):
        c, a, b = sample()
        result = analyze(c, a, b)
        self.assertEqual(result["summary"]["common_success"], 145)
        self.assertEqual(result["summary"].get("added_agent", 0), 0)
        self.assertTrue(result["release_eligible"])
        self.assertFalse(result["accuracy_certified"])

    def test_agent_added_and_workflow_excluded_from_agent_delta(self):
        c, a, b = sample()
        b["cases"][0]["agent_node_audit"] = [
            node("agent", "reviewer", "agent.py", 12),
            node("workflow_node", "run:reviewer", "agent.py", 22),
        ]
        b["cases"][0]["comparisons"]["agent_entities"]["predicted"] = 2
        result = analyze(c, a, b)
        self.assertEqual(result["summary"]["added_agent"], 1)
        self.assertEqual(result["summary"]["added_workflow_node"], 1)
        self.assertEqual(result["summary"]["current_agent_nodes"], 1)
        self.assertFalse(result["accuracy_certified"])

    def test_different_path_same_name_counts_distinct_identity(self):
        c, a, b = sample()
        a["cases"][0]["agent_node_audit"] = [node("agent", "agent", "first.py", 10)]
        b["cases"][0]["agent_node_audit"] = [node("agent", "agent", "second.py", 10)]
        a["cases"][0]["comparisons"]["agent_entities"]["predicted"] = 1
        b["cases"][0]["comparisons"]["agent_entities"]["predicted"] = 1
        result = analyze(c, a, b)
        self.assertEqual(result["summary"]["removed_agent"], 1)
        self.assertEqual(result["summary"]["added_agent"], 1)

    def test_explicit_scan_failures_preserved_and_not_go(self):
        c, a, b = sample()
        b["cases"][0]["status"] = "timeout"
        b["cases"][0]["sha"] = None
        b["cases"][0]["error"] = "scan timeout"
        result = analyze(c, a, b)
        self.assertEqual(result["summary"]["common_success"], 144)
        self.assertEqual(result["summary"]["not_common_success"], 1)
        self.assertFalse(result["release_eligible"])

    def test_failed_cases_without_sha_are_execution_failures_not_source_drift(self):
        c, a, b = sample()
        a["cases"][0].update({"status": "scanner_error", "sha": None, "error": "scan_exit_1:PermissionError"})
        b["cases"][1].update({"status": "timeout", "sha": None, "error": "security-graph timeout"})
        result = analyze(c, a, b)
        self.assertEqual(result["summary"]["common_success"], 143)
        self.assertEqual(result["summary"]["not_common_success"], 2)
        self.assertFalse(result["release_eligible"])
        failed = [row for row in result["cases"] if row["historical_status"] != "success" or row["current_status"] != "success"]
        self.assertEqual(len(failed), 2)
        self.assertIn("PermissionError", failed[0]["historical_error"])

    def test_failed_case_spoofed_sha_still_rejected(self):
        c, a, b = sample()
        b["cases"][0].update({"status": "timeout", "sha": "b" * 40, "error": "scan timeout"})
        with self.assertRaisesRegex(ValueError, "source pin drift"):
            analyze(c, a, b)

    def test_failed_case_missing_error_is_rejected(self):
        c, a, b = sample()
        b["cases"][0].update({"status": "timeout", "sha": None})
        with self.assertRaisesRegex(ValueError, "failed case missing execution evidence"):
            analyze(c, a, b)

    def test_archived_known_rw177_only_can_complete_source_evidence_not_release(self):
        c, a, b = sample()
        target = next(row for row in a["cases"] if row["case_id"] == "rw-177")
        target.update({
            "status": "scanner_error",
            "sha": None,
            "error": "scan_exit_1: PermissionError: bazel-testlogs",
        })
        report = analyze(c, a, b)
        self.assertFalse(report["release_eligible"])
        self.assertFalse(report["accuracy_certified"])
        self.assertEqual(report["summary"]["common_success"], 144)
        self.assertEqual(
            assess_source_study_completion(report),
            "legacy_144_only_not_paired_release_eligible",
        )

    def test_archival_exception_never_masks_current_failure(self):
        c, a, b = sample()
        old = next(row for row in a["cases"] if row["case_id"] == "rw-177")
        old.update({
            "status": "scanner_error", "sha": None,
            "error": "scan_exit_1: PermissionError: bazel-testlogs",
        })
        b["cases"][0].update({
            "status": "timeout", "sha": None, "error": "security-graph timeout",
        })
        with self.assertRaisesRegex(ValueError, "current 145/145 reliability NOT MET"):
            assess_source_study_completion(analyze(c, a, b))

    def test_other_historical_failure_not_accepted_as_known_exception(self):
        c, a, b = sample()
        old = next(row for row in a["cases"] if row["case_id"] == "rw-177")
        old.update({
            "status": "scanner_error", "sha": None,
            "error": "different crash",
        })
        with self.assertRaisesRegex(ValueError, "not the exact documented"):
            assess_source_study_completion(analyze(c, a, b))

    def test_complete_145_paired_study_still_distinct_from_accuracy(self):
        c, a, b = sample()
        report = analyze(c, a, b)
        self.assertTrue(report["release_eligible"])
        self.assertFalse(report["accuracy_certified"])
        self.assertEqual(assess_source_study_completion(report), "paired_145_complete")

    def test_historical_scanner_sha_locked(self):
        c, a, b = sample()
        a["scanner_sha"] = "a" * 40
        with self.assertRaisesRegex(ValueError, "scanner SHA changed"):
            analyze(c, a, b)

    def test_missing_source_witnesses_are_not_ignored(self):
        c, a, b = sample()
        del a["cases"][0]["agent_node_audit"]
        with self.assertRaisesRegex(ValueError, "per-node witnesses"):
            analyze(c, a, b)

    def test_duplicate_agent_identity_rejected(self):
        c, a, b = sample()
        a["cases"][0]["agent_node_audit"] = [
            node("agent", "a", "src.py", 3),
            node("agent", "a", "src.py", 3),
        ]
        a["cases"][0]["comparisons"]["agent_entities"]["predicted"] = 2
        with self.assertRaisesRegex(ValueError, "duplicate Graph source identity"):
            analyze(c, a, b)

    def test_graph_count_disagreement_rejected(self):
        c, a, b = sample()
        b["cases"][0]["agent_node_audit"] = [node("agent", "x", "x.py", 9)]
        with self.assertRaisesRegex(ValueError, "witness count"):
            analyze(c, a, b)

    def test_changed_source_pin_rejected(self):
        c, a, b = sample()
        b["cases"][0]["sha"] = "b" * 40
        with self.assertRaisesRegex(ValueError, "source pin drift"):
            analyze(c, a, b)

    def test_missing_case_fails_closed(self):
        c, a, b = sample()
        b["cases"].pop()
        with self.assertRaisesRegex(ValueError, "exactly 145"):
            analyze(c, a, b)

    def test_wrong_framework_rejected(self):
        c, a, b = sample()
        b["cases"][0]["framework"] = "langgraph"
        with self.assertRaisesRegex(ValueError, "source pin drift"):
            analyze(c, a, b)


if __name__ == "__main__":
    unittest.main()
