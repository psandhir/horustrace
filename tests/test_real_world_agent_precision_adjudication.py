"""Fail-closed tests for the source-backed agent-precision diagnostic."""
from __future__ import annotations

import copy
import json
import sys
import unittest
from collections import defaultdict
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / "scripts"))
from real_world_agent_precision_adjudication import evaluate

ROOT = BASE / "research" / "real-world-agent-security-2026"


class AgentPrecisionAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cohort = json.loads((ROOT / "cohort.json").read_text())
        cls.overlay = json.loads((ROOT / "agent-precision-adjudication-v1.json").read_text())

    def candidate(self):
        nodes = defaultdict(list)
        for item in self.overlay["classifications"]:
            nodes[item["case_id"]].append({
                "kind": item["node_kind"],
                "name": item["node_name"],
                "location": {"path": item["source_path"], "line": item["source_line"]},
                "matched_locked_reference": False,
            })
        cases = []
        for row in self.cohort["cases"]:
            if row["framework_stratum"] == "langgraph":
                continue
            case_nodes = nodes[row["case_id"]]
            cases.append({
                "case_id": row["case_id"], "repo": row["repo"],
                "sha": row["sha"], "framework": row["framework_stratum"],
                "status": "success",
                "agent_node_audit": case_nodes,
                "comparisons": {"agent_entities": {
                    "precision_eligible": True, "precision_tp": 0,
                    "predicted": len(case_nodes), "fp": len(case_nodes),
                }},
            })
        self.assertEqual(len(cases), 145)
        return {"study": "real-world-agent-security-2026",
                "cohort_cases": 145, "scanner_sha": "a" * 40, "cases": cases}

    def test_31_source_witnesses_and_policy_are_exact(self):
        report = evaluate(self.candidate(), self.cohort, self.overlay)
        self.assertEqual(report["classifications"],
                         {"source_supported_agent": 17, "workflow_step_not_agent": 12,
                          "taxonomy_unresolved": 2})
        self.assertTrue(report["original_locked_truth_preserved"])
        self.assertFalse(report["posthoc_support_sensitivity"]["certified_precision"])
        self.assertEqual(report["matched_workflow_nodes"], 0)
        self.assertEqual(report["successful_cases"], 145)

    def test_source_pins_and_case_identity_cannot_change(self):
        cand = self.candidate()
        cand["cases"][0]["sha"] = "f" * 40
        with self.assertRaisesRegex(ValueError, "source SHA"):
            evaluate(cand, self.cohort, self.overlay)
        cand = self.candidate()
        cand["cases"].pop()
        with self.assertRaisesRegex(ValueError, "missing candidate cases"):
            evaluate(cand, self.cohort, self.overlay)

    def test_unreviewed_or_stale_graph_candidates_fail_closed(self):
        cand = self.candidate()
        case = next(c for c in cand["cases"] if c["case_id"] == "rw-025")
        case["agent_node_audit"][0]["name"] = "spurious_extra_agent"
        with self.assertRaisesRegex(ValueError, "unreviewed or stale"):
            evaluate(cand, self.cohort, self.overlay)
        cand = self.candidate()
        case = next(c for c in cand["cases"] if c["case_id"] == "rw-025")
        case["agent_node_audit"].pop()
        with self.assertRaisesRegex(ValueError, "full Graph witnesses"):
            evaluate(cand, self.cohort, self.overlay)

    def test_overlay_cannot_silently_rewrite_frozen_truth(self):
        cand = self.candidate()
        overlay = copy.deepcopy(self.overlay)
        overlay["classifications"][0]["source_sha"] = "1" * 40
        with self.assertRaisesRegex(ValueError, "overlay source pin"):
            evaluate(cand, self.cohort, overlay)
        overlay = copy.deepcopy(self.overlay)
        overlay["classifications"][0]["classification"] = "taxonomy_unresolved"
        with self.assertRaisesRegex(ValueError, "ontology"):
            evaluate(cand, self.cohort, overlay)

    def test_already_matched_workflow_must_not_be_agent_tp(self):
        cand = self.candidate()
        case = next(c for c in cand["cases"] if c["case_id"] == "rw-006")
        case["agent_node_audit"] = [{
            "kind": "workflow_node", "name": "entrypoint:workflow_step",
            "location": {"path": "src.py", "line": 3},
            "matched_locked_reference": True,
        }]
        case["comparisons"]["agent_entities"].update({"precision_tp": 1, "predicted": 1})
        report = evaluate(cand, self.cohort, self.overlay)
        self.assertEqual(report["matched_workflow_nodes"], 1)
        self.assertEqual(report["agent_kind_only_sensitivity"]["tp"], 0)


if __name__ == "__main__":
    unittest.main()
