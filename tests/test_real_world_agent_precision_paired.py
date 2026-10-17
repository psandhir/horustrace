"""Regression tests for the exact-source historical-versus-current agent audit."""
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from real_world_agent_precision_paired import compare, strict_source_matches

TRUTH = ROOT / "research" / "real-world-agent-security-2026"


class PairedAgentPrecisionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cohort = json.loads((TRUTH / "cohort.json").read_text())
        cls.overlay = json.loads((TRUTH / "agent-precision-adjudication-v1.json").read_text())
        cls.bridges = json.loads((TRUTH / "agent-precision-crossfile-review-v1.json").read_text())

    def reports(self):
        cases = []
        for source in self.cohort["cases"]:
            if source["framework_stratum"] == "langgraph":
                continue
            cases.append({
                "case_id": source["case_id"],
                "repo": source["repo"],
                "sha": source["sha"],
                "framework": source["framework_stratum"],
                "status": "success",
                "agent_node_audit": [],
                "comparisons": {"agent_entities": {"predicted": 0}},
            })
        self.assertEqual(len(cases), 145)
        base = {"study": "real-world-agent-security-2026", "cohort_cases": 145,
                "execution_mode": "postfix", "cases": cases}
        historical = {**copy.deepcopy(base), "scanner_sha": "418db4e29798a7d25df686dd7bccfd9fefa225bd"}
        current = {**copy.deepcopy(base), "scanner_sha": "9d3f05f8e26308f1777e649e30bb62a3e44bef3f"}
        return historical, current

    def test_same_source_same_ontology_zero_predictions(self):
        historical, current = self.reports()
        result = compare(historical, current, self.cohort, self.overlay, self.bridges, TRUTH)
        self.assertEqual(result["common_success_cases"], 145)
        self.assertEqual(result["metrics"]["baseline"]["agents"], 0)
        self.assertEqual(result["metrics"]["candidate"]["agents"], 0)
        self.assertFalse(result["metrics"]["candidate"]["certified_precision"])
        self.assertEqual(result["release_gate"].split(":")[0], "NOT_EVALUATED")

    def test_source_constructs_and_workflow_steps_are_distinct(self):
        historical, current = self.reports()
        case = next(c for c in current["cases"] if c["case_id"] == "rw-170")
        case["agent_node_audit"] = [
            {"kind": "agent", "name": "_agent",
             "location": {"path": "scraping_agent.py", "line": 53}},
            {"kind": "agent", "name": "_agent_custom",
             "location": {"path": "scraping_agent.py", "line": 53}},
            {"kind": "workflow_node", "name": "fake-step",
             "location": {"path": "scraping_agent.py", "line": 100}},
        ]
        case["comparisons"]["agent_entities"]["predicted"] = 3
        result = compare(historical, current, self.cohort, self.overlay, self.bridges, TRUTH)
        score = result["metrics"]["candidate"]
        self.assertEqual(score["matched_posthoc_source"], 2)
        self.assertEqual(score["workflow_nodes_excluded"], 1)
        self.assertEqual(score["unadjudicated"], 0)
        self.assertEqual(score["conditional_lower_if_all_unresolved_invalid"], 1.0)

    def test_cross_file_import_instance_same_identity_and_metadata_exclusion(self):
        historical, current = self.reports()
        baseline_case = next(c for c in historical["cases"] if c["case_id"] == "rw-004")
        baseline_case["agent_node_audit"] = [{
            "kind": "agent", "name": "agentGemini",
            "location": {"path": "adk.yaml", "line": 1},
        }]
        baseline_case["comparisons"]["agent_entities"]["predicted"] = 1
        for cid, path, line in (
            ("rw-084", "agent.py", 35),
            ("rw-110", "agent.py", 63),
        ):
            case = next(c for c in current["cases"] if c["case_id"] == cid)
            case["agent_node_audit"] = [{
                "kind": "agent", "name": "agent",
                "location": {"path": path, "line": line},
            }]
            case["comparisons"]["agent_entities"]["predicted"] = 1
        report = compare(historical, current, self.cohort, self.overlay, self.bridges, TRUTH)
        self.assertEqual(report["metrics"]["baseline"]["metadata_only_nodes_excluded"], 1)
        self.assertEqual(report["metrics"]["baseline"]["agents"], 0)
        self.assertEqual(report["metrics"]["candidate"]["matched_crossfile_implementation"], 2)
        self.assertEqual(report["metrics"]["candidate"]["unadjudicated"], 0)

    def test_crossfile_bridge_source_pin_mismatch_fails(self):
        historical, current = self.reports()
        review = copy.deepcopy(self.bridges)
        review["decisions"][0]["sha"] = "0" * 40
        with self.assertRaisesRegex(ValueError, "source SHA mismatch"):
            compare(historical, current, self.cohort, self.overlay, review, TRUTH)

    def test_source_scoped_match_prevents_cross_file_alias_collision(self):
        fact = [{"path": "agent.py", "line": 5, "name": "same_name"}]
        observed = [{"name": "same_name", "location": {"path": "different.py", "line": 5}}]
        self.assertEqual(strict_source_matches(fact, observed), set())

    def test_only_successful_cases_are_paired(self):
        historical, current = self.reports()
        historical["cases"][0]["status"] = "timeout"
        current["cases"][1]["status"] = "timeout"
        out = compare(historical, current, self.cohort, self.overlay, self.bridges, TRUTH)
        self.assertEqual(out["common_success_cases"], 143)
        self.assertEqual(out["baseline_success"], 144)
        self.assertEqual(out["candidate_success"], 144)

    def test_mismatched_pins_invocation_or_missing_witness_fail_closed(self):
        historical, current = self.reports()
        historical["execution_mode"] = "baseline"
        with self.assertRaisesRegex(ValueError, "same postfix"):
            compare(historical, current, self.cohort, self.overlay, self.bridges, TRUTH)
        historical, current = self.reports()
        current["cases"][0]["sha"] = "0" * 40
        with self.assertRaisesRegex(ValueError, "source revision"):
            compare(historical, current, self.cohort, self.overlay, self.bridges, TRUTH)
        historical, current = self.reports()
        current["cases"][0]["agent_node_audit"] = [
            {"kind": "agent", "name": "unwitnessed"}]
        current["cases"][0]["comparisons"]["agent_entities"]["predicted"] = 1
        with self.assertRaisesRegex(ValueError, "source path/line"):
            compare(historical, current, self.cohort, self.overlay, self.bridges, TRUTH)

    def test_wrong_scanner_version_cannot_produce_comparison(self):
        historical, current = self.reports()
        current["scanner_sha"] = "1" * 40
        with self.assertRaisesRegex(ValueError, "candidate is not pinned"):
            compare(historical, current, self.cohort, self.overlay, self.bridges, TRUTH)


if __name__ == "__main__":
    unittest.main()
