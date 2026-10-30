"""Regression tests for the explicit 145-case, non-LangGraph study scope."""
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from real_world_agent_security_non_langgraph import analyze, scope_cases

ROOT = Path(__file__).resolve().parents[1] / "research" / "real-world-agent-security-2026"
DIMENSIONS = (
    "agent_entities",
    "tools",
    "mcp_servers",
    "delegation_edges",
    "effective_authority",
)


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def reports(cohort: dict) -> tuple[dict, dict]:
    rows = []
    for source in cohort["cases"]:
        rows.append(
            {
                "case_id": source["case_id"],
                "repo": source["repo"],
                "sha": source["sha"],
                "framework": source["framework_stratum"],
                "status": "success",
                "previously_studied": False,
                "observed": {},
                "findings": [],
                "comparisons": {
                    dimension: {
                        "truth": 1,
                        "predicted": 1,
                        "tp": 1,
                        "fn": 0,
                        "precision_eligible": True,
                        "precision_tp": 1,
                        "fp": 0,
                        "unadjudicated_predicted": 0,
                    }
                    for dimension in DIMENSIONS
                },
            }
        )
    common = {
        "study": "real-world-agent-security-2026",
        "cohort_cases": 180,
        "cases": rows,
    }
    return (
        {**copy.deepcopy(common), "scanner_sha": cohort["scanner_freeze_sha"], "execution_mode": "baseline"},
        {**copy.deepcopy(common), "scanner_sha": "a" * 40, "execution_mode": "postfix"},
    )


class NonLangGraphStudyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cohort = load(ROOT / "cohort.json")
        cls.benchmark = load(ROOT / "semantic-benchmark" / "benchmark-v1.json")

    def test_non_langgraph_145_integrity_and_full_reaggregation(self) -> None:
        original = copy.deepcopy(self.cohort)
        before, after = reports(original)
        source_cohort, excluded, baseline, candidate = scope_cases(
            original, before, after
        )
        self.assertEqual(len(excluded), 35)
        self.assertEqual(len(source_cohort["cases"]), 145)
        self.assertEqual(baseline["cohort_cases"], 145)
        self.assertEqual(candidate["cohort_cases"], 145)
        self.assertEqual(candidate["summary"]["successful_cases"], 145)
        self.assertEqual(candidate["metrics"]["agent_entities"]["recall"], 1.0)
        self.assertEqual(candidate["metrics"]["agent_entities"]["precision"], 1.0)
        self.assertEqual(candidate["evaluation_scope"]["excluded_framework"], "langgraph")
        self.assertEqual(original, self.cohort)
        self.assertEqual(len(before["cases"]), 180)
        self.assertEqual(len(after["cases"]), 180)

    def test_already_scanned_145_is_accepted_with_original_180_baseline(self) -> None:
        before, after = reports(self.cohort)
        after["cases"] = [
            row for row in after["cases"] if row["framework"] != "langgraph"
        ]
        after["cohort_cases"] = 145
        scoped, excluded, baseline, candidate = scope_cases(
            self.cohort, before, after
        )
        self.assertEqual(len(excluded), 35)
        self.assertEqual(len(scoped["cases"]), 145)
        self.assertEqual(baseline["cohort_cases"], candidate["cohort_cases"])
        self.assertEqual(candidate["summary"]["successful_cases"], 145)

    def test_active_gates_keep_six_original_thresholds(self) -> None:
        before, after = reports(self.cohort)
        _, _, delta, semantic = analyze(
            self.cohort, before, after, self.benchmark
        )
        self.assertTrue(delta["active_non_langgraph_gates_met"])
        self.assertEqual(len(delta["active_non_langgraph_gates"]), 6)
        self.assertEqual(delta["excluded_release_gates"], [
            "langgraph_agent_recall", "langgraph_tool_recall"
        ])
        self.assertNotIn("v09_gates_met", delta)
        self.assertEqual(semantic["excluded_semantic_case_ids"], ["rw-058"])
        self.assertEqual(semantic["assertions"], 17)

    def test_source_framework_tampering_fails_closed(self) -> None:
        before, after = reports(self.cohort)
        after["cases"][0]["framework"] = "langgraph"
        with self.assertRaisesRegex(ValueError, "framework drift"):
            scope_cases(self.cohort, before, after)

    def test_missing_or_duplicate_case_fails_closed(self) -> None:
        before, after = reports(self.cohort)
        after["cases"].pop()
        with self.assertRaisesRegex(ValueError, "missing report case"):
            scope_cases(self.cohort, before, after)
        _, after = reports(self.cohort)
        after["cases"][1] = copy.deepcopy(after["cases"][0])
        with self.assertRaisesRegex(ValueError, "unexpected or duplicate"):
            scope_cases(self.cohort, before, after)

    def test_selection_drift_fails_closed(self) -> None:
        modified = copy.deepcopy(self.cohort)
        modified["cases"][0]["framework_stratum"] = "langgraph"
        before, after = reports(self.cohort)
        with self.assertRaisesRegex(ValueError, "composition drift"):
            scope_cases(modified, before, after)

    def test_non_langgraph_precision_degradation_does_not_disappear(self) -> None:
        before, after = reports(self.cohort)
        non_langgraph = next(
            row for row in after["cases"]
            if row["framework"] == "pydantic-ai"
        )
        non_langgraph["comparisons"]["agent_entities"]["fp"] = 4
        _, _, delta, _ = analyze(self.cohort, before, after, self.benchmark)
        self.assertLess(
            delta["metric_deltas"]["agent_entities"]["precision"]["candidate"], 1
        )
        self.assertIn(
            "overall_agent_precision",
            {g["name"] for g in delta["active_non_langgraph_gates"]}
        )


if __name__ == "__main__":
    unittest.main()
