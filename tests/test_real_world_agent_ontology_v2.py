"""Tests for source-qualified, paired agent ontology V2 scoring."""
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from real_world_agent_ontology_v2 import score_one, score_pair

COHORT = ROOT / "research" / "real-world-agent-security-2026" / "cohort.json"


def witness(kind: str, name: str, path: str, line: int) -> dict:
    return {"kind": kind, "name": name, "location": {"path": path, "line": line}}


def truth(name: str, path: str, line: int, positive: bool) -> dict:
    return {"name": name, "location": {"path": path, "line": line}, "expected": positive}


def pair_data() -> tuple[dict, dict, dict, dict]:
    cohort = json.loads(COHORT.read_text(encoding="utf-8"))
    selected = [c for c in cohort["cases"] if c["framework_stratum"] != "langgraph"]
    assert len(selected) == 145
    old = []
    new = []
    refs = []
    for c in selected:
        common = {
            "case_id": c["case_id"], "repo": c["repo"],
            "sha": c["sha"], "framework": c["framework_stratum"],
            "status": "success", "agent_node_audit": [],
        }
        old.append(copy.deepcopy(common))
        new.append(copy.deepcopy(common))
        refs.append({
            "case_id": c["case_id"], "repo": c["repo"], "sha": c["sha"],
            "agent_inventory_exhaustive": True, "independent_review": True,
            "agent_sites": [],
        })
    return (
        cohort,
        {"cohort_cases": 145, "scanner_sha": "a" * 40, "cases": old},
        {"cohort_cases": 145, "scanner_sha": "b" * 40, "cases": new},
        {"scope": "non-langgraph-145", "cases": refs},
    )


class AgentOntologyV2Tests(unittest.TestCase):
    def test_workflow_steps_are_not_agent_false_positives(self) -> None:
        case = {
            "status": "success",
            "agent_node_audit": [
                witness("agent", "analyst", "agent.py", 10),
                witness("workflow_node", "flow:analyst", "agent.py", 30),
            ],
        }
        ref = {
            "agent_inventory_exhaustive": True, "independent_review": True,
            "agent_sites": [truth("analyst", "agent.py", 10, True)],
        }
        result = score_one(case, ref)
        self.assertEqual((result["tp"], result["fp"], result["fn"]), (1, 0, 0))
        self.assertEqual(result["workflow_nodes_excluded_from_agent_precision"], 1)
        self.assertEqual(result["precision"], 1.0)

    def test_same_name_different_paths_do_not_false_match(self) -> None:
        case = {"status": "success", "agent_node_audit": [witness("agent", "agent", "other.py", 10)]}
        ref = {
            "agent_inventory_exhaustive": True, "independent_review": True,
            "agent_sites": [truth("agent", "primary.py", 10, True)],
        }
        result = score_one(case, ref)
        self.assertEqual(result["tp"], 0)
        self.assertEqual(result["fn"], 1)
        self.assertEqual(result["unresolved_agent_candidates"], 1)
        self.assertIsNone(result["precision"])

    def test_duplicate_agent_source_identity_fails_closed(self) -> None:
        case = {"status": "success", "agent_node_audit": [
            witness("agent", "_agent", "scraping_agent.py", 53),
            witness("agent", "_agent", "scraping_agent.py", 53),
        ]}
        ref = {"agent_inventory_exhaustive": True, "independent_review": True, "agent_sites": []}
        with self.assertRaisesRegex(ValueError, "duplicate scanner identity"):
            score_one(case, ref)

    def test_distinct_factory_bound_instances_are_kept(self) -> None:
        case = {"status": "success", "agent_node_audit": [
            witness("agent", "_agent", "scraping_agent.py", 53),
            witness("agent", "_agent_custom", "scraping_agent.py", 53),
        ]}
        ref = {"agent_inventory_exhaustive": True, "independent_review": True, "agent_sites": [
            truth("_agent", "scraping_agent.py", 53, True),
            truth("_agent_custom", "scraping_agent.py", 53, True),
        ]}
        result = score_one(case, ref)
        self.assertEqual(result["tp"], 2)
        self.assertEqual(result["precision"], 1.0)

    def test_explicit_reviewed_negative_is_false_positive(self) -> None:
        case = {"status": "success", "agent_node_audit": [
            witness("agent", "fake", "test.py", 3),
            witness("agent", "real", "agent.py", 5),
        ]}
        ref = {"agent_inventory_exhaustive": True, "independent_review": True, "agent_sites": [
            truth("fake", "test.py", 3, False), truth("real", "agent.py", 5, True),
        ]}
        result = score_one(case, ref)
        self.assertEqual(result["precision"], 0.5)
        self.assertEqual(result["fp"], 1)

    def test_posthoc_overlay_never_certifies_release_precision(self) -> None:
        case = {"status": "success", "agent_node_audit": [witness("agent", "real", "agent.py", 5)]}
        ref = {"agent_inventory_exhaustive": True, "independent_review": False, "agent_sites": [
            truth("real", "agent.py", 5, True)
        ]}
        result = score_one(case, ref)
        self.assertFalse(result["certified"])
        self.assertIsNone(result["precision"])

    def test_v2_pair_on_same_pinned_145_cases(self) -> None:
        cohort, old, new, ref = pair_data()
        c = old["cases"][0]
        n = new["cases"][0]
        a = ref["cases"][0]
        positive = truth("a", "agent.py", 7, True)
        c["agent_node_audit"] = [witness("agent", "a", "agent.py", 7)]
        n["agent_node_audit"] = [witness("agent", "a", "agent.py", 7)]
        a["agent_sites"] = [positive]
        result = score_pair(cohort, old, new, ref)
        self.assertEqual(result["common_success_cases"], 145)
        self.assertEqual(result["baseline"]["precision"], 1.0)
        self.assertEqual(result["candidate"]["precision"], 1.0)

    def test_baseline_missing_a_graph_witness_rejected(self) -> None:
        cohort, old, new, ref = pair_data()
        del old["cases"][0]["agent_node_audit"]
        with self.assertRaisesRegex(ValueError, "per-node Graph witnesses"):
            score_pair(cohort, old, new, ref)

    def test_mismatched_source_sha_fails_closed(self) -> None:
        cohort, old, new, ref = pair_data()
        new["cases"][0]["sha"] = "0" * 40
        with self.assertRaisesRegex(ValueError, "source pin changed"):
            score_pair(cohort, old, new, ref)

    def test_failure_cannot_be_hidden_by_common_success_denominator(self) -> None:
        cohort, old, new, ref = pair_data()
        new["cases"][0]["status"] = "timeout"
        result = score_pair(cohort, old, new, ref)
        self.assertEqual(result["common_success_cases"], 144)
        self.assertFalse(result["candidate"]["certified"])
        self.assertIsNone(result["candidate"]["precision"])

    def test_unknown_agent_graph_kind_rejected(self) -> None:
        case = {"status": "success", "agent_node_audit": [witness("mystery", "x", "x.py", 9)]}
        with self.assertRaisesRegex(ValueError, "unexpected Graph node kinds"):
            score_one(case, {"agent_sites": [], "agent_inventory_exhaustive": True, "independent_review": True})


if __name__ == "__main__":
    unittest.main()
