from __future__ import annotations

import unittest

from scripts.frozen180_llm_provisional_compare import _candidate_matches, compare_case
from scripts.run_frozen180_source_llm_review import api_schema, make_input


class ProvisionalComparisonTests(unittest.TestCase):
    def test_rule_and_source_alignment_without_auto_verity(self):
        claim = {
            "id": "finding-1", "issue_type": "approval_gap",
            "agent_id": "agent-1", "support_status": "conditional",
            "evidence": [{
                "path": "app/tools.py", "line_start": 42,
                "line_end": 42, "quote": None, "claim": "tool invocation",
            }],
        }
        findings = [{
            "scanner_finding_index": 4, "rule": "AGT040", "source_path": "app/tools.py",
            "line": 45,
        }, {
            "scanner_finding_index": 5, "rule": "CAP005", "source_path": "unrelated.py",
            "line": 42,
        }]
        matches = _candidate_matches(claim, findings, path_mode=False,
                                     names={"agent-1": "orchestrator"})
        self.assertEqual([r["scanner_index"] for r in matches], [4])
        self.assertEqual(matches[0]["matching_status"],
                         "unresolved_pending_adjudication")
        self.assertTrue(matches[0]["signals"]["nearby_line"])

    def test_path_matching_never_claims_true_positive(self):
        path = {
            "id": "p-1", "support_status": "source_supported",
            "agent_id": "agent-1", "sink_kind": "process_execute",
            "evidence": [{
                "path": "app.py", "line_start": 12, "line_end": 12,
                "claim": "source to sink", "quote": None,
            }],
        }
        rows = [{
            "index": 0,
            "path": {
                "path_id": "PATH001", "agent": "orchestrator",
                "location": {"path": "app.py", "line": 12},
                "metadata": {"sink_kind": "process_execute"},
            },
        }]
        matches = _candidate_matches(path, rows, path_mode=True,
                                     names={"agent-1": "orchestrator"})
        self.assertEqual(len(matches), 1)
        self.assertTrue(matches[0]["signals"]["agent_name_compatible"])
        self.assertEqual(matches[0]["matching_status"],
                         "unresolved_pending_adjudication")

    def test_unmatched_llm_candidate_is_not_premature_false_negative(self):
        review = {
            "case_id": "rw-038", "entities": [{"id": "agent-1", "name": "orchestrator"}],
            "findings": [{
                "id": "f-1", "issue_type": "approval_gap",
                "agent_id": "agent-1", "support_status": "conditional",
                "evidence": [{"path": "app.py", "line_start": 1, "line_end": 1}],
            }],
            "attack_paths": [],
        }
        result = compare_case(review, review, [], [])
        self.assertIsNone(result["finding_false_negatives"])
        self.assertIsNone(result["attack_path_false_positives"])
        self.assertEqual(len(result["candidates"]), 2)
        self.assertTrue(all(not c["provisional_scanner_matches"]
                            for c in result["candidates"]))

    def test_api_schema_keeps_fields_but_drops_unsupported_limits(self):
        schema = {"title": "review", "properties": {
            "agent": {"type": "string", "minLength": 1, "pattern": "^[a-z]+$"},
        }}
        result = api_schema(schema)
        self.assertNotIn("title", result)
        self.assertEqual(result["properties"]["agent"], {"type": "string"})

    def test_model_input_contains_no_scan_or_ground_truth_metadata(self):
        m = {
            "case_id": "rw-038", "repo": "example/agent", "sha": "a" * 40,
            "framework": "google-adk", "application_path": "agent.py",
            "source_pack_sha256": "b" * 64, "omitted_or_truncated": 0,
            "scan_results": ["secret must not leak"],
        }
        body = make_input(m, "000001: agent = Agent()")
        self.assertNotIn("secret must not leak", body)
        self.assertNotIn("scanner_sha", body)
        self.assertIn("agent = Agent()", body)


if __name__ == "__main__":
    unittest.main()
