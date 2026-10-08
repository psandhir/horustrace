from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.frozen180_llm_review import ReviewError, validate_review
from scripts.frozen180_source_packet import _candidate_files

SCHEMA_PATH = (
    Path(__file__).resolve().parents[1]
    / "research/frozen180-llm-differential-20261008/source-review.schema.json"
)
SOURCE = (
    "===== SOURCE FILE: app.py =====\n"
    "000001: from pydantic_ai import Agent\n"
    "000002: assistant = Agent('openai:gpt-4o')\n"
    "000003: assistant_tool = lambda value: value\n"
)
SHA = "a" * 40


def evidence(line: int = 2, path: str = "app.py") -> dict:
    return {
        "path": path, "line_start": line, "line_end": line,
        "claim": "Source defines agent instance", "quote": None,
    }


def fixture():
    digest = hashlib.sha256(SOURCE.encode()).hexdigest()
    review = {
        "schema_version": 1,
        "study": "frozen180-llm-source-review-20261008",
        "case_id": "rw-777", "repo": "example/agent", "sha": SHA,
        "framework": "pydantic-ai",
        "review_scope": {"application_path": "app.py", "source_pack_sha256": digest},
        "coverage": {
            "source_coverage": "qualified", "review_result": "enumerated_candidates",
            "reviewed_files": ["app.py"], "omitted_or_truncated": 0,
            "additional_source_required": [], "limitations": ["Bounded source packet"],
        },
        "entities": [{
            "id": "agent-1", "kind": "agent", "name": "assistant",
            "framework": "pydantic-ai", "source_context": "runtime",
            "binding_status": "bound", "evidence": [evidence()], "attributes": [],
        }],
        "relationships": [], "authority_contracts": [], "findings": [],
        "attack_paths": [],
    }
    manifest = {
        "case_id": review["case_id"], "repo": review["repo"], "sha": SHA,
        "framework": "pydantic-ai", "application_path": "app.py",
        "source_output_seen": False, "status": "ok",
        "application_entrypoint_included": True,
        "source_pack_sha256": digest, "omitted_or_truncated": 0,
    }
    return review, manifest


class SourceOnlyReviewSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = json.loads(SCHEMA_PATH.read_text())

    def check_valid(self, review, manifest):
        return validate_review(review, manifest, SOURCE, self.schema)

    def test_hidden_skill_mcp_and_primary_entrypoint_in_source_packet(self):
        with tempfile.TemporaryDirectory() as dirname:
            root = Path(dirname)
            entrypoint = root / "agent.py"
            entrypoint.write_text("agent = Agent()")
            skill = root / ".agents/skills/booking/SKILL.md"
            skill.parent.mkdir(parents=True)
            skill.write_text("Use booking safely")
            mcp = root / ".mcp.json"
            mcp.write_text('{"servers": []}')
            workflow = root / ".github/workflows/deploy.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text("name: deploy")
            git_file = root / ".git/internal.py"
            git_file.parent.mkdir(parents=True)
            git_file.write_text("ignore")
            found = _candidate_files(root, entrypoint)
            self.assertEqual(found[0], entrypoint)
            self.assertIn(skill, found)
            self.assertIn(mcp, found)
            self.assertIn(workflow, found)
            self.assertNotIn(git_file, found)

    def test_valid_source_only_inventory(self):
        r, m = fixture()
        result = self.check_valid(r, m)
        self.assertEqual(result["counts"]["entities"], 1)
        self.assertFalse(result["accuracy_validated"])
        self.assertFalse(result["reveal_allowed"])

    def test_missing_entrypoint_rejected(self):
        r, m = fixture()
        m["application_entrypoint_included"] = False
        with self.assertRaisesRegex(ReviewError, "entrypoint"):
            self.check_valid(r, m)

    def test_hallucinated_source_location_rejected(self):
        r, m = fixture()
        r["entities"][0]["evidence"] = [evidence(400)]
        with self.assertRaisesRegex(ReviewError, "not supplied"):
            self.check_valid(r, m)

    def test_source_identity_or_hash_changed_rejected(self):
        r, m = fixture()
        r["sha"] = "b" * 40
        with self.assertRaisesRegex(ReviewError, "provenance mismatch"):
            self.check_valid(r, m)
        r, m = fixture()
        r["review_scope"]["source_pack_sha256"] = "b" * 64
        with self.assertRaisesRegex(ReviewError, "hash"):
            self.check_valid(r, m)

    def test_fabricated_completeness_rejected(self):
        r, m = fixture()
        r["coverage"]["source_coverage"] = "complete"
        with self.assertRaisesRegex(ReviewError, "bounded"):
            self.check_valid(r, m)
        r, m = fixture()
        r["coverage"]["review_result"] = "reviewed_no_candidate"
        with self.assertRaisesRegex(ReviewError, "negative completeness"):
            self.check_valid(r, m)

    def test_unaccounted_truncation_rejected(self):
        r, m = fixture()
        m["omitted_or_truncated"] = 2
        with self.assertRaisesRegex(ReviewError, "omissions"):
            self.check_valid(r, m)

    def test_finding_scanner_metadata_leak_rejected(self):
        r, m = fixture()
        r["scanner_sha"] = SHA
        with self.assertRaisesRegex(ReviewError, "unexpected"):
            self.check_valid(r, m)
        r, m = fixture()
        r["entities"][0]["attributes"].append({"name": "comment", "values": ["AGT040"]})
        with self.assertRaisesRegex(ReviewError, "rule identifier"):
            self.check_valid(r, m)

    def test_attack_path_without_reachable_agent_rejected(self):
        r, m = fixture()
        r["attack_paths"] = [{
            "id": "path-1", "title": "Code exec", "agent_id": "agent-missing",
            "ingress": "input", "steps": [
                {"order": i, "kind": kind, "label": kind,
                 "entity_id": None, "evidence": [evidence()]}
                for i, kind in enumerate(("ingress", "tool", "sink"), 1)
            ], "sink": "exec", "sink_kind": "code_execute",
            "data_movement": [], "severity": "critical",
            "assessment": "potential_risk", "confidence": "supported",
            "support_status": "source_supported",
            "reachability": "proven_agent_reachable", "control_status": "unresolved",
            "source_context": "runtime", "basis": "static_dataflow",
            "exploitability": "not_verified", "evidence": [evidence()],
            "limitations": ["Approval uncertain"],
        }]
        with self.assertRaisesRegex(ReviewError, "inventoried agent"):
            self.check_valid(r, m)

    def test_unknown_issue_type_and_invalid_severity_rejected(self):
        r, m = fixture()
        item = {
            "id": "finding-1", "issue_type": "made_up_vuln",
            "title": "Unsafe", "message": "Some potential issue",
            "agent_id": "agent-1", "authority_relationship_ids": [],
            "severity": "super_critical", "assessment": "heuristic_risk",
            "support_status": "source_supported", "confidence": "supported",
            "source_context": "runtime", "owasp_agentic": [],
            "evidence": [evidence()], "controls": [], "limitations": [],
            "recommendation": "Apply controls",
        }
        r["findings"] = [item]
        with self.assertRaisesRegex(ReviewError, "invalid value"):
            self.check_valid(r, m)


if __name__ == "__main__":
    unittest.main()
