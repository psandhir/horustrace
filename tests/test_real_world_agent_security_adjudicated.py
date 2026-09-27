from __future__ import annotations

import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "real_world_agent_security_adjudicated.py"
SPEC = importlib.util.spec_from_file_location("authority_adjudicated", SCRIPT)
assert SPEC and SPEC.loader
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


def test_post_hoc_patch_preserves_raw_and_corrects_multiset(tmp_path: Path) -> None:
    result = {
        "study": "real-world-agent-security-2026",
        "scanner_sha": "a" * 40,
        "cases": [
            {
                "case_id": "rw-x",
                "comparisons": {
                    "effective_authority": {
                        "precision_eligible": True,
                        "matched_pairs": [
                            {"agent": "A", "target_kind": "tool", "target_name": "good"}
                        ],
                        "missing_pairs": [
                            {"agent": "A", "target_kind": "tool", "target_name": "Wrapper"}
                        ],
                        "extra_pairs": [
                            {"agent": "A", "target_kind": "tool", "target_name": "callable"}
                        ],
                    }
                },
            }
        ],
    }
    adj = tmp_path / "adjudications"
    adj.mkdir()
    (adj / "rw-x-effective-authority.json").write_text(
        """{
          "case_id": "rw-x",
          "original_locked_truth_preserved": true,
          "authority_truth_patch": {
            "remove": [{"agent": "A", "target_kind": "tool", "target_name": "Wrapper"}],
            "add": [{"agent": "A", "target_kind": "tool", "target_name": "callable"}],
            "unresolved": []
          }
        }""",
        encoding="utf-8",
    )

    report = mod.score(result, adj)

    assert report["raw_locked_truth"]["precision"] == 0.5
    assert report["raw_locked_truth"]["recall"] == 0.5
    assert report["post_hoc_adjudicated"]["precision"] == 1.0
    assert report["post_hoc_adjudicated"]["recall"] == 1.0
    assert report["remaining_missing"] == {}


def test_unresolved_truth_is_removed_not_relabelled(tmp_path: Path) -> None:
    result = {
        "study": "real-world-agent-security-2026",
        "scanner_sha": "b" * 40,
        "cases": [{
            "case_id": "rw-y",
            "comparisons": {"effective_authority": {
                "precision_eligible": True,
                "matched_pairs": [],
                "missing_pairs": [{"agent": "A", "target_kind": "tool", "target_name": "factory"}],
                "extra_pairs": [],
            }},
        }],
    }
    adj = tmp_path / "adjudications"
    adj.mkdir()
    (adj / "rw-y-effective-authority.json").write_text(
        """{
          "case_id": "rw-y",
          "original_locked_truth_preserved": true,
          "authority_truth_patch": {
            "remove": [{"agent": "A", "target_kind": "tool", "target_name": "factory"}],
            "add": [],
            "unresolved": [{"agent": "A", "target_kind": "tool", "target_name": "custom:x"}]
          }
        }""",
        encoding="utf-8",
    )

    report = mod.score(result, adj)
    assert report["raw_locked_truth"]["fn"] == 1
    assert report["post_hoc_adjudicated"]["fn"] == 0
    assert report["post_hoc_adjudicated"]["truth"] == 0
