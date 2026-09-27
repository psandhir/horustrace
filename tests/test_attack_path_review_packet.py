from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "build_attack_path_review_packet.py"
SPEC = importlib.util.spec_from_file_location("build_attack_path_review_packet", SCRIPT)
assert SPEC and SPEC.loader
mod = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mod
SPEC.loader.exec_module(mod)


def test_packet_is_source_only_stratified_and_blinded() -> None:
    root = Path(__file__).resolve().parents[1]
    packet = mod.build_packet(
        root / "research" / "real-world-agent-security-2026" / "ground-truth"
    )

    assert packet["horustrace_output_used_for_selection"] is False
    assert packet["scanner_reveal_allowed"] is False
    assert 20 <= packet["case_counts"]["attack_path"] <= 30
    assert packet["case_counts"]["finding"] >= 12

    attack = [row for row in packet["cases"] if row["case_type"] == "attack_path"]
    categories = {row["category"] for row in attack}
    assert "proven_authority" in categories
    assert "invalid_near_miss" in categories
    assert "approval_gate" in categories
    assert "mcp_boundary" in categories
    assert "dynamic_unresolved" in categories

    for row in packet["cases"]:
        assert len(row["repository"]["sha"]) == 40
        assert row["source_scope"]
        assert row["source_review_hints"]
        assert len(row["reviewers"]) == 2
        assert row["reviewers"][0]["reviewer_id"] == ""
        assert row["reviewers"][1]["reviewer_id"] == ""
        assert row["reviewers"][0]["locked"] is False
        assert row["reviewers"][1]["locked"] is False
        assert row["reviewers"][0]["horustrace_output_seen"] is False
        assert row["reviewers"][1]["horustrace_output_seen"] is False
