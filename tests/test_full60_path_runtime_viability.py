"""Distinguish source-blocked path evidence from merely unverified execution."""
import importlib.util
from pathlib import Path

SCRIPT = (
    Path(__file__).parents[1]
    / "research"
    / "full-framework-60-post-remediation-20261006"
    / "compare.py"
)
spec = importlib.util.spec_from_file_location("full60_viability", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_blocked_paths_remain_visible_but_not_runtime_viable_claims() -> None:
    rows = {
        "ff60-anthropic-03": {
            "case_id": "ff60-anthropic-03",
            "authority_relationships": [],
            "findings": [],
            "attack_paths": [
                {
                    "path_id": "PATH001",
                    "metadata": {
                        "basis": "source_bound_ingress_authority",
                        "runtime_viability": "blocked_by_source_error",
                        "runtime_blockers": [{
                            "kind": "missing_local_module",
                            "module": "hooks.session_start",
                        }],
                    },
                },
                {"path_id": "PATH011", "metadata": {"basis": "static_dataflow"}},
            ],
        },
    }
    metrics = module.relationship_metrics(rows)
    assert metrics["attack_paths_by_runtime_viability"] == {
        "blocked_by_source_error": 1,
        "not_assessed": 1,
    }
    assert metrics["not_explicitly_blocked_paths"] == 1
    blocked = metrics["blocked_attack_paths_by_case"]["ff60-anthropic-03"]
    assert len(blocked) == 1
    assert blocked[0]["path_id"] == "PATH001"
    assert blocked[0]["runtime_blockers"][0]["module"] == "hooks.session_start"
    assert "execution and exploitability remain unverified" in (
        metrics["runtime_viability_interpretation"]
    )
