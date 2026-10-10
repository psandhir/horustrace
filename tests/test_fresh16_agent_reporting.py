"""Regression: Fresh-16 agent inventory must come from the CLI summary."""
import importlib.util
from pathlib import Path

import pytest

MODULE_PATH = (
    Path(__file__).parents[1]
    / "research"
    / "fresh-unseen-generalization-20"
    / "run_case.py"
)
spec = importlib.util.spec_from_file_location("fresh_run_case", MODULE_PATH)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_agent_count_reads_actual_summary_not_absent_agents_key() -> None:
    scan = {
        "summary": {"agents": 7, "findings": 1, "attack_paths": 2},
        "findings": [{"rule_id": "NET001"}],
    }
    assert module.scan_inventory_counts(scan) == {
        "agents": 7, "findings": 1, "attack_paths": 2
    }


@pytest.mark.parametrize("scan", [
    {},
    {"summary": {}, "findings": []},
    {"summary": {"agents": 0, "findings": 1, "attack_paths": 0}, "findings": []},
    {"summary": {"agents": False, "findings": 0, "attack_paths": 0},
     "findings": []},
    {"summary": {"agents": -1, "findings": 0, "attack_paths": 0},
     "findings": []},
])
def test_invalid_scan_inventory_fails_closed(scan: dict) -> None:
    with pytest.raises(ValueError):
        module.scan_inventory_counts(scan)


def test_real_zero_agents_preserved_without_fabricating_agent_inventory() -> None:
    scan = {
        "summary": {"agents": 0, "findings": 0, "attack_paths": 0},
        "findings": [],
    }
    assert module.scan_inventory_counts(scan)["agents"] == 0
