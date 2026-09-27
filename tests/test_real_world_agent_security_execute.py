from __future__ import annotations

import importlib.util
from pathlib import Path


def _module():
    path = Path("scripts/real_world_agent_security_execute.py")
    spec = importlib.util.spec_from_file_location("real_world_agent_security_execute", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_postfix_mode_is_explicit_and_baseline_remains_default() -> None:
    module = _module()
    parser = module.parser()

    baseline = parser.parse_args(
        [
            "--scanner-sha",
            "a" * 40,
            "--output-json",
            "result.json",
            "--output-markdown",
            "result.md",
        ]
    )
    postfix = parser.parse_args(
        [
            "--scanner-sha",
            "b" * 40,
            "--mode",
            "postfix",
            "--output-json",
            "result.json",
            "--output-markdown",
            "result.md",
        ]
    )

    assert baseline.mode == "baseline"
    assert postfix.mode == "postfix"


def test_aggregate_records_execution_mode_and_frozen_baseline_sha() -> None:
    module = _module()
    cohort = {
        "scanner_freeze_sha": "a" * 40,
        "ground_truth_reference": {},
        "tier_c_case_ids": [],
    }

    report = module.aggregate(
        [],
        "b" * 40,
        cohort,
        execution_mode="postfix",
    )

    assert report["scanner_sha"] == "b" * 40
    assert report["baseline_scanner_sha"] == "a" * 40
    assert report["execution_mode"] == "postfix"

def test_agent_entity_scoring_includes_workflow_nodes_but_not_tools() -> None:
    module = _module()
    nodes = [
        {"kind": "agent", "name": "workflow"},
        {"kind": "workflow_node", "name": "chatbot"},
        {"kind": "tool", "name": "search"},
    ]

    predicted = module.predicted_nodes_for_dimension(nodes, "agent_entities")

    assert [item["name"] for item in predicted] == ["workflow", "chatbot"]




def test_authority_scoring_canonicalizes_runtime_agent_name_by_location() -> None:
    module = _module()
    truth = {
        "tier_a": {
            "agent_roots": [
                {
                    "name": "agent",
                    "variable": "agent",
                    "kind": "Agent",
                    "path": "app/llm/agent.py",
                    "line": 31,
                }
            ]
        },
        "tier_b": {
            "authority_relationships": [
                {
                    "agent": "agent",
                    "target_kind": "tool",
                    "target_name": "tavily_search",
                }
            ]
        },
    }
    observed = {
        "relationships": [
            {
                "agent": "Devscale AI",
                "target": {"kind": "tool", "name": "tavily_search"},
            }
        ]
    }
    nodes = [
        {
            "id": "agent-node",
            "kind": "agent",
            "name": "Devscale AI",
            "location": {
                "path": "/tmp/repo/app/llm/agent.py",
                "line": 31,
                "column": 8,
            },
        }
    ]

    metrics = module.authority_metrics(truth, observed, nodes)

    assert metrics == {
        "truth": 1,
        "predicted": 1,
        "tp": 1,
        "fn": 0,
        "fp_if_complete": 0,
        "matched_pairs": [
            {
                "agent": "agent",
                "target_kind": "tool",
                "target_name": "tavilysearch",
            }
        ],
        "missing_pairs": [],
        "extra_pairs": [],
    }


def test_authority_scoring_keeps_ambiguous_runtime_name_unmapped() -> None:
    module = _module()
    truth = {
        "tier_a": {
            "agent_roots": [
                {"name": "left", "path": "agent.py", "line": 10},
                {"name": "right", "path": "agent.py", "line": 12},
            ]
        },
        "tier_b": {
            "authority_relationships": [
                {
                    "agent": "left",
                    "target_kind": "tool",
                    "target_name": "search",
                }
            ]
        },
    }
    observed = {
        "relationships": [
            {
                "agent": "runtime",
                "target": {"kind": "tool", "name": "search"},
            }
        ]
    }
    nodes = [
        {
            "id": "runtime-node",
            "kind": "agent",
            "name": "runtime",
            "location": {"path": "/tmp/repo/agent.py", "line": 11, "column": 0},
        }
    ]

    metrics = module.authority_metrics(truth, observed, nodes)

    assert metrics["tp"] == 0
    assert metrics["fn"] == 1
    assert metrics["fp_if_complete"] == 1



def test_absolute_import_roots_ignore_relative_and_nested_suffixes(tmp_path: Path) -> None:
    module = _module()
    source = tmp_path / "agent.py"
    source.write_text(
        """
import tools.audio
import os
from tools.image import render
from agents.helpers import helper
from .local import thing
from ..shared import other
""",
        encoding="utf-8",
    )

    assert module._absolute_import_roots([source]) == {"tools", "os", "agents"}


def test_repository_local_import_patterns_only_select_existing_top_level_entries(
    tmp_path: Path,
) -> None:
    module = _module()
    source = tmp_path / "agent.py"
    source.write_text(
        """
import tools.audio
import config
import requests
from agents.helpers import helper
""",
        encoding="utf-8",
    )

    patterns = module._repository_local_import_patterns(
        [source],
        {"agents", "tools", "config.py", "README.md"},
    )

    assert patterns == ["agents", "config.py", "tools"]



def test_authority_enrichment_keeps_only_primary_scope_agents() -> None:
    module = _module()
    authority = {
        "relationships": [
            {
                "agent": "primary",
                "target": {"kind": "tool", "name": "resolved_helper"},
            },
            {
                "agent": "dependency_agent",
                "target": {"kind": "tool", "name": "unrelated"},
            },
        ]
    }
    primary_nodes = [
        {"kind": "agent", "name": "primary"},
        {"kind": "tool", "name": "something_else"},
    ]

    filtered = module._authority_for_primary_agents(authority, primary_nodes)

    assert [item["agent"] for item in filtered["relationships"]] == ["primary"]
