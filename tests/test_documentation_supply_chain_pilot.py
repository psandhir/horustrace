"""Regression checks for the isolated documentation-backed evaluation pilot."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from scripts.documentation_supply_chain_pilot import compare, markdown, validate_source


def _reference() -> dict:
    return {
        "schema_version": 1,
        "source_sha": "unused",
        "source_documents": {
            "docs/architecture.md": "unused",
            "src/agents/hierarchy.json": "unused",
        },
        "scope": {
            "negative_scope": "not_established",
            "release_eligible": False,
            "independent_human_adjudication": False,
        },
        "agents": [
            {"name": "supervisor", "role": "frontend"},
            {"name": "worker", "role": "worker"},
        ],
        "delegation_edges": [{"source": "supervisor", "target": "worker"}],
        "tool_group_bindings": [{"source": "worker", "tool_group": "billing"}],
    }


def _adg() -> dict:
    return {
        "schema_version": 1,
        "nodes": [
            {"id": "a", "kind": "agent", "name": "supervisor",
             "attributes": {"agent_type": "frontend"}},
            {"id": "b", "kind": "agent", "name": "worker",
             "attributes": {"agent_type": "worker"}},
            {"id": "c", "kind": "tool", "name": "worker:billing",
             "attributes": {"tool_name": "billing"}},
            {"id": "d", "kind": "mcp_server", "name": "other",
             "attributes": {}},
        ],
        "edges": [
            {"kind": "DELEGATES_TO", "source": "a", "target": "b"},
            {"kind": "INVOKES", "source": "b", "target": "c"},
            {"kind": "INVOKES", "source": "a", "target": "d"},
        ],
    }


def test_exact_typed_edges_count_as_documentation_matches() -> None:
    result = compare(_reference(), _adg())
    assert result["agents"]["matched_unique"] == ["supervisor", "worker"]
    assert result["delegations"]["matched"] == [
        {"source": "supervisor", "target": "worker"}
    ]
    assert result["tool_groups"]["exact_label_candidates"] == [
        {"source": "worker", "target": "billing"}
    ]
    assert result["accuracy"]["certified_recall"] is None
    assert result["accuracy"]["certified_false_negatives"] is None
    assert "certified" not in result["tool_groups"]["status"]
    report = markdown({"comparison": result, "repository": "example/repo",
                       "source_sha": "deadbeef"})
    assert "not a certified false negative" in report
    assert "No release accuracy certification" in report


def test_untyped_or_misdirected_relations_do_not_match() -> None:
    adg = _adg()
    adg["edges"][0]["kind"] = "CONTROL_FLOWS_TO"
    adg["edges"][1]["source"] = "a"
    result = compare(_reference(), adg)
    assert len(result["delegations"]["not_detected"]) == 1
    assert len(result["tool_groups"]["not_exactly_aligned"]) == 1


def test_unknown_scanner_agents_are_not_automatic_false_positives() -> None:
    adg = _adg()
    adg["nodes"].append({"id": "e", "kind": "agent", "name": "undocumented",
                         "attributes": {}})
    result = compare(_reference(), adg)
    assert result["agents"]["scanner_only_unreviewed"] == ["undocumented"]
    assert result["accuracy"]["certified_false_positives"] is None


def test_duplicate_name_not_silently_matched() -> None:
    adg = _adg()
    adg["nodes"].append({"id": "e", "kind": "agent", "name": "supervisor",
                         "attributes": {}})
    result = compare(_reference(), adg)
    assert "supervisor" in result["agents"]["ambiguous"]
    assert "supervisor" not in result["agents"]["matched_unique"]


def test_unknown_adg_schema_and_duplicate_ids_are_rejected() -> None:
    adg = _adg()
    adg["schema_version"] = 2
    with pytest.raises(ValueError, match="schema"):
        compare(_reference(), adg)
    adg = _adg()
    adg["nodes"][1]["id"] = "a"
    with pytest.raises(ValueError, match="duplicate"):
        compare(_reference(), adg)


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args], text=True,
        check=True, capture_output=True,
    ).stdout.strip()


def test_reference_is_pinned_and_fail_closed_on_config_drift(tmp_path: Path) -> None:
    checkout = tmp_path / "target"
    checkout.mkdir()
    _git(checkout, "init", "-q")
    _git(checkout, "config", "user.name", "Pilot Test")
    _git(checkout, "config", "user.email", "pilot@example.invalid")
    (checkout / "docs").mkdir()
    (checkout / "src/agents").mkdir(parents=True)
    (checkout / "docs/architecture.md").write_text(
        "# Agent composition\nAgents use hierarchy.json.\n", encoding="utf-8"
    )
    hierarchy = {
        "supervisor": {"type": "frontend", "children": ["worker"]},
        "worker": {"type": "worker", "tools": ["billing"]},
    }
    (checkout / "src/agents/hierarchy.json").write_text(
        json.dumps(hierarchy), encoding="utf-8"
    )
    _git(checkout, "add", ".")
    _git(checkout, "commit", "-qm", "test source")
    reference = _reference()
    reference["source_sha"] = _git(checkout, "rev-parse", "HEAD")
    for path in reference["source_documents"]:
        reference["source_documents"][path] = _git(checkout, "rev-parse", "HEAD:" + path)
    validate_source(checkout, reference)
    reference["source_sha"] = "0" * 40
    with pytest.raises(ValueError, match="revision"):
        validate_source(checkout, reference)
    reference["source_sha"] = _git(checkout, "rev-parse", "HEAD")
    reference["agents"].append({"name": "invented", "role": "worker"})
    with pytest.raises(ValueError, match="differs"):
        validate_source(checkout, reference)
