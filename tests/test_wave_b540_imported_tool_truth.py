"""Positive and hard-negative source-truth audit for unpinned Strands tools."""
from __future__ import annotations

from copy import deepcopy

import pytest

from scripts.audit_wave_b540_imported_tool_truth import (
    PINNED_REPOSITORY,
    PINNED_SHA,
    audit_imported_tool_truth,
    dependency_declaration,
)


def _case() -> dict:
    tool = {
        "kind": "strands_vended_tool",
        "name": "python_repl",
        "capabilities": ["process.execute"],
        "metadata": {
            "source_module": "strands_tools",
            "source_symbol_origin": "import_statement",
        },
    }
    return {
        "case_id": "amazon-hold-004",
        "repo": PINNED_REPOSITORY,
        "sha": PINNED_SHA,
        "application_path": "src",
        "counts": {"agents": 1, "findings": 1, "authority_relationships": 1},
        "agent_inventory": [{
            "name": "agent",
            "metadata": {
                "source_factory": "pricing_explorer",
                "construction_scope": "tool_wrapper_deferred_invocation",
            },
            "tools": [tool],
        }],
        "findings": [{
            "rule_id": "AGT020",
            "provenance": [{
                "origin": "inferred",
                "subject": "python_repl",
                "fact": "capability=process.execute",
            }],
        }],
        "authority_relationships": [{"target": {"kind": "tool", "name": "python_repl"}}],
    }


@pytest.mark.parametrize(
    ("requirements", "expected"),
    [
        ("strands-agents-tools\nmcp[cli]\n", "unversioned"),
        ("strands-agents-tools==0.3.1\n", "exact_declared_version_not_installed_attestation"),
        ("strands-agents-tools>=0.2.0\n", "range_or_dynamic_not_installed_attestation"),
        ("strands-agents-tools @ https://example.test/tool.whl\n", "range_or_dynamic_not_installed_attestation"),
        ("# strands-agents-tools\n", "missing_or_ambiguous"),
        ("strands-agents-tools\nstrands-agents-tools>=1.0\n", "missing_or_ambiguous"),
    ],
)
def test_untrusted_package_version_never_proves_installed_effect(
    requirements: str, expected: str
) -> None:
    assert dependency_declaration(requirements) == expected
    report = audit_imported_tool_truth(_case(), requirements)
    assert report["source_dependency_declaration"] == expected
    assert report["imported_vended_tool_occurrences"] == 1
    assert report["imported_vended_tool_names"] == {"python_repl": 1}
    assert report["deferred_agent_constructors"] == 1
    assert report["provenance_fact_origins"] == {"inferred": 1}
    assert report["installed_tool_implementation_verified"] is False
    assert report["external_tool_effects_verified"] is False
    assert report["runtime_approval_controls_verified"] is False
    assert report["independent_ground_truth"] is False
    assert report["precision"] is None and report["recall"] is None
    assert report["wave_c_go"] is False


@pytest.mark.parametrize(
    "change",
    [
        lambda c: c.update({"sha": "0" * 40}),
        lambda c: c.update({"repo": "not/the-pinned-repository"}),
        lambda c: c.update({"application_path": "examples"}),
        lambda c: c["counts"].update({"agents": 2}),
        lambda c: c["counts"].update({"findings": 0}),
        lambda c: c["counts"].update({"authority_relationships": 0}),
        lambda c: c["findings"][0].update({"provenance": "inferred"}),
        lambda c: c["findings"][0]["provenance"][0].update({"origin": "runtime_verified"}),
        lambda c: c["agent_inventory"][0]["tools"][0]["metadata"].update({
            "source_symbol_origin": "inferred_from_name",
        }),
        lambda c: c["agent_inventory"][0]["tools"][0]["metadata"].update({
            "source_module": "unrelated_module",
        }),
    ],
)
def test_fail_closed_on_wrong_source_or_evidence(change) -> None:
    case = deepcopy(_case())
    change(case)
    with pytest.raises(ValueError):
        audit_imported_tool_truth(case, "strands-agents-tools\n")


def test_actual_observed_provenance_is_preserved_but_not_runtime_proof() -> None:
    case = _case()
    case["findings"][0]["provenance"].append({
        "origin": "observed",
        "subject": "agent",
        "fact": "tool_import=python_repl",
    })
    result = audit_imported_tool_truth(case, "strands-agents-tools\n")
    assert result["provenance_fact_origins"] == {"inferred": 1, "observed": 1}
    assert result["external_tool_effects_verified"] is False
    assert result["wave_c_go"] is False
