"""Opt-in source-only MCP supply-chain HTML explorer regression tests."""

from __future__ import annotations

from copy import deepcopy

import pytest

from horustrace.source_shadow_html import (
    render_source_shadow_html,
    validate_source_shadow,
)


def fixture_source_shadow() -> dict:
    nodes = [
        {
            "id": "shadow-mcp:config",
            "kind": "mcp_client_configuration",
            "name": "configured-one",
            "agent": "agent_a",
            "location": {"path": "agent.py", "line": 25},
            "source_only": True,
            "deployment_verified": False,
            "effective_authority": "unknown",
        },
        {
            "id": "shadow-mcp:impl1",
            "kind": "mcp_source_implementation",
            "name": "Calculator",
            "location": {"path": "one.py", "line": 4},
            "source_only": True,
            "deployment_verified": False,
            "effective_authority": "unknown",
        },
        {
            "id": "shadow-mcp:impl2",
            "kind": "mcp_source_implementation",
            "name": "Calculator",
            "location": {"path": "two.py", "line": 4},
            "source_only": True,
            "deployment_verified": False,
            "effective_authority": "unknown",
        },
        {
            "id": "shadow-mcp:tool1",
            "kind": "mcp_source_tool",
            "name": "add",
            "location": {"path": "one.py", "line": 16},
            "source_only": True,
            "deployment_verified": False,
            "effective_authority": "unknown",
        },
    ]
    edges = [
        {
            "id": "c1",
            "kind": "CONFIG_RESOLVES_TO_SOURCE_IMPLEMENTATION",
            "source": "shadow-mcp:config",
            "target": "shadow-mcp:impl1",
            "source_only": True,
            "effective_agent_can_call": None,
        },
        {
            "id": "e1",
            "kind": "EXPOSES_TOOL",
            "source": "shadow-mcp:impl1",
            "target": "shadow-mcp:tool1",
            "source_only": True,
            "effective_agent_can_call": None,
            "runtime_tool_catalogue_verified": False,
        },
    ]
    return {
        "schema_version": 1,
        "mode": "local_stdio_source_implementation_shadow_not_production_adg",
        "nodes": nodes,
        "edges": edges,
        "edge_kinds": {
            "CONFIG_RESOLVES_TO_SOURCE_IMPLEMENTATION": 1,
            "EXPOSES_TOOL": 1,
        },
        "unresolved": [
            {"agent": "agent_a", "server": "missing", "reason": "missing_source_tool_witness"}
        ],
        "runtime_tool_catalogue_verified": False,
        "effective_authority_verified": False,
        "production_cutover_authorized": False,
        "certified_precision": None,
        "certified_recall": None,
    }


def test_c02v_render_source_only_supply_chain_keeps_same_named_instances() -> None:
    src = fixture_source_shadow()
    original = deepcopy(src)
    output = render_source_shadow_html(src)
    assert src == original
    assert "<!doctype html>" in output
    assert output.count('class="node-card server"') == 2
    assert "one.py:4" in output and "two.py:4" in output
    assert "Source declared · Runtime unknown" in output
    assert "CONFIG_RESOLVES_TO_SOURCE_IMPLEMENTATION" in output
    assert "EXPOSES_TOOL" in output
    assert "classList.toggle('dimmed'" in output
    assert "aria-pressed" in output
    assert "No runtime catalogue" in output
    assert "production_cutover_authorized" not in output


def test_c02v_untrusted_source_metadata_cannot_embed_scripts() -> None:
    src = fixture_source_shadow()
    src["nodes"][1]["name"] = '</script><script>alert("injected")</script>'
    src["nodes"][1]["location"]["path"] = 'weird<script>"&.py'
    src["unresolved"][0]["reason"] = '<img src=x onerror=alert("evil")>'
    output = render_source_shadow_html(src)
    assert '</script><script>alert' not in output
    assert "&lt;/script&gt;&lt;script&gt;" in output
    assert '\\u003c/script\\u003e' in output
    assert '&lt;img src=x onerror=' in output


@pytest.mark.parametrize("mutation", [
    lambda d: d.update({"mode": "production_adg"}),
    lambda d: d.update({"production_cutover_authorized": True}),
    lambda d: d.update({"runtime_tool_catalogue_verified": True}),
    lambda d: d.update({"effective_authority_verified": True}),
    lambda d: d["nodes"][2].update({"id": "shadow-mcp:impl1"}),
    lambda d: d["nodes"][3].update({"deployment_verified": True}),
    lambda d: d["nodes"][3].update({"effective_authority": "permitted"}),
    lambda d: d["nodes"][3].update({"location": {"path": "../escape", "line": 0}}),
    lambda d: d["nodes"][3].update({"kind": "agent"}),
    lambda d: d["edges"][1].update({"kind": "AGENT_CAN_CALL"}),
    lambda d: d["edges"][1].update({"effective_agent_can_call": True}),
    lambda d: d["edges"][1].update({"source": "shadow-mcp:tool1"}),
    lambda d: d["edges"][1].update({"target": "shadow-mcp:missing"}),
    lambda d: d.update({"edge_kinds": {"EXPOSES_TOOL": 10}}),
])
def test_c02v_production_promotion_and_invalid_edges_fail_closed(mutation) -> None:
    original = fixture_source_shadow()
    mutation(original)
    with pytest.raises(ValueError):
        validate_source_shadow(original)


def test_c02v_tool_free_source_shadow_is_valid_but_uncertified() -> None:
    src = fixture_source_shadow()
    src["nodes"] = []
    src["edges"] = []
    src["edge_kinds"] = {}
    output = render_source_shadow_html(src)
    assert "No source witnesses in this category" in output
    assert "EXPERIMENTAL · SOURCE ONLY" in output
    assert "No runtime catalogue" in output


def test_c02v_unresolved_is_aggregated_not_inferred_authority() -> None:
    output = render_source_shadow_html(fixture_source_shadow())
    assert "missing_source_tool_witness" in output
    assert "Unresolved source relationships (1)" in output
    assert "No runtime catalogue" in output
