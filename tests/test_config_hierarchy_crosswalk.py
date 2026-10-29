"""C03f configured hierarchy source-to-canonical crosswalk negatives."""
from __future__ import annotations

import json
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from horustrace.adg import ADGEdge, ADGNode, AgentDependencyGraph
from horustrace.config_hierarchy_crosswalk import (
    build_configured_hierarchy_source_crosswalk as crosswalk,
)
from horustrace.config_hierarchy_shadow import (
    build_configured_hierarchy_source_shadow as shadow,
)


def _root(tmp_path: Path) -> None:
    (tmp_path / "config.json").write_text(json.dumps({
        "root": {
            "type": "frontend", "dir": "agents/frontend",
            "children": ["leaf"],
        },
        "leaf": {
            "type": "worker", "dir": "agents/worker",
            "tools": ["billing"],
        },
    }), encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "init", "-q"], check=True)
    subprocess.run([
        "git", "-C", str(tmp_path), "add", "config.json",
    ], check=True)
    subprocess.run([
        "git", "-C", str(tmp_path), "-c", "user.name=C03 Test",
        "-c", "user.email=c03@example.invalid",
        "commit", "-qm", "fixture",
    ], check=True)


def _base(*, include_edge: bool = True) -> AgentDependencyGraph:
    nodes = [
        ADGNode(node_id="canonical-root", kind="agent", name="root",
                attributes={"agent_type": "frontend"}),
        ADGNode(node_id="canonical-leaf", kind="agent", name="leaf",
                attributes={"agent_type": "worker"}),
        ADGNode(node_id="canonical-tool", kind="tool", name="leaf:billing"),
    ]
    edges = [
        ADGEdge(edge_id="canonical-invokes", kind="INVOKES",
                source="canonical-leaf", target="canonical-tool"),
    ]
    if include_edge:
        edges.append(ADGEdge(
            edge_id="canonical-child", kind="DELEGATES_TO",
            source="canonical-root", target="canonical-leaf",
        ))
    return AgentDependencyGraph(nodes=nodes, edges=edges)


def test_correlations_are_not_deployed_identities_or_authority(
    tmp_path: Path,
) -> None:
    _root(tmp_path)
    base = _base()
    original = deepcopy(base.as_dict())
    result = crosswalk(base, shadow(tmp_path, "config.json"), tmp_path)
    assert base.as_dict() == original
    assert result == crosswalk(base, shadow(tmp_path, "config.json"), tmp_path)
    assert result["agent_status_counts"] == {
        "single_display_name_correlation": 2,
    }
    assert result["edge_status_counts"] == {
        "tool_group_label_candidate_not_semantic_equivalence": 1,
        "typed_delegation_name_endpoint_correlated": 1,
    }
    assert all(row["semantic_identity_verified"] is False
               for row in result["source_agent_records"])
    assert all(row["runtime_relationship_verified"] is False
               and row["effective_agent_can_call"] is None
               for row in result["source_edge_records"])
    assert result["runtime_authority_verified"] is False
    assert result["certified_recall"] is None
    assert result["production_cutover_authorized"] is False


def test_no_delegation_from_unrelated_call_edge(tmp_path: Path) -> None:
    _root(tmp_path)
    base = _base(include_edge=False)
    base.edges.append(ADGEdge(
        edge_id="bogus-call", kind="AGENT_CAN_CALL",
        source="canonical-root", target="canonical-leaf",
    ))
    result = crosswalk(base, shadow(tmp_path, "config.json"), tmp_path)
    child = next(x for x in result["source_edge_records"]
                 if x["source_kind"] == "CONFIG_DECLARES_CHILD")
    assert child["status"] == "configured_only"
    assert child["canonical_relation_candidates"] == []


def test_ambiguous_same_name_agents_remain_unresolved(tmp_path: Path) -> None:
    _root(tmp_path)
    base = _base()
    base.nodes.append(ADGNode(
        node_id="canonical-root-duplicate", kind="agent", name="root",
    ))
    result = crosswalk(base, shadow(tmp_path, "config.json"), tmp_path)
    assert result["agent_status_counts"] == {
        "ambiguous_same_display_name": 1,
        "single_display_name_correlation": 1,
    }
    child = next(x for x in result["source_edge_records"]
                 if x["source_kind"] == "CONFIG_DECLARES_CHILD")
    assert child["status"] == "ambiguous_agent_identity"


def test_tampered_source_candidate_fails_before_crosswalk(tmp_path: Path) -> None:
    _root(tmp_path)
    source = shadow(tmp_path, "config.json")
    changed = deepcopy(source)
    changed["nodes"][0]["name"] = "forged"
    with pytest.raises(ValueError, match="differs"):
        crosswalk(_base(), changed, tmp_path)
    (tmp_path / "config.json").write_text('{"tampered":true}', encoding="utf-8")
    with pytest.raises(ValueError, match="differs"):
        crosswalk(_base(), source, tmp_path)


def test_missing_canonical_agents_are_candidate_only(tmp_path: Path) -> None:
    _root(tmp_path)
    result = crosswalk(
        AgentDependencyGraph(), shadow(tmp_path, "config.json"), tmp_path,
    )
    assert result["agent_status_counts"] == {"configured_only": 2}
    assert result["edge_status_counts"] == {"configured_only": 2}
    assert result["certified_precision"] is None
