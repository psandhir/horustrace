"""The WAB-05 ADG test/test-role boundary cannot promote source to runtime."""
from __future__ import annotations

from pathlib import Path

import pytest

from scripts.verify_wave_b540_wab05_adg_source_roles import check_wab05_adg_edges


def _graph(root: Path) -> dict:
    path = root / "tests" / "test_daemon_proxy.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# source\n", encoding="utf-8")
    return {
        "nodes": [
            {"id": "server", "kind": "mcp_server",
             "attributes": {"source_context": "test",
                            "deployment_verified": False}},
            {"id": "tool", "kind": "tool",
             "attributes": {"source_context": "test",
                            "deployment_verified": False}},
        ],
        "edges": [{
            "id": "exposure", "kind": "EXPOSES_TOOL",
            "source": "server", "target": "tool",
            "location": {"path": "tests/test_daemon_proxy.py", "line": 9},
            "attributes": {
                "basis": "source_proven_mcp_decorator",
                "source_context": "test",
                "server_source_context": "test",
                "agent_binding": "unbound",
                "authority_verified": False,
                "deployment_verified": False,
            },
        }],
    }


def test_test_decorator_is_not_deployed_authority(tmp_path: Path) -> None:
    r = check_wab05_adg_edges(_graph(tmp_path), tmp_path)
    assert r["source_context_counts"] == {"test": 1}
    assert r["exposes_tool_source_edges"] == 1
    assert r["wave_b_go"] is False
    assert r["deployment_verified"] is False
    assert r["precision"] is None and r["recall"] is None


def test_missing_source_context_is_not_a_runtime_default(tmp_path: Path) -> None:
    graph = _graph(tmp_path)
    graph["edges"][0]["attributes"].pop("source_context")
    with pytest.raises(ValueError, match="source role mismatch"):
        check_wab05_adg_edges(graph, tmp_path)


def test_test_only_edge_cannot_be_deployed(tmp_path: Path) -> None:
    graph = _graph(tmp_path)
    graph["edges"][0]["attributes"]["deployment_verified"] = True
    with pytest.raises(ValueError, match="live authority"):
        check_wab05_adg_edges(graph, tmp_path)


def test_unauthorized_agent_edge_is_rejected(tmp_path: Path) -> None:
    graph = _graph(tmp_path)
    graph["nodes"].append({"id": "agent", "kind": "agent"})
    with pytest.raises(ValueError, match="runtime agent"):
        check_wab05_adg_edges(graph, tmp_path)


def test_unbound_source_role_is_not_an_agent_tool_permission(
    tmp_path: Path,
) -> None:
    graph = _graph(tmp_path)
    graph["edges"][0]["attributes"]["agent_binding"] = "agent_can_call"
    with pytest.raises(ValueError, match="live authority"):
        check_wab05_adg_edges(graph, tmp_path)


def test_server_and_edge_source_roles_must_agree(tmp_path: Path) -> None:
    graph = _graph(tmp_path)
    graph["nodes"][0]["attributes"]["source_context"] = "runtime"
    with pytest.raises(ValueError, match="lost between"):
        check_wab05_adg_edges(graph, tmp_path)


def test_path_escape_cannot_be_a_source_proof(tmp_path: Path) -> None:
    graph = _graph(tmp_path)
    graph["edges"][0]["location"]["path"] = "../outside.py"
    with pytest.raises(ValueError, match="escapes"):
        check_wab05_adg_edges(graph, tmp_path)


def test_missing_catalogue_does_not_prove_zero_tools(tmp_path: Path) -> None:
    graph = _graph(tmp_path)
    graph["edges"] = []
    with pytest.raises(ValueError, match="silently dropped"):
        check_wab05_adg_edges(graph, tmp_path)
