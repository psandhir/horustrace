"""WAB-05 MCP source inventory: test fixtures cannot masquerade as deployed servers."""
from __future__ import annotations

from pathlib import Path

from horustrace.models import Graph, MCPServer, SourceLocation
from horustrace.semantic_shadow import shadow_observation_report
from horustrace.source_context import classify_source_context

from scripts.verify_wave_b540_wab05_source_context import inventory_source_records


def _server(root: Path, name: str, path: str, line: int) -> MCPServer:
    return MCPServer(
        name=name, transport="stdio",
        location=SourceLocation(root / path, line=line),
    )


def test_repeated_fixture_names_keep_qualified_test_source_sites(
    tmp_path: Path,
) -> None:
    graph = Graph(unbound_mcp_servers=[
        _server(tmp_path, "owner", "tests/test_server.py", 37),
        _server(tmp_path, "owner", "tests/test_owner.py", 43),
        _server(tmp_path, "test", "tests/test_owner.py", 73),
        _server(tmp_path, "prod", "linkedin_mcp_server/server.py", 208),
    ])
    report = inventory_source_records(graph, tmp_path)
    assert report["unbound_observation_count"] == 4
    assert report["qualified_source_site_count"] == 4
    assert report["source_context_counts"] == {"runtime": 1, "test": 3}
    assert report["ambiguous_same_source_site"] == []
    sidecar = shadow_observation_report(graph, tmp_path)
    assert sidecar["inventory_partition"]["observations_by_role"][
        "unbound_mcp_inventory"
    ] == report["source_context_counts"]
    assert sidecar["comparison"]["graph_behavior_changed"] is False
    assert not graph.agents
    assert not any(
        edge["kind"] == "agent_can_call" for edge in sidecar["bindings"]
    )


def test_same_source_site_duplication_is_reported_not_promoted(
    tmp_path: Path,
) -> None:
    graph = Graph(unbound_mcp_servers=[
        _server(tmp_path, "owner", "tests/test_server.py", 37),
        _server(tmp_path, "owner", "tests/test_server.py", 37),
    ])
    report = inventory_source_records(graph, tmp_path)
    assert report["unbound_observation_count"] == 2
    assert report["qualified_source_site_count"] == 1
    assert report["ambiguous_same_source_site"] == [{
        "path": "tests/test_server.py", "line": 37,
        "name": "owner", "observations": 2,
    }]
    assert report["source_context_counts"] == {"test": 2}


def test_missing_location_is_unknown_not_runtime(tmp_path: Path) -> None:
    graph = Graph(unbound_mcp_servers=[
        MCPServer(name="unknown", transport="stdio", location=None),
        _server(tmp_path, "example", "examples/server.py", 2),
    ])
    report = inventory_source_records(graph, tmp_path)
    assert report["source_context_counts"] == {"example": 1, "unknown": 1}
    assert report["independent_precision"] is None
    assert report["independent_recall"] is None


def test_outer_directory_cannot_change_relative_source_context(
    tmp_path: Path,
) -> None:
    root = tmp_path / "tests-parent" / "checkout"
    graph = Graph(unbound_mcp_servers=[
        _server(root, "live", "linkedin_mcp_server/server.py", 208),
        _server(root, "fixture", "tests/test_server.py", 37),
    ])
    report = inventory_source_records(graph, root)
    assert report["source_context_counts"] == {"runtime": 1, "test": 1}
    assert classify_source_context(root / "linkedin_mcp_server/server.py", root) == "runtime"
