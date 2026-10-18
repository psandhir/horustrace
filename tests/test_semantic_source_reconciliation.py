"""Wave C C01b source-native to legacy Graph site reconciliation tests."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from horustrace.models import Agent, Graph, SourceLocation
from horustrace.semantic_discovery import (
    SemanticBinding,
    SemanticBindingKind,
    SemanticDiscovery,
    SemanticEntity,
    SemanticEntityKind,
    SemanticObservation,
    SemanticResolution,
)
from horustrace.semantic_shadow import (
    build_shadow_discovery,
    shadow_observation_report,
)
from horustrace.semantic_source_reconciliation import (
    SOURCE_PRODUCERS,
    reconcile_native_source_proofs,
)


def _entity(entity_id: str, name: str, kind: SemanticEntityKind,
            path: str, line: int) -> SemanticEntity:
    return SemanticEntity(
        entity_id=entity_id, name=name, kind=kind, framework="test",
        location=SourceLocation(Path(path), line=line),
    )


def _sources(
    native: SemanticDiscovery | None = None,
    dynamic: SemanticDiscovery | None = None,
) -> dict[str, SemanticDiscovery]:
    result = {key: SemanticDiscovery(schema_version=2) for key in SOURCE_PRODUCERS}
    if native is not None:
        result["source_native"] = native
    if dynamic is not None:
        result["source_native_dynamic"] = dynamic
    return result


def test_c01b_pydantic_exposure_never_implies_callability() -> None:
    a = _entity("agent", "agent", SemanticEntityKind.AGENT, "agent.py", 3)
    server = _entity(
        "server", "mcp", SemanticEntityKind.MCP_SERVER, "server.py", 2
    )
    tool = _entity("tool", "search", SemanticEntityKind.TOOL, "server.py", 5)
    exposure = SemanticBinding(
        binding_id="edge", source_id="server", target_id="tool",
        kind=SemanticBindingKind.EXPOSES_TOOL,
        basis="fastmcp_registration", resolution=SemanticResolution.PROVEN,
        location=SourceLocation(Path("server.py"), line=4),
    )
    report = reconcile_native_source_proofs(
        SemanticDiscovery(entities=[a], schema_version=2),
        _sources(native=SemanticDiscovery(
            entities=[a, server, tool], bindings=[exposure], schema_version=2,
        )),
    )
    entry = report["source_edge_crosswalk"][0]
    assert entry["kind"] == "exposes_tool"
    assert entry["reconciliation"] == "source_only_not_false_negative"
    assert entry["source_witness"] == {"path": "server.py", "line": 4}
    assert not entry["authority_verified"]
    assert report["no_implicit_exposure_to_callability"]
    assert report["source_precision"] is None


def test_c01b_exact_site_match_is_not_independent_truth(tmp_path: Path) -> None:
    graph = Graph(agents=[Agent(
        name="agent", location=SourceLocation(tmp_path / "agent.py", line=3),
        metadata={"framework": "test"},
    )])
    legacy = build_shadow_discovery(graph, tmp_path)
    native_agent = _entity(
        "native-agent", "agent", SemanticEntityKind.AGENT, "agent.py", 3
    )
    client = _entity(
        "client", "stdio:mcp.py", SemanticEntityKind.MCP_CLIENT, "agent.py", 4
    )
    link = SemanticBinding(
        "edge", "native-agent", "client",
        SemanticBindingKind.AGENT_BINDS_CLIENT, "literal_collection",
        SemanticResolution.PROVEN,
    )
    report = reconcile_native_source_proofs(
        legacy, _sources(native=SemanticDiscovery(
            entities=[native_agent, client], bindings=[link], schema_version=2,
        )),
    )
    entry = report["source_edge_crosswalk"][0]
    assert entry["reconciliation"] == "one_legacy_site"
    assert len(entry["legacy_source_site_ids"]) == 1
    assert entry["legacy_target_site_ids"] == []
    assert report["production_projection_authorized"] is False
    assert report["not_assessed"] == "independent_positive_and_negative_source_truth"


def test_c01b_unresolved_dynamic_microsoft_is_not_empty_catalogue() -> None:
    client = _entity(
        "c", "client", SemanticEntityKind.MCP_CLIENT, "WorkIq.cs", 4
    )
    target = _entity(
        "u", "dynamic-catalogue", SemanticEntityKind.UNKNOWN, "WorkIq.cs", 5
    )
    edge = SemanticBinding(
        "dynamic", "c", "u", SemanticBindingKind.DISPATCHES_TO,
        "ListToolsAsync", SemanticResolution.UNRESOLVED,
    )
    observation = SemanticObservation(
        "obs", "u", "runtime_enumerated_tool_catalogue_unresolved",
        SemanticResolution.UNRESOLVED, "csharp", "WorkIq.cs",
        "cannot_verify_runtime_tool_catalogue",
    )
    source = SemanticDiscovery(
        entities=[client, target], bindings=[edge],
        observations=[observation], schema_version=2,
    )
    report = reconcile_native_source_proofs(
        SemanticDiscovery(schema_version=2), _sources(dynamic=source)
    )
    assert report["producers"]["source_native_dynamic"]["unresolved_edges"] == 1
    assert report["producers"]["source_native_dynamic"][
        "unresolved_observations"
    ] == 1
    assert report["unresolved_observation_queue"][0]["status"] == (
        "unresolved_not_absent"
    )
    assert not any(
        item["kind"] == "agent_can_call"
        for item in report["source_edge_crosswalk"]
    )


def test_c01b_ambiguous_legacy_instance_site_does_not_get_auto_bound(
    tmp_path: Path,
) -> None:
    location = SourceLocation(tmp_path / "agent.py", line=4)
    graph = Graph(agents=[
        Agent(name="worker", location=location),
        Agent(name="worker", location=location),
    ])
    native_agent = _entity(
        "a", "worker", SemanticEntityKind.AGENT, "agent.py", 4
    )
    client = _entity(
        "c", "mcp", SemanticEntityKind.MCP_CLIENT, "agent.py", 9
    )
    binding = SemanticBinding(
        "e", "a", "c", SemanticBindingKind.AGENT_BINDS_CLIENT,
        "literal", SemanticResolution.PROVEN,
    )
    report = reconcile_native_source_proofs(
        build_shadow_discovery(graph, tmp_path),
        _sources(native=SemanticDiscovery(
            entities=[native_agent, client], bindings=[binding],
            schema_version=2,
        )),
    )
    assert report["source_edge_crosswalk"][0]["reconciliation"] == (
        "ambiguous_legacy_instance_site"
    )
    assert len(report["source_edge_crosswalk"][0][
        "legacy_source_site_ids"
    ]) == 2


def test_c01b_source_context_never_claims_test_as_runtime(
    tmp_path: Path,
) -> None:
    server = _entity(
        "s", "test-server", SemanticEntityKind.MCP_SERVER,
        "tests/test_mcp.py", 2,
    )
    tool = _entity(
        "t", "read", SemanticEntityKind.TOOL, "tests/test_mcp.py", 4
    )
    exposure = SemanticBinding(
        "e", "s", "t", SemanticBindingKind.EXPOSES_TOOL,
        "test_source", SemanticResolution.PARTIAL,
    )
    report = reconcile_native_source_proofs(
        SemanticDiscovery(schema_version=2),
        _sources(native=SemanticDiscovery(
            entities=[server, tool], bindings=[exposure], schema_version=2
        )),
    )
    entry = report["source_edge_crosswalk"][0]
    assert entry["source_context"] == "test"
    assert entry["target_context"] == "test"
    assert entry["resolution"] == "partial"
    assert not report["source_edge_crosswalk"][0]["runtime_executed"]


def test_c01b_missing_producer_and_bad_endpoints_fail_closed() -> None:
    with pytest.raises(ValueError, match="exact four canonical"):
        reconcile_native_source_proofs(
            SemanticDiscovery(schema_version=2), {}
        )
    with pytest.raises(ValueError, match="target does not exist"):
        reconcile_native_source_proofs(
            SemanticDiscovery(schema_version=2),
            _sources(native=SemanticDiscovery(
                entities=[_entity(
                    "s", "server", SemanticEntityKind.MCP_SERVER,
                    "server.py", 1,
                )],
                bindings=[SemanticBinding(
                    "e", "s", "missing",
                    SemanticBindingKind.EXPOSES_TOOL, "bad",
                    SemanticResolution.PARTIAL,
                )],
                schema_version=2,
            )),
        )


def test_c01b_live_sidecar_preserves_graph_and_portability(
    tmp_path: Path,
) -> None:
    results = []
    for name in ("checkout-a", "checkout-b"):
        root = tmp_path / name
        root.mkdir()
        (root / "agent.py").write_text(
            "from pydantic_ai import Agent\n"
            "from pydantic_ai.mcp import MCPServerStdio\n"
            "agent = Agent('model', mcp_servers=["
            "MCPServerStdio('python', ['mcp_server.py'])])\n",
            encoding="utf-8",
        )
        (root / "mcp_server.py").write_text(
            "from fastmcp import FastMCP\n"
            "mcp = FastMCP('sample')\n"
            "@mcp.tool()\n"
            "def get_data(): return 'ok'\n"
            "if __name__ == '__main__': mcp.run()\n",
            encoding="utf-8",
        )
        graph = Graph()
        result = shadow_observation_report(graph, root)
        assert graph.agents == []
        assert result["comparison"]["graph_behavior_changed"] is False
        assert "source_native_reconciliation" in result
        report = result["source_native_reconciliation"]
        assert {item["kind"] for item in report["source_edge_crosswalk"]} == {
            "agent_binds_client", "client_connects_to_server", "exposes_tool",
        }
        assert report["production_projection_authorized"] is False
        assert str(root) not in json.dumps(result)
        results.append(report)
    assert results[0] == results[1]
