"""C03a independent migration-candidate hard negatives and rollback checks."""

from __future__ import annotations

import json
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from horustrace.adg import ADGEdge, ADGNode, AgentDependencyGraph, build_adg
from horustrace.mcp_c03_candidate import (
    build_mcp_adg_candidate,
    verify_mcp_candidate_rollback,
)
from horustrace.mcp_c03_crosswalk import build_mcp_source_crosswalk
from horustrace.models import Agent, Graph
from horustrace.source_shadow_attestation import seal_mcp_source_shadow


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(root), *args], check=True, capture_output=True,
    )


def _checkout(root: Path) -> None:
    root.mkdir(exist_ok=True)
    (root / "agent.py").write_text("client context source\n", encoding="utf-8")
    (root / "server_a.py").write_text(
        'mcp = FastMCP("Calculator")\n@mcp.tool()\ndef add(): pass\n',
        encoding="utf-8",
    )
    (root / "server_b.py").write_text(
        'mcp = FastMCP("Calculator")\n@mcp.tool()\ndef subtract(): pass\n',
        encoding="utf-8",
    )
    _git(root, "init", "-q")
    _git(root, "add", "agent.py", "server_a.py", "server_b.py")
    _git(root, "-c", "user.name=C03 Test",
         "-c", "user.email=c03@example.test", "commit", "-qm", "fixture")


def _raw() -> dict:
    nodes = [
        {
            "id": "shadow-mcp:client-a", "kind": "mcp_client_configuration",
            "name": "a", "agent": "agent_one",
            "location": {"path": "agent.py", "line": 1},
        },
        {
            "id": "shadow-mcp:impl-a", "kind": "mcp_source_implementation",
            "name": "Calculator",
            "location": {"path": "server_a.py", "line": 1},
        },
        {
            "id": "shadow-mcp:tool-a", "kind": "mcp_source_tool",
            "name": "add",
            "location": {"path": "server_a.py", "line": 3},
        },
        {
            "id": "shadow-mcp:impl-b", "kind": "mcp_source_implementation",
            "name": "Calculator",
            "location": {"path": "server_b.py", "line": 1},
        },
        {
            "id": "shadow-mcp:tool-b", "kind": "mcp_source_tool",
            "name": "subtract",
            "location": {"path": "server_b.py", "line": 3},
        },
    ]
    edges = [
        {
            "id": "relation-a",
            "kind": "CONFIG_RESOLVES_TO_SOURCE_IMPLEMENTATION",
            "source": "shadow-mcp:client-a",
            "target": "shadow-mcp:impl-a",
        },
        {
            "id": "tool-a",
            "kind": "EXPOSES_TOOL", "source": "shadow-mcp:impl-a",
            "target": "shadow-mcp:tool-a",
        },
        {
            "id": "tool-b",
            "kind": "EXPOSES_TOOL", "source": "shadow-mcp:impl-b",
            "target": "shadow-mcp:tool-b",
        },
    ]
    for node in nodes:
        node.update({
            "source_only": True, "deployment_verified": False,
            "effective_authority": "unknown",
        })
    for edge in edges:
        edge.update({
            "source_only": True, "effective_agent_can_call": None,
        })
    return {
        "schema_version": 1,
        "mode": "local_stdio_source_implementation_shadow_not_production_adg",
        "nodes": nodes,
        "edges": edges,
        "edge_kinds": {
            "CONFIG_RESOLVES_TO_SOURCE_IMPLEMENTATION": 1,
            "EXPOSES_TOOL": 2,
        },
        "unresolved": [],
        "runtime_tool_catalogue_verified": False,
        "effective_authority_verified": False,
        "production_cutover_authorized": False,
    }


def _base(root: Path) -> AgentDependencyGraph:
    return build_adg(Graph(agents=[Agent(name="agent_one")]), root)


def _sealed(root: Path) -> dict:
    return seal_mcp_source_shadow(_raw(), root)


def test_c03a_attested_same_name_instances_candidate_and_exact_rollback(
    tmp_path: Path,
) -> None:
    _checkout(tmp_path)
    base = _base(tmp_path)
    before = deepcopy(base.as_dict())
    digest = base.canonical_digest()
    evidence = _sealed(tmp_path)
    frozen = deepcopy(evidence)
    preview = build_mcp_adg_candidate(base, evidence, tmp_path)
    assert base.as_dict() == before
    assert base.canonical_digest() == digest
    assert evidence == frozen
    assert preview == build_mcp_adg_candidate(base, evidence, tmp_path)
    assert preview["candidate_adg"]["schema_version"] != 1
    assert preview["mode"] == "c03a_mcp_source_candidate_not_authoritative"
    assert preview["baseline_adg_digest"] == digest
    assert preview["rollback_digest"] == digest
    assert preview["canonical_adg_unchanged"] is True
    assert len(preview["differential"]["added_source_node_ids"]) == 5
    assert len(preview["differential"]["added_source_edge_ids"]) == 3
    assert preview["differential"]["added_source_edge_kinds"] == {
        "CONFIG_RESOLVES_TO_SOURCE_IMPLEMENTATION": 1,
        "EXPOSES_TOOL": 2,
    }
    assert not preview["differential"]["removed_canonical_node_ids"]
    assert not preview["differential"]["changed_canonical_nodes"]
    nodes = preview["candidate_adg"]["nodes"]
    same_name = [node for node in nodes
                 if node["kind"] == "mcp_source_implementation"
                 and node["name"] == "Calculator"]
    assert len(same_name) == 2
    assert len({x["id"] for x in same_name}) == 2
    assert {x["location"]["path"] for x in same_name} == {
        "server_a.py", "server_b.py",
    }
    added = [node for node in nodes
             if node["id"].startswith("c03-candidate:")]
    assert all(node["attributes"]["projection_state"] == "c03_candidate_only"
               and node["attributes"]["effective_authority"] == "unknown"
               for node in added)
    assert all(edge["kind"] != "AGENT_CAN_CALL" for edge in
               preview["candidate_adg"]["edges"] if edge["id"].startswith(
                   "c03-candidate:"
               ))
    assert preview["independently_adjudicated"] is False
    assert preview["production_cutover_authorized"] is False
    assert preview["certified_precision"] is None
    verify_mcp_candidate_rollback(base, preview)


def test_c03a_unsealed_shadow_and_stale_commit_fail(tmp_path: Path) -> None:
    _checkout(tmp_path)
    base = _base(tmp_path)
    with pytest.raises(ValueError, match="legacy/unsealed"):
        build_mcp_adg_candidate(base, _raw(), tmp_path)
    sealed = _sealed(tmp_path)
    path = tmp_path / "server_a.py"
    path.write_text(path.read_text().replace("Calculator", "CalculatoR"))
    with pytest.raises(ValueError, match="changed MCP source"):
        build_mcp_adg_candidate(base, sealed, tmp_path)


def test_c03a_same_length_claim_tampering_cannot_become_candidate(
    tmp_path: Path,
) -> None:
    _checkout(tmp_path)
    sealed = _sealed(tmp_path)
    sealed["nodes"][1]["name"] = "CalculatoR"
    with pytest.raises(ValueError, match="changed after sealing"):
        build_mcp_adg_candidate(_base(tmp_path), sealed, tmp_path)


@pytest.mark.parametrize("mutation", [
    lambda d: d["edges"][0].update({"kind": "AGENT_CAN_CALL"}),
    lambda d: d["edges"][1].update({"effective_agent_can_call": True}),
    lambda d: d["nodes"][1].update({"deployment_verified": True}),
    lambda d: d["nodes"][2].update({"effective_authority": "allowed"}),
    lambda d: d["edges"][1].update({"source": "shadow-mcp:missing"}),
])
def test_c03a_promoted_authority_or_bad_edge_fails_closed(
    tmp_path: Path, mutation,
) -> None:
    _checkout(tmp_path)
    sealed = _sealed(tmp_path)
    mutation(sealed)
    with pytest.raises((ValueError, TypeError)):
        build_mcp_adg_candidate(_base(tmp_path), sealed, tmp_path)


def test_c03a_rollback_detects_modified_claims(tmp_path: Path) -> None:
    _checkout(tmp_path)
    base = _base(tmp_path)
    preview = build_mcp_adg_candidate(base, _sealed(tmp_path), tmp_path)
    for mutation in (
        lambda p: p["differential"].update({"effective_agent_can_call_edges_added": 1}),
        lambda p: p["differential"].update({"changed_canonical_edges": ["x"]}),
        lambda p: p["candidate_adg"].update({"schema_version": 1}),
        lambda p: p.update({"production_cutover_authorized": True}),
        lambda p: p["candidate_adg"]["nodes"][0].update({"name": "tampered"}),
        lambda p: p["candidate_adg"]["edges"][0].update({"kind": "AGENT_CAN_CALL"}),
        lambda p: p["differential"].update({"added_source_node_ids": []}),
    ):
        copy = deepcopy(preview)
        mutation(copy)
        with pytest.raises(ValueError):
            verify_mcp_candidate_rollback(base, copy)


def test_c03a_empty_and_invalid_base_fail_closed(tmp_path: Path) -> None:
    _checkout(tmp_path)
    with pytest.raises(TypeError):
        build_mcp_adg_candidate(None, _sealed(tmp_path), tmp_path)
    base = _base(tmp_path)
    base.nodes.append(base.nodes[0])
    with pytest.raises(ValueError, match="duplicate node"):
        build_mcp_adg_candidate(base, _sealed(tmp_path), tmp_path)


def test_c03a_json_report_retains_noncanonical_marker(tmp_path: Path) -> None:
    _checkout(tmp_path)
    preview = build_mcp_adg_candidate(
        _base(tmp_path), _sealed(tmp_path), tmp_path,
    )
    rendered = json.loads(json.dumps(preview))
    assert rendered["candidate_adg"]["schema_version"] == (
        "c03_preview_only_incompatible_with_adg_v1"
    )
    assert rendered["differential"]["attack_paths_changed"] is False
    assert rendered["differential"]["findings_changed"] is False


def test_c03a_resigning_tampered_source_authority_still_fails(
    tmp_path: Path,
) -> None:
    """Even a recomputed preview digest cannot elevate source to authority."""
    import hashlib

    _checkout(tmp_path)
    base = _base(tmp_path)
    preview = build_mcp_adg_candidate(base, _sealed(tmp_path), tmp_path)
    source_node = next(
        n for n in preview["candidate_adg"]["nodes"]
        if n["id"].startswith("c03-candidate:")
    )
    source_node["attributes"]["effective_authority"] = "allowed"
    payload = json.dumps(
        preview["candidate_adg"], sort_keys=True, separators=(",", ":"),
    )
    preview["candidate_snapshot_sha256"] = (
        "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()
    )
    with pytest.raises(ValueError, match="promoted source nodes"):
        verify_mcp_candidate_rollback(base, preview)


def test_c03b_crosswalk_only_source_witnesses_and_keeps_rollback(tmp_path: Path) -> None:
    _checkout(tmp_path)
    base = _base(tmp_path)
    original = deepcopy(base.as_dict())
    preview = build_mcp_adg_candidate(base, _sealed(tmp_path), tmp_path)
    crosswalk = build_mcp_source_crosswalk(base, preview)
    assert base.as_dict() == original
    assert crosswalk["canonical_adg_unchanged"] is True
    assert crosswalk["production_cutover_authorized"] is False
    assert crosswalk["certified_precision"] is None
    assert crosswalk["certified_recall"] is None
    assert crosswalk["semantic_identity_verified"] is False
    assert len(crosswalk["node_correspondences"]) == 5
    assert len(crosswalk["edge_correspondences"]) == 3
    assert crosswalk["node_status_counts"] == {"candidate_only": 5}
    assert crosswalk["edge_status_counts"] == {"candidate_source_edge_only": 3}
    assert crosswalk == build_mcp_source_crosswalk(base, preview)


def test_c03b_exact_source_line_and_name_not_same_name_alone(tmp_path: Path) -> None:
    _checkout(tmp_path)
    base = _base(tmp_path)
    base.nodes.append(ADGNode(
        node_id="canonical-same-site",
        kind="mcp_server",
        name="Calculator",
        location={"path": "server_a.py", "line": 1, "column": None},
    ))
    base.nodes.append(ADGNode(
        node_id="canonical-wrong-line",
        kind="mcp_server",
        name="Calculator",
        location={"path": "server_b.py", "line": 9, "column": None},
    ))
    base.nodes.append(ADGNode(
        node_id="canonical-other-name",
        kind="mcp_server",
        name="Another",
        location={"path": "server_b.py", "line": 1, "column": None},
    ))
    preview = build_mcp_adg_candidate(base, _sealed(tmp_path), tmp_path)
    result = build_mcp_source_crosswalk(base, preview)
    implementations = [
        x for x in result["node_correspondences"]
        if x["candidate_kind"] == "mcp_source_implementation"
    ]
    matched = [x for x in implementations
               if x["status"] == "corroborated_source_site"]
    assert len(matched) == 1
    assert matched[0]["canonical_source_site_matches"] == [
        {"id": "canonical-same-site", "kind": "mcp_server"},
    ]
    assert matched[0]["semantic_identity_verified"] is False
    assert result["edge_status_counts"] == {"candidate_source_edge_only": 3}


def test_c03b_multiple_same_site_canonical_rows_are_ambiguous(tmp_path: Path) -> None:
    _checkout(tmp_path)
    base = _base(tmp_path)
    for index in range(2):
        base.nodes.append(ADGNode(
            node_id=f"canonical-duplicate-{index}",
            kind="mcp_server",
            name="Calculator",
            location={"path": "server_a.py", "line": 1},
        ))
    preview = build_mcp_adg_candidate(base, _sealed(tmp_path), tmp_path)
    result = build_mcp_source_crosswalk(base, preview)
    ambiguous = [x for x in result["node_correspondences"]
                 if x["status"] == "ambiguous_source_site"]
    assert len(ambiguous) == 1
    assert len(ambiguous[0]["canonical_source_site_matches"]) == 2
    assert result["production_cutover_authorized"] is False


def test_c03b_exact_kind_and_endpoint_relation_still_not_authority(
    tmp_path: Path,
) -> None:
    _checkout(tmp_path)
    base = _base(tmp_path)
    for name, kind, site in (
        ("a", "mcp_client_configuration", "agent.py"),
        ("Calculator", "mcp_source_implementation", "server_a.py"),
        ("add", "mcp_source_tool", "server_a.py"),
    ):
        line = 3 if name == "add" else 1
        base.nodes.append(ADGNode(
            node_id="canonical-" + name,
            kind=kind, name=name,
            location={"path": site, "line": line},
        ))
    base.edges.append(ADGEdge(
        edge_id="canonical-declaration-relation",
        kind="CONFIG_RESOLVES_TO_SOURCE_IMPLEMENTATION",
        source="canonical-a", target="canonical-Calculator",
    ))
    preview = build_mcp_adg_candidate(base, _sealed(tmp_path), tmp_path)
    result = build_mcp_source_crosswalk(base, preview)
    matched = [x for x in result["edge_correspondences"]
               if x["status"] == "same_kind_endpoint_source_correspondence"]
    assert len(matched) == 1
    assert matched[0]["canonical_same_kind_endpoint_edge_ids"] == [
        "canonical-declaration-relation",
    ]
    assert matched[0]["effective_agent_can_call"] is None
    assert result["runtime_authority_verified"] is False


def test_c03b_candidate_tampering_does_not_bypass_rollback(tmp_path: Path) -> None:
    _checkout(tmp_path)
    base = _base(tmp_path)
    preview = build_mcp_adg_candidate(base, _sealed(tmp_path), tmp_path)
    for mutation in (
        lambda p: p["candidate_adg"]["edges"][0].update({
            "kind": "AGENT_CAN_CALL",
        }),
        lambda p: p["candidate_adg"]["nodes"][0].update({
            "name": "tampered",
        }),
        lambda p: p.update({"production_cutover_authorized": True}),
        lambda p: p["differential"].update({
            "added_source_edge_ids": [],
        }),
    ):
        invalid = deepcopy(preview)
        mutation(invalid)
        with pytest.raises((ValueError, TypeError)):
            build_mcp_source_crosswalk(base, invalid)
