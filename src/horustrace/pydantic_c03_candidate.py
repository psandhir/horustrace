"""C03g: reversible Pydantic conditional tool-selection source ADG candidate.

A selected source tool symbol and apparent registration wrapper do NOT
establish an installed SDK version, active demo-level, deployed agent,
effective AGENT_CAN_CALL or an authorized production Graph projection.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

from horustrace.adg import ADGEdge, ADGNode, AgentDependencyGraph
from horustrace.source_truth_ast_pydantic import (
    inspect_pydantic_level_returns,
    inspect_pydantic_tool_plumbing,
)

_MODE = "c03g_pydantic_conditional_source_only_not_production_adg"
_NAMESPACE = "c03-pydantic-candidate:"
_BRANCHES = {
    "level_1": "level == 1",
    "level_2": "level == 2",
    "else_branch_other_values": "all_other_values",
}
_REQUIRED_FILES = (
    "agent/agent.py", "agent/base_agent.py", "agent/tools.py",
)


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args], check=True,
        capture_output=True, timeout=20,
    ).stdout.decode("utf-8").strip()


def _source(checkout: Path) -> tuple[str, dict[str, str], list[dict]]:
    root = checkout.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Pydantic source checkout is not a directory")
    try:
        if Path(_git(root, "rev-parse", "--show-toplevel")).resolve() != root:
            raise ValueError("Pydantic candidate requires repository root")
        if _git(root, "rev-parse", "--show-object-format") != "sha1":
            raise ValueError("Pydantic candidate requires SHA-1 Git objects")
        head = _git(root, "rev-parse", "--verify", "HEAD")
        if not re.fullmatch(r"[0-9a-f]{40}", head):
            raise ValueError("Pydantic source revision is invalid")
        sources = {}
        manifest = []
        for name in _REQUIRED_FILES:
            path = (root / name).resolve(strict=True)
            if not path.is_relative_to(root) or not path.is_file():
                raise ValueError("Pydantic source path escapes checkout")
            if path.stat().st_size > 2 * 1024 * 1024:
                raise ValueError("Pydantic source file exceeds size limit")
            raw = path.read_bytes()
            blob = hashlib.sha1(
                b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw
            ).hexdigest()
            if _git(root, "ls-tree", head, "--", name) not in (
                f"100644 blob {blob}\t{name}",
                f"100755 blob {blob}\t{name}",
            ):
                raise ValueError("Pydantic source changed since Git HEAD")
            sources[name] = raw.decode("utf-8")
            manifest.append({
                "path": name, "git_blob_sha": blob,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size_bytes": len(raw),
            })
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        raise ValueError("Pydantic candidate requires intact Git checkout") from exc
    return head, sources, manifest


def build_pydantic_conditional_source_candidate(
    base: AgentDependencyGraph, checkout: Path,
) -> dict[str, Any]:
    """Create noncanonical ADG-shaped preview, with source-branch semantics."""
    if not isinstance(base, AgentDependencyGraph):
        raise TypeError("canonical ADG required")
    head, src, manifest = _source(checkout)
    selection = inspect_pydantic_level_returns(
        "agent/tools.py", src["agent/tools.py"],
    )
    plumbing = inspect_pydantic_tool_plumbing(
        src["agent/agent.py"], src["agent/base_agent.py"],
    )
    if plumbing["selected_tool_registration_source_chain"] is not True:
        raise ValueError("Pydantic registration source chain not corroborated")
    before = base.as_dict()
    digest = base.canonical_digest()
    if (len({n["id"] for n in before["nodes"]}) != len(before["nodes"])
            or len({e["id"] for e in before["edges"]}) != len(before["edges"])):
        raise ValueError("canonical ADG duplicate identity")
    distinct = sorted({
        tool for key in _BRANCHES for tool in selection[key]
    })
    if not distinct:
        raise ValueError("no static source-selected tools")
    nodes: list[ADGNode] = []
    edges: list[ADGEdge] = []
    for key, meaning in _BRANCHES.items():
        nodes.append(ADGNode(
            node_id=_NAMESPACE + "branch:" + key,
            kind="pydantic_source_branch", name=meaning,
            framework="pydantic_ai",
            location={"path": "agent/tools.py",
                      "line": selection["function_line"], "column": None},
            attributes={
                "source_only": True, "projection_state": "candidate_only",
                "runtime_selection_known": False, "effective_authority": "unknown",
                "branch": key, "source_commit_sha": head,
            },
        ))
    for tool in distinct:
        nodes.append(ADGNode(
            node_id=_NAMESPACE + "tool:" + tool,
            kind="pydantic_source_tool_symbol", name=tool,
            framework="pydantic_ai",
            location={"path": "agent/tools.py",
                      "line": selection["function_line"], "column": None},
            attributes={
                "source_only": True, "projection_state": "candidate_only",
                "runtime_registration_verified": False,
                "effective_authority": "unknown", "source_commit_sha": head,
            },
        ))
    for key in _BRANCHES:
        for tool in selection[key]:
            edges.append(ADGEdge(
                edge_id=_NAMESPACE + "edge:" + key + ":" + tool,
                kind="SOURCE_BRANCH_SELECTS_TOOL",
                source=_NAMESPACE + "branch:" + key,
                target=_NAMESPACE + "tool:" + tool,
                attributes={
                    "source_only": True, "effective_agent_can_call": None,
                    "runtime_selection_known": False, "source_commit_sha": head,
                },
            ))
    old_ids = {n["id"] for n in before["nodes"]}
    old_edge_ids = {e["id"] for e in before["edges"]}
    if (any(n.node_id in old_ids for n in nodes)
            or any(e.edge_id in old_edge_ids for e in edges)
            or any(n["id"].startswith(_NAMESPACE) for n in before["nodes"])
            or any(e["id"].startswith(_NAMESPACE) for e in before["edges"])):
        raise ValueError("candidate namespace collides with canonical ADG")
    preview = AgentDependencyGraph(
        nodes=[*base.nodes, *nodes], edges=[*base.edges, *edges],
    ).as_dict()
    preview.update({
        "schema_version": "c03_source_preview_incompatible_with_adg_v1",
        "mode": _MODE, "production_cutover_authorized": False,
    })
    if base.as_dict() != before or base.canonical_digest() != digest:
        raise RuntimeError("Pydantic source candidate mutated canonical ADG")
    result = {
        "schema_version": 1, "mode": _MODE, "source_commit_sha": head,
        "source_files": manifest,
        "selection_oracle_sha256": _digest(selection),
        "registration_chain_sha256": _digest(plumbing),
        "source_branches": {key: list(selection[key]) for key in _BRANCHES},
        "source_registration_chain_observed": True,
        "baseline_adg_digest": digest, "rollback_digest": digest,
        "candidate_adg": preview, "candidate_snapshot_sha256": _digest(preview),
        "differential": {
            "source_nodes_added": len(nodes),
            "source_edges_added": len(edges),
            "effective_agent_can_call_edges_added": 0,
            "canonical_nodes_removed": [], "canonical_edges_removed": [],
            "canonical_nodes_changed": [], "canonical_edges_changed": [],
            "findings_changed": False, "attack_paths_changed": False,
        },
        "canonical_adg_unchanged": True,
        "runtime_level_known": False, "runtime_authority_verified": False,
        "independently_adjudicated": False,
        "certified_precision": None, "certified_recall": None,
        "production_cutover_authorized": False,
    }
    verify_pydantic_conditional_candidate_rollback(base, result)
    return result


def verify_pydantic_conditional_candidate_rollback(
    base: AgentDependencyGraph, candidate: dict[str, Any],
) -> None:
    """Fail closed on forged authority, changed canonical data or preview drift."""
    if not isinstance(base, AgentDependencyGraph) or not isinstance(candidate, dict):
        raise TypeError("canonical ADG and candidate dict required")
    before = base.as_dict()
    if (candidate.get("mode") != _MODE
            or candidate.get("baseline_adg_digest") != base.canonical_digest()
            or candidate.get("rollback_digest") != base.canonical_digest()
            or candidate.get("canonical_adg_unchanged") is not True
            or candidate.get("runtime_level_known") is not False
            or candidate.get("runtime_authority_verified") is not False
            or candidate.get("independently_adjudicated") is not False
            or candidate.get("production_cutover_authorized") is not False
            or candidate.get("certified_precision") is not None
            or candidate.get("certified_recall") is not None):
        raise ValueError("Pydantic source candidate release/rollback contract violated")
    preview = candidate.get("candidate_adg")
    if (not isinstance(preview, dict)
            or preview.get("schema_version")
            != "c03_source_preview_incompatible_with_adg_v1"
            or preview.get("production_cutover_authorized") is not False
            or preview.get("mode") != _MODE
            or candidate.get("candidate_snapshot_sha256") != _digest(preview)):
        raise ValueError("Pydantic candidate snapshot integrity failed")
    nodes, edges = preview.get("nodes"), preview.get("edges")
    if not isinstance(nodes, list) or not isinstance(edges, list):
        raise TypeError("invalid candidate graph")
    old_nodes = {n["id"]: n for n in before["nodes"]}
    old_edges = {e["id"]: e for e in before["edges"]}
    current_nodes = {n["id"]: n for n in nodes}
    current_edges = {e["id"]: e for e in edges}
    if (len(current_nodes) != len(nodes) or len(current_edges) != len(edges)
            or any(current_nodes.get(k) != v for k, v in old_nodes.items())
            or any(current_edges.get(k) != v for k, v in old_edges.items())):
        raise ValueError("Pydantic candidate modified canonical graph")
    added_nodes = set(current_nodes) - set(old_nodes)
    added_edges = set(current_edges) - set(old_edges)
    delta = candidate.get("differential", {})
    if (delta.get("source_nodes_added") != len(added_nodes)
            or delta.get("source_edges_added") != len(added_edges)
            or delta.get("effective_agent_can_call_edges_added") != 0
            or any(delta.get(key) != [] for key in (
                "canonical_nodes_removed", "canonical_edges_removed",
                "canonical_nodes_changed", "canonical_edges_changed",
            ))
            or delta.get("findings_changed") is not False
            or delta.get("attack_paths_changed") is not False):
        raise ValueError("Pydantic candidate source differential invalid")
    branches = candidate.get("source_branches")
    if (not isinstance(branches, dict) or set(branches) != set(_BRANCHES)
            or any(not isinstance(tools, list)
                   or len(tools) != len(set(tools))
                   or any(not isinstance(tool, str)
                          or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", tool)
                          for tool in tools)
                   for tools in branches.values())):
        raise ValueError("Pydantic source branch inventory malformed")
    tools = {tool for values in branches.values() for tool in values}
    expected_nodes = {
        *(_NAMESPACE + "branch:" + key for key in _BRANCHES),
        *(_NAMESPACE + "tool:" + tool for tool in tools),
    }
    if added_nodes != expected_nodes:
        raise ValueError("Pydantic source branch/tool identities changed")
    for key, meaning in _BRANCHES.items():
        node = current_nodes[_NAMESPACE + "branch:" + key]
        if (node["kind"] != "pydantic_source_branch"
                or node["name"] != meaning
                or node.get("attributes", {}).get("branch") != key):
            raise ValueError("Pydantic source branch identity changed")
    for tool in tools:
        node = current_nodes[_NAMESPACE + "tool:" + tool]
        if (node["kind"] != "pydantic_source_tool_symbol"
                or node["name"] != tool):
            raise ValueError("Pydantic source tool symbol identity changed")
    expected_edges = {
        _NAMESPACE + "edge:" + key + ":" + tool: (
            _NAMESPACE + "branch:" + key, _NAMESPACE + "tool:" + tool
        )
        for key, selected in branches.items() for tool in selected
    }
    if added_edges != set(expected_edges):
        raise ValueError("Pydantic source branch-to-tool edge inventory changed")
    for eid, (source, target) in expected_edges.items():
        if (current_edges[eid]["source"] != source
                or current_edges[eid]["target"] != target):
            raise ValueError("Pydantic source branch-to-tool witness remapped")
    for nid in added_nodes:
        n = current_nodes[nid]
        a = n.get("attributes", {})
        if (not nid.startswith(_NAMESPACE) or n.get("kind") not in {
            "pydantic_source_branch", "pydantic_source_tool_symbol",
        } or a.get("source_only") is not True
                or a.get("projection_state") != "candidate_only"
                or a.get("effective_authority") != "unknown"
                or a.get("source_commit_sha") != candidate.get("source_commit_sha")
                or (n["kind"] == "pydantic_source_branch"
                    and a.get("runtime_selection_known") is not False)
                or (n["kind"] == "pydantic_source_tool_symbol"
                    and a.get("runtime_registration_verified") is not False)):
            raise ValueError("Pydantic source candidate promoted node to authority")
    for eid in added_edges:
        edge = current_edges[eid]
        a = edge.get("attributes", {})
        if (not eid.startswith(_NAMESPACE)
                or edge.get("kind") != "SOURCE_BRANCH_SELECTS_TOOL"
                or edge["source"] not in added_nodes
                or edge["target"] not in added_nodes
                or a.get("source_only") is not True
                or a.get("effective_agent_can_call") is not None
                or a.get("runtime_selection_known") is not False
                or a.get("source_commit_sha") != candidate.get("source_commit_sha")):
            raise ValueError("Pydantic source candidate promoted edge to callability")
