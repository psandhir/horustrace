"""C03e: quarantined Google ADK source-declaration ADG candidate.

Literal constructor/list references only. This never supplies runtime authority,
findings, attack paths, certified accuracy or a production Graph migration.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

from horustrace.adg import ADGEdge, ADGNode, AgentDependencyGraph
from horustrace.limits import MAX_ADG_EDGES, MAX_ADG_NODES, ScanLimitError
from horustrace.source_truth_ast_adk import inspect_adk_scope

_NAMESPACE = "c03-adk-candidate:"
_MODE = "c03e_adk_literal_source_candidate_not_authoritative"
_EDGE_KINDS = frozenset({
    "ADK_DIRECT_TOOL_LIST_ENTRY", "ADK_SUB_AGENT_LIST_ENTRY",
})


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True,
        check=True, timeout=20,
    ).stdout.decode("utf-8").strip()


def _read_source(root: Path, paths: list[str]) -> tuple[str, dict, list]:
    scope = root.resolve(strict=True)
    if not scope.is_dir():
        raise ValueError("ADK source scope is not a directory")
    try:
        top = Path(_git(scope, "rev-parse", "--show-toplevel")).resolve()
        form = _git(scope, "rev-parse", "--show-object-format")
        head = _git(scope, "rev-parse", "--verify", "HEAD")
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        raise ValueError("ADK candidate requires a Git checkout") from exc
    if (top != scope or form != "sha1"
            or not re.fullmatch(r"[0-9a-f]{40}", head)):
        raise ValueError("ADK source must be a Git SHA-1 repository root")
    if (not isinstance(paths, list) or not 1 <= len(paths) <= 32
            or not all(isinstance(path, str) for path in paths)
            or len(set(paths)) != len(paths)):
        raise ValueError("ADK source scope must be unique and bounded")
    sources: dict[str, str] = {}
    manifest = []
    for path in sorted(paths):
        if (not re.fullmatch(r"[a-zA-Z0-9_./-]+\.py", path)
                or path.startswith(("/", "./"))
                or ".." in path.split("/")):
            raise ValueError("unsafe ADK source path")
        target = (scope / path).resolve(strict=True)
        if not target.is_relative_to(scope) or not target.is_file():
            raise ValueError("ADK source witness outside checkout")
        if target.stat().st_size > 2 * 1024 * 1024:
            raise ValueError("ADK source witness exceeds file limit")
        raw = target.read_bytes()
        sha = hashlib.sha1(
            b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw
        ).hexdigest()
        try:
            recorded = _git(scope, "ls-tree", head, "--", path)
        except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
            raise ValueError("ADK source Git witness lookup failed") from exc
        if recorded not in (
            f"100644 blob {sha}\t{path}", f"100755 blob {sha}\t{path}",
        ):
            raise ValueError("ADK source not tracked at HEAD or worktree modified")
        sources[path] = raw.decode("utf-8")
        manifest.append({
            "path": path, "git_blob_sha": sha,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size_bytes": len(raw),
        })
    return head, sources, manifest


def build_adk_source_candidate(
    base: AgentDependencyGraph, checkout: Path, paths: list[str],
) -> dict[str, Any]:
    """Build an isolated, reversible snapshot from verified source only."""
    if not isinstance(base, AgentDependencyGraph):
        raise TypeError("canonical ADG required")
    head, sources, manifest = _read_source(checkout, paths)
    oracle = inspect_adk_scope(sources)
    if oracle["unresolved"]:
        raise ValueError("ADK candidate contains unresolved source constructs")
    if not oracle["agents"]:
        raise ValueError("ADK candidate has no literal agent constructors")
    before = base.as_dict()
    digest = base.canonical_digest()
    canonical_ids = {n["id"] for n in before["nodes"]}
    canonical_edges = {e["id"] for e in before["edges"]}
    if (len(canonical_ids) != len(before["nodes"])
            or len(canonical_edges) != len(before["edges"])
            or any(e["source"] not in canonical_ids
                   or e["target"] not in canonical_ids
                   for e in before["edges"])
            or any(x.startswith(_NAMESPACE)
                   for x in (*canonical_ids, *canonical_edges))):
        raise ValueError("canonical ADG identity/endpoints invalid")
    agents = {(a["path"], a["symbol"]): a for a in oracle["agents"]}
    nodes: list[ADGNode] = []
    edges: list[ADGEdge] = []

    def location(row: dict) -> dict:
        return {"path": row["path"], "line": row["line"], "column": None}

    def attributes(row: dict) -> dict:
        return {
            "source_only": True, "projection_state": "c03_candidate_only",
            "deployment_verified": False, "effective_authority": "unknown",
            "runtime_callability_verified": False,
            "source_commit_sha": head, "source_witness_id": row["id"],
        }

    for agent in oracle["agents"]:
        nodes.append(ADGNode(
            node_id=_NAMESPACE + agent["id"], kind="adk_agent_constructor",
            name=agent["name"], framework="google_adk",
            location=location(agent),
            attributes={**attributes(agent), "source_symbol": agent["symbol"]},
        ))
    for binding in oracle["direct_tool_entries"]:
        if (binding["path"], binding["source_agent"]) not in agents:
            raise ValueError("direct tool owner unresolved")
        nodes.append(ADGNode(
            node_id=_NAMESPACE + binding["id"],
            kind="adk_tool_symbol_reference",
            name=binding["target_symbol"], framework="google_adk",
            location=location(binding), attributes=attributes(binding),
        ))
        edges.append(ADGEdge(
            edge_id=_NAMESPACE + "edge:" + binding["id"],
            kind="ADK_DIRECT_TOOL_LIST_ENTRY",
            source=_NAMESPACE + binding["source_agent_id"],
            target=_NAMESPACE + binding["id"],
            location=location(binding),
            attributes={
                "source_only": True, "projection_state": "c03_candidate_only",
                "effective_agent_can_call": None,
                "source_commit_sha": head,
                "source_witness_id": binding["id"],
            },
        ))
    for relation in oracle["sub_agent_entries"]:
        child = agents.get((relation["path"], relation["target_symbol"]))
        if child is None:
            raise ValueError("sub-agent target unresolved in source file")
        edges.append(ADGEdge(
            edge_id=_NAMESPACE + "edge:" + relation["id"],
            kind="ADK_SUB_AGENT_LIST_ENTRY",
            source=_NAMESPACE + relation["source_agent_id"],
            target=_NAMESPACE + child["id"],
            location=location(relation),
            attributes={
                "source_only": True, "projection_state": "c03_candidate_only",
                "effective_agent_can_call": None,
                "source_commit_sha": head,
                "source_witness_id": relation["id"],
            },
        ))
    if (len(base.nodes) + len(nodes) > MAX_ADG_NODES
            or len(base.edges) + len(edges) > MAX_ADG_EDGES):
        raise ScanLimitError("C03 ADK candidate exceeds graph limit")
    additions = {n.node_id for n in nodes}
    edge_additions = {e.edge_id for e in edges}
    if (len(additions) != len(nodes) or len(edge_additions) != len(edges)
            or additions & canonical_ids or edge_additions & canonical_edges
            or any(e.source not in additions or e.target not in additions
                   for e in edges)):
        raise ValueError("ADK candidate has duplicate or dangling relationships")
    candidate = AgentDependencyGraph(
        nodes=[*base.nodes, *nodes], edges=[*base.edges, *edges],
    ).as_dict()
    if base.as_dict() != before or base.canonical_digest() != digest:
        raise RuntimeError("C03 candidate mutated canonical ADG")
    candidate["schema_version"] = "c03_preview_only_incompatible_with_adg_v1"
    candidate["mode"] = _MODE
    candidate["production_cutover_authorized"] = False
    result = {
        "schema_version": 1, "mode": _MODE,
        "source_commit_sha": head, "source_files": manifest,
        "source_oracle_sha256": _digest(oracle),
        "baseline_adg_digest": digest, "rollback_digest": digest,
        "candidate_adg": candidate,
        "candidate_snapshot_sha256": _digest(candidate),
        "differential": {
            "added_source_node_ids": sorted(additions),
            "added_source_edge_ids": sorted(edge_additions),
            "added_source_edge_kinds": {
                kind: sum(e.kind == kind for e in edges)
                for kind in sorted(_EDGE_KINDS)
            },
            "removed_canonical_nodes": [], "removed_canonical_edges": [],
            "changed_canonical_nodes": [], "changed_canonical_edges": [],
            "effective_agent_can_call_edges_added": 0,
            "findings_changed": False, "attack_paths_changed": False,
        },
        "canonical_adg_unchanged": True,
        "runtime_authority_verified": False,
        "independently_adjudicated": False,
        "certified_precision": None, "certified_recall": None,
        "production_cutover_authorized": False,
    }
    verify_adk_candidate_rollback(base, result)
    return result


def verify_adk_candidate_rollback(
    base: AgentDependencyGraph, candidate: dict[str, Any],
) -> None:
    """Check actual canonical preservation, candidate scope and fail-closed flags."""
    if not isinstance(base, AgentDependencyGraph) or not isinstance(candidate, dict):
        raise TypeError("invalid C03 ADK rollback inputs")
    before = base.as_dict()
    digest = base.canonical_digest()
    if (candidate.get("mode") != _MODE
            or candidate.get("baseline_adg_digest") != digest
            or candidate.get("rollback_digest") != digest
            or candidate.get("canonical_adg_unchanged") is not True
            or candidate.get("production_cutover_authorized") is not False
            or candidate.get("runtime_authority_verified") is not False
            or candidate.get("independently_adjudicated") is not False
            or candidate.get("certified_precision") is not None
            or candidate.get("certified_recall") is not None):
        raise ValueError("ADK candidate rollback contract mismatch")
    graph = candidate.get("candidate_adg")
    if (not isinstance(graph, dict)
            or graph.get("schema_version")
            != "c03_preview_only_incompatible_with_adg_v1"
            or graph.get("mode") != _MODE
            or graph.get("production_cutover_authorized") is not False
            or candidate.get("candidate_snapshot_sha256") != _digest(graph)):
        raise ValueError("ADK candidate is not an immutable source-only snapshot")
    nodes, edges = graph.get("nodes"), graph.get("edges")
    if (not isinstance(nodes, list) or not isinstance(edges, list)
            or any(not isinstance(x, dict) for x in (*nodes, *edges))):
        raise ValueError("invalid C03 candidate node or edge inventory")
    old_nodes = {x["id"]: x for x in before["nodes"]}
    old_edges = {x["id"]: x for x in before["edges"]}
    new_nodes = {x["id"]: x for x in nodes}
    new_edges = {x["id"]: x for x in edges}
    if (len(new_nodes) != len(nodes) or len(new_edges) != len(edges)
            or any(new_nodes.get(k) != v for k, v in old_nodes.items())
            or any(new_edges.get(k) != v for k, v in old_edges.items())):
        raise ValueError("ADK candidate changed canonical entities")
    added = set(new_nodes) - set(old_nodes)
    linked = set(new_edges) - set(old_edges)
    delta = candidate.get("differential")
    if (not isinstance(delta, dict)
            or delta.get("added_source_node_ids") != sorted(added)
            or delta.get("added_source_edge_ids") != sorted(linked)
            or delta.get("added_source_edge_kinds") != {
                kind: sum(new_edges[e]["kind"] == kind for e in linked)
                for kind in sorted(_EDGE_KINDS)
            }
            or any(delta.get(k) != [] for k in (
                "removed_canonical_nodes", "removed_canonical_edges",
                "changed_canonical_nodes", "changed_canonical_edges",
            ))
            or delta.get("effective_agent_can_call_edges_added") != 0
            or delta.get("findings_changed") is not False
            or delta.get("attack_paths_changed") is not False):
        raise ValueError("ADK candidate rollback differential changed")
    for nid in added:
        n = new_nodes[nid]
        a = n.get("attributes", {})
        if (not nid.startswith(_NAMESPACE)
                or n.get("kind") not in (
                    "adk_agent_constructor", "adk_tool_symbol_reference")
                or not isinstance(a, dict)
                or a.get("source_only") is not True
                or a.get("projection_state") != "c03_candidate_only"
                or a.get("deployment_verified") is not False
                or a.get("effective_authority") != "unknown"):
            raise ValueError("ADK candidate node promoted to authority")
    for eid in linked:
        e = new_edges[eid]
        a = e.get("attributes", {})
        if (not eid.startswith(_NAMESPACE)
                or e.get("kind") not in _EDGE_KINDS
                or e.get("source") not in added
                or e.get("target") not in added
                or not isinstance(a, dict)
                or a.get("source_only") is not True
                or a.get("projection_state") != "c03_candidate_only"
                or a.get("effective_agent_can_call") is not None):
            raise ValueError("ADK source relation promoted to runtime authority")
    if base.as_dict() != before or base.canonical_digest() != digest:
        raise RuntimeError("ADK rollback mutated baseline")
