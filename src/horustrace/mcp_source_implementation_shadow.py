"""Wave C C02r: read-only, source-only local MCP implementation shadow.

This is NOT part of the production ADG, authority, findings or paths.
It restores source identity lost when local stdio server implementations are
folded into client configurations, without asserting deployed callability.
"""
from __future__ import annotations

import hashlib
from collections import Counter
from pathlib import Path
from typing import Any

from horustrace.models import Graph, Tool

_BINDINGS = frozenset({"local_stdio_script", "local_stdio_console_script"})
_SOURCES = frozenset({"FastMCP", "Server"})


def _id(kind: str, *parts: str) -> str:
    material = "\0".join((kind, *parts)).encode("utf-8")
    return "shadow-mcp:" + hashlib.sha256(material).hexdigest()[:24]


def _relative(root: Path, value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    path = Path(value)
    if not path.is_absolute():
        return None
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return None


def project_bound_source_mcp_implementations(graph: Graph, root: Path) -> dict[str, Any]:
    """Create source configuration, implementation and tool nodes in shadow.

    Only exact path/line/name source witnesses join an implementation to
    a tool. A matching source declaration is not runtime MCP availability
    and this never changes the input Graph or the production ADG.
    """
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}
    unresolved: set[tuple[str, str, str]] = set()
    source_tools: dict[tuple[str, int, str], list[Tool]] = {}
    for tool in graph.unbound_tools:
        if tool.kind != "mcp_exposed_tool" or tool.location is None:
            continue
        path = _relative(root, str(tool.location.path))
        if path is not None and type(tool.location.line) is int and tool.location.line > 0:
            source_tools.setdefault((path, tool.location.line, tool.name), []).append(tool)

    for agent in graph.agents:
        for server in agent.mcp_servers:
            meta = server.metadata
            if (meta.get("repository_resolved") is not True
                    or meta.get("binding_origin") not in _BINDINGS
                    or meta.get("implementation_source") not in _SOURCES):
                continue
            path = _relative(root, meta.get("implementation_path"))
            line = meta.get("implementation_line")
            name = meta.get("implementation_name")
            discovered = meta.get("discovered_tools")
            if (path is None or type(line) is not int or line < 1
                    or not isinstance(name, str) or not name.strip()
                    or not isinstance(discovered, list) or not discovered):
                unresolved.add((agent.name, server.name, "incomplete_source_implementation"))
                continue
            implementation_id = _id("implementation", path, str(line))
            nodes[implementation_id] = {
                "id": implementation_id,
                "kind": "mcp_source_implementation",
                "name": name,
                "location": {"path": path, "line": line},
                "source_only": True,
                "deployment_verified": False,
                "effective_authority": "unknown",
            }
            if server.location is None:
                unresolved.add((agent.name, server.name, "missing_client_configuration_source"))
                continue
            client_path = _relative(root, str(server.location.path))
            if client_path is None or type(server.location.line) is not int:
                unresolved.add((agent.name, server.name, "unbound_client_configuration_source"))
                continue
            client_id = _id(
                "client", agent.name, server.name, client_path, str(server.location.line),
            )
            nodes[client_id] = {
                "id": client_id,
                "kind": "mcp_client_configuration",
                "name": server.name,
                "agent": agent.name,
                "location": {"path": client_path, "line": server.location.line},
                "source_only": True,
                "deployment_verified": False,
                "effective_authority": "unknown",
            }
            edge_id = _id("resolves", client_id, implementation_id)
            edges[edge_id] = {
                "id": edge_id,
                "kind": "CONFIG_RESOLVES_TO_SOURCE_IMPLEMENTATION",
                "source": client_id,
                "target": implementation_id,
                "basis": meta["binding_origin"],
                "source_only": True,
                "effective_agent_can_call": None,
            }
            for item in discovered:
                if not isinstance(item, dict):
                    unresolved.add((agent.name, server.name, "invalid_source_tool_entry"))
                    continue
                tool_name = item.get("name")
                source_location = item.get("location")
                if not isinstance(tool_name, str) or not isinstance(source_location, dict):
                    unresolved.add((agent.name, server.name, "missing_source_tool_witness"))
                    continue
                tool_path = _relative(root, source_location.get("path"))
                tool_line = source_location.get("line")
                if tool_path != path or type(tool_line) is not int or tool_line < 1:
                    unresolved.add((agent.name, server.name, "nonlocal_or_invalid_tool_witness"))
                    continue
                matching = source_tools.get((tool_path, tool_line, tool_name), [])
                if len(matching) != 1:
                    unresolved.add((agent.name, server.name, "missing_or_ambiguous_source_tool"))
                    continue
                tool = matching[0]
                if tool.metadata.get("server") is None:
                    unresolved.add((agent.name, server.name, "tool_server_alias_unresolved"))
                    continue
                tool_id = _id("tool", tool_path, str(tool_line), tool_name)
                nodes[tool_id] = {
                    "id": tool_id,
                    "kind": "mcp_source_tool",
                    "name": tool_name,
                    "location": {"path": tool_path, "line": tool_line},
                    "binding_state": tool.metadata.get("binding_state", "unresolved"),
                    "source_only": True,
                    "deployment_verified": False,
                    "effective_authority": "unknown",
                }
                exposure_id = _id("exposes", implementation_id, tool_id)
                edges[exposure_id] = {
                    "id": exposure_id,
                    "kind": "EXPOSES_TOOL",
                    "source": implementation_id,
                    "target": tool_id,
                    "basis": "same_file_mcp_tool_source_declaration",
                    "source_only": True,
                    "runtime_tool_catalogue_verified": False,
                    "effective_agent_can_call": None,
                }

    ordered_nodes = sorted(nodes.values(), key=lambda row: row["id"])
    ordered_edges = sorted(edges.values(), key=lambda row: row["id"])
    if any(e["source"] not in nodes or e["target"] not in nodes for e in ordered_edges):
        raise ValueError("shadow edge refers to nonexistent source node")
    counts = Counter(row["kind"] for row in ordered_edges)
    return {
        "schema_version": 1,
        "mode": "local_stdio_source_implementation_shadow_not_production_adg",
        "nodes": ordered_nodes,
        "edges": ordered_edges,
        "edge_kinds": dict(sorted(counts.items())),
        "unresolved": [
            {"agent": agent, "server": server, "reason": reason}
            for agent, server, reason in sorted(unresolved)
        ],
        "target_source_executed": False,
        "runtime_tool_catalogue_verified": False,
        "effective_authority_verified": False,
        "independent_source_truth_verified": False,
        "certified_precision": None,
        "certified_recall": None,
        "production_cutover_authorized": False,
    }
