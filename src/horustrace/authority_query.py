"""Conservative effective-authority investigation queries."""
from __future__ import annotations

import fnmatch
from collections import deque
from pathlib import Path
from typing import Any

from horustrace.effective_authority import effective_authority_relationships
from horustrace.models import Agent, Graph

AUTHORITY_QUERY_SCHEMA_VERSION = 1


def _delegation_paths(graph: Graph) -> dict[str, list[list[str]]]:
    """Return unambiguous delegation paths keyed by effective leaf agent."""
    by_name: dict[str, list[Agent]] = {}
    for agent in graph.agents:
        by_name.setdefault(agent.name, []).append(agent)

    children: dict[str, list[str]] = {}
    for agent in graph.agents:
        if len(by_name.get(agent.name, [])) != 1:
            continue
        resolved: list[str] = []
        for target in agent.metadata.get("delegates_to") or []:
            name = str(target)
            if len(by_name.get(name, [])) == 1:
                resolved.append(name)
        children[agent.name] = sorted(set(resolved))

    paths: dict[str, list[list[str]]] = {}
    for root in sorted(children):
        queue: deque[list[str]] = deque([[root]])
        seen_paths: set[tuple[str, ...]] = set()
        while queue:
            path = queue.popleft()
            key = tuple(path)
            if key in seen_paths:
                continue
            seen_paths.add(key)
            leaf = path[-1]
            paths.setdefault(leaf, []).append(path)
            for child in children.get(leaf, []):
                if child in path:
                    continue
                queue.append([*path, child])

    for agent in sorted(by_name):
        if len(by_name[agent]) == 1:
            paths.setdefault(agent, []).append([agent])

    normalized: dict[str, list[list[str]]] = {}
    for leaf, values in paths.items():
        unique = {tuple(path): path for path in values}
        normalized[leaf] = [
            unique[key]
            for key in sorted(unique, key=lambda item: (len(item), item))
        ]
    return normalized


def _matches(value: str | None, pattern: str | None) -> bool:
    if pattern is None:
        return True
    if value is None:
        return False
    return fnmatch.fnmatchcase(value.lower(), pattern.lower())


def _relationship_matches(
    relationship: Any,
    *,
    capability: str | None,
    target: str | None,
    destination: str | None,
    identity: str | None,
    resolution: str | None,
    core_resolution: str | None,
) -> bool:
    if capability is not None and not any(
        _matches(item, capability) for item in relationship.capabilities
    ):
        return False
    if target is not None and not (
        _matches(relationship.target_name, target)
        or _matches(f"{relationship.target_kind}:{relationship.target_name}", target)
    ):
        return False
    if destination is not None and not any(
        _matches(str(item.get("target")), destination)
        for item in relationship.destinations
    ):
        return False
    identity_name = (
        str(relationship.identity.get("name"))
        if relationship.identity and relationship.identity.get("name")
        else None
    )
    if identity is not None and not _matches(identity_name, identity):
        return False
    if resolution is not None and relationship.resolution != resolution:
        return False
    return (
        core_resolution is None
        or relationship.core_resolution == core_resolution
    )


def query_effective_authority(
    graph: Graph,
    root: Path,
    *,
    agent: str | None = None,
    capability: str | None = None,
    target: str | None = None,
    destination: str | None = None,
    identity: str | None = None,
    resolution: str | None = None,
    core_resolution: str | None = None,
) -> dict[str, Any]:
    """Query effective authority, including explicitly delegated reachability."""
    if not any(
        (
            capability,
            target,
            destination,
            identity,
            resolution,
            core_resolution,
        )
    ):
        raise ValueError(
            "authority query requires at least one of: capability, target, "
            "destination, identity, resolution, core_resolution"
        )

    paths = _delegation_paths(graph)
    results: list[dict[str, Any]] = []
    for relationship in effective_authority_relationships(graph):
        if not _relationship_matches(
            relationship,
            capability=capability,
            target=target,
            destination=destination,
            identity=identity,
            resolution=resolution,
            core_resolution=core_resolution,
        ):
            continue

        for path in paths.get(relationship.agent, [[relationship.agent]]):
            principal = path[0]
            if agent is not None and not _matches(principal, agent):
                continue
            record = relationship.as_dict()
            location = record.get("location")
            if location and isinstance(location.get("path"), str):
                path_value = Path(location["path"])
                try:
                    location["path"] = path_value.resolve().relative_to(
                        root.resolve()
                    ).as_posix()
                except ValueError:
                    location["path"] = path_value.name
            results.append(
                {
                    "agent": principal,
                    "effective_agent": relationship.agent,
                    "delegation_path": path,
                    "delegated": len(path) > 1,
                    "relationship": record,
                }
            )

    results.sort(
        key=lambda item: (
            item["agent"],
            item["effective_agent"],
            item["relationship"]["target"]["kind"],
            item["relationship"]["target"]["name"],
            tuple(item["delegation_path"]),
        )
    )
    return {
        "schema_version": AUTHORITY_QUERY_SCHEMA_VERSION,
        "runtime_effectiveness": "not_verified",
        "query": {
            "agent": agent,
            "capability": capability,
            "target": target,
            "destination": destination,
            "identity": identity,
            "resolution": resolution,
            "core_resolution": core_resolution,
        },
        "summary": {
            "matches": len(results),
            "agents": len({item["agent"] for item in results}),
            "effective_agents": len(
                {item["effective_agent"] for item in results}
            ),
            "delegated_matches": sum(item["delegated"] for item in results),
        },
        "results": results,
    }


def render_authority_query_console(report: dict[str, Any]) -> str:
    lines = [
        "HorusTrace Authority Query",
        "=" * 28,
        f"Matches:          {report['summary']['matches']}",
        f"Agents:           {report['summary']['agents']}",
        f"Effective agents: {report['summary']['effective_agents']}",
        f"Delegated:        {report['summary']['delegated_matches']}",
        "",
    ]
    for item in report["results"]:
        relationship = item["relationship"]
        target = relationship["target"]
        lines.append(
            f"{item['agent']} -> {target['kind']}:{target['name']} "
            f"[CORE={relationship['core_resolution']}; "
            f"DETAIL={relationship['detail_resolution']}]"
        )
        if item["delegated"]:
            lines.append(
                "  delegation: " + " -> ".join(item["delegation_path"])
            )
        if relationship.get("capabilities"):
            lines.append(
                "  capabilities: " + ", ".join(relationship["capabilities"])
            )
        identity = relationship.get("identity") or {}
        if identity.get("name"):
            lines.append(f"  identity: {identity['name']}")
        destinations = [
            str(value.get("target"))
            for value in relationship.get("destinations") or []
            if value.get("target")
        ]
        if destinations:
            lines.append("  destinations: " + ", ".join(destinations))
        core_unresolved = relationship.get("core_unresolved") or []
        if core_unresolved:
            lines.append(
                "  core unresolved: " + ", ".join(core_unresolved)
            )
        unresolved = relationship.get("unresolved") or []
        if unresolved:
            lines.append(
                "  detail unresolved: " + ", ".join(unresolved)
            )
        location = relationship.get("location") or {}
        if location.get("path"):
            suffix = f":{location.get('line')}" if location.get("line") else ""
            lines.append(f"  evidence: {location['path']}{suffix}")
        lines.append("  runtime effectiveness: not_verified")
        lines.append("")
    if not report["results"]:
        lines.append("No matching effective-authority relationships.")
    return "\n".join(lines).rstrip()
