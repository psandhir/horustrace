"""Opt-in, passive scanner semantic-survival trace.

A trace is not an inference engine. Each row is a source-scoped observation of
the Graph at a named boundary. Addition/removal says *when* a semantic fact
changed, not why: root cause requires source adjudication. No target code runs.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from horustrace.models import Graph, SourceLocation

TRACE_SCHEMA_VERSION = 1
MAX_TRACE_EVENTS = 20000


def _portable(value: object, root: Path) -> str:
    if value is None:
        return ""
    text = str(value).replace("\\", "/")
    root_str = str(root.resolve()).replace("\\", "/").rstrip("/")
    if text.startswith(root_str + "/"):
        return text[len(root_str) + 1:]
    if text == root_str:
        return "."
    # The extraction directory is ephemeral and must never become an identity.
    if "/horustrace-notebooks-" in text:
        suffix = text.split("/horustrace-notebooks-", 1)[1]
        return "<temporary-notebook>/" + suffix.split("/", 1)[-1]
    return text if not Path(text).is_absolute() else "<external-source>/" + Path(text).name


def _source(location: SourceLocation | None, root: Path) -> dict[str, Any] | None:
    if location is None:
        return None
    return {"path": _portable(location.path, root), "line": location.line}


def _row(
    kind: str, name: str, root: Path, *,
    location: SourceLocation | None = None,
    owner: str = "", attributes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "kind": kind,
        "name": name,
        "owner": owner,
        "source": _source(location, root),
        "attributes": attributes or {},
    }


def _observations(graph: Graph, root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for agent in graph.agents:
        instance = _portable(agent.metadata.get("instance_key"), root)
        owner = agent.name + "@" + instance
        rows.append(_row("agent", agent.name, root, location=agent.location,
                         attributes={
                             "instance_key": instance,
                             "framework": str(agent.metadata.get("framework") or ""),
                             "source_context": str(agent.metadata.get("source_context") or ""),
                             "entity_classification": str(agent.metadata.get(
                                 "source_entity_classification") or ""),
                         }))
        for tool in agent.tools:
            rows.append(_row("binds_tool", tool.name, root, location=tool.location,
                             owner=owner, attributes={
                                 "kind": tool.kind,
                                 "capabilities": sorted(tool.capabilities),
                                 "approval": tool.approval,
                                 "binding_state": str(tool.metadata.get("binding_state") or ""),
                                 "delegation_target": str(tool.metadata.get("delegate_target") or ""),
                             }))
        for server in agent.mcp_servers:
            rows.append(_row("binds_mcp", server.name, root, location=server.location,
                             owner=owner, attributes={
                                 "transport": server.transport,
                                 "binding_state": str(server.metadata.get("binding_state") or ""),
                                 "approval": server.approval,
                                 "allow_count": len(server.allowed_tools),
                                 "deny_count": len(server.denied_tools),
                             }))
        for skill in agent.skills:
            rows.append(_row("uses_skill", skill.name, root, location=skill.location,
                             owner=owner, attributes={
                                 "capabilities": sorted(skill.capabilities),
                             }))
        for identity in agent.identities:
            rows.append(_row("uses_identity", identity.name, root,
                             location=identity.location, owner=owner,
                             attributes={"provider": identity.provider}))
    for tool in graph.unbound_tools:
        rows.append(_row("unbound_tool", tool.name, root, location=tool.location,
                         attributes={"kind": tool.kind, "capabilities": sorted(tool.capabilities)}))
    for server in graph.unbound_mcp_servers:
        rows.append(_row("unbound_mcp", server.name, root, location=server.location,
                         attributes={
                             "transport": server.transport,
                             "binding_state": str(server.metadata.get("binding_state") or ""),
                         }))
    for skill in graph.unbound_skills:
        rows.append(_row("unbound_skill", skill.name, root, location=skill.location))
    for identity in graph.identities:
        rows.append(_row("identity", identity.name, root, location=identity.location,
                         attributes={"provider": identity.provider}))
    for flow in graph.flow_paths:
        rows.append(_row("static_flow", str(flow.sink_kind), root,
                         location=flow.steps[-1].location if flow.steps else None,
                         owner=str(flow.agent or ""), attributes={
                             "source_kind": str(flow.source_kind),
                             "basis": str(flow.basis),
                             "reachability": str(flow.agent_reachability.value),
                         }))
    for path in graph.attack_paths:
        rows.append(_row("attack_path", path.path_id, root, location=path.location,
                         owner=path.agent, attributes={
                             "basis": str(path.metadata.get("basis") or ""),
                             "proof_category": str((path.metadata.get("proof") or {}).get("category") or ""),
                         }))
    if graph.adg is not None:
        for edge in graph.adg.edges:
            rows.append(_row("adg_edge", str(edge.edge_id), root, attributes={
                "source_id": str(edge.source),
                "target_id": str(edge.target),
                "relationship": str(getattr(edge, "kind", "")),
            }))
    return rows


def _packed(item: dict[str, Any]) -> str:
    return json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class SemanticTrace:
    """Capture a bounded diff of semantic observations at named stage boundaries."""

    def __init__(self, root: Path, *, max_events: int = MAX_TRACE_EVENTS):
        if max_events < 1:
            raise ValueError("semantic trace requires a positive event budget")
        self.root = root.resolve()
        self.max_events = max_events
        self.stages: list[dict[str, Any]] = []
        self.events: list[dict[str, Any]] = []
        self.truncated = False
        self._previous: Counter[str] = Counter()

    def capture(self, stage: str, graph: Graph) -> None:
        rows = Counter(_packed(row) for row in _observations(graph, self.root))
        added = rows - self._previous
        removed = self._previous - rows
        for action, delta in (("added", added), ("removed", removed)):
            for packed, count in sorted(delta.items()):
                if len(self.events) >= self.max_events:
                    self.truncated = True
                    break
                row = json.loads(packed)
                self.events.append({
                    "stage": stage,
                    "action": action,
                    "observation": row,
                    "multiplicity": count,
                    "basis": "observed_graph_delta_not_root_cause",
                })
        self.stages.append({
            "stage": stage,
            "entities": sum(rows.values()),
            "added": sum(added.values()),
            "removed": sum(removed.values()),
            "snapshot_sha256": hashlib.sha256(
                _packed(sorted(rows.items())).encode("utf-8")
            ).hexdigest(),
        })
        self._previous = rows

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": TRACE_SCHEMA_VERSION,
            "scope": "passive_source_graph_stage_observations",
            "runtime_effectiveness": "not_verified",
            "stages": self.stages,
            "events": self.events,
            "events_truncated": self.truncated,
            "event_limit": self.max_events,
            "accuracy_adjudicated": False,
        }
