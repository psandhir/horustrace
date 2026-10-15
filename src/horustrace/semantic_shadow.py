"""Passive Wave B01 projection from the public Graph to canonical semantic discovery v2.

The scanner remains the authority for *observed* membership. This projection does
not run source code, parse new files, perform source-symbol linkage, or assert that
a declared MCP catalogue is agent-callable. It deliberately marks legacy graph
memberships PARTIAL pending source-edge adjudication.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from horustrace.models import Agent, Graph, SourceLocation
from horustrace.semantic_discovery import (
    SemanticBinding,
    SemanticBindingKind,
    SemanticDiscovery,
    SemanticEntity,
    SemanticEntityKind,
    SemanticObservation,
    SemanticResolution,
    stable_binding_id,
    stable_entity_id,
    stable_observation_id,
)
from horustrace.semantic_trace import _portable
from horustrace.source_context import classify_source_context
from horustrace.source_native_mcp import inspect_local_pydantic_mcp

SHADOW_SCHEMA_VERSION = 2
ORIGIN = "legacy_graph_projection_not_independently_adjudicated"


def _portable_location(location: SourceLocation | None, root: Path) -> SourceLocation | None:
    if location is None:
        return None
    return SourceLocation(
        path=Path(_portable(location.path, root)),
        line=location.line,
        column=location.column,
    )


def _framework(agent: Agent | None) -> str:
    if agent is None:
        return "unknown"
    value = agent.metadata.get("framework")
    return str(value) if isinstance(value, str) and value.strip() else "unknown"


class _ShadowBuilder:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.entities: dict[str, SemanticEntity] = {}
        self.observations: dict[str, SemanticObservation] = {}
        self.bindings: dict[str, SemanticBinding] = {}
        self.ambiguous_source_keys: dict[str, int] = {}

    def add_entity(
        self,
        obj: Any,
        *,
        kind: SemanticEntityKind,
        framework: str,
        role: str,
        owner_scope: str = "",
        resolution: SemanticResolution = SemanticResolution.PARTIAL,
    ) -> str:
        location = getattr(obj, "location", None)
        portable_location = _portable_location(location, self.root)
        source_key = (
            str(portable_location.path)
            if portable_location is not None
            else "<unlocated>/" + owner_scope
        )
        meta = getattr(obj, "metadata", None)
        metadata = meta if isinstance(meta, dict) else {}
        instance = metadata.get("instance_key")
        instance_key = _portable(instance, self.root) if instance else ""
        # A known instance key disambiguates declarations sharing the same line.
        # Owner-scope is used only when there is no source location.
        qualified_key = source_key + ("#instance=" + instance_key if instance_key else "")
        name = str(obj.name)
        entity_id = stable_entity_id(
            framework=framework,
            kind=kind,
            name=name,
            source_key=qualified_key,
            line=portable_location.line if portable_location is not None else 0,
        )
        if kind == SemanticEntityKind.AGENT and entity_id in self.entities:
            # Distinct same-name agent entries must not be silently merged.
            # There is no source-stable identity if the Graph supplies neither
            # a different source span nor an instance key. Retain both with an
            # explicit unresolved graph-order suffix, not a proven source link.
            first = self.entities[entity_id]
            first.metadata["identity_resolution"] = "ambiguous_same_source_instance"
            for observation in self.observations.values():
                if observation.entity_id == entity_id:
                    observation.resolution = SemanticResolution.UNRESOLVED
                    observation.reason = "ambiguous_same_source_instance"
            duplicate = self.ambiguous_source_keys.get(entity_id, 1)
            self.ambiguous_source_keys[entity_id] = duplicate + 1
            qualified_key += f"#ambiguous_graph_occurrence={duplicate}"
            entity_id = stable_entity_id(
                framework=framework, kind=kind, name=name,
                source_key=qualified_key,
                line=portable_location.line if portable_location is not None else 0,
            )
            resolution = SemanticResolution.UNRESOLVED
        context = metadata.get("source_context")
        if context is None:
            context = (
                classify_source_context(location.path, root=self.root)
                if location is not None
                else "unknown"
            )
        if entity_id not in self.entities:
            self.entities[entity_id] = SemanticEntity(
                entity_id=entity_id,
                name=name,
                kind=kind,
                framework=framework,
                location=portable_location,
                metadata={
                    "origin": ORIGIN,
                    "source_context": str(context),
                    "instance_key": instance_key,
                    "identity_resolution": (
                        "ambiguous_same_source_instance"
                        if resolution == SemanticResolution.UNRESOLVED
                        and kind == SemanticEntityKind.AGENT else "legacy_observed"
                    ),
                },
            )
        # Each distinct role is an observation, not an invented second object.
        observation_id = stable_observation_id(
            entity_id=entity_id,
            role=role,
            source_key=qualified_key,
        )
        self.observations[observation_id] = SemanticObservation(
            observation_id=observation_id,
            entity_id=entity_id,
            role=role,
            resolution=resolution,
            parser_id="legacy_graph_projection",
            source_key=qualified_key,
            reason=(
                "ambiguous_same_source_instance"
                if resolution == SemanticResolution.UNRESOLVED
                and kind == SemanticEntityKind.AGENT
                else "unresolved_reference_in_legacy_graph"
                if resolution == SemanticResolution.UNRESOLVED
                else "observed_legacy_graph_membership_not_source_edge_proof"
            ),
            location=portable_location,
        )
        return entity_id

    def add_binding(
        self,
        source_id: str,
        target_id: str,
        kind: SemanticBindingKind,
        *,
        location: SourceLocation | None,
    ) -> None:
        binding_id = stable_binding_id(
            source_id=source_id,
            target_id=target_id,
            kind=kind,
            basis="observed_legacy_graph_membership",
        )
        self.bindings[binding_id] = SemanticBinding(
            binding_id=binding_id,
            source_id=source_id,
            target_id=target_id,
            kind=kind,
            basis="observed_legacy_graph_membership",
            resolution=SemanticResolution.PARTIAL,
            location=_portable_location(location, self.root),
            metadata={
                "origin": ORIGIN,
                "authority_claim": "not_independently_source_verified",
            },
        )

    def result(self) -> SemanticDiscovery:
        result = SemanticDiscovery(
            entities=sorted(self.entities.values(), key=lambda row: row.entity_id),
            bindings=sorted(self.bindings.values(), key=lambda row: row.binding_id),
            observations=sorted(
                self.observations.values(), key=lambda row: row.observation_id
            ),
            schema_version=SHADOW_SCHEMA_VERSION,
        )
        result.validate()
        return result


def build_shadow_discovery(graph: Graph, root: Path) -> SemanticDiscovery:
    """Extract source-scoped inventory and *existing* graph memberships only.

    No EXPOSES_TOOL, AGENT_CAN_CALL or permission edge is synthesized from
    MCP.allowed_tools, server startup commands, unbound tools or Skill catalogues.
    """
    collector = _ShadowBuilder(root)
    for agent in graph.agents:
        framework = _framework(agent)
        agent_id = collector.add_entity(
            agent, kind=SemanticEntityKind.AGENT, framework=framework,
            role="agent_instance_observed",
        )
        for collection, kind, edge_kind, role in (
            (agent.tools, SemanticEntityKind.TOOL, SemanticBindingKind.INVOKES,
             "agent_tool_membership_observed"),
            (agent.mcp_servers, SemanticEntityKind.MCP_SERVER,
             SemanticBindingKind.BINDS_MCP, "agent_mcp_membership_observed"),
            (agent.skills, SemanticEntityKind.SKILL, SemanticBindingKind.USES_SKILL,
             "agent_skill_membership_observed"),
            (agent.identities, SemanticEntityKind.IDENTITY,
             SemanticBindingKind.USES_IDENTITY, "agent_identity_membership_observed"),
        ):
            for obj in collection:
                obj_id = collector.add_entity(
                    obj, kind=kind, framework=framework, role=role,
                    owner_scope=agent_id,
                )
                collector.add_binding(agent_id, obj_id, edge_kind, location=obj.location)

    for items, kind, role, resolution in (
        (graph.unbound_tools, SemanticEntityKind.TOOL,
         "unbound_tool_inventory", SemanticResolution.PARTIAL),
        (graph.unbound_mcp_servers, SemanticEntityKind.MCP_SERVER,
         "unbound_mcp_inventory", SemanticResolution.PARTIAL),
        (graph.unresolved_mcp_references, SemanticEntityKind.MCP_SERVER,
         "unresolved_mcp_reference", SemanticResolution.UNRESOLVED),
        (graph.unbound_skills, SemanticEntityKind.SKILL,
         "unbound_skill_inventory", SemanticResolution.PARTIAL),
        (graph.identities, SemanticEntityKind.IDENTITY,
         "unbound_identity_inventory", SemanticResolution.PARTIAL),
    ):
        for obj in items:
            collector.add_entity(
                obj, kind=kind, framework="unknown", role=role, resolution=resolution,
            )
    return collector.result()


def shadow_comparison(graph: Graph, shadow: SemanticDiscovery) -> dict[str, Any]:
    """Compare legacy membership *counts*, not source truth or accuracy."""
    expected = {
        "invokes": sum(len(agent.tools) for agent in graph.agents),
        "binds_mcp": sum(len(agent.mcp_servers) for agent in graph.agents),
        "uses_skill": sum(len(agent.skills) for agent in graph.agents),
        "uses_identity": sum(len(agent.identities) for agent in graph.agents),
    }
    observed = Counter(binding.kind.value for binding in shadow.bindings)
    # Deliberate duplicate graph memberships may collapse to one typed binding.
    # Report this difference; do not report it as lost source truth.
    return {
        "scope": "legacy_graph_membership_vs_distinct_shadow_edges",
        "legacy_agent_instances": len(graph.agents),
        "shadow_agent_entities": sum(
            entity.kind == SemanticEntityKind.AGENT for entity in shadow.entities
        ),
        "legacy_member_links": expected,
        "shadow_distinct_member_links": {
            kind: observed.get(kind, 0) for kind in expected
        },
        "unresolved_observations": sum(
            item.resolution == SemanticResolution.UNRESOLVED
            for item in shadow.observations
        ),
        "source_precision": None,
        "source_recall": None,
        "graph_behavior_changed": False,
    }


def shadow_observation_report(
    graph: Graph, root: Path, *, target: Path | None = None,
) -> dict[str, Any]:
    """Construct a portable offline v2 sidecar without mutating the input Graph."""
    shadow = build_shadow_discovery(graph, root)
    native = inspect_local_pydantic_mcp(target if target is not None else root)
    return {
        **shadow.as_dict(),
        "mode": "passive_shadow_from_legacy_graph",
        "source_native": native.as_dict(),
        "source_native_scope": "pydantic_local_mcp_literal_stdio_pilot",
        "runtime_effectiveness": "not_verified",
        "source_edge_adjudicated": False,
        "comparison": shadow_comparison(graph, shadow),
        "limitations": [
            "legacy graph membership is not independently source-adjudicated",
            "source-symbol resolution and cross-file linkage are not run by B01",
            "server tool allowlists are not MCP EXPOSES_TOOL evidence",
            "an MCP binding does not imply AGENT_CAN_CALL for its catalogue",
            "missing source or ambiguous same-line declarations require later linking",
        ],
    }
