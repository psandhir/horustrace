from pathlib import Path

import pytest

from horustrace.models import EvidenceFact, SourceLocation
from horustrace.semantic_discovery import (
    SemanticBinding,
    SemanticBindingKind,
    SemanticDiscovery,
    SemanticEntity,
    SemanticEntityKind,
    SemanticResolution,
    semantic_binding_metadata,
    semantic_entity_metadata,
    stable_binding_id,
    stable_entity_id,
)


def test_semantic_discovery_serializes_evidence_and_relationships() -> None:
    location = SourceLocation(Path("app/graph.py"), line=12, column=3)
    agent_id = stable_entity_id(
        framework="example-framework",
        kind=SemanticEntityKind.AGENT,
        name="researcher",
        source_key="app/graph.py",
        line=12,
    )
    tool_id = stable_entity_id(
        framework="example-framework",
        kind=SemanticEntityKind.TOOL,
        name="search",
        source_key="app/tools.py",
        line=7,
    )
    binding_id = stable_binding_id(
        source_id=agent_id,
        target_id=tool_id,
        kind=SemanticBindingKind.INVOKES,
        basis="explicit_tool_list",
    )

    entity = SemanticEntity(
        entity_id=agent_id,
        name="researcher",
        kind=SemanticEntityKind.AGENT,
        framework="example-framework",
        location=location,
        provenance=[
            EvidenceFact(
                subject="researcher",
                fact="registered agent node",
                origin="example-framework",
                location=location,
            )
        ],
    )
    tool = SemanticEntity(
        entity_id=tool_id,
        name="search",
        kind=SemanticEntityKind.TOOL,
        framework="example-framework",
    )
    binding = SemanticBinding(
        binding_id=binding_id,
        source_id=agent_id,
        target_id=tool_id,
        kind=SemanticBindingKind.INVOKES,
        basis="explicit_tool_list",
        resolution=SemanticResolution.PROVEN,
        location=location,
    )

    discovery = SemanticDiscovery(entities=[entity, tool], bindings=[binding])
    value = discovery.as_dict()

    assert value["schema_version"] == 1
    assert value["entities"][0]["kind"] == "agent"
    assert value["bindings"][0]["resolution"] == "proven"
    assert value["bindings"][0]["basis"] == "explicit_tool_list"


def test_semantic_ids_are_deterministic_and_source_sensitive() -> None:
    left = stable_entity_id(
        framework="example-framework",
        kind=SemanticEntityKind.CONTROL,
        name="router",
        source_key="app/graph.py",
        line=20,
    )
    same = stable_entity_id(
        framework="example-framework",
        kind=SemanticEntityKind.CONTROL,
        name="router",
        source_key="app/graph.py",
        line=20,
    )
    other = stable_entity_id(
        framework="example-framework",
        kind=SemanticEntityKind.CONTROL,
        name="router",
        source_key="other/graph.py",
        line=20,
    )

    assert left == same
    assert left != other


def test_semantic_discovery_rejects_missing_binding_endpoint() -> None:
    entity = SemanticEntity(
        entity_id="semantic-v1:entity:one",
        name="graph",
        kind=SemanticEntityKind.WORKFLOW,
        framework="example-framework",
    )
    binding = SemanticBinding(
        binding_id="semantic-v1:binding:one",
        source_id=entity.entity_id,
        target_id="semantic-v1:entity:missing",
        kind=SemanticBindingKind.ROUTES_TO,
        basis="add_edge",
        resolution=SemanticResolution.PROVEN,
    )

    with pytest.raises(ValueError, match="target does not exist"):
        SemanticDiscovery(entities=[entity], bindings=[binding]).validate()


def test_semantic_discovery_rejects_duplicate_ids() -> None:
    entity = SemanticEntity(
        entity_id="semantic-v1:entity:duplicate",
        name="graph",
        kind=SemanticEntityKind.WORKFLOW,
        framework="example-framework",
    )

    with pytest.raises(ValueError, match="duplicate entity IDs"):
        SemanticDiscovery(entities=[entity, entity]).validate()


def test_projection_metadata_is_additive_and_resolution_explicit() -> None:
    entity = SemanticEntity(
        entity_id="semantic-v1:entity:agent",
        name="agent",
        kind=SemanticEntityKind.AGENT,
        framework="custom",
    )
    binding = SemanticBinding(
        binding_id="semantic-v1:binding:partial",
        source_id="semantic-v1:entity:agent",
        target_id="semantic-v1:entity:tool",
        kind=SemanticBindingKind.DISPATCHES_TO,
        basis="dynamic_registry",
        resolution=SemanticResolution.PARTIAL,
    )

    assert semantic_entity_metadata(entity) == {
        "semantic_entity_id": entity.entity_id,
        "semantic_entity_kind": "agent",
        "semantic_framework": "custom",
    }
    assert semantic_binding_metadata(binding)["semantic_binding_resolution"] == "partial"
