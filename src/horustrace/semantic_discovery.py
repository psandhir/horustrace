"""Internal semantic-discovery primitives for framework adapters.

These types sit between source/framework parsing and projection into HorusTrace's
public Graph model. They deliberately preserve workflow/control constructs that should
not be forced into Agent or Tool before enough evidence exists.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from horustrace.models import EvidenceFact, SourceLocation


class SemanticEntityKind(str, Enum):
    AGENT = "agent"
    WORKFLOW = "workflow"
    TOOL = "tool"
    MCP_SERVER = "mcp_server"
    MCP_CLIENT = "mcp_client"
    SKILL = "skill"
    IDENTITY = "identity"
    CONTROL = "control"
    TRANSFORM = "transform"
    UNKNOWN = "unknown"


class SemanticBindingKind(str, Enum):
    CONTAINS = "contains"
    INVOKES = "invokes"
    ADVERTISES = "advertises"
    DISPATCHES_TO = "dispatches_to"
    DELEGATES_TO = "delegates_to"
    BINDS_MCP = "binds_mcp"
    AGENT_BINDS_CLIENT = "agent_binds_client"
    CLIENT_CONNECTS_TO_SERVER = "client_connects_to_server"
    EXPOSES_TOOL = "exposes_tool"
    AGENT_CAN_CALL = "agent_can_call"
    USES_SKILL = "uses_skill"
    USES_IDENTITY = "uses_identity"
    ROUTES_TO = "routes_to"


class SemanticResolution(str, Enum):
    PROVEN = "proven"
    PARTIAL = "partial"
    UNRESOLVED = "unresolved"


def stable_entity_id(
    *,
    framework: str,
    kind: SemanticEntityKind,
    name: str,
    source_key: str,
    line: int,
) -> str:
    """Return a deterministic semantic entity ID.

    source_key should be repository-relative when callers need IDs to remain stable
    across checkout locations.
    """
    payload = "\0".join(
        [
            "entity-v1",
            framework.strip().lower(),
            kind.value,
            name.strip(),
            source_key.replace("\\", "/"),
            str(line),
        ]
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]
    return f"semantic-v1:entity:{digest}"


def stable_binding_id(
    *,
    source_id: str,
    target_id: str,
    kind: SemanticBindingKind,
    basis: str,
) -> str:
    payload = (
        f"binding-v1\0{source_id}\0{target_id}\0{kind.value}\0{basis.strip()}"
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]
    return f"semantic-v1:binding:{digest}"


@dataclass(slots=True)
class SemanticEntity:
    entity_id: str
    name: str
    kind: SemanticEntityKind
    framework: str
    location: SourceLocation | None = None
    provenance: list[EvidenceFact] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "name": self.name,
            "kind": self.kind.value,
            "framework": self.framework,
            "location": (
                {
                    "path": str(self.location.path),
                    "line": self.location.line,
                    "column": self.location.column,
                }
                if self.location
                else None
            ),
            "provenance": [item.as_dict() for item in self.provenance],
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class SemanticBinding:
    binding_id: str
    source_id: str
    target_id: str
    kind: SemanticBindingKind
    basis: str
    resolution: SemanticResolution
    location: SourceLocation | None = None
    provenance: list[EvidenceFact] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "binding_id": self.binding_id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "kind": self.kind.value,
            "basis": self.basis,
            "resolution": self.resolution.value,
            "location": (
                {
                    "path": str(self.location.path),
                    "line": self.location.line,
                    "column": self.location.column,
                }
                if self.location
                else None
            ),
            "provenance": [item.as_dict() for item in self.provenance],
            "metadata": dict(self.metadata),
        }



def stable_observation_id(*, entity_id: str, role: str, source_key: str) -> str:
    """Identify a scoped source observation without checkout-local paths."""
    payload = "\0".join(("observation-v2", entity_id, role, source_key.replace("\\", "/")))
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]
    return f"semantic-v2:observation:{digest}"


@dataclass(slots=True)
class SemanticObservation:
    """Evidence-limited claim about a discovered construct, not runtime proof."""

    observation_id: str
    entity_id: str
    role: str
    resolution: SemanticResolution
    parser_id: str
    source_key: str
    reason: str
    location: SourceLocation | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "observation_id": self.observation_id,
            "entity_id": self.entity_id,
            "role": self.role,
            "resolution": self.resolution.value,
            "parser_id": self.parser_id,
            "source_key": self.source_key,
            "reason": self.reason,
            "location": (
                {
                    "path": str(self.location.path),
                    "line": self.location.line,
                    "column": self.location.column,
                }
                if self.location
                else None
            ),
        }


@dataclass(slots=True)
class SemanticDiscovery:
    """A bounded set of semantic entities and evidence-backed relationships."""

    entities: list[SemanticEntity] = field(default_factory=list)
    bindings: list[SemanticBinding] = field(default_factory=list)
    observations: list[SemanticObservation] = field(default_factory=list)
    schema_version: int = 1

    def entity_map(self) -> dict[str, SemanticEntity]:
        return {item.entity_id: item for item in self.entities}

    def validate(self) -> None:
        entity_ids = [item.entity_id for item in self.entities]
        if len(entity_ids) != len(set(entity_ids)):
            raise ValueError("semantic discovery contains duplicate entity IDs")

        binding_ids = [item.binding_id for item in self.bindings]
        if len(binding_ids) != len(set(binding_ids)):
            raise ValueError("semantic discovery contains duplicate binding IDs")

        if self.schema_version not in (1, 2):
            raise ValueError("unsupported semantic discovery schema version")
        if self.schema_version == 1 and self.observations:
            raise ValueError("semantic observations require schema version 2")
        known = set(entity_ids)
        observation_ids = [item.observation_id for item in self.observations]
        if len(observation_ids) != len(set(observation_ids)):
            raise ValueError("semantic discovery contains duplicate observation IDs")
        for item in self.observations:
            if item.entity_id not in known:
                raise ValueError("semantic observation endpoint does not exist")
            if not all((item.role.strip(), item.parser_id.strip(), item.source_key.strip(),
                        item.reason.strip())):
                raise ValueError("semantic observation requires source and reason")
        for binding in self.bindings:
            if binding.source_id not in known:
                raise ValueError(
                    f"semantic binding source does not exist: {binding.source_id}"
                )
            if binding.target_id not in known:
                raise ValueError(
                    f"semantic binding target does not exist: {binding.target_id}"
                )
            if not binding.basis.strip():
                raise ValueError(
                    f"semantic binding requires evidence basis: {binding.binding_id}"
                )

    def as_dict(self) -> dict[str, Any]:
        self.validate()
        document = {
            "schema_version": self.schema_version,
            "entities": [item.as_dict() for item in self.entities],
            "bindings": [item.as_dict() for item in self.bindings],
        }
        if self.schema_version == 2:
            document["observations"] = [item.as_dict() for item in self.observations]
        return document


def semantic_entity_metadata(entity: SemanticEntity) -> dict[str, Any]:
    """Return additive metadata suitable for projected Graph entities."""
    return {
        "semantic_entity_id": entity.entity_id,
        "semantic_entity_kind": entity.kind.value,
        "semantic_framework": entity.framework,
    }


def semantic_binding_metadata(binding: SemanticBinding) -> dict[str, Any]:
    """Return additive metadata suitable for projected Graph relationships."""
    return {
        "semantic_binding_id": binding.binding_id,
        "semantic_binding_kind": binding.kind.value,
        "semantic_binding_basis": binding.basis,
        "semantic_binding_resolution": binding.resolution.value,
    }
