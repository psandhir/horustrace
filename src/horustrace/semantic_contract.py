"""Canonical cross-framework semantic metadata contract.

Framework adapters may keep framework-specific evidence in metadata. Shared
security semantics consumed by Effective Authority, rules, and reporting must go
through the helpers in this module so producers and consumers cannot drift on
field names or value conventions.
"""
from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from enum import Enum
from typing import Any

from horustrace.models import Agent, Graph, ResourceScope
from horustrace.source_context import SOURCE_CONTEXTS

SEMANTIC_CONTRACT_VERSION = 1


class ToolControlState(str, Enum):
    ENFORCING = "enforcing"
    NON_ENFORCING = "non_enforcing"
    UNRESOLVED = "unresolved"


class ModelResolution(str, Enum):
    RESOLVED_IDENTIFIER = "resolved_identifier"
    PROVIDER_ONLY = "provider_only"
    UNRESOLVED_REFERENCE = "unresolved_reference"
    DYNAMIC = "dynamic"
    NOT_EXPOSED = "not_exposed"


class DataConnectionResolution(str, Enum):
    RESOLVED = "resolved"
    MODEL_SELECTED = "model_selected"
    DYNAMIC = "dynamic"
    BROAD_OR_UNKNOWN = "broad_or_unknown"
    NOT_EXPOSED = "not_exposed"


class DataResourceSemanticKey(str, Enum):
    CONNECTION_TYPE = "data_connection_type"
    PROVIDER = "data_provider"
    ACCOUNT = "data_account"
    PROJECT = "data_project"
    TENANT = "data_tenant"
    SELECTOR_PROVENANCE = "selector_provenance"
    RESOURCE_PROVENANCE = "resource_provenance"
    SOURCE_REFERENCE = "data_source_reference"
    RESOLUTION = "data_connection_resolution"
    LIMITATION = "data_connection_limitation"


DATA_CONNECTION_TYPES = frozenset(
    {
        "filesystem",
        "object_store",
        "database",
        "vector_store",
        "messaging",
        "rag_source",
        "saas_api",
        "memory",
        "cloud_resource",
        "unknown",
    }
)


class ModelSemanticKey(str, Enum):
    IDENTIFIER = "model"
    PROVIDER = "model_provider"
    HOSTING = "model_hosting"
    ENDPOINT = "model_endpoint"
    REGION = "model_region"
    SOURCE_REFERENCE = "model_source_reference"
    PROVIDER_SOURCE_REFERENCE = "model_provider_source_reference"
    CONSTRUCTOR = "model_constructor"
    REFERENCE = "model_reference"
    RESOLUTION = "model_resolution"
    LIMITATION = "model_provenance_limitation"


MODEL_HOSTING_STATES = frozenset({"provider_hosted", "self_hosted"})


class AgentSemanticKey(str, Enum):
    SOURCE_CONTEXT = "source_context"
    TOOL_CONTROL_STATE = "tool_control_state"
    TOOL_CONTROL_ENFORCING = "tool_control_enforcing"
    TOOL_CONTROL_MECHANISM = "tool_control_mechanism"


DEPRECATED_AGENT_METADATA_KEYS = frozenset({"enforcing_tool_control"})


def _key(field: AgentSemanticKey) -> str:
    return field.value


def set_tool_control(
    metadata: MutableMapping[str, Any],
    state: ToolControlState | str,
    *,
    mechanism: str | None = None,
) -> None:
    """Write one canonical tool-control semantic atomically."""

    parsed = ToolControlState(state)
    metadata[_key(AgentSemanticKey.TOOL_CONTROL_STATE)] = parsed.value
    metadata[_key(AgentSemanticKey.TOOL_CONTROL_ENFORCING)] = (
        parsed is ToolControlState.ENFORCING
    )
    if mechanism is None:
        metadata.pop(_key(AgentSemanticKey.TOOL_CONTROL_MECHANISM), None)
    else:
        if not isinstance(mechanism, str) or not mechanism.strip():
            raise ValueError("tool control mechanism must be a non-empty string")
        metadata[_key(AgentSemanticKey.TOOL_CONTROL_MECHANISM)] = mechanism


def tool_control_state(
    metadata: Mapping[str, Any],
) -> ToolControlState | None:
    raw = metadata.get(_key(AgentSemanticKey.TOOL_CONTROL_STATE))
    if raw is None:
        return None
    try:
        return ToolControlState(raw)
    except ValueError:
        return None


def tool_control_enforcing(metadata: Mapping[str, Any]) -> bool:
    state = tool_control_state(metadata)
    if state is not None:
        return state is ToolControlState.ENFORCING
    return metadata.get(_key(AgentSemanticKey.TOOL_CONTROL_ENFORCING)) is True


def tool_control_mechanism(metadata: Mapping[str, Any]) -> str | None:
    value = metadata.get(_key(AgentSemanticKey.TOOL_CONTROL_MECHANISM))
    return value if isinstance(value, str) and value else None


def set_source_context(metadata: MutableMapping[str, Any], value: str) -> None:
    if value not in SOURCE_CONTEXTS:
        raise ValueError(f"invalid source context: {value!r}")
    metadata[_key(AgentSemanticKey.SOURCE_CONTEXT)] = value


def source_context(metadata: Mapping[str, Any]) -> str:
    value = metadata.get(_key(AgentSemanticKey.SOURCE_CONTEXT))
    return value if value in SOURCE_CONTEXTS else "unknown"


def _model_key(field: ModelSemanticKey) -> str:
    return field.value


def set_model_provenance(
    metadata: MutableMapping[str, Any],
    *,
    identifier: str | None = None,
    provider: str | None = None,
    hosting: str | None = None,
    endpoint: str | None = None,
    region: str | None = None,
    source_reference: str | None = None,
    provider_source_reference: str | None = None,
    constructor: str | None = None,
    reference: str | None = None,
    resolution: ModelResolution | str | None = None,
    limitation: str | None = None,
) -> None:
    """Write canonical model provenance without inventing missing facts."""

    values = {
        ModelSemanticKey.IDENTIFIER: identifier,
        ModelSemanticKey.PROVIDER: provider,
        ModelSemanticKey.ENDPOINT: endpoint,
        ModelSemanticKey.REGION: region,
        ModelSemanticKey.SOURCE_REFERENCE: source_reference,
        ModelSemanticKey.PROVIDER_SOURCE_REFERENCE: provider_source_reference,
        ModelSemanticKey.CONSTRUCTOR: constructor,
        ModelSemanticKey.REFERENCE: reference,
        ModelSemanticKey.LIMITATION: limitation,
    }
    for field, value in values.items():
        key = _model_key(field)
        if value is None:
            metadata.pop(key, None)
            continue
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{key} must be a non-empty string")
        metadata[key] = value

    if hosting is None:
        metadata.pop(_model_key(ModelSemanticKey.HOSTING), None)
    else:
        if hosting not in MODEL_HOSTING_STATES:
            raise ValueError(f"invalid model hosting state: {hosting!r}")
        metadata[_model_key(ModelSemanticKey.HOSTING)] = hosting

    parsed_resolution = (
        ModelResolution(resolution)
        if resolution is not None
        else (
            ModelResolution.RESOLVED_IDENTIFIER
            if identifier
            else ModelResolution.PROVIDER_ONLY
            if provider
            else ModelResolution.UNRESOLVED_REFERENCE
            if reference
            else ModelResolution.DYNAMIC
        )
    )
    metadata[_model_key(ModelSemanticKey.RESOLUTION)] = parsed_resolution.value


def model_resolution(metadata: Mapping[str, Any]) -> ModelResolution | None:
    raw = metadata.get(_model_key(ModelSemanticKey.RESOLUTION))
    if raw is None:
        return None
    try:
        return ModelResolution(raw)
    except ValueError:
        return None


def model_provenance(metadata: Mapping[str, Any]) -> dict[str, Any]:
    """Return canonical source-visible model evidence from agent metadata."""

    result: dict[str, Any] = {}
    for field in ModelSemanticKey:
        value = metadata.get(_model_key(field))
        if value is not None:
            result[_model_key(field)] = value
    return result


def _data_key(field: DataResourceSemanticKey) -> str:
    return field.value


def _selector_resolution(selector: str) -> DataConnectionResolution:
    lowered = selector.strip().lower()
    if lowered in {"*", "<unknown>", "unknown"}:
        return DataConnectionResolution.BROAD_OR_UNKNOWN
    if lowered.startswith("<model-selected"):
        return DataConnectionResolution.MODEL_SELECTED
    if lowered.startswith("<") and lowered.endswith(">"):
        return DataConnectionResolution.DYNAMIC
    return DataConnectionResolution.RESOLVED


def set_data_resource_provenance(
    resource: ResourceScope,
    *,
    connection_type: str | None = None,
    provider: str | None = None,
    account: str | None = None,
    project: str | None = None,
    tenant: str | None = None,
    selector_provenance: str | None = None,
    resource_provenance: str | None = None,
    source_reference: str | None = None,
    resolution: DataConnectionResolution | str | None = None,
    limitation: str | None = None,
) -> None:
    """Write canonical data-resource provenance without inventing source facts."""

    metadata = resource.metadata
    if connection_type is not None:
        if connection_type not in DATA_CONNECTION_TYPES:
            raise ValueError(f"invalid data connection type: {connection_type!r}")
        metadata[_data_key(DataResourceSemanticKey.CONNECTION_TYPE)] = connection_type

    values = {
        DataResourceSemanticKey.PROVIDER: provider,
        DataResourceSemanticKey.ACCOUNT: account,
        DataResourceSemanticKey.PROJECT: project,
        DataResourceSemanticKey.TENANT: tenant,
        DataResourceSemanticKey.SELECTOR_PROVENANCE: selector_provenance,
        DataResourceSemanticKey.RESOURCE_PROVENANCE: resource_provenance,
        DataResourceSemanticKey.SOURCE_REFERENCE: source_reference,
        DataResourceSemanticKey.LIMITATION: limitation,
    }
    for field, value in values.items():
        key = _data_key(field)
        if value is None:
            continue
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{key} must be a non-empty string")
        metadata[key] = value

    parsed_resolution = (
        DataConnectionResolution(resolution)
        if resolution is not None
        else _selector_resolution(resource.selector)
    )
    metadata[_data_key(DataResourceSemanticKey.RESOLUTION)] = parsed_resolution.value


def data_connection_resolution(
    resource: ResourceScope,
) -> DataConnectionResolution | None:
    raw = resource.metadata.get(_data_key(DataResourceSemanticKey.RESOLUTION))
    if raw is None:
        return None
    try:
        return DataConnectionResolution(raw)
    except ValueError:
        return None


def validate_data_resource_semantics(
    resource: ResourceScope,
    *,
    owner: str,
) -> list[str]:
    errors: list[str] = []
    metadata = resource.metadata

    connection_type = metadata.get(_data_key(DataResourceSemanticKey.CONNECTION_TYPE))
    if connection_type is not None and connection_type not in DATA_CONNECTION_TYPES:
        errors.append(
            f"{owner}: invalid data_connection_type {connection_type!r}"
        )

    raw_resolution = metadata.get(_data_key(DataResourceSemanticKey.RESOLUTION))
    parsed_resolution = data_connection_resolution(resource)
    if raw_resolution is not None and parsed_resolution is None:
        errors.append(
            f"{owner}: invalid data_connection_resolution {raw_resolution!r}"
        )
    if parsed_resolution is DataConnectionResolution.NOT_EXPOSED:
        limitation = metadata.get(_data_key(DataResourceSemanticKey.LIMITATION))
        if not isinstance(limitation, str) or not limitation.strip():
            errors.append(
                f"{owner}: not_exposed data connection must declare "
                "data_connection_limitation"
            )

    return errors


def validate_agent_semantics(agent: Agent) -> list[str]:
    errors: list[str] = []
    metadata = agent.metadata

    for deprecated in DEPRECATED_AGENT_METADATA_KEYS:
        if deprecated in metadata:
            errors.append(
                f"agent {agent.name!r}: deprecated semantic metadata key {deprecated!r}"
            )

    state_key = _key(AgentSemanticKey.TOOL_CONTROL_STATE)
    enforcing_key = _key(AgentSemanticKey.TOOL_CONTROL_ENFORCING)
    mechanism_key = _key(AgentSemanticKey.TOOL_CONTROL_MECHANISM)

    raw_state = metadata.get(state_key)
    state = tool_control_state(metadata)
    if raw_state is not None and state is None:
        errors.append(
            f"agent {agent.name!r}: invalid {state_key} value {raw_state!r}"
        )
    if state is not None:
        expected = state is ToolControlState.ENFORCING
        if metadata.get(enforcing_key) is not expected:
            errors.append(
                f"agent {agent.name!r}: {enforcing_key} must be {expected!r} "
                f"when {state_key}={state.value!r}"
            )

    mechanism = metadata.get(mechanism_key)
    if mechanism is not None and (
        not isinstance(mechanism, str) or not mechanism.strip()
    ):
        errors.append(
            f"agent {agent.name!r}: {mechanism_key} must be a non-empty string"
        )

    source_context = metadata.get(_key(AgentSemanticKey.SOURCE_CONTEXT))
    if source_context is not None and source_context not in SOURCE_CONTEXTS:
        errors.append(
            f"agent {agent.name!r}: invalid source_context {source_context!r}"
        )

    raw_model_resolution = metadata.get(_model_key(ModelSemanticKey.RESOLUTION))
    parsed_model_resolution = model_resolution(metadata)
    if raw_model_resolution is not None and parsed_model_resolution is None:
        errors.append(
            f"agent {agent.name!r}: invalid model_resolution "
            f"{raw_model_resolution!r}"
        )

    hosting = metadata.get(_model_key(ModelSemanticKey.HOSTING))
    if hosting is not None and hosting not in MODEL_HOSTING_STATES:
        errors.append(
            f"agent {agent.name!r}: invalid model_hosting {hosting!r}"
        )

    if parsed_model_resolution is ModelResolution.RESOLVED_IDENTIFIER:
        identifier = metadata.get(_model_key(ModelSemanticKey.IDENTIFIER))
        if not isinstance(identifier, str) or not identifier.strip():
            errors.append(
                f"agent {agent.name!r}: resolved model must declare model identifier"
            )
    elif parsed_model_resolution is ModelResolution.PROVIDER_ONLY:
        provider = metadata.get(_model_key(ModelSemanticKey.PROVIDER))
        if not isinstance(provider, str) or not provider.strip():
            errors.append(
                f"agent {agent.name!r}: provider-only model must declare provider"
            )
    elif parsed_model_resolution is ModelResolution.UNRESOLVED_REFERENCE:
        reference = metadata.get(_model_key(ModelSemanticKey.REFERENCE))
        if not isinstance(reference, str) or not reference.strip():
            errors.append(
                f"agent {agent.name!r}: unresolved model must declare model_reference"
            )
    elif parsed_model_resolution is ModelResolution.NOT_EXPOSED:
        limitation = metadata.get(_model_key(ModelSemanticKey.LIMITATION))
        if not isinstance(limitation, str) or not limitation.strip():
            errors.append(
                f"agent {agent.name!r}: not_exposed model must declare "
                "model_provenance_limitation"
            )

    for tool in agent.tools:
        delegate_target = tool.metadata.get("delegate_target")
        if delegate_target is not None and (
            not isinstance(delegate_target, str) or not delegate_target.strip()
        ):
            errors.append(
                f"agent {agent.name!r} tool {tool.name!r}: "
                "delegate_target must be a non-empty string"
            )
        if tool.kind == "delegated_agent" and not delegate_target:
            errors.append(
                f"agent {agent.name!r} tool {tool.name!r}: "
                "delegated_agent must declare delegate_target"
            )
        unresolved_catalogue = tool.metadata.get("tool_catalogue_unresolved")
        if unresolved_catalogue is not None and not isinstance(
            unresolved_catalogue, bool
        ):
            errors.append(
                f"agent {agent.name!r} tool {tool.name!r}: "
                "tool_catalogue_unresolved must be boolean"
            )
        for resource in tool.resources:
            errors.extend(
                validate_data_resource_semantics(
                    resource,
                    owner=f"agent {agent.name!r} tool {tool.name!r}",
                )
            )

    for server in agent.mcp_servers:
        for resource in server.resources:
            errors.extend(
                validate_data_resource_semantics(
                    resource,
                    owner=f"agent {agent.name!r} mcp {server.name!r}",
                )
            )

    return errors


def validate_graph_semantics(graph: Graph) -> list[str]:
    errors: list[str] = []
    for agent in graph.agents:
        errors.extend(validate_agent_semantics(agent))
    return errors
