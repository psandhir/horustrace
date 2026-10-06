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

from horustrace.models import Agent, Graph
from horustrace.source_context import SOURCE_CONTEXTS

SEMANTIC_CONTRACT_VERSION = 1


class ToolControlState(str, Enum):
    ENFORCING = "enforcing"
    NON_ENFORCING = "non_enforcing"
    UNRESOLVED = "unresolved"


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
        return ToolControlState(str(raw))
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

    return errors


def validate_graph_semantics(graph: Graph) -> list[str]:
    errors: list[str] = []
    for agent in graph.agents:
        errors.extend(validate_agent_semantics(agent))
    return errors
