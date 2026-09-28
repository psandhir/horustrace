"""Repository-level enrichment for config-driven OpenAI Agents registries.

This pass is deliberately conservative. It materializes only configured agents that
are retrieved by a literal get_agent("Name") call in executable Python. Merely
having an agents JSON file is not enough to create an authority principal.
"""
from __future__ import annotations

import ast
import json
from copy import deepcopy
from pathlib import Path

from horustrace.heuristics import infer_capabilities
from horustrace.models import Agent, Graph, SourceLocation, Tool


def _literal(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _active_registry_agent_names(python_paths: list[Path]) -> set[str]:
    names: set[str] = set()
    for path in python_paths:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr != "get_agent" or not node.args:
                continue
            name = _literal(node.args[0])
            if name:
                names.add(name)
    return names


def _registry_semantics_present(python_paths: list[Path]) -> bool:
    has_agent_registry = False
    has_instantiation = False
    for path in python_paths:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if "class AgentRegistry" in text and "load_agent_definitions" in text:
            has_agent_registry = True
        if "instantiate_agents" in text and "Agent(" in text and "_resolve_tools" in text:
            has_instantiation = True
    return has_agent_registry and has_instantiation


def _agent_definition_files(root: Path) -> list[Path]:
    paths = [
        path
        for path in root.rglob("*.json")
        if path.is_file()
        and "agent" in path.name.lower()
        and "definition" in path.name.lower()
    ]
    return sorted(
        paths,
        key=lambda path: (
            0 if "fixed" in path.name.lower() else 1,
            path.as_posix(),
        ),
    )


def _definitions(path: Path) -> list[dict]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return []
    if not isinstance(raw, dict) or not isinstance(raw.get("agents"), list):
        return []
    return [item for item in raw["agents"] if isinstance(item, dict)]


def enrich_configured_openai_agents(
    graph: Graph,
    root: Path,
    python_paths: list[Path],
) -> None:
    """Bind active config-defined agents to repository-local tools."""
    if not _registry_semantics_present(python_paths):
        return

    active_names = _active_registry_agent_names(python_paths)
    if not active_names:
        return

    concrete_by_name: dict[str, list[Tool]] = {}
    for tool in graph.all_tools():
        if tool.metadata.get("placeholder"):
            continue
        concrete_by_name.setdefault(tool.name, []).append(tool)

    existing_by_name = {agent.name: agent for agent in graph.agents}
    for config_path in _agent_definition_files(root):
        for definition in _definitions(config_path):
            name = definition.get("name")
            if not isinstance(name, str) or name not in active_names:
                continue
            agent = existing_by_name.get(name)
            if agent is None:
                agent = Agent(
                    name=name,
                    location=SourceLocation(config_path),
                    metadata={
                        "framework": "openai-agents",
                        "agent_type": "config_registry_agent",
                        "discovery_basis": "literal_registry_get_agent",
                        "configured": True,
                        "config_path": str(config_path),
                        "instance_key": f"{config_path.resolve()}:configured:{name}",
                    },
                )
                graph.agents.append(agent)
                existing_by_name[name] = agent
            else:
                agent.metadata.setdefault("configured", True)
                agent.metadata.setdefault("config_path", str(config_path))

            existing_tools = {tool.name for tool in agent.tools}
            configured_tools = definition.get("tools")
            if isinstance(configured_tools, list):
                for item in configured_tools:
                    if not isinstance(item, str) or item in existing_tools:
                        continue
                    matches = concrete_by_name.get(item, [])
                    if len(matches) == 1:
                        tool = deepcopy(matches[0])
                        tool.metadata = {
                            **tool.metadata,
                            "authority_binding": "direct",
                            "authority_binding_basis": "config_registry_tool_name",
                            "configured_agent": name,
                        }
                    else:
                        tool = Tool(
                            name=item,
                            kind="configured_tool_ref",
                            capabilities=set(infer_capabilities(item)),
                            location=SourceLocation(config_path),
                            metadata={
                                "framework": "openai-agents",
                                "authority_binding": "direct",
                                "authority_binding_basis": "config_registry_tool_name",
                                "configured_agent": name,
                                "resolution": "name_only",
                            },
                        )
                    agent.tools.append(tool)
                    existing_tools.add(item)

            handoffs = definition.get("handoffs")
            if isinstance(handoffs, list):
                names = [item for item in handoffs if isinstance(item, str)]
                if names:
                    agent.metadata["delegates_to"] = list(dict.fromkeys(names))
                    agent.metadata["handoff_semantics"] = True
