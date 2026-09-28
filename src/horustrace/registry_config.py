# ruff: noqa: I001

from __future__ import annotations

import ast
import json
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path

from horustrace.heuristics import infer_capabilities
from horustrace.models import Agent, Graph, SourceLocation, Tool


_REGISTRY_CONFIG_PREFIXES = ("agent_definitions", "tool_definitions")


def is_registry_config_filename(name: str) -> bool:
    lowered = name.lower()
    return lowered.endswith(".json") and lowered.startswith(_REGISTRY_CONFIG_PREFIXES)


@dataclass(frozen=True, slots=True)
class _RuntimeEvidence:
    active: bool
    agent_config_names: tuple[str, ...]
    tool_config_names: tuple[str, ...]


def _literal_strings(tree: ast.AST) -> list[tuple[int, str]]:
    values: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            values.append((getattr(node, "lineno", 0) or 0, node.value))
    return sorted(values)


def _method_names(node: ast.ClassDef) -> set[str]:
    return {
        item.name
        for item in node.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def _calls_name(node: ast.AST, name: str) -> bool:
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        called = (
            child.func.id
            if isinstance(child.func, ast.Name)
            else child.func.attr
            if isinstance(child.func, ast.Attribute)
            else None
        )
        if called == name:
            return True
    return False


def _function_call_names(node: ast.AST) -> set[str]:
    result: set[str] = set()
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        called = (
            child.func.id
            if isinstance(child.func, ast.Name)
            else child.func.attr
            if isinstance(child.func, ast.Attribute)
            else None
        )
        if called:
            result.add(called)
    return result


def _config_names_from_node(
    node: ast.AST,
    *,
    prefix: str,
) -> list[str]:
    names: list[str] = []
    for _line, value in _literal_strings(node):
        name = Path(value).name
        if (
            is_registry_config_filename(name)
            and name.startswith(prefix)
            and name not in names
        ):
            names.append(name)
    return names


def _runtime_evidence(python_paths: list[Path]) -> _RuntimeEvidence:
    agent_registry = False
    tool_registry = False
    active_initializer = False
    agent_names: list[str] = []
    tool_names: list[str] = []

    for path in sorted(python_paths):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue

        defines_agent_initializer = False
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                methods = _method_names(node)
                if {
                    "load_agent_definitions",
                    "instantiate_agents",
                    "_resolve_tools",
                } <= methods and _calls_name(node, "Agent"):
                    agent_registry = True
                if {
                    "load_tool_definitions",
                    "instantiate_tools",
                    "get_tool",
                } <= methods:
                    tool_registry = True

            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            calls = _function_call_names(node)
            if node.name == "initialize_agent_registry":
                defines_agent_initializer = True
                if {
                    "AgentRegistry",
                    "load_agent_definitions",
                    "instantiate_agents",
                } <= calls:
                    for name in _config_names_from_node(
                        node,
                        prefix="agent_definitions",
                    ):
                        if name not in agent_names:
                            agent_names.append(name)
            elif node.name == "initialize_tool_registry":
                if {
                    "ToolRegistry",
                    "load_tool_definitions",
                    "instantiate_tools",
                } <= calls:
                    for name in _config_names_from_node(
                        node,
                        prefix="tool_definitions",
                    ):
                        if name not in tool_names:
                            tool_names.append(name)

        # A call site in a module that does not itself define the initializer
        # proves the loader is wired into application code. This avoids treating
        # a legacy/alternate initializer definition as its own runtime call site.
        if not defines_agent_initializer:
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                called = (
                    node.func.id
                    if isinstance(node.func, ast.Name)
                    else node.func.attr
                    if isinstance(node.func, ast.Attribute)
                    else None
                )
                if called == "initialize_agent_registry":
                    active_initializer = True
                    break

    return _RuntimeEvidence(
        active=(
            agent_registry
            and tool_registry
            and active_initializer
            and bool(agent_names)
            and bool(tool_names)
        ),
        agent_config_names=tuple(agent_names),
        tool_config_names=tuple(tool_names),
    )


def _select_config(
    config_paths: list[Path],
    ordered_names: tuple[str, ...],
) -> Path | None:
    by_name: dict[str, list[Path]] = {}
    for path in config_paths:
        by_name.setdefault(path.name, []).append(path)
    for name in ordered_names:
        matches = by_name.get(name, [])
        if len(matches) == 1:
            return matches[0]
    return None


def _load_config(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    return value if isinstance(value, dict) else {}


def _candidate_tools(graph: Graph) -> list[Tool]:
    # Snapshot before registry-derived bindings are added so resolution never
    # recursively selects another synthetic registry binding.
    return [
        tool
        for tool in graph.all_tools()
        if tool.metadata.get("binding_origin") != "config_registry"
    ]


def _resolve_tool(
    definition: dict,
    candidates: list[Tool],
    config_path: Path,
) -> Tool:
    name = str(definition.get("name") or "")
    module = str(definition.get("module") or "")
    function = str(definition.get("function") or name)

    matches = []
    for tool in candidates:
        source_function = str(
            tool.metadata.get("source_function")
            or tool.metadata.get("function")
            or ""
        )
        source_module = str(
            tool.metadata.get("source_module")
            or tool.metadata.get("import_module")
            or ""
        )
        if tool.name == name:
            matches.append(tool)
            continue
        if source_function == function and (
            not module
            or not source_module
            or source_module == module
            or source_module.endswith(module)
        ):
            matches.append(tool)

    by_source: dict[tuple[str, int, str], Tool] = {}
    for item in matches:
        location = item.location
        source_path = (
            location.path.resolve().as_posix()
            if location is not None
            else str(item.metadata.get("source_path") or "")
        )
        source_line = (
            location.line
            if location is not None
            else int(item.metadata.get("source_line") or 0)
        )
        source_name = str(
            item.metadata.get("source_function")
            or item.metadata.get("function")
            or item.name
        )
        by_source.setdefault((source_path, source_line, source_name), item)

    resolved = len(by_source) == 1
    if resolved:
        tool = deepcopy(next(iter(by_source.values())))
    else:
        tool = Tool(
            name=name,
            kind="function",
            capabilities=set(infer_capabilities(name)),
            location=SourceLocation(config_path),
            metadata={"placeholder": True},
        )

    tool.name = name
    tool.metadata = {
        **tool.metadata,
        "binding_origin": "config_registry",
        "registry_config": config_path.as_posix(),
        "source_module": module or tool.metadata.get("source_module"),
        "source_function": function or tool.metadata.get("source_function"),
        "registry_resolved": resolved,
    }
    return tool


def enrich_config_registry_agents(
    graph: Graph,
    root: Path,
    *,
    python_paths: list[Path],
    config_paths: list[Path],
) -> None:
    """Reconstruct agents/tools from a source-proven JSON registry runtime.

    JSON alone is never treated as executable authority. The repository must
    prove an AgentRegistry implementation, a ToolRegistry implementation, and
    an application call to initialize_agent_registry().
    """
    evidence = _runtime_evidence(python_paths)
    if not evidence.active:
        return

    agent_config = _select_config(config_paths, evidence.agent_config_names)
    tool_config = _select_config(config_paths, evidence.tool_config_names)
    if agent_config is None or tool_config is None:
        return

    agent_doc = _load_config(agent_config)
    tool_doc = _load_config(tool_config)
    agent_defs = agent_doc.get("agents")
    tool_defs = tool_doc.get("tools")
    if not isinstance(agent_defs, list) or not isinstance(tool_defs, list):
        return

    definitions = {
        str(item.get("name")): item
        for item in tool_defs
        if isinstance(item, dict) and item.get("name")
    }
    candidates = _candidate_tools(graph)

    for item in agent_defs:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if not isinstance(name, str) or not name:
            continue

        configured_tools = item.get("tools") or []
        if not isinstance(configured_tools, list):
            configured_tools = []

        tools: list[Tool] = []
        unresolved: list[str] = []
        for tool_name in configured_tools:
            if not isinstance(tool_name, str):
                continue
            definition = definitions.get(tool_name)
            if definition is None:
                unresolved.append(tool_name)
                tools.append(
                    Tool(
                        name=tool_name,
                        kind="function",
                        capabilities=set(infer_capabilities(tool_name)),
                        location=SourceLocation(agent_config),
                        metadata={
                            "binding_origin": "config_registry",
                            "registry_config": agent_config.as_posix(),
                            "placeholder": True,
                            "registry_resolved": False,
                        },
                    )
                )
                continue
            tool = _resolve_tool(definition, candidates, tool_config)
            if not tool.metadata.get("registry_resolved"):
                unresolved.append(tool_name)
            tools.append(tool)

        agent = Agent(
            name=name,
            tools=tools,
            location=SourceLocation(agent_config),
            metadata={
                "framework": "openai-agents",
                "agent_type": "config_registry_agent",
                "discovery_basis": "source_proven_json_registry",
                "registry_config": agent_config.as_posix(),
                "tool_registry_config": tool_config.as_posix(),
                "instance_key": f"{agent_config.resolve()}:{name}",
                "model": item.get("model"),
                "instruction": item.get("instructions"),
                "tool_use_behavior": item.get("tool_use_behavior"),
                "unresolved_helpers": sorted(unresolved),
                "external_helper_semantics_unresolved": bool(unresolved),
            },
        )

        handoffs = item.get("handoffs") or []
        if isinstance(handoffs, list):
            agent.metadata["delegates_to"] = [
                value for value in handoffs if isinstance(value, str)
            ]

        graph.agents.append(agent)
