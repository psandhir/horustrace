"""Repository-level reconstruction for source-proven config-driven OpenAI agents."""
from __future__ import annotations

import ast
import json
from copy import deepcopy
from pathlib import Path

from horustrace.coverage import add_diagnostic
from horustrace.heuristics import infer_capabilities
from horustrace.limits import MAX_JSON_BYTES
from horustrace.models import Agent, EvidenceFact, Graph, ScanDiagnostic, SourceLocation, Tool


def _call_name(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _location(path: Path, node: ast.AST) -> SourceLocation:
    return SourceLocation(
        path=path,
        line=getattr(node, "lineno", 1) or 1,
        column=(getattr(node, "col_offset", 0) or 0) + 1,
    )


def _trees(paths: list[Path]) -> list[tuple[Path, ast.AST]]:
    result: list[tuple[Path, ast.AST]] = []
    for path in paths:
        try:
            result.append((path, ast.parse(path.read_text(encoding="utf-8"), filename=str(path))))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
    return result


def _module_scope_calls(tree: ast.AST) -> list[ast.Call]:
    """Collect calls executed at module scope, including control-flow blocks."""
    calls: list[ast.Call] = []

    class Visitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            return

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            return

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            return

        def visit_Lambda(self, node: ast.Lambda) -> None:
            return

        def visit_Call(self, node: ast.Call) -> None:
            calls.append(node)
            self.generic_visit(node)

    Visitor().visit(tree)
    return calls


def _registry_contract(trees: list[tuple[Path, ast.AST]]) -> tuple[bool, set[str]]:
    has_loader = False
    has_instantiator = False
    active = False
    config_names: set[str] = set()
    for _path, tree in trees:
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                calls = [
                    _call_name(child.func)
                    for child in ast.walk(node)
                    if isinstance(child, ast.Call)
                ]
                literals = {
                    child.value
                    for child in ast.walk(node)
                    if isinstance(child, ast.Constant) and isinstance(child.value, str)
                }
                if (
                    node.name == "load_agent_definitions"
                    and "load" in calls
                    and "agents" in literals
                ):
                    has_loader = True
                if node.name == "instantiate_agents" and "Agent" in calls:
                    has_instantiator = True
                if "agent_registry" in node.name.lower() and node.name.startswith("initialize"):
                    config_names.update(
                        Path(value).name
                        for value in literals
                        if value.endswith(".json")
                    )
        for call in _module_scope_calls(tree):
            called = (_call_name(call.func) or "").lower()
            if called.startswith("initialize_") and "agent_registry" in called:
                active = True
    return has_loader and has_instantiator and active, config_names


def _tool_registry_contract(
    trees: list[tuple[Path, ast.AST]],
) -> tuple[bool, set[str]]:
    active = False
    config_names: set[str] = set()
    for _path, tree in trees:
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if node.name != "initialize_tool_registry":
                continue
            literals = {
                child.value
                for child in ast.walk(node)
                if isinstance(child, ast.Constant) and isinstance(child.value, str)
            }
            calls = {
                _call_name(child.func)
                for child in ast.walk(node)
                if isinstance(child, ast.Call)
            }
            if "load" in calls and "tools" in literals:
                active = True
            config_names.update(
                Path(value).name
                for value in literals
                if value.endswith(".json")
            )
    return active, config_names


def _load_json_candidates(paths: list[Path]) -> dict[Path, dict]:
    result: dict[Path, dict] = {}
    for path in paths:
        if path.suffix.lower() != ".json":
            continue
        try:
            if path.stat().st_size > MAX_JSON_BYTES:
                continue
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(value, dict):
            result[path] = value
    return result


def _pick_config(
    documents: dict[Path, dict],
    *,
    top_key: str,
    preferred_names: set[str],
) -> tuple[Path, dict] | None:
    candidates = [
        (path, document)
        for path, document in documents.items()
        if isinstance(document.get(top_key), list)
    ]
    preferred = [item for item in candidates if item[0].name in preferred_names]
    if len(preferred) > 1:
        fixed = [
            item
            for item in preferred
            if "fixed" in item[0].stem.lower()
        ]
        if len(fixed) == 1:
            return fixed[0]
    values = preferred or candidates
    return values[0] if len(values) == 1 else None


def _concrete_tool(
    graph: Graph,
    logical_name: str,
    tool_definition: dict | None,
) -> Tool | None:
    implementation = (
        str(tool_definition.get("function"))
        if isinstance(tool_definition, dict) and tool_definition.get("function")
        else logical_name
    )
    matches = [
        tool
        for tool in graph.all_tools()
        if tool.name == implementation and not tool.metadata.get("placeholder")
    ]
    module = (
        str(tool_definition.get("module"))
        if isinstance(tool_definition, dict) and tool_definition.get("module")
        else None
    )
    if len(matches) > 1 and module:
        suffix = Path(*module.split(".")).as_posix() + ".py"
        narrowed = [
            tool
            for tool in matches
            if tool.location and tool.location.path.as_posix().endswith(suffix)
        ]
        if len(narrowed) == 1:
            matches = narrowed
    if len(matches) != 1:
        return None
    tool = deepcopy(matches[0])
    tool.name = logical_name
    tool.metadata = {
        **tool.metadata,
        "config_registry_binding": True,
        "config_registry_function": implementation,
        "config_registry_module": module,
    }
    return tool


def enrich_configured_agents(
    graph: Graph,
    *,
    python_paths: list[Path],
    json_paths: list[Path],
) -> None:
    """Attach active config-registry authority without treating arbitrary JSON as agents."""
    trees = _trees(python_paths)
    active, agent_config_names = _registry_contract(trees)
    if not active:
        return

    if not agent_config_names:
        return

    tool_active, tool_config_names = _tool_registry_contract(trees)
    referenced_names = set(agent_config_names)
    if tool_active:
        referenced_names.update(tool_config_names)
    documents = _load_json_candidates(
        [path for path in json_paths if path.name in referenced_names]
    )
    agent_config = _pick_config(
        documents,
        top_key="agents",
        preferred_names=agent_config_names,
    )
    if agent_config is None:
        return

    tool_definitions: dict[str, dict] = {}
    if tool_active:
        tool_config = _pick_config(
            documents,
            top_key="tools",
            preferred_names=tool_config_names,
        )
        if tool_config is not None:
            for item in tool_config[1].get("tools", []):
                if isinstance(item, dict) and isinstance(item.get("name"), str):
                    tool_definitions[item["name"]] = item

    path, document = agent_config
    by_name: dict[str, list[Agent]] = {}
    for agent in graph.agents:
        by_name.setdefault(agent.name, []).append(agent)

    for item in document.get("agents", []):
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            continue
        name = item["name"]
        matches = by_name.get(name, [])
        if len(matches) == 1:
            agent = matches[0]
        elif not matches:
            agent = Agent(
                name=name,
                location=SourceLocation(path),
                metadata={
                    "framework": "openai-agents",
                    "agent_type": "config_registry",
                    "instance_key": f"{path.resolve()}:config:{name}",
                },
            )
            graph.agents.append(agent)
            by_name.setdefault(name, []).append(agent)
        else:
            add_diagnostic(
                graph.coverage,
                ScanDiagnostic(
                    "dynamic_configuration",
                    f"Config-defined agent '{name}' matches multiple source instances.",
                    SourceLocation(path),
                    details={"agent": name, "matches": len(matches)},
                ),
            )
            continue

        agent.metadata["config_registry_active"] = True
        agent.metadata["config_registry_path"] = str(path)
        agent.provenance.append(
            EvidenceFact(
                name,
                "loaded_by_active_agent_registry",
                "source",
                SourceLocation(path),
            )
        )

        existing = {tool.name for tool in agent.tools}
        for logical_name in item.get("tools", []) or []:
            if not isinstance(logical_name, str) or logical_name in existing:
                continue
            tool = _concrete_tool(
                graph,
                logical_name,
                tool_definitions.get(logical_name),
            )
            if tool is None:
                tool = Tool(
                    name=logical_name,
                    kind="config_tool_ref",
                    capabilities=set(infer_capabilities(logical_name)),
                    location=SourceLocation(path),
                    metadata={
                        "framework": "openai-agents",
                        "config_registry_binding": True,
                        "placeholder": True,
                    },
                )
            agent.tools.append(tool)
            existing.add(logical_name)

        handoffs = [
            value for value in (item.get("handoffs") or []) if isinstance(value, str)
        ]
        if handoffs:
            current = list(agent.metadata.get("delegates_to") or [])
            agent.metadata["delegates_to"] = list(dict.fromkeys([*current, *handoffs]))
            agent.metadata["handoff_semantics"] = True
