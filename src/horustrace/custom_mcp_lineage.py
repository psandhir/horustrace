"""Conservative source-proven custom agent to MCP profile binding.

Only source-observed entrypoints that load a static repository YAML profile,
construct MultiMCP from that profile's mcp_servers, and inject the resulting
dispatcher into an AgentLoop can create bound MCP server relationships.
Configured tools are not treated as available or executed at runtime.
"""
from __future__ import annotations

import ast
from pathlib import Path

import yaml

from horustrace.limits import ScanLimitError, validate_yaml_safety
from horustrace.models import Graph, MCPServer, SourceLocation


def _call_leaf(call: ast.Call) -> str | None:
    target = call.func
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    return None


def _keyword(call: ast.Call, name: str) -> ast.AST | None:
    return next((kw.value for kw in call.keywords if kw.arg == name), None)


def _is_name(value: ast.AST | None, name: str) -> bool:
    return isinstance(value, ast.Name) and value.id == name


def _assignments(node: ast.AST) -> dict[str, ast.AST]:
    result: dict[str, ast.AST] = {}
    for child in ast.walk(node):
        if isinstance(child, ast.Assign):
            for target in child.targets:
                if isinstance(target, ast.Name):
                    result[target.id] = child.value
        elif (
            isinstance(child, ast.AnnAssign)
            and isinstance(child.target, ast.Name)
            and child.value is not None
        ):
            result[child.target.id] = child.value
    return result


def _profile_path(scope: ast.AST, assignments: dict[str, ast.AST]) -> str | None:
    """Trace a YAML profile into profile.get('mcp_servers') within one function."""
    loaded = {
        name
        for name, expr in assignments.items()
        if isinstance(expr, ast.Call)
        and _call_leaf(expr) == "safe_load"
        and isinstance(expr.func, ast.Attribute)
        and _is_name(expr.func.value, "yaml")
    }
    if not loaded:
        return None
    selected = any(
        isinstance(expr, ast.Call)
        and isinstance(expr.func, ast.Attribute)
        and expr.func.attr == "get"
        and isinstance(expr.func.value, ast.Name)
        and expr.func.value.id in loaded
        and expr.args
        and isinstance(expr.args[0], ast.Constant)
        and expr.args[0].value == "mcp_servers"
        for expr in assignments.values()
    )
    if not selected:
        return None
    for call in ast.walk(scope):
        if not isinstance(call, ast.Call) or _call_leaf(call) != "open" or not call.args:
            continue
        first = call.args[0]
        if (
            isinstance(first, ast.Constant)
            and isinstance(first.value, str)
            and first.value.endswith((".yaml", ".yml"))
        ):
            return first.value
    return None


def _source_connected_profile(tree: ast.AST) -> str | None:
    imports = {
        (alias.asname or alias.name, alias.name, node.module)
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
        if node.module in {"core.loop", "core.session"}
    }
    loop_aliases = {a for a, name, module in imports if name == "AgentLoop" and module == "core.loop"}
    mcp_aliases = {a for a, name, module in imports if name == "MultiMCP" and module == "core.session"}
    if not loop_aliases or not mcp_aliases:
        return None
    for scope in ast.walk(tree):
        if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        assignments = _assignments(scope)
        profile = _profile_path(scope, assignments)
        if profile is None:
            continue
        for expr in assignments.values():
            if not isinstance(expr, ast.Call) or _call_leaf(expr) not in loop_aliases:
                continue
            dispatcher = _keyword(expr, "dispatcher")
            if not isinstance(dispatcher, ast.Name):
                continue
            config = assignments.get(dispatcher.id)
            if not isinstance(config, ast.Call) or _call_leaf(config) not in mcp_aliases:
                continue
            server_list = _keyword(config, "server_configs")
            if not isinstance(server_list, ast.Name):
                continue
            selected = assignments.get(server_list.id)
            if (
                isinstance(selected, ast.Call)
                and isinstance(selected.func, ast.Attribute)
                and selected.func.attr == "get"
                and selected.args
                and isinstance(selected.args[0], ast.Constant)
                and selected.args[0].value == "mcp_servers"
            ):
                return profile
    return None


def enrich_custom_profile_mcp_bindings(
    graph: Graph, root: Path, python_paths: list[Path]
) -> None:
    """Bind only explicitly injected MCP profiles, with runtime unknown."""
    root = root.resolve()
    agents = [
        agent for agent in graph.agents
        if agent.metadata.get("framework") == "model-tool-loop"
        and agent.metadata.get("source_class") == "AgentLoop"
        and agent.location is not None
        and agent.location.path.resolve() == (root / "core" / "loop.py").resolve()
        and agent.metadata.get("discovery_basis") in {
            "model_tools_selection_dispatch",
            "source_proven_delegated_orchestration",
        }
    ]
    if not agents:
        return
    for source in python_paths:
        try:
            tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        config_name = _source_connected_profile(tree)
        if not config_name:
            continue
        config_path = (root / config_name).resolve()
        if not config_path.is_relative_to(root) or not config_path.is_file():
            continue
        try:
            profile_text = config_path.read_text(encoding="utf-8")
            validate_yaml_safety(profile_text)
            loaded = yaml.safe_load(profile_text)
        except (OSError, UnicodeDecodeError, yaml.YAMLError, ScanLimitError):
            continue
        if not isinstance(loaded, dict) or not isinstance(loaded.get("mcp_servers"), list):
            continue
        for agent in agents:
            for config in loaded["mcp_servers"]:
                if not isinstance(config, dict):
                    continue
                name = config.get("id")
                transport = config.get("transport", "stdio")
                if not isinstance(name, str) or not name or transport not in {"stdio", "sse"}:
                    continue
                if any(server.name == name for server in agent.mcp_servers):
                    continue
                script = config.get("script")
                url = config.get("url")
                if transport == "stdio" and not isinstance(script, str):
                    continue
                if transport == "sse" and not isinstance(url, str):
                    continue
                local_script = (root / script).resolve() if transport == "stdio" else None
                verified_script = (
                    local_script is not None
                    and local_script.is_relative_to(root)
                    and local_script.is_file()
                )
                agent.mcp_servers.append(
                    MCPServer(
                        name=name,
                        transport=transport,
                        command=None,
                        args=[script] if isinstance(script, str) else [],
                        url=url if isinstance(url, str) else None,
                        authenticated=None,
                        location=SourceLocation(config_path, 1, 1),
                        metadata={
                            "framework": "model-tool-loop",
                            "binding_origin": "source_proven_dispatcher_profile",
                            "source_entrypoint": source.relative_to(root).as_posix(),
                            "config_path": config_name,
                            "working_directory": config.get("cwd"),
                            "script_exists": verified_script,
                            "repository_resolved": False,
                            "tool_catalogue_dynamic": True,
                            "runtime_effectiveness": "not_verified",
                            "server_startup": "unverified",
                        },
                    )
                )
