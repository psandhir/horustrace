"""Static FastAgent adapter for HorusTrace.

Recognizes the decorator-driven Python API exposed by FastAgent without
importing or executing the target repository. FastAgent-specific constructs are
normalized into HorusTrace's framework-neutral Agent, Tool and delegation model.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from horustrace.coverage import add_diagnostic
from horustrace.heuristics import infer_capabilities
from horustrace.models import (
    Agent,
    Graph,
    InputSource,
    ScanDiagnostic,
    SourceLocation,
    Tool,
)

_FAST_AGENT_IMPORT_PREFIXES = (
    "fast_agent",
    # evalstate/fast-agent exposes FastAgent from this namespace in current
    # releases and many real applications import it directly from here.
    "mcp_agent.core.fastagent",
)

_AGENT_DECORATORS = {
    "agent",
    "custom",
    "orchestrator",
    "iterative_planner",
    "router",
    "chain",
    "parallel",
    "evaluator_optimizer",
    "maker",
}
_LIST_DELEGATION_KEYS = {"agents", "sequence", "fan_out"}
_SINGLE_DELEGATION_KEYS = {"fan_in", "generator", "evaluator", "worker"}


def _location(path: Path, node: ast.AST) -> SourceLocation:
    return SourceLocation(
        path=path,
        line=getattr(node, "lineno", 1) or 1,
        column=(getattr(node, "col_offset", 0) or 0) + 1,
    )


def _call_name(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _dotted(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        return ".".join(reversed(parts))
    return None


def _literal(node: ast.AST | None) -> Any:
    if node is None:
        return None
    try:
        return ast.literal_eval(node)
    except (TypeError, ValueError):
        return None


def _kw(call: ast.Call, name: str) -> ast.AST | None:
    return next((item.value for item in call.keywords if item.arg == name), None)


def _target_names(node: ast.Assign | ast.AnnAssign) -> list[str]:
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    return [target.id for target in targets if isinstance(target, ast.Name)]


def _fast_agent_imports(tree: ast.AST) -> tuple[set[str], set[str]]:
    class_aliases: set[str] = set()
    module_aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith(
            _FAST_AGENT_IMPORT_PREFIXES
        ):
            for alias in node.names:
                if alias.name == "FastAgent":
                    class_aliases.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith(_FAST_AGENT_IMPORT_PREFIXES):
                    module_aliases.add(alias.asname or alias.name)
    return class_aliases, module_aliases


def _is_fast_agent_constructor(
    node: ast.Call,
    class_aliases: set[str],
    module_aliases: set[str],
) -> bool:
    if isinstance(node.func, ast.Name):
        return node.func.id in class_aliases
    dotted = _dotted(node.func)
    return bool(
        dotted
        and dotted.endswith(".FastAgent")
        and dotted.split(".", 1)[0] in module_aliases
    )


def is_fast_agent_file(path: Path) -> bool:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return False
    class_aliases, module_aliases = _fast_agent_imports(tree)
    if not class_aliases and not module_aliases:
        return False
    return any(
        isinstance(node, ast.Call)
        and _is_fast_agent_constructor(node, class_aliases, module_aliases)
        for node in ast.walk(tree)
    )


def _function_capabilities(node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    capabilities = set(infer_capabilities(node.name))
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        dotted = (_dotted(child.func) or _call_name(child.func) or "").lower()
        leaf = (_call_name(child.func) or "").lower()
        if (
            dotted in {
                "exec",
                "eval",
                "compile",
                "builtins.exec",
                "builtins.eval",
                "builtins.compile",
            }
            or dotted in {"os.system", "os.popen"}
            or dotted.startswith("subprocess.")
            or "create_subprocess_" in dotted
        ):
            capabilities.add("process.execute")
        if (
            dotted.startswith(("requests.", "httpx.", "aiohttp."))
            or "urllib" in dotted
        ):
            capabilities.add("network.external")
            if leaf in {"post", "put", "patch", "delete"}:
                capabilities.add("external.write")
        if leaf in {"write", "update", "save", "insert", "create", "put", "edit", "patch"}:
            capabilities.add("data.write")
        if leaf in {"delete", "remove", "unlink", "rmdir", "rmtree", "drop", "purge"}:
            capabilities.add("destructive.write")
        if leaf in {"read", "get", "search", "retrieve", "fetch", "query", "list"}:
            capabilities.add("data.read")
        if (
            "secretmanager" in dotted
            or "vault" in dotted
            or leaf in {"get_secret", "access_secret_version"}
        ):
            capabilities.add("secrets.read")
    return capabilities


def _decorator_parts(
    decorator: ast.expr,
) -> tuple[str | None, str | None, ast.Call | None]:
    call = decorator if isinstance(decorator, ast.Call) else None
    target = call.func if call is not None else decorator
    if not isinstance(target, ast.Attribute):
        return None, None, call
    return _dotted(target.value) or _call_name(target.value), target.attr, call


def _string_sequence(
    expr: ast.AST | None,
    assignments: dict[str, ast.AST],
    *,
    visited: set[str] | None = None,
) -> list[str] | None:
    if expr is None:
        return None
    visited = visited or set()
    if isinstance(expr, ast.Name) and expr.id in assignments and expr.id not in visited:
        return _string_sequence(
            assignments[expr.id],
            assignments,
            visited=visited | {expr.id},
        )
    if not isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        return None
    values: list[str] = []
    for element in expr.elts:
        value = _literal(element)
        if not isinstance(value, str):
            return None
        values.append(value)
    return values


def _literal_mapping(expr: ast.AST | None) -> dict[str, list[str]] | None:
    value = _literal(expr)
    if not isinstance(value, dict):
        return None
    result: dict[str, list[str]] = {}
    for key, items in value.items():
        if not isinstance(key, str):
            return None
        if isinstance(items, str):
            result[key] = [items]
        elif isinstance(items, (list, tuple, set)) and all(
            isinstance(item, str) for item in items
        ):
            result[key] = list(items)
        else:
            return None
    return result


def _tool_from_function(
    path: Path,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    name: str | None = None,
    source: str,
) -> Tool:
    return Tool(
        name=name or node.name,
        kind="function",
        capabilities=_function_capabilities(node),
        location=_location(path, node),
        metadata={
            "framework": "fast-agent",
            "source": source,
            "source_function": node.name,
        },
    )


def _tool_from_reference(
    path: Path,
    expr: ast.AST,
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    imports: dict[str, str],
) -> Tool | None:
    name = _call_name(expr)
    if isinstance(expr, ast.Name) and expr.id in functions:
        return _tool_from_function(
            path,
            functions[expr.id],
            source="function_tools",
        )
    if not name:
        return None
    return Tool(
        name=name,
        kind="function",
        capabilities=set(infer_capabilities(name)),
        location=_location(path, expr),
        metadata={
            "framework": "fast-agent",
            "source": "function_tools",
            "placeholder": True,
            "import_module": imports.get(name),
        },
    )


def _agent_name(
    method: str,
    call: ast.Call | None,
    function_name: str,
) -> tuple[str, bool]:
    if call is None:
        return ("default" if method in {"agent", "custom"} else function_name), True

    explicit = _literal(_kw(call, "name"))
    if isinstance(explicit, str) and explicit:
        return explicit, False

    if method == "custom":
        if len(call.args) > 1:
            positional = _literal(call.args[1])
            if isinstance(positional, str) and positional:
                return positional, False
        return "default", False

    if call.args:
        positional = _literal(call.args[0])
        if isinstance(positional, str) and positional:
            return positional, False

    if method == "agent":
        return "default", False
    return function_name, True


def _delegation_targets(
    call: ast.Call | None,
    assignments: dict[str, ast.AST],
) -> tuple[list[str], bool]:
    if call is None:
        return [], False
    targets: list[str] = []
    dynamic = False
    for key in _LIST_DELEGATION_KEYS:
        expr = _kw(call, key)
        if expr is None:
            continue
        values = _string_sequence(expr, assignments)
        if values is None:
            dynamic = True
            continue
        targets.extend(values)
    for key in _SINGLE_DELEGATION_KEYS:
        expr = _kw(call, key)
        if expr is None:
            continue
        value = _literal(expr)
        if isinstance(value, str) and value:
            targets.append(value)
        else:
            dynamic = True
    return list(dict.fromkeys(targets)), dynamic


def _explicit_function_tools(
    path: Path,
    call: ast.Call | None,
    assignments: dict[str, ast.AST],
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    imports: dict[str, str],
) -> tuple[list[Tool], bool]:
    if call is None:
        return [], False
    expr = _kw(call, "function_tools")
    if expr is None:
        return [], False
    if isinstance(expr, ast.Name) and expr.id in assignments:
        expr = assignments[expr.id]
    if not isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        return [], True
    tools: list[Tool] = []
    for element in expr.elts:
        tool = _tool_from_reference(path, element, functions, imports)
        if tool is None:
            return tools, True
        tools.append(tool)
    return tools, False


def scan_python_file(path: Path) -> Graph:
    graph = Graph()
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return graph

    class_aliases, module_aliases = _fast_agent_imports(tree)
    if not class_aliases and not module_aliases:
        return graph

    assignments: dict[str, ast.AST] = {}
    imports: dict[str, str] = {}
    functions = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                imports[alias.asname or alias.name] = module
        elif isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            for name in _target_names(node):
                assignments[name] = node.value

    apps: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        if not isinstance(node.value, ast.Call) or not _is_fast_agent_constructor(
            node.value,
            class_aliases,
            module_aliases,
        ):
            continue
        app_name = _literal(node.value.args[0]) if node.value.args else None
        for alias in _target_names(node):
            apps[alias] = str(app_name or alias)

    if not apps:
        return graph

    function_agents: dict[str, list[Agent]] = {}
    scoped_tool_specs: list[
        tuple[ast.FunctionDef | ast.AsyncFunctionDef, str, str | None]
    ] = []

    for function in functions.values():
        for decorator in function.decorator_list:
            receiver, method, call = _decorator_parts(decorator)
            if receiver in apps and method == "tool":
                tool_name = _literal(_kw(call, "name")) if call is not None else None
                graph.unbound_tools.append(
                    _tool_from_function(
                        path,
                        function,
                        name=str(tool_name) if isinstance(tool_name, str) else None,
                        source="global_tool_decorator",
                    )
                )
                add_diagnostic(
                    graph.coverage,
                    ScanDiagnostic(
                        "unresolved_tool",
                        (
                            "FastAgent global tool reachability depends on runtime "
                            "defaults or per-agent function_tools and was not bound."
                        ),
                        _location(path, decorator),
                        details={
                            "framework": "fast-agent",
                            "construct": "global_tool",
                            "tool": (
                                str(tool_name)
                                if isinstance(tool_name, str)
                                else function.name
                            ),
                        },
                    ),
                )
                continue
            if method == "tool" and receiver:
                tool_name = _literal(_kw(call, "name")) if call is not None else None
                scoped_tool_specs.append(
                    (
                        function,
                        receiver,
                        str(tool_name) if isinstance(tool_name, str) else None,
                    )
                )
                continue
            if receiver not in apps or method not in _AGENT_DECORATORS:
                continue

            agent_name, dynamic_name = _agent_name(method, call, function.name)
            delegates_to, dynamic_delegation = _delegation_targets(call, assignments)
            model = _literal(_kw(call, "model")) if call is not None else None
            servers_expr = _kw(call, "servers") if call is not None else None
            servers = (
                _string_sequence(servers_expr, assignments)
                if servers_expr is not None
                else []
            )
            dynamic_servers = servers_expr is not None and servers is None
            function_tools, dynamic_function_tools = _explicit_function_tools(
                path,
                call,
                assignments,
                functions,
                imports,
            )
            metadata: dict[str, Any] = {
                "framework": "fast-agent",
                "agent_type": method,
                "app_alias": receiver,
                "app_name": apps[receiver],
                "decorated_function": function.name,
                "instance_key": (
                    f"{path.resolve()}:{getattr(decorator, 'lineno', 1)}:"
                    f"{receiver}:{agent_name}:{method}"
                ),
            }
            if dynamic_name:
                metadata["dynamic_name"] = True
            if isinstance(model, str):
                metadata["model"] = model
            if delegates_to:
                metadata["delegates_to"] = delegates_to
            if servers:
                metadata["mcp_server_refs"] = servers
                add_diagnostic(
                    graph.coverage,
                    ScanDiagnostic(
                        "unsupported_security_construct",
                        (
                            "FastAgent MCP server references were discovered, but "
                            "endpoint, transport and authentication authority require "
                            "FastAgent configuration or AgentCard resolution."
                        ),
                        _location(path, decorator),
                        details={
                            "framework": "fast-agent",
                            "construct": "mcp_server_reference",
                            "server_refs": list(servers),
                        },
                    ),
                )
            if dynamic_servers:
                metadata["dynamic_mcp_servers"] = True
                add_diagnostic(
                    graph.coverage,
                    ScanDiagnostic(
                        "dynamic_configuration",
                        "FastAgent MCP server references could not be statically resolved.",
                        _location(path, decorator),
                        details={
                            "framework": "fast-agent",
                            "construct": "mcp_server_reference",
                        },
                    ),
                )
            if call is not None:
                for key, metadata_key in (
                    ("tools", "mcp_tool_filters"),
                    ("resources", "mcp_resource_filters"),
                    ("prompts", "mcp_prompt_filters"),
                ):
                    expr = _kw(call, key)
                    if expr is None:
                        continue
                    resolved = _literal_mapping(expr)
                    if resolved is not None:
                        metadata[metadata_key] = resolved
                    else:
                        metadata[f"dynamic_{metadata_key}"] = True
                for key in ("default", "subagents", "harness_tools"):
                    value = _literal(_kw(call, key))
                    if isinstance(value, bool):
                        metadata[key] = value

            agent = Agent(
                name=agent_name,
                tools=function_tools,
                location=_location(path, decorator),
                metadata=metadata,
            )

            shell = _literal(_kw(call, "shell")) if call is not None else None
            if shell is True:
                agent.tools.append(
                    Tool(
                        name="shell",
                        kind="builtin_shell",
                        capabilities={"process.execute", "data.read", "data.write"},
                        location=_location(path, decorator),
                        metadata={
                            "framework": "fast-agent",
                            "source": "shell=True",
                            "builtin": True,
                        },
                    )
                )

            human_input = (
                _literal(_kw(call, "human_input")) if call is not None else None
            )
            if human_input is True:
                agent.inputs.append(
                    InputSource(
                        name="human_input",
                        trust="trusted",
                        kind="user",
                        location=_location(path, decorator),
                        metadata={"framework": "fast-agent"},
                    )
                )

            if dynamic_delegation:
                add_diagnostic(
                    graph.coverage,
                    ScanDiagnostic(
                        "unresolved_delegation",
                        "FastAgent delegation targets could not be statically resolved.",
                        _location(path, decorator),
                    ),
                )
            if dynamic_function_tools:
                add_diagnostic(
                    graph.coverage,
                    ScanDiagnostic(
                        "unresolved_tool",
                        "FastAgent function_tools could not be statically resolved.",
                        _location(path, decorator),
                    ),
                )

            graph.agents.append(agent)
            function_agents.setdefault(function.name, []).append(agent)

    for function, receiver, tool_name in scoped_tool_specs:
        targets = function_agents.get(receiver, [])
        tool = _tool_from_function(
            path,
            function,
            name=tool_name,
            source="scoped_tool_decorator",
        )
        if len(targets) == 1:
            targets[0].tools.append(tool)
        else:
            tool.metadata["scoped_agent_function"] = receiver
            tool.metadata["ambiguous_scope"] = len(targets) > 1
            graph.unbound_tools.append(tool)
            add_diagnostic(
                graph.coverage,
                ScanDiagnostic(
                    "unresolved_tool",
                    "FastAgent scoped tool target could not be resolved uniquely.",
                    _location(path, function),
                ),
            )

    return graph
