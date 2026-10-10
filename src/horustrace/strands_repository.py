from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from horustrace.adapters.amazon_agentic import (
    _VENDED_TOOL_CAPABILITIES,
    STRANDS_FRAMEWORK,
    _attach_literal_destinations,
    _attach_literal_resources,
    _aws_runtime_identity,
    _delegated_agent_tool,
    _hook_class_control_state,
    _leaf,
    _literal,
    _literal_string,
    _location,
    _mcp_server_from_call,
    _model_metadata,
    _python_effect_capabilities,
)
from horustrace.heuristics import infer_capabilities
from horustrace.models import Agent, Graph, MCPServer, Tool


@dataclass
class _ModuleInfo:
    path: Path
    module: str
    tree: ast.Module
    imports: dict[str, tuple[str, str]] = field(default_factory=dict)
    star_imports: list[str] = field(default_factory=list)
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = field(
        default_factory=dict
    )
    classes: dict[str, ast.ClassDef] = field(default_factory=dict)
    assignments: dict[str, ast.AST] = field(default_factory=dict)


@dataclass
class _ScopeContext:
    assignments: dict[str, ast.AST] = field(default_factory=dict)
    sequences: dict[str, list[tuple[ast.AST, bool]]] = field(default_factory=dict)


@dataclass
class _AgentRecord:
    info: _ModuleInfo
    call: ast.Call
    agent: Agent
    alias: str
    function: ast.FunctionDef | ast.AsyncFunctionDef | None
    class_node: ast.ClassDef | None
    context: _ScopeContext


def _module_name(root: Path, path: Path) -> str:
    parts = list(path.resolve().relative_to(root.resolve()).with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _relative_module(
    current: str,
    level: int,
    module: str | None,
    *,
    package_file: bool,
) -> str:
    if level == 0:
        return module or ""
    parts = current.split(".") if package_file else current.split(".")[:-1]
    if level > 1:
        parts = parts[: -(level - 1)]
    if module:
        parts.extend(module.split("."))
    return ".".join(parts)


def _top_level_statements(statements: list[ast.stmt]):
    for node in statements:
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        nested: list[list[ast.stmt]] = []
        if isinstance(node, (ast.If, ast.For, ast.AsyncFor, ast.While)):
            nested.extend([node.body, node.orelse])
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            nested.append(node.body)
        elif isinstance(node, ast.Try):
            nested.extend([node.body, node.orelse, node.finalbody])
            nested.extend(handler.body for handler in node.handlers)
        elif isinstance(node, ast.Match):
            nested.extend(case.body for case in node.cases)
        for body in nested:
            yield from _top_level_statements(body)


def _build_modules(root: Path, paths: list[Path]) -> dict[str, _ModuleInfo]:
    modules: dict[str, _ModuleInfo] = {}
    for path in paths:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            module = _module_name(root, path)
        except (OSError, UnicodeDecodeError, SyntaxError, ValueError):
            continue
        if not module:
            continue
        info = _ModuleInfo(path=path.resolve(), module=module, tree=tree)
        for node in _top_level_statements(tree.body):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                info.functions[node.name] = node
            elif isinstance(node, ast.ClassDef):
                info.classes[node.name] = node
            elif isinstance(node, ast.ImportFrom):
                source = _relative_module(
                    module,
                    node.level,
                    node.module,
                    package_file=path.name == "__init__.py",
                )
                for alias in node.names:
                    if alias.name == "*":
                        if source:
                            info.star_imports.append(source)
                    else:
                        info.imports[alias.asname or alias.name] = (
                            source,
                            alias.name,
                        )
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    info.imports[alias.asname or alias.name.split(".")[0]] = (
                        alias.name,
                        "",
                    )
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if node.value is None:
                    continue
                for target in targets:
                    if isinstance(target, ast.Name):
                        info.assignments[target.id] = node.value
        modules[module] = info
    return modules


def _find_module(
    modules: dict[str, _ModuleInfo],
    module_name: str,
) -> _ModuleInfo | None:
    if module_name in modules:
        return modules[module_name]
    matches = [
        info
        for name, info in modules.items()
        if name.endswith(f".{module_name}") or module_name.endswith(f".{name}")
    ]
    return matches[0] if len(matches) == 1 else None


def _resolve_symbol_module(
    modules: dict[str, _ModuleInfo],
    info: _ModuleInfo,
    name: str,
    visited: set[tuple[str, str]] | None = None,
) -> tuple[_ModuleInfo, str] | None:
    visited = set() if visited is None else set(visited)
    key = (info.module, name)
    if key in visited:
        return None
    visited.add(key)

    direct = info.imports.get(name)
    if direct:
        module_name, remote = direct
        if module_name.startswith(("strands", "strands_tools")):
            return None
        target = _find_module(modules, module_name)
        if target is None and remote:
            target = _find_module(modules, f"{module_name}.{remote}")
        if target is not None:
            if remote in target.imports:
                chained = _resolve_symbol_module(
                    modules,
                    target,
                    remote,
                    visited,
                )
                if chained:
                    return chained
            return target, remote

    for module_name in info.star_imports:
        target = _find_module(modules, module_name)
        if target is None:
            continue
        if (
            name in target.functions
            or name in target.classes
            or name in target.assignments
            or name in target.imports
        ):
            if name in target.imports:
                chained = _resolve_symbol_module(
                    modules,
                    target,
                    name,
                    visited,
                )
                if chained:
                    return chained
            return target, name
    return None


def _strands_agent_symbols(info: _ModuleInfo) -> set[str]:
    result: set[str] = set()
    for local, (module, remote) in info.imports.items():
        if module == "strands" and remote == "Agent":
            result.add(local)
    return result


def _is_strands_agent_call(info: _ModuleInfo, call: ast.Call) -> bool:
    leaf = _leaf(call.func)
    if leaf in _strands_agent_symbols(info):
        return True
    if isinstance(call.func, ast.Attribute):
        dotted = ast.unparse(call.func)
        return dotted in {"strands.Agent", "strands.agent.Agent"}
    return False


def _scope_nodes(node: ast.FunctionDef | ast.AsyncFunctionDef):
    stack: list[ast.AST] = list(reversed(node.body))
    while stack:
        current = stack.pop()
        yield current
        if isinstance(
            current,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda),
        ):
            continue
        stack.extend(reversed(list(ast.iter_child_nodes(current))))


def _enclosing_function(
    info: _ModuleInfo,
    node: ast.AST,
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    line = getattr(node, "lineno", 0)
    candidates = [
        item
        for item in ast.walk(info.tree)
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        and getattr(item, "lineno", 0) <= line <= getattr(item, "end_lineno", 0)
    ]
    candidates.sort(
        key=lambda item: getattr(item, "end_lineno", 0) - getattr(item, "lineno", 0)
    )
    return candidates[0] if candidates else None


def _enclosing_class(info: _ModuleInfo, node: ast.AST) -> ast.ClassDef | None:
    line = getattr(node, "lineno", 0)
    candidates = [
        item
        for item in ast.walk(info.tree)
        if isinstance(item, ast.ClassDef)
        and getattr(item, "lineno", 0) <= line <= getattr(item, "end_lineno", 0)
    ]
    candidates.sort(
        key=lambda item: getattr(item, "end_lineno", 0) - getattr(item, "lineno", 0)
    )
    return candidates[0] if candidates else None


def _statement_walk(
    statements: list[ast.stmt],
    *,
    conditional: bool = False,
):
    for node in statements:
        yield node, conditional
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(node, (ast.If, ast.For, ast.AsyncFor, ast.While)):
            yield from _statement_walk(node.body, conditional=True)
            yield from _statement_walk(node.orelse, conditional=True)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            yield from _statement_walk(node.body, conditional=conditional)
        elif isinstance(node, ast.Try):
            yield from _statement_walk(node.body, conditional=True)
            yield from _statement_walk(node.orelse, conditional=True)
            yield from _statement_walk(node.finalbody, conditional=True)
            for handler in node.handlers:
                yield from _statement_walk(handler.body, conditional=True)
        elif isinstance(node, ast.Match):
            for case in node.cases:
                yield from _statement_walk(case.body, conditional=True)


def _scope_context(
    info: _ModuleInfo,
    function: ast.FunctionDef | ast.AsyncFunctionDef | None,
) -> _ScopeContext:
    context = _ScopeContext()
    statements = function.body if function is not None else info.tree.body
    for node, conditional in _statement_walk(statements):
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if not isinstance(target, ast.Name):
                    continue
                context.assignments[target.id] = node.value
                if isinstance(node.value, (ast.List, ast.Tuple, ast.Set)):
                    context.sequences[target.id] = [
                        (item, conditional) for item in node.value.elts
                    ]
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            call = node.value
            if not (
                isinstance(call.func, ast.Attribute)
                and isinstance(call.func.value, ast.Name)
            ):
                continue
            name = call.func.value.id
            if call.func.attr == "append" and len(call.args) == 1:
                context.sequences.setdefault(name, []).append(
                    (call.args[0], conditional)
                )
            elif call.func.attr == "extend" and len(call.args) == 1:
                value = call.args[0]
                if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
                    context.sequences.setdefault(name, []).extend(
                        (item, conditional) for item in value.elts
                    )
                elif isinstance(value, ast.Name):
                    context.sequences.setdefault(name, []).extend(
                        context.sequences.get(value.id, [])
                    )
    return context


def _resolve_assignment(
    node: ast.AST | None,
    context: _ScopeContext,
    visited: set[str] | None = None,
) -> ast.AST | None:
    visited = set() if visited is None else set(visited)
    if isinstance(node, ast.Name):
        if node.id in visited:
            return node
        value = context.assignments.get(node.id)
        if value is not None:
            return _resolve_assignment(value, context, visited | {node.id})
    return node


def _dict_value(
    node: ast.AST | None,
    key: str,
    context: _ScopeContext,
) -> ast.AST | None:
    node = _resolve_assignment(node, context)
    if not isinstance(node, ast.Dict):
        return None
    for raw_key, value in zip(node.keys, node.values):
        if _literal_string(raw_key) == key:
            return value
    return None


def _keyword_expr(
    call: ast.Call,
    name: str,
    context: _ScopeContext,
) -> ast.AST | None:
    for item in call.keywords:
        if item.arg == name:
            return item.value
    for item in call.keywords:
        if item.arg is None:
            value = _dict_value(item.value, name, context)
            if value is not None:
                return value
    return None


def _collection_items(
    node: ast.AST | None,
    context: _ScopeContext,
    *,
    conditional: bool = False,
    visited: set[str] | None = None,
) -> list[tuple[ast.AST, bool]]:
    if node is None:
        return []
    visited = set() if visited is None else set(visited)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        result: list[tuple[ast.AST, bool]] = []
        for item in node.elts:
            result.extend(
                _collection_items(
                    item,
                    context,
                    conditional=conditional,
                    visited=visited,
                )
            )
        return result
    if isinstance(node, ast.Starred):
        return _collection_items(
            node.value,
            context,
            conditional=conditional,
            visited=visited,
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return [
            *_collection_items(
                node.left,
                context,
                conditional=conditional,
                visited=visited,
            ),
            *_collection_items(
                node.right,
                context,
                conditional=conditional,
                visited=visited,
            ),
        ]
    if isinstance(node, ast.IfExp):
        return [
            *_collection_items(
                node.body,
                context,
                conditional=True,
                visited=visited,
            ),
            *_collection_items(
                node.orelse,
                context,
                conditional=True,
                visited=visited,
            ),
        ]
    if isinstance(node, ast.Name):
        if node.id in visited:
            return [(node, conditional)]
        if node.id in context.sequences:
            return [
                (item, conditional or item_conditional)
                for item, item_conditional in context.sequences[node.id]
            ]
        assigned = context.assignments.get(node.id)
        if assigned is not None:
            return _collection_items(
                assigned,
                context,
                conditional=conditional,
                visited=visited | {node.id},
            )
    return [(node, conditional)]


def _assignment_aliases(info: _ModuleInfo) -> dict[int, tuple[str, ast.AST]]:
    result: dict[int, tuple[str, ast.AST]] = {}
    for node in ast.walk(info.tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        if isinstance(value, ast.Await):
            value = value.value
        if not isinstance(value, ast.Call):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        alias: str | None = None
        for target in targets:
            if isinstance(target, ast.Name):
                alias = target.id
                break
            if isinstance(target, ast.Attribute):
                alias = target.attr
                break
        if alias:
            result[id(value)] = (alias, node)
    return result


def _return_calls(
    info: _ModuleInfo,
) -> dict[int, ast.FunctionDef | ast.AsyncFunctionDef]:
    result: dict[int, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for function in [
        node
        for node in ast.walk(info.tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]:
        for node in _scope_nodes(function):
            if not isinstance(node, ast.Return) or node.value is None:
                continue
            value = node.value.value if isinstance(node.value, ast.Await) else node.value
            if isinstance(value, ast.Call):
                result[id(value)] = function
    return result


def _vended_tool(
    info: _ModuleInfo,
    name: str,
) -> Tool | None:
    ref = info.imports.get(name)
    if not ref:
        return None
    module, remote = ref
    if not (
        module == "strands_tools"
        or module.startswith(("strands.vended_tools", "strands_tools."))
    ):
        return None
    source_name = remote or name
    return Tool(
        name=source_name,
        kind="strands_vended_tool",
        capabilities=set(
            _VENDED_TOOL_CAPABILITIES.get(
                source_name,
                infer_capabilities(source_name),
            )
        ),
        location=_location(info.path),
        metadata={
            "framework": STRANDS_FRAMEWORK,
            "source_module": module,
            "import_name": name,
            "repository_resolved": True,
        },
    )


def _resolve_function(
    modules: dict[str, _ModuleInfo],
    info: _ModuleInfo,
    name: str,
) -> tuple[_ModuleInfo, ast.FunctionDef | ast.AsyncFunctionDef] | None:
    if name in info.functions:
        return info, info.functions[name]
    target = _resolve_symbol_module(modules, info, name)
    if target and target[1] in target[0].functions:
        return target[0], target[0].functions[target[1]]

    # Wildcard-heavy tool packages are common in Strands applications.
    # Only use a repository-wide fallback when the symbol resolves uniquely.
    matches = [
        (candidate, function)
        for candidate in modules.values()
        for function_name, function in candidate.functions.items()
        if function_name == name
    ]
    return matches[0] if len(matches) == 1 else None


def _resolve_class(
    modules: dict[str, _ModuleInfo],
    info: _ModuleInfo,
    name: str,
) -> tuple[_ModuleInfo, ast.ClassDef] | None:
    if name in info.classes:
        return info, info.classes[name]
    target = _resolve_symbol_module(modules, info, name)
    if target and target[1] in target[0].classes:
        return target[0], target[0].classes[target[1]]
    return None



def _agentcore_runtime_invocation(function: ast.AST) -> bool:
    """Match the AgentCore endpoint supplied to a direct HTTP POST.

    A mention of AgentCore elsewhere in the function is not evidence of
    delegation; the actual POST URL must contain the invocation endpoint.
    """
    url_assignments: dict[str, ast.AST] = {}
    for child in ast.walk(function):
        if isinstance(child, ast.Assign):
            for target in child.targets:
                if isinstance(target, ast.Name):
                    url_assignments[target.id] = child.value
        elif (
            isinstance(child, ast.AnnAssign)
            and isinstance(child.target, ast.Name)
            and child.value is not None
        ):
            url_assignments[child.target.id] = child.value

    def endpoint_text(expression: ast.AST) -> str:
        # One repository-local assignment is sufficient for source-backed
        # confirmation; do not infer aliases, external values, or runtime URLs.
        if isinstance(expression, ast.Name):
            expression = url_assignments.get(expression.id, expression)
        return "".join(
            part.value
            for part in ast.walk(expression)
            if isinstance(part, ast.Constant) and isinstance(part.value, str)
        ).lower()

    for child in ast.walk(function):
        if not (
            isinstance(child, ast.Call)
            and isinstance(child.func, ast.Attribute)
            and isinstance(child.func.value, ast.Name)
            and child.func.value.id in {"requests", "httpx"}
            and child.func.attr == "post"
        ):
            continue
        urls = child.args[:1] or [
            keyword.value for keyword in child.keywords if keyword.arg == "url"
        ]
        for url in urls:
            candidate = endpoint_text(url)
            if all(
                marker in candidate
                for marker in ("bedrock-agentcore", "/runtimes/", "/invocations")
            ):
                return True
    return False

def _agentcore_credential_flow(function: ast.AST) -> str:
    """Describe only directly visible JWT forwarding; do not infer validity."""
    text = ast.unparse(function)
    if (
        "Authorization" in text
        and "jwt_token" in text
        and ("data=payload" in text or "json=payload" in text)
    ):
        return "jwt_token_forwarded_to_remote_agent"
    return "not_verified"


def _function_tool(
    modules: dict[str, _ModuleInfo],
    info: _ModuleInfo,
    name: str,
) -> Tool | None:
    resolved = _resolve_function(modules, info, name)
    if resolved is None:
        return None
    target, function = resolved
    tool = Tool(
        name=function.name,
        kind="function",
        capabilities=_python_effect_capabilities(function),
        location=_location(target.path, function),
        metadata={
            "framework": STRANDS_FRAMEWORK,
            "binding_origin": "repository_bound_function",
            "repository_resolved": True,
            "source_path": str(target.path),
            "source_function": function.name,
            "import_module": target.module,
        },
    )
    if _agentcore_runtime_invocation(function):
        tool.capabilities.add("agent.delegate")
        tool.metadata.update({
            "authority_binding": "delegation_projection",
            "binding_origin": "source_proven_agentcore_http_invocation",
            "symbol_binding_origin": "repository_bound_function",
            "authority_binding_basis": "source_proven_agentcore_http_invocation",
            # This is a source-edge discriminator, not a real remote agent ID.
            "delegate_target": f"<dynamic-agentcore-runtime:{function.name}>",
            "delegation_target_resolution": "runtime_configured_unresolved",
            "delegation_transport": "bedrock_agentcore_runtime_http",
            "credential_forwarding": _agentcore_credential_flow(function),
            "runtime_effectiveness": "not_verified",
        })
    text = ast.unparse(function)
    _attach_literal_destinations(tool, text)
    _attach_literal_resources(tool, text)
    return tool


def _append_tool(agent: Agent, tool: Tool, *, conditional: bool = False) -> None:
    if conditional:
        tool.metadata["conditional_binding"] = True
    current = next(
        (
            item
            for item in agent.tools
            if item.name == tool.name and item.kind == tool.kind
        ),
        None,
    )
    if current is None:
        agent.tools.append(tool)
        return
    current.capabilities.update(tool.capabilities)
    for destination in tool.destinations:
        if destination not in current.destinations:
            current.destinations.append(destination)
    for resource in tool.resources:
        if resource not in current.resources:
            current.resources.append(resource)
    current.metadata.update(tool.metadata)


def _append_server(agent: Agent, server: MCPServer) -> None:
    current = next(
        (item for item in agent.mcp_servers if item.name == server.name),
        None,
    )
    if current is None:
        agent.mcp_servers.append(server)
        return
    if current.url is None and server.url is not None:
        current.url = server.url
    if current.command is None and server.command is not None:
        current.command = server.command
    if not current.args and server.args:
        current.args = list(server.args)
    if current.authenticated is None:
        current.authenticated = server.authenticated
    current.metadata.update(server.metadata)


def _mcp_from_receiver(
    info: _ModuleInfo,
    receiver: str,
    context: _ScopeContext,
) -> MCPServer | None:
    value = context.assignments.get(receiver) or info.assignments.get(receiver)
    if isinstance(value, ast.Call) and (_leaf(value.func) or "") == "MCPClient":
        return _mcp_server_from_call(info.path, receiver, value)
    return None


def _dynamic_tool(
    info: _ModuleInfo,
    name: str,
    node: ast.AST,
    *,
    source: str,
) -> Tool:
    return Tool(
        name=name,
        kind="dynamic_tool_collection",
        capabilities=set(),
        location=_location(info.path, node),
        metadata={
            "framework": STRANDS_FRAMEWORK,
            "binding_origin": source,
            "dynamic_bound_collection": True,
            "binding_unresolved": True,
            "tool_catalogue_unresolved": True,
            "repository_resolved": True,
        },
    )


def _hook_state(
    modules: dict[str, _ModuleInfo],
    info: _ModuleInfo,
    node: ast.AST | None,
    context: _ScopeContext,
) -> tuple[str | None, list[str]]:
    items = _collection_items(node, context)
    if not items:
        return None, []
    states: list[str] = []
    names: list[str] = []
    for item, _ in items:
        if isinstance(item, ast.Name):
            assigned = context.assignments.get(item.id)
            if isinstance(assigned, ast.Call):
                item = assigned
        name = _leaf(item.func) if isinstance(item, ast.Call) else (
            item.id if isinstance(item, ast.Name) else None
        )
        if not name:
            states.append("unresolved")
            continue
        names.append(name)
        resolved = _resolve_class(modules, info, name)
        if resolved is None:
            states.append("unresolved")
        else:
            states.append(_hook_class_control_state(resolved[1]))
    if "enforcing" in states:
        return "enforcing", names
    if states and all(state == "non_enforcing" for state in states):
        return "non_enforcing", names
    return "unresolved", names


def _expr_names(node: ast.AST | None) -> set[str]:
    if node is None:
        return set()
    return {
        child.id
        for child in ast.walk(node)
        if isinstance(child, ast.Name)
    }


def _scope_enforcing_hook(
    modules: dict[str, _ModuleInfo],
    info: _ModuleInfo,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    context: _ScopeContext,
) -> bool:
    enforcing_vars: set[str] = set()
    for name, value in context.assignments.items():
        if not isinstance(value, ast.Call):
            continue
        class_name = _leaf(value.func)
        if not class_name:
            continue
        resolved = _resolve_class(modules, info, class_name)
        if resolved and _hook_class_control_state(resolved[1]) == "enforcing":
            enforcing_vars.add(name)
    if not enforcing_vars:
        return False

    for node in _scope_nodes(function):
        if not isinstance(node, ast.Call):
            continue
        for keyword in node.keywords:
            if keyword.arg not in {"hooks", "extra_hooks", "hook_providers"}:
                continue
            if _expr_names(keyword.value) & enforcing_vars:
                return True
    return False


def _literal_or_source(node: ast.AST | None) -> tuple[Any, str | None]:
    value = _literal(node)
    if value is not None:
        return value, None
    if node is None:
        return None, None
    return None, ast.unparse(node)


def enrich_strands_repository_graph(
    graph: Graph,
    root: Path,
    *,
    python_paths: list[Path],
) -> None:
    """Resolve source-proven Strands repository composition without execution."""
    root = root.resolve()
    modules = _build_modules(root, python_paths)
    if not modules:
        return

    existing_by_location: dict[tuple[Path, int], Agent] = {}
    for agent in graph.agents:
        if agent.metadata.get("framework") != STRANDS_FRAMEWORK or agent.location is None:
            continue
        existing_by_location[
            (agent.location.path.resolve(), agent.location.line)
        ] = agent

    records: list[_AgentRecord] = []
    aliases: dict[tuple[str, str], Agent] = {}
    factory_agents: dict[tuple[str, str], list[Agent]] = {}

    for info in modules.values():
        symbols = _strands_agent_symbols(info)
        if not symbols and not any(
            isinstance(node, ast.Import)
            and any(alias.name == "strands" for alias in node.names)
            for node in ast.walk(info.tree)
        ):
            continue

        assignment_aliases = _assignment_aliases(info)
        returned = _return_calls(info)
        for call in [
            node
            for node in ast.walk(info.tree)
            if isinstance(node, ast.Call) and _is_strands_agent_call(info, node)
        ]:
            function = _enclosing_function(info, call)
            class_node = _enclosing_class(info, call)
            context = _scope_context(info, function)
            assigned = assignment_aliases.get(id(call))
            alias = assigned[0] if assigned else ""
            if not alias and id(call) in returned:
                alias = returned[id(call)].name

            explicit_name = _literal_string(
                _resolve_assignment(
                    _keyword_expr(call, "name", context),
                    context,
                )
            )
            runtime_name_unresolved = explicit_name is None
            if explicit_name:
                runtime_name = explicit_name
            elif class_node is not None and alias in {"", "agent"}:
                runtime_name = class_node.name
            elif alias:
                runtime_name = alias
            elif function is not None:
                runtime_name = function.name
            else:
                runtime_name = f"strands-agent:{getattr(call, 'lineno', 1)}"

            location_node = assigned[1] if assigned else call
            location = _location(info.path, location_node)
            existing = existing_by_location.get(
                (location.path.resolve(), location.line)
            )
            if existing is None:
                agent = Agent(
                    name=runtime_name,
                    location=location,
                    metadata={
                        "framework": STRANDS_FRAMEWORK,
                        "language": "python",
                        "repository_resolved": True,
                    },
                )
                graph.agents.append(agent)
            else:
                agent = existing
                agent.name = runtime_name
                agent.metadata["repository_resolved"] = True

            if runtime_name_unresolved:
                agent.metadata["runtime_name_unresolved"] = True
            if function is not None:
                agent.metadata["source_factory"] = function.name
            if class_node is not None:
                agent.metadata["source_class"] = class_node.name

            model_expr = _keyword_expr(call, "model", context)
            model_meta = _model_metadata(
                _resolve_assignment(model_expr, context)
            )
            for key, value in model_meta.items():
                agent.metadata.setdefault(key, value)
            identity = _aws_runtime_identity(info.path, location, model_meta)
            if identity is not None and not any(
                item.provider == identity.provider
                and item.name == identity.name
                for item in agent.identities
            ):
                agent.identities.append(identity)

            record = _AgentRecord(
                info=info,
                call=call,
                agent=agent,
                alias=alias,
                function=function,
                class_node=class_node,
                context=context,
            )
            records.append(record)
            if alias:
                aliases[(info.module, alias)] = agent
            if function is not None:
                factory_agents.setdefault((info.module, function.name), []).append(
                    agent
                )

    def resolve_agent_expr(
        info: _ModuleInfo,
        context: _ScopeContext,
        expr: ast.AST,
    ) -> Agent | None:
        if isinstance(expr, ast.Name):
            local = aliases.get((info.module, expr.id))
            if local is not None:
                return local
            assigned = context.assignments.get(expr.id)
            if assigned is not None:
                return resolve_agent_expr(info, context, assigned)
            imported = _resolve_symbol_module(modules, info, expr.id)
            if imported:
                direct = aliases.get((imported[0].module, imported[1]))
                if direct is not None:
                    return direct
                candidates = factory_agents.get(
                    (imported[0].module, imported[1]),
                    [],
                )
                unique = list(dict.fromkeys(id(item) for item in candidates))
                if len(unique) == 1 and candidates:
                    return candidates[0]
            return None
        if isinstance(expr, ast.Call):
            name = _leaf(expr.func)
            if not name:
                return None
            if name in info.functions:
                candidates = factory_agents.get((info.module, name), [])
            else:
                imported = _resolve_symbol_module(modules, info, name)
                candidates = (
                    factory_agents.get((imported[0].module, imported[1]), [])
                    if imported
                    else []
                )
            unique_agents: list[Agent] = []
            seen: set[int] = set()
            for item in candidates:
                if id(item) not in seen:
                    unique_agents.append(item)
                    seen.add(id(item))
            return unique_agents[0] if len(unique_agents) == 1 else None
        return None

    def bind_expression(
        record: _AgentRecord,
        expr: ast.AST,
        *,
        conditional: bool,
    ) -> None:
        info = record.info
        context = record.context
        agent = record.agent

        child = resolve_agent_expr(info, context, expr)
        if child is not None and child is not agent:
            tool = _delegated_agent_tool(
                agent,
                child,
                basis="strands_repository_agent_binding",
            )
            _append_tool(agent, tool, conditional=conditional)
            delegates = list(agent.metadata.get("delegates_to") or [])
            if child.name not in delegates:
                delegates.append(child.name)
            agent.metadata["delegates_to"] = delegates
            return

        if isinstance(expr, ast.Name):
            vended = _vended_tool(info, expr.id)
            if vended is not None:
                _append_tool(agent, vended, conditional=conditional)
                return
            function_tool = _function_tool(modules, info, expr.id)
            if function_tool is not None:
                _append_tool(agent, function_tool, conditional=conditional)
                return
            _append_tool(
                agent,
                _dynamic_tool(
                    info,
                    expr.id,
                    expr,
                    source="repository_unresolved_bound_symbol",
                ),
                conditional=conditional,
            )
            return

        if isinstance(expr, ast.Attribute):
            if (
                expr.attr == "tools"
                and isinstance(expr.value, ast.Name)
            ):
                provider = context.assignments.get(expr.value.id)
                if (
                    isinstance(provider, ast.Call)
                    and (_leaf(provider.func) or "") == "A2AClientToolProvider"
                ):
                    _append_tool(
                        agent,
                        _dynamic_tool(
                            info,
                            f"{expr.value.id}.tools",
                            expr,
                            source="repository_a2a_provider_tools",
                        ),
                        conditional=conditional,
                    )
                    return
            _append_tool(
                agent,
                _dynamic_tool(
                    info,
                    ast.unparse(expr),
                    expr,
                    source="repository_dynamic_attribute_collection",
                ),
                conditional=conditional,
            )
            return

        if isinstance(expr, ast.Call):
            if isinstance(expr.func, ast.Attribute):
                leaf = expr.func.attr
                receiver = expr.func.value
                if (
                    leaf in {"list_tools_sync", "list_tools"}
                    and isinstance(receiver, ast.Name)
                ):
                    server = _mcp_from_receiver(
                        info,
                        receiver.id,
                        context,
                    )
                    if server is not None:
                        server.metadata["tool_catalogue_unresolved"] = True
                        server.metadata["repository_resolved"] = True
                        _append_server(agent, server)
                        return
                if (
                    leaf in {"as_tool", "asTool"}
                    and isinstance(receiver, ast.Name)
                ):
                    child = resolve_agent_expr(info, context, receiver)
                    if child is not None:
                        delegated = _delegated_agent_tool(
                            agent,
                            child,
                            name=_literal_string(
                                next(
                                    (
                                        kw.value
                                        for kw in expr.keywords
                                        if kw.arg == "name"
                                    ),
                                    None,
                                )
                            )
                            or child.name,
                            basis="strands_repository_explicit_as_tool",
                        )
                        _append_tool(
                            agent,
                            delegated,
                            conditional=conditional,
                        )
                        return

            name = _leaf(expr.func) or "runtime-tools"
            _append_tool(
                agent,
                _dynamic_tool(
                    info,
                    name,
                    expr,
                    source="repository_runtime_tool_factory",
                ),
                conditional=conditional,
            )
            return

        _append_tool(
            agent,
            _dynamic_tool(
                info,
                "runtime-tools",
                expr,
                source="repository_dynamic_tool_binding",
            ),
            conditional=conditional,
        )

    for record in records:
        tools_expr = _keyword_expr(
            record.call,
            "tools",
            record.context,
        )
        for expr, conditional in _collection_items(
            tools_expr,
            record.context,
        ):
            bind_expression(
                record,
                expr,
                conditional=conditional,
            )

        hook_expr = _keyword_expr(
            record.call,
            "hooks",
            record.context,
        )
        hook_state, hook_names = _hook_state(
            modules,
            record.info,
            hook_expr,
            record.context,
        )
        if hook_names:
            record.agent.metadata["hooks"] = hook_names
            record.agent.metadata["hook_control_state"] = hook_state
            record.agent.metadata["tool_control_state"] = hook_state
            record.agent.metadata["tool_control_enforcing"] = (
                hook_state == "enforcing"
            )

    # Resolve GraphBuilder constructs inside methods/functions, including
    # direct 'return builder.build()' patterns.
    for info in modules.values():
        functions = [
            node
            for node in ast.walk(info.tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        for function in functions:
            context = _scope_context(info, function)
            class_node = _enclosing_class(info, function)
            scope = list(_scope_nodes(function))
            builder_names = {
                name
                for name, value in context.assignments.items()
                if isinstance(value, ast.Call)
                and (_leaf(value.func) or "") == "GraphBuilder"
            }
            for builder_name in builder_names:
                edges: list[dict[str, str]] = []
                node_specs: list[tuple[str, ast.AST]] = []
                entry_point: str | None = None
                controls: dict[str, Any] = {}
                control_sources: dict[str, str] = {}
                built = False
                result_name: str | None = None

                for node in scope:
                    if isinstance(node, (ast.Assign, ast.AnnAssign)):
                        value = node.value
                        if (
                            isinstance(value, ast.Call)
                            and isinstance(value.func, ast.Attribute)
                            and isinstance(value.func.value, ast.Name)
                            and value.func.value.id == builder_name
                            and value.func.attr == "build"
                        ):
                            built = True
                            targets = (
                                node.targets
                                if isinstance(node, ast.Assign)
                                else [node.target]
                            )
                            for target in targets:
                                if isinstance(target, ast.Name):
                                    result_name = target.id
                                    break
                    if isinstance(node, ast.Return) and isinstance(node.value, ast.Call):
                        value = node.value
                        if (
                            isinstance(value.func, ast.Attribute)
                            and isinstance(value.func.value, ast.Name)
                            and value.func.value.id == builder_name
                            and value.func.attr == "build"
                        ):
                            built = True
                    if not isinstance(node, ast.Call) or not isinstance(
                        node.func,
                        ast.Attribute,
                    ):
                        continue
                    if not (
                        isinstance(node.func.value, ast.Name)
                        and node.func.value.id == builder_name
                    ):
                        continue
                    method = node.func.attr
                    if method == "add_node" and node.args:
                        node_id = (
                            _literal_string(node.args[1])
                            if len(node.args) > 1
                            else _literal_string(
                                next(
                                    (
                                        kw.value
                                        for kw in node.keywords
                                        if kw.arg in {"node_id", "id", "name"}
                                    ),
                                    None,
                                )
                            )
                        )
                        node_specs.append(
                            (
                                node_id or "<dynamic-graph-member>",
                                node.args[0],
                            )
                        )
                    elif method == "add_edge" and len(node.args) >= 2:
                        source = _literal_string(node.args[0])
                        target = _literal_string(node.args[1])
                        if source and target:
                            edges.append({"source": source, "target": target})
                    elif method == "set_entry_point" and node.args:
                        entry_point = _literal_string(node.args[0])
                    elif method in {
                        "set_max_node_executions",
                        "set_execution_timeout",
                        "set_node_timeout",
                    } and node.args:
                        key = {
                            "set_max_node_executions": "max_node_executions",
                            "set_execution_timeout": "execution_timeout",
                            "set_node_timeout": "node_timeout",
                        }[method]
                        literal, source = _literal_or_source(node.args[0])
                        controls[key] = literal
                        if source:
                            control_sources[key] = source

                if not built:
                    continue
                if result_name is None:
                    prefix = f"{class_node.name}." if class_node else ""
                    result_name = f"{prefix}{function.name}:graph"

                orchestrator = next(
                    (
                        agent
                        for agent in graph.agents
                        if agent.name == result_name
                        and agent.metadata.get("framework") == STRANDS_FRAMEWORK
                    ),
                    None,
                )
                if orchestrator is None:
                    orchestrator = Agent(
                        name=result_name,
                        location=_location(info.path, function),
                        metadata={
                            "framework": STRANDS_FRAMEWORK,
                            "language": "python",
                            "repository_resolved": True,
                        },
                    )
                    graph.agents.append(orchestrator)
                orchestrator.metadata.update(
                    {
                        "multiagent_type": "graph",
                        "workflow": "graph",
                        "workflow_edges": edges,
                        "entry_point": entry_point,
                        **controls,
                    }
                )
                if control_sources:
                    orchestrator.metadata["control_sources"] = control_sources

                delegates: list[str] = list(
                    orchestrator.metadata.get("delegates_to") or []
                )
                unresolved_members: list[str] = []
                for node_id, expr in node_specs:
                    child = resolve_agent_expr(info, context, expr)
                    if child is None:
                        unresolved_members.append(node_id)
                        _append_tool(
                            orchestrator,
                            Tool(
                                name=node_id,
                                kind="delegated_agent",
                                capabilities={"agent.delegate"},
                                location=_location(info.path, expr),
                                metadata={
                                    "framework": STRANDS_FRAMEWORK,
                                    "delegate_target": node_id,
                                    "binding_unresolved": True,
                                    "delegation_scope_unresolved": True,
                                    "authority_binding": "graph_node",
                                },
                            ),
                        )
                        continue
                    delegated = _delegated_agent_tool(
                        orchestrator,
                        child,
                        name=node_id,
                        basis="strands_repository_graph_node",
                    )
                    _append_tool(orchestrator, delegated)
                    if child.name not in delegates:
                        delegates.append(child.name)
                if delegates:
                    orchestrator.metadata["delegates_to"] = delegates
                if unresolved_members:
                    orchestrator.metadata["unresolved_delegates"] = unresolved_members
                    orchestrator.metadata["dynamic_control_flow"] = True

                if _scope_enforcing_hook(
                    modules,
                    info,
                    function,
                    context,
                ):
                    orchestrator.metadata["hook_control_state"] = "enforcing"
                    orchestrator.metadata["tool_control_state"] = "enforcing"
                    orchestrator.metadata["tool_control_enforcing"] = True

            for node in scope:
                if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                    continue
                value = node.value
                if not (
                    isinstance(value, ast.Call)
                    and (_leaf(value.func) or "") == "Swarm"
                ):
                    continue
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                name = next(
                    (
                        target.id
                        for target in targets
                        if isinstance(target, ast.Name)
                    ),
                    None,
                )
                if not name:
                    continue
                swarm = next(
                    (
                        agent
                        for agent in graph.agents
                        if agent.name == name
                        and agent.metadata.get("framework") == STRANDS_FRAMEWORK
                    ),
                    None,
                )
                if swarm is None:
                    swarm = Agent(
                        name=name,
                        location=_location(info.path, node),
                        metadata={
                            "framework": STRANDS_FRAMEWORK,
                            "language": "python",
                            "repository_resolved": True,
                        },
                    )
                    graph.agents.append(swarm)
                swarm.metadata.update(
                    {
                        "multiagent_type": "swarm",
                        "workflow": "swarm",
                        "handoff_topology": "dynamic",
                    }
                )

                members = value.args[0] if value.args else None
                member_items = _collection_items(members, context)
                resolved_any = False
                for member_expr, conditional in member_items:
                    child = resolve_agent_expr(info, context, member_expr)
                    if child is None:
                        continue
                    resolved_any = True
                    _append_tool(
                        swarm,
                        _delegated_agent_tool(
                            swarm,
                            child,
                            basis="strands_repository_swarm_member",
                        ),
                        conditional=conditional,
                    )
                    delegates = list(swarm.metadata.get("delegates_to") or [])
                    if child.name not in delegates:
                        delegates.append(child.name)
                    swarm.metadata["delegates_to"] = delegates
                if not resolved_any:
                    _append_tool(
                        swarm,
                        Tool(
                            name="runtime-swarm-members",
                            kind="delegated_agent",
                            capabilities={"agent.delegate"},
                            location=_location(info.path, value),
                            metadata={
                                "framework": STRANDS_FRAMEWORK,
                                "binding_unresolved": True,
                                "dynamic_bound_collection": True,
                                "delegation_scope_unresolved": True,
                                "authority_binding": "swarm_membership",
                            },
                        ),
                    )
                    swarm.metadata["dynamic_control_flow"] = True
                    swarm.metadata["delegation_scope_unresolved"] = True

                for key in (
                    "max_handoffs",
                    "max_iterations",
                    "execution_timeout",
                    "node_timeout",
                ):
                    expr = next(
                        (kw.value for kw in value.keywords if kw.arg == key),
                        None,
                    )
                    literal, source = _literal_or_source(expr)
                    if literal is not None:
                        swarm.metadata[key] = literal
                    elif source:
                        swarm.metadata[f"{key}_source"] = source

                if _scope_enforcing_hook(
                    modules,
                    info,
                    function,
                    context,
                ):
                    swarm.metadata["hook_control_state"] = "enforcing"
                    swarm.metadata["tool_control_state"] = "enforcing"
                    swarm.metadata["tool_control_enforcing"] = True
