"""Repository-level LiveKit voice-agent and MCP mutation semantics."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from horustrace.models import Graph, InputSource, SourceLocation, Tool

_ROUTE_METHODS = {"get", "post", "put", "patch", "delete", "api_route"}
_AUTH_TOKENS = (
    "auth",
    "current_user",
    "require_user",
    "verify_user",
    "verify_token",
    "principal",
    "identity",
)


@dataclass(frozen=True)
class ModuleInfo:
    module: str
    path: Path
    tree: ast.Module
    imports: dict[str, tuple[str, str]]


def _location(path: Path, node: ast.AST) -> SourceLocation:
    return SourceLocation(
        path=path,
        line=getattr(node, "lineno", 1) or 1,
        column=(getattr(node, "col_offset", 0) or 0) + 1,
    )


def _leaf(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _dotted(node: ast.AST | None) -> str | None:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        return ".".join(reversed(parts))
    return None


def _literal(node: ast.AST | None):
    if node is None:
        return None
    try:
        return ast.literal_eval(node)
    except (TypeError, ValueError):
        return None


def _module_name(path: Path, root: Path) -> str:
    try:
        relative = path.resolve().relative_to(root.resolve()).with_suffix("")
    except ValueError:
        relative = Path(path.stem)
    parts = list(relative.parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _resolved_import_module(
    current_module: str,
    current_path: Path,
    node: ast.ImportFrom,
) -> str | None:
    if node.level == 0:
        return node.module or ""
    parts = current_module.split(".") if current_module else []
    if current_path.stem != "__init__" and parts:
        parts = parts[:-1]
    parents = node.level - 1
    if parents > len(parts):
        return None
    base = parts[: len(parts) - parents]
    if node.module:
        base.extend(part for part in node.module.split(".") if part)
    return ".".join(base)


def _imports(module: str, path: Path, tree: ast.Module) -> dict[str, tuple[str, str]]:
    result: dict[str, tuple[str, str]] = {}
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            source = _resolved_import_module(module, path, node)
            if source is None:
                continue
            for alias in node.names:
                result[alias.asname or alias.name] = (source, alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".", 1)[0]
                result[local] = (alias.name, "")
    return result


def _parse_modules(root: Path, python_paths: list[Path]) -> dict[str, ModuleInfo]:
    modules: dict[str, ModuleInfo] = {}
    for path in python_paths:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        module = _module_name(path, root)
        modules[module] = ModuleInfo(module, path, tree, _imports(module, path, tree))
    return modules


def _is_livekit_module(info: ModuleInfo) -> bool:
    for node in ast.walk(info.tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith(
            "livekit.agents"
        ):
            return True
        if isinstance(node, ast.Import) and any(
            alias.name.startswith("livekit.agents") for alias in node.names
        ):
            return True
    return False


def _function_tools(info: ModuleInfo) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    result: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    imported_function_tool = {
        local
        for local, (module, symbol) in info.imports.items()
        if module == "livekit.agents" and symbol == "function_tool"
    }
    if not imported_function_tool:
        return result
    for node in info.tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            if _leaf(target) in imported_function_tool:
                result[node.name] = node
                break
    return result


def _enclosing_function(
    tree: ast.Module,
    line: int,
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    functions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and (getattr(node, "lineno", 0) or 0) <= line
        <= (getattr(node, "end_lineno", 0) or 0)
    ]
    if not functions:
        return None
    return max(functions, key=lambda item: getattr(item, "lineno", 0) or 0)


def _assigned_before(scope: ast.AST, name: str, line: int) -> ast.AST | None:
    candidates: list[tuple[int, ast.AST]] = []
    for node in ast.walk(scope):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        node_line = getattr(node, "lineno", 0) or 0
        if node_line >= line:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if any(isinstance(target, ast.Name) and target.id == name for target in targets):
            candidates.append((node_line, node.value))
    return max(candidates, key=lambda item: item[0])[1] if candidates else None


def _tool_names(expr: ast.AST | None, scope: ast.AST, line: int) -> list[str]:
    if isinstance(expr, ast.Name):
        resolved = _assigned_before(scope, expr.id, line)
        if resolved is not None:
            return _tool_names(resolved, scope, line)
        return [expr.id]
    if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        return [item.id for item in expr.elts if isinstance(item, ast.Name)]
    return []


def _mcp_tool_name(function: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    names: set[str] = set()
    for call in (node for node in ast.walk(function) if isinstance(node, ast.Call)):
        leaf = _leaf(call.func) or ""
        if leaf not in {"_call_mcp_tool", "call_tool"} or not call.args:
            continue
        name = _literal(call.args[0])
        if isinstance(name, str):
            names.add(name)
    return next(iter(names)) if len(names) == 1 else None


def _server_aliases(info: ModuleInfo) -> set[str]:
    aliases: set[str] = set()
    for node in ast.walk(info.tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        if not isinstance(node.value, ast.Call) or _leaf(node.value.func) not in {
            "FastMCP",
            "Server",
        }:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        aliases.update(target.id for target in targets if isinstance(target, ast.Name))
    return aliases


def _mcp_tool_functions(
    modules: dict[str, ModuleInfo],
) -> dict[str, tuple[ModuleInfo, ast.FunctionDef | ast.AsyncFunctionDef]]:
    result: dict[str, tuple[ModuleInfo, ast.FunctionDef | ast.AsyncFunctionDef]] = {}
    for info in modules.values():
        server_aliases = _server_aliases(info)
        if not server_aliases:
            continue
        for node in info.tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                target = decorator.func if isinstance(decorator, ast.Call) else decorator
                if (
                    isinstance(target, ast.Attribute)
                    and target.attr == "tool"
                    and (_dotted(target.value) or _leaf(target.value)) in server_aliases
                ):
                    result[node.name] = (info, node)
                    break
    return result


def _function_table(
    modules: dict[str, ModuleInfo],
) -> dict[tuple[str, str], tuple[ModuleInfo, ast.FunctionDef | ast.AsyncFunctionDef]]:
    result = {}
    for info in modules.values():
        for node in info.tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                result[(info.module, node.name)] = (info, node)
    return result


def _resolved_call(info: ModuleInfo, call: ast.Call) -> tuple[str, str] | None:
    if isinstance(call.func, ast.Name):
        imported = info.imports.get(call.func.id)
        return imported if imported is not None else (info.module, call.func.id)
    return None


def _sql_write_kind(value: str) -> str | None:
    normalized = " ".join(value.strip().lower().split())
    if normalized.startswith(("insert ", "update ", "replace ")):
        return "write"
    if normalized.startswith(("delete ", "drop ", "truncate ")):
        return "destructive"
    return None


def _mutation_capabilities(
    start: tuple[ModuleInfo, ast.FunctionDef | ast.AsyncFunctionDef],
    functions: dict[
        tuple[str, str],
        tuple[ModuleInfo, ast.FunctionDef | ast.AsyncFunctionDef],
    ],
    *,
    tool_name: str,
    depth: int = 0,
    seen: set[tuple[str, str]] | None = None,
) -> tuple[set[str], bool]:
    if depth > 8:
        return set(), False
    info, function = start
    key = (info.module, function.name)
    seen = set() if seen is None else set(seen)
    if key in seen:
        return set(), False
    seen.add(key)

    capabilities: set[str] = set()
    concrete_write = False
    destructive_sql = False
    for call in (node for node in ast.walk(function) if isinstance(node, ast.Call)):
        leaf = (_leaf(call.func) or "").lower()
        if leaf in {"execute", "executemany"} and call.args:
            sql = _literal(call.args[0])
            if isinstance(sql, str):
                kind = _sql_write_kind(sql)
                if kind:
                    concrete_write = True
                    capabilities.add("data.write")
                    destructive_sql = destructive_sql or kind == "destructive"
        target = _resolved_call(info, call)
        if target is None:
            continue
        child = functions.get(target)
        if child is None:
            continue
        child_caps, child_write = _mutation_capabilities(
            child,
            functions,
            tool_name=tool_name,
            depth=depth + 1,
            seen=seen,
        )
        capabilities.update(child_caps)
        concrete_write = concrete_write or child_write

    if concrete_write and (
        destructive_sql
        or any(
            token in tool_name.lower()
            for token in (
                "transfer",
                "withdraw",
                "delete",
                "remove",
                "revoke",
                "terminate",
            )
        )
    ):
        capabilities.add("destructive.write")
    return capabilities, concrete_write


def _dependency_name(node: ast.AST | None) -> str:
    if not isinstance(node, ast.Call) or _leaf(node.func) != "Depends":
        return ""
    target = node.args[0] if node.args else next(
        (keyword.value for keyword in node.keywords if keyword.arg == "dependency"),
        None,
    )
    return (_dotted(target) or _leaf(target) or "").lower()


def _route_authentication_detected(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    principal_names = {
        "current_user",
        "authenticated_user",
        "principal",
        "identity",
        "claims",
    }
    parameters = list(function.args.args) + list(function.args.kwonlyargs)
    if any(parameter.arg.lower() in principal_names for parameter in parameters):
        return True

    defaults = list(function.args.defaults) + [
        value for value in function.args.kw_defaults if value is not None
    ]
    for default in defaults:
        dependency = _dependency_name(default)
        if dependency and any(token in dependency for token in _AUTH_TOKENS):
            return True
    return False


def _public_livekit_token_route(
    modules: dict[str, ModuleInfo],
) -> SourceLocation | None:
    for info in modules.values():
        for function in (
            node
            for node in ast.walk(info.tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ):
            is_web_route = False
            for decorator in function.decorator_list:
                target = decorator.func if isinstance(decorator, ast.Call) else decorator
                if (
                    isinstance(target, ast.Attribute)
                    and target.attr.lower() in _ROUTE_METHODS
                ):
                    is_web_route = True
                    break
            if not is_web_route or _route_authentication_detected(function):
                continue

            has_access_token = any(
                isinstance(call, ast.Call) and _leaf(call.func) == "AccessToken"
                for call in ast.walk(function)
            )
            if not has_access_token:
                continue

            publish_capable = False
            for call in (
                node for node in ast.walk(function) if isinstance(node, ast.Call)
            ):
                if _leaf(call.func) != "VideoGrants":
                    continue
                values = {
                    keyword.arg: _literal(keyword.value)
                    for keyword in call.keywords
                    if keyword.arg
                }
                if (
                    values.get("room_join") is True
                    and values.get("can_publish") is True
                ):
                    publish_capable = True
            if publish_capable:
                return _location(info.path, function)
    return None



def _livekit_session_consumes_room(info: ModuleInfo) -> bool:
    has_session = any(
        isinstance(call, ast.Call) and _leaf(call.func) == "AgentSession"
        for call in ast.walk(info.tree)
    )
    if not has_session:
        return False
    return any(
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr == "start"
        and any(
            keyword.arg == "room"
            and (
                (_dotted(keyword.value) or "").endswith(".room")
                or isinstance(keyword.value, ast.Name)
            )
            for keyword in call.keywords
        )
        for call in ast.walk(info.tree)
    )


def enrich_livekit_mcp_mutation_semantics(
    graph: Graph,
    root: Path,
    python_paths: list[Path],
) -> None:
    """Compose public LiveKit ingress with repo-local MCP mutation authority."""
    modules = _parse_modules(root, python_paths)
    if not modules:
        return

    public_token = _public_livekit_token_route(modules)
    mcp_tools = _mcp_tool_functions(modules)
    functions = _function_table(modules)
    repository_uses_sqlite = any(
        any(module == "sqlite3" for module, _ in info.imports.values())
        for info in modules.values()
    )

    by_path = {info.path.resolve(): info for info in modules.values()}
    for agent in graph.agents:
        if (
            agent.metadata.get("framework") != "model-tool-loop"
            or agent.location is None
        ):
            continue
        info = by_path.get(agent.location.path.resolve())
        if info is None or not _is_livekit_module(info):
            continue
        scope = _enclosing_function(info.tree, agent.location.line)
        if scope is None:
            continue

        agent_call = next(
            (
                call
                for call in ast.walk(scope)
                if isinstance(call, ast.Call)
                and _leaf(call.func) == "Agent"
                and getattr(call, "lineno", -1) == agent.location.line
            ),
            None,
        )
        if agent_call is None:
            continue
        tools_expr = next(
            (keyword.value for keyword in agent_call.keywords if keyword.arg == "tools"),
            None,
        )
        names = _tool_names(tools_expr, scope, agent.location.line)
        decorated = _function_tools(info)
        for name in names:
            wrapper = decorated.get(name)
            if wrapper is None:
                continue
            mcp_name = _mcp_tool_name(wrapper)
            capabilities: set[str] = set()
            mutation_proven = False
            if mcp_name and mcp_name in mcp_tools:
                capabilities, mutation_proven = _mutation_capabilities(
                    mcp_tools[mcp_name],
                    functions,
                    tool_name=mcp_name,
                )
            metadata = {
                "framework": "livekit-agents",
                "source_wrapper": name,
                "livekit_model_tool": True,
            }
            if mcp_name:
                metadata.update(
                    {
                        "mcp_tool_name": mcp_name,
                        "mcp_dispatch_proven": True,
                        "mcp_mutation_proven": mutation_proven,
                    }
                )
                if mutation_proven:
                    metadata["state_scope"] = "repository_local_state"
                    if repository_uses_sqlite:
                        metadata["state_backend"] = "local_sqlite"
            tool = next((item for item in agent.tools if item.name == name), None)
            if tool is None:
                tool = Tool(
                    name=name,
                    kind="function",
                    capabilities=set(capabilities),
                    location=_location(info.path, wrapper),
                    metadata=metadata,
                )
                agent.tools.append(tool)
            else:
                tool.capabilities.update(capabilities)
                tool.metadata.update(metadata)

        if (
            public_token is not None
            and _livekit_session_consumes_room(info)
            and not any(
                item.metadata.get("basis") == "source_proven_public_livekit_audio"
                for item in agent.inputs
            )
        ):
            agent.inputs.append(
                InputSource(
                    name="livekit:published-participant-audio",
                    trust="untrusted",
                    kind="web",
                    location=public_token,
                    metadata={
                        "basis": "source_proven_public_livekit_audio",
                        "runtime_invocation_proven": True,
                        "authenticated": False,
                        "room_join": True,
                        "can_publish": True,
                        "ingress_framework": "livekit",
                    },
                )
            )
