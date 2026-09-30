"""Repository-level realtime session capability and MCP tool semantics.

This pass enriches already-normalized model-tool-loop agents (notably LiveKit
Agent constructors) when source proves:
- a concrete function-tool catalogue bound to the agent;
- wrapper dispatch into a repository-local MCP tool;
- repository-local helper effects such as SQLite reads/writes; and
- a web endpoint that issues a publish-capable realtime session credential.

It deliberately does not treat a generic token endpoint or a generic realtime
agent as equivalent evidence. The ingress relationship requires the capability
mint and the room-backed agent session to coexist in the same repository.
"""
# ruff: noqa: I001

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from horustrace.heuristics import infer_capabilities
from horustrace.models import Agent, Graph, InputSource, SourceLocation, Tool


_ROUTE_METHODS = {"get", "post", "put", "patch", "delete", "api_route"}
_WRITE_SQL = {"insert", "update", "replace"}
_DESTRUCTIVE_SQL = {"delete", "drop", "truncate"}


@dataclass(frozen=True)
class ModuleInfo:
    module: str
    path: Path
    tree: ast.Module
    imports: dict[str, tuple[str, str]]


@dataclass(frozen=True)
class FunctionRef:
    module: str
    name: str
    path: Path
    node: ast.FunctionDef | ast.AsyncFunctionDef


@dataclass(frozen=True)
class RealtimeCapability:
    path: Path
    function: str
    line: int
    capability: str
    authenticated: bool


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
    except (ValueError, TypeError):
        return None


def _kw(call: ast.Call, name: str) -> ast.AST | None:
    return next((item.value for item in call.keywords if item.arg == name), None)


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


def _functions(modules: dict[str, ModuleInfo]) -> dict[tuple[str, str], FunctionRef]:
    result: dict[tuple[str, str], FunctionRef] = {}
    for module, info in modules.items():
        for node in ast.walk(info.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                result[(module, node.name)] = FunctionRef(module, node.name, info.path, node)
    return result


def _resolve_function(
    modules: dict[str, ModuleInfo],
    functions: dict[tuple[str, str], FunctionRef],
    module: str,
    called: str,
) -> FunctionRef | None:
    leaf = called.rsplit(".", 1)[-1]
    info = modules.get(module)
    if info is not None:
        imported = info.imports.get(leaf)
        if imported is not None:
            return functions.get(imported)
    return functions.get((module, leaf))


def _function_tool_decorators(info: ModuleInfo) -> set[str]:
    result: set[str] = set()
    for local, (module, symbol) in info.imports.items():
        if module == "livekit.agents" and symbol == "function_tool":
            result.add(local)
    return result


def _mcp_dispatch_name(function: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    for call in (node for node in ast.walk(function) if isinstance(node, ast.Call)):
        called = _dotted(call.func) or _leaf(call.func) or ""
        if called.rsplit(".", 1)[-1] != "_call_mcp_tool":
            continue
        value = _literal(call.args[0] if call.args else _kw(call, "tool_name"))
        if isinstance(value, str):
            return value
    return None


def _mcp_exposed_functions(
    modules: dict[str, ModuleInfo],
    functions: dict[tuple[str, str], FunctionRef],
) -> dict[str, FunctionRef]:
    result: dict[str, FunctionRef] = {}
    for ref in functions.values():
        for decorator in ref.node.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            if not isinstance(target, ast.Attribute) or target.attr != "tool":
                continue
            receiver = _dotted(target.value) or ""
            if receiver:
                result.setdefault(ref.name, ref)
    return result


def _sql_statement_capability(value: str) -> set[str]:
    stripped = value.strip().lower()
    first = stripped.split(None, 1)[0] if stripped else ""
    if first == "select":
        return {"data.read"}
    if first in _WRITE_SQL:
        return {"data.write"}
    if first in _DESTRUCTIVE_SQL:
        return {"data.write", "destructive.write"}
    return set()


def _repository_function_capabilities(
    ref: FunctionRef,
    modules: dict[str, ModuleInfo],
    functions: dict[tuple[str, str], FunctionRef],
    *,
    seen: set[tuple[str, str]] | None = None,
    depth: int = 0,
) -> tuple[set[str], set[str]]:
    if depth > 8:
        return set(), set()
    key = (ref.module, ref.name)
    seen = set() if seen is None else set(seen)
    if key in seen:
        return set(), set()
    seen.add(key)

    capabilities = set(infer_capabilities(ref.name))
    backends: set[str] = set()

    info = modules.get(ref.module)
    if info is not None:
        imported_modules = {
            module for module, _ in info.imports.values()
        }
        if "sqlite3" in imported_modules or any(
            isinstance(node, ast.Import)
            and any(alias.name == "sqlite3" for alias in node.names)
            for node in ast.walk(info.tree)
        ):
            backends.add("local_sqlite")

    for call in (node for node in ast.walk(ref.node) if isinstance(node, ast.Call)):
        called = _dotted(call.func) or _leaf(call.func) or ""
        leaf = called.rsplit(".", 1)[-1].lower()

        if leaf in {"execute", "executemany", "executescript"} and call.args:
            sql = _literal(call.args[0])
            if isinstance(sql, str):
                capabilities.update(_sql_statement_capability(sql))
        if leaf == "commit":
            capabilities.add("data.write")
        if leaf == "rollback":
            backends.add("transactional_state")
        if leaf in {"fetchone", "fetchall"}:
            capabilities.add("data.read")

        helper = _resolve_function(modules, functions, ref.module, called)
        if helper is not None and (helper.module, helper.name) != key:
            helper_caps, helper_backends = _repository_function_capabilities(
                helper,
                modules,
                functions,
                seen=seen,
                depth=depth + 1,
            )
            capabilities.update(helper_caps)
            backends.update(helper_backends)

    # Avoid name-only external-write claims for repository-local state helpers.
    if backends & {"local_sqlite", "transactional_state"}:
        capabilities.discard("external.write")
        capabilities.discard("network.external")
    return capabilities, backends


def _decorated_realtime_tools(
    modules: dict[str, ModuleInfo],
    functions: dict[tuple[str, str], FunctionRef],
) -> dict[tuple[str, str], tuple[FunctionRef, str | None]]:
    result: dict[tuple[str, str], tuple[FunctionRef, str | None]] = {}
    for module, info in modules.items():
        decorators = _function_tool_decorators(info)
        if not decorators:
            continue
        for ref in functions.values():
            if ref.module != module:
                continue
            matched = False
            for decorator in ref.node.decorator_list:
                target = decorator.func if isinstance(decorator, ast.Call) else decorator
                if (_leaf(target) or "") in decorators:
                    matched = True
                    break
            if matched:
                result[(module, ref.name)] = (ref, _mcp_dispatch_name(ref.node))
    return result


def _enclosing_function(tree: ast.Module, line: int) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    candidates = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and (getattr(node, "lineno", 0) or 0)
        <= line
        <= (getattr(node, "end_lineno", 0) or 0)
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda node: getattr(node, "lineno", 0) or 0)


def _assigned_sequence(
    scope: ast.AST,
    name: str,
    before_line: int,
) -> list[ast.AST]:
    candidates: list[tuple[int, list[ast.AST]]] = []
    for node in ast.walk(scope):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        line = getattr(node, "lineno", 0) or 0
        if line >= before_line:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if not any(isinstance(target, ast.Name) and target.id == name for target in targets):
            continue
        if isinstance(node.value, (ast.List, ast.Tuple, ast.Set)):
            candidates.append((line, list(node.value.elts)))
    if not candidates:
        return []
    return max(candidates, key=lambda item: item[0])[1]


def _agent_tool_names(
    tree: ast.Module,
    agent: Agent,
) -> list[str]:
    if agent.location is None:
        return []
    target_call = next(
        (
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and (_leaf(node.func) or "") == "Agent"
            and (getattr(node, "lineno", 0) or 0) == agent.location.line
        ),
        None,
    )
    if target_call is None:
        return []
    tools_expr = _kw(target_call, "tools")
    if tools_expr is None:
        return []
    if isinstance(tools_expr, (ast.List, ast.Tuple, ast.Set)):
        return [
            element.id
            for element in tools_expr.elts
            if isinstance(element, ast.Name)
        ]
    if isinstance(tools_expr, ast.Name):
        scope = _enclosing_function(tree, agent.location.line) or tree
        return [
            element.id
            for element in _assigned_sequence(
                scope,
                tools_expr.id,
                agent.location.line,
            )
            if isinstance(element, ast.Name)
        ]
    return []


def _route_function(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for decorator in function.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if (_leaf(target) or "").lower() in _ROUTE_METHODS:
            return True
    return False


def _depends_target(node: ast.AST | None) -> str:
    if not isinstance(node, ast.Call) or (_leaf(node.func) or "") != "Depends":
        return ""
    target = node.args[0] if node.args else _kw(node, "dependency")
    return (_dotted(target) or _leaf(target) or "").lower()


def _authentication_detected(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    principal_tokens = {
        "current_user",
        "authenticated_user",
        "principal",
        "identity",
        "claims",
    }
    params = list(function.args.args) + list(function.args.kwonlyargs)
    if any(arg.arg.lower() in principal_tokens for arg in params):
        return True

    defaults: list[ast.AST | None] = [
        *([None] * (len(function.args.args) - len(function.args.defaults))),
        *function.args.defaults,
        *function.args.kw_defaults,
    ]
    for default in defaults:
        target = _depends_target(default)
        if target and any(
            token in target
            for token in (
                "auth",
                "current_user",
                "get_user",
                "verify_user",
                "verify_token",
                "principal",
            )
        ):
            return True
    return False


def _public_realtime_capabilities(
    modules: dict[str, ModuleInfo],
) -> list[RealtimeCapability]:
    result: list[RealtimeCapability] = []
    for info in modules.values():
        for function in (
            node
            for node in ast.walk(info.tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and _route_function(node)
        ):
            has_access_token = False
            publish_grant = False
            room_join = False
            for call in (
                node for node in ast.walk(function) if isinstance(node, ast.Call)
            ):
                leaf = _leaf(call.func) or ""
                if leaf == "AccessToken":
                    has_access_token = True
                if leaf == "VideoGrants":
                    publish_grant = _literal(_kw(call, "can_publish")) is True
                    room_join = _literal(_kw(call, "room_join")) is True
            if not (has_access_token and publish_grant and room_join):
                continue
            authenticated = _authentication_detected(function)
            result.append(
                RealtimeCapability(
                    path=info.path,
                    function=function.name,
                    line=getattr(function, "lineno", 1) or 1,
                    capability="room_join+publish",
                    authenticated=authenticated,
                )
            )
    return result


def _livekit_session_wires_agent(
    info: ModuleInfo,
    agent: Agent,
) -> bool:
    if agent.location is None:
        return False
    function = _enclosing_function(info.tree, agent.location.line)
    if function is None:
        return False

    agent_aliases: set[str] = set()
    for node in ast.walk(function):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        if not isinstance(node.value, ast.Call) or (_leaf(node.value.func) or "") != "Agent":
            continue
        if (getattr(node.value, "lineno", 0) or 0) != agent.location.line:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        agent_aliases.update(
            target.id for target in targets if isinstance(target, ast.Name)
        )
    if not agent_aliases:
        return False

    session_aliases: set[str] = set()
    for node in ast.walk(function):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        if not isinstance(node.value, ast.Call) or (_leaf(node.value.func) or "") != "AgentSession":
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        session_aliases.update(
            target.id for target in targets if isinstance(target, ast.Name)
        )

    for call in (node for node in ast.walk(function) if isinstance(node, ast.Call)):
        if not isinstance(call.func, ast.Attribute) or call.func.attr != "start":
            continue
        if not isinstance(call.func.value, ast.Name) or call.func.value.id not in session_aliases:
            continue
        agent_expr = _kw(call, "agent")
        room_expr = _kw(call, "room")
        if (
            isinstance(agent_expr, ast.Name)
            and agent_expr.id in agent_aliases
            and room_expr is not None
            and "room" in (_dotted(room_expr) or _leaf(room_expr) or "").lower()
        ):
            return True
    return False


def _tool_from_wrapper(
    wrapper: FunctionRef,
    mcp_name: str | None,
    mcp_functions: dict[str, FunctionRef],
    modules: dict[str, ModuleInfo],
    functions: dict[tuple[str, str], FunctionRef],
) -> Tool:
    capabilities = set(infer_capabilities(wrapper.name))
    backends: set[str] = set()
    mcp_ref = mcp_functions.get(mcp_name or "")
    if mcp_ref is not None:
        caps, detected_backends = _repository_function_capabilities(
            mcp_ref,
            modules,
            functions,
        )
        capabilities.update(caps)
        backends.update(detected_backends)

    if backends & {"local_sqlite", "transactional_state"}:
        capabilities.discard("external.write")
        capabilities.discard("network.external")

    metadata: dict[str, object] = {
        "framework": "model-tool-loop",
        "authority_binding": "direct",
        "authority_binding_basis": "livekit_agent_tool_catalogue",
        "repository_resolved": True,
        "source_function": wrapper.name,
        "mcp_backed": mcp_name is not None,
        "mcp_tool_name": mcp_name,
    }
    if backends:
        metadata["state_backends"] = sorted(backends)
    if "local_sqlite" in backends:
        metadata["state_scope"] = "local_demo_sqlite"
        metadata["external_service_mutation"] = False
    return Tool(
        name=wrapper.name,
        kind="livekit_function_tool",
        capabilities=capabilities,
        location=_location(wrapper.path, wrapper.node),
        metadata=metadata,
    )


def enrich_public_realtime_mcp_authority(
    graph: Graph,
    root: Path,
    python_paths: list[Path],
) -> None:
    """Bind realtime function tools and public room capabilities to agents."""
    modules: dict[str, ModuleInfo] = {}
    by_path: dict[Path, ModuleInfo] = {}
    for path in python_paths:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        module = _module_name(path, root)
        info = ModuleInfo(module, path, tree, _imports(module, path, tree))
        modules[module] = info
        by_path[path.resolve()] = info

    if not modules:
        return
    functions = _functions(modules)
    wrappers = _decorated_realtime_tools(modules, functions)
    if not wrappers:
        return
    mcp_functions = _mcp_exposed_functions(modules, functions)
    capabilities = _public_realtime_capabilities(modules)
    public_capabilities = [item for item in capabilities if not item.authenticated]

    for agent in graph.agents:
        if (
            agent.metadata.get("framework") != "model-tool-loop"
            or agent.location is None
        ):
            continue
        info = by_path.get(agent.location.path.resolve())
        if info is None:
            continue
        tool_names = _agent_tool_names(info.tree, agent)
        if not tool_names:
            continue

        existing = {tool.name: tool for tool in agent.tools}
        for name in tool_names:
            wrapper_item = wrappers.get((info.module, name))
            if wrapper_item is None:
                continue
            wrapper, mcp_name = wrapper_item
            tool = _tool_from_wrapper(
                wrapper,
                mcp_name,
                mcp_functions,
                modules,
                functions,
            )
            current = existing.get(tool.name)
            if current is None:
                agent.tools.append(tool)
                existing[tool.name] = tool
            else:
                current.capabilities.update(tool.capabilities)
                current.metadata.update(tool.metadata)

        if not public_capabilities or not _livekit_session_wires_agent(info, agent):
            continue
        if not any(
            tool.metadata.get("mcp_backed") is True
            and {"data.write", "destructive.write"} & tool.capabilities
            for tool in agent.tools
        ):
            continue

        capability = public_capabilities[0]
        basis = "source_proven_public_realtime_capability"
        if not any(item.metadata.get("basis") == basis for item in agent.inputs):
            agent.inputs.append(
                InputSource(
                    name=f"{capability.path.stem}:{capability.function}:participant",
                    trust="untrusted",
                    kind="web",
                    location=SourceLocation(capability.path, capability.line, 1),
                    metadata={
                        "basis": basis,
                        "runtime_invocation_proven": True,
                        "session_transport": "livekit",
                        "session_capability": capability.capability,
                        "authentication_detected": False,
                        "credential_mint_endpoint": capability.function,
                        "credential_mint_path": capability.path.as_posix(),
                    },
                )
            )
        agent.metadata["public_realtime_session_authority"] = True
        agent.metadata["realtime_session_transport"] = "livekit"
        agent.metadata["realtime_session_capability"] = capability.capability
