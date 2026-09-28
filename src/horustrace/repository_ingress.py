"""Repository-level binding of source-proven external ingress to agent execution."""
# ruff: noqa: I001
from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from horustrace.models import (
    Agent,
    EvidenceFact,
    Graph,
    InputSource,
    SourceLocation,
)


_ROUTE_METHODS = {"get", "post", "put", "patch", "delete", "route", "api_route", "websocket"}
_AGENT_RUN_METHODS = {"invoke", "ainvoke", "stream", "astream", "run", "run_sync", "run_streamed"}


@dataclass
class _Function:
    key: str
    name: str
    class_name: str | None
    path: Path
    node: ast.FunctionDef | ast.AsyncFunctionDef
    params: list[str]


def _call_name(node: ast.AST | None) -> str | None:
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


def _location(path: Path, node: ast.AST) -> SourceLocation:
    return SourceLocation(
        path=path,
        line=getattr(node, "lineno", 1) or 1,
        column=(getattr(node, "col_offset", 0) or 0) + 1,
    )


def _params(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    values = [
        *node.args.posonlyargs,
        *node.args.args,
        *node.args.kwonlyargs,
    ]
    result = [item.arg for item in values]
    if node.args.vararg:
        result.append(node.args.vararg.arg)
    if node.args.kwarg:
        result.append(node.args.kwarg.arg)
    return result


def _collect_functions(paths: list[Path]) -> dict[str, _Function]:
    result: dict[str, _Function] = {}
    for path in paths:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        for statement in tree.body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                key = f"{path.resolve()}::{statement.name}"
                result[key] = _Function(key, statement.name, None, path, statement, _params(statement))
            elif isinstance(statement, ast.ClassDef):
                for child in statement.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        key = f"{path.resolve()}::{statement.name}.{child.name}"
                        result[key] = _Function(
                            key,
                            child.name,
                            statement.name,
                            path,
                            child,
                            _params(child),
                        )
    return result


def _is_web_handler(info: _Function) -> bool:
    for decorator in info.node.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if _call_name(target) in _ROUTE_METHODS:
            return True
    for child in info.node.args.args:
        annotation = _dotted(child.annotation) or _call_name(child.annotation)
        if annotation and annotation.split(".")[-1] in {"Request", "WebSocket", "HTTPConnection"}:
            return True
    return False


def _expr_tainted(node: ast.AST | None, tainted: set[str]) -> bool:
    if node is None:
        return False
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in tainted:
            return True
        if isinstance(child, ast.Call) and _call_name(child.func) == "input":
            return True
        dotted = _dotted(child)
        if dotted and (
            dotted == "request"
            or dotted.startswith("request.")
            or ".request." in dotted
        ):
            return True
    return False


def _targets(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        values: list[str] = []
        for child in node.elts:
            values.extend(_targets(child))
        return values
    return []


def _literal_string(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _unique_simple(functions: dict[str, _Function]) -> dict[str, str]:
    values: dict[str, list[str]] = {}
    for key, info in functions.items():
        values.setdefault(info.name, []).append(key)
    return {name: keys[0] for name, keys in values.items() if len(keys) == 1}


def _class_methods(functions: dict[str, _Function]) -> dict[tuple[str, str], str]:
    return {
        (info.class_name, info.name): key
        for key, info in functions.items()
        if info.class_name
    }


def _resolve_callee(
    info: _Function,
    call: ast.Call,
    *,
    unique: dict[str, str],
    methods: dict[tuple[str, str], str],
    local_types: dict[str, str],
) -> str | None:
    leaf = _call_name(call.func)
    if not leaf:
        return None
    if isinstance(call.func, ast.Name):
        return unique.get(leaf)
    if isinstance(call.func, ast.Attribute):
        root = call.func.value
        if isinstance(root, ast.Name):
            if root.id == "self" and info.class_name:
                return methods.get((info.class_name, leaf))
            if root.id in local_types:
                return methods.get((local_types[root.id], leaf))
        return unique.get(leaf)
    return None


def _call_argument_map(
    call: ast.Call,
    callee: _Function,
) -> dict[str, ast.AST]:
    result: dict[str, ast.AST] = {}
    for index, argument in enumerate(call.args):
        if index < len(callee.params):
            result[callee.params[index]] = argument
    for keyword in call.keywords:
        if keyword.arg in callee.params:
            result[keyword.arg] = keyword.value
    return result


def _agent_maps(graph: Graph) -> tuple[dict[str, Agent], dict[tuple[Path, str], Agent], dict[str, Agent]]:
    by_name = {agent.name: agent for agent in graph.agents}
    by_source_alias: dict[tuple[Path, str], Agent] = {}
    by_factory: dict[str, Agent] = {}
    for agent in graph.agents:
        if agent.location:
            alias = str(agent.metadata.get("source_alias") or agent.name)
            by_source_alias[(agent.location.path.resolve(), alias)] = agent
        factory = agent.metadata.get("factory_function")
        if isinstance(factory, str):
            by_factory[factory] = agent
    return by_name, by_source_alias, by_factory


def _add_input(
    agent: Agent,
    *,
    source_name: str,
    source_kind: str,
    source_location: SourceLocation,
    handler: str,
) -> None:
    if any(item.metadata.get("binding_origin") == "repository_ingress" for item in agent.inputs):
        return
    agent.inputs.append(
        InputSource(
            name=source_name,
            trust="untrusted",
            kind=source_kind,
            location=source_location,
            metadata={
                "inferred": False,
                "binding_origin": "repository_ingress",
                "basis": "interprocedural_agent_input",
                "handler": handler,
            },
            provenance=[
                EvidenceFact(
                    agent.name,
                    f"untrusted_input_via={handler}",
                    "source",
                    source_location,
                )
            ],
        )
    )


def bind_repository_ingress(
    graph: Graph,
    *,
    python_paths: list[Path],
) -> None:
    """Propagate supported web/CLI ingress to statically identifiable agent runs."""
    functions = _collect_functions(python_paths)
    if not functions:
        return
    unique = _unique_simple(functions)
    methods = _class_methods(functions)
    by_name, by_source_alias, by_factory = _agent_maps(graph)

    tainted_params: dict[str, set[str]] = {
        key: (set(info.params) if _is_web_handler(info) else set())
        for key, info in functions.items()
    }
    source_handlers: dict[str, set[str]] = {
        key: ({info.name} if _is_web_handler(info) else set())
        for key, info in functions.items()
    }

    for _ in range(12):
        changed = False
        for key, info in functions.items():
            tainted = set(tainted_params[key])
            local_types: dict[str, str] = {}
            local_agents: dict[str, Agent] = {}

            for agent_alias_key, agent in by_source_alias.items():
                path, alias = agent_alias_key
                if path == info.path.resolve():
                    local_agents.setdefault(alias, agent)

            assignments = [
                node
                for node in ast.walk(info.node)
                if isinstance(node, (ast.Assign, ast.AnnAssign))
                and node.value is not None
            ]
            for _pass in range(5):
                local_changed = False
                for assignment in assignments:
                    value = assignment.value
                    targets = (
                        assignment.targets
                        if isinstance(assignment, ast.Assign)
                        else [assignment.target]
                    )
                    names = [name for target in targets for name in _targets(target)]
                    if isinstance(value, ast.Call):
                        constructor = _call_name(value.func)
                        if constructor and constructor[:1].isupper():
                            for name in names:
                                local_types[name] = constructor
                        if constructor in by_factory:
                            for name in names:
                                local_agents[name] = by_factory[constructor]
                        if (
                            isinstance(value.func, ast.Attribute)
                            and value.func.attr == "get_agent"
                            and value.args
                        ):
                            runtime_name = _literal_string(value.args[0])
                            if runtime_name in by_name:
                                for name in names:
                                    local_agents[name] = by_name[runtime_name]
                    if _expr_tainted(value, tainted):
                        before = len(tainted)
                        tainted.update(names)
                        local_changed = local_changed or len(tainted) != before
                if not local_changed:
                    break

            for call in (
                node for node in ast.walk(info.node) if isinstance(node, ast.Call)
            ):
                callee_key = _resolve_callee(
                    info,
                    call,
                    unique=unique,
                    methods=methods,
                    local_types=local_types,
                )
                if callee_key:
                    callee = functions[callee_key]
                    mapping = _call_argument_map(call, callee)
                    incoming = {
                        param
                        for param, expr in mapping.items()
                        if _expr_tainted(expr, tainted)
                    }
                    if incoming - tainted_params[callee_key]:
                        tainted_params[callee_key].update(incoming)
                        source_handlers[callee_key].update(source_handlers[key] or {info.name})
                        changed = True

                target_agent: Agent | None = None
                input_expr: ast.AST | None = None
                leaf = _call_name(call.func) or ""
                if isinstance(call.func, ast.Attribute):
                    receiver = call.func.value
                    if isinstance(receiver, ast.Name) and receiver.id in local_agents:
                        if leaf in _AGENT_RUN_METHODS:
                            target_agent = local_agents[receiver.id]
                            input_expr = (
                                call.args[0]
                                if call.args
                                else next(
                                    (kw.value for kw in call.keywords if kw.arg in {"input", "message", "messages"}),
                                    None,
                                )
                            )
                    elif leaf in {"run", "run_sync", "run_streamed"}:
                        dotted = _dotted(receiver) or ""
                        if dotted.endswith("Runner") or dotted == "Runner":
                            agent_expr = call.args[0] if call.args else next(
                                (kw.value for kw in call.keywords if kw.arg in {"agent", "starting_agent"}),
                                None,
                            )
                            alias = _call_name(agent_expr)
                            target_agent = local_agents.get(alias or "")
                            input_expr = next(
                                (kw.value for kw in call.keywords if kw.arg == "input"),
                                call.args[1] if len(call.args) > 1 else None,
                            )

                if (
                    target_agent is not None
                    and input_expr is not None
                    and _expr_tainted(input_expr, tainted)
                ):
                    handler = min(source_handlers[key] or {info.name})
                    kind = "external" if source_handlers[key] else "user"
                    _add_input(
                        target_agent,
                        source_name=f"{handler}:input",
                        source_kind=kind,
                        source_location=_location(info.path, input_expr),
                        handler=handler,
                    )
        if not changed:
            break
