# ruff: noqa: I001
"""Repository-level propagation of untrusted ingress into agent runtimes.

The pass is evidence-driven: it starts from web-handler parameters, explicit request
reads, and builtin input(), propagates values through statically resolved Python
function calls, and annotates an agent only when a tainted value reaches a recognized
agent runtime invocation.
"""
from __future__ import annotations

import ast
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from horustrace.models import Agent, Graph, InputSource, SourceLocation


_ROUTE_METHODS = {"route", "api_route", "get", "post", "put", "patch", "delete", "websocket"}
_RUNTIME_METHODS = {"invoke", "ainvoke", "run", "run_sync", "run_streamed"}
_REQUEST_READS = {"get_json", "json", "body", "form", "receive_json", "receive_text", "receive_bytes"}


@dataclass(slots=True)
class _Function:
    name: str
    path: Path
    node: ast.FunctionDef | ast.AsyncFunctionDef
    assignments: list[ast.Assign | ast.AnnAssign] = field(default_factory=list)
    calls: list[ast.Call] = field(default_factory=list)

    @property
    def params(self) -> list[str]:
        result = [
            arg.arg
            for arg in (
                list(self.node.args.posonlyargs)
                + list(self.node.args.args)
                + list(self.node.args.kwonlyargs)
            )
        ]
        if self.node.args.vararg:
            result.append(self.node.args.vararg.arg)
        if self.node.args.kwarg:
            result.append(self.node.args.kwarg.arg)
        return result


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


def _literal(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _kw(call: ast.Call, name: str) -> ast.AST | None:
    return next((item.value for item in call.keywords if item.arg == name), None)


def _target_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, (ast.Tuple, ast.List)):
        result: set[str] = set()
        for item in node.elts:
            result.update(_target_names(item))
        return result
    return set()


def _roots(node: ast.AST | None) -> set[str]:
    if node is None:
        return set()
    result: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            result.add(child.id)
    return result


def _is_route(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for decorator in function.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if _call_name(target) in _ROUTE_METHODS:
            return True
    return False


def _has_explicit_untrusted_source(node: ast.AST) -> bool:
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        called = (_dotted(child.func) or _call_name(child.func) or "").lower()
        leaf = (_call_name(child.func) or "").lower()
        if called == "input" or leaf == "input":
            return True
        if leaf in _REQUEST_READS and called.startswith(
            ("request.", "websocket.", "ws.")
        ):
            return True
    return False


def _expr_tainted(node: ast.AST | None, tainted: set[str]) -> bool:
    if node is None:
        return False
    if _roots(node) & tainted:
        return True
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        called = (_dotted(child.func) or _call_name(child.func) or "").lower()
        leaf = (_call_name(child.func) or "").lower()
        if called == "input" or leaf == "input":
            return True
        if leaf in _REQUEST_READS and called.startswith(
            ("request.", "websocket.", "ws.")
        ):
            return True
        if called.startswith("request.") and leaf in {"get", "values", "args"}:
            return True
    return False


def _collect_functions(python_paths: list[Path]) -> tuple[list[_Function], dict[str, _Function]]:
    functions: list[_Function] = []
    by_name_multi: dict[str, list[_Function]] = {}
    for path in python_paths:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                children = list(ast.walk(node))
                info = _Function(
                    node.name,
                    path,
                    node,
                    assignments=[
                        child
                        for child in children
                        if isinstance(child, (ast.Assign, ast.AnnAssign))
                    ],
                    calls=[
                        child
                        for child in children
                        if isinstance(child, ast.Call)
                    ],
                )
                functions.append(info)
                by_name_multi.setdefault(node.name, []).append(info)
    unique = {name: values[0] for name, values in by_name_multi.items() if len(values) == 1}
    return functions, unique


def _factory_agents(graph: Graph, functions: list[_Function]) -> dict[str, str]:
    result: dict[str, str] = {}
    for agent in graph.agents:
        if agent.metadata.get("framework") != "langgraph" or agent.location is None:
            continue
        candidates = [
            info
            for info in functions
            if info.path.resolve() == agent.location.path.resolve()
            and getattr(info.node, "lineno", 0) <= agent.location.line
            <= getattr(info.node, "end_lineno", 0)
        ]
        if len(candidates) == 1:
            result[candidates[0].name] = agent.name
    return result


def _agents_by_source_alias(graph: Graph) -> dict[tuple[Path, str], str]:
    result: dict[tuple[Path, str], str] = {}
    for agent in graph.agents:
        if agent.location is None:
            continue
        alias = agent.metadata.get("source_alias")
        if isinstance(alias, str):
            result[(agent.location.path.resolve(), alias)] = agent.name
        if agent.metadata.get("framework") == "pydantic-ai":
            result[(agent.location.path.resolve(), agent.name)] = agent.name
    return result


def _append_untrusted_input(agent: Agent, location: SourceLocation, basis: str) -> None:
    if any(item.metadata.get("binding_origin") == "repository_ingress" for item in agent.inputs):
        return
    agent.inputs.append(
        InputSource(
            name="external-user-input",
            trust="untrusted",
            kind="external",
            location=location,
            metadata={
                "inferred": True,
                "binding_origin": "repository_ingress",
                "basis": basis,
            },
        )
    )


def propagate_repository_ingress(
    graph: Graph,
    python_paths: list[Path],
) -> None:
    functions, unique_functions = _collect_functions(python_paths)
    if not functions:
        return

    factory_agents = _factory_agents(graph, functions)
    source_aliases = _agents_by_source_alias(graph)
    agents_by_name = {agent.name: agent for agent in graph.agents}

    tainted_params: dict[tuple[Path, str], set[str]] = {
        (info.path.resolve(), info.name): set(info.params) if _is_route(info.node) else set()
        for info in functions
    }

    queue = deque(functions)
    queued = {
        (info.path.resolve(), info.name)
        for info in functions
    }

    while queue:
        info = queue.popleft()
        key = (info.path.resolve(), info.name)
        queued.discard(key)
        tainted = set(tainted_params[key])
        local_agents: dict[str, str] = {}

        # Explicit source reads taint their assignment targets.
        for child in info.assignments:
            value = child.value
            if value is None:
                continue
            targets = child.targets if isinstance(child, ast.Assign) else [child.target]
            target_names = {
                name for target in targets for name in _target_names(target)
            }
            if _expr_tainted(value, tainted) or _has_explicit_untrusted_source(value):
                tainted.update(target_names)

            if isinstance(value, ast.Call):
                called = _call_name(value.func)
                if called in factory_agents:
                    for name in target_names:
                        local_agents[name] = factory_agents[called]
                if isinstance(value.func, ast.Attribute) and value.func.attr == "get_agent":
                    name = _literal(value.args[0]) if value.args else None
                    if name in agents_by_name:
                        for target_name in target_names:
                            local_agents[target_name] = name

        # Resolve local assignment chains without rescanning the AST.
        while True:
            local_changed = False
            for child in info.assignments:
                value = child.value
                if value is None or not _expr_tainted(value, tainted):
                    continue
                targets = child.targets if isinstance(child, ast.Assign) else [child.target]
                for target in targets:
                    for name in _target_names(target):
                        if name not in tainted:
                            tainted.add(name)
                            local_changed = True
            if not local_changed:
                break

        # Direct framework aliases are source-file scoped.
        for (path, alias), agent_name in source_aliases.items():
            if path == info.path.resolve():
                local_agents.setdefault(alias, agent_name)

        for child in info.calls:
            called = _call_name(child.func)

            # Propagate tainted arguments through uniquely-resolved functions.
            callee = unique_functions.get(called or "")
            if callee is not None:
                callee_key = (callee.path.resolve(), callee.name)
                positional = list(child.args)
                keywords = {item.arg: item.value for item in child.keywords if item.arg}
                parameters = list(callee.params)
                if (
                    isinstance(child.func, ast.Attribute)
                    and parameters
                    and parameters[0] in {"self", "cls"}
                ):
                    parameters = parameters[1:]
                gained = False
                for index, param in enumerate(parameters):
                    value = (
                        positional[index]
                        if index < len(positional)
                        else keywords.get(param)
                    )
                    if (
                        value is not None
                        and _expr_tainted(value, tainted)
                        and param not in tainted_params[callee_key]
                    ):
                        tainted_params[callee_key].add(param)
                        gained = True
                if gained and callee_key not in queued:
                    queue.append(callee)
                    queued.add(callee_key)

            target_agent: str | None = None
            input_expr: ast.AST | None = None

            dotted = _dotted(child.func) or ""
            if dotted.endswith(("Runner.run", "Runner.run_sync", "Runner.run_streamed")):
                agent_expr = child.args[0] if child.args else _kw(child, "starting_agent")
                alias = _call_name(agent_expr)
                target_agent = local_agents.get(alias or "") or agents_by_name.get(
                    alias or "",
                    None,
                )
                input_expr = _kw(child, "input")
                if input_expr is None and len(child.args) > 1:
                    input_expr = child.args[1]
            elif isinstance(child.func, ast.Attribute) and child.func.attr in _RUNTIME_METHODS:
                receiver = _call_name(child.func.value)
                target_agent = local_agents.get(receiver or "")
                input_expr = child.args[0] if child.args else _kw(child, "input")
            elif called in {"run", "run_sync", "run_streamed"}:
                continue
            elif called is None:
                continue

            if (
                target_agent
                and input_expr is not None
                and _expr_tainted(input_expr, tainted)
                and target_agent in agents_by_name
            ):
                _append_untrusted_input(
                    agents_by_name[target_agent],
                    SourceLocation(info.path, getattr(child, "lineno", 1) or 1),
                    "static_web_or_cli_value_to_agent_runtime",
                )

        tainted_params[key].update(tainted)
