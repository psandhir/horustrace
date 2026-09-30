"""Source-proven external ingress -> normalized agent runtime binding.

This module complements framework adapters after repository-wide normalization.  It
does not infer that every web handler reaches every agent.  Instead it requires a
concrete runtime receiver (a normalized agent class, a compiled LangGraph alias, or
a wrapper class that constructs a source-proven agent factory) and a handler-derived
value passed into that receiver.
"""
import ast
from pathlib import Path

from horustrace.models import (
    Agent,
    Graph,
    InputSource,
    SourceLocation,
)

_RUNTIME_METHODS = {
    "run",
    "run_sync",
    "run_stream",
    "run_stream_sync",
    "run_stream_events",
    "invoke",
    "ainvoke",
    "stream",
    "astream",
    "process_query",
    "ingest",
    "ingest_file",
    "query",
    "consolidate",
    "process_message",
}
_ROUTE_DECORATORS = {
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "api_route",
    "websocket",
    "on_message",
    "route",
}


def _module_name(path: Path, root: Path) -> str:
    try:
        relative = path.resolve().relative_to(root.resolve()).with_suffix("")
    except ValueError:
        relative = Path(path.stem)
    parts = list(relative.parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


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


def _call_name(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _imports(tree: ast.Module) -> dict[str, str]:
    result: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                if alias.name == "*":
                    continue
                result[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        elif isinstance(node, ast.Import):
            for alias in node.names:
                result[alias.asname or alias.name.split(".")[0]] = alias.name
    return result


def _resolve_symbol(module: str, imports: dict[str, str], value: str) -> str:
    if not value:
        return value
    first, dot, rest = value.partition(".")
    imported = imports.get(first)
    if imported:
        return imported + (f".{rest}" if dot else "")
    return f"{module}.{value}" if module else value


def _matches_key(resolved: str, candidate: str) -> bool:
    return (
        resolved == candidate
        or resolved.endswith(f".{candidate}")
        or candidate.endswith(f".{resolved}")
    )


def _target_names(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        result: list[str] = []
        for item in node.elts:
            result.extend(_target_names(item))
        return result
    return []


def _parameter_annotations(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[tuple[str, ast.AST | None]]:
    args = [
        *function.args.posonlyargs,
        *function.args.args,
        *function.args.kwonlyargs,
    ]
    return [(arg.arg, arg.annotation) for arg in args]


def _annotation_name(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _dotted(node)
    if isinstance(node, ast.Subscript):
        return _annotation_name(node.value)
    return None


def _inside(container: ast.AST, child: ast.AST) -> bool:
    start = getattr(container, "lineno", 0) or 0
    end = getattr(container, "end_lineno", start) or start
    line = getattr(child, "lineno", 0) or 0
    return start <= line <= end


def _decorator_kind(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    imports: dict[str, str],
) -> str | None:
    for decorator in function.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        leaf = (_call_name(target) or "").lower()
        if leaf not in _ROUTE_DECORATORS:
            continue
        dotted = (_dotted(target) or "").lower()
        if leaf == "on_message" or "chainlit" in dotted or dotted.startswith("cl."):
            return "chainlit"
        if leaf == "websocket":
            return "fastapi_websocket"
        if leaf == "route":
            if any(
                value == "flask.Flask"
                or value == "flask.request"
                or value.startswith("flask.")
                for value in imports.values()
            ):
                return "flask"
            return "web"
        return "web"
    return None


def _global_ingress_names(
    imports: dict[str, str],
    framework: str,
) -> set[str]:
    if framework != "flask":
        return set()
    return {
        alias
        for alias, imported in imports.items()
        if imported == "flask.request"
    }

def _authentication_posture(
    tree: ast.Module,
    framework: str,
) -> dict[str, object]:
    """Extract conservative module-level ingress authentication semantics."""
    if framework != "aiohttp":
        return {}

    auth_headers = {"authorization", "x-api-key", "x-auth-token", "api-key"}
    auth_header_detected = False
    environment_variables: set[str] = set()
    public_default = False

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            called = (_dotted(node.func) or _call_name(node.func) or "").lower()
            if called in {"os.getenv", "os.environ.get"} and node.args:
                value = node.args[0]
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    key = value.value
                    if any(marker in key.lower() for marker in ("api_key", "apikey", "token", "auth")):
                        environment_variables.add(key)
            if isinstance(node.func, ast.Attribute) and node.func.attr == "get":
                receiver = (_dotted(node.func.value) or "").lower()
                if "headers" in receiver and node.args:
                    header = node.args[0]
                    if isinstance(header, ast.Constant) and isinstance(header.value, str):
                        if header.value.lower() in auth_headers:
                            auth_header_detected = True

    middleware_functions = [
        function
        for function in ast.walk(tree)
        if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
        and any(
            (_dotted(decorator.func if isinstance(decorator, ast.Call) else decorator) or "").lower().endswith(
                ("web.middleware", ".middleware")
            )
            for decorator in function.decorator_list
        )
    ]
    for middleware in middleware_functions:
        for conditional in (
            node for node in ast.walk(middleware) if isinstance(node, ast.If)
        ):
            test = conditional.test
            optional_state = (
                isinstance(test, ast.UnaryOp)
                and isinstance(test.op, ast.Not)
                and isinstance(test.operand, ast.Name)
            ) or (
                isinstance(test, ast.Compare)
                and isinstance(test.left, ast.Name)
                and any(isinstance(op, (ast.Eq, ast.Is)) for op in test.ops)
                and any(
                    isinstance(value, ast.Constant) and value.value in {None, "", False}
                    for value in test.comparators
                )
            )
            if not optional_state:
                continue
            calls_handler = any(
                isinstance(child, ast.Call)
                and _call_name(child.func) == "handler"
                for statement in conditional.body
                for child in ast.walk(statement)
            )
            assigns_request_identity = any(
                isinstance(child, (ast.Assign, ast.AnnAssign))
                and any(
                    isinstance(target, ast.Subscript)
                    and isinstance(target.value, ast.Name)
                    and target.value.id == "request"
                    for target in (
                        child.targets if isinstance(child, ast.Assign) else [child.target]
                    )
                )
                for statement in conditional.body
                for child in ast.walk(statement)
            )
            if calls_handler and assigns_request_identity:
                public_default = True
                break

    if public_default:
        return {
            "authentication_detected": auth_header_detected,
            "authentication_mode": "optional_public_default",
            "public_default": True,
            "authentication_environment_variables": sorted(environment_variables),
        }
    if auth_header_detected:
        return {
            "authentication_detected": True,
            "authentication_mode": "required",
            "public_default": False,
            "authentication_environment_variables": sorted(environment_variables),
        }
    return {
        "authentication_detected": False,
        "authentication_mode": "not_detected",
        "public_default": False,
        "authentication_environment_variables": sorted(environment_variables),
    }


def _registered_route_handlers(tree: ast.Module) -> set[str]:
    result: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        leaf = node.func.attr.lower()
        receiver = (_dotted(node.func.value) or "").lower()
        if not leaf.startswith("add_") or "router" not in receiver:
            continue
        if len(node.args) < 2 or not isinstance(node.args[1], ast.Name):
            continue
        result.add(node.args[1].id)
    return result


def _expr_tainted(node: ast.AST | None, tainted: set[str]) -> bool:
    if node is None:
        return False
    return any(
        isinstance(child, ast.Name) and child.id in tainted
        for child in ast.walk(node)
    )


def _propagate_taint(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    initial: set[str],
) -> set[str]:
    tainted = set(initial)
    assignments: list[tuple[list[str], ast.AST]] = []
    for node in ast.walk(function):
        if isinstance(node, ast.Assign):
            names = [
                name
                for target in node.targets
                for name in _target_names(target)
            ]
            assignments.append((names, node.value))
        elif (
            isinstance(node, ast.AnnAssign) and node.value is not None
        ) or isinstance(node, ast.NamedExpr):
            assignments.append((_target_names(node.target), node.value))

    for _ in range(8):
        changed = False
        for names, value in assignments:
            if not names or not _expr_tainted(value, tainted):
                continue
            before = len(tainted)
            tainted.update(names)
            changed = changed or len(tainted) != before
        if not changed:
            break
    return tainted


def _agent_for_key(
    resolved: str,
    targets: dict[str, Agent],
) -> Agent | None:
    matches = [
        agent
        for key, agent in targets.items()
        if _matches_key(resolved, key)
    ]
    unique = {id(agent): agent for agent in matches}
    return next(iter(unique.values())) if len(unique) == 1 else None


def _factory_targets(
    graph: Graph,
    modules: dict[Path, tuple[str, ast.Module, dict[str, str]]],
) -> dict[str, Agent]:
    result: dict[str, Agent] = {}
    agents_by_path: dict[Path, list[Agent]] = {}
    for agent in graph.agents:
        if agent.location is not None:
            agents_by_path.setdefault(agent.location.path.resolve(), []).append(agent)

    for path, (module, tree, _) in modules.items():
        path_agents = agents_by_path.get(path.resolve(), [])
        if not path_agents:
            continue
        for function in ast.walk(tree):
            if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            returned_aliases = {
                node.value.id
                for node in ast.walk(function)
                if isinstance(node, ast.Return) and isinstance(node.value, ast.Name)
            }
            if not returned_aliases:
                continue
            matches = [
                agent
                for agent in path_agents
                if agent.location is not None
                and (getattr(function, "lineno", 0) or 0)
                <= agent.location.line
                <= (getattr(function, "end_lineno", 0) or 0)
                and str(agent.metadata.get("source_alias") or "") in returned_aliases
            ]
            unique = {id(agent): agent for agent in matches}
            if len(unique) == 1:
                result[f"{module}.{function.name}" if module else function.name] = next(
                    iter(unique.values())
                )
    return result


def _class_targets(
    graph: Graph,
    modules: dict[Path, tuple[str, ast.Module, dict[str, str]]],
    factories: dict[str, Agent],
) -> dict[str, Agent]:
    targets: dict[str, Agent] = {}
    agents_by_path: dict[Path, list[Agent]] = {}
    for agent in graph.agents:
        if agent.location is not None:
            agents_by_path.setdefault(agent.location.path.resolve(), []).append(agent)

    for agent in graph.agents:
        if agent.location is None:
            continue
        source_class = agent.metadata.get("source_class")
        if not isinstance(source_class, str) or not source_class:
            continue
        parsed = modules.get(agent.location.path.resolve())
        if parsed is None:
            continue
        module = parsed[0]
        targets[f"{module}.{source_class}" if module else source_class] = agent

    for path, (module, tree, imports) in modules.items():
        path_agents = agents_by_path.get(path.resolve(), [])
        for class_node in (
            node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)
        ):
            matched: list[Agent] = []
            agent_attributes: set[str] = set()
            runtime_bound_attributes: set[str] = set()

            for init in class_node.body:
                if (
                    not isinstance(init, (ast.FunctionDef, ast.AsyncFunctionDef))
                    or init.name != "__init__"
                ):
                    continue
                for node in ast.walk(init):
                    if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                        continue
                    value = node.value
                    if not isinstance(value, ast.Call):
                        continue

                    called = _dotted(value.func) or _call_name(value.func) or ""
                    resolved = _resolve_symbol(module, imports, called)
                    agent = _agent_for_key(resolved, factories)
                    if agent is None:
                        inline_matches = [
                            candidate
                            for candidate in path_agents
                            if candidate.location is not None
                            and candidate.location.line
                            == (getattr(value, "lineno", 0) or 0)
                        ]
                        unique_inline = {
                            id(candidate): candidate for candidate in inline_matches
                        }
                        if len(unique_inline) == 1:
                            agent = next(iter(unique_inline.values()))
                    if agent is not None:
                        target_nodes = (
                            node.targets
                            if isinstance(node, ast.Assign)
                            else [node.target]
                        )
                        for target in target_nodes:
                            if (
                                isinstance(target, ast.Attribute)
                                and isinstance(target.value, ast.Name)
                                and target.value.id == "self"
                            ):
                                agent_attributes.add(target.attr)
                                matched.append(agent)

            if not agent_attributes:
                continue

            for node in ast.walk(class_node):
                if not isinstance(node, ast.Call):
                    continue
                for keyword in node.keywords:
                    value = keyword.value
                    if (
                        keyword.arg in {"agent", "root_agent"}
                        and isinstance(value, ast.Attribute)
                        and isinstance(value.value, ast.Name)
                        and value.value.id == "self"
                        and value.attr in agent_attributes
                    ):
                        runtime_bound_attributes.add(value.attr)
                if isinstance(node.func, ast.Attribute):
                    receiver = node.func.value
                    if (
                        isinstance(receiver, ast.Attribute)
                        and isinstance(receiver.value, ast.Name)
                        and receiver.value.id == "self"
                        and receiver.attr in agent_attributes
                        and node.func.attr in _RUNTIME_METHODS
                    ):
                        runtime_bound_attributes.add(receiver.attr)

                    called = _dotted(node.func) or ""
                    resolved_called = _resolve_symbol(module, imports, called)
                    if (
                        node.func.attr in _RUNTIME_METHODS
                        and resolved_called.startswith(
                            ("agents.Runner.", "openai.agents.Runner.")
                        )
                        and node.args
                    ):
                        first = node.args[0]
                        if (
                            isinstance(first, ast.Attribute)
                            and isinstance(first.value, ast.Name)
                            and first.value.id == "self"
                            and first.attr in agent_attributes
                        ):
                            runtime_bound_attributes.add(first.attr)

            unique = {id(agent): agent for agent in matched}
            if len(unique) == 1 and runtime_bound_attributes:
                key = f"{module}.{class_node.name}" if module else class_node.name
                targets[key] = next(iter(unique.values()))
    return targets


def _wrapper_factory_targets(
    modules: dict[Path, tuple[str, ast.Module, dict[str, str]]],
    class_targets: dict[str, Agent],
) -> dict[str, Agent]:
    result: dict[str, Agent] = {}
    for module, tree, imports in modules.values():
        for function in ast.walk(tree):
            if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            returned_names = {
                node.value.id
                for node in ast.walk(function)
                if isinstance(node, ast.Return) and isinstance(node.value, ast.Name)
            }
            if not returned_names:
                continue

            matched: list[Agent] = []
            for node in ast.walk(function):
                if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                    continue
                value = node.value
                if not isinstance(value, ast.Call):
                    continue
                target_nodes = (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
                assigned_names = {
                    name
                    for target in target_nodes
                    for name in _target_names(target)
                }
                if not (assigned_names & returned_names):
                    continue
                called = _dotted(value.func) or _call_name(value.func) or ""
                resolved = _resolve_symbol(module, imports, called)
                agent = _agent_for_key(resolved, class_targets)
                if agent is not None:
                    matched.append(agent)

            unique = {id(agent): agent for agent in matched}
            if len(unique) == 1:
                key = f"{module}.{function.name}" if module else function.name
                result[key] = next(iter(unique.values()))
    return result

def _compiled_alias_targets(
    graph: Graph,
    modules: dict[Path, tuple[str, ast.Module, dict[str, str]]],
) -> dict[str, Agent]:
    result: dict[str, Agent] = {}
    for agent in graph.agents:
        if agent.metadata.get("framework") != "langgraph" or agent.location is None:
            continue
        parsed = modules.get(agent.location.path.resolve())
        if parsed is None:
            continue
        module, tree, _ = parsed
        aliases = {
            agent.name,
            str(agent.metadata.get("source_alias") or ""),
        }
        aliases.discard("")
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            value = node.value
            if (
                not isinstance(value, ast.Call)
                or not isinstance(value.func, ast.Attribute)
                or value.func.attr != "compile"
            ):
                continue
            receiver = _dotted(value.func.value) or _call_name(value.func.value) or ""
            if receiver not in aliases:
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                for name in _target_names(target):
                    result[f"{module}.{name}" if module else name] = agent
    return result


def _receiver_from_annotation(
    annotation: ast.AST | None,
    module: str,
    imports: dict[str, str],
    class_targets: dict[str, Agent],
) -> Agent | None:
    name = _annotation_name(annotation)
    if not name:
        return None
    return _agent_for_key(_resolve_symbol(module, imports, name), class_targets)


def _constructor_agent(
    call: ast.Call,
    module: str,
    imports: dict[str, str],
    class_targets: dict[str, Agent],
) -> Agent | None:
    called = _dotted(call.func) or _call_name(call.func) or ""
    if not called:
        return None
    return _agent_for_key(_resolve_symbol(module, imports, called), class_targets)


def _handler_receivers(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    tree: ast.Module,
    module: str,
    imports: dict[str, str],
    class_targets: dict[str, Agent],
    compiled_targets: dict[str, Agent],
) -> dict[str, Agent]:
    receivers: dict[str, Agent] = {}

    for key, agent in compiled_targets.items():
        prefix = f"{module}." if module else ""
        if key.startswith(prefix):
            receivers[key[len(prefix):]] = agent

    scopes = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node is not function
        and _inside(node, function)
    ]
    scopes.sort(
        key=lambda node: (
            (getattr(node, "end_lineno", 0) or 0)
            - (getattr(node, "lineno", 0) or 0)
        )
    )
    for scope in [*reversed(scopes), function]:
        for name, annotation in _parameter_annotations(scope):
            agent = _receiver_from_annotation(
                annotation,
                module,
                imports,
                class_targets,
            )
            if agent is not None:
                receivers[name] = agent

    for node in ast.walk(function):
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(node.value, ast.Call):
            agent = _constructor_agent(
                node.value,
                module,
                imports,
                class_targets,
            )
            if agent is None:
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                for name in _target_names(target):
                    receivers[name] = agent
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if not isinstance(item.context_expr, ast.Call) or item.optional_vars is None:
                    continue
                agent = _constructor_agent(
                    item.context_expr,
                    module,
                    imports,
                    class_targets,
                )
                if agent is None:
                    continue
                for name in _target_names(item.optional_vars):
                    receivers[name] = agent
    return receivers


def _direct_runtime_invocation(
    node: ast.Call,
    receivers: dict[str, Agent],
    tainted: set[str],
) -> Agent | None:
    if not isinstance(node.func, ast.Attribute):
        return None
    receiver = node.func.value
    if not isinstance(receiver, ast.Name) or receiver.id not in receivers:
        return None
    if node.func.attr not in _RUNTIME_METHODS:
        return None
    values = [*node.args, *(keyword.value for keyword in node.keywords)]
    if not any(_expr_tainted(value, tainted) for value in values):
        return None
    return receivers[receiver.id]


def _callback_runtime_invocation(
    node: ast.Call,
    receivers: dict[str, Agent],
    tainted: set[str],
) -> Agent | None:
    bound: list[tuple[int, Agent]] = []
    for index, argument in enumerate(node.args):
        if not isinstance(argument, ast.Attribute):
            continue
        if argument.attr not in _RUNTIME_METHODS or not isinstance(argument.value, ast.Name):
            continue
        agent = receivers.get(argument.value.id)
        if agent is not None:
            bound.append((index, agent))
    if len(bound) != 1:
        return None
    callback_index, agent = bound[0]
    payloads = [
        argument
        for index, argument in enumerate(node.args)
        if index != callback_index
    ] + [keyword.value for keyword in node.keywords]
    if not any(_expr_tainted(value, tainted) for value in payloads):
        return None
    return agent


def enrich_runtime_ingress_inputs(
    graph: Graph,
    root: Path,
    python_paths: list[Path],
) -> None:
    """Attach untrusted inputs when source proves handler data invokes an agent."""
    modules: dict[Path, tuple[str, ast.Module, dict[str, str]]] = {}
    for path in python_paths:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        modules[path.resolve()] = (
            _module_name(path, root),
            tree,
            _imports(tree),
        )

    if not modules or not graph.agents:
        return

    factories = _factory_targets(graph, modules)
    class_targets = _class_targets(graph, modules, factories)
    wrapper_factories = _wrapper_factory_targets(modules, class_targets)
    receiver_targets = {
        **factories,
        **class_targets,
        **wrapper_factories,
    }
    compiled_targets = _compiled_alias_targets(graph, modules)

    for path, (module, tree, imports) in modules.items():
        registered = _registered_route_handlers(tree)
        for function in ast.walk(tree):
            if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            framework = _decorator_kind(function, imports)
            if framework is None and function.name in registered:
                framework = "aiohttp"
            if framework is None:
                continue

            initial_taint = {
                name for name, _ in _parameter_annotations(function)
            }
            initial_taint.update(_global_ingress_names(imports, framework))
            if not initial_taint:
                continue
            tainted = _propagate_taint(function, initial_taint)
            receivers = _handler_receivers(
                function,
                tree,
                module,
                imports,
                receiver_targets,
                compiled_targets,
            )
            if not receivers:
                continue

            invoked: dict[int, Agent] = {}
            for node in ast.walk(function):
                if not isinstance(node, ast.Call):
                    continue
                agent = _direct_runtime_invocation(node, receivers, tainted)
                if agent is None:
                    agent = _callback_runtime_invocation(node, receivers, tainted)
                if agent is not None:
                    invoked[id(agent)] = agent

            for agent in invoked.values():
                input_name = f"{module or path.stem}.{function.name}:external-input"
                if any(
                    item.name == input_name
                    and item.metadata.get("basis") == "source_bound_runtime_ingress"
                    for item in agent.inputs
                ):
                    continue
                agent.inputs.append(
                    InputSource(
                        name=input_name,
                        trust="untrusted",
                        kind="web",
                        location=SourceLocation(
                            path,
                            getattr(function, "lineno", 1) or 1,
                            (getattr(function, "col_offset", 0) or 0) + 1,
                        ),
                        metadata={
                            "basis": "source_bound_runtime_ingress",
                            "runtime_invocation_proven": True,
                            "ingress_framework": framework,
                            "handler": function.name,
                            **_authentication_posture(tree, framework),
                        },
                    )
                )
