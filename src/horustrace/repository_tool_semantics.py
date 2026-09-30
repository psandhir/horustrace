from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from horustrace.models import Graph, InputSource, NetworkDestination, ResourceScope, Tool


@dataclass(frozen=True, slots=True)
class FunctionDefRef:
    module: str
    path: Path
    node: ast.FunctionDef | ast.AsyncFunctionDef


@dataclass(frozen=True, slots=True)
class FunctionSemantics:
    accesses: frozenset[str] = frozenset()
    constrained: bool = False
    returns_file_content: bool = False
    path_parameters: frozenset[str] = frozenset()


def _module_name(path: Path, root: Path) -> str:
    try:
        relative = path.resolve().relative_to(root.resolve()).with_suffix("")
    except ValueError:
        relative = Path(path.stem)
    parts = list(relative.parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _dotted_name(node: ast.AST | None) -> str | None:
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


def _call_leaf(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _parameter_names(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    return [
        arg.arg
        for arg in [
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
        ]
    ]


def _expr_names(node: ast.AST | None) -> set[str]:
    if node is None:
        return set()
    return {
        child.id
        for child in ast.walk(node)
        if isinstance(child, ast.Name)
    }


def _target_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, (ast.Tuple, ast.List)):
        names: set[str] = set()
        for element in node.elts:
            names.update(_target_names(element))
        return names
    return set()


def _taint_origins(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    tainted_parameters: set[str],
) -> dict[str, set[str]]:
    origins: dict[str, set[str]] = {
        parameter: {parameter}
        for parameter in tainted_parameters
    }
    changed = True
    while changed:
        changed = False
        for child in ast.walk(function):
            if not isinstance(child, (ast.Assign, ast.AnnAssign)):
                continue
            value_origins: set[str] = set()
            for name in _expr_names(child.value):
                value_origins.update(origins.get(name, set()))
            if not value_origins:
                continue
            targets = (
                child.targets
                if isinstance(child, ast.Assign)
                else [child.target]
            )
            for target in targets:
                for name in _target_names(target):
                    previous = set(origins.get(name, set()))
                    combined = previous | value_origins
                    if combined != previous:
                        origins[name] = combined
                        changed = True
    return origins


def _tainted_aliases(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    tainted_parameters: set[str],
) -> set[str]:
    return set(_taint_origins(function, tainted_parameters))


def _containment_detected(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    tainted: set[str],
) -> bool:
    for child in ast.walk(function):
        if not isinstance(child, ast.Call):
            continue
        called = (_dotted_name(child.func) or "").lower()
        leaf = _call_leaf(child) or ""
        if leaf in {"relative_to", "is_relative_to"}:
            receiver = child.func.value if isinstance(child.func, ast.Attribute) else None
            if _expr_names(receiver) & tainted:
                return True
        if (
            called in {"os.path.commonpath", "posixpath.commonpath", "ntpath.commonpath"}
            and _expr_names(child) & tainted
        ):
            return True
        if (
            leaf in {
                "_validate_agent_scoped_path",
                "validate_agent_scoped_path",
                "_resolve_agent_scoped_path",
            }
            and any(_expr_names(argument) & tainted for argument in child.args)
        ):
            return True
    return False


def _function_semantics(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    tainted_parameters: set[str],
) -> FunctionSemantics:
    taint_origins = _taint_origins(function, tainted_parameters)
    tainted = set(taint_origins)

    def path_origins(node: ast.AST | None) -> set[str]:
        result: set[str] = set()
        for name in _expr_names(node):
            result.update(taint_origins.get(name, set()))
        return result

    accesses: set[str] = set()
    path_parameters: set[str] = set()
    read_calls: list[ast.Call] = []

    for child in ast.walk(function):
        if not isinstance(child, ast.Call):
            continue
        leaf = _call_leaf(child) or ""
        receiver = child.func.value if isinstance(child.func, ast.Attribute) else None
        receiver_tainted = bool(_expr_names(receiver) & tainted)
        arg_tainted = any(_expr_names(argument) & tainted for argument in child.args)

        if leaf in {"read_text", "read_bytes", "rglob", "glob", "iterdir"} and receiver_tainted:
            accesses.add("read")
            path_parameters.update(path_origins(receiver))
            if leaf in {"read_text", "read_bytes"}:
                read_calls.append(child)

        if leaf in {"write_text", "write_bytes", "unlink", "rename", "replace"} and receiver_tainted:
            accesses.add("write")
            path_parameters.update(path_origins(receiver))

        if leaf == "open":
            path_expr: ast.AST | None = receiver if receiver_tainted else None
            if path_expr is None and child.args:
                path_expr = child.args[0]
            if path_expr is None:
                path_expr = next(
                    (
                        keyword.value
                        for keyword in child.keywords
                        if keyword.arg in {"file", "path"}
                    ),
                    None,
                )
            selected_path_parameters = path_origins(path_expr)
            if not selected_path_parameters:
                continue

            mode = None
            if len(child.args) > 1 and isinstance(child.args[1], ast.Constant):
                mode = child.args[1].value
            for keyword in child.keywords:
                if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant):
                    mode = keyword.value.value
            if isinstance(mode, str) and any(flag in mode for flag in "wax+"):
                accesses.add("write")
            else:
                accesses.add("read")
                read_calls.append(child)
            path_parameters.update(selected_path_parameters)

    returns_file_content = False
    for child in ast.walk(function):
        if not isinstance(child, ast.Return) or child.value is None:
            continue
        if any(
            return_call is nested
            for nested in ast.walk(child.value)
            if isinstance(nested, ast.Call)
            for return_call in read_calls
        ):
            returns_file_content = True
            break
        returned_names = _expr_names(child.value)
        for assignment in ast.walk(function):
            if not isinstance(assignment, (ast.Assign, ast.AnnAssign)):
                continue
            targets = (
                assignment.targets
                if isinstance(assignment, ast.Assign)
                else [assignment.target]
            )
            assigned_names = {
                name
                for target in targets
                for name in _target_names(target)
            }
            if not (assigned_names & returned_names):
                continue
            if any(
                read_call is nested
                for nested in ast.walk(assignment.value)
                if isinstance(nested, ast.Call)
                for read_call in read_calls
            ):
                returns_file_content = True
                break
        if returns_file_content:
            break

    return FunctionSemantics(
        accesses=frozenset(accesses),
        constrained=_containment_detected(function, tainted),
        returns_file_content=returns_file_content,
        path_parameters=frozenset(path_parameters),
    )


def _resolved_import_module(
    current_module: str,
    current_path: Path,
    node: ast.ImportFrom,
) -> str | None:
    if node.level == 0:
        return node.module or ""
    package_parts = current_module.split(".") if current_module else []
    if current_path.stem != "__init__" and package_parts:
        package_parts = package_parts[:-1]
    parents = node.level - 1
    if parents > len(package_parts):
        return None
    base = package_parts[: len(package_parts) - parents]
    if node.module:
        base.extend(part for part in node.module.split(".") if part)
    return ".".join(base)


def _fixed_url_origin(node: ast.AST | None) -> str | None:
    """Return a fixed scheme/host when an expression only varies below the host."""
    if node is None:
        return None
    prefix = ""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        prefix = node.value
    elif isinstance(node, ast.JoinedStr):
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                prefix += value.value
            else:
                break
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _fixed_url_origin(node.left)

    if not prefix.startswith(("http://", "https://")):
        return None
    parsed = urlparse(prefix)
    if not parsed.scheme or not parsed.hostname:
        return None
    port = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme}://{parsed.hostname}{port}"


def _source_network_semantics(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[list[NetworkDestination], dict[str, object]]:
    """Infer fixed-provider HTTP scope only when caller parameters do not choose the URL."""
    parameters = set(_parameter_names(function))
    tainted = _tainted_aliases(function, parameters)
    fixed_origins: dict[str, str] = {}

    for child in ast.walk(function):
        if not isinstance(child, (ast.Assign, ast.AnnAssign)) or child.value is None:
            continue
        origin = _fixed_url_origin(child.value)
        if origin is None:
            continue
        targets = child.targets if isinstance(child, ast.Assign) else [child.target]
        for target in targets:
            for name in _target_names(target):
                fixed_origins[name] = origin

    if not fixed_origins:
        return [], {}

    observed_origins: set[str] = set()
    caller_selected_http = False
    for child in ast.walk(function):
        if not isinstance(child, ast.Call):
            continue
        called = (_dotted_name(child.func) or "").lower()
        leaf = _call_leaf(child) or ""
        is_http = (
            called in {
                "requests.get",
                "requests.post",
                "requests.put",
                "requests.patch",
                "requests.delete",
                "httpx.get",
                "httpx.post",
                "httpx.put",
                "httpx.patch",
                "httpx.delete",
            }
            or leaf in {"get", "post", "put", "patch", "delete", "request"}
            and any(token in called for token in ("requests", "httpx", "aiohttp"))
        )
        if not is_http:
            continue
        target = child.args[0] if child.args else next(
            (keyword.value for keyword in child.keywords if keyword.arg in {"url", "uri"}),
            None,
        )
        if target is None:
            continue
        if isinstance(target, ast.Name) and target.id in fixed_origins:
            observed_origins.add(fixed_origins[target.id])
            continue
        origin = _fixed_url_origin(target)
        if origin:
            observed_origins.add(origin)
            continue
        if _expr_names(target) & tainted:
            caller_selected_http = True
            break

    if caller_selected_http or not observed_origins:
        return [], {}

    destinations = [
        NetworkDestination(
            target=origin,
            restricted=True,
            metadata={
                "source": "source_function_fixed_origin",
                "network_scope": "fixed_provider_network",
                "dynamic_path": True,
            },
        )
        for origin in sorted(observed_origins)
    ]
    return destinations, {
        "network_scope": "fixed_provider_network",
        "fixed_provider_origins": sorted(observed_origins),
        "destination_constraint_basis": "source_function_fixed_origin",
    }


def _source_internal_state_semantics(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> dict[str, object]:
    """Detect source-visible mutations confined to Pydantic RunContext.deps state."""
    context_params: set[str] = set()
    for argument in [
        *function.args.posonlyargs,
        *function.args.args,
        *function.args.kwonlyargs,
    ]:
        annotation = argument.annotation
        if annotation is None:
            continue
        rendered = ast.unparse(annotation)
        if "RunContext" in rendered:
            context_params.add(argument.arg)
    if not context_params:
        return {}

    def expr_is_internal(node: ast.AST | None, aliases: set[str]) -> bool:
        if node is None:
            return False
        dotted = _dotted_name(node)
        if dotted and any(
            dotted == f"{name}.deps" or dotted.startswith(f"{name}.deps.")
            for name in context_params
        ):
            return True
        names = _expr_names(node)
        return bool(names & aliases)

    aliases: set[str] = set()
    changed = True
    while changed:
        changed = False
        for child in ast.walk(function):
            if isinstance(child, (ast.Assign, ast.AnnAssign)) and child.value is not None:
                if not expr_is_internal(child.value, aliases):
                    continue
                targets = child.targets if isinstance(child, ast.Assign) else [child.target]
                for target in targets:
                    for name in _target_names(target):
                        if name not in aliases:
                            aliases.add(name)
                            changed = True
            elif isinstance(child, (ast.For, ast.AsyncFor)):
                if not expr_is_internal(child.iter, aliases):
                    continue
                for name in _target_names(child.target):
                    if name not in aliases:
                        aliases.add(name)
                        changed = True

    internal_mutation = False
    external_sink = False
    mutating_collection_methods = {
        "append",
        "extend",
        "insert",
        "remove",
        "pop",
        "clear",
        "update",
        "add",
        "discard",
    }
    external_call_leaves = {
        "open",
        "write_text",
        "write_bytes",
        "unlink",
        "rename",
        "replace",
        "commit",
        "execute",
        "executemany",
        "save",
        "upsert",
        "put",
        "post",
        "patch",
        "delete",
    }

    for child in ast.walk(function):
        targets: list[ast.AST] = []
        if isinstance(child, ast.Assign):
            targets = list(child.targets)
        elif isinstance(child, (ast.AnnAssign, ast.AugAssign)):
            targets = [child.target]
        elif isinstance(child, ast.Delete):
            targets = list(child.targets)

        for target in targets:
            if expr_is_internal(target, aliases):
                internal_mutation = True

        if not isinstance(child, ast.Call):
            continue
        called = (_dotted_name(child.func) or _call_leaf(child) or "").lower()
        leaf = (_call_leaf(child) or "").lower()
        receiver = child.func.value if isinstance(child.func, ast.Attribute) else None
        receiver_internal = expr_is_internal(receiver, aliases)

        if receiver_internal and leaf in mutating_collection_methods:
            internal_mutation = True
            continue

        if (
            called.startswith(("requests.", "httpx.", "aiohttp.", "subprocess."))
            or "create_subprocess_" in called
            or called in {"os.system", "os.popen", "exec", "eval"}
            or leaf in external_call_leaves
        ):
            external_sink = True

    if not internal_mutation or external_sink:
        return {}
    return {
        "agent_internal_state": True,
        "mutation_semantics": "agent_internal_state",
        "internal_state_basis": "pydantic_run_context_deps",
    }


def _source_control_semantics(
    ref: FunctionDefRef,
    functions: dict[tuple[str, str], FunctionDefRef],
) -> dict[str, object]:
    """Resolve source-visible path/process controls through local helper calls."""
    visited: set[tuple[str, str]] = set()

    def inspect(current: FunctionDefRef) -> dict[str, object]:
        key = (current.module, current.node.name)
        if key in visited:
            return {}
        visited.add(key)
        result: dict[str, object] = {}

        names = {
            child.id
            for child in ast.walk(current.node)
            if isinstance(child, ast.Name)
        }
        calls = [
            child for child in ast.walk(current.node) if isinstance(child, ast.Call)
        ]
        if (
            "ALLOWED_COMMANDS" in names
            and "DANGEROUS_PATTERNS" in names
            and any(
                (_dotted_name(call.func) or "").endswith("create_subprocess_exec")
                or (_dotted_name(call.func) or "").endswith("subprocess.run")
                or (_dotted_name(call.func) or "").endswith("subprocess.Popen")
                for call in calls
            )
        ):
            result.update(
                {
                    "process_execution_constrained": True,
                    "process_command_allowlist": True,
                    "process_injection_filter": True,
                    "process_control_basis": "source_command_allowlist_and_injection_filter",
                }
            )

        if any(
            _call_leaf(call)
            in {
                "_validate_agent_scoped_path",
                "validate_agent_scoped_path",
                "_resolve_agent_scoped_path",
            }
            for call in calls
        ):
            result.update(
                {
                    "filesystem_path_constrained": True,
                    "filesystem_scope": ".shotgun/**",
                    "agent_internal_artifact": True,
                    "filesystem_control_basis": "agent_scoped_path_validation",
                }
            )

        for call in calls:
            leaf = _call_leaf(call)
            if not leaf:
                continue
            helper = functions.get((current.module, leaf))
            if helper is None:
                continue
            nested = inspect(helper)
            for name, value in nested.items():
                result.setdefault(name, value)
        return result

    return inspect(ref)


def enrich_indirect_tool_content_semantics(
    graph: Graph,
    root: Path,
    python_paths: list[Path],
) -> None:
    """Annotate source-proven tool-result content and model-selected filesystem authority."""

    trees: dict[Path, ast.Module] = {}
    functions: dict[tuple[str, str], FunctionDefRef] = {}
    modules_by_path: dict[Path, str] = {}

    for raw_path in python_paths:
        path = raw_path.resolve()
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        module = _module_name(path, root)
        trees[path] = tree
        modules_by_path[path] = module
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions[(module, node.name)] = FunctionDefRef(module, path, node)

    if not functions:
        return

    def ref_for_tool(tool: Tool) -> FunctionDefRef | None:
        source_path = tool.metadata.get("source_path")
        source_function = tool.metadata.get("source_function")
        if not isinstance(source_path, str) or not isinstance(source_function, str):
            return None
        path = Path(source_path).resolve()
        module = modules_by_path.get(path)
        if module is None:
            return None
        return functions.get((module, source_function))

    def imported_functions(ref: FunctionDefRef) -> dict[str, FunctionDefRef]:
        tree = trees.get(ref.path)
        if tree is None:
            return {}
        resolved: dict[str, FunctionDefRef] = {}
        for node in tree.body:
            if not isinstance(node, ast.ImportFrom):
                continue
            source_module = _resolved_import_module(ref.module, ref.path, node)
            if not source_module:
                continue
            for alias in node.names:
                target = functions.get((source_module, alias.name))
                if target is not None:
                    resolved[alias.asname or alias.name] = target
        return resolved

    def enrich_source_semantics(tool: Tool) -> None:
        ref = ref_for_tool(tool)
        if ref is None:
            return

        destinations, network_metadata = _source_network_semantics(ref.node)
        if destinations:
            tool.capabilities.add("network.external")
            for destination in destinations:
                if not any(
                    existing.target == destination.target
                    and existing.metadata.get("network_scope")
                    == destination.metadata.get("network_scope")
                    for existing in tool.destinations
                ):
                    tool.destinations.append(destination)
            tool.metadata.update(network_metadata)

        internal_state = _source_internal_state_semantics(ref.node)
        if internal_state:
            tool.metadata.update(internal_state)
            # Function-name heuristics such as create_*/remove_* describe
            # in-memory agent control state here, not external mutation authority.
            tool.capabilities.difference_update({"data.write", "destructive.write"})

        controls = _source_control_semantics(ref, functions)
        if controls:
            tool.metadata.update(controls)
            tool.guardrails = True

        if (
            controls.get("filesystem_path_constrained") is True
            and not any(
                resource.kind == "file" and resource.selector == ".shotgun/**"
                for resource in tool.resources
            )
        ):
            tool.resources.append(
                ResourceScope(
                    kind="file",
                    selector=".shotgun/**",
                    access=set(
                        tool.capabilities
                        & {"data.read", "data.write", "destructive.write"}
                    ),
                    location=tool.location,
                )
            )

    def inspect_tool(tool: Tool) -> FunctionSemantics | None:
        ref = ref_for_tool(tool)
        if ref is None:
            return None
        wrapper_parameters = set(_parameter_names(ref.node))
        combined_accesses: set[str] = set()
        combined_path_parameters: set[str] = set()
        constrained_evidence: list[bool] = []
        returns_file_content = False

        direct = _function_semantics(ref.node, wrapper_parameters)
        combined_accesses.update(direct.accesses)
        combined_path_parameters.update(direct.path_parameters)
        if direct.accesses:
            constrained_evidence.append(direct.constrained)
        returns_file_content = returns_file_content or direct.returns_file_content

        helpers = imported_functions(ref)
        for call in [
            child
            for child in ast.walk(ref.node)
            if isinstance(child, ast.Call)
        ]:
            helper_name = _call_leaf(call)
            helper = helpers.get(helper_name or "")
            if helper is None:
                continue
            helper_parameters = _parameter_names(helper.node)
            tainted_helper_parameters: set[str] = set()
            for index, argument in enumerate(call.args):
                if index >= len(helper_parameters):
                    break
                if _expr_names(argument) & wrapper_parameters:
                    tainted_helper_parameters.add(helper_parameters[index])
            for keyword in call.keywords:
                if keyword.arg and _expr_names(keyword.value) & wrapper_parameters:
                    tainted_helper_parameters.add(keyword.arg)
            if not tainted_helper_parameters:
                continue

            helper_semantics = _function_semantics(
                helper.node,
                tainted_helper_parameters,
            )
            if not helper_semantics.accesses:
                continue
            combined_accesses.update(helper_semantics.accesses)
            constrained_evidence.append(helper_semantics.constrained)
            for wrapper_parameter in wrapper_parameters:
                if any(
                    wrapper_parameter in _expr_names(argument)
                    for argument in call.args
                ) or any(
                    wrapper_parameter in _expr_names(keyword.value)
                    for keyword in call.keywords
                ):
                    combined_path_parameters.add(wrapper_parameter)

            if helper_semantics.returns_file_content:
                for return_node in ast.walk(ref.node):
                    if not isinstance(return_node, ast.Return) or return_node.value is None:
                        continue
                    if any(
                        nested is call
                        for nested in ast.walk(return_node.value)
                    ):
                        returns_file_content = True
                        break

        if not combined_accesses:
            return None
        return FunctionSemantics(
            accesses=frozenset(combined_accesses),
            constrained=bool(constrained_evidence) and all(constrained_evidence),
            returns_file_content=returns_file_content,
            path_parameters=frozenset(combined_path_parameters),
        )

    for agent in graph.agents:
        content_sources: list[Tool] = []
        for tool in agent.tools:
            enrich_source_semantics(tool)
            semantics = inspect_tool(tool)
            if semantics is None:
                continue
            tool.metadata["model_selected_filesystem_path"] = True
            tool.metadata["filesystem_access"] = sorted(semantics.accesses)
            tool.metadata["filesystem_path_constrained"] = (
                tool.metadata.get("filesystem_path_constrained") is True
                or semantics.constrained
            )
            tool.metadata["model_selected_path_parameters"] = sorted(
                semantics.path_parameters
            )
            tool.metadata["filesystem_semantics_basis"] = (
                "source_function_and_local_helper"
            )

            if (
                semantics.path_parameters
                and semantics.constrained is False
                and not any(
                    resource.kind == "file"
                    and resource.metadata.get("model_selected_path") is True
                    for resource in tool.resources
                )
            ):
                access: set[str] = set()
                if "read" in semantics.accesses:
                    access.add("data.read")
                if "write" in semantics.accesses:
                    write_capabilities = tool.capabilities & {
                        "data.write",
                        "destructive.write",
                    }
                    access.update(write_capabilities or {"data.write"})
                tool.resources.append(
                    ResourceScope(
                        kind="file",
                        selector="<model-selected-path>",
                        access=access,
                        location=tool.location,
                        metadata={
                            "model_selected_path": True,
                            "path_parameters": sorted(semantics.path_parameters),
                            "path_containment": "not_detected",
                            "basis": "source_function_and_local_helper",
                        },
                    )
                )

            if semantics.returns_file_content and "read" in semantics.accesses:
                tool.metadata["returns_local_file_content"] = True
                content_sources.append(tool)

        for source_tool in content_sources:
            input_name = f"{source_tool.name}:tool-result"
            if any(item.name == input_name for item in agent.inputs):
                continue
            agent.inputs.append(
                InputSource(
                    name=input_name,
                    trust="untrusted",
                    kind="document",
                    location=source_tool.location or agent.location,
                    metadata={
                        "basis": "source_proven_tool_result_content",
                        "indirect": True,
                        "source_tool": source_tool.name,
                        "source_function_key": source_tool.metadata.get(
                            "source_function_key"
                        ),
                    },
                )
            )
