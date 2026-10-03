from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from horustrace.effect_semantics import (\n    executor_wrapped_callable,\n    http_mutation_capabilities,\n    sql_call_capabilities,\n)\nfrom horustrace.models import Graph, NetworkDestination, SourceLocation, Tool\n

@dataclass
class _FunctionEffect:
    capabilities: set[str] = field(default_factory=set)
    destinations: list[NetworkDestination] = field(default_factory=list)
    evidence: set[str] = field(default_factory=set)


@dataclass
class _ModuleInfo:
    path: Path
    tree: ast.AST
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef]
    wrappers: dict[str, str]
    imports: dict[str, tuple[str, str]]
    module_aliases: dict[str, str]
    imported_modules: set[str]


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


def _call_leaf(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _literal(node: ast.AST | None):
    if node is None:
        return None
    try:
        return ast.literal_eval(node)
    except (TypeError, ValueError):
        return None


def _module_name_for_path(path: Path, root: Path) -> str:
    try:
        relative = path.resolve().relative_to(root.resolve()).with_suffix("")
    except ValueError:
        relative = Path(path.stem)
    parts = list(relative.parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _resolve_import_module(
    current_module: str,
    current_path: Path,
    node: ast.ImportFrom,
) -> str:
    if node.level == 0:
        return node.module or ""

    package_parts = current_module.split(".") if current_module else []
    if current_path.stem != "__init__" and package_parts:
        package_parts = package_parts[:-1]
    parents = max(node.level - 1, 0)
    base = package_parts[: max(0, len(package_parts) - parents)]
    if node.module:
        base.extend(part for part in node.module.split(".") if part)
    return ".".join(base)


def _location(path: Path, node: ast.AST) -> SourceLocation:
    return SourceLocation(
        path=path,
        line=getattr(node, "lineno", 1) or 1,
        column=(getattr(node, "col_offset", 0) or 0) + 1,
    )


def _fixed_destination(path: Path, node: ast.AST, target: str, source: str) -> NetworkDestination:
    return NetworkDestination(
        target=target,
        restricted=True,
        location=_location(path, node),
        metadata={
            "source": source,
            "network_scope": "fixed_literal_destination",
            "repository_effect_summary": True,
        },
    )


def _merge_effect(target: _FunctionEffect, source: _FunctionEffect) -> None:
    target.capabilities.update(source.capabilities)
    target.evidence.update(source.evidence)
    seen = {
        (item.target, item.restricted, str(item.metadata.get("source") or ""))
        for item in target.destinations
    }
    for item in source.destinations:
        key = (item.target, item.restricted, str(item.metadata.get("source") or ""))
        if key not in seen:
            target.destinations.append(item)
            seen.add(key)


def _build_modules(root: Path, python_paths: list[Path]) -> dict[str, _ModuleInfo]:
    modules: dict[str, _ModuleInfo] = {}
    path_to_module: dict[Path, str] = {}
    for path in python_paths:
        module = _module_name_for_path(path, root)
        if module:
            path_to_module[path.resolve()] = module

    for path in python_paths:
        module = _module_name_for_path(path, root)
        if not module:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue

        functions = {
            node.name: node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        wrappers: dict[str, str] = {}
        imports: dict[str, tuple[str, str]] = {}
        module_aliases: dict[str, str] = {}
        imported_modules: set[str] = set()

        for node in getattr(tree, "body", []):
            if isinstance(node, ast.ImportFrom):
                source_module = _resolve_import_module(module, path, node)
                if source_module:
                    imported_modules.add(source_module)
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    imports[alias.asname or alias.name] = (source_module, alias.name)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".")[0]
                    module_aliases[local] = alias.name
                    imported_modules.add(alias.name)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if not isinstance(node.value, ast.Call) or _call_leaf(node.value.func) != "Tool":
                    continue
                wrapped = node.value.args[0] if node.value.args else next(
                    (kw.value for kw in node.value.keywords if kw.arg == "function"),
                    None,
                )
                wrapped_name = _call_leaf(wrapped)
                if not wrapped_name:
                    continue
                for target in targets:
                    if isinstance(target, ast.Name):
                        wrappers[target.id] = wrapped_name

        modules[module] = _ModuleInfo(
            path=path,
            tree=tree,
            functions=functions,
            wrappers=wrappers,
            imports=imports,
            module_aliases=module_aliases,
            imported_modules=imported_modules,
        )
    return modules


def _call_target(
    module: str,
    info: _ModuleInfo,
    call: ast.Call,
) -> tuple[str, str] | None:
    wrapped = executor_wrapped_callable(call)
    if isinstance(wrapped, ast.Name):
        if wrapped.id in info.functions:
            return module, wrapped.id
        if wrapped.id in info.imports:
            return info.imports[wrapped.id]

    if isinstance(call.func, ast.Name):
        name = call.func.id
        if name in info.functions:
            return module, name
        if name in info.imports:
            return info.imports[name]

    dotted = _dotted(call.func)
    if not dotted or "." not in dotted:
        return None
    root, _, rest = dotted.partition(".")
    imported_module = info.module_aliases.get(root)
    if imported_module and rest and "." not in rest:
        return imported_module, rest
    return None


def _typed_configuration_destination(
    info: _ModuleInfo,
    function_name: str,
    target_expr: ast.AST | None,
) -> NetworkDestination | None:
    """Recognize URL origins carried by typed operator configuration objects."""
    if target_expr is None:
        return None
    function = info.functions.get(function_name)
    if function is None:
        return None

    config_parameters: set[str] = set()
    for parameter in [
        *function.args.posonlyargs,
        *function.args.args,
        *function.args.kwonlyargs,
    ]:
        annotation = (_dotted(parameter.annotation) or _call_leaf(parameter.annotation) or "")
        leaf = annotation.rsplit(".", 1)[-1].lower()
        if leaf.endswith(("config", "settings", "configuration")):
            config_parameters.add(parameter.arg)
    if not config_parameters:
        return None

    destination_attributes = {
        "base_url",
        "api_url",
        "url",
        "endpoint",
        "base_endpoint",
        "host",
    }
    for part in ast.walk(target_expr):
        if not isinstance(part, ast.Attribute) or part.attr.lower() not in destination_attributes:
            continue
        dotted = _dotted(part)
        if not dotted or "." not in dotted:
            continue
        root = dotted.split(".", 1)[0]
        if root not in config_parameters:
            continue
        return NetworkDestination(
            target=f"<operator-configured:{dotted}>",
            restricted=True,
            location=_location(info.path, part),
            metadata={
                "source": "typed_operator_configuration",
                "network_scope": "operator_configured_destination",
                "configuration_source": dotted,
                "destination_constraint_basis": "typed_configuration_object",
                "repository_effect_summary": True,
            },
        )
    return None


def _direct_effect(
    module: str,
    info: _ModuleInfo,
    call: ast.Call,
    *,
    function_name: str = "",
) -> _FunctionEffect:
    result = _FunctionEffect()
    dotted = (_dotted(call.func) or _call_leaf(call.func) or "").lower()
    leaf = (_call_leaf(call.func) or "").lower()

    if (
        dotted in {
            "exec",
            "eval",
            "compile",
            "builtins.exec",
            "builtins.eval",
            "builtins.compile",
            "os.system",
            "os.popen",
        }
        or dotted.startswith("subprocess.")
        or "create_subprocess_" in dotted
    ):
        result.capabilities.add("process.execute")
        result.evidence.add(f"process:{dotted}")

    if (
        dotted.startswith(("requests.", "httpx.", "aiohttp."))
        or "urllib.request" in dotted
    ):
        result.capabilities.add("network.external")
        result.capabilities.update(
            http_mutation_capabilities(call, function_name=function_name)
        )
        result.evidence.add(f"http:{dotted}")
        target_expr = (
            call.args[1]
            if leaf == "request" and len(call.args) > 1
            else call.args[0]
            if call.args
            else next(
                (kw.value for kw in call.keywords if kw.arg in {"url", "uri", "endpoint"}),
                None,
            )
        )
        target = _literal(target_expr)
        if (
            isinstance(target, str)
            and target.startswith(("http://", "https://"))
            and urlparse(target).hostname
        ):
            result.destinations.append(
                _fixed_destination(info.path, target_expr or call, target, "literal_url")
            )
        else:
            configured = _typed_configuration_destination(
                info,
                function_name,
                target_expr,
            )
            if configured is not None:
                result.destinations.append(configured)
                result.evidence.add(
                    f"operator-configured-destination:{configured.metadata.get('configuration_source')}"
                )

    if leaf == "open" or dotted.endswith(".open"):
        mode = _literal(call.args[1]) if len(call.args) > 1 else next(
            (_literal(kw.value) for kw in call.keywords if kw.arg == "mode"),
            "r",
        )
        if isinstance(mode, str) and any(char in mode for char in "wax+"):
            result.capabilities.add("data.write")
            result.evidence.add("file:write")
        else:
            result.capabilities.add("data.read")
            result.evidence.add("file:read")

    # Concrete SQL and persistence APIs.
    sql_capabilities = sql_call_capabilities(call)
    if sql_capabilities:
        result.capabilities.update(sql_capabilities)
        result.evidence.add(f"sql:{leaf}")
    if leaf in {"add", "add_all", "commit", "flush", "merge", "bulk_save_objects"} and (
        "session" in dotted or "db" in dotted
    ):
        result.capabilities.add("data.write")
        result.evidence.add(f"database:{dotted}")
    if leaf in {"delete", "remove"} and ("session" in dotted or "db" in dotted):
        result.capabilities.update({"data.write", "destructive.write"})
        result.evidence.add(f"database:{dotted}")
    if leaf in {"query", "scalar", "scalars", "execute"} and (
        "session" in dotted or "db" in dotted
    ):
        result.capabilities.add("data.read")
        result.evidence.add(f"database:{dotted}")

    # Source-visible outbound SDK sinks.
    sendgrid_present = any(name.startswith("sendgrid") for name in info.imported_modules)
    twilio_present = any(name.startswith("twilio") for name in info.imported_modules)
    if sendgrid_present and leaf == "send":
        result.capabilities.update({"external.write", "network.external"})
        result.evidence.add(f"sendgrid:{dotted}")
        result.destinations.append(
            NetworkDestination(
                target="<provider:sendgrid>",
                restricted=True,
                location=_location(info.path, call),
                metadata={
                    "source": "provider_sdk",
                    "network_scope": "fixed_provider_network",
                    "provider": "sendgrid",
                    "repository_effect_summary": True,
                },
            )
        )
    if twilio_present and dotted.endswith(".messages.create"):
        result.capabilities.update({"external.write", "network.external"})
        result.evidence.add(f"twilio:{dotted}")
        result.destinations.append(
            NetworkDestination(
                target="<provider:twilio>",
                restricted=True,
                location=_location(info.path, call),
                metadata={
                    "source": "provider_sdk",
                    "network_scope": "fixed_provider_network",
                    "provider": "twilio",
                    "repository_effect_summary": True,
                },
            )
        )

    # NATS is a network transport. Literal brokers are fixed destinations;
    # only source-visible control/actuation subjects establish external writes.
    nats_present = any(name == "nats" or name.startswith("nats.") for name in info.imported_modules)
    if nats_present and leaf in {"connect", "request", "publish"}:
        result.capabilities.add("network.external")
        result.evidence.add(f"nats:{dotted}")
        if leaf == "connect" and call.args:
            broker = _literal(call.args[0])
            if isinstance(broker, str) and broker.startswith(("nats://", "tls://")):
                result.destinations.append(
                    NetworkDestination(
                        target=broker,
                        restricted=True,
                        location=_location(info.path, call),
                        metadata={
                            "source": "literal_broker",
                            "network_scope": "fixed_literal_destination",
                            "provider": "nats",
                            "repository_effect_summary": True,
                        },
                    )
                )
        if leaf in {"request", "publish"}:
            subject = _literal(call.args[0]) if call.args else None
            if isinstance(subject, str):
                lowered = subject.lower()
                write_markers = (
                    "motion",
                    "nav",
                    "navigate",
                    "control",
                    "actuate",
                    "ros_cmd",
                    "write",
                    "update",
                )
                read_markers = ("status", "vision", "query", "read", "get", "search")
                if any(token in lowered for token in write_markers) and not any(
                    token in lowered for token in read_markers
                ):
                    result.capabilities.add("external.write")
                    result.evidence.add(f"nats-command:{subject}")

    return result


def _resolve_wrapper_symbol(
    modules: dict[str, _ModuleInfo],
    module: str,
    symbol: str,
) -> tuple[str, str] | None:
    info = modules.get(module)
    if info is None:
        return None
    wrapped = info.wrappers.get(symbol)
    if wrapped:
        if wrapped in info.functions:
            return module, wrapped
        if wrapped in info.imports:
            return info.imports[wrapped]
    if symbol in info.functions:
        return module, symbol
    if symbol in info.imports:
        return info.imports[symbol]
    return None


def _summarize_function(
    modules: dict[str, _ModuleInfo],
    module: str,
    symbol: str,
    cache: dict[tuple[str, str], _FunctionEffect],
    stack: set[tuple[str, str]],
) -> _FunctionEffect:
    resolved = _resolve_wrapper_symbol(modules, module, symbol) or (module, symbol)
    if resolved != (module, symbol):
        return _summarize_function(
            modules,
            resolved[0],
            resolved[1],
            cache,
            stack,
        )

    key = (module, symbol)
    if key in cache:
        return cache[key]
    if key in stack:
        return _FunctionEffect()

    info = modules.get(module)
    function = info.functions.get(symbol) if info is not None else None
    if info is None or function is None:
        return _FunctionEffect()

    result = _FunctionEffect()
    next_stack = set(stack)
    next_stack.add(key)

    for call in (node for node in ast.walk(function) if isinstance(node, ast.Call)):
        _merge_effect(
            result,
            _direct_effect(
                module,
                info,
                call,
                function_name=symbol,
            ),
        )
        target = _call_target(module, info, call)
        if target is None:
            continue
        target_module, target_symbol = target
        if target_module not in modules:
            continue
        _merge_effect(
            result,
            _summarize_function(
                modules,
                target_module,
                target_symbol,
                cache,
                next_stack,
            ),
        )

    cache[key] = result
    return result


def _has_cross_module_call(
    modules: dict[str, _ModuleInfo],
    module: str,
    symbol: str,
    seen: set[tuple[str, str]] | None = None,
) -> bool:
    """Return True when a repository-local function chain crosses module boundaries."""
    resolved = _resolve_wrapper_symbol(modules, module, symbol) or (module, symbol)
    module, symbol = resolved
    key = (module, symbol)
    seen = set() if seen is None else set(seen)
    if key in seen:
        return False
    seen.add(key)

    info = modules.get(module)
    function = info.functions.get(symbol) if info is not None else None
    if info is None or function is None:
        return False

    for call in (node for node in ast.walk(function) if isinstance(node, ast.Call)):
        target = _call_target(module, info, call)
        if target is None or target[0] not in modules:
            continue
        if target[0] != module:
            return True
        if _has_cross_module_call(
            modules,
            target[0],
            target[1],
            seen,
        ):
            return True
    return False


def _direct_function_effect(
    modules: dict[str, _ModuleInfo],
    module: str,
    symbol: str,
) -> _FunctionEffect:
    resolved = _resolve_wrapper_symbol(modules, module, symbol) or (module, symbol)
    info = modules.get(resolved[0])
    function = info.functions.get(resolved[1]) if info is not None else None
    if info is None or function is None:
        return _FunctionEffect()

    result = _FunctionEffect()
    for call in (node for node in ast.walk(function) if isinstance(node, ast.Call)):
        _merge_effect(
            result,
            _direct_effect(
                resolved[0],
                info,
                call,
                function_name=resolved[1],
            ),
        )
    return result


def _effect_has_transitive_delta(
    effect: _FunctionEffect,
    direct: _FunctionEffect,
) -> bool:
    if effect.capabilities - direct.capabilities:
        return True
    direct_destinations = {
        (item.target, item.restricted, str(item.metadata.get("source") or ""))
        for item in direct.destinations
    }
    return any(
        (item.target, item.restricted, str(item.metadata.get("source") or ""))
        not in direct_destinations
        for item in effect.destinations
    )


def _tool_source_symbol(
    tool: Tool,
    root: Path,
    modules: dict[str, _ModuleInfo],
) -> tuple[str, str] | None:
    import_module = tool.metadata.get("import_module")
    if isinstance(import_module, str) and import_module:
        resolved = _resolve_wrapper_symbol(modules, import_module, tool.name)
        if resolved is not None:
            return resolved

    if tool.location is None:
        return None
    module = _module_name_for_path(tool.location.path, root)
    if not module or module not in modules:
        return None
    resolved = _resolve_wrapper_symbol(modules, module, tool.name)
    if resolved is not None:
        return resolved
    return None


def enrich_repository_tool_effects(
    graph: Graph,
    root: Path,
    python_paths: list[Path],
) -> None:
    """Propagate source-visible effects across repository-local function boundaries."""
    modules = _build_modules(root, python_paths)
    if not modules:
        return

    cache: dict[tuple[str, str], _FunctionEffect] = {}
    for agent in graph.agents:
        resolved_names: set[str] = set()
        for tool in agent.tools:
            source = _tool_source_symbol(tool, root, modules)
            if source is None:
                continue
            effect = _summarize_function(
                modules,
                source[0],
                source[1],
                cache,
                set(),
            )
            if not effect.capabilities and not effect.destinations:
                continue

            imported_or_wrapped = bool(tool.metadata.get("import_module")) or bool(
                tool.metadata.get("placeholder")
            )
            if not imported_or_wrapped and not _has_cross_module_call(
                modules,
                source[0],
                source[1],
            ):
                direct_effect = _direct_function_effect(
                    modules,
                    source[0],
                    source[1],
                )
                if not _effect_has_transitive_delta(effect, direct_effect):
                    continue

            before = set(tool.capabilities)
            tool.capabilities.update(effect.capabilities)
            seen = {
                (item.target, item.restricted, str(item.metadata.get("source") or ""))
                for item in tool.destinations
            }
            for destination in effect.destinations:
                key = (
                    destination.target,
                    destination.restricted,
                    str(destination.metadata.get("source") or ""),
                )
                if key not in seen:
                    tool.destinations.append(destination)
                    seen.add(key)

            tool.metadata.update(
                {
                    "repository_effect_resolved": True,
                    "repository_effect_source": f"{source[0]}.{source[1]}",
                    "repository_effect_evidence": sorted(effect.evidence),
                    "repository_effect_capabilities": sorted(effect.capabilities),
                }
            )
            if tool.metadata.get("placeholder"):
                tool.metadata["placeholder"] = False
                tool.metadata["repository_resolved"] = True
            if tool.capabilities != before:
                tool.metadata["repository_effect_enriched"] = True
            resolved_names.add(tool.name)

        unresolved = set(agent.metadata.get("unresolved_helpers") or [])
        if resolved_names & unresolved:
            unresolved.difference_update(resolved_names)
            if unresolved:
                agent.metadata["unresolved_helpers"] = sorted(unresolved)
            else:
                agent.metadata.pop("unresolved_helpers", None)
                agent.metadata.pop("external_helper_semantics_unresolved", None)
