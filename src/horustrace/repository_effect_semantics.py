from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from horustrace.effect_semantics import (
    executor_wrapped_callable,
    http_mutation_capabilities,
    sql_call_capabilities,
)
from horustrace.models import Graph, NetworkDestination, SourceLocation, Tool


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
    classes: dict[str, ast.ClassDef]
    wrappers: dict[str, str]
    imports: dict[str, tuple[str, str]]
    module_aliases: dict[str, str]
    function_imports: dict[str, dict[str, tuple[str, str]]]
    function_module_aliases: dict[str, dict[str, str]]
    module_assignments: dict[str, ast.AST]
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


def _function_scope_nodes(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
):
    """Yield nodes owned by one function without descending into nested scopes."""
    stack = list(reversed(function.body))
    while stack:
        node = stack.pop()
        yield node
        if isinstance(
            node,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda),
        ):
            continue
        children = list(ast.iter_child_nodes(node))
        stack.extend(reversed(children))


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


def _transitive_effect_for_call(
    source: _FunctionEffect,
    target_symbol: str,
    call: ast.Call,
) -> _FunctionEffect:
    """Return the authority that may flow through one repository-local call.

    Source-fixed prerequisite/control helpers can execute implementation-detail
    subprocesses (for example mounting a workspace) without granting each caller
    arbitrary process-execution authority. Keep their other material effects,
    but do not leak process.execute through an argument-free setup/control call.
    """
    result = _FunctionEffect(
        capabilities=set(source.capabilities),
        destinations=list(source.destinations),
        evidence=set(source.evidence),
    )
    normalized = target_symbol.lower()
    control_helper = normalized.startswith(
        (
            "_ensure",
            "ensure_",
            "_validate",
            "validate_",
            "_check",
            "check_",
            "_safe",
            "safe_",
        )
    )
    if (
        control_helper
        and not call.args
        and not call.keywords
        and "process.execute" in result.capabilities
    ):
        result.capabilities.discard("process.execute")
        result.evidence = {
            item for item in result.evidence if not item.startswith("process:")
        }
    return result


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
        classes = {
            node.name: node
            for node in getattr(tree, "body", [])
            if isinstance(node, ast.ClassDef)
        }
        wrappers: dict[str, str] = {}
        imports: dict[str, tuple[str, str]] = {}
        module_aliases: dict[str, str] = {}
        function_imports: dict[str, dict[str, tuple[str, str]]] = {}
        function_module_aliases: dict[str, dict[str, str]] = {}
        module_assignments: dict[str, ast.AST] = {}
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
                for target in targets:
                    if isinstance(target, ast.Name):
                        module_assignments[target.id] = node.value
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

        for function_name, function in functions.items():
            local_imports: dict[str, tuple[str, str]] = {}
            local_module_aliases: dict[str, str] = {}
            for node in _function_scope_nodes(function):
                if isinstance(node, ast.ImportFrom):
                    source_module = _resolve_import_module(module, path, node)
                    if source_module:
                        imported_modules.add(source_module)
                    for alias in node.names:
                        if alias.name == "*":
                            continue
                        local_imports[alias.asname or alias.name] = (
                            source_module,
                            alias.name,
                        )
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        local = alias.asname or alias.name.split(".")[0]
                        local_module_aliases[local] = alias.name
                        imported_modules.add(alias.name)
            if local_imports:
                function_imports[function_name] = local_imports
            if local_module_aliases:
                function_module_aliases[function_name] = local_module_aliases

        modules[module] = _ModuleInfo(
            path=path,
            tree=tree,
            functions=functions,
            classes=classes,
            wrappers=wrappers,
            imports=imports,
            module_aliases=module_aliases,
            function_imports=function_imports,
            function_module_aliases=function_module_aliases,
            module_assignments=module_assignments,
            imported_modules=imported_modules,
        )
    return modules


def _module_info_by_name(
    modules: dict[str, _ModuleInfo],
    module: str,
) -> tuple[str, _ModuleInfo] | None:
    """Resolve exact or uniquely suffix-qualified repository modules."""
    if module in modules:
        return module, modules[module]
    matches = [
        (name, info)
        for name, info in modules.items()
        if name.endswith(f".{module}") or module.endswith(f".{name}")
    ]
    return matches[0] if len(matches) == 1 else None


def _annotation_type_name(node: ast.AST | None) -> str | None:
    """Return one concrete source-visible type name from a Python annotation."""
    if node is None:
        return None
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        dotted = _dotted(node)
        return dotted.rsplit(".", 1)[-1] if dotted else node.attr
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value.rsplit(".", 1)[-1]
    if isinstance(node, ast.Subscript):
        value = _call_leaf(node.value) or ""
        if value in {"Annotated", "Optional", "Required", "NotRequired"}:
            target = node.slice
            if isinstance(target, (ast.Tuple, ast.List)) and target.elts:
                target = target.elts[0]
            return _annotation_type_name(target)
        return _annotation_type_name(node.slice)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        left = _annotation_type_name(node.left)
        right = _annotation_type_name(node.right)
        if left not in {None, "None", "NoneType"}:
            return left
        if right not in {None, "None", "NoneType"}:
            return right
    if isinstance(node, (ast.Tuple, ast.List)):
        for item in node.elts:
            value = _annotation_type_name(item)
            if value not in {None, "None", "NoneType"}:
                return value
    return None


def _resolve_class(
    modules: dict[str, _ModuleInfo],
    module: str,
    info: _ModuleInfo,
    class_name: str,
) -> tuple[str, _ModuleInfo, ast.ClassDef] | None:
    local = info.classes.get(class_name)
    if local is not None:
        return module, info, local

    imported = info.imports.get(class_name)
    if imported and imported[1]:
        target = _module_info_by_name(modules, imported[0])
        if target is not None:
            target_name, target_info = target
            cls = target_info.classes.get(imported[1])
            if cls is not None:
                return target_name, target_info, cls

    matches = [
        (name, candidate, cls)
        for name, candidate in modules.items()
        for cls_name, cls in candidate.classes.items()
        if cls_name == class_name
    ]
    return matches[0] if len(matches) == 1 else None


def _run_context_dependency(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[str, str] | None:
    for parameter in [
        *function.args.posonlyargs,
        *function.args.args,
        *function.args.kwonlyargs,
    ]:
        annotation = parameter.annotation
        if not isinstance(annotation, ast.Subscript):
            continue
        base = (_dotted(annotation.value) or _call_leaf(annotation.value) or "").rsplit(".", 1)[-1]
        if base != "RunContext":
            continue
        dependency_type = _annotation_type_name(annotation.slice)
        if dependency_type:
            return parameter.arg, dependency_type
    return None


def _class_field_type(
    cls: ast.ClassDef,
    field_name: str,
) -> str | None:
    for statement in cls.body:
        if (
            isinstance(statement, ast.AnnAssign)
            and isinstance(statement.target, ast.Name)
            and statement.target.id == field_name
        ):
            return _annotation_type_name(statement.annotation)

    init = next(
        (
            node
            for node in cls.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == "__init__"
        ),
        None,
    )
    if init is None:
        return None
    for statement in ast.walk(init):
        if isinstance(statement, ast.AnnAssign):
            target = statement.target
            if (
                isinstance(target, ast.Attribute)
                and isinstance(target.value, ast.Name)
                and target.value.id == "self"
                and target.attr == field_name
            ):
                value = _annotation_type_name(statement.annotation)
                if value:
                    return value
        if isinstance(statement, (ast.Assign, ast.AnnAssign)) and statement.value is not None:
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            if not any(
                isinstance(target, ast.Attribute)
                and isinstance(target.value, ast.Name)
                and target.value.id == "self"
                and target.attr == field_name
                for target in targets
            ):
                continue
            if isinstance(statement.value, ast.Call):
                value = _call_leaf(statement.value.func)
                if value:
                    return value
    return None


def _class_method_is_unambiguous(
    info: _ModuleInfo,
    cls: ast.ClassDef,
    method_name: str,
) -> bool:
    method = next(
        (
            node
            for node in cls.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == method_name
        ),
        None,
    )
    if method is None:
        return False
    matches = [
        node
        for node in ast.walk(info.tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == method_name
    ]
    return len(matches) == 1 and matches[0] is method and info.functions.get(method_name) is method


def _pydantic_dependency_method_target(
    modules: dict[str, _ModuleInfo],
    module: str,
    info: _ModuleInfo,
    call: ast.Call,
    *,
    function_name: str | None,
) -> tuple[str, str] | None:
    """Resolve ctx.deps.<field>.<method>() through source-visible RunContext types."""
    if not function_name:
        return None
    function = info.functions.get(function_name)
    if function is None:
        return None
    dependency = _run_context_dependency(function)
    if dependency is None:
        return None

    dotted = _dotted(call.func)
    if not dotted:
        return None
    parts = dotted.split(".")
    context_name, dependency_type = dependency
    if len(parts) != 4 or parts[0] != context_name or parts[1] != "deps":
        return None
    field_name, method_name = parts[2], parts[3]

    resolved_dependency = _resolve_class(
        modules,
        module,
        info,
        dependency_type,
    )
    if resolved_dependency is None:
        return None
    dependency_module, dependency_info, dependency_class = resolved_dependency
    field_type = _class_field_type(dependency_class, field_name)
    if not field_type:
        return None

    resolved_field = _resolve_class(
        modules,
        dependency_module,
        dependency_info,
        field_type,
    )
    if resolved_field is None:
        return None
    field_module, field_info, field_class = resolved_field
    if not _class_method_is_unambiguous(field_info, field_class, method_name):
        return None
    return field_module, method_name


def _call_target(
    modules: dict[str, _ModuleInfo],
    module: str,
    info: _ModuleInfo,
    call: ast.Call,
    *,
    function_name: str | None = None,
) -> tuple[str, str] | None:
    local_imports = (
        info.function_imports.get(function_name, {})
        if function_name is not None
        else {}
    )
    local_module_aliases = (
        info.function_module_aliases.get(function_name, {})
        if function_name is not None
        else {}
    )

    wrapped = executor_wrapped_callable(call)
    if isinstance(wrapped, ast.Name):
        if wrapped.id in info.functions:
            return module, wrapped.id
        if wrapped.id in local_imports:
            return local_imports[wrapped.id]
        if wrapped.id in info.imports:
            return info.imports[wrapped.id]

    if isinstance(call.func, ast.Name):
        name = call.func.id
        if name in info.functions:
            return module, name
        if name in local_imports:
            return local_imports[name]
        if name in info.imports:
            return info.imports[name]

    dotted = _dotted(call.func)
    if not dotted or "." not in dotted:
        return None
    root, _, rest = dotted.partition(".")
    imported_module = local_module_aliases.get(root) or info.module_aliases.get(root)
    if imported_module and rest and "." not in rest:
        return imported_module, rest

    dependency_target = _pydantic_dependency_method_target(
        modules,
        module,
        info,
        call,
        function_name=function_name,
    )
    if dependency_target is not None:
        return dependency_target
    return None


def _environment_key(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Subscript) and _dotted(node.value) == "os.environ":
        value = _literal(node.slice)
        return value if isinstance(value, str) else "environment"
    if isinstance(node, ast.Call):
        called = (_dotted(node.func) or "").lower()
        if called in {"os.getenv", "os.environ.get"}:
            value = _literal(node.args[0]) if node.args else None
            return value if isinstance(value, str) else "environment"
    return None


def _configuration_source_from_expr(
    node: ast.AST | None,
    sources: dict[str, str],
) -> str | None:
    if node is None:
        return None
    direct = _environment_key(node)
    if direct:
        return direct
    if isinstance(node, ast.Name):
        return sources.get(node.id)
    if isinstance(node, ast.Constant):
        return None
    if isinstance(node, ast.JoinedStr):
        origin_source: str | None = None
        first_dynamic = True
        for value in node.values:
            if isinstance(value, ast.Constant):
                continue
            expr = value.value if isinstance(value, ast.FormattedValue) else value
            source = _configuration_source_from_expr(expr, sources)
            if first_dynamic:
                first_dynamic = False
                if source is None:
                    return None
                origin_source = source
                continue
            if source is not None and source != origin_source:
                return None
        return origin_source
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        found: set[str] = set()
        for part in (node.left, node.right):
            if isinstance(part, ast.Constant):
                continue
            source = _configuration_source_from_expr(part, sources)
            if source is None:
                return None
            found.add(source)
        return next(iter(found)) if len(found) == 1 else None
    if isinstance(node, ast.Call):
        called = (_dotted(node.func) or _call_leaf(node.func) or "").lower()
        if called in {"urllib.request.request", "request"}:
            target = node.args[0] if node.args else next(
                (kw.value for kw in node.keywords if kw.arg == "url"),
                None,
            )
            return _configuration_source_from_expr(target, sources)
        if isinstance(node.func, ast.Attribute) and node.func.attr in {
            "rstrip",
            "lstrip",
            "strip",
        }:
            return _configuration_source_from_expr(node.func.value, sources)
    return None


def _fixed_url_from_module_expr(
    node: ast.AST | None,
    assignments: dict[str, ast.AST],
    seen: set[str] | None = None,
) -> str | None:
    """Resolve a fixed HTTP origin carried by module-level constants.

    This deliberately does not treat environment/configuration calls as fixed:
    those are handled by operator-configured provenance instead.
    """
    if node is None:
        return None
    seen = set() if seen is None else set(seen)

    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        if node.value.startswith(("http://", "https://")) and urlparse(node.value).hostname:
            return node.value
        return None

    if isinstance(node, ast.Name):
        if node.id in seen:
            return None
        assigned = assignments.get(node.id)
        if assigned is None:
            return None
        seen.add(node.id)
        return _fixed_url_from_module_expr(assigned, assignments, seen)

    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"rstrip", "lstrip", "strip"}
    ):
        return _fixed_url_from_module_expr(node.func.value, assignments, seen)

    if isinstance(node, ast.JoinedStr):
        for value in node.values:
            if not isinstance(value, ast.FormattedValue):
                continue
            resolved = _fixed_url_from_module_expr(value.value, assignments, seen)
            if resolved:
                parsed = urlparse(resolved)
                port = f":{parsed.port}" if parsed.port else ""
                return f"{parsed.scheme}://{parsed.hostname}{port}"
        prefix = "".join(
            value.value
            for value in node.values
            if isinstance(value, ast.Constant) and isinstance(value.value, str)
        )
        if prefix.startswith(("http://", "https://")):
            parsed = urlparse(prefix)
            if parsed.hostname:
                port = f":{parsed.port}" if parsed.port else ""
                return f"{parsed.scheme}://{parsed.hostname}{port}"
        return None

    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        for part in (node.left, node.right):
            resolved = _fixed_url_from_module_expr(part, assignments, seen)
            if not resolved:
                continue
            parsed = urlparse(resolved)
            port = f":{parsed.port}" if parsed.port else ""
            return f"{parsed.scheme}://{parsed.hostname}{port}"

    return None


def _operator_configured_destinations(
    info: _ModuleInfo,
    function_name: str,
) -> list[NetworkDestination]:
    function = info.functions.get(function_name)
    if function is None:
        return []

    sources: dict[str, str] = {}
    # Seed provenance from module-level configuration before following local
    # aliases/f-strings in the tool body.
    for _ in range(8):
        changed = False
        for name, expression in info.module_assignments.items():
            source = _configuration_source_from_expr(expression, sources)
            if source is not None and sources.get(name) != source:
                sources[name] = source
                changed = True
        if not changed:
            break

    assignments = [
        node
        for node in ast.walk(function)
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None
    ]
    for _ in range(8):
        changed = False
        for assignment in assignments:
            source = _configuration_source_from_expr(assignment.value, sources)
            if source is None:
                continue
            targets = assignment.targets if isinstance(assignment, ast.Assign) else [assignment.target]
            for target in targets:
                if isinstance(target, ast.Name) and sources.get(target.id) != source:
                    sources[target.id] = source
                    changed = True
        if not changed:
            break

    destinations: list[NetworkDestination] = []
    seen: set[str] = set()
    for call in (node for node in _function_scope_nodes(function) if isinstance(node, ast.Call)):
        called = (_dotted(call.func) or _call_leaf(call.func) or "").lower()
        if not (
            called.startswith(("requests.", "httpx.", "aiohttp."))
            or "urllib.request" in called
        ):
            continue
        leaf = (_call_leaf(call.func) or "").lower()
        target = (
            call.args[1]
            if leaf == "request" and len(call.args) > 1
            else call.args[0]
            if call.args
            else next(
                (kw.value for kw in call.keywords if kw.arg in {"url", "uri", "endpoint"}),
                None,
            )
        )
        source = _configuration_source_from_expr(target, sources)
        if source is None or source in seen:
            continue
        seen.add(source)
        destinations.append(
            NetworkDestination(
                target=f"<operator-configured:{source}>",
                restricted=True,
                location=_location(info.path, call),
                metadata={
                    "source": "operator_configuration",
                    "network_scope": "operator_configured_destination",
                    "configuration_source": source,
                    "destination_constraint_basis": "operator_configuration",
                    "repository_effect_summary": True,
                },
            )
        )
    return destinations


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

    expressions: list[ast.AST] = [target_expr]
    seen_names: set[str] = set()
    for _ in range(8):
        added = False
        for expression in list(expressions):
            if not isinstance(expression, ast.Name) or expression.id in seen_names:
                continue
            seen_names.add(expression.id)
            for assignment in ast.walk(function):
                if not isinstance(assignment, (ast.Assign, ast.AnnAssign)):
                    continue
                targets = (
                    assignment.targets
                    if isinstance(assignment, ast.Assign)
                    else [assignment.target]
                )
                if any(
                    isinstance(target, ast.Name)
                    and target.id == expression.id
                    for target in targets
                ) and assignment.value is not None:
                    expressions.append(assignment.value)
                    added = True
        if not added:
            break

    for expression in expressions:
        for part in ast.walk(expression):
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


def _path_like_names(
    info: _ModuleInfo,
    function_name: str,
) -> set[str]:
    """Resolve simple pathlib.Path aliases within one function."""
    function = info.functions.get(function_name)
    if function is None:
        return set()

    path_names = {
        parameter.arg
        for parameter in [
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
        ]
        if (
            (_dotted(parameter.annotation) or _call_leaf(parameter.annotation) or "")
            .rsplit(".", 1)[-1]
            == "Path"
        )
    }

    def expr_is_path_like(expr: ast.AST | None) -> bool:
        if expr is None:
            return False
        if isinstance(expr, ast.Name):
            return expr.id in path_names
        if isinstance(expr, ast.Call):
            called = _dotted(expr.func) or _call_leaf(expr.func) or ""
            if called.rsplit(".", 1)[-1] == "Path":
                return True
            if (
                isinstance(expr.func, ast.Attribute)
                and expr.func.attr in {"resolve", "absolute", "expanduser"}
            ):
                return expr_is_path_like(expr.func.value)
        if isinstance(expr, ast.Attribute):
            return expr.attr in {"parent", "parents"} and expr_is_path_like(expr.value)
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Div):
            return expr_is_path_like(expr.left)
        return False

    assignments = [
        node
        for node in ast.walk(function)
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and node.value is not None
    ]
    for _ in range(8):
        changed = False
        for assignment in assignments:
            if not expr_is_path_like(assignment.value):
                continue
            targets = (
                assignment.targets
                if isinstance(assignment, ast.Assign)
                else [assignment.target]
            )
            for target in targets:
                if isinstance(target, ast.Name) and target.id not in path_names:
                    path_names.add(target.id)
                    changed = True
        if not changed:
            break
    return path_names


def _temporary_handle_names(
    info: _ModuleInfo,
    function_name: str,
) -> set[str]:
    """Return local variables bound to source-created temporary resources."""
    function = info.functions.get(function_name)
    if function is None:
        return set()

    result: set[str] = set()
    for node in _function_scope_nodes(function):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        if not isinstance(value, ast.Call):
            continue
        called = (_dotted(value.func) or _call_leaf(value.func) or "").rsplit(".", 1)[-1]
        if called not in {"NamedTemporaryFile", "TemporaryFile", "TemporaryDirectory"}:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            if isinstance(target, ast.Name):
                result.add(target.id)
    return result


def _path_receiver_is_internal_temporary(
    info: _ModuleInfo,
    function_name: str,
    receiver: ast.AST | None,
) -> bool:
    """Identify pathlib receivers derived solely from a locally-created temp."""
    temporary_handles = _temporary_handle_names(info, function_name)
    if not temporary_handles:
        return False

    def from_temp_name(expr: ast.AST | None) -> bool:
        if isinstance(expr, ast.Attribute) and expr.attr in {"name", "path"}:
            return isinstance(expr.value, ast.Name) and expr.value.id in temporary_handles
        if isinstance(expr, ast.Call):
            called = (_dotted(expr.func) or _call_leaf(expr.func) or "").rsplit(".", 1)[-1]
            if called == "Path" and expr.args:
                return from_temp_name(expr.args[0])
        return False

    if from_temp_name(receiver):
        return True

    function = info.functions.get(function_name)
    if function is None or not isinstance(receiver, ast.Name):
        return False
    target_name = receiver.id
    for node in _function_scope_nodes(function):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if not any(
            isinstance(target, ast.Name) and target.id == target_name
            for target in targets
        ):
            continue
        if from_temp_name(node.value):
            return True
    return False


def _path_receiver_is_source_proven(
    info: _ModuleInfo,
    function_name: str,
    receiver: ast.AST | None,
) -> bool:
    path_names = _path_like_names(info, function_name)

    def check(expr: ast.AST | None) -> bool:
        if expr is None:
            return False
        if isinstance(expr, ast.Name):
            return expr.id in path_names
        if isinstance(expr, ast.Call):
            called = _dotted(expr.func) or _call_leaf(expr.func) or ""
            if called.rsplit(".", 1)[-1] == "Path":
                return True
            if (
                isinstance(expr.func, ast.Attribute)
                and expr.func.attr in {"resolve", "absolute", "expanduser"}
            ):
                return check(expr.func.value)
        if isinstance(expr, ast.Attribute):
            return expr.attr in {"parent", "parents"} and check(expr.value)
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Div):
            return check(expr.left)
        return False

    return check(receiver)


def _smtp_receiver_is_source_proven(
    info: _ModuleInfo,
    function_name: str,
    receiver: ast.AST | None,
) -> bool:
    if not isinstance(receiver, ast.Name):
        return False
    function = info.functions.get(function_name)
    if function is None:
        return False

    def is_smtp_constructor(expr: ast.AST | None) -> bool:
        if not isinstance(expr, ast.Call):
            return False
        called = (_dotted(expr.func) or _call_leaf(expr.func) or "").lower()
        if called in {"smtplib.smtp", "smtplib.smtp_ssl"}:
            return True
        leaf = (_call_leaf(expr.func) or "")
        imported = info.imports.get(leaf)
        return bool(
            imported
            and imported[0] == "smtplib"
            and imported[1] in {"SMTP", "SMTP_SSL"}
        )

    for node in ast.walk(function):
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(
                isinstance(target, ast.Name) and target.id == receiver.id
                for target in targets
            ) and is_smtp_constructor(node.value):
                return True
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if (
                    isinstance(item.optional_vars, ast.Name)
                    and item.optional_vars.id == receiver.id
                    and is_smtp_constructor(item.context_expr)
                ):
                    return True
    return False


def _literal_mcp_operation(call: ast.Call) -> str | None:
    """Return a source-visible MCP operation invoked through a tool-call sink.

    The wrapper function name is deliberately ignored.  Authority is derived
    only when the source contains a literal operation at the actual tool
    invocation boundary, e.g. call_tool_sync(name="create_branch", ...).
    """
    leaf = (_call_leaf(call.func) or "").lower()
    if leaf not in {
        "call_tool",
        "call_tool_sync",
        "invoke_tool",
        "invoke_tool_sync",
    }:
        return None

    node = next(
        (keyword.value for keyword in call.keywords if keyword.arg == "name"),
        None,
    )
    if node is None and leaf.startswith("invoke_tool") and call.args:
        node = call.args[0]
    value = _literal(node)
    return value if isinstance(value, str) and value.strip() else None


def _mcp_operation_capabilities(operation: str) -> set[str]:
    """Classify a literal MCP operation conservatively from its action verb."""
    normalized = operation.strip().lower().replace("-", "_")
    verb = normalized.split("_", 1)[0]
    if verb in {
        "delete",
        "remove",
        "drop",
        "purge",
        "destroy",
        "revoke",
        "terminate",
    }:
        return {"external.write", "destructive.write"}
    if verb in {
        "create",
        "update",
        "write",
        "edit",
        "put",
        "patch",
        "merge",
        "commit",
        "push",
        "add",
        "set",
        "enable",
        "disable",
        "apply",
        "submit",
        "send",
        "publish",
        "upload",
        "move",
        "rename",
    }:
        return {"external.write"}
    if verb in {
        "get",
        "list",
        "read",
        "search",
        "query",
        "fetch",
        "find",
        "inspect",
        "describe",
    }:
        return {"data.read"}
    return set()


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

    mcp_operation = _literal_mcp_operation(call)
    if mcp_operation is not None:
        mcp_capabilities = _mcp_operation_capabilities(mcp_operation)
        if mcp_capabilities:
            result.capabilities.update(mcp_capabilities)
            result.evidence.add(f"mcp-tool:{mcp_operation}")

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
            http_mutation_capabilities(
                call,
                function_name=function_name,
                context=info.functions.get(function_name),
            )
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
            module_fixed = _fixed_url_from_module_expr(
                target_expr,
                info.module_assignments,
            )
            if module_fixed is not None:
                result.destinations.append(
                    _fixed_destination(
                        info.path,
                        target_expr or call,
                        module_fixed,
                        "module_fixed_url",
                    )
                )
                result.evidence.add(f"fixed-destination:{module_fixed}")
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

    receiver = call.func.value if isinstance(call.func, ast.Attribute) else None
    if _path_receiver_is_source_proven(info, function_name, receiver):
        if leaf in {"write_text", "write_bytes", "touch", "mkdir", "chmod"}:
            result.capabilities.add("data.write")
            result.evidence.add(f"pathlib-write:{leaf}")
        elif leaf in {"unlink", "rmdir"}:
            result.capabilities.add("data.write")
            if _path_receiver_is_internal_temporary(
                info,
                function_name,
                receiver,
            ):
                result.evidence.add(f"pathlib-temp-cleanup:{leaf}")
            else:
                result.capabilities.add("destructive.write")
                result.evidence.add(f"pathlib-destructive:{leaf}")
        elif leaf in {
            "read_text",
            "read_bytes",
            "iterdir",
            "glob",
            "rglob",
            "stat",
            "exists",
        }:
            result.capabilities.add("data.read")
            result.evidence.add(f"pathlib-read:{leaf}")

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
    smtp_present = any(
        name == "smtplib" or name.startswith("smtplib.")
        for name in info.imported_modules
    )
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

    if (
        smtp_present
        and leaf in {"send_message", "sendmail"}
        and _smtp_receiver_is_source_proven(
            info,
            function_name,
            receiver,
        )
    ):
        result.capabilities.update({"external.write", "network.external"})
        result.evidence.add(f"smtp:{dotted}")
        result.destinations.append(
            NetworkDestination(
                target="<operator-configured:smtp>",
                restricted=True,
                location=_location(info.path, call),
                metadata={
                    "source": "standard_library_smtp",
                    "network_scope": "operator_configured_destination",
                    "provider": "smtp",
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

    for call in (node for node in _function_scope_nodes(function) if isinstance(node, ast.Call)):
        _merge_effect(
            result,
            _direct_effect(
                module,
                info,
                call,
                function_name=symbol,
            ),
        )
        target = _call_target(
            modules,
            module,
            info,
            call,
            function_name=symbol,
        )
        if target is None:
            continue
        target_module, target_symbol = target
        if target_module not in modules:
            continue
        target_effect = _summarize_function(
            modules,
            target_module,
            target_symbol,
            cache,
            next_stack,
        )
        _merge_effect(
            result,
            _transitive_effect_for_call(
                target_effect,
                target_symbol,
                call,
            ),
        )

    for destination in _operator_configured_destinations(info, symbol):
        if not any(
            existing.target == destination.target
            and existing.metadata.get("network_scope")
            == destination.metadata.get("network_scope")
            for existing in result.destinations
        ):
            result.destinations.append(destination)
            result.evidence.add(
                f"operator-configured-destination:{destination.metadata.get('configuration_source')}"
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

    for call in (node for node in _function_scope_nodes(function) if isinstance(node, ast.Call)):
        target = _call_target(
            modules,
            module,
            info,
            call,
            function_name=symbol,
        )
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
    for call in (node for node in _function_scope_nodes(function) if isinstance(node, ast.Call)):
        _merge_effect(
            result,
            _direct_effect(
                resolved[0],
                info,
                call,
                function_name=resolved[1],
            ),
        )
    for destination in _operator_configured_destinations(info, resolved[1]):
        if not any(
            existing.target == destination.target
            and existing.metadata.get("network_scope")
            == destination.metadata.get("network_scope")
            for existing in result.destinations
        ):
            result.destinations.append(destination)
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


def _effect_refines_tool_destination(
    tool: Tool,
    effect: _FunctionEffect,
) -> bool:
    """Return True when repository semantics adds stricter destination provenance.

    Local framework adapters often recover the network effect before repository
    analysis runs, but can only represent its destination as dynamic.  A
    source-visible fixed or operator-configured origin is therefore a material
    refinement even when the function has no cross-module/transitive effect
    delta.
    """
    existing = {
        (
            item.target,
            item.restricted,
            str(item.metadata.get("network_scope") or ""),
        )
        for item in tool.destinations
    }
    for destination in effect.destinations:
        if destination.restricted is not True:
            continue
        key = (
            destination.target,
            destination.restricted,
            str(destination.metadata.get("network_scope") or ""),
        )
        if key not in existing:
            return True
    return False


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
            merge_capabilities = True
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
                transitive_delta = _effect_has_transitive_delta(
                    effect,
                    direct_effect,
                )
                destination_refinement = _effect_refines_tool_destination(
                    tool,
                    effect,
                )
                source_grounded_repository_sink = any(
                    evidence.startswith("mcp-tool:")
                    for evidence in direct_effect.evidence
                )
                if (
                    not transitive_delta
                    and not destination_refinement
                    and not source_grounded_repository_sink
                ):
                    continue
                # A same-module destination-only refinement must not re-promote
                # direct effects into privileged capabilities. Literal MCP tool
                # invocations are an exception: the repository layer has the
                # source-visible operation that framework-local adapters do not.
                merge_capabilities = (
                    transitive_delta or source_grounded_repository_sink
                )

            before = set(tool.capabilities)
            if merge_capabilities:
                tool.capabilities.update(effect.capabilities)
            if any(
                destination.restricted is True
                and destination.metadata.get("network_scope")
                in {
                    "operator_configured_destination",
                    "fixed_provider_network",
                    "fixed_literal_destination",
                }
                for destination in effect.destinations
            ):
                tool.destinations = [
                    destination
                    for destination in tool.destinations
                    if not (
                        destination.target in {"<dynamic-url>", "<model-selected-url>"}
                        and destination.restricted is False
                    )
                ]
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
