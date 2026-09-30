"""Repository-level model-tool object authorization semantics.

This pass resolves LangChain BaseTool instances hidden behind repository-local
tool factories and binds them to LangGraph agents when source proves a
ChatOpenAI.bind_tools(...) relationship. It also identifies a narrow class of
authorization mismatch: a model-callable tool accepts an object identifier,
loads an owner-scoped model, commits a mutation, and omits the owner check that
the repository's normal web/API path applies to the same model.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from horustrace.models import (
    Agent,
    Graph,
    InputSource,
    ResourceScope,
    SourceLocation,
    Tool,
)


_ROUTE_METHODS = {"get", "post", "put", "patch", "delete", "api_route"}
_RUNTIME_METHODS = {
    "get_response",
    "get_stream_response",
    "invoke",
    "ainvoke",
    "stream",
    "astream",
}
_OWNER_FIELDS = {"owner_id", "user_id", "tenant_id", "organization_id"}


@dataclass(frozen=True)
class ModuleInfo:
    module: str
    path: Path
    tree: ast.Module
    imports: dict[str, tuple[str, str]]


@dataclass(frozen=True)
class ToolDef:
    module: str
    alias: str
    runtime_name: str
    class_name: str
    path: Path
    class_node: ast.ClassDef
    method: ast.FunctionDef | ast.AsyncFunctionDef


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


def _literal_string(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
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


def _class_runtime_name(class_node: ast.ClassDef) -> str:
    for child in class_node.body:
        if not isinstance(child, (ast.Assign, ast.AnnAssign)):
            continue
        value = child.value
        targets = child.targets if isinstance(child, ast.Assign) else [child.target]
        if any(isinstance(target, ast.Name) and target.id == "name" for target in targets):
            value_literal = _literal_string(value)
            if value_literal:
                return value_literal
    return class_node.name


def _base_tool_classes(info: ModuleInfo) -> set[str]:
    names: set[str] = set()
    for local, (module, symbol) in info.imports.items():
        if symbol == "BaseTool" and module in {
            "langchain_core.tools",
            "langchain_core.tools.base",
            "langchain.tools",
        }:
            names.add(local)
    return names


def _module_assignments(tree: ast.Module) -> dict[str, ast.AST]:
    result: dict[str, ast.AST] = {}
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            if isinstance(target, ast.Name):
                result[target.id] = node.value
    return result


def _tool_defs(modules: dict[str, ModuleInfo]) -> dict[tuple[str, str], ToolDef]:
    result: dict[tuple[str, str], ToolDef] = {}
    classes: dict[tuple[str, str], ast.ClassDef] = {}
    assignments: dict[str, dict[str, ast.AST]] = {}

    for module, info in modules.items():
        base_names = _base_tool_classes(info)
        assignments[module] = _module_assignments(info.tree)
        for node in info.tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            if not any((_leaf(base) or "") in base_names for base in node.bases):
                continue
            classes[(module, node.name)] = node

    for module, info in modules.items():
        for alias, value in assignments[module].items():
            if not isinstance(value, ast.Call):
                continue
            called = _leaf(value.func)
            if not called:
                continue
            target_module = module
            target_class = called
            imported = info.imports.get(called)
            if imported is not None:
                target_module, target_class = imported
            class_node = classes.get((target_module, target_class))
            target_info = modules.get(target_module)
            if class_node is None or target_info is None:
                continue
            methods = [
                child
                for child in class_node.body
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                and child.name in {"_run", "_arun"}
            ]
            if not methods:
                continue
            method = next((item for item in methods if item.name == "_run"), methods[0])
            result[(module, alias)] = ToolDef(
                module=module,
                alias=alias,
                runtime_name=_class_runtime_name(class_node),
                class_name=class_node.name,
                path=target_info.path,
                class_node=class_node,
                method=method,
            )
    return result


def _function_table(modules: dict[str, ModuleInfo]) -> dict[tuple[str, str], ast.FunctionDef | ast.AsyncFunctionDef]:
    result: dict[tuple[str, str], ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for module, info in modules.items():
        for node in info.tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                result[(module, node.name)] = node
    return result


def _resolve_symbol(
    modules: dict[str, ModuleInfo],
    module: str,
    symbol: str,
) -> tuple[str, str]:
    info = modules.get(module)
    if info is None:
        return module, symbol
    imported = info.imports.get(symbol)
    if imported is not None:
        return imported
    return module, symbol


def _assigned_value(scope: ast.AST, name: str, before_line: int | None = None) -> ast.AST | None:
    candidates: list[tuple[int, ast.AST]] = []
    for node in ast.walk(scope):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        line = getattr(node, "lineno", 0) or 0
        if before_line is not None and line >= before_line:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if any(isinstance(target, ast.Name) and target.id == name for target in targets):
            candidates.append((line, node.value))
    if not candidates:
        return None
    return max(candidates, key=lambda item: item[0])[1]


def _factory_symbols(
    modules: dict[str, ModuleInfo],
    functions: dict[tuple[str, str], ast.FunctionDef | ast.AsyncFunctionDef],
    module: str,
    call: ast.Call,
) -> list[tuple[str, str]]:
    called = _leaf(call.func)
    if not called:
        return []
    target_module, target_name = _resolve_symbol(modules, module, called)
    function = functions.get((target_module, target_name))
    if function is None:
        return []

    local_lists: dict[str, list[ast.AST]] = {}
    for node in ast.walk(function):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        names = [target.id for target in targets if isinstance(target, ast.Name)]
        if not names or not isinstance(node.value, (ast.List, ast.Tuple, ast.Set)):
            continue
        for name in names:
            local_lists[name] = list(node.value.elts)

    elements: list[ast.AST] = []
    for node in ast.walk(function):
        if not isinstance(node, ast.Return):
            continue
        if isinstance(node.value, (ast.List, ast.Tuple, ast.Set)):
            elements.extend(node.value.elts)
        elif isinstance(node.value, ast.Name):
            elements.extend(local_lists.get(node.value.id, []))

    result: list[tuple[str, str]] = []
    target_info = modules.get(target_module)
    if target_info is None:
        return result
    for element in elements:
        if not isinstance(element, ast.Name):
            continue
        result.append(_resolve_symbol(modules, target_module, element.id))
    return result


def _bound_tool_defs_for_class(
    modules: dict[str, ModuleInfo],
    functions: dict[tuple[str, str], ast.FunctionDef | ast.AsyncFunctionDef],
    tool_defs: dict[tuple[str, str], ToolDef],
    module: str,
    class_node: ast.ClassDef,
) -> list[ToolDef]:
    result: list[ToolDef] = []
    for call in (node for node in ast.walk(class_node) if isinstance(node, ast.Call)):
        if not isinstance(call.func, ast.Attribute) or call.func.attr != "bind_tools":
            continue
        tools_expr = call.args[0] if call.args else next(
            (item.value for item in call.keywords if item.arg == "tools"),
            None,
        )
        if tools_expr is None:
            continue

        symbols: list[tuple[str, str]] = []
        if isinstance(tools_expr, (ast.List, ast.Tuple, ast.Set)):
            for element in tools_expr.elts:
                if isinstance(element, ast.Name):
                    symbols.append(_resolve_symbol(modules, module, element.id))
        elif isinstance(tools_expr, ast.Call):
            symbols.extend(_factory_symbols(modules, functions, module, tools_expr))
        elif isinstance(tools_expr, ast.Name):
            value = _assigned_value(class_node, tools_expr.id, getattr(call, "lineno", None))
            if isinstance(value, ast.Call):
                symbols.extend(_factory_symbols(modules, functions, module, value))
            elif isinstance(value, (ast.List, ast.Tuple, ast.Set)):
                for element in value.elts:
                    if isinstance(element, ast.Name):
                        symbols.append(_resolve_symbol(modules, module, element.id))

        for key in symbols:
            tool = tool_defs.get(key)
            if tool is not None and tool not in result:
                result.append(tool)
    return result


def _parameters(function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    return {
        arg.arg
        for arg in (
            list(function.args.posonlyargs)
            + list(function.args.args)
            + list(function.args.kwonlyargs)
        )
        if arg.arg not in {"self", "cls", "run_manager"}
    }


def _model_owner_fields(modules: dict[str, ModuleInfo]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for info in modules.values():
        for node in ast.walk(info.tree):
            if not isinstance(node, ast.ClassDef):
                continue
            fields: set[str] = set()
            for child in node.body:
                if isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name):
                    if child.target.id in _OWNER_FIELDS:
                        fields.add(child.target.id)
                elif isinstance(child, ast.Assign):
                    for target in child.targets:
                        if isinstance(target, ast.Name) and target.id in _OWNER_FIELDS:
                            fields.add(target.id)
            if fields:
                result.setdefault(node.name, set()).update(fields)
    return result


def _loaded_object(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[str, str, str] | None:
    params = _parameters(function)
    for node in ast.walk(function):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        if not isinstance(node.value, ast.Call):
            continue
        call = node.value
        if (_leaf(call.func) or "") != "get" or len(call.args) < 2:
            continue
        model = _leaf(call.args[0])
        identifier = call.args[1]
        if not model or not isinstance(identifier, ast.Name) or identifier.id not in params:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        obj = next((target.id for target in targets if isinstance(target, ast.Name)), None)
        if obj:
            return obj, model, identifier.id
    return None


def _committed_mutation(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    object_name: str,
) -> bool:
    mutated = any(
        isinstance(node, (ast.Assign, ast.AnnAssign))
        and any(
            isinstance(target, ast.Attribute)
            and isinstance(target.value, ast.Name)
            and target.value.id == object_name
            for target in (node.targets if isinstance(node, ast.Assign) else [node.target])
        )
        for node in ast.walk(function)
    )
    committed = any(
        isinstance(node, ast.Call) and (_leaf(node.func) or "") == "commit"
        for node in ast.walk(function)
    )
    return mutated and committed


def _has_owner_check(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    object_name: str,
    owner_field: str,
) -> bool:
    for node in ast.walk(function):
        if not isinstance(node, ast.Compare):
            continue
        for child in ast.walk(node):
            if (
                isinstance(child, ast.Attribute)
                and child.attr == owner_field
                and isinstance(child.value, ast.Name)
                and child.value.id == object_name
            ):
                return True
    return False


def _repository_owner_checks(
    modules: dict[str, ModuleInfo],
    owner_models: dict[str, set[str]],
) -> set[tuple[str, str]]:
    result: set[tuple[str, str]] = set()
    for info in modules.values():
        for function in (
            node
            for node in ast.walk(info.tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ):
            loaded = _loaded_object(function)
            if loaded is None:
                continue
            object_name, model, _ = loaded
            for field in owner_models.get(model, set()):
                if _has_owner_check(function, object_name, field):
                    result.add((model, field))
    return result


def _tool_capabilities(tool_def: ToolDef) -> set[str]:
    capabilities: set[str] = set()
    loaded = _loaded_object(tool_def.method)
    if loaded is not None:
        capabilities.add("data.read")
        if _committed_mutation(tool_def.method, loaded[0]):
            capabilities.add("data.write")
    for node in ast.walk(tool_def.method):
        if not isinstance(node, ast.Call):
            continue
        called = (_dotted(node.func) or _leaf(node.func) or "").lower()
        if called.startswith("subprocess.") or called in {
            "os.system",
            "os.popen",
            "exec",
            "eval",
            "compile",
        }:
            capabilities.add("process.execute")
    return capabilities


def _authorization_metadata(
    tool_def: ToolDef,
    owner_models: dict[str, set[str]],
    owner_checks: set[tuple[str, str]],
) -> dict[str, object]:
    loaded = _loaded_object(tool_def.method)
    if loaded is None:
        return {}
    object_name, model, identifier = loaded
    if not _committed_mutation(tool_def.method, object_name):
        return {}
    for field in sorted(owner_models.get(model, set())):
        if (model, field) not in owner_checks:
            continue
        if _has_owner_check(tool_def.method, object_name, field):
            continue
        return {
            "object_authorization_boundary_bypass": True,
            "object_model": model,
            "object_id_parameter": identifier,
            "ownership_field": field,
            "repository_owner_check_detected": True,
            "source_tool_class": tool_def.class_name,
            "source_tool_method": tool_def.method.name,
        }
    return {}


def _enclosing_class(tree: ast.Module, line: int) -> ast.ClassDef | None:
    candidates = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef)
        and (getattr(node, "lineno", 0) or 0)
        <= line
        <= (getattr(node, "end_lineno", 0) or 0)
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda node: getattr(node, "lineno", 0) or 0)


def _route_kind(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for decorator in function.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if (_leaf(target) or "").lower() in _ROUTE_METHODS:
            return True
    return False


def _route_invokes_wrapper(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    wrapper_class: str,
) -> bool:
    instances: set[str] = set()
    for node in ast.walk(function):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        if not isinstance(node.value, ast.Call) or (_leaf(node.value.func) or "") != wrapper_class:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        instances.update(target.id for target in targets if isinstance(target, ast.Name))
    if not instances:
        return False
    return any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in _RUNTIME_METHODS
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id in instances
        for node in ast.walk(function)
    )


def _attach_runtime_ingress(
    agent: Agent,
    modules: dict[str, ModuleInfo],
    wrapper_class: str,
) -> None:
    for info in modules.values():
        for function in (
            node
            for node in ast.walk(info.tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and _route_kind(node)
        ):
            if not _route_invokes_wrapper(function, wrapper_class):
                continue
            basis = "source_bound_object_authorization_route"
            if any(item.metadata.get("basis") == basis for item in agent.inputs):
                return
            authenticated = any(
                arg.arg in {"current_user", "user", "principal"}
                for arg in list(function.args.args) + list(function.args.kwonlyargs)
            )
            agent.inputs.append(
                InputSource(
                    name=f"{info.path.stem}:{function.name}",
                    trust="untrusted",
                    kind="web",
                    location=_location(info.path, function),
                    metadata={
                        "basis": basis,
                        "runtime_invocation_proven": True,
                        "handler": function.name,
                        "authenticated": authenticated,
                    },
                )
            )
            return


def enrich_model_tool_object_authorization(
    graph: Graph,
    root: Path,
    python_paths: list[Path],
) -> None:
    """Bind repository-local BaseTools and mark owner-scope bypasses."""
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

    functions = _function_table(modules)
    tool_defs = _tool_defs(modules)
    if not tool_defs:
        return
    owner_models = _model_owner_fields(modules)
    owner_checks = _repository_owner_checks(modules, owner_models)

    for agent in graph.agents:
        if agent.metadata.get("framework") != "langgraph" or agent.location is None:
            continue
        info = by_path.get(agent.location.path.resolve())
        if info is None:
            continue
        owner_class = _enclosing_class(info.tree, agent.location.line)
        if owner_class is None:
            continue

        bound = _bound_tool_defs_for_class(
            modules,
            functions,
            tool_defs,
            info.module,
            owner_class,
        )
        if not bound:
            continue

        existing = {tool.name for tool in agent.tools}
        for tool_def in bound:
            auth_metadata = _authorization_metadata(
                tool_def,
                owner_models,
                owner_checks,
            )
            metadata = {
                "framework": "langchain",
                "authority_binding": "direct",
                "authority_binding_basis": "langchain_bind_tools_factory",
                "repository_resolved": True,
                "source_alias": tool_def.alias,
                "source_path": tool_def.path.as_posix(),
                "source_tool_class": tool_def.class_name,
                "source_tool_method": tool_def.method.name,
                **auth_metadata,
            }
            capabilities = _tool_capabilities(tool_def)
            tool = Tool(
                name=tool_def.runtime_name,
                kind="langchain_tool",
                capabilities=capabilities,
                location=_location(tool_def.path, tool_def.class_node),
                metadata=metadata,
            )
            if auth_metadata:
                tool.resources.append(
                    ResourceScope(
                        kind="database_record",
                        selector=(
                            f"{auth_metadata['object_model']}:"
                            f"<{auth_metadata['object_id_parameter']}>"
                        ),
                        access={"data.write"},
                        classification="internal",
                        location=tool.location,
                        metadata={
                            "authorization_scope": "owner_check_missing",
                            "ownership_field": auth_metadata["ownership_field"],
                        },
                    )
                )
            if tool.name in existing:
                current = next(item for item in agent.tools if item.name == tool.name)
                current.capabilities.update(tool.capabilities)
                current.metadata.update(tool.metadata)
                current.resources.extend(
                    resource
                    for resource in tool.resources
                    if resource not in current.resources
                )
            else:
                agent.tools.append(tool)
                existing.add(tool.name)

        if any(
            tool.metadata.get("object_authorization_boundary_bypass") is True
            for tool in agent.tools
        ):
            _attach_runtime_ingress(agent, modules, owner_class.name)
