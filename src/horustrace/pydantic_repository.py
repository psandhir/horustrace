"""Repository-level Pydantic AI authority composition.

This pass resolves only source-provable cross-file bindings that the file-level
adapter deliberately leaves dynamic: repository-local FunctionToolset subclasses
and imported Pydantic Agent.run delegation.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from horustrace.heuristics import infer_capabilities
from horustrace.models import Graph, NetworkDestination, SourceLocation, Tool

_AGENT_RUN_METHODS = {
    "run",
    "run_sync",
    "run_stream",
    "run_stream_sync",
    "run_stream_events",
    "iter",
}


@dataclass(slots=True)
class _ModuleInfo:
    name: str
    path: Path
    tree: ast.AST
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef]
    imports: dict[str, tuple[str, str]]
    imported_modules: set[str]
    toolset_classes: dict[str, ast.ClassDef]


def _call_name(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Subscript):
        return _call_name(node.value)
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

    parts = current_module.split(".") if current_module else []
    if current_path.stem != "__init__" and parts:
        parts = parts[:-1]
    parents = max(node.level - 1, 0)
    if parents:
        parts = parts[:-parents] if parents <= len(parts) else []
    if node.module:
        parts.extend(node.module.split("."))
    return ".".join(part for part in parts if part)


def _build_modules(root: Path, python_paths: list[Path]) -> dict[str, _ModuleInfo]:
    modules: dict[str, _ModuleInfo] = {}
    for path in python_paths:
        module = _module_name_for_path(path, root)
        if not module:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue

        imports: dict[str, tuple[str, str]] = {}
        imported_modules: set[str] = set()
        for node in getattr(tree, "body", []):
            if isinstance(node, ast.ImportFrom):
                source = _resolve_import_module(module, path, node)
                if source:
                    imported_modules.add(source)
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    imports[alias.asname or alias.name] = (source, alias.name)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".")[0]
                    imports[local] = (alias.name, "")
                    imported_modules.add(alias.name)

        functions = {
            node.name: node
            for node in getattr(tree, "body", [])
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        toolset_classes: dict[str, ast.ClassDef] = {}
        for node in getattr(tree, "body", []):
            if not isinstance(node, ast.ClassDef):
                continue
            if any((_call_name(base) or "") == "FunctionToolset" for base in node.bases):
                toolset_classes[node.name] = node

        modules[module] = _ModuleInfo(
            name=module,
            path=path.resolve(),
            tree=tree,
            functions=functions,
            imports=imports,
            imported_modules=imported_modules,
            toolset_classes=toolset_classes,
        )
    return modules


def _module_by_path(modules: dict[str, _ModuleInfo]) -> dict[Path, _ModuleInfo]:
    return {info.path: info for info in modules.values()}


def _local_module(
    modules: dict[str, _ModuleInfo],
    requested: str,
) -> _ModuleInfo | None:
    """Resolve a repository module when the scan root truncates package prefixes.

    Exact matches win. A suffix match is accepted only when it identifies one
    scanned module uniquely, so narrowed scan roots never guess between
    ambiguous local packages.
    """
    direct = modules.get(requested)
    if direct is not None:
        return direct
    if not requested:
        return None
    matches = [
        info
        for name, info in modules.items()
        if name and requested.endswith(f".{name}")
    ]
    return matches[0] if len(matches) == 1 else None


def _names_from_sequence(node: ast.AST | None) -> list[str]:
    if not isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return []
    result: list[str] = []
    for element in node.elts:
        name = _call_name(element)
        if name:
            result.append(name)
    return result


def _toolset_members(cls: ast.ClassDef) -> list[tuple[str, bool]]:
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
        return []

    collections: dict[str, list[tuple[str, bool]]] = {}

    def collect(statement: ast.AST, *, conditional: bool) -> None:
        if isinstance(statement, (ast.Assign, ast.AnnAssign)) and statement.value is not None:
            names = _names_from_sequence(statement.value)
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            for target in targets:
                if isinstance(target, ast.Name) and names:
                    collections[target.id] = [(name, conditional) for name in names]

        for call in (node for node in ast.walk(statement) if isinstance(node, ast.Call)):
            if not isinstance(call.func, ast.Attribute) or call.func.attr != "append":
                continue
            if not isinstance(call.func.value, ast.Name) or len(call.args) != 1:
                continue
            name = _call_name(call.args[0])
            if name:
                collections.setdefault(call.func.value.id, []).append((name, conditional))

    for statement in init.body:
        if isinstance(statement, ast.If):
            for child in statement.body:
                collect(child, conditional=True)
            for child in statement.orelse:
                collect(child, conditional=True)
        else:
            collect(statement, conditional=False)

    selected: list[tuple[str, bool]] = []
    for call in (node for node in ast.walk(init) if isinstance(node, ast.Call)):
        dotted = _dotted(call.func) or ""
        is_super_init = (
            isinstance(call.func, ast.Attribute)
            and call.func.attr == "__init__"
            and isinstance(call.func.value, ast.Call)
            and _call_name(call.func.value.func) == "super"
        )
        is_function_toolset_init = dotted.endswith("FunctionToolset.__init__")
        if not (is_super_init or is_function_toolset_init):
            continue
        tools_expr = call.args[0] if call.args else next(
            (item.value for item in call.keywords if item.arg == "tools"),
            None,
        )
        if isinstance(tools_expr, ast.Name):
            selected.extend(collections.get(tools_expr.id, []))
        else:
            selected.extend((name, False) for name in _names_from_sequence(tools_expr))

    deduped: list[tuple[str, bool]] = []
    seen: set[str] = set()
    for name, conditional in selected:
        if name in seen:
            continue
        seen.add(name)
        deduped.append((name, conditional))
    return deduped


def _call_target(
    modules: dict[str, _ModuleInfo],
    module: str,
    call: ast.Call,
) -> tuple[str, str] | None:
    info = modules.get(module)
    if info is None:
        return None
    if isinstance(call.func, ast.Name):
        name = call.func.id
        if name in info.functions:
            return module, name
        imported = info.imports.get(name)
        if imported and imported[1]:
            target = _local_module(modules, imported[0])
            return (target.name, imported[1]) if target is not None else imported
        return None
    if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
        imported = info.imports.get(call.func.value.id)
        if imported and not imported[1]:
            target = _local_module(modules, imported[0])
            return (
                (target.name, call.func.attr)
                if target is not None
                else (imported[0], call.func.attr)
            )
    return None


def _remote_sandbox_boundary(
    modules: dict[str, _ModuleInfo],
    module: str,
    symbol: str,
    seen: set[tuple[str, str]] | None = None,
) -> str | None:
    key = (module, symbol)
    seen = set() if seen is None else set(seen)
    if key in seen:
        return None
    seen.add(key)
    info = modules.get(module)
    function = info.functions.get(symbol) if info is not None else None
    if info is None or function is None:
        return None

    daytona_imported = any(
        name == "daytona" or name.startswith("daytona.")
        for name in info.imported_modules
    )
    if daytona_imported:
        leaves = {
            (_call_name(call.func) or "").lower()
            for call in ast.walk(function)
            if isinstance(call, ast.Call)
        }
        if leaves & {"create", "code_run", "exec", "run_python", "run_shell"}:
            return "daytona"

    for call in (node for node in ast.walk(function) if isinstance(node, ast.Call)):
        target = _call_target(modules, module, call)
        if target is None:
            continue
        provider = _remote_sandbox_boundary(
            modules,
            target[0],
            target[1],
            seen,
        )
        if provider:
            return provider
    return None


def _merge_tool(tools: list[Tool], incoming: Tool) -> None:
    for existing in tools:
        if (
            existing.name == incoming.name
            and existing.location is not None
            and incoming.location is not None
            and existing.location.path.resolve() == incoming.location.path.resolve()
        ):
            existing.capabilities.update(incoming.capabilities)
            existing.metadata.update(incoming.metadata)
            for destination in incoming.destinations:
                if destination not in existing.destinations:
                    existing.destinations.append(destination)
            return
    tools.append(incoming)


def _resolve_toolset_class(
    modules: dict[str, _ModuleInfo],
    owner: _ModuleInfo,
    candidate: str,
) -> tuple[_ModuleInfo, ast.ClassDef] | None:
    imported = owner.imports.get(candidate)
    if imported and imported[1]:
        target = _local_module(modules, imported[0])
        if target is not None:
            cls = target.toolset_classes.get(imported[1])
            if cls is not None:
                return target, cls
    cls = owner.toolset_classes.get(candidate)
    if cls is not None:
        return owner, cls
    matches = [
        (info, value)
        for info in modules.values()
        for name, value in info.toolset_classes.items()
        if name == candidate
    ]
    return matches[0] if len(matches) == 1 else None


def _resolve_member(
    modules: dict[str, _ModuleInfo],
    owner: _ModuleInfo,
    member: str,
) -> tuple[_ModuleInfo, ast.FunctionDef | ast.AsyncFunctionDef] | None:
    function = owner.functions.get(member)
    if function is not None:
        return owner, function
    imported = owner.imports.get(member)
    if imported and imported[1]:
        target = _local_module(modules, imported[0])
        function = target.functions.get(imported[1]) if target is not None else None
        if target is not None and function is not None:
            return target, function
    return None


def _resolve_custom_toolsets(
    graph: Graph,
    modules: dict[str, _ModuleInfo],
) -> None:
    by_path = _module_by_path(modules)
    for agent in graph.agents:
        if agent.metadata.get("framework") != "pydantic-ai" or agent.location is None:
            continue
        owner = by_path.get(agent.location.path.resolve())
        if owner is None:
            continue
        replacements: list[tuple[Tool, list[Tool]]] = []
        for placeholder in agent.tools:
            candidate = placeholder.metadata.get("toolset_class_candidate")
            if not isinstance(candidate, str):
                continue
            resolved = _resolve_toolset_class(modules, owner, candidate)
            if resolved is None:
                continue
            class_module, cls = resolved
            members = _toolset_members(cls)
            if not members:
                continue
            tools: list[Tool] = []
            for member, conditional in members:
                target = _resolve_member(modules, class_module, member)
                if target is None:
                    continue
                source_module, function = target
                capabilities = set(infer_capabilities(member))
                provider = _remote_sandbox_boundary(
                    modules,
                    source_module.name,
                    function.name,
                )
                destinations: list[NetworkDestination] = []
                metadata = {
                    "framework": "pydantic-ai",
                    "binding_origin": "repository_function_toolset_subclass",
                    "toolset_class": candidate,
                    "repository_resolved": True,
                    "availability_condition_unresolved": conditional,
                }
                if provider:
                    capabilities.update({"process.execute", "network.external"})
                    metadata.update(
                        {
                            "execution_boundary": "remote-sandbox",
                            "sandbox_provider": provider,
                            "sandboxed": True,
                        }
                    )
                    destinations.append(
                        NetworkDestination(
                            target=f"<provider:{provider}>",
                            restricted=True,
                            location=SourceLocation(source_module.path, function.lineno),
                            metadata={
                                "source": "remote_sandbox_sdk",
                                "network_scope": "fixed_provider_network",
                                "provider": provider,
                            },
                        )
                    )
                tools.append(
                    Tool(
                        name=member,
                        kind="function",
                        capabilities=capabilities,
                        destinations=destinations,
                        location=SourceLocation(
                            source_module.path,
                            function.lineno,
                            function.col_offset + 1,
                        ),
                        metadata=metadata,
                    )
                )
            if tools:
                replacements.append((placeholder, tools))

        for placeholder, tools in replacements:
            if placeholder in agent.tools:
                agent.tools.remove(placeholder)
            for tool in tools:
                _merge_tool(agent.tools, tool)
            agent.metadata["repository_function_toolsets_resolved"] = True


def _resolve_imported_delegation(
    graph: Graph,
    modules: dict[str, _ModuleInfo],
) -> None:
    by_path = _module_by_path(modules)
    agents_by_source: dict[tuple[Path, str], list] = {}
    for child in graph.agents:
        if child.metadata.get("framework") != "pydantic-ai" or child.location is None:
            continue
        agents_by_source.setdefault(
            (child.location.path.resolve(), child.name),
            [],
        ).append(child)

    for parent in graph.agents:
        if parent.metadata.get("framework") != "pydantic-ai":
            continue
        for tool in parent.tools:
            if tool.location is None:
                continue
            info = by_path.get(tool.location.path.resolve())
            function = info.functions.get(tool.name) if info is not None else None
            if info is None or function is None:
                continue
            targets: list[str] = []
            for call in (node for node in ast.walk(function) if isinstance(node, ast.Call)):
                if not isinstance(call.func, ast.Attribute):
                    continue
                if call.func.attr not in _AGENT_RUN_METHODS:
                    continue
                if not isinstance(call.func.value, ast.Name):
                    continue
                imported = info.imports.get(call.func.value.id)
                if not imported or not imported[1]:
                    continue
                child_module = _local_module(modules, imported[0])
                if child_module is None:
                    continue
                matches = agents_by_source.get(
                    (child_module.path, imported[1]),
                    [],
                )
                if len(matches) == 1:
                    targets.append(matches[0].name)
            if not targets:
                continue
            resolved = sorted(set(targets))
            tool.capabilities.add("agent.delegate")
            tool.metadata["delegate_target"] = resolved[0]
            tool.metadata["delegate_targets"] = resolved
            tool.metadata["delegation_basis"] = "repository_imported_pydantic_agent_run"
            tool.metadata["authority_binding_basis"] = (
                "repository_imported_pydantic_agent_run"
            )


def enrich_pydantic_repository_graph(
    graph: Graph,
    root: Path,
    *,
    python_paths: list[Path],
) -> None:
    modules = _build_modules(root, python_paths)
    if not modules:
        return
    _resolve_custom_toolsets(graph, modules)
    _resolve_imported_delegation(graph, modules)
