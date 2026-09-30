"""Repository-level RAG filesystem semantics for Pydantic AI wrappers."""
from __future__ import annotations

import ast
from pathlib import Path

from horustrace.models import Agent, Graph, InputSource, ResourceScope, SourceLocation


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


def _leaf(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
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


def _expr_uses(node: ast.AST | None, names: set[str]) -> bool:
    if node is None or not names:
        return False
    return any(
        isinstance(child, ast.Name) and child.id in names
        for child in ast.walk(node)
    )


def _target_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    dotted = _dotted(node)
    return {dotted} if dotted else set()


def _params(function: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    return [
        arg.arg
        for arg in [
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
        ]
    ]


def _containment_detected(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    tainted: set[str],
) -> bool:
    containment_methods = {"relative_to", "is_relative_to"}
    for child in ast.walk(function):
        if not isinstance(child, ast.Call):
            continue
        leaf = _leaf(child.func) or ""
        if leaf in containment_methods and (
            _expr_uses(
                child.func.value if isinstance(child.func, ast.Attribute) else None,
                tainted,
            )
            or any(_expr_uses(arg, tainted) for arg in child.args)
        ):
            return True
        called = (_dotted(child.func) or "").lower()
        if called in {"os.path.commonpath", "posixpath.commonpath", "ntpath.commonpath"}:
            if any(_expr_uses(arg, tainted) for arg in child.args):
                return True
    return False


def _recursive_sink(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    tainted: set[str],
) -> ast.Call | None:
    aliases = set(tainted)
    assignments = [
        node
        for node in ast.walk(function)
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and node.value is not None
    ]
    for _ in range(8):
        changed = False
        for assignment in assignments:
            if not _expr_uses(assignment.value, aliases):
                continue
            targets = (
                assignment.targets
                if isinstance(assignment, ast.Assign)
                else [assignment.target]
            )
            for target in targets:
                for name in _target_names(target):
                    if name not in aliases:
                        aliases.add(name)
                        changed = True
        if not changed:
            break

    for child in ast.walk(function):
        if not isinstance(child, ast.Call):
            continue
        leaf = _leaf(child.func) or ""
        receiver = child.func.value if isinstance(child.func, ast.Attribute) else None
        if leaf == "rglob" and _expr_uses(receiver, aliases):
            return child
        if leaf in {"glob", "iterdir"} and _expr_uses(receiver, aliases):
            return child
        called = (_dotted(child.func) or "").lower()
        if called == "os.walk" and child.args and _expr_uses(child.args[0], aliases):
            return child
    return None


def _retrieval_tools(
    agent: Agent,
    tree: ast.AST,
    owner_class: ast.ClassDef,
) -> list:
    tools = []
    for tool in agent.tools:
        candidates = [
            node
            for node in ast.walk(owner_class)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == tool.name
        ]
        if not candidates:
            continue
        function = candidates[0]
        vector_search = any(
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and call.func.attr == "search"
            and "vector_store" in (_dotted(call.func.value) or "")
            for call in ast.walk(function)
        )
        if vector_search:
            tools.append(tool)
    return tools


def enrich_streamlit_rag_directory_semantics(
    graph: Graph,
    root: Path,
    python_paths: list[Path],
) -> None:
    """Trace Streamlit-selected directories into recursive RAG ingestion."""
    root_package = root.name if (root / "__init__.py").exists() else None

    def aliases(path: Path) -> tuple[str, ...]:
        module = _module_name(path, root)
        result = [module] if module else []
        if root_package:
            package_module = root_package if not module else f"{root_package}.{module}"
            if package_module not in result:
                result.append(package_module)
        return tuple(result)

    trees: dict[Path, ast.AST] = {}
    module_paths: dict[str, Path] = {}
    functions: dict[tuple[str, str], ast.FunctionDef | ast.AsyncFunctionDef] = {}
    imports: dict[tuple[str, str], tuple[str, str]] = {}

    for path in python_paths:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        trees[path] = tree
        for module in aliases(path):
            module_paths[module] = path
            for node in getattr(tree, "body", []):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    functions[(module, node.name)] = node
                elif isinstance(node, ast.ImportFrom):
                    source_module = _resolved_import_module(module, path, node)
                    if not source_module:
                        continue
                    for alias in node.names:
                        imports[(module, alias.asname or alias.name)] = (
                            source_module,
                            alias.name,
                        )

    wrapper_factories: dict[tuple[str, str], tuple[Agent, list]] = {}

    for agent in graph.agents:
        if (
            agent.metadata.get("framework") != "pydantic-ai"
            or agent.location is None
            or not agent.name.startswith("self.")
        ):
            continue
        source_path = agent.location.path
        tree = trees.get(source_path)
        if tree is None:
            continue
        line = agent.location.line
        owner_classes = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef)
            and (getattr(node, "lineno", 0) or 0)
            <= line
            <= (getattr(node, "end_lineno", 0) or 0)
        ]
        if not owner_classes:
            continue
        owner_class = max(
            owner_classes,
            key=lambda node: getattr(node, "lineno", 0) or 0,
        )
        retrieval_tools = _retrieval_tools(agent, tree, owner_class)
        if not retrieval_tools:
            continue
        for module in aliases(source_path):
            for node in getattr(tree, "body", []):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if any(
                    isinstance(ret, ast.Return)
                    and isinstance(ret.value, ast.Call)
                    and _leaf(ret.value.func) == owner_class.name
                    for ret in ast.walk(node)
                ):
                    wrapper_factories[(module, node.name)] = (agent, retrieval_tools)

    if not wrapper_factories:
        return

    def resolve_call(
        module: str,
        call: ast.Call,
    ) -> tuple[str, str] | None:
        if isinstance(call.func, ast.Name):
            local = call.func.id
            if (module, local) in functions:
                return module, local
            return imports.get((module, local))
        return None

    def trace_sink(
        module: str,
        function_name: str,
        tainted_params: set[str],
        *,
        constrained: bool = False,
        seen: set[tuple[str, str, tuple[str, ...]]] | None = None,
        depth: int = 0,
    ) -> tuple[ast.Call, bool, str, str] | None:
        if depth > 10:
            return None
        function = functions.get((module, function_name))
        if function is None:
            return None
        key = (module, function_name, tuple(sorted(tainted_params)))
        seen = set() if seen is None else set(seen)
        if key in seen:
            return None
        seen.add(key)

        tainted = set(tainted_params)

        assignments = [
            node
            for node in ast.walk(function)
            if isinstance(node, (ast.Assign, ast.AnnAssign))
            and node.value is not None
        ]
        for _ in range(8):
            changed = False
            for assignment in assignments:
                if not _expr_uses(assignment.value, tainted):
                    continue
                targets = (
                    assignment.targets
                    if isinstance(assignment, ast.Assign)
                    else [assignment.target]
                )
                for target in targets:
                    for name in _target_names(target):
                        if name not in tainted:
                            tainted.add(name)
                            changed = True
            if not changed:
                break

        local_constrained = constrained or _containment_detected(function, tainted)
        sink = _recursive_sink(function, tainted)
        if sink is not None:
            return sink, local_constrained, module, function_name

        for call in (
            node for node in ast.walk(function) if isinstance(node, ast.Call)
        ):
            target = resolve_call(module, call)
            if target is None:
                continue
            target_function = functions.get(target)
            if target_function is None:
                continue
            target_params = _params(target_function)
            next_taint: set[str] = set()
            for index, argument in enumerate(call.args):
                if index >= len(target_params):
                    break
                if _expr_uses(argument, tainted):
                    next_taint.add(target_params[index])
            keywords = {
                keyword.arg: keyword.value
                for keyword in call.keywords
                if keyword.arg
            }
            for param in target_params:
                argument = keywords.get(param)
                if argument is not None and _expr_uses(argument, tainted):
                    next_taint.add(param)
            if not next_taint:
                continue
            result = trace_sink(
                target[0],
                target[1],
                next_taint,
                constrained=local_constrained,
                seen=seen,
                depth=depth + 1,
            )
            if result is not None:
                return result
        return None

    for path, tree in trees.items():
        current_module = _module_name(path, root)
        streamlit_modules: set[str] = set()
        imported_factories: dict[str, tuple[str, str, Agent, list]] = {}

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "streamlit":
                        streamlit_modules.add(alias.asname or alias.name)
            elif isinstance(node, ast.ImportFrom):
                source_module = _resolved_import_module(current_module, path, node)
                if not source_module:
                    continue
                for alias in node.names:
                    factory = wrapper_factories.get((source_module, alias.name))
                    if factory is not None:
                        imported_factories[alias.asname or alias.name] = (
                            source_module,
                            alias.name,
                            factory[0],
                            factory[1],
                        )

        if not streamlit_modules or not imported_factories:
            continue

        tainted: set[str] = set()
        for node in ast.walk(tree):
            value: ast.AST | None = None
            targets: list[ast.AST] = []
            if isinstance(node, ast.NamedExpr):
                value = node.value
                targets = [node.target]
            elif isinstance(node, ast.Assign):
                value = node.value
                targets = list(node.targets)
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                value = node.value
                targets = [node.target]
            if not isinstance(value, ast.Call):
                continue
            if not isinstance(value.func, ast.Attribute):
                continue
            if (
                _dotted(value.func.value) in streamlit_modules
                and value.func.attr == "text_input"
            ):
                for target in targets:
                    if isinstance(target, ast.Name):
                        tainted.add(target.id)

        if not tainted:
            continue

        for call in (
            node for node in ast.walk(tree) if isinstance(node, ast.Call)
        ):
            called = _leaf(call.func)
            if called not in imported_factories:
                continue
            source_module, factory_name, agent, retrieval_tools = imported_factories[
                called
            ]
            factory_function = functions.get((source_module, factory_name))
            if factory_function is None:
                continue
            factory_params = _params(factory_function)
            start_taint: set[str] = set()
            for index, argument in enumerate(call.args):
                if index >= len(factory_params):
                    break
                if _expr_uses(argument, tainted):
                    start_taint.add(factory_params[index])
            keywords = {
                keyword.arg: keyword.value
                for keyword in call.keywords
                if keyword.arg
            }
            for param in factory_params:
                argument = keywords.get(param)
                if argument is not None and _expr_uses(argument, tainted):
                    start_taint.add(param)
            if not start_taint:
                continue

            traced = trace_sink(source_module, factory_name, start_taint)
            if traced is None:
                continue
            sink, constrained, sink_module, sink_function = traced
            basis = "source_proven_user_selected_rag_directory"
            input_name = f"{path.stem}:documents-folder"
            if not any(
                item.name == input_name
                and item.metadata.get("basis") == basis
                for item in agent.inputs
            ):
                agent.inputs.append(
                    InputSource(
                        name=input_name,
                        trust="untrusted",
                        kind="web",
                        location=SourceLocation(
                            path,
                            getattr(call, "lineno", 1) or 1,
                            (getattr(call, "col_offset", 0) or 0) + 1,
                        ),
                        metadata={
                            "basis": basis,
                            "recursive_ingestion": True,
                            "filesystem_path_constrained": constrained,
                            "sink_module": sink_module,
                            "sink_function": sink_function,
                            "sink_line": getattr(sink, "lineno", 1) or 1,
                            "ingress_framework": "streamlit",
                        },
                    )
                )

            for tool in retrieval_tools:
                tool.metadata["rag_retrieval"] = True
                tool.metadata["rag_returns_indexed_content"] = True
                tool.metadata["rag_recursive_ingestion"] = True
                tool.metadata["filesystem_path_constrained"] = constrained
                if not any(
                    resource.metadata.get("source") == "streamlit_rag_directory"
                    for resource in tool.resources
                ):
                    tool.resources.append(
                        ResourceScope(
                            kind="file",
                            selector="<user-selected-directory>",
                            access={"data.read"},
                            location=SourceLocation(
                                path,
                                getattr(call, "lineno", 1) or 1,
                                (getattr(call, "col_offset", 0) or 0) + 1,
                            ),
                            metadata={
                                "source": "streamlit_rag_directory",
                                "recursive": True,
                                "constrained": constrained,
                            },
                        )
                    )
