from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from horustrace.models import Graph, InputSource, Tool


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


def _tainted_aliases(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    tainted_parameters: set[str],
) -> set[str]:
    tainted = set(tainted_parameters)
    changed = True
    while changed:
        changed = False
        for child in ast.walk(function):
            if not isinstance(child, (ast.Assign, ast.AnnAssign)):
                continue
            value = child.value
            if not (_expr_names(value) & tainted):
                continue
            targets = (
                child.targets
                if isinstance(child, ast.Assign)
                else [child.target]
            )
            for target in targets:
                for name in _target_names(target):
                    if name not in tainted:
                        tainted.add(name)
                        changed = True
    return tainted


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
    tainted = _tainted_aliases(function, tainted_parameters)
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
            path_parameters.update(tainted_parameters)
            if leaf in {"read_text", "read_bytes"}:
                read_calls.append(child)

        if leaf in {"write_text", "write_bytes", "unlink", "rename", "replace"} and receiver_tainted:
            accesses.add("write")
            path_parameters.update(tainted_parameters)

        if leaf == "open" and (receiver_tainted or arg_tainted):
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
            path_parameters.update(tainted_parameters)

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
            semantics = inspect_tool(tool)
            if semantics is None:
                continue
            tool.metadata["model_selected_filesystem_path"] = True
            tool.metadata["filesystem_access"] = sorted(semantics.accesses)
            tool.metadata["filesystem_path_constrained"] = semantics.constrained
            tool.metadata["model_selected_path_parameters"] = sorted(
                semantics.path_parameters
            )
            tool.metadata["filesystem_semantics_basis"] = (
                "source_function_and_local_helper"
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
