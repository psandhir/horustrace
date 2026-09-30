from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from horustrace.models import Graph, Tool


@dataclass(frozen=True, slots=True)
class FunctionRef:
    key: str
    module: str
    name: str
    path: Path
    line: int


@dataclass(frozen=True, slots=True)
class ImportRef:
    module: str
    name: str
    target_module: str
    target_name: str


def _module_name(path: Path, root: Path) -> str:
    try:
        relative = path.resolve().relative_to(root.resolve()).with_suffix("")
    except ValueError:
        relative = Path(path.stem)
    parts = list(relative.parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _collect_functions(root: Path, python_paths: list[Path]) -> list[FunctionRef]:
    refs: list[FunctionRef] = []
    for path in sorted(python_paths):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        module = _module_name(path, root)
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            key = f"{module}.{node.name}" if module else node.name
            refs.append(
                FunctionRef(
                    key=key,
                    module=module,
                    name=node.name,
                    path=path.resolve(),
                    line=getattr(node, "lineno", 1) or 1,
                )
            )
    return refs


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


def _collect_imports(
    root: Path,
    python_paths: list[Path],
) -> tuple[dict[tuple[str, str], ImportRef], set[str]]:
    bindings: dict[tuple[str, str], ImportRef] = {}
    modules: set[str] = set()
    for path in sorted(python_paths):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        module = _module_name(path, root)
        modules.add(module)
        for node in tree.body:
            if not isinstance(node, ast.ImportFrom):
                continue
            target_module = _resolved_import_module(module, path, node)
            if not target_module:
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue
                local_name = alias.asname or alias.name
                bindings[(module, local_name)] = ImportRef(
                    module=module,
                    name=local_name,
                    target_module=target_module,
                    target_name=alias.name,
                )
    return bindings, modules


def _resolve_function_binding(
    module: str,
    name: str,
    *,
    by_key: dict[str, FunctionRef],
    imports: dict[tuple[str, str], ImportRef],
    visited: set[tuple[str, str]] | None = None,
) -> FunctionRef | None:
    visited = visited or set()
    key = (module, name)
    if key in visited:
        return None
    visited.add(key)

    direct = by_key.get(f"{module}.{name}" if module else name)
    if direct is not None:
        return direct

    imported = imports.get(key)
    if imported is None:
        return None
    return _resolve_function_binding(
        imported.target_module,
        imported.target_name,
        by_key=by_key,
        imports=imports,
        visited=visited,
    )


def _unique(values: list[FunctionRef]) -> FunctionRef | None:
    by_key = {item.key: item for item in values}
    return next(iter(by_key.values())) if len(by_key) == 1 else None


def _suffix_matches(refs: list[FunctionRef], candidate: str) -> list[FunctionRef]:
    return [
        ref
        for ref in refs
        if ref.key == candidate or ref.key.endswith(f".{candidate}")
    ]


def _tool_ref(
    tool: Tool,
    refs: list[FunctionRef],
    by_path_name: dict[tuple[Path, str], FunctionRef],
    by_key: dict[str, FunctionRef],
    *,
    root: Path,
    imports: dict[tuple[str, str], ImportRef],
    modules: set[str],
) -> FunctionRef | None:
    existing = tool.metadata.get("source_function_key")
    if isinstance(existing, str) and existing in by_key:
        return by_key[existing]

    names: list[str] = []
    for value in (
        tool.metadata.get("source_function"),
        tool.metadata.get("function"),
        tool.name,
    ):
        if isinstance(value, str) and value and value not in names:
            names.append(value)

    if tool.location is not None:
        path = tool.location.path.resolve()
        local = _unique(
            [
                ref
                for name in names
                if (ref := by_path_name.get((path, name))) is not None
            ]
        )
        if local:
            return local

    import_module = tool.metadata.get("import_module")
    if isinstance(import_module, str) and import_module:
        imported_candidates: list[FunctionRef] = []
        for name in names:
            imported_candidates.extend(
                _suffix_matches(refs, f"{import_module}.{name}")
            )
        imported = _unique(imported_candidates)
        if imported:
            return imported

        # Adapters see the ImportFrom.module value but not always its relative
        # level. Resolve the common package-relative case from the binding file,
        # then follow package __init__ re-exports to the concrete function.
        if tool.location is not None:
            current_module = _module_name(tool.location.path, root)
            package_parts = current_module.split(".") if current_module else []
            if tool.location.path.stem != "__init__" and package_parts:
                package_parts = package_parts[:-1]
            sibling_module = ".".join(
                [*package_parts, *[part for part in import_module.split(".") if part]]
            )
            module_candidates = [sibling_module]
            if import_module in modules:
                module_candidates.append(import_module)
            module_candidates.extend(
                module
                for module in sorted(modules)
                if module.endswith(f".{import_module}")
            )
            for candidate_module in dict.fromkeys(module_candidates):
                if not candidate_module or candidate_module not in modules:
                    continue
                resolved_candidates = [
                    resolved
                    for name in names
                    if (
                        resolved := _resolve_function_binding(
                            candidate_module,
                            name,
                            by_key=by_key,
                            imports=imports,
                        )
                    )
                    is not None
                ]
                resolved = _unique(resolved_candidates)
                if resolved:
                    return resolved

    source_module = tool.metadata.get("source_module")
    if isinstance(source_module, str) and source_module:
        module_candidates: list[FunctionRef] = []
        for name in names:
            module_candidates.extend(
                _suffix_matches(refs, f"{source_module}.{name}")
            )
        module_ref = _unique(module_candidates)
        if module_ref:
            return module_ref

    return None


def annotate_tool_source_provenance(
    graph: Graph,
    root: Path,
    python_paths: list[Path],
) -> None:
    """Attach canonical source-function provenance where the binding is unique.

    This pass deliberately does not infer from a simple function name across the
    whole repository. It requires same-file evidence, an imported-module binding,
    or an already-resolved source module/key.
    """
    refs = _collect_functions(root, python_paths)
    if not refs:
        return

    by_key = {ref.key: ref for ref in refs}
    by_path_name = {(ref.path, ref.name): ref for ref in refs}
    imports, modules = _collect_imports(root, python_paths)

    for tool in graph.all_tools():
        ref = _tool_ref(
            tool,
            refs,
            by_path_name,
            by_key,
            root=root,
            imports=imports,
            modules=modules,
        )
        if ref is None:
            continue

        tool.metadata["source_function_key"] = ref.key
        tool.metadata["source_module"] = ref.module
        tool.metadata["source_function"] = ref.name
        tool.metadata["source_path"] = ref.path.as_posix()
        tool.metadata["source_line"] = ref.line

        import_module = tool.metadata.get("import_module")
        if isinstance(import_module, str) and import_module:
            aliases = tool.metadata.setdefault("import_aliases", [])
            alias = f"{import_module}.{tool.name}"
            if alias not in aliases:
                aliases.append(alias)
