"""Repository-level LangChain SQLDatabase authority reconstruction."""

import ast
from dataclasses import dataclass
from pathlib import Path

from horustrace.models import Graph, Tool


_SQL_DATABASE_MODULES = {
    "langchain_community.utilities",
    "langchain_community.utilities.sql_database",
    "langchain.utilities",
    "langchain.utilities.sql_database",
}
_SQL_EXECUTION_METHODS = {"run", "run_no_throw"}
_READ_ONLY_PREFIXES = {
    "select",
    "show",
    "describe",
    "desc",
    "explain",
    "pragma",
}


@dataclass(slots=True)
class _Module:
    name: str
    path: Path
    tree: ast.Module


def _module_name(path: Path, root: Path) -> str:
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


def _target_names(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        result: list[str] = []
        for item in node.elts:
            result.extend(_target_names(item))
        return result
    return []


def _sql_database_constructor_aliases(tree: ast.Module) -> set[str]:
    aliases: set[str] = set()
    for node in tree.body:
        if not isinstance(node, ast.ImportFrom):
            continue
        if (node.module or "") not in _SQL_DATABASE_MODULES:
            continue
        for alias in node.names:
            if alias.name == "SQLDatabase":
                aliases.add(alias.asname or alias.name)
    return aliases


def _is_sql_database_constructor(
    call: ast.Call,
    aliases: set[str],
) -> bool:
    dotted = _dotted(call.func) or ""
    if dotted in aliases:
        return True
    return any(
        dotted == f"{alias}.{method}"
        for alias in aliases
        for method in {"from_uri", "from_databricks", "from_cnosdb"}
    )


def _direct_sql_globals(module: _Module) -> set[str]:
    constructors = _sql_database_constructor_aliases(module.tree)
    if not constructors:
        return set()

    result: set[str] = set()
    for node in module.tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        if not isinstance(value, ast.Call) or not _is_sql_database_constructor(
            value,
            constructors,
        ):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            result.update(_target_names(target))
    return result


def _collect_sql_globals(modules: dict[str, _Module]) -> set[tuple[str, str]]:
    resolved = {
        (module.name, name)
        for module in modules.values()
        for name in _direct_sql_globals(module)
    }

    for _ in range(max(1, len(modules))):
        changed = False
        for module in modules.values():
            for node in module.tree.body:
                if not isinstance(node, ast.ImportFrom):
                    continue
                source_module = _resolve_import_module(
                    module.name,
                    module.path,
                    node,
                )
                if not source_module:
                    continue
                for alias in node.names:
                    if (source_module, alias.name) not in resolved:
                        continue
                    local_name = alias.asname or alias.name
                    key = (module.name, local_name)
                    if key not in resolved:
                        resolved.add(key)
                        changed = True
        if not changed:
            break

    return resolved


def _function_parameters(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[str]:
    return {
        arg.arg
        for arg in (
            list(node.args.posonlyargs)
            + list(node.args.args)
            + list(node.args.kwonlyargs)
        )
    }


def _expr_depends_on(node: ast.AST | None, names: set[str]) -> bool:
    if node is None:
        return False
    return any(
        isinstance(child, ast.Name) and child.id in names
        for child in ast.walk(node)
    )


def _tainted_names(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[str]:
    tainted = _function_parameters(function)
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
            if not names or not _expr_depends_on(value, tainted):
                continue
            before = len(tainted)
            tainted.update(names)
            changed = changed or len(tainted) != before
        if not changed:
            break

    return tainted


def _local_sql_receivers(
    module: _Module,
    sql_globals: set[tuple[str, str]],
) -> set[str]:
    receivers = {
        name
        for candidate_module, name in sql_globals
        if candidate_module == module.name
    }

    for node in module.tree.body:
        if not isinstance(node, ast.ImportFrom):
            continue
        source_module = _resolve_import_module(
            module.name,
            module.path,
            node,
        )
        if not source_module:
            continue
        for alias in node.names:
            if (source_module, alias.name) in sql_globals:
                receivers.add(alias.asname or alias.name)

    return receivers


def _literal_statement_mode(node: ast.AST) -> str | None:
    if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
        return None
    stripped = node.value.lstrip().lower()
    first = stripped.split(None, 1)[0] if stripped else ""
    if first in _READ_ONLY_PREFIXES:
        return "read_only"
    if first:
        return "state_changing"
    return None


def _sql_call_argument(call: ast.Call) -> ast.AST | None:
    if call.args:
        return call.args[0]
    for keyword in call.keywords:
        if keyword.arg in {"command", "query", "sql", "statement"}:
            return keyword.value
    return None


def _function_sql_authority(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    sql_receivers: set[str],
) -> dict[str, str] | None:
    tainted = _tainted_names(function)

    for node in ast.walk(function):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in _SQL_EXECUTION_METHODS:
            continue
        receiver = node.func.value
        if not isinstance(receiver, ast.Name) or receiver.id not in sql_receivers:
            continue

        statement = _sql_call_argument(node)
        if statement is None:
            continue

        literal_mode = _literal_statement_mode(statement)
        if literal_mode == "read_only":
            return {
                "mode": "read_only",
                "api": f"SQLDatabase.{node.func.attr}",
            }
        if literal_mode == "state_changing":
            return {
                "mode": "state_changing",
                "api": f"SQLDatabase.{node.func.attr}",
            }
        if _expr_depends_on(statement, tainted):
            return {
                "mode": "unconstrained",
                "api": f"SQLDatabase.{node.func.attr}",
            }

    return None


def _source_function(
    tool: Tool,
    modules_by_path: dict[Path, _Module],
) -> tuple[_Module, ast.FunctionDef | ast.AsyncFunctionDef] | None:
    raw_path = tool.metadata.get("source_path")
    function_name = tool.metadata.get("source_function")
    if not isinstance(raw_path, str) or not isinstance(function_name, str):
        return None

    module = modules_by_path.get(Path(raw_path).resolve())
    if module is None:
        return None

    matches = [
        node
        for node in module.tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == function_name
    ]
    if len(matches) != 1:
        return None
    return module, matches[0]


def enrich_langchain_sql_authority(
    graph: Graph,
    root: Path,
    python_paths: list[Path],
) -> None:
    """Widen SQLDatabase-backed tool authority only from source-proven call shapes."""
    modules: dict[str, _Module] = {}
    modules_by_path: dict[Path, _Module] = {}

    for path in python_paths:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        module = _Module(
            name=_module_name(path, root),
            path=path.resolve(),
            tree=tree,
        )
        modules[module.name] = module
        modules_by_path[module.path] = module

    if not modules:
        return

    sql_globals = _collect_sql_globals(modules)
    if not sql_globals:
        return

    receivers_by_module = {
        module.name: _local_sql_receivers(module, sql_globals)
        for module in modules.values()
    }

    for tool in graph.all_tools():
        source = _source_function(tool, modules_by_path)
        if source is None:
            continue
        module, function = source
        receivers = receivers_by_module.get(module.name, set())
        if not receivers:
            continue

        authority = _function_sql_authority(function, receivers)
        if authority is None:
            continue

        tool.capabilities.add("data.read")
        mode = authority["mode"]
        if mode in {"state_changing", "unconstrained"}:
            tool.capabilities.update({"data.write", "destructive.write"})

        tool.metadata.update(
            {
                "sql_database_api": authority["api"],
                "sql_statement_scope": mode,
                "sql_dynamic_statement": mode == "unconstrained",
                "sql_authority_basis": (
                    "source_proven_langchain_sql_database"
                ),
            }
        )
