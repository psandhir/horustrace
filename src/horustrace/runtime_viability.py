"""Conservative source-level runtime viability qualification.

This module does not execute or import target code. It only records blockers that are
provable from the pinned repository source, such as a missing local module or a direct
undefined name used while constructing an agent.
"""
from __future__ import annotations

import ast
import builtins
from pathlib import Path

from horustrace.coverage import add_diagnostic
from horustrace.models import Graph, ScanDiagnostic, SourceLocation

_AGENT_CONSTRUCTORS = {
    "Agent",
    "LlmAgent",
    "SequentialAgent",
    "ParallelAgent",
    "LoopAgent",
}


def _call_name(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _target_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, (ast.Tuple, ast.List)):
        result: set[str] = set()
        for item in node.elts:
            result.update(_target_names(item))
        return result
    return set()


def _module_exists(root: Path, module: str) -> bool:
    if not module:
        return True
    path = root.joinpath(*module.split("."))
    return path.with_suffix(".py").is_file() or (path / "__init__.py").is_file()


def _relative_module(path: Path, root: Path, node: ast.ImportFrom) -> str | None:
    try:
        relative = path.resolve().relative_to(root.resolve())
    except ValueError:
        return None
    package = list(relative.parent.parts)
    ascend = max(node.level - 1, 0)
    if ascend > len(package):
        return None
    if ascend:
        package = package[:-ascend]
    if node.module:
        package.extend(part for part in node.module.split(".") if part)
    return ".".join(package)


def _missing_local_imports(path: Path, root: Path, tree: ast.Module) -> list[dict[str, object]]:
    blockers: list[dict[str, object]] = []
    for node in tree.body:
        if not isinstance(node, ast.ImportFrom):
            continue
        if node.level:
            module = _relative_module(path, root, node)
            if module and not _module_exists(root, module):
                blockers.append(
                    {
                        "kind": "missing_local_module",
                        "module": module,
                        "line": getattr(node, "lineno", 1) or 1,
                    }
                )
            continue

        module = node.module or ""
        if not module:
            continue
        first = module.split(".", 1)[0]
        # Treat an absolute import as repository-local only when the root
        # exposes an actual Python module/package for that namespace. A plain
        # same-named directory (for example a repository's "agents/" samples
        # alongside the OpenAI Agents SDK import) is not proof that Python
        # resolves the import locally.
        local_namespace = _module_exists(root, first)
        if local_namespace and not _module_exists(root, module):
            blockers.append(
                {
                    "kind": "missing_local_module",
                    "module": module,
                    "line": getattr(node, "lineno", 1) or 1,
                }
            )
    return blockers


def _module_defined_names(tree: ast.Module) -> set[str]:
    names = set(dir(builtins))
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                names.update(_target_names(target))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.asname or alias.name.split(".", 1)[0])
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name != "*":
                    names.add(alias.asname or alias.name)
    return names


def _undefined_agent_constructor_names(tree: ast.Module) -> list[dict[str, object]]:
    """Find direct module-scope undefined names used by agent constructors."""
    defined = _module_defined_names(tree)
    blockers: list[dict[str, object]] = []

    for statement in tree.body:
        calls = [
            node
            for node in ast.walk(statement)
            if isinstance(node, ast.Call)
            and _call_name(node.func) in _AGENT_CONSTRUCTORS
        ]
        # Avoid reasoning about local function scopes here; local variables and
        # closure state require a fuller control-flow model.
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for call in calls:
            values = [*call.args, *(keyword.value for keyword in call.keywords)]
            for value in values:
                if not isinstance(value, ast.Name):
                    continue
                if value.id in defined:
                    continue
                blockers.append(
                    {
                        "kind": "undefined_agent_constructor_name",
                        "name": value.id,
                        "line": getattr(call, "lineno", 1) or 1,
                    }
                )
    return blockers


def annotate_runtime_viability(
    graph: Graph,
    root: Path,
    python_paths: list[Path],
) -> None:
    """Annotate agents whose pinned source is provably initialization-blocked."""
    agents_by_path: dict[Path, list] = {}
    for agent in graph.agents:
        if agent.location is not None:
            agents_by_path.setdefault(agent.location.path.resolve(), []).append(agent)

    for path in python_paths:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue

        blockers = [
            *_missing_local_imports(path, root, tree),
            *_undefined_agent_constructor_names(tree),
        ]
        if not blockers:
            continue

        affected = agents_by_path.get(path.resolve(), [])
        if not affected:
            continue

        for agent in affected:
            agent.metadata["runtime_viability"] = "blocked_by_source_error"
            current = list(agent.metadata.get("runtime_blockers") or [])
            for blocker in blockers:
                if blocker not in current:
                    current.append(blocker)
            agent.metadata["runtime_blockers"] = current

        first = blockers[0]
        add_diagnostic(
            graph.coverage,
            ScanDiagnostic(
                "runtime_viability_blocker",
                "Pinned source contains a static initialization/import blocker; declared authority is retained but live runtime reachability is not proven.",
                SourceLocation(path, line=int(first.get("line") or 1)),
                incomplete=False,
                details={
                    "blockers": blockers,
                    "affected_agents": sorted(agent.name for agent in affected),
                },
            ),
        )
