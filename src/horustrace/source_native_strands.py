"""Wave B04 source-only Strands composition through explicitly re-exported @tool wrappers.

Emit source-visible *candidate* two-hop relationships, not runtime invocation,
effective tool permissions, or proof of consolidation errors.
"""
from __future__ import annotations

import ast
from pathlib import Path

from horustrace.models import SourceLocation
from horustrace.semantic_discovery import (
    SemanticBinding,
    SemanticBindingKind,
    SemanticDiscovery,
    SemanticEntity,
    SemanticEntityKind,
    SemanticObservation,
    SemanticResolution,
    stable_binding_id,
    stable_entity_id,
    stable_observation_id,
)
from horustrace.source_native_mcp import _imports, _read_ast, _source_files

PARSER = "strands_imported_tool_composition_ast_v1"


class _Evidence:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.entities: dict[str, SemanticEntity] = {}
        self.bindings: dict[str, SemanticBinding] = {}
        self.observations: dict[str, SemanticObservation] = {}

    def entity(self, source: Path, line: int, name: str,
               kind: SemanticEntityKind, role: str) -> str:
        path = source.resolve().relative_to(self.root)
        location = SourceLocation(path, line=line)
        identity = stable_entity_id(
            framework="strands", kind=kind, name=name,
            source_key=path.as_posix(), line=line,
        )
        self.entities[identity] = SemanticEntity(
            entity_id=identity, name=name, kind=kind,
            framework="strands", location=location,
            metadata={"origin": PARSER, "runtime_verified": False},
        )
        key = f"{path}:{line}:{name}"
        oid = stable_observation_id(
            entity_id=identity, role=role, source_key=key,
        )
        self.observations[oid] = SemanticObservation(
            observation_id=oid, entity_id=identity, role=role,
            resolution=SemanticResolution.PARTIAL,
            parser_id=PARSER, source_key=key,
            reason="source_visible_imported_tool_composition_not_runtime_execution",
            location=location,
        )
        return identity

    def edge(self, src: str, dst: str, source: Path,
             line: int, basis: str) -> None:
        kind = SemanticBindingKind.INVOKES
        bid = stable_binding_id(
            source_id=src, target_id=dst, kind=kind, basis=basis,
        )
        self.bindings[bid] = SemanticBinding(
            binding_id=bid, source_id=src, target_id=dst, kind=kind,
            basis=basis, resolution=SemanticResolution.PARTIAL,
            location=SourceLocation(
                source.resolve().relative_to(self.root), line=line,
            ),
            metadata={
                "origin": PARSER,
                "runtime_verified": False,
                "agent_callability": "not_adjudicated",
                "source_candidate_not_runtime_delegation": True,
            },
        )

    def result(self) -> SemanticDiscovery:
        value = SemanticDiscovery(
            schema_version=2,
            entities=sorted(self.entities.values(), key=lambda e: e.entity_id),
            bindings=sorted(self.bindings.values(), key=lambda b: b.binding_id),
            observations=sorted(
                self.observations.values(), key=lambda o: o.observation_id,
            ),
        )
        value.validate()
        return value


def _exported_modules(init: ast.Module) -> dict[str, str]:
    """Package __init__ must explicitly re-export each tool from a local module."""
    result: dict[str, str] = {}
    for statement in init.body:
        if not (isinstance(statement, ast.ImportFrom) and statement.level == 1
                and statement.module and statement.module.isidentifier()):
            continue
        for item in statement.names:
            if item.name.isidentifier():
                alias = item.asname or item.name
                if alias in result:
                    result[alias] = ""  # ambiguous two re-exports
                else:
                    result[alias] = statement.module
    return {alias: module for alias, module in result.items() if module}


def _decorated_strands_wrapper(tree: ast.Module, name: str) -> ast.FunctionDef | None:
    # Imports inside module-level try handlers represent conditional source
    # registration, never verified successful runtime imports.
    imports: set[str] = set()
    agents: set[str] = set()
    for statement in tree.body:
        segments = statement.body if isinstance(statement, ast.Try) else [statement]
        for part in segments:
            if isinstance(part, ast.ImportFrom) and part.module == "strands":
                imports.update(a.asname or a.name for a in part.names if a.name == "tool")
                agents.update(a.asname or a.name for a in part.names if a.name == "Agent")
    if not imports or not agents:
        return None
    # A module-level overwrite of an Agent constructor or decorated wrapper
    # loses original source identity, including conditionally overwritten calls.
    if any(
        isinstance(stmt, (ast.Assign, ast.AnnAssign))
        and any(
            isinstance(t, ast.Name) and t.id in agents
            for t in (stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target])
        )
        for stmt in tree.body
    ):
        return None
    funcs = [
        stmt for stmt in tree.body
        if isinstance(stmt, ast.FunctionDef) and stmt.name == name
        and any(isinstance(d, ast.Name) and d.id in imports
                for d in stmt.decorator_list)
    ]
    if len(funcs) != 1:
        return None
    func = funcs[0]
    created: dict[str, int] = {}
    for node in ast.walk(func):
        if not (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Name)
                and node.value.func.id in agents):
            continue
        created[node.targets[0].id] = node.value.lineno
    if len(created) != 1:
        return None
    symbol, _ = next(iter(created.items()))
    # Require a source-visible call to the constructed agent; merely storing
    # an Agent instance inside a tool wrapper is not a tool-to-agent flow.
    if not any(
        isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        and node.func.id == symbol for node in ast.walk(func)
    ):
        return None
    return func


def _agent_call_line(wrapper: ast.FunctionDef) -> int | None:
    for node in ast.walk(wrapper):
        if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Name)
                and node.value.func.id == "Agent"):
            return node.value.lineno
    return None


def _compositions(tree: ast.Module) -> list[tuple[int, list[str]]]:
    agents = _imports(tree, "strands", "Agent")
    if not agents:
        return []
    imported = {
        a.asname or a.name
        for stmt in tree.body
        if isinstance(stmt, ast.ImportFrom) and stmt.module == "agents"
        for a in stmt.names
    }
    result: list[tuple[int, list[str]]] = []
    for function in tree.body:
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        assignments: dict[str, list[ast.AST]] = {}
        for node in ast.walk(function):
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
            ):
                assignments.setdefault(node.targets[0].id, []).append(node.value)
        # Local rebinding (or a same-name function parameter) invalidates
        # an imported wrapper's source identity.
        parameters = {
            arg.arg for arg in (
                function.args.posonlyargs + function.args.args
                + function.args.kwonlyargs
            )
        }
        trusted_imports = {
            name for name in imported
            if name not in assignments and name not in parameters
            and name in _imports(tree, "agents", name)
        }
        for node in ast.walk(function):
            if not (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id in agents):
                continue
            options = [
                kw.value for kw in node.keywords if kw.arg == "tools"
            ]
            if len(options) != 1 or not isinstance(options[0], ast.BinOp):
                continue
            expr = options[0]
            if not (isinstance(expr.op, ast.Add)
                    and isinstance(expr.left, ast.Name)
                    and isinstance(expr.right, ast.Name)):
                continue
            left, right = expr.left.id, expr.right.id
            if (len(assignments.get(left, [])) != 1
                    or len(assignments.get(right, [])) != 1):
                continue
            first, second = assignments[left][0], assignments[right][0]
            if not (isinstance(first, ast.List) and isinstance(second, ast.List)):
                continue
            members = [
                item.id for item in second.elts
                if isinstance(item, ast.Name) and item.id in trusted_imports
            ]
            # Unknown or locally shadowed list members must not erase
            # independently source-proven peers in the same literal list.
            if not members or not all(
                isinstance(item, ast.Name) for item in second.elts
            ):
                continue
            result.append((node.lineno, members))
    return result


def inspect_strands_tool_composition(target: Path) -> SemanticDiscovery:
    """Resolve package re-exports + @tool wrappers + nested Agent invocations."""
    root = target.resolve() if target.is_dir() else target.resolve().parent
    collector = _Evidence(root)
    files = set(_source_files(target))
    trees = {
        file.resolve(): tree
        for file in files
        if (tree := _read_ast(file)) is not None
    }
    for path, tree in trees.items():
        if not _compositions(tree):
            continue
        init_file = path.parent / "agents" / "__init__.py"
        init = trees.get(init_file.resolve())
        if init is None:
            continue
        exports = _exported_modules(init)
        for line, names in _compositions(tree):
            for name in names:
                module = exports.get(name)
                if not module:
                    continue
                candidate = init_file.parent / f"{module}.py"
                tool_file = candidate.resolve()
                # No symlinks, foreign package roots or unobserved files.
                if candidate.is_symlink() or tool_file not in trees:
                    continue
                wrapped = _decorated_strands_wrapper(trees[tool_file], name)
                if wrapped is None:
                    continue
                inner_line = _agent_call_line(wrapped)
                if inner_line is None:
                    continue
                orchestrator = collector.entity(
                    path, line, "orchestrator", SemanticEntityKind.AGENT,
                    "source_orchestrator_instance",
                )
                wrapper = collector.entity(
                    tool_file, wrapped.lineno, name, SemanticEntityKind.TOOL,
                    "strands_imported_decorated_tool_wrapper",
                )
                inner = collector.entity(
                    tool_file, inner_line, f"inner_agent:{name}",
                    SemanticEntityKind.AGENT, "source_nested_agent_instance",
                )
                collector.edge(
                    orchestrator, wrapper, path, line,
                    "source_imported_tool_in_concatenated_agent_tools",
                )
                collector.edge(
                    wrapper, inner, tool_file, inner_line,
                    "source_wrapper_constructs_and_invokes_nested_agent",
                )
    return collector.result()
