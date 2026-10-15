"""Wave B: conservative source-linked, condition-qualified MCP ToolSet inventory.

This opt-in provider-only proof follows local Python imports:
ServerSpec.tools -> ToolSet(read_only/write) -> imported function definition.
It never asserts an enabled runtime catalogue, AGENT_CAN_CALL, or credentials.
"""
from __future__ import annotations

import ast
from collections import Counter
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
from horustrace.source_native_dynamic_mcp import _registered_factory
from horustrace.source_native_mcp import _read_ast

PARSER = "local_python_toolset_import_chain_v1"


def _source_under(root: Path, candidate: Path) -> bool:
    """Never traverse out of the scan root or through source symlinks."""
    root = root.resolve()
    try:
        candidate.relative_to(root)
        path = candidate
        while path != root:
            if path.is_symlink():
                return False
            path = path.parent
        return candidate.resolve().is_relative_to(root)
    except ValueError:
        return False


def _relative_import(
    root: Path, origin: Path, stmt: ast.ImportFrom,
) -> Path | None:
    """Resolve a *local* Python import without importing the source package."""
    if not stmt.level:
        return None
    base = origin.parent
    for _ in range(stmt.level - 1):
        base = base.parent
    for part in (stmt.module or "").split("."):
        if part:
            if not part.isidentifier():
                return None
            base /= part
    candidates = (base / "__init__.py", base.with_suffix(".py"))
    for candidate in candidates:
        if _source_under(root, candidate) and candidate.is_file():
            return candidate
    return None


def _targets(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        return [name for item in node.elts for name in _targets(item)]
    return []


def _top_bindings(tree: ast.Module) -> Counter[str]:
    counts: Counter[str] = Counter()

    def visit(stmt: ast.stmt) -> None:
        if isinstance(stmt, ast.ImportFrom):
            for item in stmt.names:
                counts[item.asname or item.name] += 1
            return
        if isinstance(stmt, ast.Import):
            for item in stmt.names:
                counts[item.asname or item.name.split(".")[0]] += 1
            return
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            counts[stmt.name] += 1
            return
        if isinstance(stmt, ast.Assign):
            for t in stmt.targets:
                counts.update(_targets(t))
        elif isinstance(stmt, (ast.AnnAssign, ast.AugAssign, ast.For, ast.AsyncFor)):
            counts.update(_targets(stmt.target))
        for child in getattr(stmt, "body", ()):
            if isinstance(child, ast.stmt):
                visit(child)
        for child in getattr(stmt, "orelse", ()):
            if isinstance(child, ast.stmt):
                visit(child)

    for stmt in tree.body:
        visit(stmt)
    return counts


def _aliases(
    root: Path, origin: Path, tree: ast.Module,
) -> dict[str, tuple[Path, str]]:
    counts = _top_bindings(tree)
    if "*" in counts:  # wildcard origin is unknowable
        return {}
    found: dict[str, tuple[Path, str]] = {}
    for stmt in tree.body:
        if not isinstance(stmt, ast.ImportFrom):
            continue
        local = _relative_import(root, origin, stmt)
        if local is None:
            continue
        for item in stmt.names:
            alias = item.asname or item.name
            if counts[alias] == 1 and item.name.isidentifier():
                found[alias] = (local, item.name)
    return found


def _unique_call(
    tree: ast.Module, symbol: str, constructor: str,
    constructor_origin: tuple[Path, str] | None, expected: Path,
) -> ast.Call | None:
    if constructor_origin != (expected, constructor):
        return None
    if _top_bindings(tree)[symbol] != 1:
        return None
    assigned = [
        stmt.value for stmt in tree.body
        if isinstance(stmt, ast.Assign)
        and len(stmt.targets) == 1
        and isinstance(stmt.targets[0], ast.Name)
        and stmt.targets[0].id == symbol
    ]
    if len(assigned) != 1 or not isinstance(assigned[0], ast.Call):
        return None
    call = assigned[0]
    if not isinstance(call.func, ast.Name):
        return None
    aliases = {
        a.asname or a.name for stmt in tree.body
        if isinstance(stmt, ast.ImportFrom)
        for a in stmt.names
        if a.name == constructor
    }
    if call.func.id not in aliases:
        return None
    return call


def _function_location(root: Path, source: Path, name: str) -> int | None:
    tree = _read_ast(source)
    if tree is None or _top_bindings(tree)[name] != 1:
        return None
    funcs = [
        stmt for stmt in tree.body
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef))
        and stmt.name == name
    ]
    return funcs[0].lineno if len(funcs) == 1 else None


class _Evidence:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.entities: dict[str, SemanticEntity] = {}
        self.observations: dict[str, SemanticObservation] = {}
        self.bindings: dict[str, SemanticBinding] = {}

    def entity(self, source: Path, line: int, name: str,
               kind: SemanticEntityKind, role: str) -> str:
        portable = source.resolve().relative_to(self.root).as_posix()
        location = SourceLocation(Path(portable), line=line)
        entity_id = stable_entity_id(
            framework="python-fastmcp-toolset", kind=kind, name=name,
            source_key=portable, line=line,
        )
        self.entities[entity_id] = SemanticEntity(
            entity_id=entity_id, name=name, kind=kind,
            framework="python-fastmcp-toolset", location=location,
            metadata={"origin": PARSER, "runtime_verified": False},
        )
        obs_id = stable_observation_id(
            entity_id=entity_id, role=role, source_key=f"{portable}:{line}",
        )
        self.observations[obs_id] = SemanticObservation(
            observation_id=obs_id, entity_id=entity_id, role=role,
            resolution=SemanticResolution.PARTIAL, parser_id=PARSER,
            source_key=f"{portable}:{line}",
            reason="local_import_chain_declaration_not_runtime_registration",
            location=location,
        )
        return entity_id

    def edge(self, server_id: str, tool_id: str, source: Path, line: int,
             bucket: str) -> None:
        # Candidate catalogue only: disabled-tool lists, read-only mode and
        # runtime scope checks can all restrict actual exposure.
        basis = "static_toolset_import_chain:" + bucket
        kind = SemanticBindingKind.EXPOSES_TOOL
        eid = stable_binding_id(
            source_id=server_id, target_id=tool_id, kind=kind, basis=basis,
        )
        portable = source.resolve().relative_to(self.root).as_posix()
        self.bindings[eid] = SemanticBinding(
            binding_id=eid, source_id=server_id, target_id=tool_id,
            kind=kind, basis=basis, resolution=SemanticResolution.PARTIAL,
            location=SourceLocation(Path(portable), line=line),
            metadata={
                "origin": PARSER,
                "exposure_state": "conditional_candidate",
                "registration_bucket": bucket,
                "read_only_mode": (
                    "must_be_false" if bucket == "write"
                    else "either"
                ),
                "disabled_tools": "unresolved",
                "auth_scope": "unresolved",
                "agent_callability": "not_adjudicated",
                "runtime_verified": False,
            },
        )

    def result(self) -> SemanticDiscovery:
        result = SemanticDiscovery(
            schema_version=2,
            entities=sorted(self.entities.values(), key=lambda e: e.entity_id),
            observations=sorted(
                self.observations.values(), key=lambda o: o.observation_id,
            ),
            bindings=sorted(self.bindings.values(), key=lambda b: b.binding_id),
        )
        result.validate()
        return result


def inspect_local_toolset_catalogues(target: Path) -> SemanticDiscovery:
    """Link source-declared ToolSets to their local tool implementations.

    Without a traceable FastMCP factory this API emits no provider exposure.
    Does not interpret arbitrary Python or remote runtime inputs.
    """
    root = target.resolve() if target.is_dir() else target.resolve().parent
    evidence = _Evidence(root)
    packages = [root / "src" / "cb_mcp", root / "cb_mcp"]
    for package in packages:
        core = package / "core" / "spec.py"
        factory = package / "core" / "app.py"
        if not all(
            _source_under(root, p) and p.is_file() for p in (core, factory)
        ):
            continue
        core_tree = _read_ast(core)
        factory_tree = _read_ast(factory)
        if core_tree is None or factory_tree is None:
            continue
        if not {"ToolSet", "ServerSpec"} <= {
            node.name for node in core_tree.body if isinstance(node, ast.ClassDef)
        } or not _registered_factory(factory_tree):
            continue
        for spec in sorted((package / "servers").glob("*/spec.py"))[:32]:
            if not _source_under(root, spec):
                continue
            spec_tree = _read_ast(spec)
            if spec_tree is None:
                continue
            spec_imports = _aliases(root, spec, spec_tree)
            spec_call = _unique_call(
                spec_tree, "SPEC", "ServerSpec",
                spec_imports.get("ServerSpec"), core,
            )
            if spec_call is None:
                continue
            tool_values = [kw.value for kw in spec_call.keywords if kw.arg == "tools"]
            if len(tool_values) != 1 or not isinstance(tool_values[0], ast.Name):
                continue
            tool_source = spec_imports.get(tool_values[0].id)
            if tool_source is None or tool_source[1] != "TOOL_SET":
                continue
            tool_pkg = tool_source[0]
            tool_tree = _read_ast(tool_pkg)
            if tool_tree is None:
                continue
            tool_imports = _aliases(root, tool_pkg, tool_tree)
            set_call = _unique_call(
                tool_tree, "TOOL_SET", "ToolSet",
                tool_imports.get("ToolSet"), core,
            )
            if set_call is None:
                continue
            candidates: list[tuple[str, Path, str, int]] = []
            valid = True
            for bucket in ("read_only", "write"):
                fields = [kw.value for kw in set_call.keywords if kw.arg == bucket]
                if len(fields) != 1 or not isinstance(fields[0], (ast.Tuple, ast.List)):
                    valid = False
                    break
                for symbol in fields[0].elts:
                    if not isinstance(symbol, ast.Name):
                        valid = False
                        break
                    definition = tool_imports.get(symbol.id)
                    if definition is None:
                        valid = False
                        break
                    path, declared_name = definition
                    def_line = _function_location(root, path, declared_name)
                    if def_line is None:
                        valid = False
                        break
                    candidates.append((bucket, path, declared_name, def_line))
                if not valid:
                    break
            if not valid or not candidates:
                # Do not publish an incomplete catalogue under a misleading
                # set of known names when a module member is dynamic/ambiguous.
                continue
            server_id = evidence.entity(
                spec, spec_call.lineno, spec.parent.name,
                SemanticEntityKind.MCP_SERVER, "source_server_spec_candidate",
            )
            for bucket, path, name, line in candidates:
                tool_id = evidence.entity(
                    path, line, name, SemanticEntityKind.TOOL,
                    "source_declared_tool_candidate",
                )
                evidence.edge(server_id, tool_id, tool_pkg, set_call.lineno, bucket)
    return evidence.result()
