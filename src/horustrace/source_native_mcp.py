"""Bounded source-native Pydantic MCP client -> local provider registration pilot.

Pure AST reading only: no imports, execution, network, or runtime catalogue
enumeration. The proof concerns source linkage and declared exposure, NOT a
runtime call or effective agent authorization.
"""
from __future__ import annotations

import ast
import os
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

MAX_SOURCE_BYTES = 1_000_000
MAX_SOURCE_FILES = 256
MAX_VISITED_ENTRIES = 8192
IGNORED_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build"}


def _read_ast(path: Path) -> ast.Module | None:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_SOURCE_BYTES:
            return None
        return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return None


def _imports(tree: ast.Module, module_name: str) -> set[str]:
    names: set[str] = set()
    for statement in tree.body:
        if isinstance(statement, ast.ImportFrom) and statement.module == module_name:
            names.update(
                item.asname or item.name
                for item in statement.names if item.name in {"Agent", "MCPServerStdio", "FastMCP"}
            )
    return names


def _assignments(tree: ast.Module) -> dict[str, ast.AST]:
    result: dict[str, ast.AST] = {}
    for item in tree.body:
        if isinstance(item, ast.Assign) and len(item.targets) == 1:
            if isinstance(item.targets[0], ast.Name):
                result[item.targets[0].id] = item.value
    return result


def _registered_provider_tools(tree: ast.Module) -> list[tuple[str, int, str, int]]:
    """Only accept decorators bound to a top-level FastMCP constructor instance."""
    imported = _imports(tree, "mcp.server.fastmcp") | _imports(tree, "fastmcp")
    if "FastMCP" not in imported:
        return []
    servers = {
        name: value.lineno for name, value in _assignments(tree).items()
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
        and value.func.id == "FastMCP"
    }
    tools: list[tuple[str, int, str, int]] = []
    for statement in tree.body:
        if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in statement.decorator_list:
            if (
                isinstance(decorator, ast.Call)
                and isinstance(decorator.func, ast.Attribute)
                and decorator.func.attr == "tool"
                and isinstance(decorator.func.value, ast.Name)
                and decorator.func.value.id in servers
            ):
                # FastMCP `name=` overrides must be literal to be named as such.
                name = statement.name
                overrides = [kw.value for kw in decorator.keywords if kw.arg == "name"]
                if overrides:
                    if len(overrides) != 1 or not isinstance(overrides[0], ast.Constant):
                        continue
                    if not isinstance(overrides[0].value, str):
                        continue
                    name = overrides[0].value
                server_name = decorator.func.value.id
                tools.append((name, statement.lineno, server_name, servers[server_name]))
    return tools


def _static_script(call: ast.AST, imported_mcp: set[str]) -> str | None:
    if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name):
        return None
    if call.func.id not in imported_mcp or not call.args:
        return None
    program = call.args[0]
    if not isinstance(program, ast.Constant) or program.value not in ("python", "python3"):
        return None
    if len(call.args) < 2 or not isinstance(call.args[1], (ast.List, ast.Tuple)):
        return None
    args = call.args[1].elts
    if len(args) != 1 or not isinstance(args[0], ast.Constant):
        return None
    script = args[0].value
    if not isinstance(script, str) or not script.endswith(".py"):
        return None
    relative = Path(script)
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        return None
    return relative.as_posix()


def _source_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    if not root.is_dir():
        return []
    # Sort only one directory at a time: rglob + sorted would enumerate an
    # entire very large third-party checkout before applying any budget.
    files: list[Path] = []
    visited = 0
    for directory, subdirs, names in os.walk(root, followlinks=False):
        subdirs[:] = sorted(
            name for name in subdirs
            if name not in IGNORED_DIRS and not (Path(directory) / name).is_symlink()
        )
        for name in sorted(names):
            visited += 1
            if visited > MAX_VISITED_ENTRIES or len(files) >= MAX_SOURCE_FILES:
                return files
            if not name.endswith(".py"):
                continue
            path = Path(directory) / name
            if not path.is_symlink() and path.is_file():
                files.append(path)
    return files


def _runs_server(tree: ast.Module, symbol: str) -> bool:
    """Require a source-visible process entrypoint invoking this server's run()."""
    def is_run(node: ast.AST) -> bool:
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "run"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == symbol
        )

    def main_guard(node: ast.AST) -> bool:
        if not isinstance(node, ast.If):
            return False
        check = node.test
        if not (isinstance(check, ast.Compare) and len(check.ops) == 1
                and isinstance(check.ops[0], ast.Eq)
                and len(check.comparators) == 1):
            return False
        left, right = check.left, check.comparators[0]
        return (
            isinstance(left, ast.Name) and left.id == "__name__"
            and isinstance(right, ast.Constant) and right.value == "__main__"
        ) or (
            isinstance(right, ast.Name) and right.id == "__name__"
            and isinstance(left, ast.Constant) and left.value == "__main__"
        )

    functions = {
        statement.name: statement
        for statement in tree.body
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    for statement in tree.body:
        # Top-level direct script startup or a guarded main() call.
        if isinstance(statement, ast.Expr) and is_run(statement.value):
            return True
        if not main_guard(statement):
            continue
        for nested in ast.walk(statement):
            if is_run(nested):
                return True
            if (
                isinstance(nested, ast.Call) and isinstance(nested.func, ast.Name)
                and nested.func.id in functions
                and any(is_run(call) for call in ast.walk(functions[nested.func.id]))
            ):
                return True
    return False


class _Evidence:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.entities: dict[str, SemanticEntity] = {}
        self.bindings: dict[str, SemanticBinding] = {}
        self.observations: dict[str, SemanticObservation] = {}

    def entity(
        self, *, name: str, kind: SemanticEntityKind, source: Path, line: int,
        role: str, resolution: SemanticResolution = SemanticResolution.PROVEN,
    ) -> str:
        relative = source.resolve().relative_to(self.root).as_posix()
        key = f"{relative}:{line}:{name}"
        entity_id = stable_entity_id(
            framework="pydantic-ai-local-mcp",
            kind=kind, name=name, source_key=relative, line=line,
        )
        location = SourceLocation(Path(relative), line=line)
        self.entities.setdefault(entity_id, SemanticEntity(
            entity_id=entity_id, name=name, kind=kind,
            framework="pydantic-ai-local-mcp", location=location,
            metadata={"origin": "source_native_ast", "runtime_verified": False},
        ))
        observation_id = stable_observation_id(
            entity_id=entity_id, role=role, source_key=key,
        )
        self.observations[observation_id] = SemanticObservation(
            observation_id=observation_id, entity_id=entity_id, role=role,
            resolution=resolution, parser_id="pydantic_local_mcp_ast_v1",
            source_key=key,
            reason=(
                "static_local_source_declaration"
                if resolution == SemanticResolution.PROVEN
                else "static_source_reference_not_resolved"
            ),
            location=location,
        )
        return entity_id

    def edge(
        self, *, source_id: str, target_id: str, kind: SemanticBindingKind,
        basis: str, path: Path, line: int,
    ) -> None:
        binding_id = stable_binding_id(
            source_id=source_id, target_id=target_id, kind=kind, basis=basis,
        )
        self.bindings[binding_id] = SemanticBinding(
            binding_id=binding_id, source_id=source_id, target_id=target_id,
            kind=kind, basis=basis, resolution=SemanticResolution.PROVEN,
            location=SourceLocation(path.resolve().relative_to(self.root), line=line),
            metadata={
                "origin": "source_native_ast",
                "proves": "source_registration_only",
                "runtime_verified": False,
                "agent_callable": False,
            },
        )

    def result(self) -> SemanticDiscovery:
        discovery = SemanticDiscovery(
            schema_version=2,
            entities=sorted(self.entities.values(), key=lambda x: x.entity_id),
            bindings=sorted(self.bindings.values(), key=lambda x: x.binding_id),
            observations=sorted(
                self.observations.values(), key=lambda x: x.observation_id
            ),
        )
        discovery.validate()
        return discovery


def inspect_local_pydantic_mcp(target: Path) -> SemanticDiscovery:
    """Find explicit local Pydantic agent/MCP composition with hard uncertainty limits."""
    root = target.resolve() if target.is_dir() else target.resolve().parent
    evidence = _Evidence(root)
    for source in _source_files(target):
        try:
            source.resolve().relative_to(root)
        except ValueError:
            continue
        tree = _read_ast(source)
        if tree is None:
            continue
        imported_agents = _imports(tree, "pydantic_ai")
        imported_clients = _imports(tree, "pydantic_ai.mcp")
        if not imported_agents or not imported_clients:
            continue
        assignments = _assignments(tree)
        for agent_name, call in assignments.items():
            if not (
                isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                and call.func.id in imported_agents
            ):
                continue
            keywords = [keyword.value for keyword in call.keywords
                        if keyword.arg == "mcp_servers"]
            if len(keywords) != 1:
                continue
            collection = keywords[0]
            if isinstance(collection, ast.Name):
                collection = assignments.get(collection.id)
            if not isinstance(collection, (ast.List, ast.Tuple)):
                continue
            for candidate in collection.elts:
                script_name = _static_script(candidate, imported_clients)
                if not script_name:
                    continue
                # Local launch script resolved relative to its declaring source.
                candidate_path = (source.parent / script_name).resolve()
                if candidate_path.parent != source.parent.resolve():
                    continue  # conservative pilot; nested/local dynamic cases remain unresolved
                try:
                    candidate_path.relative_to(root)
                except ValueError:
                    continue
                agent_id = evidence.entity(
                    name=agent_name, kind=SemanticEntityKind.AGENT,
                    source=source, line=call.lineno, role="source_agent_with_mcp_collection",
                )
                client_id = evidence.entity(
                    name=f"stdio:{script_name}", kind=SemanticEntityKind.MCP_CLIENT,
                    source=source, line=candidate.lineno,
                    role="pydantic_stdio_client_configuration",
                )
                evidence.edge(
                    source_id=agent_id, target_id=client_id,
                    kind=SemanticBindingKind.AGENT_BINDS_CLIENT,
                    basis="literal_mcp_servers_list_registration",
                    path=source, line=call.lineno,
                )
                provider_tree = _read_ast(candidate_path)
                if provider_tree is None:
                    evidence.observations[next(
                        id_ for id_, row in evidence.observations.items()
                        if row.entity_id == client_id
                    )].resolution = SemanticResolution.UNRESOLVED
                    continue
                registered = _registered_provider_tools(provider_tree)
                if not registered:
                    # Valid source but unknown/dynamic registration is NOT a proof of
                    # empty catalogue. Leave the client without exposure claims.
                    continue
                grouped: dict[tuple[str, int], list[tuple[str, int]]] = {}
                for tool_name, line, server_symbol, server_line in registered:
                    grouped.setdefault((server_symbol, server_line), []).append(
                        (tool_name, line)
                    )
                if len(grouped) != 1:
                    # More than one independent FastMCP object in the script:
                    # a process entrypoint alone does not prove which instance
                    # is served. Keep only the client observation until B02.
                    continue
                (server_symbol, server_line), exposed = next(iter(grouped.items()))
                if not _runs_server(provider_tree, server_symbol):
                    # A single FastMCP declaration is not proof that the process
                    # ever serves that object. Do not assert a client connection.
                    continue
                server_id = evidence.entity(
                    name=f"{script_name}:{server_symbol}",
                    kind=SemanticEntityKind.MCP_SERVER,
                    source=candidate_path, line=server_line,
                    role="local_fastmcp_server_object",
                )
                evidence.edge(
                    source_id=client_id, target_id=server_id,
                    kind=SemanticBindingKind.CLIENT_CONNECTS_TO_SERVER,
                    basis="literal_python_stdio_script_unique_fastmcp_object",
                    path=source, line=candidate.lineno,
                )
                for tool_name, line in exposed:
                    tool_id = evidence.entity(
                        name=tool_name, kind=SemanticEntityKind.TOOL,
                        source=candidate_path, line=line,
                        role="fastmcp_decorated_tool_exposure",
                    )
                    evidence.edge(
                        source_id=server_id, target_id=tool_id,
                        kind=SemanticBindingKind.EXPOSES_TOOL,
                        basis="fastmcp_decorated_function",
                        path=candidate_path, line=line,
                    )
    return evidence.result()
