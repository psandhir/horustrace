"""Wave B02/B03 passive evidence for dynamic MCP registration and enumeration.

Never imports or executes scanned repositories. Intentionally emits unresolved
catalogue placeholders, not guessed tools or effective agent authority.
"""
from __future__ import annotations

import ast
import os
import re
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
from horustrace.source_native_mcp import (
    IGNORED_DIRS,
    MAX_SOURCE_BYTES,
    MAX_SOURCE_FILES,
    MAX_VISITED_ENTRIES,
    _imports,
    _read_ast,
    _source_files,
)

PARSER_ID = "wave_b_dynamic_mcp_source_v1"


class _Collector:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.entities: dict[str, SemanticEntity] = {}
        self.observations: dict[str, SemanticObservation] = {}
        self.bindings: dict[str, SemanticBinding] = {}

    def add(
        self,
        *,
        source: Path,
        line: int,
        kind: SemanticEntityKind,
        name: str,
        role: str,
        reason: str,
        resolution: SemanticResolution,
        framework: str,
    ) -> str:
        path = source.resolve().relative_to(self.root)
        key = f"{path.as_posix()}:{line}:{name}"
        entity_id = stable_entity_id(
            framework=framework, kind=kind, name=name,
            source_key=path.as_posix(), line=line,
        )
        location = SourceLocation(path, line=line)
        self.entities[entity_id] = SemanticEntity(
            entity_id=entity_id, name=name, kind=kind,
            framework=framework, location=location,
            metadata={"origin": PARSER_ID, "runtime_verified": False},
        )
        observation_id = stable_observation_id(
            entity_id=entity_id, role=role, source_key=key,
        )
        self.observations[observation_id] = SemanticObservation(
            observation_id=observation_id,
            entity_id=entity_id, role=role, resolution=resolution,
            parser_id=PARSER_ID, source_key=key,
            reason=reason, location=location,
        )
        return entity_id

    def edge(
        self, source_id: str, target_id: str, *, source: Path, line: int,
        kind: SemanticBindingKind, basis: str,
        resolution: SemanticResolution,
    ) -> None:
        binding_id = stable_binding_id(
            source_id=source_id, target_id=target_id, kind=kind, basis=basis,
        )
        path = source.resolve().relative_to(self.root)
        self.bindings[binding_id] = SemanticBinding(
            binding_id=binding_id, source_id=source_id, target_id=target_id,
            kind=kind, basis=basis, resolution=resolution,
            location=SourceLocation(path, line=line),
            metadata={
                "origin": PARSER_ID, "runtime_verified": False,
                "catalogue_state": "unresolved_dynamic",
                "agent_callability": "not_adjudicated",
            },
        )

    def result(self) -> SemanticDiscovery:
        result = SemanticDiscovery(
            schema_version=2,
            entities=sorted(self.entities.values(), key=lambda e: e.entity_id),
            bindings=sorted(self.bindings.values(), key=lambda b: b.binding_id),
            observations=sorted(
                self.observations.values(), key=lambda o: o.observation_id,
            ),
        )
        result.validate()
        return result


def _is_name_call(node: ast.AST, aliases: set[str]) -> bool:
    return (
        isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        and node.func.id in aliases
    )


def _registered_factory(tree: ast.Module) -> list[tuple[int, int]]:
    """Return (server constructor line, registration line) for bounded factory flows."""
    fastmcp = _imports(tree, "fastmcp", "FastMCP")
    wrappers = _imports(tree, "fastmcp.tools", "FunctionTool")
    if not fastmcp or not wrappers:
        return []

    matches: list[tuple[int, int]] = []
    for func in tree.body:
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        parameters = {
            arg.arg for arg in (
                func.args.posonlyargs + func.args.args + func.args.kwonlyargs
            )
        }
        # A function-local symbol shadows the original imported wrapper.
        if any(
            isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign))
            and any(
                isinstance(target, ast.Name) and target.id in wrappers
                for target in (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
            )
            for node in ast.walk(func)
        ):
            continue
        servers: dict[str, int] = {}
        for statement in func.body:
            if not (isinstance(statement, ast.Assign)
                    and len(statement.targets) == 1
                    and isinstance(statement.targets[0], ast.Name)
                    and _is_name_call(statement.value, fastmcp)):
                continue
            servers[statement.targets[0].id] = statement.lineno
        # Multiple server objects cannot be matched to an unknown host-selected
        # return value; an alias or reassignment also makes identity ambiguous.
        if len(servers) != 1:
            continue
        symbol, server_line = next(iter(servers.items()))
        assignments = [
            stmt for stmt in ast.walk(func)
            if isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign))
            and any(
                isinstance(target, ast.Name) and target.id == symbol
                for target in (
                    stmt.targets if isinstance(stmt, ast.Assign)
                    else [stmt.target]
                )
            )
        ]
        if len(assignments) != 1:
            continue
        if not any(
            isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Name)
            and stmt.value.id == symbol for stmt in func.body
        ):
            continue
        for loop in func.body:
            if not (
                isinstance(loop, ast.For) and isinstance(loop.target, ast.Name)
                and isinstance(loop.iter, ast.Name)
                and loop.iter.id in parameters
            ):
                continue
            var_name = loop.target.id
            made: dict[str, int] = {}
            for stmt in loop.body:
                if (
                    isinstance(stmt, ast.Assign) and len(stmt.targets) == 1
                    and isinstance(stmt.targets[0], ast.Name)
                    and isinstance(stmt.value, ast.Call)
                    and isinstance(stmt.value.func, ast.Attribute)
                    and stmt.value.func.attr == "from_function"
                    and isinstance(stmt.value.func.value, ast.Name)
                    and stmt.value.func.value.id in wrappers
                    and len(stmt.value.args) >= 1
                    and isinstance(stmt.value.args[0], ast.Name)
                    and stmt.value.args[0].id == var_name
                ):
                    made[stmt.targets[0].id] = stmt.lineno
                if (
                    isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign))
                    and any(
                        isinstance(target, ast.Name) and target.id in made
                        for target in (
                            stmt.targets if isinstance(stmt, ast.Assign)
                            else [stmt.target]
                        )
                    )
                    and not (
                        isinstance(stmt, ast.Assign)
                        and isinstance(stmt.value, ast.Call)
                        and isinstance(stmt.value.func, ast.Attribute)
                        and stmt.value.func.attr == "from_function"
                    )
                ):
                    for target in (
                        stmt.targets if isinstance(stmt, ast.Assign)
                        else [stmt.target]
                    ):
                        if isinstance(target, ast.Name):
                            made.pop(target.id, None)
                if not (isinstance(stmt, ast.Expr)
                        and isinstance(stmt.value, ast.Call)
                        and isinstance(stmt.value.func, ast.Attribute)
                        and stmt.value.func.attr == "add_tool"
                        and isinstance(stmt.value.func.value, ast.Name)
                        and stmt.value.func.value.id == symbol
                        and len(stmt.value.args) == 1
                        and isinstance(stmt.value.args[0], ast.Name)):
                    continue
                if stmt.value.args[0].id in made:
                    matches.append((server_line, stmt.lineno))
    return matches


# C# lexer: remove strings and comments (preserving newlines/offsets) so
# illustrative text cannot claim remote runtime enumeration.
_CS_IGNORED = re.compile(
    r'//[^\n]*|/\*[\s\S]*?\*/|@?"(?:[^"]|"")*"|'
    r'"(?:\\.|[^"\\])*"',
    re.MULTILINE,
)


def _csharp_code(raw: str) -> str:
    return _CS_IGNORED.sub(
        lambda match: "".join("\n" if c == "\n" else " " for c in match.group()),
        raw,
    )


def _csharp_sources(target: Path) -> list[Path]:
    if target.is_file():
        return [target] if target.suffix.lower() == ".cs" else []
    if not target.is_dir():
        return []
    found: list[Path] = []
    visited = 0
    for directory, subdirs, files in os.walk(target, followlinks=False):
        subdirs[:] = sorted(
            n for n in subdirs if n not in IGNORED_DIRS
            and not (Path(directory) / n).is_symlink()
        )
        for name in sorted(files):
            visited += 1
            if visited > MAX_VISITED_ENTRIES or len(found) >= MAX_SOURCE_FILES:
                return found
            candidate = Path(directory) / name
            if name.lower().endswith(".cs") and not candidate.is_symlink():
                found.append(candidate)
    return found


def _csharp_scope_at(source: str, offset: int) -> tuple[int, ...]:
    """Return source block IDs containing a C# token (comments/strings masked)."""
    stack: list[int] = []
    for index, character in enumerate(source[:offset]):
        if character == "{":
            stack.append(index)
        elif character == "}" and stack:
            stack.pop()
    return tuple(stack)


def _csharp_list_tools_line(source: str) -> int | None:
    """Recognize same-lexical-scope MCP client creation -> remote enumeration.

    Conservative source evidence only: refuse reassigned or shadowed clients,
    and refuse joining constructors with calls in unrelated methods or blocks.
    Neither a call site nor its tool catalogue proves successful runtime access.
    """
    constructor_pattern = re.compile(
        r"\bvar\s+([A-Za-z_]\w*)\s*=\s*await\s+"
        r"McpClient\s*\.\s*CreateAsync\s*\("
    )
    for constructor in constructor_pattern.finditer(source):
        name = constructor.group(1)
        declaring_blocks = set(_csharp_scope_at(source, constructor.start()))
        call_pattern = re.compile(
            r"\b" + re.escape(name) + r"\s*\.\s*ListToolsAsync\s*\("
        )
        for call in call_pattern.finditer(source, constructor.end()):
            call_pos = call.start()
            # A local declared inside an inner block does not remain visible
            # after leaving that block; a different method never shares its ID.
            if not declaring_blocks.issubset(
                set(_csharp_scope_at(source, call_pos))
            ):
                continue
            between = source[constructor.end():call_pos]
            # Reject writes to the original client before enumeration; equality
            # comparisons and lambda arrows are not assignments.
            rebinding = re.search(
                r"\b" + re.escape(name)
                + r"\s*(?:\?\?=|[+*/%&|^\-]=|=(?![=>])|\+\+|--)",
                between,
            )
            if rebinding:
                break
            return source.count("\n", 0, call_pos) + 1
    return None


def inspect_dynamic_mcp_registration(target: Path) -> SemanticDiscovery:
    """Conservatively recognize registration pipelines, not live catalogues."""
    root = target.resolve() if target.is_dir() else target.resolve().parent
    evidence = _Collector(root)
    for path in _source_files(target):
        tree = _read_ast(path)
        if tree is None:
            continue
        for server_line, registration_line in _registered_factory(tree):
            server_id = evidence.add(
                source=path, line=server_line, framework="fastmcp-factory",
                kind=SemanticEntityKind.MCP_SERVER,
                name=f"fastmcp_factory:{server_line}",
                role="source_factory_server_constructed",
                reason="FastMCP_constructor_returned_from_factory",
                resolution=SemanticResolution.PARTIAL,
            )
            unknown_id = evidence.add(
                source=path, line=registration_line,
                framework="fastmcp-factory", kind=SemanticEntityKind.UNKNOWN,
                name=f"runtime_selected_tool_catalogue:{registration_line}",
                role="dynamic_factory_tool_registration",
                reason="FunctionTool_from_function_then_add_tool_over_parameter_tools",
                resolution=SemanticResolution.UNRESOLVED,
            )
            evidence.edge(
                server_id, unknown_id, source=path, line=registration_line,
                kind=SemanticBindingKind.CONTAINS,
                basis="factory_registers_parameter_selected_tools_no_static_names",
                resolution=SemanticResolution.PARTIAL,
            )

    for path in _csharp_sources(target):
        try:
            if path.stat().st_size > MAX_SOURCE_BYTES:
                continue
            raw = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        source = _csharp_code(raw)
        if not (
            re.search(r"\busing\s+ModelContextProtocol\.Client\s*;", source)
            and re.search(r"\bnew\s+HttpClientTransport\s*\(", source)
        ):
            continue
        # Match a source-local constructor to its actual client enumeration.
        # Do not infer a catalogue from another method or a rebound variable.
        line = _csharp_list_tools_line(source)
        if line is None:
            continue
        client_id = evidence.add(
            source=path, line=line, framework="dotnet-mcp",
            kind=SemanticEntityKind.MCP_CLIENT,
            name="runtime_mcp_client", role="runtime_mcp_tool_enumeration",
            reason="source_calls_remote_McpClient_ListToolsAsync",
            resolution=SemanticResolution.PARTIAL,
        )
        catalogue = evidence.add(
            source=path, line=line, framework="dotnet-mcp",
            kind=SemanticEntityKind.UNKNOWN,
            name="remote_runtime_tool_catalogue",
            role="runtime_enumerated_tool_catalogue_unresolved",
            reason="tool_names_depend_on_remote_authenticated_runtime_response",
            resolution=SemanticResolution.UNRESOLVED,
        )
        evidence.edge(
            client_id, catalogue, source=path, line=line,
            kind=SemanticBindingKind.DISPATCHES_TO,
            basis="remote_McpClient_ListToolsAsync_catalogue_unresolved",
            resolution=SemanticResolution.UNRESOLVED,
        )
    return evidence.result()
