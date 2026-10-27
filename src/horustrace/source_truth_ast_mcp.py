"""Independent, source-only AST witness oracle for bounded FastMCP syntax.

Deliberately does not import or call HorusTrace scanner, adapters, Graph, ADG,
or any target module. This verifies Python declaration syntax, not deployed MCP
catalogues or effective agent authority.
"""

from __future__ import annotations

import ast
import hashlib
import json
from collections.abc import Mapping
from typing import Any

_SUPPORTED_DECORATORS = frozenset({"tool", "resource", "prompt"})


def _canonical_id(kind: str, path: str, line: int, name: str) -> str:
    data = json.dumps([kind, path, line, name], separators=(",", ":"))
    return hashlib.sha256(data.encode("utf-8")).hexdigest()[:24]


def _literal_string(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _declaration(node: ast.stmt, imports: set[str]) -> tuple[str, str] | None:
    """Only a module-level, single-target FastMCP constructor qualifies."""
    if not isinstance(node, ast.Assign) or len(node.targets) != 1:
        return None
    target = node.targets[0]
    value = node.value
    if not (isinstance(target, ast.Name) and isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id in imports and value.args):
        return None
    title = _literal_string(value.args[0])
    if not title or not title.strip():
        return None
    return target.id, title


def inspect_mcp_python(path: str, source: str) -> dict[str, Any]:
    """Enumerate bounded module-level FastMCP and decorated-function syntax.

    Dynamic registrations, nested declarations, rebinding and imported objects
    are NOT represented as absence of tools. Unsupported constructs are
    recorded for review rather than guessed.
    """
    if (not isinstance(path, str) or not path.endswith(".py")
            or path.startswith(("/", "./"))
            or "\\" in path or ".." in path.split("/")):
        raise ValueError("unsafe or non-Python source path")
    if not isinstance(source, str):
        raise ValueError("source must be UTF-8 text")
    tree = ast.parse(source, filename=path)
    lines = source.splitlines()
    imports: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module == "mcp.server.fastmcp":
            imports.update(alias.asname or alias.name for alias in node.names
                           if alias.name == "FastMCP")
    implementations: list[dict[str, Any]] = []
    tools: list[dict[str, Any]] = []
    non_tools: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    owners: dict[str, dict[str, Any]] = {}
    for node in tree.body:
        declared = _declaration(node, imports)
        if declared is not None:
            symbol, name = declared
            if symbol in owners:
                unresolved.append({"path": path, "line": node.lineno,
                                   "reason": "duplicate_implementation_symbol"})
                owners.pop(symbol)
                continue
            entry = {
                "id": _canonical_id("implementation", path, node.lineno, symbol),
                "path": path, "line": node.lineno,
                "symbol": symbol, "name": name,
            }
            owners[symbol] = entry
            implementations.append(entry)
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            assigned: list[ast.Name] = []
            if isinstance(node, ast.Assign):
                assigned = [x for target in node.targets for x in ast.walk(target)
                            if isinstance(x, ast.Name)]
            else:
                assigned = [x for x in ast.walk(node.target)
                            if isinstance(x, ast.Name)]
            for name in {x.id for x in assigned} & set(owners):
                unresolved.append({"path": path, "line": node.lineno,
                                   "reason": "implementation_symbol_rebound",
                                   "symbol": name})
                owners.pop(name)
    if unresolved:
        implementations = [x for x in implementations
                           if x["symbol"] in owners]
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            call = decorator if isinstance(decorator, ast.Call) else None
            attr = call.func if call else decorator
            if not (isinstance(attr, ast.Attribute) and
                    isinstance(attr.value, ast.Name) and
                    attr.attr in _SUPPORTED_DECORATORS):
                continue
            symbol = attr.value.id
            if symbol not in owners:
                unresolved.append({
                    "path": path, "line": decorator.lineno,
                    "reason": "unknown_mcp_decorator_owner",
                    "symbol": symbol,
                })
                continue
            if attr.attr != "tool":
                # Resource/prompt declarations are hard-negative TOOL candidates,
                # regardless of their URI/template arguments.
                non_tools.append({
                    "kind": attr.attr, "path": path,
                    "line": node.lineno, "name": node.name,
                    "decorator_line": decorator.lineno,
                    "excluded_from_tool_exports": True,
                })
                continue
            if call is None or call.args:
                unresolved.append({
                    "path": path, "line": decorator.lineno,
                    "reason": "unsupported_mcp_decorator_arguments",
                    "symbol": symbol,
                })
                continue
            keyword_names = [kw.arg for kw in call.keywords]
            if (any(k is None for k in keyword_names)
                    or len(set(keyword_names)) != len(keyword_names)
                    or set(keyword_names) - {"name", "description", "annotations"}):
                unresolved.append({
                    "path": path, "line": decorator.lineno,
                    "reason": "unsupported_mcp_decorator_keywords",
                    "symbol": symbol,
                })
                continue
            if attr.attr == "tool":
                explicit = next((kw.value for kw in call.keywords
                                 if kw.arg == "name"), None)
                exported = node.name if explicit is None else _literal_string(explicit)
                if not exported:
                    unresolved.append({
                        "path": path, "line": decorator.lineno,
                        "reason": "dynamic_tool_export_name",
                        "symbol": symbol,
                    })
                    continue
                tools.append({
                    "id": _canonical_id("tool", path, node.lineno, node.name),
                    "implementation_id": owners[symbol]["id"],
                    "path": path, "line": node.lineno,
                    "name": exported, "function": node.name,
                    "decorator_line": decorator.lineno,
                    "source_only": True,
                })
    # An unrecognized registration API is unresolved, never a negative.
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and
                isinstance(node.func, ast.Attribute) and
                node.func.attr in {"add_tool", "register_tool"}):
            unresolved.append({
                "path": path, "line": node.lineno,
                "reason": "dynamic_registration_not_evaluated",
            })
    return {
        "path": path,
        "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
        "source_line_count": len(lines),
        "implementations": sorted(implementations,
                                  key=lambda x: (x["path"], x["line"])),
        "tools": sorted(tools, key=lambda x: (x["path"], x["line"])),
        "excluded_non_tools": sorted(non_tools,
                                     key=lambda x: (x["path"], x["line"])),
        "unresolved": sorted(unresolved, key=lambda x: (x["path"], x["line"],
                                                        x["reason"])),
    }


def inspect_mcp_scope(files: Mapping[str, str]) -> dict[str, Any]:
    if not files:
        raise ValueError("cannot certify an empty source scope")
    if any(not isinstance(k, str) or not isinstance(v, str)
           for k, v in files.items()):
        raise ValueError("source scope must be path to text")
    per_file = [inspect_mcp_python(path, source)
                for path, source in sorted(files.items())]
    implementations = [row for item in per_file
                       for row in item["implementations"]]
    tools = [row for item in per_file for row in item["tools"]]
    non_tools = [row for item in per_file
                 for row in item["excluded_non_tools"]]
    unresolved = [row for item in per_file
                  for row in item["unresolved"]]
    return {
        "schema_version": 1,
        "mode": "bounded_python_ast_mcp_source_declaration_oracle",
        "scope_files": [item["path"] for item in per_file],
        "scope_digests": {item["path"]: item["source_sha256"]
                          for item in per_file},
        "implementations": implementations,
        "tools": tools,
        "excluded_non_tools": non_tools,
        "unresolved": unresolved,
        "source_scope_complete": not unresolved,
        "complete_scope_kind": "module_level_literal_fastmcp_and_decorated_tools_only",
        "runtime_server_connected": None,
        "runtime_tool_catalogue_verified": False,
        "effective_agent_can_call": None,
        "independent_human_review_verified": False,
        "certified_precision": None,
        "certified_recall": None,
        "production_cutover_authorized": False,
    }
