"""Framework-neutral discovery for schema-declared custom agent tools.

This adapter targets a narrow structural contract used by custom tool
registries: a function decorated with @tool(...) that declares an explicit
name plus description/parameter schema. Bare @tool decorators remain owned by
framework-specific adapters such as LangChain.
"""
from __future__ import annotations

import ast
from pathlib import Path

from horustrace.heuristics import infer_capabilities
from horustrace.models import Graph, SourceLocation, Tool


def _location(path: Path, node: ast.AST) -> SourceLocation:
    return SourceLocation(
        path=path,
        line=getattr(node, "lineno", 1) or 1,
        column=(getattr(node, "col_offset", 0) or 0) + 1,
    )


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


def _call_name(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _schema_tool_decorator(node: ast.FunctionDef | ast.AsyncFunctionDef) -> ast.Call | None:
    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call):
            continue
        if _call_name(decorator.func) != "tool" or isinstance(decorator.func, ast.Attribute):
            continue
        keywords = {item.arg for item in decorator.keywords if item.arg}
        if "name" in keywords and keywords & {"description", "parameters", "schema"}:
            return decorator
    return None


def _kw(call: ast.Call, name: str) -> ast.AST | None:
    for item in call.keywords:
        if item.arg == name:
            return item.value
    return None


def _string(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _function_capabilities(node: ast.FunctionDef | ast.AsyncFunctionDef, name: str) -> set[str]:
    capabilities = set(infer_capabilities(name))
    for child in ast.walk(node):
        if isinstance(child, ast.Delete):
            capabilities.add("destructive.write")
            continue
        if not isinstance(child, ast.Call):
            continue
        called = (_dotted(child.func) or _call_name(child.func) or "").lower()
        leaf = (_call_name(child.func) or "").lower()
        if (
            called.startswith("subprocess.")
            or called in {"os.system", "os.popen", "exec", "eval", "compile"}
            or "create_subprocess_" in called
        ):
            capabilities.add("process.execute")
        if (
            called.startswith(("requests.", "httpx."))
            or "aiohttp" in called
        ):
            capabilities.add("network.external")
            if leaf in {"post", "put", "patch", "delete", "request"}:
                capabilities.add("external.write")
        if leaf in {
            "write",
            "write_text",
            "write_bytes",
            "save",
            "update",
            "insert",
            "put",
            "commit",
        }:
            capabilities.add("data.write")
        if leaf in {"delete", "unlink", "remove", "rmdir", "rmtree"}:
            capabilities.update({"data.write", "destructive.write"})
        if leaf in {
            "read",
            "read_text",
            "read_bytes",
            "get",
            "search",
            "retrieve",
            "fetch",
            "query",
        }:
            capabilities.add("data.read")
    return capabilities


def _scan_tree(path: Path, tree: ast.AST) -> Graph:
    graph = Graph()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        decorator = _schema_tool_decorator(node)
        if decorator is None:
            continue
        name = _string(_kw(decorator, "name")) or node.name
        graph.unbound_tools.append(
            Tool(
                name=name,
                kind="custom_registry_tool",
                capabilities=_function_capabilities(node, name),
                location=_location(path, node),
                metadata={
                    "framework": "custom-tool-registry",
                    "source": "schema_tool_decorator",
                    "definition_name": node.name,
                    "explicit_schema": True,
                    "topology_visible_unbound": True,
                },
            )
        )
    return graph


def is_custom_tool_registry_file(path: Path) -> bool:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return False
    return bool(_scan_tree(path, tree).unbound_tools)


def scan_python_file(path: Path) -> Graph:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return Graph()
    return _scan_tree(path, tree)
