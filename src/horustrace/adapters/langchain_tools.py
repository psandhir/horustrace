"""Static discovery for standalone LangChain tool definitions.

This adapter deliberately discovers tool *existence* without assigning authority.
Repository-level or framework-specific binders may later associate these tools with an
agent when source evidence proves that relationship.
"""
# ruff: noqa: I001

from __future__ import annotations

import ast
from pathlib import Path

from horustrace.heuristics import infer_capabilities
from horustrace.models import Graph, SourceLocation, Tool


_TOOL_MODULES = {
    "langchain_core.tools",
    "langchain_core.tools.base",
    "langchain.tools",
}
_TOOL_EXPORTS = {"tool", "StructuredTool", "Tool"}


def _location(path: Path, node: ast.AST) -> SourceLocation:
    return SourceLocation(
        path=path,
        line=getattr(node, "lineno", 1) or 1,
        column=(getattr(node, "col_offset", 0) or 0) + 1,
    )


def _call_name(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _dotted(node: ast.AST | None) -> str | None:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        return ".".join(reversed(parts))
    return None


def _literal_string(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _kw(call: ast.Call, name: str) -> ast.AST | None:
    return next((item.value for item in call.keywords if item.arg == name), None)


def _imports(tree: ast.AST) -> tuple[set[str], set[str], set[str]]:
    decorator_names: set[str] = set()
    structured_names: set[str] = set()
    tool_class_names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom) or (node.module or "") not in _TOOL_MODULES:
            continue
        for alias in node.names:
            local = alias.asname or alias.name
            if alias.name == "tool":
                decorator_names.add(local)
            elif alias.name == "StructuredTool":
                structured_names.add(local)
            elif alias.name == "Tool":
                tool_class_names.add(local)
    return decorator_names, structured_names, tool_class_names


def is_langchain_tool_file(path: Path) -> bool:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return False
    decorators, structured, tool_classes = _imports(tree)
    return bool(decorators or structured or tool_classes)


def _decorator_name(
    decorator: ast.AST,
    decorator_names: set[str],
) -> tuple[bool, str | None]:
    call = decorator if isinstance(decorator, ast.Call) else None
    base = call.func if call is not None else decorator
    name = _call_name(base)
    if name not in decorator_names:
        return False, None
    explicit = None
    if call is not None:
        if call.args:
            explicit = _literal_string(call.args[0])
        explicit = explicit or _literal_string(_kw(call, "name"))
    return True, explicit


def _name_capabilities(name: str) -> set[str]:
    """Keep name heuristics conservative when "execute" is domain-specific.

    A function such as execute_sqlite_query is not process execution merely
    because its name contains "execute". Strong process-oriented companion
    tokens retain the process capability; concrete process calls are handled
    separately from the function body.
    """
    capabilities = set(infer_capabilities(name))
    tokens = {
        token
        for token in name.lower().replace("-", "_").replace(".", "_").split("_")
        if token
    }
    if "process.execute" in capabilities and not (
        tokens
        & {
            "shell",
            "bash",
            "powershell",
            "command",
            "terminal",
            "exec",
            "process",
            "subprocess",
            "code",
        }
    ):
        capabilities.discard("process.execute")
    return capabilities


def _dynamic_sql_authority(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[bool, bool]:
    """Return (dynamic_sql, commits) for a source-proven DB execution shape."""
    parameters = {
        arg.arg
        for arg in (
            list(node.args.posonlyargs)
            + list(node.args.args)
            + list(node.args.kwonlyargs)
        )
    }
    dynamic_sql = False
    commits = False
    database_context = False

    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        called = (_dotted(child.func) or _call_name(child.func) or "").lower()
        leaf = (_call_name(child.func) or "").lower()
        if called in {"sqlite3.connect", "duckdb.connect"} or called.endswith(
            (".cursor", ".connect")
        ):
            database_context = True
        if leaf == "commit":
            commits = True
        if leaf in {"execute", "executemany", "executescript"} and child.args:
            query = child.args[0]
            dynamic_sql = dynamic_sql or (
                (isinstance(query, ast.Name) and query.id in parameters)
                or not (
                    isinstance(query, ast.Constant)
                    and isinstance(query.value, str)
                )
            )

        # LangChain SQLDatabase.run/run_no_throw forwards SQL text to the
        # underlying database engine. Treat a function parameter that reaches
        # this API as source-proven unconstrained SQL authority. run_no_throw
        # is distinctive; for run(), require a database-like receiver token to
        # avoid classifying arbitrary obj.run(value) methods as SQL.
        if leaf in {"run", "run_no_throw"} and child.args:
            receiver = (
                _dotted(child.func.value)
                if isinstance(child.func, ast.Attribute)
                else None
            )
            receiver_tokens = {
                token
                for token in (receiver or "")
                .lower()
                .replace("-", "_")
                .replace(".", "_")
                .split("_")
                if token
            }
            sql_database_method = leaf == "run_no_throw" or bool(
                receiver_tokens & {"db", "database", "sqldatabase", "sql"}
            )
            if sql_database_method:
                query = child.args[0]
                model_controlled = (
                    isinstance(query, ast.Name) and query.id in parameters
                )
                if model_controlled:
                    database_context = True
                    dynamic_sql = True
                    # SQLDatabase executes arbitrary statements through its
                    # engine transaction boundary; absent a source-visible
                    # read-only restriction, writes/destructive statements are
                    # part of the authority surface.
                    commits = True

    return database_context and dynamic_sql, commits


def _function_capabilities(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[str]:
    capabilities = _name_capabilities(node.name)
    dynamic_sql, commits = _dynamic_sql_authority(node)
    if dynamic_sql:
        # An unconstrained SQL parameter can perform reads. A committed dynamic
        # statement can also modify or destroy database state.
        capabilities.add("data.read")
        if commits:
            capabilities.update({"data.write", "destructive.write"})

    for child in ast.walk(node):
        if isinstance(child, ast.Delete):
            capabilities.add("destructive.write")
            continue
        if not isinstance(child, ast.Call):
            continue
        called = (_dotted(child.func) or _call_name(child.func) or "").lower()
        leaf = (_call_name(child.func) or "").lower()

        if (
            called in {"exec", "eval", "compile", "os.system", "os.popen"}
            or called.startswith("subprocess.")
            or "create_subprocess_" in called
        ):
            capabilities.add("process.execute")

        if called.startswith(("requests.", "httpx.")) or "aiohttp" in called:
            capabilities.add("network.external")
            if leaf in {"post", "put", "patch", "delete"}:
                capabilities.add("external.write")

        if leaf == "open" or called in {"open", "path.open"} or called.endswith(".open"):
            mode_node = child.args[1] if len(child.args) > 1 else _kw(child, "mode")
            mode = _literal_string(mode_node) or "r"
            if any(marker in mode for marker in ("w", "a", "x", "+")):
                capabilities.add("data.write")
            else:
                capabilities.add("data.read")

        if leaf in {"write", "write_text", "write_bytes", "save", "insert", "append"}:
            capabilities.add("data.write")
        if leaf in {"read", "read_text", "read_bytes", "search", "query", "retrieve", "fetch"}:
            capabilities.add("data.read")

    return capabilities


def _tool(
    path: Path,
    node: ast.AST,
    *,
    name: str,
    definition: str | None,
    source: str,
    capabilities: set[str] | None = None,
) -> Tool:
    return Tool(
        name=name,
        kind="langchain_tool",
        capabilities=set(capabilities or _name_capabilities(name)),
        location=_location(path, node),
        metadata={
            "framework": "langchain",
            "structural_tool": True,
            "topology_visible_unbound": True,
            "binding_state": "unbound",
            "discovery_source": source,
            "definition_name": definition,
        },
    )


def _assignment_names(node: ast.Assign | ast.AnnAssign) -> list[str]:
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    return [target.id for target in targets if isinstance(target, ast.Name)]


def _wrapped_function(call: ast.Call) -> str | None:
    value = _kw(call, "func") or _kw(call, "coroutine")
    if value is None and call.args:
        value = call.args[0]
    return _call_name(value)


def scan_python_file(path: Path) -> Graph:
    graph = Graph()
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return graph

    decorator_names, structured_names, tool_class_names = _imports(tree)
    if not (decorator_names or structured_names or tool_class_names):
        return graph

    functions = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    discovered: dict[tuple[str, int], Tool] = {}

    for function in functions.values():
        for decorator in function.decorator_list:
            matched, explicit_name = _decorator_name(decorator, decorator_names)
            if not matched:
                continue
            name = explicit_name or function.name
            tool = _tool(
                path,
                function,
                name=name,
                definition=function.name,
                source="langchain_tool_decorator",
                capabilities=_function_capabilities(function),
            )
            discovered[(tool.name, tool.location.line if tool.location else 1)] = tool
            break

    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        if not isinstance(node.value, ast.Call):
            continue
        call = node.value
        dotted = _dotted(call.func) or ""
        call_name = _call_name(call.func) or ""
        aliases = _assignment_names(node)
        if not aliases:
            continue

        is_structured = (
            dotted.endswith(".from_function")
            and dotted.split(".")[0] in structured_names | tool_class_names
        )
        is_constructor = call_name in structured_names | tool_class_names
        if not (is_structured or is_constructor):
            continue

        definition = _wrapped_function(call)
        explicit_name = _literal_string(_kw(call, "name"))
        name = explicit_name or aliases[0]
        capabilities = (
            _function_capabilities(functions[definition])
            if definition in functions
            else set(infer_capabilities(name))
        )
        tool = _tool(
            path,
            node,
            name=name,
            definition=definition,
            source=(
                "langchain_structured_tool"
                if is_structured
                else "langchain_tool_constructor"
            ),
            capabilities=capabilities,
        )
        discovered[(tool.name, tool.location.line if tool.location else 1)] = tool

    graph.unbound_tools.extend(discovered.values())
    return graph
