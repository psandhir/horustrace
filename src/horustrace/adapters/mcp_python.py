"""Static programmatic MCP discovery for Python source files.

This adapter recognizes common MCP client/server construction patterns without
importing or executing the target application. It is intentionally conservative:
dynamic connection values are retained as coverage uncertainty rather than guessed.
"""
# ruff: noqa: I001

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from horustrace.heuristics import infer_capabilities
from horustrace.models import Graph, MCPServer, ScanDiagnostic, SourceLocation, Tool


_MCP_IMPORT_PREFIXES = (
    "mcp",
    "fastmcp",
    "langchain_mcp_adapters",
    "mcp_use",
)


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


def _target_name(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _dotted(node)
    return None


def _literal(node: ast.AST | None) -> Any:
    if node is None:
        return None
    try:
        return ast.literal_eval(node)
    except (TypeError, ValueError):
        return None


def _kw(call: ast.Call, name: str) -> ast.AST | None:
    return next((item.value for item in call.keywords if item.arg == name), None)


def _uses_mcp(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module.startswith(_MCP_IMPORT_PREFIXES):
                return True
        elif isinstance(node, ast.Import):
            if any(alias.name.startswith(_MCP_IMPORT_PREFIXES) for alias in node.names):
                return True
    return False


def is_mcp_python_file(path: Path) -> bool:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return False
    return _uses_mcp(tree)


def _string(node: ast.AST | None) -> str | None:
    value = _literal(node)
    return value if isinstance(value, str) else None


def _string_list(node: ast.AST | None) -> list[str]:
    value = _literal(node)
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return []


def _dict_entries(node: ast.AST | None) -> dict[str, ast.AST]:
    if not isinstance(node, ast.Dict):
        return {}
    result: dict[str, ast.AST] = {}
    for key, value in zip(node.keys, node.values):
        literal = _literal(key)
        if isinstance(literal, str):
            result[literal] = value
    return result


def _auth_from_headers(node: ast.AST | None) -> tuple[bool | None, list[str]]:
    entries = _dict_entries(node)
    normalized = {key.lower() for key in entries}
    auth_keys = sorted(
        normalized
        & {"authorization", "proxy-authorization", "x-api-key", "x-goog-api-key"}
    )
    if auth_keys:
        return True, auth_keys
    if isinstance(node, ast.Dict):
        return False, []
    return None, []


def _credential_reference(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    if isinstance(node, ast.Call):
        called = (_dotted(node.func) or _call_name(node.func) or "").lower()
        if called in {"os.getenv", "os.environ.get"} and node.args:
            name = _literal(node.args[0])
            if isinstance(name, str):
                return f"env:{name}"
    if (
        isinstance(node, ast.Subscript)
        and (_dotted(node.value) or "").lower() == "os.environ"
    ):
        name = _literal(node.slice)
        if isinstance(name, str):
            return f"env:{name}"
    if isinstance(node, ast.Name):
        return f"variable:{node.id}"
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return "literal"

    references = [
        reference
        for child in ast.iter_child_nodes(node)
        if (reference := _credential_reference(child)) is not None
    ]
    unique = list(dict.fromkeys(references))
    non_literal = [reference for reference in unique if reference != "literal"]
    if len(non_literal) == 1:
        return non_literal[0]
    if not non_literal and len(unique) == 1:
        return unique[0]
    return None


def _auth_credential_source(headers_node: ast.AST | None) -> str | None:
    entries = _dict_entries(headers_node)
    auth_headers = {
        "authorization",
        "proxy-authorization",
        "x-api-key",
        "x-goog-api-key",
    }
    references = [
        reference
        for key, value in entries.items()
        if key.lower() in auth_headers
        if (reference := _credential_reference(value)) is not None
    ]
    unique = list(dict.fromkeys(references))
    return unique[0] if len(unique) == 1 else None


def _server_from_connection_dict(
    path: Path,
    name: str,
    node: ast.AST,
) -> MCPServer | None:
    entries = _dict_entries(node)
    if not entries:
        return None
    command = _string(entries.get("command"))
    url = _string(entries.get("url") or entries.get("server_url"))
    transport = _string(entries.get("transport"))
    if not transport:
        transport = "stdio" if "command" in entries else "streamable-http" if "url" in entries or "server_url" in entries else "unknown"
    authenticated, auth_keys = _auth_from_headers(entries.get("headers"))
    credential_source = _auth_credential_source(entries.get("headers"))
    if url and "headers" not in entries:
        authenticated = False
    allowed_tools = _string_list(
        entries.get("allowed_tools") or entries.get("allowedTools")
    )
    denied_tools = _string_list(
        entries.get("denied_tools") or entries.get("deniedTools")
    )
    return MCPServer(
        name=name,
        transport=transport,
        url=url,
        command=command,
        args=_string_list(entries.get("args")),
        authenticated=authenticated,
        allowed_tools=allowed_tools,
        denied_tools=denied_tools,
        location=_location(path, node),
        metadata={
            "framework": "mcp",
            "source": "python_connection_config",
            "auth_keys": auth_keys,
            "credential_source": credential_source,
            "dynamic_mcp_endpoint": bool(("url" in entries or "server_url" in entries) and url is None),
            "dynamic_command": bool("command" in entries and command is None),
        },
    )


def _stdio_server(path: Path, call: ast.Call, name: str) -> MCPServer:
    command_node = _kw(call, "command")
    command = _string(command_node)
    args_node = _kw(call, "args")
    return MCPServer(
        name=name,
        transport="stdio",
        command=command,
        args=_string_list(args_node),
        authenticated=None,
        location=_location(path, call),
        metadata={
            "framework": "mcp",
            "source": "StdioServerParameters",
            "dynamic_command": command_node is not None and command is None,
        },
    )


def _resolved_assignment(
    node: ast.AST | None,
    assignments: dict[str, ast.AST],
    *,
    visited: set[str] | None = None,
) -> ast.AST | None:
    visited = visited or set()
    if isinstance(node, ast.Name) and node.id in assignments and node.id not in visited:
        return _resolved_assignment(
            assignments[node.id],
            assignments,
            visited=visited | {node.id},
        )
    return node


def _recognized_remote_auth(
    node: ast.AST | None,
    assignments: dict[str, ast.AST],
) -> tuple[bool | None, str | None]:
    resolved = _resolved_assignment(node, assignments)
    if isinstance(resolved, ast.Call):
        called = _call_name(resolved.func) or ""
        if called == "OAuthClientProvider":
            return True, "oauth2.1"
    return None, None


def _http_client_auth_state(
    node: ast.AST | None,
    assignments: dict[str, ast.AST],
) -> tuple[bool | None, str | None]:
    """Resolve explicit httpx client auth without assuming defaults.

    A client is considered source-proven unauthenticated only when source
    constructs httpx.Client/AsyncClient, supplies a statically visible headers
    mapping with no recognized credential header, and does not configure
    auth/cookies. Other client shapes remain unknown.
    """
    resolved = _resolved_assignment(node, assignments)
    if not isinstance(resolved, ast.Call):
        return None, None

    called = _dotted(resolved.func) or _call_name(resolved.func) or ""
    if called not in {"httpx.Client", "httpx.AsyncClient", "Client", "AsyncClient"}:
        return None, None

    if _kw(resolved, "auth") is not None:
        return True, "http-client-auth"
    if _kw(resolved, "cookies") is not None:
        return None, None

    headers_node = _resolved_assignment(_kw(resolved, "headers"), assignments)
    headers = _literal(headers_node)
    if not isinstance(headers, dict):
        return None, None

    header_names = {str(key).lower() for key in headers}
    auth_headers = {
        "authorization",
        "proxy-authorization",
        "x-api-key",
        "x-goog-api-key",
    }
    if header_names & auth_headers:
        return True, "http-header"
    return False, "explicit-http-client-no-auth"


def _remote_client_server(
    path: Path,
    call: ast.Call,
    name: str,
    transport: str,
    assignments: dict[str, ast.AST],
) -> MCPServer:
    url_node = call.args[0] if call.args else _kw(call, "url")
    url = _string(_resolved_assignment(url_node, assignments))
    authenticated, auth_mechanism = _recognized_remote_auth(
        _kw(call, "auth"),
        assignments,
    )
    if authenticated is None:
        authenticated, auth_mechanism = _http_client_auth_state(
            _kw(call, "http_client"),
            assignments,
        )
    metadata: dict[str, Any] = {
        "framework": "mcp",
        "source": _call_name(call.func),
        "dynamic_mcp_endpoint": url_node is not None and url is None,
    }
    if auth_mechanism:
        metadata["auth_mechanism"] = auth_mechanism
    return MCPServer(
        name=name,
        transport=transport,
        url=url,
        authenticated=authenticated,
        location=_location(path, call),
        metadata=metadata,
    )


def _function_tool(path: Path, node: ast.FunctionDef | ast.AsyncFunctionDef, server_aliases: set[str]) -> Tool | None:
    for decorator in node.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if not isinstance(target, ast.Attribute) or target.attr != "tool":
            continue
        receiver = _dotted(target.value) or _call_name(target.value)
        if receiver not in server_aliases:
            continue
        capabilities = set(infer_capabilities(node.name))
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            called = (_dotted(child.func) or _call_name(child.func) or "").lower()
            leaf = (_call_name(child.func) or "").lower()
            if called.startswith("subprocess.") or called in {"os.system", "os.popen"}:
                capabilities.add("process.execute")
            if called.startswith(("requests.", "httpx.")) or "aiohttp" in called:
                capabilities.add("network.external")
                if leaf in {"post", "put", "patch", "delete"}:
                    capabilities.add("external.write")
            if leaf in {"write", "save", "update", "insert", "put", "delete"}:
                capabilities.add("data.write")
            if leaf in {"read", "get", "search", "retrieve", "fetch", "query"}:
                capabilities.add("data.read")
        return Tool(
            name=node.name,
            kind="mcp_exposed_tool",
            capabilities=capabilities,
            location=_location(path, node),
            metadata={
                "framework": "mcp",
                "server": receiver,
                "topology_visible_unbound": True,
                "binding_state": "unbound",
                "discovery_source": "mcp_python_tool_decorator",
            },
        )
    return None


def _custom_mcp_wrapper_classes(tree: ast.AST) -> dict[str, str]:
    """Return source-proven custom MCP wrapper classes and their transport."""
    result: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        lowered = node.name.lower()
        if "mcp" not in lowered or (
            "server" not in lowered and "connection" not in lowered
        ):
            continue

        calls = {
            _call_name(child.func) or ""
            for child in ast.walk(node)
            if isinstance(child, ast.Call)
        }
        strong = {
            "Server",
            "FastMCP",
            "ClientSession",
            "StdioServerParameters",
            "stdio_client",
            "stdio_server",
            "sse_client",
            "sse_client_async",
            "streamable_http_client",
            "streamablehttp_client",
        }
        if not (calls & strong):
            continue

        if calls & {"StdioServerParameters", "stdio_client", "stdio_server"}:
            transport = "stdio"
        elif calls & {"sse_client", "sse_client_async"}:
            transport = "sse"
        elif calls & {"streamable_http_client", "streamablehttp_client"}:
            transport = "streamable-http"
        elif calls & {"Server", "FastMCP"}:
            transport = "server"
        else:
            transport = "unknown"
        result[node.name] = transport
    return result


def scan_python_file(path: Path) -> Graph:
    graph = Graph()
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return graph
    if not _uses_mcp(tree):
        return graph

    assignments: dict[str, ast.AST] = {}
    runtime_commands: set[str] = set()
    server_aliases: set[str] = set()
    servers: list[MCPServer] = []
    clients: set[str] = set()
    run_alias_lines: dict[str, list[int]] = {}
    custom_wrappers = _custom_mcp_wrapper_classes(tree)

    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        names = [name for target in targets if (name := _target_name(target))]
        for name in names:
            if value is not None:
                assignments[name] = value
                if (
                    isinstance(value, ast.Attribute)
                    and _dotted(value) == "sys.executable"
                ):
                    runtime_commands.add(name)
        if not isinstance(value, ast.Call) or not names:
            continue
        name = names[0]
        call_name = _call_name(value.func) or ""

        if call_name in {"FastMCP", "Server"}:
            runtime_name = (
                _string(value.args[0] if value.args else None)
                or _string(_kw(value, "name"))
                or name
            )
            authenticated = True if _kw(value, "auth") is not None or _kw(value, "token_verifier") is not None else None
            servers.append(
                MCPServer(
                    name=runtime_name,
                    transport="server",
                    authenticated=authenticated,
                    location=_location(path, value),
                    metadata={"framework": "mcp", "source": call_name, "alias": name},
                )
            )
            server_aliases.add(name)
        elif call_name in custom_wrappers:
            servers.append(
                MCPServer(
                    name=name,
                    transport=custom_wrappers[call_name],
                    authenticated=None,
                    location=_location(path, value),
                    metadata={
                        "framework": "mcp",
                        "source": "custom_mcp_wrapper_instance",
                        "wrapper_class": call_name,
                    },
                )
            )
        elif call_name == "StdioServerParameters":
            servers.append(_stdio_server(path, value, name))
        elif call_name == "MultiServerMCPClient":
            clients.add(name)
            config_node = value.args[0] if value.args else _kw(value, "connections")
            for server_name, config_node_item in _dict_entries(config_node).items():
                server = _server_from_connection_dict(path, server_name, config_node_item)
                if server:
                    servers.append(server)
        elif call_name in {"MCPClient"} or (_dotted(value.func) or "").endswith("MCPClient.from_dict"):
            clients.add(name)
            config_node = value.args[0] if value.args else _kw(value, "config")
            config_entries = _dict_entries(config_node)
            nested = config_entries.get("mcpServers") or config_entries.get("servers")
            for server_name, config_node_item in _dict_entries(nested).items():
                server = _server_from_connection_dict(path, server_name, config_node_item)
                if server:
                    servers.append(server)


    for node in ast.walk(tree):
        if not isinstance(node, (ast.With, ast.AsyncWith)):
            continue
        for item in node.items:
            if not isinstance(item.context_expr, ast.Call):
                continue
            call_name = _call_name(item.context_expr.func) or ""
            alias = _target_name(item.optional_vars)
            if alias:
                assignments[alias] = item.context_expr
            if call_name == "MultiServerMCPClient" and alias:
                clients.add(alias)
                config_node = (
                    item.context_expr.args[0]
                    if item.context_expr.args
                    else _kw(item.context_expr, "connections")
                )
                for server_name, config_node_item in _dict_entries(config_node).items():
                    server = _server_from_connection_dict(
                        path, server_name, config_node_item
                    )
                    if server:
                        servers.append(server)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        call_name = _call_name(node.func) or ""
        if call_name == "StdioServerParameters":
            if not any(server.location and server.location.line == getattr(node, "lineno", -1) for server in servers):
                servers.append(_stdio_server(path, node, f"stdio@{getattr(node, 'lineno', 1)}"))
        elif call_name in {"sse_client", "sse_client_async"}:
            servers.append(
                _remote_client_server(
                    path,
                    node,
                    f"sse@{getattr(node, 'lineno', 1)}",
                    "sse",
                    assignments,
                )
            )
        elif call_name in {"streamable_http_client", "streamablehttp_client"}:
            servers.append(
                _remote_client_server(
                    path,
                    node,
                    f"http@{getattr(node, 'lineno', 1)}",
                    "streamable-http",
                    assignments,
                )
            )

        if isinstance(node.func, ast.Attribute):
            receiver = _dotted(node.func.value) or _call_name(node.func.value)
            if node.func.attr == "connect_to_server" and receiver in clients:
                server_name = _string(node.args[0] if node.args else None) or f"server@{getattr(node, 'lineno', 1)}"
                command_node = _kw(node, "command")
                url_node = _kw(node, "url")
                command = _string(command_node)
                if (
                    command is None
                    and isinstance(command_node, ast.Name)
                    and command_node.id in runtime_commands
                ):
                    command = "<python-executable>"
                url = _string(url_node)
                transport = "stdio" if command_node is not None else "streamable-http" if url_node is not None else "unknown"
                servers.append(
                    MCPServer(
                        name=server_name,
                        transport=transport,
                        command=command,
                        url=url,
                        args=_string_list(_kw(node, "args")),
                        authenticated=None,
                        location=_location(path, node),
                        metadata={
                            "framework": "mcp",
                            "source": "connect_to_server",
                            "dynamic_command": command_node is not None and command is None,
                            "dynamic_mcp_endpoint": url_node is not None and url is None,
                        },
                    )
                )
            elif node.func.attr == "run" and receiver in server_aliases:
                run_alias_lines.setdefault(receiver, []).append(
                    getattr(node, "lineno", 1) or 1
                )
                transport = _string(_kw(node, "transport"))
                if transport:
                    for server in servers:
                        if server.metadata.get("alias") == receiver:
                            server.transport = transport

    # Python assignment is last-write-wins. When source also proves that an
    # alias is subsequently used to run the MCP server, earlier FastMCP/Server
    # constructions assigned to the same alias are shadowed rather than
    # separate effective server instances. Preserve that provenance on the live
    # object instead of emitting duplicate findings for abandoned instances.
    for alias, run_lines in run_alias_lines.items():
        latest_run = max(run_lines)
        candidates = [
            server
            for server in servers
            if server.metadata.get("alias") == alias
            and server.metadata.get("source") in {"FastMCP", "Server"}
            and server.location is not None
            and server.location.line < latest_run
        ]
        if len(candidates) <= 1:
            continue
        live = max(candidates, key=lambda item: item.location.line if item.location else 0)
        shadowed = [server for server in candidates if server is not live]
        live.metadata["shadowed_constructions"] = [
            {
                "line": server.location.line if server.location else None,
                "name": server.name,
            }
            for server in shadowed
        ]
        servers = [server for server in servers if server not in shadowed]

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            tool = _function_tool(path, node, server_aliases)
            if tool:
                graph.unbound_tools.append(tool)

    tools_by_server: dict[str, list[Tool]] = {}
    for tool in graph.unbound_tools:
        server_alias = str(tool.metadata.get("server") or "")
        if server_alias:
            tools_by_server.setdefault(server_alias, []).append(tool)

    seen: set[tuple[str, str, int]] = set()
    for server in servers:
        server_alias = str(server.metadata.get("alias") or server.name)
        exposed_tools = tools_by_server.get(server_alias, [])
        if exposed_tools:
            server.metadata["discovered_tools"] = [
                {
                    "name": tool.name,
                    "capabilities": sorted(tool.capabilities),
                    "location": (
                        {
                            "path": str(tool.location.path),
                            "line": tool.location.line,
                            "column": tool.location.column,
                        }
                        if tool.location is not None
                        else None
                    ),
                }
                for tool in sorted(exposed_tools, key=lambda item: item.name)
            ]
            server.metadata["discovered_tool_capabilities"] = sorted(
                {
                    capability
                    for tool in exposed_tools
                    for capability in tool.capabilities
                }
            )
        line = server.location.line if server.location else 1
        key = (server.name, server.transport, line)
        if key in seen:
            continue
        seen.add(key)
        server.metadata.setdefault("framework", "mcp")
        server.metadata.setdefault("topology_visible_unbound", True)
        server.metadata.setdefault("binding_state", "unbound")
        server.metadata.setdefault("discovery_source", "mcp_python")
        graph.unbound_mcp_servers.append(server)
        if server.metadata.get("dynamic_command"):
            graph.coverage.diagnostics.append(
                ScanDiagnostic(
                    "dynamic_configuration",
                    f"MCP stdio command for '{server.name}' could not be resolved statically.",
                    server.location,
                )
            )

    return graph
