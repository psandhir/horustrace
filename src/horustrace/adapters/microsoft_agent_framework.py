"""Static Microsoft Agent Framework adapter.

This adapter only parses source; it never imports or executes target code.
It normalizes Microsoft Agent Framework agents, local/function tools, hosted
provider tools, MCP clients, Foundry Toolbox bindings, and agent-as-tool
delegation into HorusTrace's framework-neutral graph.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from horustrace.effect_semantics import (
    http_mutation_capabilities,
    is_local_collection_mutation,
    sql_call_capabilities,
)
from horustrace.heuristics import infer_capabilities
from horustrace.models import (
    Agent,
    Graph,
    MCPServer,
    NetworkDestination,
    SourceLocation,
    Tool,
)

_FRAMEWORK_PREFIX = "agent_framework"
_AGENT_TYPES = {"Agent", "FoundryAgent"}

_MCP_TYPES = {
    "MCPStdioTool": "stdio",
    "MCPStreamableHTTPTool": "streamable-http",
    "MCPWebsocketTool": "websocket",
}

_PROVIDER_TOOL_FACTORIES: dict[str, tuple[str, set[str]]] = {
    "get_web_search_tool": (
        "microsoft_web_search",
        {"data.read", "network.external"},
    ),
    "get_file_search_tool": ("microsoft_file_search", {"data.read"}),
    "get_code_interpreter_tool": (
        "microsoft_code_interpreter",
        {"process.execute", "data.read", "data.write"},
    ),
    "get_shell_tool": (
        "microsoft_shell",
        {"process.execute", "data.read", "data.write", "network.external"},
    ),
    "get_image_generation_tool": (
        "microsoft_image_generation",
        {"external.write", "network.external"},
    ),
}

_HOSTED_TOOL_FUNCTIONS: dict[str, tuple[str, set[str]]] = {
    "web_search_tool": (
        "microsoft_web_search",
        {"data.read", "network.external"},
    ),
    "file_search_tool": ("microsoft_file_search", {"data.read"}),
    "code_interpreter_tool": (
        "microsoft_code_interpreter",
        {"process.execute", "data.read", "data.write"},
    ),
    "hosted_mcp_tool": (
        "microsoft_hosted_mcp",
        {"network.external"},
    ),
}

_SHELL_TOOL_TYPES = {"LocalShellTool", "DockerShellTool"}


def _location(path: Path, node: ast.AST) -> SourceLocation:
    return SourceLocation(
        path=path,
        line=getattr(node, "lineno", 1) or 1,
        column=(getattr(node, "col_offset", 0) or 0) + 1,
    )


def _call_name(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Subscript):
        return _call_name(node.value)
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _dotted(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    if isinstance(node, ast.Subscript):
        return _dotted(node.value)
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        return ".".join(reversed(parts))
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


def _expr(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    try:
        return ast.unparse(node)
    except (AttributeError, ValueError):
        return _dotted(node) or _call_name(node)


def _target_names(node: ast.Assign | ast.AnnAssign) -> list[str]:
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    result: list[str] = []
    for target in targets:
        if isinstance(target, ast.Name):
            result.append(target.id)
        elif isinstance(target, ast.Attribute):
            dotted = _dotted(target)
            if dotted:
                result.append(dotted)
        elif isinstance(target, (ast.List, ast.Tuple)):
            for item in target.elts:
                if isinstance(item, ast.Name):
                    result.append(item.id)
    return result


def _uses_agent_framework(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module == _FRAMEWORK_PREFIX or module.startswith(_FRAMEWORK_PREFIX + "."):
                return True
        elif isinstance(node, ast.Import):
            if any(
                alias.name == _FRAMEWORK_PREFIX
                or alias.name.startswith(_FRAMEWORK_PREFIX + ".")
                for alias in node.names
            ):
                return True
    return False


def is_microsoft_agent_framework_file(path: Path) -> bool:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return False
    return _uses_agent_framework(tree)


def _function_capabilities(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[str]:
    capabilities = set(infer_capabilities(node.name))
    capabilities.difference_update(
        {"process.execute", "network.external", "external.write"}
    )
    body_write = False

    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        dotted = (_dotted(child.func) or _call_name(child.func) or "").lower()
        leaf = (_call_name(child.func) or "").lower()

        sql_caps = sql_call_capabilities(child)
        capabilities.update(sql_caps)
        body_write = body_write or "data.write" in sql_caps

        if (
            dotted in {"exec", "eval", "compile", "builtins.exec", "builtins.eval"}
            or dotted in {"os.system", "os.popen"}
            or dotted.startswith("subprocess.")
            or "create_subprocess_" in dotted
        ):
            capabilities.add("process.execute")

        if dotted.startswith(("requests.", "httpx.", "aiohttp.")) or "urllib" in dotted:
            capabilities.add("network.external")
            mutation = http_mutation_capabilities(child, function_name=node.name)
            capabilities.update(mutation)
            body_write = body_write or "data.write" in mutation

        if leaf in {"write", "save", "insert", "create", "put", "patch", "update"}:
            if not is_local_collection_mutation(child):
                capabilities.add("data.write")
                body_write = True
        if leaf in {"delete", "unlink", "rmdir", "rmtree", "drop", "purge"}:
            if not is_local_collection_mutation(child):
                capabilities.update({"data.write", "destructive.write"})
                body_write = True
        if leaf in {"read", "get", "search", "retrieve", "fetch", "query", "list"}:
            capabilities.add("data.read")
        if (
            "keyvault" in dotted
            or "secretclient" in dotted
            or leaf in {"get_secret", "access_secret"}
        ):
            capabilities.add("secrets.read")

    first = node.name.lower().replace("-", "_").split("_", 1)[0]
    if first in {"add", "set", "update"} and not body_write:
        capabilities.difference_update(
            {"data.write", "destructive.write", "external.write"}
        )
    return capabilities


def _approval(
    node: ast.AST | None,
) -> tuple[bool | None, dict[str, Any]]:
    if node is None:
        return None, {}
    value = _literal(node)
    if value in {"always_require", "always"} or value is True:
        return True, {"approval_mode": value}
    if value in {"never_require", "never"} or value is False:
        return False, {"approval_mode": value}
    if isinstance(value, dict):
        always = value.get("always_require_approval")
        never = value.get("never_require_approval")
        return None, {
            "conditional_approval": True,
            "approval_scope": "per_tool",
            "approval_policy": value,
            "always_require_approval": list(always or []),
            "never_require_approval": list(never or []),
        }
    return None, {
        "conditional_approval": True,
        "approval_scope": "per_call",
        "approval_policy_callable": _expr(node),
    }


def _operator_configured(node: ast.AST | None) -> tuple[bool, str | None]:
    if node is None:
        return False, None
    expression = _expr(node) or ""
    markers = ("os.environ", "os.getenv", "getenv(", "environ.get", "dotenv")
    return any(marker in expression for marker in markers), expression or None


def _mcp_from_call(
    path: Path,
    call: ast.Call,
    *,
    alias: str | None = None,
) -> MCPServer | None:
    kind = _call_name(call.func)
    if kind not in _MCP_TYPES:
        return None

    transport = _MCP_TYPES[kind]
    runtime_name = _literal(_kw(call, "name"))
    server = MCPServer(
        name=str(runtime_name or alias or kind),
        transport=transport,
        location=_location(path, call),
        metadata={"framework": "microsoft-agent-framework", "mcp_class": kind},
    )

    approval, approval_metadata = _approval(_kw(call, "approval_mode"))
    server.approval = approval
    server.metadata.update(approval_metadata)

    allowed = _literal(_kw(call, "allowed_tools"))
    if isinstance(allowed, (list, tuple, set)):
        server.allowed_tools = [str(item) for item in allowed]

    if transport == "stdio":
        command = _literal(_kw(call, "command"))
        args = _literal(_kw(call, "args"))
        if command is None and call.args:
            command = _literal(call.args[0])
        server.command = str(command) if isinstance(command, str) else None
        if isinstance(args, (list, tuple)):
            server.args = [str(item) for item in args]
        return server

    url_node = (
        _kw(call, "url")
        or _kw(call, "endpoint")
        or _kw(call, "server_url")
    )
    if url_node is None and call.args:
        url_node = call.args[0]
    url = _literal(url_node)
    if isinstance(url, str):
        server.url = url
        server.metadata["network_scope"] = "fixed_destination"
    else:
        configured, expression = _operator_configured(url_node)
        if configured:
            server.metadata.update(
                {
                    "dynamic_mcp_endpoint_basis": "operator_configuration",
                    "configuration_source": expression,
                    "network_scope": "operator_configured_destination",
                }
            )
        elif url_node is not None:
            server.metadata.update(
                {
                    "dynamic_mcp_endpoint": True,
                    "endpoint_expression": expression,
                }
            )

    headers = _kw(call, "headers") or _kw(call, "static_headers") or _kw(call, "header_provider")
    server.authenticated = True if headers is not None else None
    if headers is not None:
        server.metadata["authentication_evidence"] = _expr(headers)
    return server


def _tool_from_call(
    path: Path,
    call: ast.Call,
    *,
    alias: str | None = None,
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> Tool | None:
    name = _call_name(call.func)
    dotted = _dotted(call.func) or name or ""
    if not name:
        return None

    if name in _PROVIDER_TOOL_FACTORIES:
        kind, capabilities = _PROVIDER_TOOL_FACTORIES[name]
        return Tool(
            name=alias or name,
            kind=kind,
            capabilities=set(capabilities),
            location=_location(path, call),
            metadata={
                "framework": "microsoft-agent-framework",
                "provider_managed": name != "get_shell_tool",
                "tool_factory": dotted,
            },
        )

    if name in _HOSTED_TOOL_FUNCTIONS:
        kind, capabilities = _HOSTED_TOOL_FUNCTIONS[name]
        tool = Tool(
            name=alias or name,
            kind=kind,
            capabilities=set(capabilities),
            location=_location(path, call),
            metadata={
                "framework": "microsoft-agent-framework",
                "provider_managed": True,
                "tool_factory": dotted,
            },
        )
        if "network.external" in tool.capabilities:
            tool.destinations.append(
                NetworkDestination(
                    target="<microsoft-foundry>",
                    restricted=True,
                    location=tool.location,
                    metadata={
                        "source": "provider_managed",
                        "network_scope": "fixed_provider_network",
                        "provider": "microsoft-foundry",
                    },
                )
            )
        return tool

    if name in _SHELL_TOOL_TYPES:
        return Tool(
            name=alias or name,
            kind="microsoft_local_shell",
            capabilities={"process.execute", "data.read", "data.write", "network.external"},
            location=_location(path, call),
            metadata={
                "framework": "microsoft-agent-framework",
                "shell_tool": name,
            },
        )

    if name == "FunctionTool":
        wrapped = call.args[0] if call.args else _kw(call, "func")
        wrapped_name = _call_name(wrapped) or alias or "function_tool"
        function = functions.get(wrapped_name)
        approval, approval_metadata = _approval(_kw(call, "approval_mode"))
        return Tool(
            name=str(_literal(_kw(call, "name")) or alias or wrapped_name),
            kind="function",
            capabilities=(
                _function_capabilities(function)
                if function is not None
                else set(infer_capabilities(wrapped_name))
            ),
            approval=approval,
            location=_location(path, call),
            metadata={
                "framework": "microsoft-agent-framework",
                "wrapped": wrapped_name,
                **approval_metadata,
            },
        )

    if isinstance(call.func, ast.Attribute) and call.func.attr == "as_tool":
        target = _dotted(call.func.value) or _call_name(call.func.value) or "agent"
        approval, approval_metadata = _approval(_kw(call, "approval_mode"))
        return Tool(
            name=str(_literal(_kw(call, "name")) or alias or target),
            kind="delegated_agent",
            capabilities={"agent.delegate"},
            approval=approval,
            location=_location(path, call),
            metadata={
                "framework": "microsoft-agent-framework",
                "delegate_target": target,
                "binding_origin": "agent_as_tool",
                "propagate_session": bool(_literal(_kw(call, "propagate_session"))),
                **approval_metadata,
            },
        )

    return None


def _tool_from_expr(
    path: Path,
    node: ast.AST,
    *,
    variables: dict[str, ast.AST],
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> tuple[list[Tool], list[MCPServer]]:
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        tools: list[Tool] = []
        servers: list[MCPServer] = []
        for item in node.elts:
            item_tools, item_servers = _tool_from_expr(
                path,
                item,
                variables=variables,
                functions=functions,
            )
            tools.extend(item_tools)
            servers.extend(item_servers)
        return tools, servers

    if isinstance(node, ast.Call):
        server = _mcp_from_call(path, node)
        if server is not None:
            return [], [server]
        tool = _tool_from_call(path, node, functions=functions)
        return ([tool] if tool else []), []

    reference = _dotted(node) or _call_name(node)
    if not reference:
        return [], []
    leaf = reference.rsplit(".", 1)[-1]

    if leaf in variables:
        value = variables[leaf]
        if isinstance(value, ast.Call):
            server = _mcp_from_call(path, value, alias=leaf)
            if server is not None:
                return [], [server]
            tool = _tool_from_call(
                path,
                value,
                alias=leaf,
                functions=functions,
            )
            if tool is not None:
                return [tool], []

    function = functions.get(leaf)
    if function is not None:
        return [
            Tool(
                name=leaf,
                kind="function",
                capabilities=_function_capabilities(function),
                location=_location(path, function),
                metadata={
                    "framework": "microsoft-agent-framework",
                    "binding_origin": "callable",
                },
            )
        ], []

    return [
        Tool(
            name=leaf,
            kind="dynamic_tool_reference",
            capabilities=set(),
            location=_location(path, node),
            metadata={
                "framework": "microsoft-agent-framework",
                "placeholder": True,
                "authority_binding": True,
                "authority_binding_basis": "source_reference",
                "dynamic_tool_catalogue": True,
            },
        )
    ], []


def _foundry_toolbox_server(
    path: Path,
    call: ast.Call,
    *,
    alias: str | None = None,
) -> MCPServer:
    endpoint_node = _kw(call, "endpoint") or _kw(call, "toolbox_endpoint")
    endpoint = _literal(endpoint_node)
    toolbox_name = _literal(_kw(call, "toolbox_name")) or _literal(_kw(call, "name"))
    server = MCPServer(
        name=str(toolbox_name or alias or "foundry-toolbox"),
        transport="foundry-toolbox",
        url=endpoint if isinstance(endpoint, str) else None,
        authenticated=True,
        location=_location(path, call),
        metadata={
            "framework": "microsoft-agent-framework",
            "provider": "microsoft-foundry",
            "foundry_toolbox": True,
            "authentication": "entra",
        },
    )
    if server.url:
        server.metadata["network_scope"] = "fixed_destination"
    else:
        configured, expression = _operator_configured(endpoint_node)
        server.metadata.update(
            {
                "dynamic_mcp_endpoint_basis": "operator_configuration",
                "configuration_source": expression or "foundry_project_configuration",
                "network_scope": "operator_configured_destination",
            }
        )
    return server


def scan_python_file(path: Path) -> Graph:
    graph = Graph()
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return graph
    if not _uses_agent_framework(tree):
        return graph

    functions = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    variables: dict[str, ast.AST] = {}
    toolbox_variables: set[str] = set()

    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        for target in _target_names(node):
            variables[target.rsplit(".", 1)[-1]] = node.value
            if isinstance(node.value, ast.Call) and _call_name(node.value.func) == "FoundryToolbox":
                toolbox_variables.add(target.rsplit(".", 1)[-1])

    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        if not isinstance(node.value, ast.Call):
            continue
        aliases = _target_names(node)
        alias = aliases[0] if aliases else None
        if _call_name(node.value.func) != "FoundryToolbox":
            continue
        graph.unbound_mcp_servers.append(
            _foundry_toolbox_server(path, node.value, alias=alias)
        )

    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        if not isinstance(node.value, ast.Call):
            continue
        call = node.value
        if _call_name(call.func) not in _AGENT_TYPES:
            continue

        targets = _target_names(node)
        runtime_name = _literal(_kw(call, "name"))
        agent_name = str(runtime_name or (targets[0] if targets else "agent"))
        client_node = _kw(call, "client") or (call.args[0] if call.args else None)
        client_expr = _expr(client_node)
        foundry_backed = bool(
            client_expr
            and (
                "Foundry" in client_expr
                or "AzureAI" in client_expr
                or "AzureOpenAI" in client_expr
            )
        ) or _call_name(call.func) == "FoundryAgent"

        agent = Agent(
            name=agent_name,
            location=_location(path, call),
            metadata={
                "framework": "microsoft-agent-framework",
                "agent_type": _call_name(call.func),
                "client": client_expr,
                "provider": "microsoft-foundry" if foundry_backed else None,
                "foundry_backed": foundry_backed,
            },
        )

        tools_node = _kw(call, "tools")
        if tools_node is None:
            default_options = _literal(_kw(call, "default_options"))
            if isinstance(default_options, dict) and "tools" in default_options:
                agent.metadata["default_options_tools_dynamic"] = True

        if tools_node is not None:
            tools, servers = _tool_from_expr(
                path,
                tools_node,
                variables=variables,
                functions=functions,
            )
            agent.tools.extend(tools)
            agent.mcp_servers.extend(servers)

            for ref in {
                _dotted(item) or _call_name(item)
                for item in ast.walk(tools_node)
                if isinstance(item, (ast.Name, ast.Attribute))
            }:
                if not ref:
                    continue
                leaf = ref.rsplit(".", 1)[-1]
                if leaf not in toolbox_variables:
                    continue
                value = variables.get(leaf)
                if isinstance(value, ast.Call):
                    agent.mcp_servers.append(
                        _foundry_toolbox_server(path, value, alias=leaf)
                    )

        graph.agents.append(agent)

    return graph
