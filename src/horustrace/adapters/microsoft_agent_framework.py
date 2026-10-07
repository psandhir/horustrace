"""Static Microsoft Agent Framework adapter.

This adapter only parses source; it never imports or executes target code.
It normalizes Microsoft Agent Framework agents, local/function tools, hosted
provider tools, MCP clients, Foundry Toolbox bindings, and agent-as-tool
delegation into HorusTrace's framework-neutral graph.
"""
from __future__ import annotations

import ast
from copy import deepcopy
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
from horustrace.semantic_contract import set_model_provenance

_FRAMEWORK_PREFIX = "agent_framework"
_AGENT_TYPES = {"Agent", "ChatAgent", "FoundryAgent", "create_harness_agent"}

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


def _static_skill_path(
    node: ast.AST | None,
    path: Path,
    variables: dict[str, ast.AST],
    seen: set[str] | None = None,
) -> str | None:
    if node is None:
        return None
    seen = set() if seen is None else seen
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        if node.id == "__file__":
            return str(path)
        if node.id in seen or node.id not in variables:
            return None
        return _static_skill_path(variables[node.id], path, variables, seen | {node.id})
    if isinstance(node, ast.Call):
        called = _call_name(node.func)
        if called == "Path" and node.args:
            return _static_skill_path(node.args[0], path, variables, seen)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "resolve":
            return _static_skill_path(node.func.value, path, variables, seen)
    if isinstance(node, ast.Attribute) and node.attr == "parent":
        base = _static_skill_path(node.value, path, variables, seen)
        return str(Path(base).parent) if base else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        left = _static_skill_path(node.left, path, variables, seen)
        right = _static_skill_path(node.right, path, variables, seen)
        if left and right:
            return str(Path(left) / right)
    return None


def _skill_paths_from_node(
    node: ast.AST | None,
    path: Path,
    variables: dict[str, ast.AST],
) -> list[str]:
    if node is None:
        return []
    if isinstance(node, ast.Name) and node.id in variables:
        return _skill_paths_from_node(variables[node.id], path, variables)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        result: list[str] = []
        for item in node.elts:
            result.extend(_skill_paths_from_node(item, path, variables))
        return list(dict.fromkeys(result))
    if not isinstance(node, ast.Call):
        return []

    dotted = _dotted(node.func) or ""
    called = _call_name(node.func) or ""
    if called == "from_paths" and "SkillsProvider" in dotted:
        raw = _kw(node, "skill_paths") or (node.args[0] if node.args else None)
        if isinstance(raw, (ast.List, ast.Tuple, ast.Set)):
            candidates = list(raw.elts)
        else:
            candidates = [raw] if raw is not None else []
        return [
            value
            for item in candidates
            if (value := _static_skill_path(item, path, variables)) is not None
        ]
    if called == "FileSkillsSource":
        raw = node.args[0] if node.args else _kw(node, "path")
        value = _static_skill_path(raw, path, variables)
        return [value] if value else []
    return []


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


def _agent_framework_imported_symbols(tree: ast.AST) -> set[str]:
    """Return local symbols imported from the Microsoft Agent Framework."""
    result: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module == _FRAMEWORK_PREFIX or module.startswith(
                _FRAMEWORK_PREFIX + "."
            ):
                for alias in node.names:
                    result.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == _FRAMEWORK_PREFIX or alias.name.startswith(
                    _FRAMEWORK_PREFIX + "."
                ):
                    result.add(alias.asname or alias.name.split(".", 1)[0])
    return result


def _is_maf_client_expression(
    node: ast.AST | None,
    *,
    variables: dict[str, ast.AST],
    imported_symbols: set[str],
    seen: set[str] | None = None,
) -> bool:
    if node is None:
        return False
    seen = set(seen or ())

    if isinstance(node, ast.Name):
        if node.id in seen:
            return False
        value = variables.get(node.id)
        if value is None:
            return False
        seen.add(node.id)
        return _is_maf_client_expression(
            value,
            variables=variables,
            imported_symbols=imported_symbols,
            seen=seen,
        )

    if not isinstance(node, ast.Call):
        return False

    name = _call_name(node.func)
    dotted = _dotted(node.func) or ""
    if not name or not name.endswith("Client"):
        return False
    return (
        name in imported_symbols
        or dotted == _FRAMEWORK_PREFIX
        or dotted.startswith(_FRAMEWORK_PREFIX + ".")
    )


def _is_maf_client_create_agent(
    call: ast.Call,
    *,
    variables: dict[str, ast.AST],
    imported_symbols: set[str],
) -> bool:
    return (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "create_agent"
        and _is_maf_client_expression(
            call.func.value,
            variables=variables,
            imported_symbols=imported_symbols,
        )
    )


_MODEL_CLIENT_PROVIDERS = {
    "OpenAIChatClient": "openai",
    "OpenAIResponsesClient": "openai",
    "AzureOpenAIChatClient": "microsoft-azure-openai",
    "AzureOpenAIResponsesClient": "microsoft-azure-openai",
    "FoundryChatClient": "microsoft-foundry",
}


def _client_model_metadata(
    node: ast.AST | None,
    variables: dict[str, ast.AST],
    *,
    seen: set[str] | None = None,
) -> dict[str, Any]:
    """Extract source-visible model facts from a MAF client constructor."""
    seen = set(seen or ())
    if isinstance(node, ast.Name):
        if node.id in seen:
            return {}
        target = variables.get(node.id)
        if target is None:
            return {}
        return _client_model_metadata(
            target,
            variables,
            seen=seen | {node.id},
        )
    if not isinstance(node, ast.Call):
        return {}

    constructor = _call_name(node.func) or ""
    provider = _MODEL_CLIENT_PROVIDERS.get(constructor)
    if provider is None:
        return {}

    raw_model = (
        _kw(node, "model_id")
        or _kw(node, "model")
        or _kw(node, "deployment_name")
        or _kw(node, "deployment")
    )
    model = _literal(raw_model)
    metadata: dict[str, Any] = {}
    set_model_provenance(
        metadata,
        identifier=model if isinstance(model, str) else None,
        provider=provider,
        hosting="provider_hosted",
        constructor=constructor,
    )
    return metadata


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

        if (
            leaf in {"write", "save", "insert", "create", "put", "patch", "update"}
            and not is_local_collection_mutation(child)
        ):
            capabilities.add("data.write")
            body_write = True
        if (
            leaf in {"delete", "unlink", "rmdir", "rmtree", "drop", "purge"}
            and not is_local_collection_mutation(child)
        ):
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
    if value is True or (
        isinstance(value, str) and value in {"always_require", "always"}
    ):
        return True, {"approval_mode": value}
    if value is False or (
        isinstance(value, str) and value in {"never_require", "never"}
    ):
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


def _function_approval(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[bool | None, dict[str, Any]]:
    """Return approval declared by the Agent Framework @tool decorator."""
    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call):
            continue
        if _call_name(decorator.func) != "tool":
            continue
        return _approval(_kw(decorator, "approval_mode"))
    return None, {}


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
    hosted = kind == "get_mcp_tool" and isinstance(call.func, ast.Attribute)
    if kind not in _MCP_TYPES and not hosted:
        return None

    transport = "hosted" if hosted else _MCP_TYPES[kind]
    runtime_name = _literal(_kw(call, "name"))
    if runtime_name is None and call.args:
        positional_name = _literal(call.args[0])
        if isinstance(positional_name, str):
            runtime_name = positional_name

    metadata: dict[str, Any] = {
        "framework": "microsoft-agent-framework",
        "mcp_class": kind,
    }
    if hosted:
        metadata.update(
            {
                "provider_managed": True,
                "hosted_mcp": True,
                "tool_factory": _dotted(call.func) or kind,
            }
        )

    server = MCPServer(
        name=str(runtime_name or alias or kind),
        transport=transport,
        location=_location(path, call),
        metadata=metadata,
    )

    approval, approval_metadata = _approval(_kw(call, "approval_mode"))
    server.approval = approval
    server.metadata.update(approval_metadata)

    allowed = _literal(_kw(call, "allowed_tools"))
    if isinstance(allowed, (list, tuple, set)):
        server.allowed_tools = [str(item) for item in allowed]

    if transport == "stdio":
        # Agent Framework's canonical signature is
        # MCPStdioTool(name=..., command=..., args=[...]). Never reinterpret the
        # positional server name as a process command.
        command = _literal(_kw(call, "command"))
        args = _literal(_kw(call, "args"))
        server.command = str(command) if isinstance(command, str) else None
        if isinstance(args, (list, tuple)):
            server.args = [str(item) for item in args]
        return server

    url_node = _kw(call, "url") or _kw(call, "endpoint") or _kw(call, "server_url")
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

    headers = (
        _kw(call, "headers")
        or _kw(call, "static_headers")
        or _kw(call, "header_provider")
        or _kw(call, "http_client")
    )
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
        approval_node = _kw(call, "approval_mode")
        if approval_node is not None:
            approval, approval_metadata = _approval(approval_node)
        elif function is not None:
            approval, approval_metadata = _function_approval(function)
        else:
            approval, approval_metadata = (None, {})
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
        if _call_name(node.func) == "FoundryToolbox":
            return [], [_foundry_toolbox_server(path, node)]
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
            if _call_name(value.func) == "FoundryToolbox":
                return [], [_foundry_toolbox_server(path, value, alias=leaf)]
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
        approval, approval_metadata = _function_approval(function)
        return [
            Tool(
                name=leaf,
                kind="function",
                capabilities=_function_capabilities(function),
                approval=approval,
                location=_location(path, function),
                metadata={
                    "framework": "microsoft-agent-framework",
                    "binding_origin": "callable",
                    **approval_metadata,
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
        _configured, expression = _operator_configured(endpoint_node)
        server.metadata.update(
            {
                "dynamic_mcp_endpoint_basis": "operator_configuration",
                "configuration_source": expression or "foundry_project_configuration",
                "network_scope": "operator_configured_destination",
            }
        )
    return server


def _tool_key(tool: Tool) -> tuple[str, str, str]:
    return (
        tool.name,
        tool.kind,
        str(tool.metadata.get("delegate_target") or ""),
    )


def _server_key(server: MCPServer) -> tuple[str, str, str, str]:
    return (
        server.name,
        server.transport,
        server.url or "",
        server.command or "",
    )


def _attach_tools(
    agent: Agent,
    tools: list[Tool],
    servers: list[MCPServer],
    *,
    runtime: bool = False,
) -> None:
    tool_keys = {_tool_key(tool) for tool in agent.tools}
    server_keys = {_server_key(server) for server in agent.mcp_servers}
    for tool in tools:
        key = _tool_key(tool)
        if key in tool_keys:
            continue
        if runtime:
            tool.metadata["runtime_tool_binding"] = True
        agent.tools.append(tool)
        tool_keys.add(key)
    for server in servers:
        key = _server_key(server)
        if key in server_keys:
            continue
        if runtime:
            server.metadata["runtime_tool_binding"] = True
        agent.mcp_servers.append(server)
        server_keys.add(key)


def _propagate_microsoft_delegation(graph: Graph) -> None:
    """Project source-proven Agent.as_tool delegation onto effective authority."""
    agents = [
        agent
        for agent in graph.agents
        if agent.metadata.get("framework") == "microsoft-agent-framework"
    ]
    aliases: dict[str, list[Agent]] = {}
    for agent in agents:
        aliases.setdefault(agent.name, []).append(agent)
        for alias in agent.metadata.get("source_aliases") or []:
            aliases.setdefault(str(alias), []).append(agent)

    for _ in range(8):
        changed = False
        for parent in agents:
            for tool in parent.tools:
                if tool.kind != "delegated_agent":
                    continue
                target = tool.metadata.get("delegate_target")
                if not isinstance(target, str):
                    continue
                candidates = [
                    candidate
                    for candidate in aliases.get(target, [])
                    if candidate is not parent
                ]
                unique = []
                for candidate in candidates:
                    if candidate not in unique:
                        unique.append(candidate)
                if len(unique) != 1:
                    continue
                child = unique[0]
                before = (
                    frozenset(tool.capabilities),
                    len(tool.resources),
                    len(tool.destinations),
                )
                tool.capabilities.update(child.capabilities)
                tool.capabilities.add("agent.delegate")
                resource_keys = {
                    (
                        item.kind,
                        item.selector,
                        tuple(sorted(item.access)),
                        item.classification,
                    )
                    for item in tool.resources
                }
                for item in child.effective_resources:
                    key = (
                        item.kind,
                        item.selector,
                        tuple(sorted(item.access)),
                        item.classification,
                    )
                    if key not in resource_keys:
                        copied = deepcopy(item)
                        copied.metadata = {**copied.metadata, "via_agent": child.name}
                        tool.resources.append(copied)
                        resource_keys.add(key)
                destination_keys = {
                    (item.target, item.direction, item.restricted)
                    for item in tool.destinations
                }
                for item in child.effective_destinations:
                    key = (item.target, item.direction, item.restricted)
                    if key not in destination_keys:
                        copied = deepcopy(item)
                        copied.metadata = {**copied.metadata, "via_agent": child.name}
                        tool.destinations.append(copied)
                        destination_keys.add(key)
                tool.metadata["delegated_agent_targets"] = [child.name]
                tool.metadata["authority_binding"] = "delegation_projection"
                tool.metadata["authority_binding_basis"] = "microsoft_agent_as_tool"
                after = (
                    frozenset(tool.capabilities),
                    len(tool.resources),
                    len(tool.destinations),
                )
                changed = changed or before != after
        if not changed:
            break


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
    declared_servers: dict[str, MCPServer] = {}
    agent_specs: list[tuple[ast.Call, list[str]]] = []
    imported_symbols = _agent_framework_imported_symbols(tree)

    # Resolve assignments before classifying factory calls so client aliases
    # work regardless of source ordering.
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        for target in _target_names(node):
            variables[target.rsplit(".", 1)[-1]] = node.value

    # Capture ordinary assignments first.
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        targets = _target_names(node)
        for target in targets:
            alias = target.rsplit(".", 1)[-1]
            variables[alias] = node.value
        if not isinstance(node.value, ast.Call):
            continue
        call_name = _call_name(node.value.func)
        aliases = [target.rsplit(".", 1)[-1] for target in targets]
        if call_name in _AGENT_TYPES or _is_maf_client_create_agent(
            node.value,
            variables=variables,
            imported_symbols=imported_symbols,
        ):
            agent_specs.append((node.value, aliases))
        elif aliases:
            alias = aliases[0]
            if call_name == "FoundryToolbox":
                declared_servers[alias] = _foundry_toolbox_server(
                    path, node.value, alias=alias
                )
            else:
                server = _mcp_from_call(path, node.value, alias=alias)
                if server is not None:
                    declared_servers[alias] = server

    # Agent Framework's canonical samples frequently construct MCP/shell tools
    # and Agents as context managers. Preserve the "as name" binding exactly as
    # an assignment so later tools=... and agent.run(..., tools=...) resolution
    # works without executing the target.
    for node in ast.walk(tree):
        if not isinstance(node, ast.withitem) or not isinstance(node.context_expr, ast.Call):
            continue
        alias = _dotted(node.optional_vars) or _call_name(node.optional_vars)
        aliases = [alias] if alias else []
        if alias:
            variables[alias.rsplit(".", 1)[-1]] = node.context_expr
        call_name = _call_name(node.context_expr.func)
        if call_name in _AGENT_TYPES:
            agent_specs.append((node.context_expr, aliases))
        elif alias:
            leaf = alias.rsplit(".", 1)[-1]
            if call_name == "FoundryToolbox":
                declared_servers[leaf] = _foundry_toolbox_server(
                    path, node.context_expr, alias=leaf
                )
            else:
                server = _mcp_from_call(path, node.context_expr, alias=leaf)
                if server is not None:
                    declared_servers[leaf] = server

    # Provider clients also expose create_agent(...). This can appear inside
    # return statements rather than assignments, so collect any remaining
    # source-proven Agent Framework client factories without treating arbitrary
    # create_agent methods as framework agents.
    known_agent_calls = {id(call) for call, _ in agent_specs}
    for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
        if id(call) in known_agent_calls:
            continue
        if _is_maf_client_create_agent(
            call,
            variables=variables,
            imported_symbols=imported_symbols,
        ):
            agent_specs.append((call, []))
            known_agent_calls.add(id(call))

    agents_by_alias: dict[str, Agent] = {}
    bound_references: set[str] = set()

    for call, aliases in agent_specs:
        runtime_name = _literal(_kw(call, "name"))
        alias = aliases[0] if aliases else None
        agent_name = str(runtime_name or alias or "agent")
        client_factory = _is_maf_client_create_agent(
            call,
            variables=variables,
            imported_symbols=imported_symbols,
        )
        client_node = (
            call.func.value
            if client_factory and isinstance(call.func, ast.Attribute)
            else (_kw(call, "client") or (call.args[0] if call.args else None))
        )
        client_expr = _expr(client_node)
        foundry_backed = (
            _call_name(call.func) == "FoundryAgent"
            or bool(
                client_expr
                and (
                    "Foundry" in client_expr
                    or "AzureAI" in client_expr
                    or "AzureOpenAI" in client_expr
                )
            )
        )

        agent = Agent(
            name=agent_name,
            location=_location(path, call),
            metadata={
                "framework": "microsoft-agent-framework",
                "agent_type": (
                    "client.create_agent"
                    if client_factory
                    else _call_name(call.func)
                ),
                "client": client_expr,
                "binding_origin": (
                    "agent_framework_client.create_agent"
                    if client_factory
                    else None
                ),
                "provider": "microsoft-foundry" if foundry_backed else None,
                "foundry_backed": foundry_backed,
                "source_aliases": list(aliases),
            },
        )
        agent.metadata.update(_client_model_metadata(client_node, variables))

        skill_paths: list[str] = []
        if _call_name(call.func) == "create_harness_agent":
            raw_skill_paths = _kw(call, "skills_paths")
            if isinstance(raw_skill_paths, (ast.List, ast.Tuple, ast.Set)):
                skill_nodes = list(raw_skill_paths.elts)
            else:
                skill_nodes = [raw_skill_paths] if raw_skill_paths is not None else []
            for skill_node in skill_nodes:
                value = _static_skill_path(skill_node, path, variables)
                if value:
                    skill_paths.append(value)
        context_providers = _kw(call, "context_providers")
        if isinstance(context_providers, (ast.List, ast.Tuple, ast.Set)):
            provider_nodes = list(context_providers.elts)
        else:
            provider_nodes = [context_providers] if context_providers is not None else []
        for provider_node in provider_nodes:
            skill_paths.extend(_skill_paths_from_node(provider_node, path, variables))
        if skill_paths:
            agent.metadata["skill_source_paths"] = list(dict.fromkeys(skill_paths))

        tools_node = _kw(call, "tools")
        if tools_node is not None:
            for item in ast.walk(tools_node):
                if isinstance(item, (ast.Name, ast.Attribute)):
                    ref = _dotted(item) or _call_name(item)
                    if ref:
                        bound_references.add(ref.rsplit(".", 1)[-1])
            tools, servers = _tool_from_expr(
                path,
                tools_node,
                variables=variables,
                functions=functions,
            )
            _attach_tools(agent, tools, servers)
        else:
            default_options = _literal(_kw(call, "default_options"))
            if isinstance(default_options, dict) and "tools" in default_options:
                agent.metadata["default_options_tools_dynamic"] = True

        graph.agents.append(agent)
        for source_alias in aliases:
            agents_by_alias[source_alias.rsplit(".", 1)[-1]] = agent
        agents_by_alias.setdefault(agent.name, agent)

    # Per-run tools are a first-class Agent Framework authority surface:
    # await agent.run(..., tools=mcp_server). Keep them attached to the exact
    # source-proven agent variable and mark the binding as runtime-scoped.
    for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
        if not isinstance(call.func, ast.Attribute) or call.func.attr != "run":
            continue
        owner = _dotted(call.func.value) or _call_name(call.func.value)
        if not owner:
            continue
        agent = agents_by_alias.get(owner.rsplit(".", 1)[-1])
        if agent is None:
            continue
        tools_node = _kw(call, "tools")
        if tools_node is None:
            continue
        for item in ast.walk(tools_node):
            if isinstance(item, (ast.Name, ast.Attribute)):
                ref = _dotted(item) or _call_name(item)
                if ref:
                    bound_references.add(ref.rsplit(".", 1)[-1])
        tools, servers = _tool_from_expr(
            path,
            tools_node,
            variables=variables,
            functions=functions,
        )
        _attach_tools(agent, tools, servers, runtime=True)
        if tools or servers:
            agent.metadata["runtime_tool_bindings"] = (
                int(agent.metadata.get("runtime_tool_bindings") or 0) + 1
            )

    for alias, server in declared_servers.items():
        if alias not in bound_references:
            graph.unbound_mcp_servers.append(server)

    _propagate_microsoft_delegation(graph)
    return graph
