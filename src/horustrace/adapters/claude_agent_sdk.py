from __future__ import annotations

import ast
from copy import deepcopy
from pathlib import Path
from typing import Any

from horustrace.coverage import add_diagnostic
from horustrace.effect_semantics import (
    http_mutation_capabilities,
    is_local_collection_mutation,
    sql_call_capabilities,
)
from horustrace.heuristics import corroborate_name_inferred_authority, infer_capabilities
from horustrace.models import (
    Agent,
    Graph,
    MCPServer,
    NetworkDestination,
    ResourceScope,
    ScanDiagnostic,
    SourceLocation,
    Tool,
)

FRAMEWORK = "claude-agent-sdk"

_BUILTIN_TOOLS: dict[str, tuple[str, set[str]]] = {
    "Read": ("filesystem_read", {"data.read"}),
    "Glob": ("filesystem_search", {"data.read"}),
    "Grep": ("filesystem_search", {"data.read"}),
    "Write": ("filesystem_write", {"data.write"}),
    "Edit": ("filesystem_write", {"data.read", "data.write"}),
    "NotebookEdit": ("notebook_edit", {"data.read", "data.write"}),
    "Bash": ("shell", {"process.execute", "data.read", "data.write", "network.external"}),
    "WebFetch": ("web_fetch", {"data.read", "network.external"}),
    "WebSearch": ("web_search", {"data.read", "network.external"}),
    "Agent": ("delegated_agent_runtime", {"agent.delegate"}),
    "AskUserQuestion": ("user_interaction", set()),
    "Monitor": ("task_monitor", {"data.read"}),
    "TodoWrite": ("task_state", {"data.write"}),
    "TaskCreate": ("task_state", {"data.write"}),
    "TaskUpdate": ("task_state", {"data.read", "data.write"}),
    "TaskGet": ("task_state", {"data.read"}),
    "TaskList": ("task_state", {"data.read"}),
    "TaskStop": ("task_control", {"process.execute"}),
    "ExitPlanMode": ("plan_control", set()),
    "ListMcpResourcesTool": ("mcp_resource", {"data.read"}),
    "ReadMcpResourceTool": ("mcp_resource", {"data.read"}),
}

_SECURITY_RELEVANT_DEFAULT_TOOLS = (
    "Read",
    "Glob",
    "Grep",
    "Write",
    "Edit",
    "NotebookEdit",
    "Bash",
    "WebFetch",
    "WebSearch",
    "Agent",
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
    if isinstance(node, ast.Subscript):
        return _call_name(node.value)
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
    except (ValueError, TypeError):
        return None


def _expr_key(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _dotted(node)
    return None


def _targets(node: ast.Assign | ast.AnnAssign) -> list[str]:
    raw = node.targets if isinstance(node, ast.Assign) else [node.target]
    result: list[str] = []
    for target in raw:
        key = _expr_key(target)
        if key:
            result.append(key)
    return result


def _dict_nodes(node: ast.AST | None) -> dict[str, ast.AST]:
    if not isinstance(node, ast.Dict):
        return {}
    result: dict[str, ast.AST] = {}
    for key, value in zip(node.keys, node.values):
        key_value = _literal(key)
        if isinstance(key_value, str):
            result[key_value] = value
    return result


def _resolve_node(
    node: ast.AST | None,
    values: dict[str, ast.AST] | None = None,
) -> ast.AST | None:
    current = node
    seen: set[str] = set()
    for _ in range(6):
        if current is None:
            return None
        key = _expr_key(current)
        if not key or not values or key not in values or key in seen:
            return current
        seen.add(key)
        current = values[key]
    return current


def _mapping_entries(
    node: ast.AST | None,
    dicts: dict[str, ast.Dict],
    values: dict[str, ast.AST] | None = None,
) -> dict[str, ast.AST]:
    current = _resolve_node(node, values)
    key = _expr_key(current)
    if key and key in dicts:
        current = dicts[key]
    return _dict_nodes(current)


def _kw(
    call: ast.Call,
    name: str,
    dicts: dict[str, ast.Dict] | None = None,
    values: dict[str, ast.AST] | None = None,
) -> ast.AST | None:
    direct = next((item.value for item in call.keywords if item.arg == name), None)
    if direct is not None:
        return direct
    if not dicts:
        return None
    for item in call.keywords:
        if item.arg is not None:
            continue
        entries = _mapping_entries(item.value, dicts, values)
        if name in entries:
            return entries[name]
    return None


def _resolved_literal(
    node: ast.AST | None,
    values: dict[str, ast.AST] | None = None,
) -> Any:
    current = _resolve_node(node, values)
    if (
        isinstance(current, ast.Call)
        and _call_name(current.func) == "cast"
        and len(current.args) >= 2
    ):
        current = _resolve_node(current.args[1], values)
    return _literal(current)


def _list_nodes(
    node: ast.AST | None,
    sequences: dict[str, list[ast.AST]],
    values: dict[str, ast.AST] | None = None,
) -> list[ast.AST]:
    current = _resolve_node(node, values)
    if isinstance(current, (ast.List, ast.Tuple, ast.Set)):
        result: list[ast.AST] = []
        for item in current.elts:
            if isinstance(item, ast.Starred):
                result.extend(_list_nodes(item.value, sequences, values))
            else:
                result.append(item)
        return result
    if isinstance(current, ast.BinOp) and isinstance(current.op, ast.Add):
        return _list_nodes(current.left, sequences, values) + _list_nodes(
            current.right, sequences, values
        )
    key = _expr_key(current)
    if key:
        return list(sequences.get(key, []))
    return []


def _string_list(
    node: ast.AST | None,
    sequences: dict[str, list[ast.AST]],
    values: dict[str, ast.AST] | None = None,
) -> list[str] | None:
    elements = _list_nodes(node, sequences, values)
    current = _resolve_node(node, values)
    if not elements and current is not None:
        literal = _literal(current)
        if isinstance(literal, (list, tuple, set)):
            return [str(item) for item in literal if isinstance(item, str)]
        return None
    resolved: list[str] = []
    for element in elements:
        value = _resolved_literal(element, values)
        if not isinstance(value, str):
            return None
        resolved.append(value)
    return resolved


def _expr_reference(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    try:
        return ast.unparse(node)
    except (AttributeError, ValueError):
        return _dotted(node) or _call_name(node)


def _uses_claude_agent_sdk(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module == "claude_agent_sdk" or module.startswith("claude_agent_sdk."):
                return True
        elif isinstance(node, ast.Import):
            if any(
                alias.name == "claude_agent_sdk"
                or alias.name.startswith("claude_agent_sdk.")
                for alias in node.names
            ):
                return True
    return False


def is_claude_agent_sdk_file(path: Path) -> bool:
    if path.suffix.lower() != ".py":
        return False
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return False
    return _uses_claude_agent_sdk(tree)


def _function_capabilities(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[str]:
    name_capabilities = set(infer_capabilities(node.name))
    body_capabilities: set[str] = set()

    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        dotted = (_dotted(child.func) or _call_name(child.func) or "").lower()
        leaf = (_call_name(child.func) or "").lower()

        sql_capabilities = sql_call_capabilities(child)
        if sql_capabilities:
            body_capabilities.update(sql_capabilities)

        if (
            dotted in {
                "exec",
                "eval",
                "compile",
                "builtins.exec",
                "builtins.eval",
                "builtins.compile",
                "os.system",
                "os.popen",
            }
            or dotted.startswith("subprocess.")
            or "create_subprocess_" in dotted
        ):
            body_capabilities.add("process.execute")

        if dotted.startswith(("requests.", "httpx.", "aiohttp.")) or "urllib" in dotted:
            body_capabilities.add("network.external")
            body_capabilities.update(http_mutation_capabilities(child, function_name=node.name))

        if leaf == "open":
            mode = _literal(child.args[1]) if len(child.args) > 1 else None
            if not isinstance(mode, str):
                mode = "r"
            body_capabilities.add(
                "data.write" if any(flag in mode for flag in "wax+") else "data.read"
            )

        local_collection = is_local_collection_mutation(child)
        if (
            leaf in {"write", "save", "insert", "create", "update", "put", "patch"}
            and not local_collection
        ):
            body_capabilities.add("data.write")
        if (
            leaf in {"delete", "remove", "unlink", "rmdir", "rmtree", "drop", "purge"}
            and not local_collection
        ):
            body_capabilities.update({"data.write", "destructive.write"})
        if leaf in {"read", "get", "search", "retrieve", "fetch", "query", "list"}:
            body_capabilities.add("data.read")
        if (
            "secretmanager" in dotted
            or "vault" in dotted
            or leaf in {"get_secret", "access_secret_version"}
        ):
            body_capabilities.add("secrets.read")

    capabilities, _ = corroborate_name_inferred_authority(
        name_capabilities,
        body_capabilities,
    )
    capabilities.update(body_capabilities)
    return capabilities


def _tool_annotations(call: ast.Call) -> dict[str, Any]:
    node = _kw(call, "annotations")
    if node is None:
        return {}
    literal = _literal(node)
    if isinstance(literal, dict):
        return {"tool_annotations": literal}
    if isinstance(node, ast.Call) and _call_name(node.func) == "ToolAnnotations":
        values: dict[str, Any] = {}
        for keyword in node.keywords:
            if keyword.arg:
                value = _literal(keyword.value)
                if value is not None:
                    values[keyword.arg] = value
        if values:
            return {"tool_annotations": values}
    return {"tool_annotations_dynamic": True}


def _custom_tool(
    path: Path,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> Tool | None:
    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call) or _call_name(decorator.func) != "tool":
            continue
        runtime_name = (
            _literal(decorator.args[0])
            if decorator.args
            else _literal(_kw(decorator, "name"))
        )
        tool = Tool(
            name=str(runtime_name or node.name),
            kind="claude_sdk_mcp_tool",
            capabilities=_function_capabilities(node),
            location=_location(path, node),
            metadata={
                "framework": FRAMEWORK,
                "source_function": node.name,
                "sdk_tool": True,
                **_tool_annotations(decorator),
            },
        )
        return tool
    return None


def _builtin_tool(path: Path, name: str, location: SourceLocation) -> Tool:
    kind, capabilities = _BUILTIN_TOOLS.get(
        name,
        ("claude_builtin_or_configured_tool", set(infer_capabilities(name))),
    )
    tool = Tool(
        name=name,
        kind=kind,
        capabilities=set(capabilities),
        location=location,
        metadata={
            "framework": FRAMEWORK,
            "claude_builtin": name in _BUILTIN_TOOLS,
        },
    )
    if name == "WebFetch":
        tool.destinations.append(
            NetworkDestination(
                target="<model-selected-url>",
                restricted=False,
                location=location,
                metadata={
                    "source": "model_selected_url_argument",
                    "network_scope": "dynamic_destination",
                    "server_side_fetch": False,
                },
            )
        )
        tool.metadata["untrusted_input"] = True
        tool.metadata["model_selected_url_fetch"] = True
    elif name == "WebSearch":
        tool.destinations.append(
            NetworkDestination(
                target="<web-search>",
                restricted=False,
                location=location,
                metadata={
                    "source": "claude_builtin",
                    "network_scope": "dynamic_search_results",
                },
            )
        )
        tool.metadata["untrusted_input"] = True
    elif name == "Bash":
        tool.metadata["implicit_network"] = True
    return tool


def _bare_denied_tools(values: list[str]) -> set[str]:
    return {value for value in values if "(" not in value and ")" not in value}


def _apply_permission_semantics(
    agent: Agent,
    allowed: list[str],
    denied: list[str],
    permission_mode: str | None,
    can_use_tool: ast.AST | None,
    hooks: ast.AST | None,
) -> None:
    agent.metadata["allowed_tools_auto_approve"] = list(allowed)
    agent.metadata["disallowed_tools"] = list(denied)
    if permission_mode:
        agent.metadata["permission_mode"] = permission_mode
    if can_use_tool is not None:
        agent.metadata["can_use_tool"] = _expr_reference(can_use_tool)
        agent.metadata["can_use_tool_fallback_only"] = True
    if hooks is not None:
        hook_entries = _dict_nodes(hooks)
        hook_literal = _literal(hooks)
        if hook_entries:
            agent.metadata["hook_events"] = sorted(hook_entries)
        elif isinstance(hook_literal, dict):
            agent.metadata["hook_events"] = sorted(str(key) for key in hook_literal)
        else:
            agent.metadata["hooks_configured"] = True
            agent.metadata["hooks_expression"] = _expr_reference(hooks)

    bare_denied = _bare_denied_tools(denied)
    agent.tools = [tool for tool in agent.tools if tool.name not in bare_denied]
    for tool in agent.tools:
        if tool.name in allowed:
            tool.approval = False
            tool.metadata["auto_approved"] = True
            tool.metadata["approval_basis"] = "allowed_tools"
        if permission_mode == "bypassPermissions" and tool.approval is None:
            tool.approval = False
            tool.metadata["approval_basis"] = "permission_mode_bypassPermissions"
        scoped_denies = [
            rule
            for rule in denied
            if rule.startswith(f"{tool.name}(") and rule.endswith(")")
        ]
        if scoped_denies:
            tool.metadata["scoped_deny_rules"] = scoped_denies


def _filesystem_scopes(
    path: Path,
    call: ast.Call,
    sequences: dict[str, list[ast.AST]],
) -> list[ResourceScope]:
    resources: list[ResourceScope] = []
    cwd = _literal(_kw(call, "cwd"))
    if isinstance(cwd, str):
        resources.append(
            ResourceScope(
                kind="filesystem",
                selector=cwd,
                access={"data.read", "data.write"},
                location=_location(path, call),
                metadata={"source": "claude_cwd"},
            )
        )
    add_dirs = _string_list(_kw(call, "add_dirs"), sequences)
    if add_dirs:
        resources.extend(
            ResourceScope(
                kind="filesystem",
                selector=value,
                access={"data.read", "data.write"},
                location=_location(path, call),
                metadata={"source": "claude_add_dirs"},
            )
            for value in add_dirs
        )
    return resources


def _auth_headers(node: ast.AST | None) -> tuple[bool | None, list[str]]:
    entries = _dict_nodes(node)
    if not entries:
        return None, []
    auth_keys = sorted(
        key.lower()
        for key in entries
        if key.lower() in {"authorization", "proxy-authorization", "x-api-key", "x-goog-api-key"}
    )
    return bool(auth_keys), auth_keys


def _mcp_from_dict(
    path: Path,
    name: str,
    node: ast.AST,
) -> MCPServer | None:
    entries = _dict_nodes(node)
    if not entries:
        return None
    config_type = _literal(entries.get("type"))
    command = _literal(entries.get("command"))
    url = _literal(entries.get("url"))
    args = _literal(entries.get("args"))
    headers_node = entries.get("headers")
    authenticated, auth_keys = _auth_headers(headers_node)
    if command is not None:
        transport = "stdio"
    elif config_type in {"sse", "http"}:
        transport = str(config_type)
    elif url is not None:
        transport = "http"
    else:
        transport = str(config_type or "unknown")
    return MCPServer(
        name=name,
        transport=transport,
        url=str(url) if isinstance(url, str) else None,
        command=str(command) if isinstance(command, str) else None,
        args=[str(item) for item in args] if isinstance(args, list) else [],
        authenticated=authenticated if isinstance(url, str) else None,
        location=_location(path, node),
        metadata={
            "framework": FRAMEWORK,
            "source": "ClaudeAgentOptions.mcp_servers",
            "auth_headers": auth_keys,
            "dynamic_mcp_endpoint": bool(
                entries.get("url") is not None and not isinstance(url, str)
            ),
            "dynamic_command": bool(
                entries.get("command") is not None and not isinstance(command, str)
            ),
        },
    )


def _mcp_from_call(
    path: Path,
    name: str,
    call: ast.Call,
) -> MCPServer | None:
    called = _call_name(call.func)
    transport_by_type = {
        "McpStdioServerConfig": "stdio",
        "McpSSEServerConfig": "sse",
        "McpHttpServerConfig": "http",
        "McpSdkServerConfig": "sdk",
    }
    transport = transport_by_type.get(str(called))
    if transport is None:
        return None
    command = _literal(_kw(call, "command"))
    url = _literal(_kw(call, "url"))
    args = _literal(_kw(call, "args"))
    headers_node = _kw(call, "headers")
    authenticated, auth_keys = _auth_headers(headers_node)
    return MCPServer(
        name=name,
        transport=transport,
        url=str(url) if isinstance(url, str) else None,
        command=str(command) if isinstance(command, str) else None,
        args=[str(item) for item in args] if isinstance(args, list) else [],
        authenticated=authenticated if isinstance(url, str) else None,
        location=_location(path, call),
        metadata={
            "framework": FRAMEWORK,
            "source": f"ClaudeAgentOptions.mcp_servers.{called}",
            "typed_sdk_config": True,
            "auth_headers": auth_keys,
            "dynamic_mcp_endpoint": bool(
                _kw(call, "url") is not None and not isinstance(url, str)
            ),
            "dynamic_command": bool(
                _kw(call, "command") is not None and not isinstance(command, str)
            ),
        },
    )


def _sdk_server_from_call(
    path: Path,
    alias: str,
    call: ast.Call,
    custom_tools: dict[str, Tool],
    sequences: dict[str, list[ast.AST]],
) -> MCPServer | None:
    if _call_name(call.func) != "create_sdk_mcp_server":
        return None
    runtime_name = _literal(_kw(call, "name"))
    if runtime_name is None and call.args:
        runtime_name = _literal(call.args[0])
    tool_nodes = _list_nodes(_kw(call, "tools"), sequences)
    discovered: list[str] = []
    capabilities: set[str] = set()
    dynamic_catalogue = False
    for item in tool_nodes:
        if isinstance(item, ast.Name) and item.id in custom_tools:
            tool = custom_tools[item.id]
            discovered.append(tool.name)
            capabilities.update(tool.capabilities)
        else:
            dynamic_catalogue = True
    if _kw(call, "tools") is not None and not tool_nodes:
        dynamic_catalogue = True
    return MCPServer(
        name=str(runtime_name or alias),
        transport="sdk",
        authenticated=None,
        location=_location(path, call),
        metadata={
            "framework": FRAMEWORK,
            "source": "create_sdk_mcp_server",
            "sdk_server_alias": alias,
            "discovered_tools": discovered,
            "discovered_tool_capabilities": sorted(capabilities),
            "dynamic_tool_catalogue": dynamic_catalogue,
            "in_process": True,
        },
    )


def _resolve_mcp_servers(
    path: Path,
    node: ast.AST | None,
    sdk_servers: dict[str, MCPServer],
    dicts: dict[str, ast.Dict],
    values: dict[str, ast.AST] | None = None,
) -> tuple[list[MCPServer], bool]:
    if node is None:
        return [], False
    current = _resolve_node(node, values)
    if isinstance(current, (ast.Constant, ast.JoinedStr)):
        return [], True
    entries = _mapping_entries(current, dicts, values)
    if isinstance(current, ast.Dict) and not current.keys:
        return [], False
    if not entries:
        return [], True
    result: list[MCPServer] = []
    dynamic = False
    for name, raw_value in entries.items():
        value = _resolve_node(raw_value, values)
        key = _expr_key(value)
        if key and key in sdk_servers:
            server = deepcopy(sdk_servers[key])
            server.name = name
            server.metadata["configured_name"] = name
            result.append(server)
            continue
        server: MCPServer | None = None
        if isinstance(value, ast.Dict):
            server = _mcp_from_dict(path, name, value)
        elif isinstance(value, ast.Call):
            server = _mcp_from_call(path, name, value)
        if server is not None:
            result.append(server)
        else:
            dynamic = True
    return result, dynamic


def _tools_for_names(
    path: Path,
    names: list[str],
    location: SourceLocation,
    custom_tools: dict[str, Tool],
) -> list[Tool]:
    result: list[Tool] = []
    for name in names:
        if name in custom_tools:
            result.append(deepcopy(custom_tools[name]))
        elif name.startswith("mcp__"):
            continue
        else:
            result.append(_builtin_tool(path, name, location))
    return result


def _subagent_from_call(
    path: Path,
    name: str,
    call: ast.Call,
    sequences: dict[str, list[ast.AST]],
    sdk_servers: dict[str, MCPServer],
    custom_tools: dict[str, Tool],
) -> Agent:
    location = _location(path, call)
    tools = _string_list(_kw(call, "tools"), sequences)
    denied = _string_list(_kw(call, "disallowedTools"), sequences) or []
    permission_mode = _literal(_kw(call, "permissionMode"))
    model = _literal(_kw(call, "model"))
    agent = Agent(
        name=name,
        location=location,
        metadata={
            "framework": FRAMEWORK,
            "subagent": True,
            "agent_definition": True,
            "disallowed_tools": denied,
        },
    )
    if isinstance(model, str):
        agent.metadata["model"] = model
    if isinstance(permission_mode, str):
        agent.metadata["permission_mode"] = permission_mode
    memory = _literal(_kw(call, "memory"))
    if isinstance(memory, str):
        agent.metadata["memory_scope"] = memory
    skills = _string_list(_kw(call, "skills"), sequences)
    if skills is not None:
        agent.metadata["skills"] = skills

    if tools is None:
        agent.metadata["tool_surface_inherited"] = True
    else:
        agent.tools.extend(_tools_for_names(path, tools, location, custom_tools))
        bare_denied = _bare_denied_tools(denied)
        agent.tools = [tool for tool in agent.tools if tool.name not in bare_denied]

    mcp_node = _kw(call, "mcpServers")
    if mcp_node is not None:
        for item in _list_nodes(mcp_node, sequences):
            if isinstance(item, ast.Name) and item.id in sdk_servers:
                agent.mcp_servers.append(deepcopy(sdk_servers[item.id]))
            elif isinstance(item, ast.Constant) and isinstance(item.value, str):
                agent.mcp_servers.append(
                    MCPServer(
                        name=item.value,
                        transport="configured",
                        authenticated=None,
                        location=_location(path, item),
                        metadata={
                            "framework": FRAMEWORK,
                            "reference_only": True,
                            "tool_catalogue_unresolved": True,
                            "source": "AgentDefinition.mcpServers",
                        },
                    )
                )
            elif isinstance(item, ast.Dict):
                server_name = _literal(_dict_nodes(item).get("name")) or "subagent-mcp"
                server = _mcp_from_dict(path, str(server_name), item)
                if server:
                    agent.mcp_servers.append(server)
    return agent


def _option_agent(
    path: Path,
    name: str,
    call: ast.Call | None,
    sequences: dict[str, list[ast.AST]],
    dicts: dict[str, ast.Dict],
    values: dict[str, ast.AST],
    custom_tools: dict[str, Tool],
    sdk_servers: dict[str, MCPServer],
    subagents: dict[str, Agent],
    *,
    unresolved_options: ast.AST | None = None,
) -> Agent:
    location = _location(path, call) if call is not None else SourceLocation(path)
    agent = Agent(
        name=name,
        location=location,
        metadata={
            "framework": FRAMEWORK,
            "sdk_entrypoint": True,
            "instance_key": f"{path.resolve()}:{location.line}:{name}",
        },
    )
    if call is None:
        if unresolved_options is not None:
            agent.metadata["dynamic_options"] = True
            agent.metadata["options_expression"] = _expr_reference(unresolved_options)
            agent.metadata["tool_surface"] = "unresolved"
            return agent
        agent.metadata["options_defaulted"] = True
        agent.metadata["tool_surface"] = "runtime_default"
        for tool_name in _SECURITY_RELEVANT_DEFAULT_TOOLS:
            agent.tools.append(_builtin_tool(path, tool_name, location))
        return agent

    model = _resolved_literal(_kw(call, "model", dicts, values), values)
    if isinstance(model, str):
        agent.metadata["model"] = model

    tools_node = _kw(call, "tools", dicts, values)
    tool_names = _string_list(tools_node, sequences, values)
    preset = _resolved_literal(tools_node, values)
    default_surface = tools_node is None or (
        isinstance(preset, dict)
        and preset.get("type") == "preset"
        and preset.get("preset") == "claude_code"
    )
    if tool_names is not None:
        agent.tools.extend(_tools_for_names(path, tool_names, location, custom_tools))
        agent.metadata["tool_surface"] = "explicit"
    elif default_surface:
        agent.metadata["tool_surface"] = "runtime_default"
        agent.metadata["default_tool_surface_projection"] = "security_relevant_builtins"
        for tool_name in _SECURITY_RELEVANT_DEFAULT_TOOLS:
            agent.tools.append(_builtin_tool(path, tool_name, location))
    else:
        agent.metadata["dynamic_tools"] = True
        agent.metadata["tool_surface"] = "dynamic"

    allowed_node = _kw(call, "allowed_tools", dicts, values)
    denied_node = _kw(call, "disallowed_tools", dicts, values)
    allowed = _string_list(allowed_node, sequences, values) or []
    denied = _string_list(denied_node, sequences, values) or []
    permission_mode = _resolved_literal(
        _kw(call, "permission_mode", dicts, values),
        values,
    )
    hooks_node = _resolve_node(_kw(call, "hooks", dicts, values), values)
    _apply_permission_semantics(
        agent,
        allowed,
        denied,
        permission_mode if isinstance(permission_mode, str) else None,
        _resolve_node(_kw(call, "can_use_tool", dicts, values), values),
        hooks_node,
    )
    if allowed_node is not None and not allowed:
        agent.metadata["dynamic_allowed_tools"] = True
    if denied_node is not None and not denied:
        agent.metadata["dynamic_disallowed_tools"] = True

    strict_mcp = _resolved_literal(
        _kw(call, "strict_mcp_config", dicts, values),
        values,
    )
    if isinstance(strict_mcp, bool):
        agent.metadata["strict_mcp_config"] = strict_mcp
    setting_sources = _string_list(
        _kw(call, "setting_sources", dicts, values),
        sequences,
        values,
    )
    if setting_sources is not None:
        agent.metadata["setting_sources"] = setting_sources
        agent.metadata["filesystem_settings_disabled"] = setting_sources == []
    else:
        agent.metadata["setting_sources"] = None
        agent.metadata["external_settings_may_apply"] = True
    agent.metadata["managed_policy_may_apply"] = True

    sandbox = _resolved_literal(_kw(call, "sandbox", dicts, values), values)
    if isinstance(sandbox, dict):
        agent.metadata["sandbox"] = sandbox
        if sandbox.get("enabled") is True:
            agent.metadata["sandbox_enabled"] = True
        if sandbox.get("allowUnsandboxedCommands") is True:
            agent.metadata["allow_unsandboxed_commands"] = True
            if permission_mode == "bypassPermissions":
                agent.metadata["silent_sandbox_escape_possible"] = True

    resources = _filesystem_scopes(path, call, sequences)
    if resources:
        for tool in agent.tools:
            if tool.name in {"Read", "Glob", "Grep", "Write", "Edit", "NotebookEdit", "Bash"}:
                tool.resources.extend(deepcopy(resources))

    mcp_node = _kw(call, "mcp_servers", dicts, values)
    servers, dynamic_mcp = _resolve_mcp_servers(
        path,
        mcp_node,
        sdk_servers,
        dicts,
        values,
    )
    agent.mcp_servers.extend(servers)
    if dynamic_mcp:
        agent.metadata["dynamic_mcp_servers"] = True
        agent.mcp_servers.append(
            MCPServer(
                name="<dynamic-mcp>",
                transport="dynamic",
                authenticated=None,
                location=location,
                metadata={
                    "framework": FRAMEWORK,
                    "source": "ClaudeAgentOptions.mcp_servers",
                    "reference_only": True,
                    "conditional": True,
                    "tool_catalogue_unresolved": True,
                    "expression": _expr_reference(mcp_node),
                },
            )
        )
    for server in agent.mcp_servers:
        if server.name == "<dynamic-mcp>":
            continue
        server_prefix = f"mcp__{server.name}"
        auto_approved = [
            rule
            for rule in allowed
            if rule == server_prefix or rule.startswith(server_prefix + "__")
        ]
        denied_rules = [
            rule
            for rule in denied
            if rule == server_prefix or rule.startswith(server_prefix + "__")
        ]
        if auto_approved:
            server.metadata["auto_approved_tool_rules"] = auto_approved
            server.metadata["conditional_approval"] = True
            server.metadata["approval_mechanism"] = "allowed_tools"
            server.metadata["approval_scope"] = "per_tool"
        if denied_rules:
            server.metadata["denied_tool_rules"] = denied_rules

    agents_node = _resolve_node(_kw(call, "agents", dicts, values), values)
    agent_entries = _mapping_entries(agents_node, dicts, values)
    for subagent_name, raw_value in agent_entries.items():
        value = _resolve_node(raw_value, values)
        target: Agent | None = None
        key = _expr_key(value)
        if key:
            target = subagents.get(key)
        elif isinstance(value, ast.Call) and _call_name(value.func) == "AgentDefinition":
            target = _subagent_from_call(
                path,
                subagent_name,
                value,
                sequences,
                sdk_servers,
                custom_tools,
            )
        if target is None:
            agent.metadata.setdefault("unresolved_subagents", []).append(subagent_name)
            continue
        if target.name != subagent_name:
            target = deepcopy(target)
            target.name = subagent_name
        subagents.setdefault(subagent_name, deepcopy(target))
        agent.metadata.setdefault("delegates_to", []).append(target.name)
        delegated = Tool(
            name=target.name,
            kind="delegated_agent",
            capabilities={"agent.delegate"} | set(target.capabilities),
            resources=deepcopy(target.effective_resources),
            destinations=deepcopy(target.effective_destinations),
            location=location,
            metadata={
                "framework": FRAMEWORK,
                "delegate_target": target.name,
                "authority_binding": "delegation_projection",
                "authority_binding_basis": "ClaudeAgentOptions.agents",
            },
        )
        agent.tools.append(delegated)

    if agents_node is not None and not agent_entries:
        resolved_agents_node = _resolve_node(agents_node, values)
        explicitly_empty = (
            isinstance(resolved_agents_node, ast.Constant)
            and resolved_agents_node.value is None
        ) or (
            isinstance(resolved_agents_node, ast.Dict)
            and not resolved_agents_node.keys
        )
        if not explicitly_empty:
            agent.metadata["dynamic_subagents"] = True
            agent.metadata["unresolved_subagent_registry"] = _expr_reference(
                resolved_agents_node
            )
            agent.tools.append(
                Tool(
                    name="<dynamic-subagents>",
                    kind="delegated_agent",
                    capabilities={"agent.delegate"},
                    location=location,
                    metadata={
                        "framework": FRAMEWORK,
                        "authority_binding": "dynamic_agent_registry",
                        "authority_binding_basis": "ClaudeAgentOptions.agents",
                        "conditional": True,
                        "delegate_target_unresolved": True,
                    },
                )
            )
    return agent

def _resolve_option_calls(
    node: ast.AST | None,
    option_calls: dict[str, ast.Call],
    function_returns: dict[str, list[ast.Call]],
    values: dict[str, ast.AST],
) -> list[ast.Call]:
    current = _resolve_node(node, values)
    if isinstance(current, ast.Call) and _call_name(current.func) == "ClaudeAgentOptions":
        return [current]
    key = _expr_key(current)
    if key and key in option_calls:
        return [option_calls[key]]
    if isinstance(current, ast.Call):
        return list(function_returns.get(_call_name(current.func) or "", []))
    return []


def _record_container_mutations(
    tree: ast.AST,
    sequences: dict[str, list[ast.AST]],
    dicts: dict[str, ast.Dict],
    values: dict[str, ast.AST],
) -> None:
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            raw_targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in raw_targets:
                if not isinstance(target, ast.Subscript):
                    continue
                base = _expr_key(target.value)
                key = _literal(target.slice)
                if base and isinstance(key, str) and base in dicts:
                    dicts[base].keys.append(ast.Constant(value=key))
                    dicts[base].values.append(node.value)

        if not isinstance(node, ast.Expr) or not isinstance(node.value, ast.Call):
            continue
        call = node.value
        if not isinstance(call.func, ast.Attribute):
            continue
        base = _expr_key(call.func.value)
        if not base:
            continue
        if call.func.attr == "append" and len(call.args) == 1 and base in sequences:
            sequences[base].append(call.args[0])
        elif call.func.attr == "extend" and len(call.args) == 1 and base in sequences:
            sequences[base].extend(_list_nodes(call.args[0], sequences, values))
        elif call.func.attr == "update" and len(call.args) == 1 and base in dicts:
            for key, value in _mapping_entries(call.args[0], dicts, values).items():
                dicts[base].keys.append(ast.Constant(value=key))
                dicts[base].values.append(value)


def scan_python_file(path: Path) -> Graph:
    graph = Graph()
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return graph
    if not _uses_claude_agent_sdk(tree):
        return graph

    sequences: dict[str, list[ast.AST]] = {}
    dicts: dict[str, ast.Dict] = {}
    values: dict[str, ast.AST] = {}
    option_calls: dict[str, ast.Call] = {}
    custom_tools: dict[str, Tool] = {}
    sdk_servers: dict[str, MCPServer] = {}
    subagent_defs: dict[str, Agent] = {}

    # Literal/default function parameters are useful for builders such as
    # build_claude_options(permission_mode="bypassPermissions").
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        positional = list(node.args.posonlyargs) + list(node.args.args)
        if node.args.defaults:
            for arg, default in zip(positional[-len(node.args.defaults):], node.args.defaults):
                if arg.arg not in values:
                    values[arg.arg] = default
        for arg, default in zip(node.args.kwonlyargs, node.args.kw_defaults):
            if default is not None and arg.arg not in values:
                values[arg.arg] = default

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            custom = _custom_tool(path, node)
            if custom is not None:
                custom_tools[node.name] = custom

    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        names = _targets(node)
        for name in names:
            values[name] = node.value
        if isinstance(node.value, (ast.List, ast.Tuple, ast.Set)):
            for name in names:
                sequences[name] = list(node.value.elts)
        if isinstance(node.value, ast.Dict):
            for name in names:
                dicts[name] = node.value
        if not isinstance(node.value, ast.Call):
            continue
        called = _call_name(node.value.func)
        for name in names:
            if called == "ClaudeAgentOptions":
                option_calls[name] = node.value
            elif called == "AgentDefinition":
                subagent_defs[name] = _subagent_from_call(
                    path,
                    name,
                    node.value,
                    sequences,
                    sdk_servers,
                    custom_tools,
                )
            elif called == "create_sdk_mcp_server":
                server = _sdk_server_from_call(
                    path,
                    name,
                    node.value,
                    custom_tools,
                    sequences,
                )
                if server:
                    sdk_servers[name] = server

    _record_container_mutations(tree, sequences, dicts, values)

    # Second pass re-resolves subagents now that SDK MCP declarations are known.
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        if not isinstance(node.value, ast.Call) or _call_name(node.value.func) != "AgentDefinition":
            continue
        for name in _targets(node):
            subagent_defs[name] = _subagent_from_call(
                path,
                name,
                node.value,
                sequences,
                sdk_servers,
                custom_tools,
            )

    # Summarise simple helper/method return values. This intentionally handles
    # only direct ClaudeAgentOptions returns or aliases already resolved in-file.
    function_returns: dict[str, list[ast.Call]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        candidates: list[ast.Call] = []
        for child in ast.walk(node):
            if not isinstance(child, ast.Return):
                continue
            current = _resolve_node(child.value, values)
            if isinstance(current, ast.Call) and _call_name(current.func) == "ClaudeAgentOptions":
                candidates.append(current)
                continue
            key = _expr_key(current)
            if key and key in option_calls:
                candidates.append(option_calls[key])
        if candidates:
            unique: list[ast.Call] = []
            seen: set[int] = set()
            for call in candidates:
                if id(call) not in seen:
                    unique.append(call)
                    seen.add(id(call))
            function_returns[node.name] = unique

    roots: list[Agent] = []
    used_option_calls: set[int] = set()

    # ClaudeSDKClient can appear in assignments, returns, attributes and
    # async-with expressions. Scan constructor calls directly rather than only
    # assignment statements.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or _call_name(node.func) != "ClaudeSDKClient":
            continue
        option_node = _kw(node, "options", dicts, values)
        if option_node is None and node.args:
            option_node = node.args[0]
        calls = _resolve_option_calls(
            option_node,
            option_calls,
            function_returns,
            values,
        )
        base_name = _expr_key(option_node) or f"claude-client@{getattr(node, 'lineno', 1)}"
        if calls:
            for index, call in enumerate(calls):
                used_option_calls.add(id(call))
                root_name = base_name if len(calls) == 1 else f"{base_name}#{index + 1}"
                roots.append(
                    _option_agent(
                        path,
                        root_name,
                        call,
                        sequences,
                        dicts,
                        values,
                        custom_tools,
                        sdk_servers,
                        subagent_defs,
                    )
                )
        else:
            roots.append(
                _option_agent(
                    path,
                    base_name,
                    None,
                    sequences,
                    dicts,
                    values,
                    custom_tools,
                    sdk_servers,
                    subagent_defs,
                    unresolved_options=option_node if option_node is not None else None,
                )
            )

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or _call_name(node.func) != "query":
            continue
        # Avoid treating client.query(...) as the top-level SDK query() function.
        if isinstance(node.func, ast.Attribute):
            continue
        option_node = _kw(node, "options", dicts, values)
        calls = _resolve_option_calls(
            option_node,
            option_calls,
            function_returns,
            values,
        )
        base_name = _expr_key(option_node) or f"claude-query@{getattr(node, 'lineno', 1)}"
        if calls:
            for index, call in enumerate(calls):
                used_option_calls.add(id(call))
                root_name = base_name if len(calls) == 1 else f"{base_name}#{index + 1}"
                roots.append(
                    _option_agent(
                        path,
                        root_name,
                        call,
                        sequences,
                        dicts,
                        values,
                        custom_tools,
                        sdk_servers,
                        subagent_defs,
                    )
                )
        else:
            roots.append(
                _option_agent(
                    path,
                    base_name,
                    None,
                    sequences,
                    dicts,
                    values,
                    custom_tools,
                    sdk_servers,
                    subagent_defs,
                    unresolved_options=option_node if option_node is not None else None,
                )
            )

    # Preserve configured options that are passed through wrappers the bounded
    # resolver cannot connect to an SDK entrypoint.
    for alias, call in option_calls.items():
        if id(call) in used_option_calls:
            continue
        roots.append(
            _option_agent(
                path,
                alias,
                call,
                sequences,
                dicts,
                values,
                custom_tools,
                sdk_servers,
                subagent_defs,
            )
        )
        roots[-1].metadata["execution_binding_unresolved"] = True

    graph.agents.extend(roots)

    delegated_names = {
        target
        for root in roots
        for target in root.metadata.get("delegates_to", [])
        if isinstance(target, str)
    }
    graph.agents.extend(
        deepcopy(agent)
        for name, agent in subagent_defs.items()
        if name in delegated_names
    )

    bound_server_names = {
        server.metadata.get("sdk_server_alias")
        for agent in graph.agents
        for server in agent.mcp_servers
    }
    graph.unbound_mcp_servers.extend(
        deepcopy(server)
        for alias, server in sdk_servers.items()
        if alias not in bound_server_names
    )

    bound_custom_names = {
        tool.name
        for agent in graph.agents
        for tool in agent.tools
        if tool.kind == "claude_sdk_mcp_tool"
    }
    graph.unbound_tools.extend(
        deepcopy(tool)
        for tool in custom_tools.values()
        if tool.name not in bound_custom_names
    )

    for agent in graph.agents:
        if agent.metadata.get("dynamic_tools"):
            add_diagnostic(
                graph.coverage,
                ScanDiagnostic(
                    "dynamic_configuration",
                    "Claude Agent SDK tool configuration could not be fully resolved statically.",
                    agent.location,
                    details={"framework": FRAMEWORK},
                )
            )
        if agent.metadata.get("dynamic_options"):
            add_diagnostic(
                graph.coverage,
                ScanDiagnostic(
                    "dynamic_configuration",
                    "Claude Agent SDK options binding could not be fully resolved statically.",
                    agent.location,
                    details={
                        "framework": FRAMEWORK,
                        "expression": agent.metadata.get("options_expression"),
                    },
                )
            )
        if agent.metadata.get("dynamic_mcp_servers"):
            add_diagnostic(
                graph.coverage,
                ScanDiagnostic(
                    "dynamic_configuration",
                    "Claude Agent SDK MCP configuration could not be fully resolved statically.",
                    agent.location,
                    details={"framework": FRAMEWORK},
                )
            )
        if agent.metadata.get("dynamic_subagents"):
            add_diagnostic(
                graph.coverage,
                ScanDiagnostic(
                    "unresolved_delegation",
                    "Claude Agent SDK subagent registry could not be fully resolved statically.",
                    agent.location,
                    details={"framework": FRAMEWORK},
                )
            )
    return graph
