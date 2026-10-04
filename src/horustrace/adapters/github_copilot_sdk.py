from __future__ import annotations

import ast
import re
from collections.abc import Iterable
from copy import deepcopy
from pathlib import Path

from horustrace.adapters.csharp_source import (
    argument_value,
    balanced_end,
    collection_strings,
    mask_comments,
    mask_non_code,
    method_body,
    named_string,
    refs,
    unquote,
)
from horustrace.adapters.csharp_source import (
    assignments as csharp_assignments,
)
from horustrace.adapters.csharp_source import (
    location as csharp_location,
)
from horustrace.heuristics import infer_capabilities
from horustrace.models import (
    Agent,
    Graph,
    Identity,
    MCPServer,
    NetworkDestination,
    ResourceScope,
    SourceLocation,
    Tool,
)

FRAMEWORK = "github-copilot-sdk"

_ALL_BUILTIN_CAPABILITIES = {
    "data.read",
    "data.write",
    "process.execute",
    "network.external",
    "external.write",
    "destructive.write",
    "agent.delegate",
}

_BUILTIN_TOOL_CAPABILITIES: dict[str, set[str]] = {
    "view": {"data.read"},
    "read": {"data.read"},
    "grep": {"data.read"},
    "glob": {"data.read"},
    "search": {"data.read"},
    "edit": {"data.read", "data.write"},
    "write": {"data.write"},
    "bash": {
        "data.read",
        "data.write",
        "process.execute",
        "network.external",
        "external.write",
        "destructive.write",
    },
    "powershell": {
        "data.read",
        "data.write",
        "process.execute",
        "network.external",
        "external.write",
        "destructive.write",
    },
    "shell": {
        "data.read",
        "data.write",
        "process.execute",
        "network.external",
        "external.write",
        "destructive.write",
    },
    "web_fetch": {"data.read", "network.external"},
    "web_search": {"data.read", "network.external"},
    "task": {"agent.delegate"},
    "delegate": {"agent.delegate"},
    "subagent": {"agent.delegate"},
}


_URL_RE = re.compile(r"""https?://[^\s"'<>]+""")


def _attach_literal_destinations(tool: Tool, text: str) -> None:
    if "network.external" not in tool.capabilities:
        return
    seen = {item.target for item in tool.destinations}
    for raw in _URL_RE.findall(text):
        target = raw.rstrip('",);]}')
        if not target or target in seen:
            continue
        tool.destinations.append(
            NetworkDestination(
                target=target,
                restricted=True,
                location=tool.location,
                metadata={
                    "source": "literal_url",
                    "network_scope": "fixed_literal_destination",
                },
            )
        )
        seen.add(target)


def _source_location(path: Path, node: ast.AST) -> SourceLocation:
    return SourceLocation(
        path,
        getattr(node, "lineno", 1) or 1,
        (getattr(node, "col_offset", 0) or 0) + 1,
    )


def _call_leaf(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _python_dotted(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _python_dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def _unwrap_call(node: ast.AST | None) -> ast.Call | None:
    if isinstance(node, ast.Call):
        return node
    if isinstance(node, ast.Await) and isinstance(node.value, ast.Call):
        return node.value
    return None


def _literal_string(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _literal_bool(node: ast.AST | None) -> bool | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return node.value
    return None


def _string_list(node: ast.AST | None) -> list[str] | None:
    if not isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return None
    result: list[str] = []
    for item in node.elts:
        value = _literal_string(item)
        if value is None:
            return None
        result.append(value)
    return result


def _keyword(call: ast.Call, name: str) -> ast.AST | None:
    return next((kw.value for kw in call.keywords if kw.arg == name), None)


def _strip_tool_prefix(name: str) -> tuple[str, str]:
    if ":" in name:
        source, tool = name.split(":", 1)
        return source.lower(), tool
    return "", name


def _capabilities_for_tool_names(names: Iterable[str]) -> set[str]:
    result: set[str] = set()
    for raw in names:
        source, name = _strip_tool_prefix(raw)
        if source and source not in {"builtin", "custom"}:
            continue
        if name == "*":
            if source in {"", "builtin"}:
                result.update(_ALL_BUILTIN_CAPABILITIES)
            continue
        normalized = name.lower().replace("-", "_")
        if normalized in _BUILTIN_TOOL_CAPABILITIES:
            result.update(_BUILTIN_TOOL_CAPABILITIES[normalized])
            continue
        result.update(infer_capabilities(normalized))
    return result


def _builtin_capabilities(
    available: list[str] | None,
    excluded: list[str] | None,
) -> set[str]:
    if available is None:
        enabled = set(_BUILTIN_TOOL_CAPABILITIES)
    else:
        enabled: set[str] = set()
        for raw in available:
            source, name = _strip_tool_prefix(raw)
            if source and source != "builtin":
                continue
            normalized = name.lower().replace("-", "_")
            if normalized == "*":
                enabled.update(_BUILTIN_TOOL_CAPABILITIES)
            else:
                enabled.add(normalized)

    for raw in excluded or []:
        source, name = _strip_tool_prefix(raw)
        if source and source != "builtin":
            continue
        normalized = name.lower().replace("-", "_")
        if normalized == "*":
            enabled.clear()
        else:
            enabled.discard(normalized)

    capabilities: set[str] = set()
    for name in enabled:
        capabilities.update(
            _BUILTIN_TOOL_CAPABILITIES.get(name, infer_capabilities(name))
        )
    return capabilities


def _filesystem_resources(
    *,
    working_directory: str | None,
    additional_directories: list[str] | None,
    capabilities: set[str],
    location: SourceLocation,
) -> list[ResourceScope]:
    access: set[str] = set()
    if {"data.read", "process.execute"} & capabilities:
        access.add("data.read")
    if {"data.write", "process.execute"} & capabilities:
        access.add("data.write")
    if not access:
        return []

    result = [
        ResourceScope(
            kind="filesystem",
            selector=working_directory or ".",
            access=access,
            location=location,
            metadata={
                "basis": (
                    "copilot_session_working_directory"
                    if working_directory
                    else "copilot_default_working_directory"
                )
            },
        )
    ]
    for directory in additional_directories or []:
        result.append(
            ResourceScope(
                kind="filesystem",
                selector=directory,
                access=set(access),
                location=location,
                metadata={"basis": "copilot_additional_directory"},
            )
        )
    return result


def _builtin_tool(
    *,
    location: SourceLocation,
    available: list[str] | None,
    excluded: list[str] | None,
    approve_all: bool,
    working_directory: str | None,
    additional_directories: list[str] | None,
) -> Tool | None:
    capabilities = _builtin_capabilities(available, excluded)
    if not capabilities:
        return None
    tool = Tool(
        name="copilot-cli-builtins",
        kind="github_copilot_builtin_tools",
        capabilities=capabilities,
        approval=not approve_all,
        location=location,
        metadata={
            "framework": FRAMEWORK,
            "runtime": "copilot-cli",
            "approval_basis": (
                "approve_all"
                if approve_all
                else "runtime_permission_handler_or_manual_approval"
            ),
            "available_tools": available,
            "excluded_tools": excluded or [],
        },
    )
    tool.resources.extend(
        _filesystem_resources(
            working_directory=working_directory,
            additional_directories=additional_directories,
            capabilities=capabilities,
            location=location,
        )
    )
    return tool


def _python_body_capabilities(node: ast.AST) -> set[str]:
    text = ast.unparse(node).lower()
    caps: set[str] = set()
    if any(
        marker in text
        for marker in (
            "subprocess.",
            "os.system(",
            "os.popen(",
            "asyncio.create_subprocess",
        )
    ):
        caps.add("process.execute")
    if any(
        marker in text
        for marker in (
            "requests.",
            "httpx.",
            "aiohttp.",
            "urllib.request",
            "socket.",
        )
    ):
        caps.add("network.external")
    if any(
        marker in text
        for marker in (
            ".post(",
            ".put(",
            ".patch(",
            ".delete(",
            "send_message",
            "send_email",
        )
    ):
        caps.update({"external.write", "data.write"})
    if any(
        marker in text
        for marker in (
            "os.remove(",
            "os.unlink(",
            "shutil.rmtree(",
            ".delete(",
        )
    ):
        caps.update({"data.write", "destructive.write"})
    if any(
        marker in text
        for marker in (
            "open(",
            "path.read_",
            "pathlib.path(",
            ".read_text(",
            ".read_bytes(",
        )
    ):
        caps.add("data.read")
    if any(
        marker in text
        for marker in (
            ".write_text(",
            ".write_bytes(",
            "open(",
        )
    ) and any(mode in text for mode in ('"w"', "'w'", '"a"', "'a'", '"x"', "'x'")):
        caps.add("data.write")
    if any(marker in text for marker in ("secretclient", "get_secret(", "keyvault")):
        caps.add("secrets.read")
    return caps


def _python_custom_tools(
    path: Path,
    tree: ast.AST,
) -> dict[str, Tool]:
    result: dict[str, Tool] = {}

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        decorator = next(
            (
                dec
                for dec in node.decorator_list
                if (
                    isinstance(dec, ast.Call)
                    and _call_leaf(dec.func) == "define_tool"
                )
                or (
                    isinstance(dec, ast.Name)
                    and dec.id == "define_tool"
                )
            ),
            None,
        )
        if decorator is None:
            continue
        explicit = (
            _literal_string(decorator.args[0])
            if isinstance(decorator, ast.Call) and decorator.args
            else None
        )
        name = explicit or node.name
        tool = Tool(
            name=name,
            kind="function",
            capabilities=_python_body_capabilities(node),
            location=_source_location(path, node),
            metadata={
                "framework": FRAMEWORK,
                "binding_origin": "define_tool",
                "wrapped": node.name,
            },
        )
        _attach_literal_destinations(tool, ast.unparse(node))
        result[node.name] = tool

    functions = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        if not isinstance(value, ast.Call):
            continue
        leaf = _call_leaf(value.func)
        if leaf not in {"define_tool", "Tool"}:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        target = next((item.id for item in targets if isinstance(item, ast.Name)), None)
        if target is None:
            continue

        explicit = (
            _literal_string(value.args[0])
            if leaf == "define_tool" and value.args
            else _literal_string(_keyword(value, "name"))
        )
        name = explicit or target
        handler = _keyword(value, "handler")
        handler_name = handler.id if isinstance(handler, ast.Name) else None
        body = functions.get(handler_name) if handler_name else None
        tool = Tool(
            name=name,
            kind="function",
            capabilities=_python_body_capabilities(body) if body else set(),
            location=_source_location(path, node),
            metadata={
                "framework": FRAMEWORK,
                "binding_origin": leaf,
                "wrapped": handler_name,
                "declaration_only": body is None,
            },
        )
        if body is not None:
            _attach_literal_destinations(tool, ast.unparse(body))
        result[target] = tool
    return result


def _resolve_python_node(
    node: ast.AST | None,
    assignments: dict[str, ast.AST],
) -> ast.AST | None:
    if isinstance(node, ast.Name):
        return assignments.get(node.id, node)
    return node


def _python_mapping_items(
    node: ast.AST | None,
    assignments: dict[str, ast.AST],
    updates: dict[str, dict[str, ast.AST]] | None = None,
) -> dict[str, ast.AST]:
    reference = _python_dotted(node)
    resolved = _resolve_python_node(node, assignments)
    if not isinstance(resolved, ast.Dict):
        return {}
    items = {
        key: value
        for key_node, value in zip(resolved.keys, resolved.values)
        if (key := _literal_string(key_node)) is not None
    }
    for key, value in (updates or {}).get(reference or "", {}).items():
        items[key] = value
    return items


def _python_session_option(
    call: ast.Call,
    name: str,
    assignments: dict[str, ast.AST],
    updates: dict[str, dict[str, ast.AST]],
) -> ast.AST | None:
    direct = _keyword(call, name)
    if direct is not None:
        return direct
    if not call.args:
        return None
    return _python_mapping_items(call.args[0], assignments, updates).get(name)


def _python_options_call(
    node: ast.AST | None,
    assignments: dict[str, ast.AST],
) -> ast.Call | None:
    resolved = _resolve_python_node(node, assignments)
    call = _unwrap_call(resolved)
    if call is not None and _call_leaf(call.func) == "GitHubCopilotOptions":
        return call
    return None


def _python_mcp_servers(
    path: Path,
    node: ast.AST | None,
    assignments: dict[str, ast.AST],
) -> list[MCPServer]:
    node = _resolve_python_node(node, assignments)
    if not isinstance(node, ast.Dict):
        return []

    servers: list[MCPServer] = []
    for key, value in zip(node.keys, node.values):
        name = _literal_string(key)
        value = _resolve_python_node(value, assignments)
        if name is None or not isinstance(value, ast.Dict):
            continue

        items = {
            _literal_string(k): v
            for k, v in zip(value.keys, value.values)
            if _literal_string(k) is not None
        }
        server_type = (_literal_string(items.get("type")) or "").lower()
        allowed = _string_list(items.get("tools")) or []
        location = _source_location(path, value)
        if server_type in {"http", "sse"} or "url" in items:
            url = _literal_string(items.get("url"))
            auth = isinstance(items.get("headers"), ast.Dict)
            metadata: dict[str, object] = {
                "framework": FRAMEWORK,
                "provider": "github-copilot",
            }
            if url is None:
                metadata.update(
                    {
                        "dynamic_mcp_endpoint_basis": "operator_configuration",
                        "network_scope": "operator_configured_destination",
                    }
                )
            servers.append(
                MCPServer(
                    name=name,
                    transport="streamable-http",
                    url=url,
                    authenticated=True if auth else None,
                    allowed_tools=allowed,
                    location=location,
                    metadata=metadata,
                )
            )
            continue

        command = _literal_string(items.get("command"))
        args = _string_list(items.get("args")) or []
        servers.append(
            MCPServer(
                name=name,
                transport="stdio",
                command=command,
                args=args,
                allowed_tools=allowed,
                location=location,
                metadata={
                    "framework": FRAMEWORK,
                    "provider": "github-copilot",
                },
            )
        )
    return servers


def _python_agent_from_custom_config(
    path: Path,
    config: ast.Dict,
    *,
    parent: Agent,
    approve_all: bool,
    custom_tools: dict[str, Tool],
    assignments: dict[str, ast.AST],
) -> Agent | None:
    items = {
        _literal_string(k): v
        for k, v in zip(config.keys, config.values)
        if _literal_string(k) is not None
    }
    name = _literal_string(items.get("name"))
    if not name:
        return None
    location = _source_location(path, config)
    tool_names = _string_list(items.get("tools"))
    child = Agent(
        name=name,
        location=location,
        metadata={
            "framework": FRAMEWORK,
            "runtime": "copilot-cli",
            "custom_agent": True,
            "parent_session": parent.name,
            "automatic_inference": _literal_bool(items.get("infer")) is not False,
        },
    )

    if tool_names is None:
        child.tools = [deepcopy(tool) for tool in parent.tools if tool.kind != "delegated_agent"]
        child.mcp_servers = deepcopy(parent.mcp_servers)
    else:
        builtin = _builtin_tool(
            location=location,
            available=tool_names,
            excluded=None,
            approve_all=approve_all,
            working_directory=None,
            additional_directories=None,
        )
        if builtin is not None:
            child.tools.append(builtin)
        requested = set(tool_names)
        for tool in custom_tools.values():
            if tool.name in requested or f"custom:{tool.name}" in requested:
                child.tools.append(deepcopy(tool))
        for server in parent.mcp_servers:
            if any(
                name.startswith(
                    (f"{server.name}-", f"mcp:{server.name}-")
                )
                for name in requested
            ):
                child.mcp_servers.append(deepcopy(server))

    child.mcp_servers.extend(
        _python_mcp_servers(
            path,
            items.get("mcp_servers"),
            assignments,
        )
    )
    return child


def _delegation_tool(child: Agent, location: SourceLocation) -> Tool:
    tool = Tool(
        name=child.name,
        kind="delegated_agent",
        capabilities={"agent.delegate"} | child.capabilities,
        location=location,
        metadata={
            "framework": FRAMEWORK,
            "delegate_target": child.name,
            "authority_binding": "delegation_projection",
            "authority_binding_basis": "github_copilot_custom_agent",
        },
    )
    tool.resources.extend(deepcopy(child.effective_resources))
    tool.destinations.extend(deepcopy(child.effective_destinations))
    return tool


def _python_auth_identity(path: Path, call: ast.Call) -> Identity | None:
    token = _keyword(call, "github_token")
    provider = _keyword(call, "github_token_provider")
    if token is not None or provider is not None:
        return Identity(
            name="github-copilot-auth",
            provider="github",
            credential_source=(
                "github_token_provider"
                if provider is not None
                else "github_token"
            ),
            location=_source_location(path, call),
            metadata={"runtime_resolved": True},
        )
    return None


def _scan_python(path: Path, source: str) -> Graph:
    graph = Graph()
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return graph

    imports_copilot = False
    imports_maf_bridge = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports_copilot |= any(
                alias.name == "copilot" or alias.name.startswith("copilot.")
                for alias in node.names
            )
            imports_maf_bridge |= any(
                alias.name == "agent_framework.github"
                or alias.name.startswith("agent_framework.github.")
                for alias in node.names
            )
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            imports_copilot |= module == "copilot" or module.startswith("copilot.")
            imports_maf_bridge |= (
                module == "agent_framework.github"
                or module.startswith("agent_framework.github.")
            )

    assignments: dict[str, ast.AST] = {}
    dict_updates: dict[str, dict[str, ast.AST]] = {}
    assigned_calls: list[tuple[str, ast.Call, ast.AST]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Subscript):
                    owner = _python_dotted(target.value)
                    key = _literal_string(target.slice)
                    if owner and key is not None:
                        dict_updates.setdefault(owner, {})[key] = node.value
                    continue
                binding = _python_dotted(target)
                if binding is None:
                    continue
                assignments[binding] = node.value
                assignments.setdefault(binding.rsplit(".", 1)[-1], node.value)
                call = _unwrap_call(node.value)
                if call is not None:
                    assigned_calls.append((binding, call, node))
        elif isinstance(node, ast.AnnAssign):
            binding = _python_dotted(node.target)
            if binding is None:
                continue
            assignments[binding] = node.value
            assignments.setdefault(binding.rsplit(".", 1)[-1], node.value)
            call = _unwrap_call(node.value)
            if call is not None:
                assigned_calls.append((binding, call, node))
        elif isinstance(node, ast.AsyncWith):
            for item in node.items:
                binding = _python_dotted(item.optional_vars)
                if binding is None:
                    continue
                call = _unwrap_call(item.context_expr)
                if call is None:
                    continue
                assignments[binding] = item.context_expr
                assignments.setdefault(binding.rsplit(".", 1)[-1], item.context_expr)
                assigned_calls.append((binding, call, item.context_expr))

    custom_tools = _python_custom_tools(path, tree)
    functions_by_name = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

    if imports_maf_bridge:
        for variable, call, binding in assigned_calls:
            if _call_leaf(call.func) != "GitHubCopilotAgent":
                continue
            default_options = _python_options_call(
                _keyword(call, "default_options"),
                assignments,
            )
            approve = (
                _keyword(default_options, "on_permission_request")
                if default_options is not None
                else None
            )
            approve_text = ast.unparse(approve) if approve is not None else ""
            approve_all = "approve_all" in approve_text.lower()
            available = (
                _string_list(_keyword(default_options, "available_tools"))
                if default_options is not None
                else None
            )
            excluded = (
                _string_list(_keyword(default_options, "excluded_tools"))
                if default_options is not None
                else None
            )
            working = (
                _literal_string(_keyword(default_options, "working_directory"))
                if default_options is not None
                else None
            )
            additional = (
                _string_list(_keyword(default_options, "additional_directories"))
                if default_options is not None
                else None
            )
            agent = Agent(
                name=variable.rsplit(".", 1)[-1],
                location=_source_location(path, binding),
                metadata={
                    "framework": FRAMEWORK,
                    "runtime": "copilot-cli",
                    "maf_integration": True,
                    "language": "python",
                    "source_aliases": [variable],
                },
            )
            builtin = _builtin_tool(
                location=agent.location,
                available=available,
                excluded=excluded,
                approve_all=approve_all,
                working_directory=working,
                additional_directories=additional,
            )
            if builtin:
                agent.tools.append(builtin)
            tools_node = _keyword(call, "tools")
            if isinstance(tools_node, (ast.List, ast.Tuple)):
                for item in tools_node.elts:
                    if isinstance(item, ast.Name):
                        if item.id in custom_tools:
                            agent.tools.append(deepcopy(custom_tools[item.id]))
                        elif item.id in functions_by_name:
                            fn = functions_by_name[item.id]
                            tool = Tool(
                                name=item.id,
                                kind="function",
                                capabilities=_python_body_capabilities(fn),
                                location=_source_location(path, item),
                                metadata={
                                    "framework": FRAMEWORK,
                                    "binding_origin": "GitHubCopilotAgent.tools",
                                },
                            )
                            _attach_literal_destinations(tool, ast.unparse(fn))
                            agent.tools.append(tool)
            if default_options is not None:
                agent.mcp_servers.extend(
                    _python_mcp_servers(
                        path,
                        _keyword(default_options, "mcp_servers"),
                        assignments,
                    )
                )
            graph.agents.append(agent)

    if not imports_copilot:
        return graph

    clients: set[str] = set()
    client_identities: dict[str, Identity] = {}
    for variable, call, _binding in assigned_calls:
        if _call_leaf(call.func) != "CopilotClient":
            continue
        aliases = {variable, variable.rsplit(".", 1)[-1]}
        clients.update(aliases)
        identity = _python_auth_identity(path, call)
        if identity:
            for alias in aliases:
                client_identities[alias] = identity

    for variable, call, binding in assigned_calls:
        if not isinstance(call.func, ast.Attribute):
            continue
        if call.func.attr not in {"create_session", "resume_session"}:
            continue
        owner = _python_dotted(call.func.value)
        owner_aliases = (
            {owner, owner.rsplit(".", 1)[-1]}
            if owner
            else set()
        )
        if clients and not (owner_aliases & clients):
            continue

        location = _source_location(path, binding)
        approve = _python_session_option(
            call,
            "on_permission_request",
            assignments,
            dict_updates,
        )
        approve_text = ast.unparse(approve) if approve is not None else ""
        approve_all = "approve_all" in approve_text.lower()

        available = _string_list(
            _python_session_option(
                call, "available_tools", assignments, dict_updates
            )
        )
        excluded = _string_list(
            _python_session_option(
                call, "excluded_tools", assignments, dict_updates
            )
        )
        working = _literal_string(
            _python_session_option(
                call, "working_directory", assignments, dict_updates
            )
        )
        additional = _string_list(
            _python_session_option(
                call, "additional_directories", assignments, dict_updates
            )
        )

        agent = Agent(
            name=variable.rsplit(".", 1)[-1],
            location=location,
            metadata={
                "framework": FRAMEWORK,
                "runtime": "copilot-cli",
                "language": "python",
                "session_operation": call.func.attr,
                "source_aliases": [variable],
            },
        )
        builtin = _builtin_tool(
            location=location,
            available=available,
            excluded=excluded,
            approve_all=approve_all,
            working_directory=working,
            additional_directories=additional,
        )
        if builtin:
            agent.tools.append(builtin)

        tools_node = _resolve_python_node(
            _python_session_option(call, "tools", assignments, dict_updates),
            assignments,
        )
        if isinstance(tools_node, (ast.List, ast.Tuple)):
            for item in tools_node.elts:
                if isinstance(item, ast.Name) and item.id in custom_tools:
                    agent.tools.append(deepcopy(custom_tools[item.id]))

        mcp_servers = _python_mcp_servers(
            path,
            _python_session_option(
                call, "mcp_servers", assignments, dict_updates
            ),
            assignments,
        )
        disabled = set(
            _string_list(
                _python_session_option(
                    call,
                    "disabled_mcp_servers",
                    assignments,
                    dict_updates,
                )
            )
            or []
        )
        agent.mcp_servers.extend(
            server for server in mcp_servers if server.name not in disabled
        )

        session_identity = _python_auth_identity(path, call)
        if session_identity:
            agent.identities.append(session_identity)
        elif owner_aliases:
            inherited = next(
                (
                    client_identities[alias]
                    for alias in owner_aliases
                    if alias in client_identities
                ),
                None,
            )
            if inherited is not None:
                agent.identities.append(deepcopy(inherited))
            else:
                agent.identities.append(
                    Identity(
                        name="github-copilot-user",
                        provider="github",
                        credential_source="copilot_cli_logged_in_user",
                        location=location,
                        metadata={"runtime_resolved": True},
                    )
                )
        else:
            agent.identities.append(
                Identity(
                    name="github-copilot-user",
                    provider="github",
                    credential_source="copilot_cli_logged_in_user",
                    location=location,
                    metadata={"runtime_resolved": True},
                )
            )

        custom_agents_node = _resolve_python_node(
            _python_session_option(
                call, "custom_agents", assignments, dict_updates
            ),
            assignments,
        )
        if isinstance(custom_agents_node, (ast.List, ast.Tuple)):
            for config in custom_agents_node.elts:
                config = _resolve_python_node(config, assignments)
                if not isinstance(config, ast.Dict):
                    continue
                child = _python_agent_from_custom_config(
                    path,
                    config,
                    parent=agent,
                    approve_all=approve_all,
                    custom_tools=custom_tools,
                    assignments=assignments,
                )
                if child is None:
                    continue
                graph.agents.append(child)
                agent.tools.append(_delegation_tool(child, location))

        graph.agents.append(agent)

    return graph


def _csharp_body_capabilities(body: str) -> set[str]:
    lowered = body.lower()
    caps: set[str] = set()
    if any(
        marker in lowered
        for marker in (
            "process.start",
            "processstartinfo",
            "powershell.create",
            "system.management.automation",
        )
    ):
        caps.add("process.execute")
    if any(
        marker in lowered
        for marker in (
            "httpclient",
            ".getasync(",
            ".postasync(",
            ".putasync(",
            ".patchasync(",
            ".sendasync(",
        )
    ):
        caps.add("network.external")
    if any(
        marker in lowered
        for marker in (
            ".postasync(",
            ".putasync(",
            ".patchasync(",
            "sendmail",
            "sendemail",
        )
    ):
        caps.update({"external.write", "data.write"})
    if any(
        marker in lowered
        for marker in (
            "file.write",
            "file.append",
            "file.create",
            "savechanges",
            "executenonquery",
        )
    ):
        caps.add("data.write")
    if any(
        marker in lowered
        for marker in (
            "file.delete",
            "directory.delete",
            ".deleteasync(",
        )
    ):
        caps.update({"data.write", "destructive.write"})
    if any(
        marker in lowered
        for marker in (
            "file.read",
            "file.openread",
            ".getasync(",
            ".query",
        )
    ):
        caps.add("data.read")
    if any(marker in lowered for marker in ("secretclient", "getsecret", "keyvault")):
        caps.add("secrets.read")
    return caps


def _csharp_custom_tools(
    path: Path,
    source: str,
    masked: str,
    known_assignments: dict,
) -> dict[str, Tool]:
    result: dict[str, Tool] = {}
    for name, assignment in known_assignments.items():
        expression = assignment.expression
        if "CopilotTool.DefineTool" not in expression:
            continue
        match = re.search(
            r"CopilotTool\.DefineTool\s*\(\s*([A-Za-z_]\w*)",
            expression,
        )
        target = match.group(1) if match else None
        factory_name = named_string(expression, "Name")
        tool_name = factory_name or target or name
        body_info = method_body(source, masked, target) if target else None
        capabilities = (
            _csharp_body_capabilities(body_info[0])
            if body_info is not None
            else set()
        )
        tool = Tool(
            name=tool_name,
            kind="function",
            capabilities=capabilities,
            location=csharp_location(path, source, assignment.offset),
            metadata={
                "framework": FRAMEWORK,
                "binding_origin": "CopilotTool.DefineTool",
                "wrapped": target,
            },
        )
        if body_info is not None:
            _attach_literal_destinations(tool, body_info[0])
        result[name] = tool
    return result


def _csharp_collection(value: str | None) -> list[str] | None:
    if value is None:
        return None
    strings = re.findall(r'@?"([^"]+)"', value)
    return strings if strings else []


def _csharp_call_argument(
    expression: str,
    method_name: str,
    index: int = 0,
) -> str | None:
    masked = mask_non_code(expression)
    match = re.search(
        rf"\.{re.escape(method_name)}\s*\(",
        masked,
    )
    if not match:
        return None
    start = masked.find("(", match.start())
    if start < 0:
        return None
    end = balanced_end(masked, start, "(", ")")
    if end is None:
        return None
    body = expression[start + 1:end]
    body_masked = masked[start + 1:end]
    parts: list[str] = []
    offset = 0
    paren = bracket = brace = 0
    for pos, char in enumerate(body_masked):
        if char == "(":
            paren += 1
        elif char == ")":
            paren = max(0, paren - 1)
        elif char == "[":
            bracket += 1
        elif char == "]":
            bracket = max(0, bracket - 1)
        elif char == "{":
            brace += 1
        elif char == "}":
            brace = max(0, brace - 1)
        elif char == "," and paren == bracket == brace == 0:
            parts.append(body[offset:pos].strip())
            offset = pos + 1
    parts.append(body[offset:].strip())
    return parts[index] if index < len(parts) and parts[index] else None


def _csharp_initializer_body(expression: str) -> tuple[str, int] | None:
    masked = mask_non_code(expression)
    brace = masked.find("{")
    if brace < 0:
        return None
    end = balanced_end(masked, brace, "{", "}")
    if end is None:
        return None
    return expression[brace + 1:end], brace + 1


def _csharp_session_config(
    expression: str,
    known_assignments: dict,
) -> tuple[str, int] | None:
    argument = _csharp_call_argument(expression, "CreateSessionAsync", 0)
    if not argument:
        return None
    candidate = argument.strip()
    assignment = None
    if re.fullmatch(r"[A-Za-z_]\w*", candidate):
        assignment = known_assignments.get(candidate)
        if assignment is None:
            return None
        candidate = assignment.expression
    if (
        "SessionConfig" not in candidate
        and not (
            assignment is not None
            and (assignment.declared_type or "").endswith("SessionConfig")
        )
    ):
        return None
    body = _csharp_initializer_body(candidate)
    if body is None:
        return None
    return body


def _csharp_inline_tool_factories(
    value: str | None,
    location: SourceLocation,
) -> list[Tool]:
    if not value:
        return []
    result: list[Tool] = []
    seen: set[str] = set()
    for match in re.finditer(
        r"\b([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\.CreateTool\s*\(",
        value,
    ):
        owner = match.group(1)
        name = owner.rsplit(".", 1)[-1]
        if name in seen:
            continue
        seen.add(name)
        result.append(
            Tool(
                name=name,
                kind="function",
                capabilities=set(),
                location=location,
                metadata={
                    "framework": FRAMEWORK,
                    "binding_origin": "CreateTool",
                    "factory_reference": owner,
                    "placeholder": True,
                    "authority_binding": True,
                    "authority_binding_basis": "source_factory_reference",
                },
            )
        )
    return result


def _csharp_initializer_entries(value: str, type_name: str) -> list[tuple[str, str, int]]:
    result: list[tuple[str, str, int]] = []
    pattern = re.compile(
        rf'\["([^"]+)"\]\s*=\s*new\s+{re.escape(type_name)}\b'
    )
    masked = mask_comments(value)
    for match in pattern.finditer(masked):
        brace = masked.find("{", match.end())
        if brace < 0:
            continue
        end = balanced_end(masked, brace, "{", "}")
        if end is None:
            continue
        result.append((match.group(1), value[brace + 1:end], match.start()))
    return result


def _csharp_braced_property_value(
    expression: str,
    name: str,
) -> str | None:
    masked = mask_non_code(expression)
    match = re.search(rf"\b{re.escape(name)}\s*=", masked, re.IGNORECASE)
    if not match:
        return None
    brace = masked.find("{", match.end())
    if brace < 0:
        return None
    end = balanced_end(masked, brace, "{", "}")
    if end is None:
        return None
    return expression[match.end():end + 1].strip()


def _csharp_mcp_servers(
    path: Path,
    source: str,
    config_expression: str,
    *,
    base_offset: int,
) -> list[MCPServer]:
    value = _csharp_braced_property_value(
        config_expression,
        "McpServers",
    )
    if not value:
        return []
    result: list[MCPServer] = []

    for name, body, offset in _csharp_initializer_entries(
        value,
        "McpStdioServerConfig",
    ):
        result.append(
            MCPServer(
                name=name,
                transport="stdio",
                command=named_string(body, "Command"),
                args=collection_strings(body, "Args"),
                allowed_tools=collection_strings(body, "Tools"),
                location=csharp_location(path, source, base_offset + offset),
                metadata={"framework": FRAMEWORK, "provider": "github-copilot"},
            )
        )

    for name, body, offset in _csharp_initializer_entries(
        value,
        "McpHttpServerConfig",
    ):
        url = named_string(body, "Url")
        auth = "Headers" in body or "Bearer" in body or "OAuth" in body
        metadata: dict[str, object] = {
            "framework": FRAMEWORK,
            "provider": "github-copilot",
        }
        if url is None:
            metadata.update(
                {
                    "dynamic_mcp_endpoint_basis": "operator_configuration",
                    "network_scope": "operator_configured_destination",
                }
            )
        result.append(
            MCPServer(
                name=name,
                transport="streamable-http",
                url=url,
                authenticated=True if auth else None,
                allowed_tools=collection_strings(body, "Tools"),
                location=csharp_location(path, source, base_offset + offset),
                metadata=metadata,
            )
        )
    return result


def _csharp_session_custom_agents(
    path: Path,
    source: str,
    config_expression: str,
    *,
    parent: Agent,
    approve_all: bool,
) -> list[Agent]:
    value = argument_value(config_expression, "CustomAgents")
    if not value:
        return []
    masked = mask_non_code(value)
    result: list[Agent] = []
    for match in re.finditer(r"new\s*(?:CustomAgentConfig)?\s*\(\s*\)\s*\{", masked):
        brace = masked.find("{", match.start())
        if brace < 0:
            continue
        end = balanced_end(masked, brace, "{", "}")
        if end is None:
            continue
        body = value[brace + 1:end]
        name = named_string(body, "Name")
        if not name:
            continue
        tool_names = _csharp_collection(argument_value(body, "Tools"))
        child = Agent(
            name=name,
            location=parent.location,
            metadata={
                "framework": FRAMEWORK,
                "runtime": "copilot-cli",
                "custom_agent": True,
                "parent_session": parent.name,
                "automatic_inference": not bool(
                    re.search(r"\bInfer\s*=\s*false\b", body, re.IGNORECASE)
                ),
            },
        )
        if tool_names is None:
            child.tools = [
                deepcopy(tool)
                for tool in parent.tools
                if tool.kind != "delegated_agent"
            ]
            child.mcp_servers = deepcopy(parent.mcp_servers)
        else:
            builtin = _builtin_tool(
                location=parent.location,
                available=tool_names,
                excluded=None,
                approve_all=approve_all,
                working_directory=None,
                additional_directories=None,
            )
            if builtin:
                child.tools.append(builtin)
            requested = set(tool_names)
            for tool in parent.tools:
                if tool.kind == "github_copilot_builtin_tools":
                    continue
                if tool.name in requested or f"custom:{tool.name}" in requested:
                    child.tools.append(deepcopy(tool))
            for server in parent.mcp_servers:
                if any(
                    item.startswith(
                        (f"{server.name}-", f"mcp:{server.name}-")
                    )
                    for item in requested
                ):
                    child.mcp_servers.append(deepcopy(server))
        result.append(child)
    return result


def _scan_csharp(path: Path, source: str) -> Graph:
    graph = Graph()
    if "GitHub.Copilot" not in source:
        return graph

    masked = mask_non_code(source)
    known = csharp_assignments(source, masked)
    custom_tools = _csharp_custom_tools(path, source, masked, known)

    clients = {
        name
        for name, assignment in known.items()
        if (
            "CopilotClient" in assignment.expression
            or (assignment.declared_type or "").endswith("CopilotClient")
        )
    }

    # MAF provider bridge: copilotClient.AsAIAgent(...)
    for name, assignment in known.items():
        expression = assignment.expression
        match = re.search(r"\b([A-Za-z_]\w*)\.AsAIAgent\s*\(", expression)
        if not match or match.group(1) not in clients:
            continue
        location = csharp_location(path, source, assignment.offset)
        agent = Agent(
            name=name,
            location=location,
            metadata={
                "framework": FRAMEWORK,
                "runtime": "copilot-cli",
                "maf_integration": True,
                "language": "csharp",
            },
        )
        builtin = _builtin_tool(
            location=location,
            available=None,
            excluded=None,
            approve_all=False,
            working_directory=None,
            additional_directories=None,
        )
        if builtin:
            agent.tools.append(builtin)
        tools_value = argument_value(expression, "Tools")
        for ref in refs(tools_value or ""):
            if ref in custom_tools:
                agent.tools.append(deepcopy(custom_tools[ref]))
        graph.agents.append(agent)

    for name, assignment in known.items():
        expression = assignment.expression
        match = re.match(
            r"\s*(?:await\s+)?([A-Za-z_]\w*)\.CreateSessionAsync\s*\(",
            expression,
        )
        if not match or (clients and match.group(1) not in clients):
            continue
        resolved_config = _csharp_session_config(expression, known)
        if resolved_config is None:
            continue
        config, config_relative_offset = resolved_config
        location = csharp_location(path, source, assignment.offset)

        approve_all = "PermissionHandler.ApproveAll" in config
        available = _csharp_collection(argument_value(config, "AvailableTools"))
        excluded = _csharp_collection(argument_value(config, "ExcludedTools"))
        working_expr = argument_value(config, "WorkingDirectory")
        working = unquote(working_expr) if working_expr else None
        additional = _csharp_collection(argument_value(config, "AdditionalDirectories"))

        agent = Agent(
            name=name,
            location=location,
            metadata={
                "framework": FRAMEWORK,
                "runtime": "copilot-cli",
                "language": "csharp",
                "session_operation": "CreateSessionAsync",
            },
        )
        builtin = _builtin_tool(
            location=location,
            available=available,
            excluded=excluded,
            approve_all=approve_all,
            working_directory=working,
            additional_directories=additional,
        )
        if builtin:
            agent.tools.append(builtin)

        tools_value = argument_value(config, "Tools")
        bound_custom_tools = 0
        for ref in refs(tools_value or ""):
            if ref in custom_tools:
                agent.tools.append(deepcopy(custom_tools[ref]))
                bound_custom_tools += 1
        inline_tools = _csharp_inline_tool_factories(tools_value, location)
        agent.tools.extend(inline_tools)
        bound_custom_tools += len(inline_tools)
        if tools_value and bound_custom_tools == 0:
            agent.tools.append(
                Tool(
                    name="copilot-custom-tools",
                    kind="dynamic_tool_reference",
                    capabilities=set(),
                    location=location,
                    metadata={
                        "framework": FRAMEWORK,
                        "placeholder": True,
                        "authority_binding": True,
                        "authority_binding_basis": "session_config_tools_expression",
                        "dynamic_tool_catalogue": True,
                        "tools_expression": tools_value,
                    },
                )
            )

        disabled = set(
            _csharp_collection(argument_value(config, "DisabledMcpServers")) or []
        )
        agent.mcp_servers.extend(
            server
            for server in _csharp_mcp_servers(
                path,
                source,
                config,
                base_offset=assignment.offset + config_relative_offset,
            )
            if server.name not in disabled
        )

        identity_source = "copilot_cli_logged_in_user"
        if "GitHubToken" in source or "GithubToken" in source:
            identity_source = "github_token"
        agent.identities.append(
            Identity(
                name="github-copilot-auth",
                provider="github",
                credential_source=identity_source,
                location=location,
                metadata={"runtime_resolved": True},
            )
        )

        children = _csharp_session_custom_agents(
            path,
            source,
            config,
            parent=agent,
            approve_all=approve_all,
        )
        for child in children:
            graph.agents.append(child)
            agent.tools.append(_delegation_tool(child, location))

        graph.agents.append(agent)

    return graph


def is_github_copilot_sdk_file(path: Path) -> bool:
    if path.suffix.lower() not in {".py", ".cs"}:
        return False
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False
    if path.suffix.lower() == ".py":
        return (
            ("from copilot import" in source or "import copilot" in source)
            and ("create_session" in source or "CopilotClient" in source)
        ) or (
            "agent_framework.github" in source
            and "GitHubCopilotAgent" in source
        )
    return (
        "GitHub.Copilot" in source
        and (
            "CreateSessionAsync" in source
            or ".AsAIAgent(" in source
            or "CopilotTool.DefineTool" in source
        )
    )


def scan_github_copilot_sdk_file(path: Path) -> Graph:
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return Graph()
    if not is_github_copilot_sdk_file(path):
        return Graph()
    if path.suffix.lower() == ".py":
        return _scan_python(path, source)
    if path.suffix.lower() == ".cs":
        return _scan_csharp(path, source)
    return Graph()
