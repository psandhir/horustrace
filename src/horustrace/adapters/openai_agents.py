# ruff: noqa: I001

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from horustrace.heuristics import infer_capabilities
from horustrace.models import (
    Agent,
    Graph,
    InputSource,
    MCPServer,
    NetworkDestination,
    SourceLocation,
    Tool,
)


_OPENAI_AGENT_EXPORTS = {
    "Agent", "Runner", "RunContextWrapper", "function_tool", "handoff",
    "input_guardrail", "output_guardrail", "trace",
    "enable_verbose_stdout_logging", "ShellTool", "ApplyPatchTool",
    "HostedMCPTool", "WebSearchTool", "FileSearchTool",
    "CodeInterpreterTool", "ImageGenerationTool", "ComputerTool",
    "ToolSearchTool",
}


_OPENAI_AGENT_SUBMODULES = (
    "agents.mcp",
    "agents.tool",
    "agents.run_context",
    "agents.extensions",
    "agents.models",
    "agents.items",
    "agents.guardrail",
    "agents.lifecycle",
    "agents.memory",
    "agents.tracing",
)


def _is_openai_agents_module(module: str) -> bool:
    if module == "agents" or module.startswith("openai.agents"):
        return True
    return any(
        module == prefix or module.startswith(prefix + ".")
        for prefix in _OPENAI_AGENT_SUBMODULES
    )


def _uses_openai_agents(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module == "agents":
                if any(alias.name in _OPENAI_AGENT_EXPORTS for alias in node.names):
                    return True
                continue
            if _is_openai_agents_module(module):
                return True
        if isinstance(node, ast.Import) and any(
            _is_openai_agents_module(alias.name) for alias in node.names
        ):
            return True
    return False


def is_openai_agents_file(path: Path) -> bool:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return False
    return _uses_openai_agents(tree)


MCP_TYPES = {
    "MCPServerStdio": "stdio",
    "MCPServerSse": "sse",
    "MCPServerStreamableHttp": "streamable-http",
}


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Subscript):
        return _call_name(node.value)
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _dotted_name(node: ast.AST | None) -> str | None:
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


def _literal(node: ast.AST | None) -> Any:
    if node is None:
        return None
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError):
        return None


def _kw(call: ast.Call, name: str) -> ast.AST | None:
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _approval_value(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.lower()
        if lowered == "always":
            return True
        if lowered == "never":
            return False
    if isinstance(value, dict):
        values = list(value.values())
        if values and all(v == "always" or v is True for v in values):
            return True
        if values and all(v == "never" or v is False for v in values):
            return False
    return None


def _location(path: Path, node: ast.AST) -> SourceLocation:
    return SourceLocation(path=path, line=getattr(node, "lineno", 1), column=getattr(node, "col_offset", 0) + 1)


_HOSTED_TOOL_CAPABILITIES: dict[str, tuple[str, set[str]]] = {
    "WebSearchTool": ("openai_web_search", {"data.read", "network.external"}),
    "FileSearchTool": ("openai_file_search", {"data.read"}),
    "CodeInterpreterTool": (
        "openai_code_interpreter",
        {"process.execute", "data.read", "data.write"},
    ),
    "ImageGenerationTool": (
        "openai_image_generation",
        {"external.write", "network.external"},
    ),
    "ComputerTool": (
        "openai_computer",
        {"computer.control", "data.read", "data.write", "network.external"},
    ),
    "ToolSearchTool": ("openai_tool_search", {"data.read"}),
}


def _tool_from_call(path: Path, node: ast.Call, alias: str | None = None) -> Tool | None:
    name = _call_name(node.func)
    if not name:
        return None

    if name in _HOSTED_TOOL_CAPABILITIES:
        kind, capabilities = _HOSTED_TOOL_CAPABILITIES[name]
        tool = Tool(
            name=alias or name,
            kind=kind,
            capabilities=set(capabilities),
            location=_location(path, node),
            metadata={
                "framework": "openai-agents",
                "provider_managed": True,
                "hosted_tool": name,
            },
        )
        if name == "WebSearchTool":
            tool.metadata["untrusted_input"] = True
        return tool

    if name == "activity_as_tool":
        wrapped = node.args[0] if node.args else _kw(node, "activity")
        wrapped_name = _call_name(wrapped) or alias or "temporal_activity"
        return Tool(
            name=alias or wrapped_name,
            kind="temporal_activity_tool",
            capabilities=set(infer_capabilities(wrapped_name)),
            location=_location(path, node),
            metadata={
                "framework": "openai-agents",
                "wrapper": "activity_as_tool",
                "wrapped": wrapped_name,
            },
        )

    if isinstance(node.func, ast.Attribute) and node.func.attr == "as_tool":
        target = _dotted_name(node.func.value) or _call_name(node.func.value) or "agent"
        runtime_name = _literal(_kw(node, "tool_name"))
        return Tool(
            name=str(runtime_name or alias or target),
            kind="delegated_agent",
            capabilities={"agent.delegate"},
            location=_location(path, node),
            metadata={
                "framework": "openai-agents",
                "delegate_target": target,
                "source": "agent.as_tool",
                "binding_origin": "agent_as_tool",
            },
        )

    if name == "ShellTool":
        approval = _approval_value(_literal(_kw(node, "needs_approval")))
        return Tool(
            name=alias or "ShellTool",
            kind="shell",
            capabilities={"process.execute", "data.read", "data.write", "network.external"},
            approval=approval,
            location=_location(path, node),
            metadata={"implicit_network": True,
                      "approval_hook_detected": _kw(node, "on_approval") is not None},
        )

    if name == "ApplyPatchTool":
        approval = _approval_value(_literal(_kw(node, "needs_approval")))
        return Tool(
            name=alias or "ApplyPatchTool",
            kind="apply_patch",
            capabilities={"data.write"},
            approval=approval,
            metadata={"approval_hook_detected": _kw(node, "on_approval") is not None},
            location=_location(path, node),
        )

    if name == "HostedMCPTool":
        config = _literal(_kw(node, "tool_config")) or {}
        server_label = str(config.get("server_label") or alias or "hosted-mcp")
        approval = _approval_value(config.get("require_approval"))
        tool = Tool(
            name=server_label,
            kind="hosted_mcp",
            capabilities={"mcp.remote", "network.external"},
            approval=approval,
            guardrails=_kw(node, "on_approval_request") is not None,
            location=_location(path, node),
            metadata={
                "server_url": config.get("server_url"),
                "connector_id": config.get("connector_id"),
                "allowed_tools": config.get("allowed_tools"),
            },
        )
        if config.get("server_url"):
            tool.destinations.append(
                NetworkDestination(
                    target=str(config["server_url"]),
                    restricted=True,
                    location=tool.location,
                )
            )
        return tool

    return None


def _static_string(node: ast.AST | None, constants: dict[str, str]) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    return None


def _dict_nodes(node: ast.AST | None) -> dict[str, ast.AST]:
    if not isinstance(node, ast.Dict):
        return {}
    result: dict[str, ast.AST] = {}
    for key, value in zip(node.keys, node.values):
        literal = _literal(key)
        if isinstance(literal, str):
            result[literal] = value
    return result


def _credential_reference(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    if isinstance(node, ast.Call):
        called = (_dotted_name(node.func) or _call_name(node.func) or "").lower()
        if called in {"os.getenv", "os.environ.get"} and node.args:
            name = _literal(node.args[0])
            if isinstance(name, str):
                return f"env:{name}"
    if isinstance(node, ast.Subscript):
        dotted = (_dotted_name(node.value) or "").lower()
        if dotted == "os.environ":
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
    if not isinstance(headers_node, ast.Dict):
        return None
    auth_headers = {"authorization", "proxy-authorization", "x-api-key", "x-goog-api-key"}
    references: list[str] = []
    for key_node, value_node in zip(headers_node.keys, headers_node.values):
        key = _literal(key_node)
        if not isinstance(key, str) or key.lower() not in auth_headers:
            continue
        reference = _credential_reference(value_node)
        if reference:
            references.append(reference)
    unique = list(dict.fromkeys(references))
    return unique[0] if len(unique) == 1 else None


def _mcp_from_call(
    path: Path,
    node: ast.Call,
    alias: str,
    constants: dict[str, str] | None = None,
) -> MCPServer | None:
    call_name = _call_name(node.func)
    if call_name not in MCP_TYPES:
        return None

    constants = constants or {}
    params_node = _kw(node, "params")
    params = _literal(params_node) or {}
    entries = _dict_nodes(params_node)
    url = (
        params.get("url") if isinstance(params, dict) else None
    ) or _static_string(entries.get("url"), constants)
    command = (
        params.get("command") if isinstance(params, dict) else None
    ) or _static_string(entries.get("command"), constants)

    args_node = entries.get("args")
    args = params.get("args", []) if isinstance(params, dict) else []
    if not isinstance(args, list):
        literal_args = _literal(args_node)
        args = literal_args if isinstance(literal_args, list) else []

    headers_node = entries.get("headers")
    headers = params.get("headers", {}) if isinstance(params, dict) else {}
    header_keys = (
        {str(k).lower() for k in headers}
        if isinstance(headers, dict)
        else set()
    )
    if isinstance(headers_node, ast.Dict):
        for key in headers_node.keys:
            literal = _literal(key)
            if isinstance(literal, str):
                header_keys.add(literal.lower())
    authenticated = (
        bool({"authorization", "proxy-authorization", "x-api-key", "x-goog-api-key"} & header_keys)
        if url
        else None
    )
    approval = _approval_value(_literal(_kw(node, "require_approval")))
    guardrails = bool(_literal(_kw(node, "tool_input_guardrails"))) or bool(
        _literal(_kw(node, "tool_output_guardrails"))
    )

    allowed_tools: list[str] = []
    denied_tools: list[str] = []
    dynamic_tool_filter = False
    tool_filter_node = _kw(node, "tool_filter")
    if tool_filter_node is not None:
        if (
            isinstance(tool_filter_node, ast.Call)
            and _call_name(tool_filter_node.func) == "create_static_tool_filter"
        ):
            allowed = _literal(_kw(tool_filter_node, "allowed_tool_names"))
            blocked = _literal(_kw(tool_filter_node, "blocked_tool_names"))
            if isinstance(allowed, list) and all(isinstance(item, str) for item in allowed):
                allowed_tools = list(allowed)
            elif _kw(tool_filter_node, "allowed_tool_names") is not None:
                dynamic_tool_filter = True
            if isinstance(blocked, list) and all(isinstance(item, str) for item in blocked):
                denied_tools = list(blocked)
            elif _kw(tool_filter_node, "blocked_tool_names") is not None:
                dynamic_tool_filter = True
        elif isinstance(_literal(tool_filter_node), dict):
            value = _literal(tool_filter_node)
            allowed = value.get("allowed_tool_names")
            blocked = value.get("blocked_tool_names")
            if isinstance(allowed, list) and all(isinstance(item, str) for item in allowed):
                allowed_tools = list(allowed)
            if isinstance(blocked, list) and all(isinstance(item, str) for item in blocked):
                denied_tools = list(blocked)
        else:
            dynamic_tool_filter = True

    return MCPServer(
        name=alias,
        transport=MCP_TYPES[call_name],
        url=str(url) if url else None,
        command=str(command) if command else None,
        args=[str(x) for x in args],
        authenticated=authenticated,
        approval=approval,
        guardrails=guardrails,
        allowed_tools=allowed_tools,
        denied_tools=denied_tools,
        location=_location(path, node),
        metadata={
            "auth_headers": sorted(header_keys),
            "credential_source": _auth_credential_source(headers_node),
            "dynamic_mcp_endpoint": bool(
                params_node is not None
                and entries.get("url") is not None
                and url is None
            ),
            "dynamic_tool_filter": dynamic_tool_filter,
        },
    )

def _inline_confirmation_gate(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Detect a conservative preview/confirm execution gate inside a tool function."""
    confirmation_names = {
        arg.arg
        for arg in [*node.args.args, *node.args.kwonlyargs]
        if arg.arg.lower() in {"confirmed", "confirm", "approved", "approve"}
    }
    if not confirmation_names:
        return False

    for child in ast.walk(node):
        if not isinstance(child, ast.If):
            continue
        negated_confirmation = any(
            isinstance(test_node, ast.UnaryOp)
            and isinstance(test_node.op, ast.Not)
            and isinstance(test_node.operand, ast.Name)
            and test_node.operand.id in confirmation_names
            for test_node in ast.walk(child.test)
        )
        if not negated_confirmation:
            continue
        if any(isinstance(body_node, ast.Return) for statement in child.body for body_node in ast.walk(statement)):
            return True
    return False


_CONTROL_HELPER_PREFIXES = {
    "approve",
    "check",
    "confirm",
    "validate",
    "verify",
}
_CONTROL_NAME_SENSITIVE_CAPABILITIES = {
    "data.write",
    "destructive.write",
    "external.write",
    "identity.admin",
    "network.external",
    "process.execute",
    "secrets.read",
}


def _body_call_capabilities(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[str]:
    """Collect semantic evidence from calls made by a decorated tool body."""
    capabilities: set[str] = set()
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        called = _dotted_name(child.func) or _call_name(child.func) or ""
        capabilities.update(infer_capabilities(called))

        normalized = called.lower()
        if (
            normalized
            in {
                "exec",
                "eval",
                "compile",
                "builtins.exec",
                "builtins.eval",
                "builtins.compile",
                "os.system",
                "os.popen",
            }
            or normalized.startswith("subprocess.")
            or "create_subprocess_" in normalized
        ):
            capabilities.add("process.execute")
    return capabilities


def _decorated_tool_capabilities(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[set[str], dict[str, Any]]:
    """Keep control/helper names from implying privileged side effects by themselves."""
    name_capabilities = set(infer_capabilities(node.name))
    body_capabilities = _body_call_capabilities(node)
    capabilities = set(name_capabilities)

    first_token = node.name.lower().replace("-", "_").split("_", 1)[0]
    suppressed: set[str] = set()
    if first_token in _CONTROL_HELPER_PREFIXES:
        suppressed = (
            name_capabilities
            & _CONTROL_NAME_SENSITIVE_CAPABILITIES
            - body_capabilities
        )
        capabilities.difference_update(suppressed)

    metadata: dict[str, Any] = {
        "name_inferred_capabilities": sorted(name_capabilities),
        "body_call_inferred_capabilities": sorted(body_capabilities),
    }
    if suppressed:
        metadata["suppressed_name_only_capabilities"] = sorted(suppressed)
        metadata["capability_inference"] = "control_helper_body_corroboration"
    return capabilities, metadata


def _decorated_tool_network_destinations(
    path: Path,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[NetworkDestination]:
    destinations: list[NetworkDestination] = []
    seen: set[tuple[str, str]] = set()
    literal_urls: dict[str, set[str]] = {}

    for statement in node.body:
        if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
            continue
        value = statement.value
        if not (
            isinstance(value, ast.Constant)
            and isinstance(value.value, str)
            and value.value.startswith(("http://", "https://"))
            and urlparse(value.value).hostname
        ):
            continue
        targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
        for target in targets:
            if isinstance(target, ast.Name):
                literal_urls.setdefault(target.id, set()).add(value.value)

    def add(target: str, source: str, location: ast.AST) -> None:
        key = (target, source)
        if key in seen:
            return
        seen.add(key)
        destinations.append(
            NetworkDestination(
                target=target,
                restricted=False,
                location=_location(path, location),
                metadata={
                    "source": source,
                    "network_scope": (
                        "fixed_literal_destination"
                        if source == "literal_url"
                        else "dynamic_destination"
                    ),
                },
            )
        )

    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        called = (_dotted_name(child.func) or _call_name(child.func) or "").lower()
        is_network_call = (
            called.startswith(("requests.", "httpx.", "aiohttp."))
            or "urllib.request" in called
        )
        if not is_network_call:
            continue

        target_expr = _kw(child, "url")
        if target_expr is None:
            if called.endswith(".request") and len(child.args) >= 2:
                target_expr = child.args[1]
            elif child.args:
                target_expr = child.args[0]

        direct = _literal(target_expr)
        if isinstance(direct, str) and direct.startswith(("http://", "https://")):
            if urlparse(direct).hostname:
                add(direct, "literal_url", target_expr or child)
            continue

        if target_expr is not None:
            for part in ast.walk(target_expr):
                if (
                    isinstance(part, ast.Constant)
                    and isinstance(part.value, str)
                    and part.value.startswith(("http://", "https://"))
                    and urlparse(part.value).hostname
                ):
                    add(part.value, "literal_url", part)
                elif isinstance(part, ast.Name):
                    for possible in sorted(literal_urls.get(part.id, ())):
                        add(possible, "literal_url", part)

        add("<dynamic-url>", "dynamic_network_call", target_expr or child)

    return destinations


def _decorated_function_tool(path: Path, node: ast.FunctionDef | ast.AsyncFunctionDef) -> Tool | None:
    for decorator in node.decorator_list:
        decorator_name: str | None = None
        needs_approval: bool | None = None
        guardrails = False

        if isinstance(decorator, ast.Call):
            decorator_name = _call_name(decorator.func)
            needs_approval = _approval_value(_literal(_kw(decorator, "needs_approval")))
            guardrails = bool(_literal(_kw(decorator, "tool_input_guardrails"))) or bool(
                _literal(_kw(decorator, "tool_output_guardrails"))
            )
        else:
            decorator_name = _call_name(decorator)

        if decorator_name in {"function_tool", "tool"}:
            inline_approval = _inline_confirmation_gate(node)
            capabilities, capability_metadata = _decorated_tool_capabilities(node)
            tool = Tool(
                name=node.name,
                kind="function",
                capabilities=capabilities,
                approval=True if inline_approval else needs_approval,
                guardrails=guardrails or inline_approval,
                location=_location(path, node),
                metadata={
                    **capability_metadata,
                    "approval_mechanism": (
                        "inline_confirmation" if inline_approval else None
                    ),
                    "approval_scope": "execution_gate" if inline_approval else None,
                    "approval_mandatory": True if inline_approval else None,
                },
            )
            tool.destinations.extend(_decorated_tool_network_destinations(path, node))
            return tool
    return None


def _resolve_sequence(expr: ast.AST | None, sequences: dict[str, list[ast.AST]]) -> list[ast.AST]:
    if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        return list(expr.elts)
    if isinstance(expr, ast.Name):
        return list(sequences.get(expr.id, []))
    return []


def _enclosing_function_parameter_names(
    functions: list[ast.FunctionDef | ast.AsyncFunctionDef],
    node: ast.AST,
) -> set[str]:
    line = getattr(node, "lineno", 0)
    candidates = [
        function
        for function in functions
        if getattr(function, "lineno", 0) <= line <= getattr(function, "end_lineno", 0)
    ]
    if not candidates:
        return set()
    function = min(
        candidates,
        key=lambda item: getattr(item, "end_lineno", 0) - getattr(item, "lineno", 0),
    )
    names = {
        arg.arg
        for arg in [
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
        ]
    }
    if function.args.vararg is not None:
        names.add(function.args.vararg.arg)
    if function.args.kwarg is not None:
        names.add(function.args.kwarg.arg)
    return names


def scan_python_file(path: Path) -> Graph:
    graph = Graph()
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (SyntaxError, UnicodeDecodeError, OSError):
        return graph
    if not _uses_openai_agents(tree):
        return graph

    tools: dict[str, Tool] = {}
    mcp_servers: dict[str, MCPServer] = {}
    sequences: dict[str, list[ast.AST]] = {}
    functions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    imports: dict[str, str] = {}
    constants: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                imports[alias.asname or alias.name] = module
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            literal = _literal(value)
            if isinstance(literal, str):
                for target in targets:
                    if isinstance(target, ast.Name):
                        constants[target.id] = literal

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            tool = _decorated_function_tool(path, node)
            if tool:
                tools[node.name] = tool

        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            targets: list[ast.AST] = node.targets if isinstance(node, ast.Assign) else [node.target]
            alias = next((target.id for target in targets if isinstance(target, ast.Name)), None)
            if not alias:
                continue
            if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
                sequences[alias] = list(value.elts)
                continue
            if not isinstance(value, ast.Call):
                continue
            tool = _tool_from_call(path, value, alias)
            if tool:
                tools[alias] = tool
            server = _mcp_from_call(path, value, alias, constants)
            if server:
                mcp_servers[alias] = server

        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if not isinstance(item.context_expr, ast.Call) or not isinstance(item.optional_vars, ast.Name):
                    continue
                alias = item.optional_vars.id
                server = _mcp_from_call(path, item.context_expr, alias, constants)
                if server:
                    mcp_servers[alias] = server

    agent_names_by_alias: dict[str, str] = {}
    for statement in ast.walk(tree):
        if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
            continue
        value = statement.value
        if not isinstance(value, ast.Call) or _call_name(value.func) != "Agent":
            continue
        targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
        alias = next((target.id for target in targets if isinstance(target, ast.Name)), None)
        if alias:
            runtime_name = _literal(_kw(value, "name"))
            agent_names_by_alias[alias] = str(runtime_name or alias)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or _call_name(node.func) != "Agent":
            continue

        name_value = _literal(_kw(node, "name"))
        instructions = _literal(_kw(node, "instructions"))
        metadata: dict[str, Any] = {"framework": "openai-agents"}
        if isinstance(instructions, str):
            metadata["instructions"] = instructions
        model = _literal(_kw(node, "model"))
        if isinstance(model, str):
            metadata["model"] = model
        agent = Agent(
            name=str(name_value or f"agent@{getattr(node, 'lineno', 1)}"),
            location=_location(path, node),
            metadata=metadata,
        )

        tools_expr = _kw(node, "tools")
        parameter_names = _enclosing_function_parameter_names(functions, node)
        if isinstance(tools_expr, ast.Name) and tools_expr.id in parameter_names:
            agent.metadata["dynamic_tools"] = True
            tool_elements: list[ast.AST] = []
        else:
            tool_elements = _resolve_sequence(tools_expr, sequences)

        for element in tool_elements:
            if isinstance(element, ast.Name) and element.id in tools:
                agent.tools.append(tools[element.id])
            elif isinstance(element, ast.Name) and element.id in imports:
                agent.tools.append(
                    Tool(
                        name=element.id,
                        kind="imported_tool_ref",
                        capabilities=set(infer_capabilities(element.id)),
                        location=_location(path, element),
                        metadata={
                            "framework": "openai-agents",
                            "import_module": imports[element.id],
                            "placeholder": True,
                        },
                    )
                )
            elif isinstance(element, ast.Call):
                direct_tool = _tool_from_call(path, element)
                if direct_tool:
                    agent.tools.append(direct_tool)

        for element in _resolve_sequence(_kw(node, "mcp_servers"), sequences):
            if isinstance(element, ast.Name) and element.id in mcp_servers:
                agent.mcp_servers.append(mcp_servers[element.id])
            elif isinstance(element, ast.Name) and element.id in imports:
                agent.mcp_servers.append(
                    MCPServer(
                        name=element.id,
                        transport="configured",
                        authenticated=None,
                        location=_location(path, element),
                        metadata={
                            "framework": "openai-agents",
                            "import_module": imports[element.id],
                            "placeholder": True,
                        },
                    )
                )
            elif isinstance(element, ast.Constant) and isinstance(element.value, str):
                agent.mcp_servers.append(
                    MCPServer(
                        name=element.value,
                        transport="configured",
                        authenticated=None,
                        location=_location(path, element),
                        metadata={
                            "framework": "openai-agents",
                            "config_reference": True,
                            "dynamic_mcp_endpoint": True,
                        },
                    )
                )

        delegates: list[str] = []
        for element in _resolve_sequence(_kw(node, "handoffs"), sequences):
            if isinstance(element, ast.Name):
                delegates.append(agent_names_by_alias.get(element.id, element.id))
            elif isinstance(element, ast.Call):
                target_node = element.args[0] if element.args else _kw(element, "agent")
                target = _call_name(target_node)
                if target:
                    delegates.append(agent_names_by_alias.get(target, target))
        if delegates:
            agent.metadata["delegates_to"] = list(dict.fromkeys(delegates))
            agent.metadata["handoff_semantics"] = True

        # Infer inbound untrusted content only for tools whose names/kinds imply retrieval/browser input.
        inbound_markers = ("search", "browser", "fetch", "retrieve", "web_read", "read_email", "inbox", "webhook")
        inbound_tools = [
            t for t in agent.tools
            if t.kind == "hosted_mcp" or any(marker in t.name.lower() for marker in inbound_markers)
        ]
        if inbound_tools or any(server.url for server in agent.mcp_servers):
            agent.inputs.append(
                InputSource(
                    name="external-content",
                    trust="untrusted",
                    kind="web",
                    location=agent.location,
                    metadata={"inferred": True},
                )
            )

        graph.agents.append(agent)

    # OpenAI Agents commonly attach MCP servers to a runtime clone rather than the
    # base Agent declaration. Treat a statically resolvable clone as an effective
    # runtime variant so security analysis includes that MCP authority.
    agents_by_name = {agent.name: agent for agent in graph.agents}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "clone":
            continue
        base_alias = _call_name(node.func.value)
        base_name = agent_names_by_alias.get(base_alias or "")
        target = agents_by_name.get(base_name or "")
        if target is None:
            continue
        attached = False
        for element in _resolve_sequence(_kw(node, "mcp_servers"), sequences):
            if isinstance(element, ast.Name) and element.id in mcp_servers:
                server = mcp_servers[element.id]
                if all(existing.name != server.name for existing in target.mcp_servers):
                    target.mcp_servers.append(server)
                attached = True
        if attached:
            target.metadata["runtime_clone_mcp"] = True
            if not any(source.name == "external-content" for source in target.inputs):
                target.inputs.append(
                    InputSource(
                        name="external-content",
                        trust="untrusted",
                        kind="web",
                        location=target.location,
                        metadata={"inferred": True, "source": "runtime_mcp_clone"},
                    )
                )

    bound_tool_ids = {id(tool) for agent in graph.agents for tool in agent.tools}
    bound_server_ids = {id(server) for agent in graph.agents for server in agent.mcp_servers}
    graph.unbound_tools.extend(tool for tool in tools.values() if id(tool) not in bound_tool_ids)
    for server in mcp_servers.values():
        if id(server) in bound_server_ids:
            continue
        server.metadata.setdefault("topology_visible_unbound", True)
        server.metadata.setdefault("binding_state", "unbound")
        server.metadata.setdefault("discovery_source", "openai_agents_mcp")
        graph.unbound_mcp_servers.append(server)
    return graph
