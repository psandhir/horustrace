# ruff: noqa: I001

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from horustrace.heuristics import corroborate_name_inferred_authority, infer_capabilities
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
    "ServerStdio": "stdio",
    "ServerSse": "sse",
    "ServerStreamableHttp": "streamable-http",
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


def _tool_from_call(
    path: Path,
    node: ast.Call,
    alias: str | None = None,
    constants: dict[str, str] | None = None,
    configuration_sources: dict[str, str] | None = None,
) -> Tool | None:
    constants = constants or {}
    configuration_sources = configuration_sources or {}
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
        if name in {"WebSearchTool", "ImageGenerationTool"}:
            tool.destinations.append(
                NetworkDestination(
                    target="<openai-provider>",
                    restricted=True,
                    location=tool.location,
                    metadata={
                        "source": "provider_managed",
                        "network_scope": "fixed_provider_network",
                        "provider": "openai",
                    },
                )
            )
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
        config_node = _kw(node, "tool_config")
        config = _literal(config_node)
        config = config if isinstance(config, dict) else {}
        config_nodes: dict[str, ast.AST] = {}
        if isinstance(config_node, ast.Call) and _call_name(config_node.func) in {
            "Mcp",
            "MCP",
        }:
            config_nodes = {
                keyword.arg: keyword.value
                for keyword in config_node.keywords
                if keyword.arg
            }

        def config_value(key: str) -> Any:
            if key in config:
                return config[key]
            value_node = config_nodes.get(key)
            static = _static_string(value_node, constants)
            return static if static is not None else _literal(value_node)

        server_label = str(
            config_value("server_label") or alias or "hosted-mcp"
        )
        approval = _approval_value(config_value("require_approval"))
        server_url = config_value("server_url")
        server_url_node = config_nodes.get("server_url")
        server_url_source = (
            configuration_sources.get(server_url_node.id)
            if isinstance(server_url_node, ast.Name)
            else None
        )
        allowed_tools = config_value("allowed_tools")
        dynamic_catalogue = not (
            isinstance(allowed_tools, list) and bool(allowed_tools)
        )
        metadata = {
            "server_url": server_url,
            "connector_id": config_value("connector_id"),
            "allowed_tools": allowed_tools,
            "dynamic_remote_mcp_catalogue": dynamic_catalogue,
            "per_call_approval": approval,
        }
        if server_url_node is not None and server_url is None:
            metadata["dynamic_mcp_endpoint"] = True
            metadata["dynamic_mcp_endpoint_basis"] = (
                "operator_configuration"
                if server_url_source
                else "dynamic_expression"
            )
            if server_url_source:
                metadata["configuration_source"] = server_url_source
                metadata["network_scope"] = "operator_configured_destination"

        tool = Tool(
            name=server_label,
            kind="hosted_mcp",
            capabilities={"mcp.remote", "network.external"},
            approval=approval,
            guardrails=_kw(node, "on_approval_request") is not None,
            location=_location(path, node),
            metadata=metadata,
        )
        if server_url:
            tool.destinations.append(
                NetworkDestination(
                    target=str(server_url),
                    restricted=True,
                    location=tool.location,
                    metadata={
                        "source": "literal_url",
                        "network_scope": "fixed_literal_destination",
                    },
                )
            )
        elif server_url_source:
            tool.destinations.append(
                NetworkDestination(
                    target="<operator-configured-mcp>",
                    restricted=True,
                    location=tool.location,
                    metadata={
                        "source": "operator_configuration",
                        "network_scope": "operator_configured_destination",
                        "configuration_source": server_url_source,
                    },
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
    configuration_sources: dict[str, str] | None = None,
) -> MCPServer | None:
    call_name = _call_name(node.func)
    if call_name not in MCP_TYPES:
        return None

    constants = constants or {}
    configuration_sources = configuration_sources or {}
    params_node = _kw(node, "params")
    if (
        params_node is None
        and node.args
        and isinstance(node.args[0], ast.Dict)
    ):
        params_node = node.args[0]
    params = _literal(params_node) or {}
    entries = _dict_nodes(params_node)
    direct_url_node = _kw(node, "url") or (node.args[0] if node.args else None)
    url = (
        params.get("url") if isinstance(params, dict) else None
    ) or _static_string(entries.get("url"), constants) or _static_string(
        direct_url_node,
        constants,
    )
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
    dynamic_url_node = entries.get("url") or direct_url_node
    dynamic_url_source = (
        configuration_sources.get(dynamic_url_node.id)
        if isinstance(dynamic_url_node, ast.Name)
        else None
    )
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
                dynamic_url_node is not None and url is None
            ),
            "dynamic_mcp_endpoint_basis": (
                "operator_configuration"
                if url is None and dynamic_url_source
                else "dynamic_expression"
                if dynamic_url_node is not None and url is None
                else None
            ),
            "configuration_source": dynamic_url_source,
            "network_scope": (
                "operator_configured_destination"
                if url is None and dynamic_url_source
                else None
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
        normalized = called.lower()
        leaf = (_call_name(child.func) or "").lower()
        receiver = child.func.value if isinstance(child.func, ast.Attribute) else None

        # Local/in-memory collection mutation is not persistent authority.
        # Repository/external helper effects are resolved by later source passes.
        if not (
            leaf in {
                "append",
                "extend",
                "insert",
                "remove",
                "pop",
                "clear",
                "update",
                "add",
                "discard",
            }
            and isinstance(receiver, ast.Name)
        ):
            # Arbitrary business/client method names are weak semantic hints,
            # not proof of host execution or network authority. Concrete process
            # sinks are handled below; concrete network sinks/destinations are
            # reconstructed separately from source and repository semantics.
            call_name_capabilities = set(infer_capabilities(called))
            # Process execution is never established by an arbitrary method
            # name. Network/write hints are retained only for explicit outbound
            # action verbs; generic "request"/"api" naming is insufficient.
            call_name_capabilities.discard("process.execute")
            semantic_tokens = {
                token
                for token in called.lower().replace("-", "_").replace(".", "_").split("_")
                if token
            }
            outbound_action_tokens = {
                "send",
                "email",
                "post",
                "publish",
                "upload",
                "notify",
                "notification",
                "message",
                "push",
            }
            if not (semantic_tokens & outbound_action_tokens):
                call_name_capabilities.difference_update(
                    {"network.external", "external.write"}
                )
            capabilities.update(call_name_capabilities)

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


def _context_only_mutation(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    body_capabilities: set[str],
) -> bool:
    """Return True when writes are confined to an agent run-context object."""
    parameter_names = {
        arg.arg
        for arg in [
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
        ]
    }
    context_mutation = False

    def target_is_run_context(target: ast.AST) -> bool:
        dotted = _dotted_name(target)
        if dotted:
            root = dotted.split(".", 1)[0]
            return root in parameter_names and (
                dotted.startswith(f"{root}.context.")
                or dotted == f"{root}.context"
            )
        if isinstance(target, ast.Subscript):
            receiver = _dotted_name(target.value)
            if receiver:
                root = receiver.split(".", 1)[0]
                return root in parameter_names and (
                    receiver.startswith(f"{root}.context.")
                    or receiver == f"{root}.context"
                )
        return False

    for child in ast.walk(node):
        targets: list[ast.AST] = []
        if isinstance(child, ast.Assign):
            targets = list(child.targets)
        elif isinstance(child, (ast.AnnAssign, ast.AugAssign)):
            targets = [child.target]
        elif isinstance(child, ast.Delete):
            targets = list(child.targets)
        if any(target_is_run_context(target) for target in targets):
            context_mutation = True

    if not context_mutation:
        return False
    return not bool(body_capabilities & _CONTROL_NAME_SENSITIVE_CAPABILITIES)


def _decorated_tool_capabilities(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[set[str], dict[str, Any]]:
    """Require source effects before promoting local helpers to privileged authority."""
    name_capabilities = set(infer_capabilities(node.name))
    body_capabilities = _body_call_capabilities(node)
    capabilities, suppressed = corroborate_name_inferred_authority(
        name_capabilities,
        body_capabilities,
    )
    inference_basis: str | None = (
        "body_effect_corroboration" if suppressed else None
    )

    first_token = node.name.lower().replace("-", "_").split("_", 1)[0]
    if first_token in _CONTROL_HELPER_PREFIXES:
        control_suppressed = (
            name_capabilities
            & _CONTROL_NAME_SENSITIVE_CAPABILITIES
            - body_capabilities
        )
        suppressed.update(control_suppressed)
        capabilities.difference_update(control_suppressed)
        if control_suppressed:
            inference_basis = "control_helper_body_corroboration"

    context_only = _context_only_mutation(node, body_capabilities)
    if context_only:
        suppressed.update(
            name_capabilities
            & {"data.write", "destructive.write", "external.write"}
            - body_capabilities
        )
        if inference_basis is None:
            inference_basis = "run_context_effect_boundary"

    capabilities.difference_update(suppressed)

    metadata: dict[str, Any] = {
        "name_inferred_capabilities": sorted(name_capabilities),
        "body_call_inferred_capabilities": sorted(body_capabilities),
    }
    if context_only:
        metadata["effect_scope"] = "run_context"
        metadata["persistent_effect_proven"] = False
    if suppressed:
        metadata["suppressed_name_only_capabilities"] = sorted(suppressed)
        metadata["capability_inference"] = inference_basis
    return capabilities, metadata


def _decorated_tool_network_destinations(
    path: Path,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    imports: dict[str, str] | None = None,
    external_clients: dict[str, str] | None = None,
) -> list[NetworkDestination]:
    destinations: list[NetworkDestination] = []
    seen: set[tuple[str, str]] = set()
    literal_urls: dict[str, set[str]] = {}
    imports = imports or {}
    external_clients = external_clients or {}
    url_parameters = {
        arg.arg
        for arg in [
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
        ]
        if "url" in arg.arg.lower() or arg.arg.lower() in {"uri", "endpoint"}
    }

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
        dotted_called = _dotted_name(child.func) or _call_name(child.func) or ""
        called = dotted_called.lower()
        call_leaf = (_call_name(child.func) or "").lower()
        is_network_call = (
            called.startswith(("requests.", "httpx.", "aiohttp."))
            or "urllib.request" in called
        )

        # Some model-callable tools pass caller-selected URLs through
        # third-party network clients instead of requests/httpx directly.
        # Only treat this as destination authority when both the sink provenance
        # and URL-parameter data flow are source-visible.
        external_sink = False
        if isinstance(child.func, ast.Name):
            source_module = imports.get(child.func.id)
            external_sink = bool(
                source_module
                and call_leaf in {"ingest", "ingest_async", "crawl", "scrape", "extract"}
            )
        elif isinstance(child.func, ast.Attribute):
            receiver = _dotted_name(child.func.value) or _call_name(child.func.value)
            receiver_root = (receiver or "").split(".", 1)[0]
            external_sink = bool(
                receiver_root in external_clients
                and call_leaf in {"crawl", "scrape", "extract", "ingest", "ingest_async"}
            )

        target_expr = _kw(child, "url")
        if target_expr is None:
            target_expr = _kw(child, "urls")
        if target_expr is None:
            if called.endswith(".request") and len(child.args) >= 2:
                target_expr = child.args[1]
            elif child.args:
                target_expr = child.args[0]

        if not is_network_call and external_sink:
            referenced = {
                part.id
                for part in ast.walk(target_expr)
                if isinstance(part, ast.Name)
            } if target_expr is not None else set()
            if not (referenced & url_parameters):
                continue
        elif not is_network_call:
            continue

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

        add(
            "<dynamic-url>",
            "model_selected_url_argument" if external_sink else "dynamic_network_call",
            target_expr or child,
        )

    return destinations


def _decorated_function_tool(
    path: Path,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    imports: dict[str, str] | None = None,
    external_clients: dict[str, str] | None = None,
) -> Tool | None:
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
            tool.destinations.extend(
                _decorated_tool_network_destinations(
                    path,
                    node,
                    imports,
                    external_clients,
                )
            )
            if tool.destinations:
                tool.capabilities.add("network.external")
            return tool
    return None


def _resolve_sequence(expr: ast.AST | None, sequences: dict[str, list[ast.AST]]) -> list[ast.AST]:
    if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        return list(expr.elts)
    if isinstance(expr, ast.Name):
        return list(sequences.get(expr.id, []))
    return []


def _enclosing_function(
    functions: list[ast.FunctionDef | ast.AsyncFunctionDef],
    node: ast.AST,
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    line = getattr(node, "lineno", 0)
    candidates = [
        function
        for function in functions
        if getattr(function, "lineno", 0)
        <= line
        <= getattr(function, "end_lineno", 0)
    ]
    if not candidates:
        return None
    return min(
        candidates,
        key=lambda item: (
            getattr(item, "end_lineno", 0) - getattr(item, "lineno", 0)
        ),
    )


def _enclosing_function_parameter_names(
    functions: list[ast.FunctionDef | ast.AsyncFunctionDef],
    node: ast.AST,
) -> set[str]:
    function = _enclosing_function(functions, node)
    if function is None:
        return set()
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


def _root_name(node: ast.AST | None) -> str | None:
    current = node
    while isinstance(current, ast.Attribute):
        current = current.value
    if isinstance(current, ast.Name):
        return current.id
    return None


def _external_handler_evidence(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> str | None:
    route_names = {
        "websocket",
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "route",
        "api_route",
    }
    for decorator in function.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if _call_name(target) in route_names:
            return "web_route_decorator"

    parameters = [
        *function.args.posonlyargs,
        *function.args.args,
        *function.args.kwonlyargs,
    ]
    for parameter in parameters:
        annotation = _dotted_name(parameter.annotation) or _call_name(
            parameter.annotation
        )
        if annotation and annotation.split(".")[-1] in {
            "WebSocket",
            "Request",
            "HTTPConnection",
        }:
            return "web_framework_parameter"

    for child in ast.walk(function):
        if not isinstance(child, ast.Call):
            continue
        if _call_name(child.func) in {
            "receive_json",
            "receive_text",
            "receive_bytes",
            "json",
            "body",
            "form",
        }:
            return "web_input_read"
    return None


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
    import_symbols: dict[str, str] = {}
    aliases: dict[str, str] = {}
    constants: dict[str, str] = {}
    configuration_sources: dict[str, str] = {}
    external_clients: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                local_name = alias.asname or alias.name
                imports[local_name] = module
                import_symbols[local_name] = alias.name
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        if value is None:
            continue
        source = _credential_reference(value)
        if not source or not source.startswith("env:"):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            if isinstance(target, ast.Name):
                configuration_sources[target.id] = source

    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            literal = _literal(value)
            if isinstance(literal, str):
                for target in targets:
                    if isinstance(target, ast.Name):
                        constants[target.id] = literal
            if isinstance(value, ast.Name):
                for target in targets:
                    if isinstance(target, ast.Name):
                        aliases[target.id] = value.id
            if isinstance(value, ast.Call) and isinstance(value.func, ast.Name):
                source_module = imports.get(value.func.id)
                if source_module:
                    for target in targets:
                        if isinstance(target, ast.Name):
                            external_clients[target.id] = source_module

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            tool = _decorated_function_tool(
                path,
                node,
                imports,
                external_clients,
            )
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
            tool = _tool_from_call(path, value, alias, constants, configuration_sources)
            if tool:
                tools[alias] = tool
            server = _mcp_from_call(path, value, alias, constants, configuration_sources)
            if server:
                mcp_servers[alias] = server

        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if not isinstance(item.context_expr, ast.Call) or not isinstance(item.optional_vars, ast.Name):
                    continue
                alias = item.optional_vars.id
                server = _mcp_from_call(path, item.context_expr, alias, constants, configuration_sources)
                if server:
                    mcp_servers[alias] = server

    agent_names_by_alias: dict[str, str] = {}
    agent_alias_by_line: dict[int, str] = {}
    for statement in ast.walk(tree):
        if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
            continue
        value = statement.value
        if not isinstance(value, ast.Call) or _call_name(value.func) != "Agent":
            continue
        targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
        alias = next((target.id for target in targets if isinstance(target, ast.Name)), None)
        if alias:
            name_node = _kw(value, "name")
            runtime_name = _literal(name_node)
            if runtime_name is None and isinstance(name_node, ast.Name):
                runtime_name = constants.get(name_node.id)
            agent_names_by_alias[alias] = str(runtime_name or alias)
            agent_alias_by_line[getattr(value, "lineno", 1)] = alias

    def resolve_alias(name: str) -> str:
        seen: set[str] = set()
        current = name
        while current in aliases and current not in seen:
            seen.add(current)
            current = aliases[current]
        return current

    def assignment_value_before_node(node: ast.AST, name: str) -> ast.AST | None:
        owner = _enclosing_function(functions, node)
        before_line = getattr(node, "lineno", 0)
        candidates: list[tuple[int, ast.AST]] = []
        for assignment in ast.walk(tree):
            if not isinstance(assignment, (ast.Assign, ast.AnnAssign)):
                continue
            if _enclosing_function(functions, assignment) is not owner:
                continue
            line = getattr(assignment, "lineno", 0)
            if line >= before_line or assignment.value is None:
                continue
            targets = (
                assignment.targets
                if isinstance(assignment, ast.Assign)
                else [assignment.target]
            )
            if any(
                isinstance(target, ast.Name) and target.id == name
                for target in targets
            ):
                candidates.append((line, assignment.value))
        return max(candidates, key=lambda item: item[0])[1] if candidates else None

    def dynamic_collection_tools(node: ast.AST, expr: ast.AST | None) -> list[Tool]:
        """Normalize source-bound tool collection expressions without inventing members."""
        alias = expr.id if isinstance(expr, ast.Name) else "dynamic_tools"
        value = assignment_value_before_node(node, alias) if isinstance(expr, ast.Name) else expr
        if value is None:
            return []
        if isinstance(value, ast.Await):
            value = value.value
        if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Add):
            return [
                *dynamic_collection_tools(node, value.left),
                *dynamic_collection_tools(node, value.right),
            ]
        if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
            result: list[Tool] = []
            for element in value.elts:
                if isinstance(element, ast.Name) and element.id in tools:
                    result.append(tools[element.id])
                else:
                    result.extend(dynamic_collection_tools(node, element))
            return result
        if isinstance(value, ast.Name):
            if value.id in tools:
                return [tools[value.id]]
            nested = assignment_value_before_node(node, value.id)
            if nested is not None and nested is not value:
                return dynamic_collection_tools(node, nested)
            return []
        if not isinstance(value, ast.Call):
            return []
        called = _dotted_name(value.func) or _call_name(value.func) or ""
        if "tool" not in called.lower():
            return []
        toolkits = _literal(_kw(value, "toolkits"))
        if toolkits is None and value.args:
            toolkits = _literal(value.args[0])
        return [
            Tool(
                name=alias,
                kind="dynamic_tool_collection",
                capabilities=set(),
                location=_location(path, value),
                metadata={
                    "framework": "openai-agents",
                    "binding_origin": "source_bound_dynamic_tool_collection",
                    "dynamic_bound_collection": True,
                    "catalogue_source": called,
                    "catalogue_name": toolkits if isinstance(toolkits, (list, tuple, str)) else None,
                    "tool_scope_unresolved": True,
                },
            )
        ]

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or _call_name(node.func) != "Agent":
            continue

        name_node = _kw(node, "name")
        name_value = _literal(name_node)
        if name_value is None and isinstance(name_node, ast.Name):
            name_value = constants.get(name_node.id)
        instructions = _literal(_kw(node, "instructions"))
        metadata: dict[str, Any] = {
            "framework": "openai-agents",
            "instance_key": f"{path.resolve()}:{getattr(node, 'lineno', 1)}",
        }
        source_alias = agent_alias_by_line.get(getattr(node, "lineno", 1))
        if source_alias:
            metadata["source_alias"] = source_alias
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
            owner_function = _enclosing_function(functions, node)
            if owner_function is not None:
                agent.metadata["dynamic_tools_function"] = owner_function.name
                agent.metadata["dynamic_tools_parameter"] = tools_expr.id
            tool_elements: list[ast.AST] = []
        else:
            tool_elements = _resolve_sequence(tools_expr, sequences)
            if not tool_elements:
                dynamic_collections = dynamic_collection_tools(node, tools_expr)
                if dynamic_collections:
                    for dynamic_collection in dynamic_collections:
                        if not any(
                            existing.name == dynamic_collection.name
                            and existing.kind == dynamic_collection.kind
                            for existing in agent.tools
                        ):
                            agent.tools.append(dynamic_collection)
                    agent.metadata["dynamic_tools"] = True
                    agent.metadata["dynamic_tools_source_bound"] = True

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
                direct_tool = _tool_from_call(
                    path,
                    element,
                    constants=constants,
                    configuration_sources=configuration_sources,
                )
                if direct_tool:
                    agent.tools.append(direct_tool)

        mcp_servers_expr = _kw(node, "mcp_servers")
        mcp_server_elements = _resolve_sequence(mcp_servers_expr, sequences)
        if not mcp_server_elements and isinstance(mcp_servers_expr, ast.Name):
            mcp_server_elements = [mcp_servers_expr]
        for element in mcp_server_elements:
            if isinstance(element, ast.Name):
                source_name = resolve_alias(element.id)
                if source_name in mcp_servers:
                    agent.mcp_servers.append(mcp_servers[source_name])
                    continue
                if element.id in parameter_names or source_name in parameter_names:
                    agent.mcp_servers.append(
                        MCPServer(
                            name=element.id,
                            transport="unknown",
                            authenticated=None,
                            location=_location(path, element),
                            metadata={
                                "framework": "openai-agents",
                                "binding_origin": "function_parameter",
                                "source_bound_parameter": True,
                                "transport_unresolved": True,
                                "tool_catalogue_unresolved": True,
                            },
                        )
                    )
                    agent.metadata["parameter_bound_mcp"] = True
                    continue
                local_factory_value = assignment_value_before_node(node, element.id)
                local_factory_call = (
                    local_factory_value.value
                    if isinstance(local_factory_value, ast.Await)
                    else local_factory_value
                )
                if isinstance(local_factory_call, ast.Call):
                    factory_name = _call_name(local_factory_call.func)
                    if factory_name and any(
                        function.name == factory_name for function in functions
                    ):
                        agent.mcp_servers.append(
                            MCPServer(
                                name=element.id,
                                transport="unknown",
                                authenticated=None,
                                location=_location(path, local_factory_call),
                                metadata={
                                    "framework": "openai-agents",
                                    "binding_origin": "local_mcp_collection_factory",
                                    "catalogue_source": factory_name,
                                    "source_bound_collection": True,
                                    "transport_unresolved": True,
                                    "tool_catalogue_unresolved": True,
                                },
                            )
                        )
                        agent.metadata["dynamic_mcp_source_bound"] = True
                        continue
                if source_name in imports:
                    agent.mcp_servers.append(
                        MCPServer(
                            name=import_symbols.get(source_name, source_name),
                            transport="configured",
                            authenticated=None,
                            location=_location(path, element),
                            metadata={
                                "framework": "openai-agents",
                                "import_module": imports[source_name],
                                "import_symbol": import_symbols.get(
                                    source_name,
                                    source_name,
                                ),
                                "local_alias": element.id,
                                "placeholder": True,
                            },
                        )
                    )
                    continue
            if isinstance(element, ast.Constant) and isinstance(element.value, str):
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

    def parameter_names_in_order(
        function: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> list[str]:
        return [
            arg.arg
            for arg in [
                *function.args.posonlyargs,
                *function.args.args,
                *function.args.kwonlyargs,
            ]
        ]

    def call_argument_for_parameter(
        call: ast.Call,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
        parameter: str,
    ) -> ast.AST | None:
        for keyword in call.keywords:
            if keyword.arg == parameter:
                return keyword.value
        ordered = parameter_names_in_order(function)
        if parameter not in ordered:
            return None
        index = ordered.index(parameter)
        return call.args[index] if index < len(call.args) else None

    def assignment_value_before(
        function: ast.FunctionDef | ast.AsyncFunctionDef,
        name: str,
        before_line: int,
    ) -> ast.AST | None:
        candidates: list[tuple[int, ast.AST]] = []
        for assignment in ast.walk(function):
            if not isinstance(assignment, (ast.Assign, ast.AnnAssign)):
                continue
            if _enclosing_function(functions, assignment) is not function:
                continue
            line = getattr(assignment, "lineno", 0)
            if line >= before_line:
                continue
            targets = (
                assignment.targets
                if isinstance(assignment, ast.Assign)
                else [assignment.target]
            )
            if not any(
                isinstance(target, ast.Name) and target.id == name
                for target in targets
            ):
                continue
            if assignment.value is not None:
                candidates.append((line, assignment.value))
        if not candidates:
            return None
        return max(candidates, key=lambda item: item[0])[1]

    def unwrap_await(value: ast.AST | None) -> ast.AST | None:
        return value.value if isinstance(value, ast.Await) else value

    functions_by_name = {function.name: function for function in functions}
    dynamic_agents = [
        agent
        for agent in graph.agents
        if agent.metadata.get("dynamic_tools") is True
        and agent.metadata.get("dynamic_tools_function")
        and agent.metadata.get("dynamic_tools_parameter")
    ]
    for agent in dynamic_agents:
        function_name = str(agent.metadata["dynamic_tools_function"])
        parameter = str(agent.metadata["dynamic_tools_parameter"])
        target_function = functions_by_name.get(function_name)
        if target_function is None:
            continue

        for call in (
            child for child in ast.walk(tree)
            if isinstance(child, ast.Call)
            and _call_name(child.func) == function_name
        ):
            caller = _enclosing_function(functions, call)
            if caller is target_function:
                continue
            argument = call_argument_for_parameter(
                call,
                target_function,
                parameter,
            )
            if argument is None:
                continue

            value = argument
            if isinstance(argument, ast.Name) and caller is not None:
                value = assignment_value_before(
                    caller,
                    argument.id,
                    getattr(call, "lineno", 0),
                )
            if value is None:
                continue

            elements = (
                list(value.elts)
                if isinstance(value, (ast.List, ast.Tuple, ast.Set))
                else []
            )
            for element in elements:
                if not isinstance(element, ast.Call):
                    continue
                bound_tool = _tool_from_call(
                    path,
                    element,
                    constants=constants,
                    configuration_sources=configuration_sources,
                )
                if (
                    bound_tool is None
                    or bound_tool.kind != "hosted_mcp"
                    or bound_tool.metadata.get("dynamic_remote_mcp_catalogue")
                    is not True
                ):
                    continue
                bound_tool.metadata["binding_origin"] = (
                    "source_bound_dynamic_tools_parameter"
                )
                if not any(
                    existing.name == bound_tool.name
                    and existing.kind == bound_tool.kind
                    for existing in agent.tools
                ):
                    agent.tools.append(bound_tool)
                agent.metadata["dynamic_tools_source_bound"] = True

            if not isinstance(value, ast.ListComp):
                continue
            conversion = value.elt
            if (
                not isinstance(conversion, ast.Call)
                or not isinstance(conversion.func, ast.Attribute)
                or conversion.func.attr != "to_function_tool"
                or len(conversion.args) < 2
            ):
                continue
            server_name = _call_name(conversion.args[1])
            if not server_name or server_name not in mcp_servers:
                continue
            source_names = {
                generator.iter.id
                for generator in value.generators
                if isinstance(generator.iter, ast.Name)
            }
            if len(source_names) != 1 or caller is None:
                continue
            source_name = next(iter(source_names))
            catalogue_value = assignment_value_before(
                caller,
                source_name,
                getattr(value, "lineno", getattr(call, "lineno", 0)),
            )
            catalogue_call = unwrap_await(catalogue_value)
            if (
                not isinstance(catalogue_call, ast.Call)
                or not isinstance(catalogue_call.func, ast.Attribute)
                or catalogue_call.func.attr != "list_tools"
                or _call_name(catalogue_call.func.value) != server_name
            ):
                continue

            server = mcp_servers[server_name]
            server.metadata["dynamic_remote_mcp_catalogue"] = True
            server.metadata["per_call_approval"] = False
            server.metadata["dynamic_catalogue_binding"] = (
                "list_tools_to_function_tool"
            )
            server.metadata["binding_origin"] = (
                "source_bound_dynamic_tools_parameter"
            )
            if all(
                existing.name != server.name
                for existing in agent.mcp_servers
            ):
                agent.mcp_servers.append(server)
            agent.metadata["dynamic_tools_source_bound"] = True

    agents_by_alias = {
        str(agent.metadata.get("source_alias")): agent
        for agent in graph.agents
        if agent.metadata.get("source_alias")
    }
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in {"run", "run_streamed", "run_sync"}:
            continue
        receiver = _dotted_name(node.func.value) or _call_name(node.func.value)
        if receiver not in {"Runner", "agents.Runner"}:
            continue
        agent_expr = (
            node.args[0]
            if node.args
            else _kw(node, "starting_agent") or _kw(node, "agent")
        )
        agent_alias = _call_name(agent_expr)
        target = agents_by_alias.get(agent_alias or "")
        if target is None:
            continue
        input_expr = _kw(node, "input")
        if input_expr is None and len(node.args) > 1:
            input_expr = node.args[1]
        input_root = _root_name(input_expr)
        if not input_root:
            continue
        function = _enclosing_function(functions, node)
        if function is None:
            continue
        parameters = _enclosing_function_parameter_names(functions, node)
        if input_root not in parameters:
            continue
        external_basis = _external_handler_evidence(function)
        if external_basis is None:
            continue
        if any(
            source.name == input_root
            and source.metadata.get("binding_origin") == "runner_external_input"
            for source in target.inputs
        ):
            continue
        target.inputs.append(
            InputSource(
                name=input_root,
                trust="untrusted",
                kind="external",
                location=_location(path, input_expr or node),
                metadata={
                    "inferred": True,
                    "binding_origin": "runner_external_input",
                    "basis": external_basis,
                    "runner": node.func.attr,
                    "handler": function.name,
                },
            )
        )

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
