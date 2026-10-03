from __future__ import annotations

import re
from collections.abc import Iterable
from copy import deepcopy
from pathlib import Path

from horustrace.adapters.csharp_source import (
    CSharpAssignment,
    argument_value,
    assignments,
    balanced_end,
    collection_strings,
    literal_or_configured,
    location,
    mask_non_code,
    method_body,
    named_string,
    refs,
    statement_end,
)
from horustrace.heuristics import (
    corroborate_name_inferred_authority,
    infer_capabilities,
)
from horustrace.models import (
    Agent,
    Graph,
    MCPServer,
    NetworkDestination,
    ResourceScope,
    Tool,
)

FRAMEWORK = "microsoft-agent-framework-dotnet"

_AGENT_MARKERS = (
    ".AsAIAgent(",
    "new ChatClientAgent(",
    "new ChatClientAgent (",
    ".BuildAIAgent(",
    ".AsHarnessAgent(",
)

_HOSTED_AGENT_MARKER = ".AddAIAgent("
_SKILL_MARKERS = (
    "AgentInlineSkill",
    "AgentClassSkill",
    "AgentSkillsProvider",
    "UseFileSkills",
)


def is_microsoft_agent_framework_dotnet_file(path: Path) -> bool:
    if path.suffix.lower() != ".cs":
        return False
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False
    return (
        "Microsoft.Agents.AI" in source
        and (
            any(marker in source for marker in _AGENT_MARKERS)
            or re.search(
                r"\b(?:AIAgent|ChatClientAgent)\s+[A-Za-z_]\w*\s*=\s*new\s*\(",
                source,
            )
            is not None
            or _HOSTED_AGENT_MARKER in source
            or any(marker in source for marker in _SKILL_MARKERS)
            or "HostedMcpServerTool" in source
            or "AgentSkillsProviderBuilder" in source
            or "AgentWorkflowBuilder" in source
            or ".AddWorkflow(" in source
            or "ChatClientAgentRunOptions" in source
            or "FunctionInvokingChatClient.CurrentContext" in source
        )
    )


def _body_capabilities(body: str) -> set[str]:
    value = body.lower()
    caps: set[str] = set()
    if any(x in value for x in (
        "process.start", "processstartinfo", "powershell.create",
        "system.management.automation", "shell.execute",
    )):
        caps.add("process.execute")
    if any(x in value for x in (
        "httpclient", ".getasync(", ".postasync(", ".putasync(",
        ".patchasync(", ".sendasync(", "webrequest", "restclient",
    )):
        caps.add("network.external")
    if any(x in value for x in (
        ".postasync(", ".putasync(", ".patchasync(",
        "sendmail", "sendemail", "sendmessage",
    )):
        caps.update({"external.write", "data.write"})
    if any(x in value for x in (
        "file.write", "file.append", "file.create", "directory.create",
        "savechanges", "executenonquery", ".insert(", ".update(", ".upsert(",
    )):
        caps.add("data.write")
    if any(x in value for x in (
        "file.delete", "directory.delete", ".deleteasync(", ".remove(", ".drop(",
    )):
        caps.update({"data.write", "destructive.write"})
    if any(x in value for x in (
        "file.read", "file.openread", ".getasync(", ".query",
        ".tolistasync(", ".findasync(",
    )):
        caps.add("data.read")
    if any(x in value for x in (
        "secretclient", "getsecret", "keyvault", "tokencredential",
    )):
        caps.add("secrets.read")
    return caps


def _function_tool(
    path: Path,
    source: str,
    masked: str,
    expression: str,
    *,
    offset: int,
    approval: bool | None,
) -> Tool | None:
    match = re.search(
        r"AIFunctionFactory\.Create\s*\(\s*"
        r"(?P<target>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)",
        expression,
    )
    if not match:
        return None
    target = match.group("target")
    method_name = target.rsplit(".", 1)[-1]
    name = named_string(expression, "name") or method_name
    method = method_body(source, masked, method_name)
    body = method[0] if method else ""
    body_caps = _body_capabilities(body)
    name_caps, suppressed = corroborate_name_inferred_authority(
        set(infer_capabilities(name)),
        body_caps,
    )
    tool = Tool(
        name=name,
        kind="function",
        capabilities=name_caps | body_caps,
        approval=approval,
        location=location(path, source, offset),
        metadata={
            "framework": FRAMEWORK,
            "wrapped": target,
            "binding_origin": "AIFunctionFactory.Create",
            "method_source_resolved": method is not None,
        },
    )
    if suppressed:
        tool.metadata["name_only_capabilities_suppressed"] = sorted(suppressed)
    if method:
        for url in sorted(set(re.findall(r"https?://[^\s\"')]+", body))):
            tool.destinations.append(
                NetworkDestination(
                    target=url.rstrip(",;"),
                    restricted=True,
                    location=tool.location,
                    metadata={
                        "source": "literal_url",
                        "network_scope": "fixed_literal_destination",
                    },
                )
            )
    return tool



_PROVIDER_TOOL_CAPABILITIES: dict[str, set[str]] = {
    "HostedCodeInterpreterTool": {"process.execute", "data.read", "data.write"},
    "HostedWebSearchTool": {"data.read", "network.external"},
    "HostedFileSearchTool": {"data.read"},
    "CreateCodeInterpreterTool": {"process.execute", "data.read", "data.write"},
    "CreateWebSearchTool": {"data.read", "network.external"},
    "CreateFileSearchTool": {"data.read"},
    "CreateImageGenerationTool": {"external.write", "network.external"},
    "CreateOpenApiTool": {"network.external"},
    "CreateBingGroundingTool": {"data.read", "network.external"},
    "CreateBingCustomSearchTool": {"data.read", "network.external"},
    "CreateMicrosoftFabricTool": {"data.read", "network.external"},
    "CreateSharepointTool": {"data.read", "network.external"},
    "CreateAzureAISearchTool": {"data.read", "network.external"},
    "CreateBrowserAutomationTool": {
        "data.read", "data.write", "external.write", "network.external"
    },
    "CreateComputerTool": {"process.execute", "data.read", "data.write"},
    "CreateA2ATool": {"agent.delegate", "network.external"},
}


def _provider_tool_kind(expression: str) -> str | None:
    for kind in _PROVIDER_TOOL_CAPABILITIES:
        if re.search(rf"\b{re.escape(kind)}\s*\(", expression):
            return kind
    return None


def _provider_tool(
    path: Path,
    source: str,
    expression: str,
    *,
    name: str,
    offset: int,
) -> Tool | None:
    kind = _provider_tool_kind(expression)
    if kind is None:
        return None
    capabilities = set(_PROVIDER_TOOL_CAPABILITIES[kind])
    metadata: dict[str, object] = {
        "framework": FRAMEWORK,
        "provider": "microsoft-foundry",
        "provider_managed": True,
        "provider_tool_type": kind,
    }

    # OpenAPI can represent either read-only or mutating HTTP operations. Promote
    # effects only when the source-visible schema/function definition proves them.
    if kind == "CreateOpenApiTool":
        target = re.search(
            r"CreateOpenApiTool\s*\(\s*([A-Za-z_]\w*)\s*\(",
            expression,
        )
        definition = (
            method_body(source, mask_non_code(source), target.group(1))
            if target
            else None
        )
        definition_source = definition[0] if definition else ""
        lowered = definition_source.lower()
        if any(f'"{verb}"' in lowered for verb in ("post", "put", "patch", "delete")):
            capabilities.update({"external.write", "data.write"})
        if '"get"' in lowered:
            capabilities.add("data.read")
        urls = sorted(set(re.findall(r"https?://[^\s\"'}]+", definition_source)))
        metadata["http_effect_basis"] = (
            "source_visible_openapi_schema" if definition_source else "unresolved"
        )
    else:
        urls = []

    tool = Tool(
        name=name,
        kind="provider_tool",
        capabilities=capabilities,
        location=location(path, source, offset),
        metadata=metadata,
    )
    for url in urls:
        tool.destinations.append(NetworkDestination(
            target=url.rstrip(",;"),
            restricted=True,
            location=tool.location,
            metadata={
                "source": "provider_tool_literal_url",
                "network_scope": "fixed_literal_destination",
            },
        ))
    return tool


def _provider_tools_in_expression(
    path: Path,
    source: str,
    expression: str,
    *,
    offset: int,
) -> list[Tool]:
    tools: list[Tool] = []
    for kind in _PROVIDER_TOOL_CAPABILITIES:
        for match in re.finditer(rf"\b{re.escape(kind)}\s*\(", expression):
            tool = _provider_tool(
                path,
                source,
                expression[match.start():],
                name=kind,
                offset=offset + match.start(),
            )
            if tool is not None:
                tools.append(tool)
    return _dedupe_tools(tools)


def _codeact_provider_tool(
    path: Path,
    source: str,
    item: CSharpAssignment,
) -> Tool | None:
    provider_type = next(
        (
            marker
            for marker in ("HyperlightCodeActProvider", "LocalCodeActProvider")
            if marker in item.expression
        ),
        None,
    )
    if provider_type is None:
        return None
    approval = None
    if re.search(r"ApprovalMode\s*=\s*[\w.]*NeverRequire\b", item.expression):
        approval = False
    elif re.search(r"ApprovalMode\s*=\s*[\w.]*AlwaysRequire\b", item.expression):
        approval = True
    return Tool(
        name=item.name,
        kind="microsoft_dotnet_codeact",
        capabilities={"process.execute"},
        approval=approval,
        location=location(path, source, item.offset),
        metadata={
            "framework": FRAMEWORK,
            "binding_origin": provider_type,
            "code_execution": True,
            "sandbox": (
                "hyperlight"
                if provider_type == "HyperlightCodeActProvider"
                else "host-process"
            ),
        },
    )


def _tool_variable(
    path: Path,
    source: str,
    masked: str,
    item: CSharpAssignment,
) -> Tool | None:
    expr = item.expression
    if "AIFunctionFactory.Create" in expr:
        return _function_tool(
            path,
            source,
            masked,
            expr,
            offset=item.offset,
            approval=True if "ApprovalRequiredAIFunction" in expr else None,
        )

    provider_tool = _provider_tool(
        path,
        source,
        expr,
        name=item.name,
        offset=item.offset,
    )
    if provider_tool is not None:
        return provider_tool

    shell = (
        "local" if "LocalShellExecutor" in expr
        else "docker" if "DockerShellExecutor" in expr
        else None
    )
    if shell:
        approval = (
            False
            if "ApprovalMode.NeverRequire" in expr
            else True
            if (
                "ApprovalMode.AlwaysRequire" in expr
                or "RequireApproval = true" in expr
                or ".AsAIFunction()" in expr
            )
            else None
        )
        return Tool(
            name=item.name,
            kind=f"microsoft_dotnet_{shell}_shell",
            capabilities={
                "process.execute", "data.read", "data.write", "network.external"
            },
            approval=approval,
            location=location(path, source, item.offset),
            metadata={"framework": FRAMEWORK, "shell_executor": shell},
        )
    return None


def _hosted_mcp(
    path: Path,
    source: str,
    expr: str,
    *,
    alias: str,
    offset: int,
    known: dict[str, CSharpAssignment],
) -> MCPServer | None:
    if "HostedMcpServerTool" not in expr:
        return None
    name = (
        named_string(expr, "serverName")
        or named_string(expr, "name")
        or alias
    )
    address = argument_value(expr, "serverAddress")
    url, config = (
        literal_or_configured(address, known)
        if address else (None, None)
    )
    approval = None
    metadata: dict[str, object] = {
        "framework": FRAMEWORK,
        "provider_managed": True,
        "hosted_mcp": True,
    }
    if re.search(r"ApprovalMode\s*=\s*[\w.]*NeverRequire\b", expr):
        approval = False
        metadata["approval_mode"] = "never_require"
    elif re.search(r"ApprovalMode\s*=\s*[\w.]*AlwaysRequire\b", expr):
        approval = True
        metadata["approval_mode"] = "always_require"
    elif "ApprovalMode" in expr:
        metadata["conditional_approval"] = True
        metadata["approval_mode_expression"] = (
            argument_value(expr, "ApprovalMode") or "dynamic"
        )
    if url:
        metadata["network_scope"] = "fixed_destination"
    elif config:
        metadata.update({
            "dynamic_mcp_endpoint_basis": "operator_configuration",
            "configuration_source": config,
            "network_scope": "operator_configured_destination",
        })
    return MCPServer(
        name=name,
        transport="hosted",
        url=url,
        approval=approval,
        allowed_tools=collection_strings(expr, "AllowedTools"),
        location=location(path, source, offset),
        metadata=metadata,
    )


def _authenticated_http_clients(
    source: str,
    known: dict[str, CSharpAssignment],
) -> set[str]:
    result = {
        name
        for name, item in known.items()
        if any(
            marker in item.expression
            for marker in (
                "BearerTokenHandler", "Authorization", "TokenCredential",
                "DefaultRequestHeaders.Authorization",
            )
        )
    }
    for name in known:
        if re.search(
            rf"\b{re.escape(name)}\.(?:DefaultRequestHeaders\.)?"
            r"Authorization\s*=",
            source,
        ):
            result.add(name)
    return result


def _transport_server(
    path: Path,
    source: str,
    expr: str,
    *,
    alias: str,
    offset: int,
    known: dict[str, CSharpAssignment],
    auth_clients: set[str],
) -> MCPServer | None:
    if "StdioClientTransport" in expr:
        command_expr = argument_value(expr, "Command")
        command, config = (
            literal_or_configured(command_expr, known)
            if command_expr else (None, None)
        )
        metadata: dict[str, object] = {
            "framework": FRAMEWORK,
            "mcp_client": True,
        }
        if config:
            metadata["command_configuration_source"] = config
        args = re.findall(
            r'@?"([^"]+)"',
            argument_value(expr, "Arguments") or "",
        )
        return MCPServer(
            name=named_string(expr, "Name") or alias,
            transport="stdio",
            command=command,
            args=args,
            location=location(path, source, offset),
            metadata=metadata,
        )

    if "HttpClientTransport" not in expr:
        return None
    endpoint = argument_value(expr, "Endpoint")
    url, config = (
        literal_or_configured(endpoint, known)
        if endpoint else (None, None)
    )
    metadata = {"framework": FRAMEWORK, "mcp_client": True}
    if url:
        metadata["network_scope"] = "fixed_destination"
    elif config:
        metadata.update({
            "dynamic_mcp_endpoint_basis": "operator_configuration",
            "configuration_source": config,
            "network_scope": "operator_configured_destination",
        })
    if (
        (config and "FOUNDRY_TOOLBOX" in config.upper())
        or "Toolboxes=V1Preview" in expr
    ):
        metadata.update({
            "provider": "microsoft-foundry",
            "foundry_toolbox": True,
        })

    authenticated = any(name in expr for name in auth_clients) or any(
        marker in expr
        for marker in ("Authorization", "BearerToken", "AdditionalHeaders")
    )
    return MCPServer(
        name=named_string(expr, "Name") or alias,
        transport="streamable-http",
        url=url,
        authenticated=True if authenticated else None,
        location=location(path, source, offset),
        metadata=metadata,
    )


def _mcp_client(
    path: Path,
    source: str,
    item: CSharpAssignment,
    known: dict[str, CSharpAssignment],
    auth_clients: set[str],
) -> MCPServer | None:
    if "McpClient.CreateAsync" not in item.expression:
        return None
    expr = item.expression
    match = re.search(
        r"McpClient\.CreateAsync\s*\(\s*([A-Za-z_]\w*)",
        expr,
    )
    if match and match.group(1) in known:
        expr = known[match.group(1)].expression
    return _transport_server(
        path,
        source,
        expr,
        alias=item.name,
        offset=item.offset,
        known=known,
        auth_clients=auth_clients,
    )


def _agent_name(expr: str, variable: str) -> str:
    return (
        named_string(expr, "name")
        or named_string(expr, "Name")
        or variable
    )


def _foundry_agent(expr: str, foundry_clients: set[str]) -> bool:
    if "AIProjectClient" in expr or "Foundry" in expr:
        return True
    match = re.search(r"\b([A-Za-z_]\w*)\.AsAIAgent\s*\(", expr)
    return bool(match and match.group(1) in foundry_clients)


def _tool_value(expr: str) -> str | None:
    return argument_value(expr, "tools") or argument_value(expr, "Tools")


def _context_value(expr: str) -> str | None:
    return argument_value(expr, "AIContextProviders")



def _assignment_is_agent(item: CSharpAssignment) -> bool:
    if any(marker in item.expression for marker in _AGENT_MARKERS):
        return True
    declared = (item.declared_type or "").replace("?", "").strip()
    return (
        declared in {"AIAgent", "ChatClientAgent"}
        and re.match(r"^\s*new\s*\(", item.expression) is not None
    )


def _inline_skill_tool(
    path: Path,
    source: str,
    item: CSharpAssignment,
) -> Tool | None:
    expr = item.expression
    if "AgentInlineSkill" not in expr:
        return None
    name = named_string(expr, "name") or item.name
    capabilities = _body_capabilities(expr)
    resources = re.findall(r"\.AddResource\s*\(\s*@?\"([^\"]+)\"", expr)
    scripts = re.findall(r"\.AddScript\s*\(\s*@?\"([^\"]+)\"", expr)
    if resources:
        capabilities.add("data.read")
    return Tool(
        name=name,
        kind="microsoft_dotnet_agent_skill",
        capabilities=capabilities,
        location=location(path, source, item.offset),
        metadata={
            "framework": FRAMEWORK,
            "skill_source": "inline",
            "binding_origin": "AgentInlineSkill",
            "resources": resources,
            "scripts": scripts,
        },
    )


def _class_skill_tool(
    path: Path,
    source: str,
    masked: str,
    item: CSharpAssignment,
) -> Tool | None:
    match = re.match(r"\s*new\s+([A-Za-z_]\w*)\s*\(", item.expression)
    if not match:
        return None
    class_name = match.group(1)
    declaration = re.search(
        rf"\bclass\s+{re.escape(class_name)}\b[^{{:]*"
        rf":\s*AgentClassSkill\s*<[^>]+>[^{{]*\{{",
        masked,
        re.DOTALL,
    )
    if not declaration:
        return None
    brace = masked.find("{", declaration.start(), declaration.end() + 1)
    end = balanced_end(masked, brace, "{", "}") if brace >= 0 else None
    if end is None:
        return None
    class_source = source[declaration.start():end + 1]
    resources = re.findall(
        r'AgentSkillResource\s*\(\s*@?"([^"]+)"',
        class_source,
    )
    scripts = re.findall(
        r'AgentSkillScript\s*\(\s*@?"([^"]+)"',
        class_source,
    )
    frontmatter = re.search(
        r"Frontmatter[^=]*=\s*new\s*\(\s*@?\"([^\"]+)\"",
        class_source,
        re.DOTALL,
    )
    capabilities = _body_capabilities(class_source)
    if "AgentSkillResource" in class_source:
        capabilities.add("data.read")
    return Tool(
        name=frontmatter.group(1) if frontmatter else class_name,
        kind="microsoft_dotnet_agent_skill",
        capabilities=capabilities,
        location=location(path, source, item.offset),
        metadata={
            "framework": FRAMEWORK,
            "skill_source": "class",
            "binding_origin": "AgentClassSkill",
            "class_name": class_name,
            "resources": resources,
            "scripts": scripts,
        },
    )


def _file_skill_tool(
    path: Path,
    source: str,
    item: CSharpAssignment,
) -> Tool | None:
    if "UseFileSkills" not in item.expression:
        return None
    capabilities = {"data.read"}
    if "SubprocessScriptRunner" in item.expression:
        capabilities.add("process.execute")
    return Tool(
        name=f"{item.name}:file-skills",
        kind="microsoft_dotnet_agent_skill",
        capabilities=capabilities,
        approval=True if "SubprocessScriptRunner" in item.expression else None,
        location=location(path, source, item.offset),
        metadata={
            "framework": FRAMEWORK,
            "skill_source": "file",
            "binding_origin": "UseFileSkills",
            "dynamic_tool_catalogue": True,
            "script_runner": (
                "subprocess"
                if "SubprocessScriptRunner" in item.expression
                else None
            ),
        },
    )


def _hosted_agent_name(expression: str) -> str | None:
    match = re.search(
        r"\.AddAIAgent\s*\(\s*(?:name\s*:\s*)?@?\"([^\"]+)\"",
        expression,
    )
    return match.group(1) if match else None


def _hosted_agent_expressions(source: str, masked: str) -> list[tuple[str, int]]:
    result: list[tuple[str, int]] = []
    for match in re.finditer(r"\.AddAIAgent\s*\(", masked):
        end = statement_end(masked, match.start())
        expression = source[match.start():end].strip()
        if expression:
            result.append((expression, match.start()))
    return result



def _bool_property(expression: str, name: str) -> bool | None:
    match = re.search(
        rf"\b{re.escape(name)}\s*=\s*(true|false)\b",
        expression,
        re.IGNORECASE,
    )
    if not match:
        return None
    return match.group(1).lower() == "true"


def _resolve_expression(
    value: str | None,
    known: dict[str, CSharpAssignment],
) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    if re.fullmatch(r"[A-Za-z_]\w*", stripped) and stripped in known:
        return known[stripped].expression
    return stripped


def _resource_selector(expression: str | None, fallback: str) -> str:
    if not expression:
        return fallback
    match = re.search(
        r"new\s+(?:FileSystem)?AgentFileStore\s*\(\s*(.*?)\s*\)",
        expression,
        re.DOTALL,
    )
    if match:
        value = match.group(1).strip()
        literal = re.fullmatch(r'@?"([^"]+)"', value)
        if literal:
            return literal.group(1)
        if value:
            return value[:240]
    return fallback


def _harness_builtin_tools(
    path: Path,
    source: str,
    expression: str,
    *,
    offset: int,
    known: dict[str, CSharpAssignment],
    agent_aliases: dict[str, Agent],
) -> list[Tool]:
    if ".AsHarnessAgent(" not in expression:
        return []

    result: list[Tool] = []

    # HostedWebSearchTool is enabled by default by HarnessAgent.
    if _bool_property(expression, "DisableWebSearch") is not True:
        result.append(Tool(
            name="HostedWebSearchTool",
            kind="provider_tool",
            capabilities={"data.read", "network.external"},
            location=location(path, source, offset),
            metadata={
                "framework": FRAMEWORK,
                "provider": "microsoft-foundry",
                "provider_managed": True,
                "provider_tool_type": "HostedWebSearchTool",
                "binding_origin": "HarnessAgent.default",
                "framework_default": True,
            },
        ))

    # File memory is enabled by default and exposes persistent read/write memory
    # tools. The delete operation is deliberately represented as data.write
    # rather than broad destructive authority because the store is harness-owned
    # session memory, not the shared FileAccessStore.
    if _bool_property(expression, "DisableFileMemory") is not True:
        memory_store = _resolve_expression(
            argument_value(expression, "FileMemoryStore"),
            known,
        )
        selector = _resource_selector(
            memory_store,
            "<harness-default-file-memory>",
        )
        result.append(Tool(
            name="harness:file-memory",
            kind="microsoft_dotnet_harness_file_memory",
            capabilities={"data.read", "data.write"},
            approval=False,
            location=location(path, source, offset),
            resources=[ResourceScope(
                kind="filesystem",
                selector=selector,
                access={"data.read", "data.write"},
                location=location(path, source, offset),
                metadata={
                    "framework": FRAMEWORK,
                    "harness_internal_memory": True,
                    "persistent": True,
                    "framework_default": memory_store is None,
                },
            )],
            metadata={
                "framework": FRAMEWORK,
                "binding_origin": "HarnessAgent.FileMemoryProvider",
                "persistent_memory": True,
                "supports_delete": True,
                "framework_default": memory_store is None,
            },
        ))

    # Harness file-based AgentSkillsProvider is also enabled by default. With no
    # explicit script runner the framework guarantees skill/resource reads, but
    # not arbitrary process execution.
    if _bool_property(expression, "DisableAgentSkillsProvider") is not True:
        source_value = _resolve_expression(
            argument_value(expression, "AgentSkillsSource"),
            known,
        )
        result.append(Tool(
            name="harness:agent-skills",
            kind="microsoft_dotnet_agent_skill",
            capabilities={"data.read"},
            approval=True,
            location=location(path, source, offset),
            metadata={
                "framework": FRAMEWORK,
                "binding_origin": "HarnessAgent.AgentSkillsProvider",
                "dynamic_tool_catalogue": True,
                "skill_source": "custom" if source_value else "cwd",
                "skill_source_expression": source_value,
                "framework_default": source_value is None,
            },
        ))

    file_store = _resolve_expression(
        argument_value(expression, "FileAccessStore"),
        known,
    )
    if file_store:
        file_options = _resolve_expression(
            argument_value(expression, "FileAccessProviderOptions"),
            known,
        ) or ""
        disable_write = _bool_property(file_options, "DisableWriteTools") is True
        read_approval = (
            _bool_property(file_options, "DisableReadOnlyToolApproval") is not True
        )
        write_approval = (
            _bool_property(file_options, "DisableWriteToolApproval") is not True
        )

        auto_approval_enabled = (
            _bool_property(expression, "DisableToolAutoApproval") is not True
        )
        approval_options = _resolve_expression(
            argument_value(expression, "ToolApprovalAgentOptions"),
            known,
        ) or ""
        read_auto = (
            auto_approval_enabled
            and (
                "FileAccessProvider.ReadOnlyToolsAutoApprovalRule"
                in approval_options
                or "FileAccessProvider.AllToolsAutoApprovalRule"
                in approval_options
            )
        )
        write_auto = (
            auto_approval_enabled
            and "FileAccessProvider.AllToolsAutoApprovalRule" in approval_options
        )
        selector = _resource_selector(
            file_store,
            "<configured-harness-file-store>",
        )
        shared_metadata = {
            "framework": FRAMEWORK,
            "binding_origin": "HarnessAgent.FileAccessProvider",
            "store_expression": file_store,
        }
        result.append(Tool(
            name="harness:file-access-read",
            kind="microsoft_dotnet_harness_file_access",
            capabilities={"data.read"},
            approval=False if read_auto else read_approval,
            location=location(path, source, offset),
            resources=[ResourceScope(
                kind="filesystem",
                selector=selector,
                access={"data.read"},
                location=location(path, source, offset),
                metadata={**shared_metadata, "shared_store": True},
            )],
            metadata={
                **shared_metadata,
                "access_mode": "read",
                "auto_approved": read_auto,
            },
        ))
        if not disable_write:
            result.append(Tool(
                name="harness:file-access-write",
                kind="microsoft_dotnet_harness_file_access",
                capabilities={"data.write", "destructive.write"},
                approval=False if write_auto else write_approval,
                location=location(path, source, offset),
                resources=[ResourceScope(
                    kind="filesystem",
                    selector=selector,
                    access={"data.write", "destructive.write"},
                    location=location(path, source, offset),
                    metadata={**shared_metadata, "shared_store": True},
                )],
                metadata={
                    **shared_metadata,
                    "access_mode": "write",
                    "auto_approved": write_auto,
                    "supports_delete": True,
                },
            ))

    background = argument_value(expression, "BackgroundAgents")
    if background:
        for ref in refs(background):
            child = agent_aliases.get(ref)
            if child is None:
                continue
            result.append(Tool(
                name=child.name,
                kind="delegated_agent",
                capabilities={"agent.delegate"},
                location=location(path, source, offset),
                metadata={
                    "framework": FRAMEWORK,
                    "delegate_target": ref,
                    "binding_origin": "HarnessAgent.BackgroundAgentsProvider",
                    "authority_binding_basis": (
                        "microsoft_dotnet_harness_background_agent"
                    ),
                    "background_execution": True,
                },
            ))

    return _dedupe_tools(result)


_WORKFLOW_MARKERS = (
    "AgentWorkflowBuilder.BuildSequential",
    "AgentWorkflowBuilder.BuildConcurrent",
    "AgentWorkflowBuilder.CreateHandoffBuilderWith",
    "AgentWorkflowBuilder.CreateGroupChatBuilderWith",
    "AgentWorkflowBuilder.CreateSequentialBuilderWith",
    "AgentWorkflowBuilder.CreateConcurrentBuilderWith",
)


def _workflow_kind(expression: str) -> str | None:
    if "BuildSequential" in expression or "CreateSequentialBuilderWith" in expression:
        return "sequential"
    if "BuildConcurrent" in expression or "CreateConcurrentBuilderWith" in expression:
        return "concurrent"
    if "CreateHandoffBuilderWith" in expression or ".WithHandoffs(" in expression:
        return "handoff"
    if "CreateGroupChatBuilderWith" in expression or ".AddParticipants(" in expression:
        return "group_chat"
    return None


def _workflow_participants(
    expression: str,
    agent_aliases: dict[str, Agent],
) -> list[str]:
    result: list[str] = []
    for ref in refs(expression):
        if ref in agent_aliases and ref not in result:
            result.append(ref)
    return result


def _workflow_definitions(
    source: str,
    known: dict[str, CSharpAssignment],
    agent_aliases: dict[str, Agent],
) -> dict[str, dict[str, object]]:
    builders: dict[str, dict[str, object]] = {}
    workflows: dict[str, dict[str, object]] = {}

    for name, item in known.items():
        if any(marker in item.expression for marker in _WORKFLOW_MARKERS):
            kind = _workflow_kind(item.expression) or "workflow"
            builders[name] = {
                "kind": kind,
                "participants": _workflow_participants(
                    item.expression,
                    agent_aliases,
                ),
                "source_alias": name,
            }

    # Builder mutation is common for handoff/group-chat workflows.
    for builder_name, definition in builders.items():
        for match in re.finditer(
            rf"\b{re.escape(builder_name)}\."
            r"(?:WithHandoffs|AddParticipants)\s*\(",
            source,
        ):
            end = statement_end(mask_non_code(source), match.start())
            statement = source[match.start():end]
            for participant in _workflow_participants(
                statement,
                agent_aliases,
            ):
                participants = definition["participants"]
                if (
                    isinstance(participants, list)
                    and participant not in participants
                ):
                    participants.append(participant)

    for name, item in known.items():
        direct = any(marker in item.expression for marker in _WORKFLOW_MARKERS)
        builder_match = re.search(
            r"\b([A-Za-z_]\w*)\.Build\s*\(",
            item.expression,
        )
        if direct:
            workflows[name] = dict(builders.get(name, {
                "kind": _workflow_kind(item.expression) or "workflow",
                "participants": _workflow_participants(
                    item.expression,
                    agent_aliases,
                ),
                "source_alias": name,
            }))
        elif builder_match and builder_match.group(1) in builders:
            workflows[name] = dict(builders[builder_match.group(1)])
            workflows[name]["source_alias"] = name

    return workflows


def _workflow_delegation_tools(
    path: Path,
    source: str,
    definition: dict[str, object],
    *,
    offset: int,
    agent_aliases: dict[str, Agent],
) -> list[Tool]:
    result: list[Tool] = []
    kind = str(definition.get("kind") or "workflow")
    participants = definition.get("participants")
    if not isinstance(participants, list):
        return result
    for alias in participants:
        child = agent_aliases.get(str(alias))
        if child is None:
            continue
        result.append(Tool(
            name=child.name,
            kind="delegated_agent",
            capabilities={"agent.delegate"},
            location=location(path, source, offset),
            metadata={
                "framework": FRAMEWORK,
                "delegate_target": str(alias),
                "binding_origin": "AgentWorkflowBuilder",
                "workflow_kind": kind,
                "authority_binding_basis": "microsoft_dotnet_workflow_projection",
            },
        ))
    return _dedupe_tools(result)


def _hosted_workflow_agent_expressions(
    source: str,
    masked: str,
) -> list[tuple[str, int]]:
    result: list[tuple[str, int]] = []
    for match in re.finditer(r"\.AddWorkflow\s*\(", masked):
        end = statement_end(masked, match.start())
        expression = source[match.start():end].strip()
        if ".AddAsAIAgent" in expression:
            result.append((expression, match.start()))
    return result


def _hosted_workflow_name(expression: str) -> str | None:
    match = re.search(
        r"\.AddWorkflow\s*\(\s*@?\"([^\"]+)\"",
        expression,
    )
    return match.group(1) if match else None


def _dedupe_tools(items: Iterable[Tool]) -> list[Tool]:
    result: list[Tool] = []
    seen: set[tuple[str, str, str]] = set()
    for item in items:
        key = (
            item.name,
            item.kind,
            str(item.metadata.get("delegate_target") or ""),
        )
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def _dedupe_servers(items: Iterable[MCPServer]) -> list[MCPServer]:
    result: list[MCPServer] = []
    seen: set[tuple[str, str, str, str]] = set()
    for item in items:
        key = (item.name, item.transport, item.url or "", item.command or "")
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def _parse_tools(
    path: Path,
    source: str,
    masked: str,
    value: str,
    *,
    offset: int,
    known: dict[str, CSharpAssignment],
    tool_vars: dict[str, Tool],
    hosted_vars: dict[str, MCPServer],
    mcp_lists: dict[str, str],
    mcp_servers: dict[str, MCPServer],
    agent_aliases: dict[str, Agent],
) -> tuple[list[Tool], list[MCPServer]]:
    tools: list[Tool] = []
    servers: list[MCPServer] = []
    masked_value = mask_non_code(value)

    approval_spans: list[tuple[int, int]] = []
    for match in re.finditer(r"new\s+ApprovalRequiredAIFunction\s*\(", value):
        start = value.find("(", match.start())
        end = balanced_end(masked_value, start, "(", ")")
        if end is None:
            continue
        approval_spans.append((match.start(), end + 1))
        tool = _function_tool(
            path, source, masked, value[match.start():end + 1],
            offset=offset + match.start(), approval=True,
        )
        if tool:
            tools.append(tool)

    for match in re.finditer(r"AIFunctionFactory\.Create\s*\(", value):
        if any(a <= match.start() < b for a, b in approval_spans):
            continue
        start = value.find("(", match.start())
        end = balanced_end(masked_value, start, "(", ")")
        if end is None:
            continue
        tool = _function_tool(
            path, source, masked, value[match.start():end + 1],
            offset=offset + match.start(), approval=None,
        )
        if tool:
            tools.append(tool)

    tools.extend(
        _provider_tools_in_expression(
            path,
            source,
            value,
            offset=offset,
        )
    )

    for match in re.finditer(r"\b([A-Za-z_]\w*)\.AsAIFunction\s*\(", value):
        alias = match.group(1)
        child = agent_aliases.get(alias)
        tools.append(Tool(
            name=child.name if child else alias,
            kind="delegated_agent",
            capabilities={"agent.delegate"},
            location=location(path, source, offset + match.start()),
            metadata={
                "framework": FRAMEWORK,
                "delegate_target": alias,
                "binding_origin": "AIAgent.AsAIFunction",
            },
        ))

    references = refs(value)
    for ref in references:
        if ref in tool_vars:
            tools.append(deepcopy(tool_vars[ref]))
        if ref in hosted_vars:
            servers.append(deepcopy(hosted_vars[ref]))
        if ref in mcp_lists:
            server = mcp_servers.get(mcp_lists[ref])
            if server:
                servers.append(deepcopy(server))
        assigned = known.get(ref)
        if assigned:
            for nested in refs(assigned.expression):
                if nested in tool_vars:
                    tools.append(deepcopy(tool_vars[nested]))
                if nested in mcp_lists:
                    server = mcp_servers.get(mcp_lists[nested])
                    if server:
                        servers.append(deepcopy(server))

    for match in re.finditer(r"new\s+HostedMcpServerTool\s*\(", value):
        start = value.find("(", match.start())
        end = balanced_end(masked_value, start, "(", ")")
        if end is None:
            continue
        j = end + 1
        while j < len(value) and value[j].isspace():
            j += 1
        full_end = end + 1
        if j < len(value) and value[j] == "{":
            obj_end = balanced_end(masked_value, j, "{", "}")
            if obj_end is not None:
                full_end = obj_end + 1
        server = _hosted_mcp(
            path, source, value[match.start():full_end],
            alias="hosted-mcp", offset=offset + match.start(), known=known,
        )
        if server:
            servers.append(server)

    return _dedupe_tools(tools), _dedupe_servers(servers)



def _dynamic_tool_catalogues(
    path: Path,
    source: str,
    masked: str,
    known: dict[str, CSharpAssignment],
    *,
    tool_vars: dict[str, Tool],
    hosted_vars: dict[str, MCPServer],
    mcp_lists: dict[str, str],
    mcp_servers: dict[str, MCPServer],
    agent_aliases: dict[str, Agent],
) -> tuple[dict[str, Tool], dict[str, list[Tool]]]:
    loaders: dict[str, Tool] = {}
    catalogues: dict[str, list[Tool]] = {}

    for name, item in known.items():
        expr = item.expression
        if (
            "FunctionInvokingChatClient.CurrentContext" not in expr
            or ".Tools" not in expr
            or ".Add(" not in expr
        ):
            continue

        candidates: list[Tool] = []
        for ref in refs(expr):
            assigned = known.get(ref)
            if assigned is None or ref == name:
                continue
            parsed, _ = _parse_tools(
                path,
                source,
                masked,
                assigned.expression,
                offset=assigned.offset,
                known=known,
                tool_vars=tool_vars,
                hosted_vars=hosted_vars,
                mcp_lists=mcp_lists,
                mcp_servers=mcp_servers,
                agent_aliases=agent_aliases,
            )
            for tool in parsed:
                tool.metadata["runtime_scope"] = "dynamic_catalogue"
                tool.metadata["conditional_authority"] = True
                tool.metadata["binding_origin"] = (
                    "FunctionInvokingChatClient.CurrentContext"
                )
                candidates.append(tool)

        candidates = _dedupe_tools(candidates)
        loader_name = named_string(expr, "name") or name
        loader = Tool(
            name=loader_name,
            kind="microsoft_dotnet_dynamic_tool_loader",
            capabilities=set().union(
                *(tool.capabilities for tool in candidates)
            ) if candidates else set(),
            location=location(path, source, item.offset),
            metadata={
                "framework": FRAMEWORK,
                "binding_origin": "FunctionInvokingChatClient.CurrentContext",
                "dynamic_tool_catalogue": True,
                "conditional_authority": True,
                "catalogue_tools": [tool.name for tool in candidates],
                "source_alias": name,
            },
        )
        loaders[name] = loader
        catalogues[name] = candidates

    return loaders, catalogues


def _run_option_tool_sets(
    path: Path,
    source: str,
    masked: str,
    known: dict[str, CSharpAssignment],
    *,
    tool_vars: dict[str, Tool],
    hosted_vars: dict[str, MCPServer],
    mcp_lists: dict[str, str],
    mcp_servers: dict[str, MCPServer],
    agent_aliases: dict[str, Agent],
) -> dict[str, tuple[list[Tool], list[MCPServer]]]:
    result: dict[str, tuple[list[Tool], list[MCPServer]]] = {}
    for name, item in known.items():
        if "ChatClientAgentRunOptions" not in item.expression:
            continue
        value = _tool_value(item.expression)
        if not value:
            continue
        value_start = item.expression.find(value)
        tools, servers = _parse_tools(
            path,
            source,
            masked,
            value,
            offset=item.offset + max(value_start, 0),
            known=known,
            tool_vars=tool_vars,
            hosted_vars=hosted_vars,
            mcp_lists=mcp_lists,
            mcp_servers=mcp_servers,
            agent_aliases=agent_aliases,
        )
        for tool in tools:
            tool.metadata["runtime_scope"] = "per_run"
            tool.metadata["conditional_authority"] = True
            tool.metadata["binding_origin"] = "ChatClientAgentRunOptions"
        for server in servers:
            server.metadata["runtime_scope"] = "per_run"
            server.metadata["conditional_authority"] = True
            server.metadata["binding_origin"] = "ChatClientAgentRunOptions"
        result[name] = (tools, servers)
    return result


def _bind_per_run_authority(
    path: Path,
    source: str,
    masked: str,
    *,
    agent_aliases: dict[str, Agent],
    run_options: dict[str, tuple[list[Tool], list[MCPServer]]],
    known: dict[str, CSharpAssignment],
    tool_vars: dict[str, Tool],
    hosted_vars: dict[str, MCPServer],
    mcp_lists: dict[str, str],
    mcp_servers: dict[str, MCPServer],
) -> None:
    for match in re.finditer(
        r"\b([A-Za-z_]\w*)\.(RunAsync|RunStreamingAsync)\s*\(",
        masked,
    ):
        alias = match.group(1)
        agent = agent_aliases.get(alias)
        if agent is None:
            continue
        open_paren = masked.find("(", match.start(), match.end() + 1)
        end = (
            balanced_end(masked, open_paren, "(", ")")
            if open_paren >= 0 else None
        )
        if end is None:
            continue
        invocation = source[match.start():end + 1]
        invocation_refs = refs(invocation)

        for option_name in invocation_refs & run_options.keys():
            tools, servers = run_options[option_name]
            agent.tools.extend(deepcopy(tools))
            agent.mcp_servers.extend(deepcopy(servers))

        if "new ChatClientAgentRunOptions" in invocation:
            value = _tool_value(invocation)
            if value:
                tools, servers = _parse_tools(
                    path,
                    source,
                    masked,
                    value,
                    offset=match.start() + max(invocation.find(value), 0),
                    known=known,
                    tool_vars=tool_vars,
                    hosted_vars=hosted_vars,
                    mcp_lists=mcp_lists,
                    mcp_servers=mcp_servers,
                    agent_aliases=agent_aliases,
                )
                for tool in tools:
                    tool.metadata["runtime_scope"] = "per_run"
                    tool.metadata["conditional_authority"] = True
                    tool.metadata["binding_origin"] = "ChatClientAgentRunOptions"
                for server in servers:
                    server.metadata["runtime_scope"] = "per_run"
                    server.metadata["conditional_authority"] = True
                    server.metadata["binding_origin"] = "ChatClientAgentRunOptions"
                agent.tools.extend(tools)
                agent.mcp_servers.extend(servers)

        agent.tools = _dedupe_tools(agent.tools)
        agent.mcp_servers = _dedupe_servers(agent.mcp_servers)


def _propagate_delegation(graph: Graph) -> None:
    agents = [
        a for a in graph.agents
        if a.metadata.get("framework") == FRAMEWORK
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
                candidates = (
                    [a for a in aliases.get(str(target), []) if a is not parent]
                    if target else []
                )
                unique: list[Agent] = []
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
                    (r.kind, r.selector, tuple(sorted(r.access)), r.classification)
                    for r in tool.resources
                }
                for r in child.effective_resources:
                    key = (r.kind, r.selector, tuple(sorted(r.access)), r.classification)
                    if key not in resource_keys:
                        tool.resources.append(ResourceScope(
                            kind=r.kind, selector=r.selector, access=set(r.access),
                            classification=r.classification, location=r.location,
                            metadata={**r.metadata, "via_agent": child.name},
                            provenance=list(r.provenance),
                        ))
                        resource_keys.add(key)
                destination_keys = {
                    (d.target, d.direction, d.restricted)
                    for d in tool.destinations
                }
                for d in child.effective_destinations:
                    key = (d.target, d.direction, d.restricted)
                    if key not in destination_keys:
                        tool.destinations.append(NetworkDestination(
                            target=d.target, direction=d.direction,
                            restricted=d.restricted, location=d.location,
                            metadata={**d.metadata, "via_agent": child.name},
                            provenance=list(d.provenance),
                        ))
                        destination_keys.add(key)
                tool.metadata["delegated_agent_targets"] = [child.name]
                tool.metadata["authority_binding"] = "delegation_projection"
                tool.metadata.setdefault(
                    "authority_binding_basis",
                    "microsoft_dotnet_agent_as_function",
                )
                changed = changed or before != (
                    frozenset(tool.capabilities),
                    len(tool.resources),
                    len(tool.destinations),
                )
        if not changed:
            break


def scan_dotnet_file(path: Path) -> Graph:
    graph = Graph()
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return graph
    if not is_microsoft_agent_framework_dotnet_file(path):
        return graph

    masked = mask_non_code(source)
    known = assignments(source, masked)
    foundry_clients = {
        name for name, item in known.items()
        if "AIProjectClient" in item.expression
    }
    auth_clients = _authenticated_http_clients(source, known)

    mcp_servers = {
        name: server
        for name, item in known.items()
        if (server := _mcp_client(
            path, source, item, known, auth_clients
        )) is not None
    }
    hosted_vars = {
        name: server
        for name, item in known.items()
        if (server := _hosted_mcp(
            path, source, item.expression, alias=name,
            offset=item.offset, known=known,
        )) is not None
    }

    mcp_lists: dict[str, str] = {}
    for name, item in known.items():
        match = re.search(
            r"\b([A-Za-z_]\w*)\.ListToolsAsync\s*\(",
            item.expression,
        )
        if match and match.group(1) in mcp_servers:
            mcp_lists[name] = match.group(1)

    tool_vars = {
        name: tool
        for name, item in known.items()
        if (tool := _tool_variable(path, source, masked, item)) is not None
    }
    codeact_vars = {
        name: tool
        for name, item in known.items()
        if (tool := _codeact_provider_tool(path, source, item)) is not None
    }

    # Agent Skills are effective authority only when their provider is attached
    # to an agent. Keep source variables/providers separate until that binding.
    skill_vars: dict[str, Tool] = {}
    for name, item in known.items():
        skill = (
            _inline_skill_tool(path, source, item)
            or _class_skill_tool(path, source, masked, item)
        )
        if skill is not None:
            skill_vars[name] = skill

    skill_builder_tools: dict[str, list[Tool]] = {}
    skill_builder_mcp: dict[str, list[str]] = {}
    for name, item in known.items():
        file_skill = _file_skill_tool(path, source, item)
        if file_skill is not None:
            skill_builder_tools.setdefault(name, []).append(file_skill)

        match = re.search(
            r"\.UseMcpSkills\s*\(\s*([A-Za-z_]\w*)",
            item.expression,
        )
        if match and match.group(1) in mcp_servers:
            skill_builder_mcp.setdefault(name, []).append(match.group(1))

    # Builders are often mutated after construction, e.g.
    # skillsBuilder.UseMcpSkills(toolboxMcpClient);
    for builder_name in known:
        for match in re.finditer(
            rf"\b{re.escape(builder_name)}\.UseMcpSkills\s*"
            r"\(\s*([A-Za-z_]\w*)",
            source,
        ):
            client = match.group(1)
            if client in mcp_servers:
                values = skill_builder_mcp.setdefault(builder_name, [])
                if client not in values:
                    values.append(client)

    skill_provider_tools: dict[str, list[Tool]] = {}
    skill_provider_mcp: dict[str, list[str]] = {}
    for name, item in known.items():
        expression_refs = refs(item.expression)

        if "new AgentSkillsProvider" in item.expression:
            local_tools = [
                deepcopy(skill_vars[ref])
                for ref in expression_refs
                if ref in skill_vars
            ]
            if local_tools:
                skill_provider_tools[name] = _dedupe_tools(local_tools)

        build_match = re.search(
            r"\b([A-Za-z_]\w*)\.Build\s*\(",
            item.expression,
        )
        if build_match:
            builder_name = build_match.group(1)
            if builder_name in skill_builder_tools:
                skill_provider_tools[name] = _dedupe_tools(
                    deepcopy(skill_builder_tools[builder_name])
                )
            if builder_name in skill_builder_mcp:
                skill_provider_mcp[name] = list(
                    dict.fromkeys(skill_builder_mcp[builder_name])
                )

        if name in skill_builder_tools:
            skill_provider_tools.setdefault(
                name,
                _dedupe_tools(deepcopy(skill_builder_tools[name])),
            )
        if name in skill_builder_mcp:
            skill_provider_mcp.setdefault(
                name,
                list(dict.fromkeys(skill_builder_mcp[name])),
            )

    agent_items = [
        item for item in known.values()
        if _assignment_is_agent(item)
    ]
    aliases: dict[str, Agent] = {}
    for item in agent_items:
        foundry = _foundry_agent(item.expression, foundry_clients)
        declared = (item.declared_type or "").replace("?", "").strip()
        target_typed_chat_agent = (
            declared == "ChatClientAgent"
            and re.match(r"^\s*new\s*\(", item.expression) is not None
        )
        agent = Agent(
            name=_agent_name(item.expression, item.name),
            location=location(path, source, item.offset),
            metadata={
                "framework": FRAMEWORK,
                "language": "csharp",
                "agent_type": (
                    "HarnessAgent"
                    if ".AsHarnessAgent(" in item.expression
                    else (
                        "ChatClientAgent"
                        if (
                            "ChatClientAgent" in item.expression
                            or target_typed_chat_agent
                        )
                        else "AIAgent"
                    )
                ),
                "provider": "microsoft-foundry" if foundry else None,
                "foundry_backed": foundry,
                "source_aliases": [item.name],
                "target_typed_constructor": target_typed_chat_agent,
            },
        )
        graph.agents.append(agent)
        aliases[item.name] = agent
        aliases.setdefault(agent.name, agent)

    dynamic_loaders, dynamic_catalogues = _dynamic_tool_catalogues(
        path,
        source,
        masked,
        known,
        tool_vars=tool_vars,
        hosted_vars=hosted_vars,
        mcp_lists=mcp_lists,
        mcp_servers=mcp_servers,
        agent_aliases=aliases,
    )
    tool_vars.update(dynamic_loaders)

    bound_clients: set[str] = set()
    bound_hosted: set[str] = set()

    def bind_agent_expression(
        agent: Agent,
        expression: str,
        expression_offset: int,
    ) -> None:
        value = _tool_value(expression)
        if value:
            value_start = expression.find(value)
            tools, servers = _parse_tools(
                path, source, masked, value,
                offset=expression_offset + max(value_start, 0),
                known=known,
                tool_vars=tool_vars,
                hosted_vars=hosted_vars,
                mcp_lists=mcp_lists,
                mcp_servers=mcp_servers,
                agent_aliases=aliases,
            )
            agent.tools.extend(tools)
            agent.mcp_servers.extend(servers)
            references = refs(value)
            bound_hosted.update(references & hosted_vars.keys())
            for ref in references:
                if ref in dynamic_catalogues:
                    agent.tools.extend(deepcopy(dynamic_catalogues[ref]))
                if ref in mcp_lists:
                    bound_clients.add(mcp_lists[ref])
                if ref in known:
                    for nested in refs(known[ref].expression):
                        if nested in mcp_lists:
                            bound_clients.add(mcp_lists[nested])

        context = _context_value(expression)
        if context:
            for ref in refs(context):
                for skill in skill_provider_tools.get(ref, []):
                    agent.tools.append(deepcopy(skill))
                if ref in codeact_vars:
                    agent.tools.append(deepcopy(codeact_vars[ref]))

                for client in skill_provider_mcp.get(ref, []):
                    server = mcp_servers.get(client)
                    if server is None:
                        continue
                    server_copy = deepcopy(server)
                    server_copy.metadata["binding_origin"] = "UseMcpSkills"
                    server_copy.metadata["mcp_skills"] = True
                    agent.mcp_servers.append(server_copy)
                    bound_clients.add(client)
                    agent.tools.append(Tool(
                        name=f"{ref}:mcp-skills",
                        kind="microsoft_dotnet_mcp_skills",
                        capabilities={"data.read", "process.execute"},
                        approval=True,
                        location=agent.location,
                        metadata={
                            "framework": FRAMEWORK,
                            "binding_origin": "UseMcpSkills",
                            "dynamic_tool_catalogue": True,
                        },
                    ))

        agent.tools.extend(_harness_builtin_tools(
            path,
            source,
            expression,
            offset=expression_offset,
            known=known,
            agent_aliases=aliases,
        ))

        agent.tools = _dedupe_tools(agent.tools)
        agent.mcp_servers = _dedupe_servers(agent.mcp_servers)

    for item, agent in zip(agent_items, graph.agents):
        bind_agent_expression(agent, item.expression, item.offset)

    # Microsoft hosting packages commonly register agents directly on the host
    # builder. These registrations are first-class agent inventory entries even
    # when no AIAgent variable exists in source.
    for expression, expression_offset in _hosted_agent_expressions(source, masked):
        name = _hosted_agent_name(expression)
        if not name:
            continue
        if any(
            existing.name == name
            and existing.metadata.get("hosting_registration") is True
            and existing.location
            and existing.location.path == path
            for existing in graph.agents
        ):
            continue

        source_aliases = [
            item.name
            for item in known.values()
            if _HOSTED_AGENT_MARKER in item.expression
            and _hosted_agent_name(item.expression) == name
        ]
        hosted_agent = Agent(
            name=name,
            location=location(path, source, expression_offset),
            metadata={
                "framework": FRAMEWORK,
                "language": "csharp",
                "agent_type": "HostedAIAgent",
                "hosting_registration": True,
                "binding_origin": "AddAIAgent",
                "source_aliases": source_aliases,
            },
        )
        graph.agents.append(hosted_agent)
        for alias in source_aliases:
            aliases[alias] = hosted_agent
        aliases.setdefault(name, hosted_agent)

        # Fluent WithAITool(s) calls and MCP tool collections are in the same
        # registration statement, so the ordinary tool binder can normalize
        # them without introducing hosting-specific authority semantics.
        tools, servers = _parse_tools(
            path,
            source,
            masked,
            expression,
            offset=expression_offset,
            known=known,
            tool_vars=tool_vars,
            hosted_vars=hosted_vars,
            mcp_lists=mcp_lists,
            mcp_servers=mcp_servers,
            agent_aliases=aliases,
        )
        hosted_agent.tools.extend(tools)
        hosted_agent.mcp_servers.extend(servers)

        references = refs(expression)
        bound_hosted.update(references & hosted_vars.keys())
        for ref in references:
            if ref in mcp_lists:
                bound_clients.add(mcp_lists[ref])

        hosted_agent.tools = _dedupe_tools(hosted_agent.tools)
        hosted_agent.mcp_servers = _dedupe_servers(hosted_agent.mcp_servers)

    # Reconstruct workflow authority only when a workflow is exposed as an
    # agent. The effective authority of that surface is the union of its
    # source-proven participant agents.
    workflows = _workflow_definitions(source, known, aliases)

    for item, agent in zip(agent_items, graph.agents):
        for ref in refs(item.expression):
            definition = workflows.get(ref)
            if definition is None:
                continue
            agent.tools.extend(_workflow_delegation_tools(
                path,
                source,
                definition,
                offset=item.offset,
                agent_aliases=aliases,
            ))
            agent.metadata["workflow_kind"] = definition.get("kind")
            agent.metadata["workflow_source_alias"] = ref
        agent.tools = _dedupe_tools(agent.tools)

    for expression, expression_offset in _hosted_agent_expressions(source, masked):
        name = _hosted_agent_name(expression)
        if not name:
            continue
        hosted_agent = next(
            (
                candidate for candidate in graph.agents
                if candidate.name == name
                and candidate.metadata.get("hosting_registration") is True
            ),
            None,
        )
        if hosted_agent is None:
            continue
        for ref in refs(expression):
            definition = workflows.get(ref)
            if definition is None:
                continue
            hosted_agent.tools.extend(_workflow_delegation_tools(
                path,
                source,
                definition,
                offset=expression_offset,
                agent_aliases=aliases,
            ))
            hosted_agent.metadata["workflow_kind"] = definition.get("kind")
            hosted_agent.metadata["workflow_source_alias"] = ref
        hosted_agent.tools = _dedupe_tools(hosted_agent.tools)

    # Hosting's AddWorkflow(...).AddAsAIAgent() creates an agent surface without
    # an explicit AIAgent assignment. Inventory it and project participant
    # authority from the workflow construction statement.
    for expression, expression_offset in _hosted_workflow_agent_expressions(
        source,
        masked,
    ):
        name = _hosted_workflow_name(expression)
        if not name:
            continue
        workflow_agent = next(
            (candidate for candidate in graph.agents if candidate.name == name),
            None,
        )
        if workflow_agent is None:
            workflow_agent = Agent(
                name=name,
                location=location(path, source, expression_offset),
                metadata={
                    "framework": FRAMEWORK,
                    "language": "csharp",
                    "agent_type": "WorkflowAgent",
                    "hosting_registration": True,
                    "binding_origin": "AddWorkflow.AddAsAIAgent",
                    "source_aliases": [],
                },
            )
            graph.agents.append(workflow_agent)
            aliases.setdefault(name, workflow_agent)

        referenced_definition = next(
            (
                workflows[ref] for ref in refs(expression)
                if ref in workflows
            ),
            None,
        )
        definition = referenced_definition or {
            "kind": _workflow_kind(expression) or "workflow",
            "participants": _workflow_participants(expression, aliases),
        }
        workflow_agent.tools.extend(_workflow_delegation_tools(
            path,
            source,
            definition,
            offset=expression_offset,
            agent_aliases=aliases,
        ))
        workflow_agent.metadata["workflow_kind"] = definition.get("kind")
        workflow_agent.tools = _dedupe_tools(workflow_agent.tools)

    run_options = _run_option_tool_sets(
        path,
        source,
        masked,
        known,
        tool_vars=tool_vars,
        hosted_vars=hosted_vars,
        mcp_lists=mcp_lists,
        mcp_servers=mcp_servers,
        agent_aliases=aliases,
    )
    _bind_per_run_authority(
        path,
        source,
        masked,
        agent_aliases=aliases,
        run_options=run_options,
        known=known,
        tool_vars=tool_vars,
        hosted_vars=hosted_vars,
        mcp_lists=mcp_lists,
        mcp_servers=mcp_servers,
    )

    graph.unbound_mcp_servers.extend(
        server for name, server in mcp_servers.items()
        if name not in bound_clients
    )
    graph.unbound_mcp_servers.extend(
        server for name, server in hosted_vars.items()
        if name not in bound_hosted
    )
    _propagate_delegation(graph)
    return graph
