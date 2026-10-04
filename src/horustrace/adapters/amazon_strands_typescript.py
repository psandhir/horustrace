from __future__ import annotations

import re
from copy import deepcopy
from pathlib import Path

from horustrace.heuristics import infer_capabilities
from horustrace.models import (
    Agent,
    Graph,
    Identity,
    MCPServer,
    NetworkDestination,
    SourceLocation,
    Tool,
)

FRAMEWORK = "strands-agents"
_SDK = "@strands-agents/sdk"
_URL_RE = re.compile(r"https?://[^\s\\"')\]\}<>]+")
_BINDING_RE = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*")

_VENDED_TOOL_CAPABILITIES: dict[str, set[str]] = {
    "fileEditor": {"data.read", "data.write"},
    "shell": {
        "data.read",
        "data.write",
        "process.execute",
        "network.external",
        "external.write",
        "destructive.write",
    },
    "pythonRepl": {"data.read", "data.write", "process.execute"},
    "httpRequest": {"data.read", "network.external", "external.write"},
    "retrieve": {"data.read", "network.external"},
    "useAws": {"data.read", "data.write", "network.external", "external.write"},
}


def _location(path: Path, source: str, offset: int) -> SourceLocation:
    line = source.count("\n", 0, max(0, offset)) + 1
    last_newline = source.rfind("\n", 0, max(0, offset))
    column = offset - last_newline
    return SourceLocation(path, line, max(1, column))


def _balanced(
    source: str,
    start: int,
    opener: str,
    closer: str,
) -> tuple[str, int] | None:
    if start < 0 or start >= len(source) or source[start] != opener:
        return None
    depth = 0
    quote: str | None = None
    escape = False
    index = start
    while index < len(source):
        char = source[index]
        if quote is not None:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in {"'", '"', "`"}:
            quote = char
            index += 1
            continue
        if char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return source[start + 1:index], index + 1
        index += 1
    return None


def _named_imports(source: str, module: str) -> dict[str, str]:
    result: dict[str, str] = {}
    pattern = re.compile(
        r"import\s*\{(?P<body>.*?)\}\s*from\s*[\\"']"
        + re.escape(module)
        + r"[\\"']",
        re.DOTALL,
    )
    for match in pattern.finditer(source):
        for raw in match.group("body").split(","):
            item = raw.strip()
            if not item:
                continue
            parts = re.split(r"\s+as\s+", item)
            imported = parts[0].strip()
            local = parts[-1].strip()
            if imported and local:
                result[local] = imported
    return result


def _string_property(text: str, name: str) -> str | None:
    match = re.search(
        rf"\b{re.escape(name)}\s*:\s*([\\"'])(.*?)\1",
        text,
        re.DOTALL,
    )
    return match.group(2) if match else None


def _array_property(text: str, name: str) -> list[str]:
    marker = re.search(rf"\b{re.escape(name)}\s*:", text)
    if not marker:
        return []
    start = text.find("[", marker.end())
    if start < 0:
        return []
    segment = _balanced(text, start, "[", "]")
    if segment is None:
        return []
    body, _ = segment
    refs: list[str] = []
    for item in body.split(","):
        value = item.strip()
        if not value:
            continue
        match = re.match(
            r"([A-Za-z_$][\w$]*)(?:\.asTool\s*\(.*)?$",
            value,
            re.DOTALL,
        )
        if match:
            refs.append(match.group(1))
    return refs


def _effect_capabilities(name: str, text: str) -> set[str]:
    lower = text.lower()
    capabilities = set(infer_capabilities(name))
    if any(
        marker in lower
        for marker in ("fetch(", "axios.", "http.", "https.", "request(")
    ):
        capabilities.add("network.external")
    if any(
        marker in lower
        for marker in (
            ".post(",
            ".put(",
            ".patch(",
            "method: 'post'",
            'method: "post"',
        )
    ):
        capabilities.update({"data.write", "external.write"})
    if any(marker in lower for marker in (".delete(", "unlink(", "rm(", "remove(")):
        capabilities.update({"data.write", "destructive.write"})
    if any(
        marker in lower
        for marker in ("exec(", "spawn(", "child_process", "bun.$", "deno.command")
    ):
        capabilities.add("process.execute")
    if any(marker in lower for marker in ("getsecretvalue", "secretsmanager", "secret")):
        capabilities.add("secrets.read")
    if any(marker in lower for marker in ("getobject", "getitem", "query(", "scan(")):
        capabilities.add("data.read")
    if any(
        marker in lower
        for marker in ("putobject", "putitem", "updateitem", "writefile")
    ):
        capabilities.add("data.write")
    return capabilities


def _destinations(
    path: Path,
    source: str,
    offset: int,
    text: str,
    capabilities: set[str],
) -> list[NetworkDestination]:
    if "network.external" not in capabilities:
        return []
    seen: set[str] = set()
    result: list[NetworkDestination] = []
    for target in _URL_RE.findall(text):
        if target in seen:
            continue
        seen.add(target)
        result.append(
            NetworkDestination(
                target=target,
                restricted=True,
                location=_location(path, source, offset),
                metadata={
                    "source": "literal_url",
                    "network_scope": "fixed_literal_destination",
                },
            )
        )
    return result


def _constructor_bindings(
    source: str,
    symbols: set[str],
) -> list[tuple[str, str, int]]:
    result: list[tuple[str, str, int]] = []
    for binding in _BINDING_RE.finditer(source):
        variable = binding.group(1)
        tail = source[binding.end():]
        ctor = re.match(r"new\s+([A-Za-z_$][\w$]*)\s*\(", tail)
        if not ctor or ctor.group(1) not in symbols:
            continue
        open_offset = binding.end() + ctor.end() - 1
        segment = _balanced(source, open_offset, "(", ")")
        if segment is None:
            continue
        body, _ = segment
        result.append((variable, body, binding.start()))
    return result


def _tool_bindings(
    path: Path,
    source: str,
    symbols: set[str],
) -> dict[str, Tool]:
    result: dict[str, Tool] = {}
    for binding in _BINDING_RE.finditer(source):
        variable = binding.group(1)
        tail = source[binding.end():]
        call = re.match(r"([A-Za-z_$][\w$]*)\s*\(", tail)
        if not call or call.group(1) not in symbols:
            continue
        open_offset = binding.end() + call.end() - 1
        segment = _balanced(source, open_offset, "(", ")")
        if segment is None:
            continue
        body, _ = segment
        explicit = _string_property(body, "name")
        capabilities = _effect_capabilities(explicit or variable, body)
        result[variable] = Tool(
            name=explicit or variable,
            kind="function",
            capabilities=capabilities,
            destinations=_destinations(
                path,
                source,
                binding.start(),
                body,
                capabilities,
            ),
            location=_location(path, source, binding.start()),
            metadata={
                "framework": FRAMEWORK,
                "language": "typescript",
                "binding_origin": "tool()",
                "source_alias": variable,
            },
        )
    return result


def _vended_tools(path: Path, source: str) -> dict[str, Tool]:
    result: dict[str, Tool] = {}
    pattern = re.compile(
        r"import\s*\{(?P<body>.*?)\}\s*from\s*([\\"'])"
        r"(?P<module>@strands-agents/sdk/vended-tools/[^\\"']+)\2",
        re.DOTALL,
    )
    for match in pattern.finditer(source):
        for raw in match.group("body").split(","):
            item = raw.strip()
            if not item:
                continue
            parts = re.split(r"\s+as\s+", item)
            imported = parts[0].strip()
            local = parts[-1].strip()
            capabilities = set(
                _VENDED_TOOL_CAPABILITIES.get(
                    imported,
                    infer_capabilities(imported),
                )
            )
            result[local] = Tool(
                name=imported,
                kind="strands_vended_tool",
                capabilities=capabilities,
                location=_location(path, source, match.start()),
                metadata={
                    "framework": FRAMEWORK,
                    "language": "typescript",
                    "source_module": match.group("module"),
                    "import_name": local,
                },
            )
    return result


def _mcp_server(
    path: Path,
    source: str,
    variable: str,
    body: str,
    offset: int,
) -> MCPServer:
    transport = "unknown"
    command: str | None = None
    args: list[str] = []
    url: str | None = None
    if "StdioClientTransport" in body:
        transport = "stdio"
        command = _string_property(body, "command")
        raw_args = re.search(r"\bargs\s*:\s*\[(.*?)\]", body, re.DOTALL)
        if raw_args:
            args = re.findall(r"[\\"']([^\\"']+)[\\"']", raw_args.group(1))
    elif "StreamableHTTPClientTransport" in body:
        transport = "streamable-http"
    elif "SSEClientTransport" in body:
        transport = "sse"
    if transport in {"streamable-http", "sse"}:
        url_match = _URL_RE.search(body)
        if url_match:
            url = url_match.group(0)
    authenticated = (
        True
        if re.search(
            r"\b(headers|authorization|token)\b",
            body,
            re.IGNORECASE,
        )
        else None
    )
    metadata = {
        "framework": FRAMEWORK,
        "language": "typescript",
        "provider": "strands",
    }
    if transport in {"streamable-http", "sse"} and url is None:
        metadata.update(
            {
                "dynamic_mcp_endpoint_basis": "operator_configuration",
                "network_scope": "operator_configured_destination",
            }
        )
    return MCPServer(
        name=variable,
        transport=transport,
        url=url,
        command=command,
        args=args,
        authenticated=authenticated,
        location=_location(path, source, offset),
        metadata=metadata,
    )


def _model_metadata(body: str) -> dict[str, object]:
    model_match = re.search(
        r"\bmodel\s*:\s*(?:new\s+)?([A-Za-z_$][\w$]*)",
        body,
    )
    if not model_match:
        return {"model_provider": "amazon-bedrock", "model_default": True}
    model_ref = model_match.group(1)
    provider = {
        "BedrockModel": "amazon-bedrock",
        "OpenAIModel": "openai",
        "AnthropicModel": "anthropic",
        "GoogleModel": "google",
        "GeminiModel": "google",
    }.get(model_ref)
    if provider:
        result: dict[str, object] = {"model_provider": provider}
        model_id = _string_property(body, "modelId")
        if model_id:
            result["model"] = model_id
        return result
    return {"model_reference": model_ref}


def is_amazon_strands_typescript_file(path: Path) -> bool:
    if path.suffix.lower() not in {
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
    }:
        return False
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False
    return _SDK in source


def scan_amazon_strands_typescript_file(path: Path) -> Graph:
    graph = Graph()
    if not is_amazon_strands_typescript_file(path):
        return graph
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return graph

    imports = _named_imports(source, _SDK)
    agent_symbols = {
        local
        for local, imported in imports.items()
        if imported == "Agent"
    }
    tool_symbols = {
        local
        for local, imported in imports.items()
        if imported == "tool"
    }
    mcp_symbols = {
        local
        for local, imported in imports.items()
        if imported == "McpClient"
    }
    if not agent_symbols:
        return graph

    custom_tools = _tool_bindings(path, source, tool_symbols)
    vended_tools = _vended_tools(path, source)
    tool_lookup = {**vended_tools, **custom_tools}

    mcp_lookup: dict[str, MCPServer] = {}
    for variable, body, offset in _constructor_bindings(source, mcp_symbols):
        mcp_lookup[variable] = _mcp_server(
            path,
            source,
            variable,
            body,
            offset,
        )

    agents_by_variable: dict[str, Agent] = {}
    raw_tools: dict[str, list[str]] = {}
    for variable, body, offset in _constructor_bindings(source, agent_symbols):
        model_meta = _model_metadata(body)
        explicit_name = _string_property(body, "name")
        agent = Agent(
            name=explicit_name or variable,
            location=_location(path, source, offset),
            metadata={
                "framework": FRAMEWORK,
                "language": "typescript",
                "source_aliases": [variable],
                **model_meta,
            },
        )
        if re.search(r"\bsystemPrompt\s*:", body):
            agent.metadata["system_prompt_declared"] = True
        if (
            model_meta.get("model_provider") == "amazon-bedrock"
            or model_meta.get("model_default") is True
        ):
            agent.identities.append(
                Identity(
                    name="aws-runtime-credentials",
                    provider="aws",
                    credential_source="aws_default_credential_chain",
                    location=agent.location,
                    metadata={
                        "runtime_resolved": True,
                        "framework": FRAMEWORK,
                        "language": "typescript",
                    },
                )
            )
        agents_by_variable[variable] = agent
        raw_tools[variable] = _array_property(body, "tools")

    for variable, agent in agents_by_variable.items():
        for ref in raw_tools.get(variable, []):
            if ref in tool_lookup:
                agent.tools.append(deepcopy(tool_lookup[ref]))
                continue
            if ref in mcp_lookup:
                agent.mcp_servers.append(deepcopy(mcp_lookup[ref]))
                continue
            child = agents_by_variable.get(ref)
            if child is not None and child is not agent:
                agent.tools.append(
                    Tool(
                        name=child.name,
                        kind="delegated_agent",
                        capabilities={"agent.delegate"}
                        | set(child.capabilities),
                        resources=deepcopy(child.effective_resources),
                        destinations=deepcopy(child.effective_destinations),
                        location=agent.location,
                        metadata={
                            "framework": FRAMEWORK,
                            "language": "typescript",
                            "delegate_target": child.name,
                            "authority_binding": "delegation_projection",
                            "authority_binding_basis": (
                                "strands_agent_as_tool"
                            ),
                        },
                    )
                )
                agent.metadata.setdefault("delegates_to", []).append(
                    child.name
                )
        graph.agents.append(agent)

    bound_mcp = {
        server.name
        for agent in graph.agents
        for server in agent.mcp_servers
    }
    graph.unbound_mcp_servers.extend(
        server
        for name, server in mcp_lookup.items()
        if name not in bound_mcp
    )
    bound_tools = {
        tool.name
        for agent in graph.agents
        for tool in agent.tools
    }
    graph.unbound_tools.extend(
        tool
        for tool in tool_lookup.values()
        if tool.name not in bound_tools
    )
    return graph
