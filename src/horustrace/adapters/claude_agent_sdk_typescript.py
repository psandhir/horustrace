from __future__ import annotations

import re
from copy import deepcopy
from pathlib import Path

from horustrace.heuristics import infer_capabilities
from horustrace.models import (
    Agent,
    Graph,
    MCPServer,
    NetworkDestination,
    ResourceScope,
    SourceLocation,
    Tool,
)

FRAMEWORK = "claude-agent-sdk"
_SDK = "@anthropic-ai/claude-agent-sdk"
_EXTENSIONS = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}
_URL_RE = re.compile(r"https?://[^\s\"')\]\}<>]+")
_BINDING_RE = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*")

_BUILTINS: dict[str, tuple[str, set[str]]] = {
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
    "Workflow": (
        "dynamic_workflow",
        {"agent.delegate", "process.execute", "data.read", "data.write"},
    ),
}


def _location(path: Path, source: str, offset: int) -> SourceLocation:
    line = source.count("\n", 0, max(0, offset)) + 1
    last = source.rfind("\n", 0, max(0, offset))
    return SourceLocation(path, line, max(1, offset - last))


def _balanced(source: str, start: int, opener: str, closer: str) -> tuple[str, int] | None:
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


def _named_imports(source: str) -> dict[str, str]:
    result: dict[str, str] = {}
    pattern = re.compile(
        r"import\s*\{(?P<body>[^}]*)\}\s*from\s*[\"']"
        + re.escape(_SDK)
        + r"[\"']",
        re.DOTALL,
    )
    for match in pattern.finditer(source):
        for raw in match.group("body").split(","):
            item = raw.strip()
            if not item or item.startswith("type "):
                continue
            parts = re.split(r"\s+as\s+", item)
            imported = parts[0].strip()
            local = parts[-1].strip()
            if imported and local:
                result[local] = imported
    return result


def _string_property(text: str, name: str) -> str | None:
    match = re.search(
        rf"\b{re.escape(name)}\s*:\s*([\"'])(.*?)\1",
        text,
        re.DOTALL,
    )
    return match.group(2) if match else None


def _bool_property(text: str, name: str) -> bool | None:
    match = re.search(rf"\b{re.escape(name)}\s*:\s*(true|false)\b", text)
    if not match:
        return None
    return match.group(1) == "true"


def _array_segment(text: str, name: str) -> str | None:
    marker = re.search(rf"\b{re.escape(name)}\s*:", text)
    if not marker:
        return None
    start = text.find("[", marker.end())
    if start < 0:
        return None
    segment = _balanced(text, start, "[", "]")
    return segment[0] if segment else None


def _string_array(text: str, name: str) -> list[str] | None:
    body = _array_segment(text, name)
    if body is None:
        return None
    # Return None for obviously dynamic entries rather than inventing a list.
    values = re.findall(r"[\"']([^\"']+)[\"']", body)
    stripped = re.sub(r"[\"'][^\"']+[\"']", "", body)
    if re.sub(r"[\s,]", "", stripped):
        return None
    return values


def _object_segment(text: str, name: str) -> str | None:
    marker = re.search(rf"\b{re.escape(name)}\s*:", text)
    if not marker:
        return None
    start = text.find("{", marker.end())
    if start < 0:
        return None
    segment = _balanced(text, start, "{", "}")
    return segment[0] if segment else None


def _binding_objects(source: str) -> dict[str, tuple[str, int]]:
    result: dict[str, tuple[str, int]] = {}
    for binding in _BINDING_RE.finditer(source):
        start = binding.end()
        while start < len(source) and source[start].isspace():
            start += 1
        if start >= len(source) or source[start] != "{":
            continue
        segment = _balanced(source, start, "{", "}")
        if segment:
            result[binding.group(1)] = (segment[0], binding.start())
    return result


def _builtin(path: Path, source: str, offset: int, name: str) -> Tool:
    kind, capabilities = _BUILTINS.get(
        name,
        ("claude_builtin_or_configured_tool", set(infer_capabilities(name))),
    )
    tool = Tool(
        name=name,
        kind=kind,
        capabilities=set(capabilities),
        location=_location(path, source, offset),
        metadata={
            "framework": FRAMEWORK,
            "language": "typescript",
            "claude_builtin": name in _BUILTINS,
        },
    )
    if name == "WebFetch":
        tool.destinations.append(
            NetworkDestination(
                target="<model-selected-url>",
                restricted=False,
                location=tool.location,
                metadata={
                    "source": "model_selected_url_argument",
                    "network_scope": "dynamic_destination",
                },
            )
        )
        tool.metadata["model_selected_url_fetch"] = True
        tool.metadata["untrusted_input"] = True
    elif name == "WebSearch":
        tool.destinations.append(
            NetworkDestination(
                target="<web-search>",
                restricted=False,
                location=tool.location,
                metadata={
                    "source": "claude_builtin",
                    "network_scope": "dynamic_search_results",
                },
            )
        )
    elif name == "Bash":
        tool.metadata["implicit_network"] = True
    elif name == "Workflow":
        tool.metadata.update(
            {
                "dynamic_workflow": True,
                "runtime_generated_workflow": True,
                "workflow_runtime": "claude-code",
                "delegate_target_unresolved": True,
            }
        )
    return tool


def _effect_capabilities(name: str, body: str) -> set[str]:
    lower = body.lower()
    capabilities = set(infer_capabilities(name))
    if any(marker in lower for marker in ("fetch(", "axios.", "http.", "https.", "request(")):
        capabilities.add("network.external")
    if any(
        marker in lower
        for marker in (
            ".post(",
            ".put(",
            ".patch(",
            "method: 'post'",
            'method: "post"',
            "method: 'put'",
            'method: "put"',
            "method: 'patch'",
            'method: "patch"',
        )
    ):
        capabilities.update({"data.write", "external.write"})
    if any(
        marker in lower
        for marker in (
            ".delete(",
            "method: 'delete'",
            'method: "delete"',
            "unlink(",
            "rm(",
        )
    ):
        capabilities.update({"data.write", "destructive.write", "external.write"})
    if any(marker in lower for marker in ("exec(", "spawn(", "child_process", "deno.command", "bun.$")):
        capabilities.add("process.execute")
    if any(marker in lower for marker in ("readfile", "readdir", "getobject", "query(")):
        capabilities.add("data.read")
    if any(marker in lower for marker in ("writefile", "putobject", "updateitem")):
        capabilities.add("data.write")
    return capabilities


def _destinations(
    path: Path,
    source: str,
    offset: int,
    body: str,
    capabilities: set[str],
) -> list[NetworkDestination]:
    if "network.external" not in capabilities:
        return []
    result: list[NetworkDestination] = []
    seen: set[str] = set()
    for target in _URL_RE.findall(body):
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


def _tool_bindings(path: Path, source: str, tool_symbols: set[str]) -> dict[str, Tool]:
    result: dict[str, Tool] = {}
    for binding in _BINDING_RE.finditer(source):
        variable = binding.group(1)
        tail = source[binding.end():]
        call = re.match(r"([A-Za-z_$][\w$]*)\s*\(", tail)
        if not call or call.group(1) not in tool_symbols:
            continue
        open_offset = binding.end() + call.end() - 1
        segment = _balanced(source, open_offset, "(", ")")
        if segment is None:
            continue
        body, _ = segment
        # Claude TS tool(name, description, schema, handler) uses a positional
        # name while older shapes may use an object.
        explicit_match = re.match(r"\s*[\"']([^\"']+)[\"']", body)
        explicit = explicit_match.group(1) if explicit_match else _string_property(body, "name")
        capabilities = _effect_capabilities(explicit or variable, body)
        result[variable] = Tool(
            name=explicit or variable,
            kind="claude_sdk_mcp_tool",
            capabilities=capabilities,
            destinations=_destinations(path, source, binding.start(), body, capabilities),
            location=_location(path, source, binding.start()),
            metadata={
                "framework": FRAMEWORK,
                "language": "typescript",
                "sdk_tool": True,
                "source_alias": variable,
            },
        )
    return result


def _sdk_mcp_servers(
    path: Path,
    source: str,
    server_symbols: set[str],
    custom_tools: dict[str, Tool],
) -> dict[str, MCPServer]:
    result: dict[str, MCPServer] = {}
    for binding in _BINDING_RE.finditer(source):
        variable = binding.group(1)
        tail = source[binding.end():]
        call = re.match(r"([A-Za-z_$][\w$]*)\s*\(", tail)
        if not call or call.group(1) not in server_symbols:
            continue
        open_offset = binding.end() + call.end() - 1
        segment = _balanced(source, open_offset, "(", ")")
        if segment is None:
            continue
        body, _ = segment
        runtime_name = _string_property(body, "name") or variable
        tool_body = _array_segment(body, "tools")
        discovered: list[str] = []
        capabilities: set[str] = set()
        dynamic = False
        if tool_body is not None:
            refs = [
                item.strip()
                for item in tool_body.split(",")
                if item.strip()
            ]
            for ref in refs:
                if re.fullmatch(r"[A-Za-z_$][\w$]*", ref) and ref in custom_tools:
                    tool = custom_tools[ref]
                    discovered.append(tool.name)
                    capabilities.update(tool.capabilities)
                else:
                    dynamic = True
        result[variable] = MCPServer(
            name=runtime_name,
            transport="sdk",
            authenticated=None,
            location=_location(path, source, binding.start()),
            metadata={
                "framework": FRAMEWORK,
                "language": "typescript",
                "source": "createSdkMcpServer",
                "sdk_server_alias": variable,
                "discovered_tools": discovered,
                "discovered_tool_capabilities": sorted(capabilities),
                "dynamic_tool_catalogue": dynamic,
                "in_process": True,
            },
        )
    return result


def _options_for_queries(
    source: str,
    query_symbols: set[str],
    objects: dict[str, tuple[str, int]],
) -> list[tuple[str, str, int]]:
    result: list[tuple[str, str, int]] = []
    seen: set[str] = set()
    pattern = re.compile(
        r"\b(" + "|".join(re.escape(s) for s in sorted(query_symbols)) + r")\s*\(",
    ) if query_symbols else None
    if pattern is None:
        return result
    for match in pattern.finditer(source):
        open_offset = source.find("(", match.start())
        segment = _balanced(source, open_offset, "(", ")")
        if segment is None:
            continue
        body, _ = segment
        outer_options = _object_segment(body, "options")
        if outer_options is not None:
            name = f"claude-query@{source.count(chr(10), 0, match.start()) + 1}"
            result.append((name, outer_options, match.start()))
            continue
        ref_match = re.search(r"\boptions\s*:\s*([A-Za-z_$][\w$]*)", body)
        if ref_match and ref_match.group(1) in objects:
            ref = ref_match.group(1)
            if ref in seen:
                continue
            seen.add(ref)
            option_body, offset = objects[ref]
            result.append((ref, option_body, offset))
    # Preserve option objects even when passed through a local wrapper.
    for name, (body, offset) in objects.items():
        if name == "options" and name not in seen:
            result.append((name, body, offset))
    return result


def _subagents(
    path: Path,
    source: str,
    options_body: str,
    offset: int,
) -> dict[str, Agent]:
    agents_body = _object_segment(options_body, "agents")
    if agents_body is None:
        return {}
    result: dict[str, Agent] = {}
    cursor = 0
    key_re = re.compile(r"([A-Za-z_$][\w$]*|[\"'][^\"']+[\"'])\s*:")
    while True:
        match = key_re.search(agents_body, cursor)
        if not match:
            break
        name = match.group(1).strip("\"'")
        start = agents_body.find("{", match.end())
        if start < 0:
            cursor = match.end()
            continue
        segment = _balanced(agents_body, start, "{", "}")
        if segment is None:
            break
        body, end = segment
        agent = Agent(
            name=name,
            location=_location(path, source, offset),
            metadata={
                "framework": FRAMEWORK,
                "language": "typescript",
                "subagent": True,
                "agent_definition": True,
            },
        )
        tools = _string_array(body, "tools")
        if tools is None:
            agent.metadata["tool_surface_inherited"] = True
        else:
            agent.tools.extend(_builtin(path, source, offset, item) for item in tools)
        permission = _string_property(body, "permissionMode")
        if permission:
            agent.metadata["permission_mode"] = permission
        result[name] = agent
        cursor = end
    return result


def is_claude_agent_sdk_typescript_file(path: Path) -> bool:
    if path.suffix.lower() not in _EXTENSIONS:
        return False
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False
    return _SDK in source


def scan_claude_agent_sdk_typescript_file(path: Path) -> Graph:
    graph = Graph()
    if not is_claude_agent_sdk_typescript_file(path):
        return graph
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return graph

    imports = _named_imports(source)
    query_symbols = {local for local, imported in imports.items() if imported == "query"}
    tool_symbols = {local for local, imported in imports.items() if imported == "tool"}
    server_symbols = {
        local for local, imported in imports.items() if imported == "createSdkMcpServer"
    }

    objects = _binding_objects(source)
    custom_tools = _tool_bindings(path, source, tool_symbols)
    sdk_servers = _sdk_mcp_servers(path, source, server_symbols, custom_tools)

    for name, body, offset in _options_for_queries(source, query_symbols, objects):
        agent = Agent(
            name=name,
            location=_location(path, source, offset),
            metadata={
                "framework": FRAMEWORK,
                "language": "typescript",
                "sdk_entrypoint": True,
                "tool_surface": "explicit",
            },
        )

        tool_names = _string_array(body, "tools")
        if tool_names is None:
            agent.metadata["dynamic_tools"] = True
            agent.metadata["tool_surface"] = "dynamic"
        else:
            for tool_name in tool_names:
                agent.tools.append(_builtin(path, source, offset, tool_name))

        allowed = _string_array(body, "allowedTools") or []
        denied = _string_array(body, "disallowedTools") or []
        agent.metadata["allowed_tools_auto_approve"] = allowed
        agent.metadata["disallowed_tools"] = denied
        permission = _string_property(body, "permissionMode")
        if permission:
            agent.metadata["permission_mode"] = permission

        bare_denied = {value for value in denied if "(" not in value and ")" not in value}
        agent.tools = [tool for tool in agent.tools if tool.name not in bare_denied]
        for tool in agent.tools:
            if tool.name in allowed:
                tool.approval = False
                tool.metadata["auto_approved"] = True
                tool.metadata["approval_basis"] = "allowedTools"
            if permission == "bypassPermissions" and tool.approval is None:
                tool.approval = False
                tool.metadata["approval_basis"] = "permissionMode_bypassPermissions"

        cwd = _string_property(body, "cwd")
        add_dirs = _string_array(body, "addDirs") or []
        if cwd or add_dirs:
            scopes = [
                ResourceScope(
                    kind="filesystem",
                    selector=value,
                    access={"data.read", "data.write"},
                    location=agent.location,
                    metadata={"source": "claude_ts_filesystem_scope"},
                )
                for value in ([cwd] if cwd else []) + add_dirs
            ]
            for tool in agent.tools:
                if tool.name in {
                    "Read", "Glob", "Grep", "Write", "Edit",
                    "NotebookEdit", "Bash", "Workflow",
                }:
                    tool.resources.extend(deepcopy(scopes))

        mcp_body = _object_segment(body, "mcpServers")
        if mcp_body is not None:
            configured: list[tuple[str, str]] = []
            consumed: list[tuple[int, int]] = []
            for match in re.finditer(
                r"([A-Za-z_$][\w$]*|[\"'][^\"']+[\"'])\s*:\s*([A-Za-z_$][\w$]*)",
                mcp_body,
            ):
                configured.append((match.group(1).strip("\"'"), match.group(2)))
                consumed.append(match.span())
            remainder = mcp_body
            for pair_start, pair_end in reversed(consumed):
                remainder = (
                    remainder[:pair_start]
                    + " " * (pair_end - pair_start)
                    + remainder[pair_end:]
                )
            for raw in remainder.split(","):
                ref = raw.strip()
                if re.fullmatch(r"[A-Za-z_$][\w$]*", ref):
                    configured.append((ref, ref))

            for configured_name, ref in configured:
                if ref not in sdk_servers:
                    continue
                server = deepcopy(sdk_servers[ref])
                server.name = configured_name
                prefix = f"mcp__{configured_name}"
                auto = [
                    rule
                    for rule in allowed
                    if rule == prefix or rule.startswith(prefix + "__")
                ]
                denied_rules = [
                    rule
                    for rule in denied
                    if rule == prefix or rule.startswith(prefix + "__")
                ]
                if auto:
                    server.metadata["auto_approved_tool_rules"] = auto
                    server.metadata["conditional_approval"] = True
                    server.metadata["approval_mechanism"] = "allowedTools"
                if denied_rules:
                    server.metadata["denied_tool_rules"] = denied_rules
                agent.mcp_servers.append(server)

        children = _subagents(path, source, body, offset)
        for child in children.values():
            agent.metadata.setdefault("delegates_to", []).append(child.name)
            agent.tools.append(
                Tool(
                    name=child.name,
                    kind="delegated_agent",
                    capabilities={"agent.delegate"} | set(child.capabilities),
                    resources=deepcopy(child.effective_resources),
                    destinations=deepcopy(child.effective_destinations),
                    location=agent.location,
                    metadata={
                        "framework": FRAMEWORK,
                        "language": "typescript",
                        "delegate_target": child.name,
                        "authority_binding": "delegation_projection",
                        "authority_binding_basis": "Options.agents",
                    },
                )
            )
        graph.agents.append(agent)
        graph.agents.extend(children.values())

    bound_servers = {server.metadata.get("sdk_server_alias") for a in graph.agents for server in a.mcp_servers}
    graph.unbound_mcp_servers.extend(
        deepcopy(server)
        for alias, server in sdk_servers.items()
        if alias not in bound_servers
    )
    bound_custom = {
        name for server in graph.all_mcp_servers()
        for name in server.metadata.get("discovered_tools", [])
    }
    graph.unbound_tools.extend(
        deepcopy(tool) for tool in custom_tools.values() if tool.name not in bound_custom
    )
    return graph
