from __future__ import annotations

import re
from pathlib import Path

from horustrace.models import Agent, Graph, MCPServer, SourceLocation, Tool

FRAMEWORK = "claude-managed-agents"
_EXTENSIONS = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}

_MANAGED_BUILTINS: dict[str, tuple[str, set[str]]] = {
    "read": ("filesystem_read", {"data.read"}),
    "glob": ("filesystem_search", {"data.read"}),
    "grep": ("filesystem_search", {"data.read"}),
    "write": ("filesystem_write", {"data.write"}),
    "edit": ("filesystem_write", {"data.read", "data.write"}),
    "bash": (
        "shell",
        {"process.execute", "data.read", "data.write", "network.external"},
    ),
    "web_fetch": ("web_fetch", {"data.read", "network.external"}),
    "web_search": ("web_search", {"data.read", "network.external"}),
}


def _location(path: Path, source: str, offset: int) -> SourceLocation:
    line = source.count("\n", 0, max(0, offset)) + 1
    previous = source.rfind("\n", 0, max(0, offset))
    column = offset + 1 if previous < 0 else offset - previous
    return SourceLocation(path, line, column)


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
    escaped = False
    template_depth = 0
    for index in range(start, len(source)):
        char = source[index]
        if quote is not None:
            if escaped:
                escaped = False
                continue
            if char == "\\":
                escaped = True
                continue
            if quote == "`":
                if char == "$" and index + 1 < len(source) and source[index + 1] == "{":
                    template_depth += 1
                    continue
                if char == "}" and template_depth:
                    template_depth -= 1
                    continue
                if char == "`" and template_depth == 0:
                    quote = None
                continue
            if char == quote:
                quote = None
            continue
        if char in {"\"", "'", "`"}:
            quote = char
            continue
        if char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return source[start : index + 1], index + 1
    return None


def _string_constants(source: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for match in re.finditer(
        r"\b(?:export\s+)?const\s+([A-Za-z_$][\w$]*)\s*=\s*"
        r"([\"'])(.*?)\2",
        source,
        re.DOTALL,
    ):
        result[match.group(1)] = match.group(3)
    return result


def _resolve_string(value: str, constants: dict[str, str]) -> str | None:
    stripped = value.strip()
    quoted = re.fullmatch(r"([\"'])(.*?)\1", stripped, re.DOTALL)
    if quoted:
        return quoted.group(2)
    return constants.get(stripped)


def _property_expression(body: str, name: str) -> str | None:
    match = re.search(rf"\b{re.escape(name)}\s*:\s*", body)
    if not match:
        return None
    start = match.end()
    index = start
    depth = 0
    quote: str | None = None
    escaped = False
    while index < len(body):
        char = body[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in {"\"", "'", "`"}:
            quote = char
            index += 1
            continue
        if char in "([{":
            depth += 1
        elif char in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif char == "," and depth == 0:
            break
        index += 1
    return body[start:index].strip()


def _resolve_import(path: Path, specifier: str) -> Path | None:
    if not specifier.startswith("."):
        return None
    candidate = (path.parent / specifier).resolve()
    candidates = [candidate]
    if candidate.suffix in {".js", ".mjs", ".cjs"}:
        candidates.extend(candidate.with_suffix(suffix) for suffix in (".ts", ".tsx"))
    elif not candidate.suffix:
        candidates.extend(
            candidate.with_suffix(suffix)
            for suffix in (".ts", ".tsx", ".js", ".mjs", ".cjs")
        )
        candidates.extend(candidate / f"index{suffix}" for suffix in (".ts", ".tsx", ".js"))
    return next((item for item in candidates if item.is_file()), None)


def _imported_functions(path: Path, source: str) -> dict[str, tuple[Path, str]]:
    result: dict[str, tuple[Path, str]] = {}
    pattern = re.compile(
        r"import\s*\{(?P<body>[^}]*)\}\s*from\s*"
        r"(?P<quote>[\"'])(?P<specifier>[^\"']+)(?P=quote)",
        re.DOTALL,
    )
    for match in pattern.finditer(source):
        target = _resolve_import(path, match.group("specifier"))
        if target is None:
            continue
        for raw in match.group("body").split(","):
            item = raw.strip()
            if not item or item.startswith("type "):
                continue
            parts = re.split(r"\s+as\s+", item)
            imported = parts[0].strip()
            local = parts[-1].strip()
            if imported and local:
                result[local] = (target, imported)
    return result


def _function_body(source: str, name: str) -> str | None:
    match = re.search(
        rf"\b(?:export\s+)?(?:async\s+)?function\s+{re.escape(name)}\s*\(",
        source,
    )
    if not match:
        return None
    args_start = source.find("(", match.start())
    args = _balanced(source, args_start, "(", ")")
    if args is None:
        return None
    body_start = source.find("{", args[1])
    segment = _balanced(source, body_start, "{", "}")
    return segment[0] if segment else None


def _returned_object(body: str) -> str | None:
    match = re.search(r"\breturn\s*\{", body)
    if not match:
        return None
    start = body.find("{", match.start())
    segment = _balanced(body, start, "{", "}")
    return segment[0] if segment else None


def _object_candidates(source: str, discriminator: str) -> list[tuple[str, int]]:
    result: list[tuple[str, int]] = []
    pattern = re.compile(
        rf"\{{\s*type\s*:\s*[\"']{re.escape(discriminator)}[\"']"
    )
    for match in pattern.finditer(source):
        segment = _balanced(source, match.start(), "{", "}")
        if segment is not None:
            result.append((segment[0], match.start()))
    return result


def _managed_builtin(path: Path, source: str, offset: int, name: str) -> Tool:
    kind, capabilities = _MANAGED_BUILTINS.get(name, ("managed_builtin", set()))
    return Tool(
        name=name,
        kind=kind,
        capabilities=set(capabilities),
        approval=False,
        location=_location(path, source, offset),
        metadata={
            "framework": FRAMEWORK,
            "language": "typescript",
            "managed_tool": True,
            "approval_basis": "managed_agent_toolset_default",
        },
    )


def _apply_builder(
    agent: Agent,
    *,
    path: Path,
    source: str,
    builder_path: Path,
    builder_name: str,
) -> None:
    try:
        builder_source = builder_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        agent.metadata["dynamic_agent_builder"] = True
        return
    body = _function_body(builder_source, builder_name)
    if body is None:
        agent.metadata["dynamic_agent_builder"] = True
        return

    constants = _string_constants(builder_source)
    body_offset = builder_source.find(body)
    agent.metadata["agent_builder"] = builder_name
    agent.metadata["agent_builder_source"] = str(builder_path)

    returned = _returned_object(body)
    if returned is not None:
        for field in ("name", "model"):
            expression = _property_expression(returned, field)
            if expression is None:
                continue
            value = _resolve_string(expression, constants)
            if value is None:
                continue
            if field == "name":
                agent.name = value
            else:
                agent.metadata["model"] = value

    servers: dict[str, MCPServer] = {server.name: server for server in agent.mcp_servers}
    for object_body, offset in _object_candidates(body, "url"):
        name_expr = _property_expression(object_body, "name")
        url_expr = _property_expression(object_body, "url")
        if name_expr is None:
            continue
        name = _resolve_string(name_expr, constants)
        if not name:
            continue
        url = _resolve_string(url_expr or "", constants)
        server = MCPServer(
            name=name,
            transport="http",
            url=url,
            authenticated=None,
            location=_location(
                builder_path,
                builder_source,
                max(0, body_offset) + offset,
            ),
            metadata={
                "framework": FRAMEWORK,
                "language": "typescript",
                "managed_mcp": True,
                "configuration_source": f"{builder_name}.mcp_servers",
                "dynamic_mcp_endpoint": url is None,
            },
        )
        if url is None and url_expr:
            server.metadata["mcp_url_expression"] = url_expr
        prefix = body[max(0, offset - 300) : offset]
        if re.search(r"\bif\s*\(", prefix):
            server.metadata["conditional"] = True
        servers[name] = server

    for object_body, _ in _object_candidates(body, "mcp_toolset"):
        server_expr = _property_expression(object_body, "mcp_server_name")
        server_name = _resolve_string(server_expr or "", constants)
        if not server_name:
            continue
        server = servers.get(server_name)
        if server is None:
            server = MCPServer(
                name=server_name,
                transport="managed",
                authenticated=None,
                location=agent.location,
                metadata={
                    "framework": FRAMEWORK,
                    "language": "typescript",
                    "managed_mcp": True,
                    "reference_only": True,
                    "tool_catalogue_unresolved": True,
                },
            )
            servers[server_name] = server
        policy_expr = _property_expression(object_body, "permission_policy")
        policy = None
        if policy_expr:
            nested = re.search(r"type\s*:\s*([\"'])(.*?)\1", policy_expr)
            if nested:
                policy = nested.group(2)
        if policy is None and "always_allow" in object_body:
            policy = "always_allow"
        if policy:
            server.metadata["permission_policy"] = policy
            if policy == "always_allow":
                server.approval = False
                server.metadata["approval_basis"] = "managed_permission_policy"
            elif policy == "always_ask":
                server.approval = True
                server.metadata["approval_basis"] = "managed_permission_policy"

    if re.search(r"type\s*:\s*[\"']agent_toolset", body):
        for name in _MANAGED_BUILTINS:
            if not any(tool.name == name for tool in agent.tools):
                agent.tools.append(_managed_builtin(builder_path, builder_source, 0, name))

    agent.mcp_servers = list(servers.values())


def is_anthropic_managed_agents_typescript_file(path: Path) -> bool:
    if path.suffix.lower() not in _EXTENSIONS:
        return False
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False
    return (
        "@anthropic-ai/sdk" in source
        and ".beta.agents.create(" in source
    )


def scan_anthropic_managed_agents_typescript_file(path: Path) -> Graph:
    graph = Graph()
    if not is_anthropic_managed_agents_typescript_file(path):
        return graph
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return graph

    imported = _imported_functions(path, source)
    pattern = re.compile(r"\.beta\.agents\.create\s*\(")
    for match in pattern.finditer(source):
        args_start = source.find("(", match.start())
        args = _balanced(source, args_start, "(", ")")
        if args is None:
            continue
        args_body, _ = args
        object_start = args_body.find("{")
        object_segment = _balanced(args_body, object_start, "{", "}")
        if object_segment is None:
            continue
        body = object_segment[0]

        prefix = source[max(0, match.start() - 160) : match.start()]
        binding_match = re.search(
            r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:await\s*)?$",
            prefix,
        )
        binding = binding_match.group(1) if binding_match else (
            f"managed-agent@{source.count(chr(10), 0, match.start()) + 1}"
        )
        agent = Agent(
            name=binding,
            location=_location(path, source, match.start()),
            metadata={
                "framework": FRAMEWORK,
                "language": "typescript",
                "managed_runtime": True,
                "execution_boundary": "server-managed",
                "source_alias": binding,
            },
        )

        constants = _string_constants(source)
        for field in ("name", "model"):
            expression = _property_expression(body, field)
            value = _resolve_string(expression or "", constants)
            if value is None:
                continue
            if field == "name":
                agent.name = value
            else:
                agent.metadata["model"] = value

        for spread in re.finditer(r"\.\.\.([A-Za-z_$][\w$]*)\s*\(", body):
            local = spread.group(1)
            target = imported.get(local)
            if target is None:
                agent.metadata["dynamic_agent_builder"] = True
                continue
            _apply_builder(
                agent,
                path=path,
                source=source,
                builder_path=target[0],
                builder_name=target[1],
            )

        graph.agents.append(agent)

    return graph
