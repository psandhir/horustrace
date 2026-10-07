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
from horustrace.semantic_contract import set_model_provenance
from horustrace.semantic_contract import ToolControlState, set_tool_control

FRAMEWORK = "claude-agent-sdk"
_SDK = "@anthropic-ai/claude-agent-sdk"
_EXTENSIONS = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}
_URL_RE = re.compile(r"https?://[^\s\"')\]\}<>]+")
_BINDING_RE = re.compile(
    r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)"
    r"(?:\s*:\s*[^=\n]+)?\s*=\s*"
)

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


_DEFAULT_TOOLS = tuple(_BUILTINS)


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
    line_comment = False
    block_comment = False
    index = start
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""

        if line_comment:
            if char in {"\n", "\r"}:
                line_comment = False
            index += 1
            continue

        if block_comment:
            if char == "*" and next_char == "/":
                block_comment = False
                index += 2
            else:
                index += 1
            continue

        if quote is not None:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == quote:
                quote = None
            index += 1
            continue

        if char == "/" and next_char == "/":
            line_comment = True
            index += 2
            continue
        if char == "/" and next_char == "*":
            block_comment = True
            index += 2
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


def _mask_comments(source: str) -> str:
    """Mask JavaScript/TypeScript comments while preserving offsets and literals."""
    result = list(source)
    quote: str | None = None
    escape = False
    line_comment = False
    block_comment = False
    index = 0

    def blank(position: int) -> None:
        if result[position] not in {"\n", "\r"}:
            result[position] = " "

    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""

        if line_comment:
            if char in {"\n", "\r"}:
                line_comment = False
            else:
                blank(index)
            index += 1
            continue

        if block_comment:
            blank(index)
            if char == "*" and next_char == "/":
                if index + 1 < len(source):
                    blank(index + 1)
                block_comment = False
                index += 2
            else:
                index += 1
            continue

        if quote is not None:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == quote:
                quote = None
            index += 1
            continue

        if char == "/" and next_char == "/":
            blank(index)
            if index + 1 < len(source):
                blank(index + 1)
            line_comment = True
            index += 2
            continue
        if char == "/" and next_char == "*":
            blank(index)
            if index + 1 < len(source):
                blank(index + 1)
            block_comment = True
            index += 2
            continue
        if char in {"'", '"', "`"}:
            quote = char
        index += 1

    return "".join(result)


def _named_imports(source: str) -> dict[str, str]:
    result: dict[str, str] = {}
    masked = _mask_comments(source)
    pattern = re.compile(
        r"import\s*\{(?P<body>[^}]*)\}\s*from\s*[\"']"
        + re.escape(_SDK)
        + r"[\"']",
        re.DOTALL,
    )
    for match in pattern.finditer(masked):
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
        _mask_comments(text),
        re.DOTALL,
    )
    return match.group(2) if match else None


def _bool_property(text: str, name: str) -> bool | None:
    match = re.search(
        rf"\b{re.escape(name)}\s*:\s*(true|false)\b",
        _mask_comments(text),
    )
    if not match:
        return None
    return match.group(1) == "true"


def _array_segment(text: str, name: str) -> str | None:
    masked = _mask_comments(text)
    marker = re.search(rf"\b{re.escape(name)}\s*:", masked)
    if not marker:
        return None
    start = masked.find("[", marker.end())
    if start < 0:
        return None
    segment = _balanced(text, start, "[", "]")
    return segment[0] if segment else None


def _string_array(text: str, name: str) -> list[str] | None:
    body = _array_segment(text, name)
    if body is None:
        return None
    # Return None for obviously dynamic entries rather than inventing a list.
    clean = _mask_comments(body)
    values = re.findall(r"[\"']([^\"']+)[\"']", clean)
    stripped = re.sub(r"[\"'][^\"']+[\"']", "", clean)
    if re.sub(r"[\s,]", "", stripped):
        return None
    return values


def _object_segment(text: str, name: str) -> str | None:
    masked = _mask_comments(text)
    marker = re.search(rf"\b{re.escape(name)}\s*:", masked)
    if not marker:
        return None
    start = masked.find("{", marker.end())
    if start < 0:
        return None
    segment = _balanced(text, start, "{", "}")
    return segment[0] if segment else None


def _has_property(text: str, name: str) -> bool:
    return re.search(
        rf"\b{re.escape(name)}\s*:",
        _mask_comments(text),
    ) is not None


def _resolve_typescript_import(path: Path, specifier: str) -> Path | None:
    if not specifier.startswith("."):
        return None
    candidate = (path.parent / specifier).resolve()
    candidates = [candidate]
    if candidate.suffix in {".js", ".mjs", ".cjs"}:
        candidates.extend(
            candidate.with_suffix(suffix)
            for suffix in (".ts", ".tsx")
        )
    elif not candidate.suffix:
        candidates.extend(
            candidate.with_suffix(suffix)
            for suffix in (".ts", ".tsx", ".js", ".mjs", ".cjs")
        )
        candidates.extend(
            candidate / f"index{suffix}"
            for suffix in (".ts", ".tsx", ".js")
        )
    return next((item for item in candidates if item.is_file()), None)


def _function_return_object(source: str, name: str) -> str | None:
    masked = _mask_comments(source)
    match = re.search(
        rf"\b(?:export\s+)?(?:async\s+)?function\s+{re.escape(name)}\s*\(",
        masked,
    )
    if not match:
        return None
    args_start = masked.find("(", match.start())
    args = _balanced(source, args_start, "(", ")")
    if args is None:
        return None
    body_start = masked.find("{", args[1])
    body_segment = _balanced(source, body_start, "{", "}")
    if body_segment is None:
        return None
    body, _ = body_segment
    return_match = re.search(r"\breturn\s*\{", _mask_comments(body))
    if not return_match:
        return None
    object_start = body.find("{", return_match.start())
    returned = _balanced(body, object_start, "{", "}")
    return returned[0] if returned else None


def _string_array_expression(
    expression: str,
    arrays: dict[str, list[str]],
) -> list[str] | None:
    current = _mask_comments(expression).strip()
    alias = re.fullmatch(r"([A-Za-z_$][\w$]*)", current)
    if alias:
        return list(arrays[alias.group(1)]) if alias.group(1) in arrays else None
    start = current.find("[")
    if start < 0:
        return None
    segment = _balanced(current, start, "[", "]")
    if segment is None:
        return None
    body, _ = segment
    values: list[str] = []
    cursor = 0
    token = re.compile(
        r"\s*(?:([\"'])(.*?)\1|\.\.\.([A-Za-z_$][\w$]*))\s*(?:,|$)",
        re.DOTALL,
    )
    while cursor < len(body):
        match = token.match(body, cursor)
        if not match:
            if not body[cursor:].strip():
                break
            return None
        if match.group(2) is not None:
            values.append(match.group(2))
        else:
            ref = match.group(3)
            if ref not in arrays:
                return None
            values.extend(arrays[ref])
        cursor = match.end()
    return values


def _exported_string_arrays(source: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    masked = _mask_comments(source)
    pattern = re.compile(
        r"\b(?:export\s+)?const\s+([A-Za-z_$][\w$]*)"
        r"(?:\s*:\s*[^=\n]+)?\s*=\s*"
    )
    for match in pattern.finditer(masked):
        tail = masked[match.end():]
        start = tail.find("[")
        if start < 0 or tail[:start].strip():
            continue
        absolute = match.end() + start
        segment = _balanced(source, absolute, "[", "]")
        if segment is None:
            continue
        _body, end = segment
        expression = source[absolute:end]
        values = _string_array_expression(expression, result)
        if values is not None:
            result[match.group(1)] = values
    return result


def _imported_string_arrays(path: Path, source: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    masked = _mask_comments(source)
    pattern = re.compile(
        r"import\s*\{(?P<body>[^}]*)\}\s*from\s*"
        r"(?P<quote>[\"'])(?P<specifier>[^\"']+)(?P=quote)",
        re.DOTALL,
    )
    cache: dict[Path, dict[str, list[str]]] = {}
    for match in pattern.finditer(masked):
        imported_path = _resolve_typescript_import(path, match.group("specifier"))
        if imported_path is None:
            continue
        exported = cache.get(imported_path)
        if exported is None:
            try:
                imported_source = imported_path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            exported = _exported_string_arrays(imported_source)
            cache[imported_path] = exported
        for raw in match.group("body").split(","):
            item = raw.strip()
            if not item or item.startswith("type "):
                continue
            parts = re.split(r"\s+as\s+", item)
            imported = parts[0].strip()
            local = parts[-1].strip()
            if imported in exported:
                result[local] = list(exported[imported])
    return result


def _expand_string_array_constants(
    body: str,
    arrays: dict[str, list[str]],
) -> str:
    current = body
    for name, values in arrays.items():
        literal = "[" + ", ".join(repr(value) for value in values) + "]"
        current = re.sub(
            rf"\b(allowedTools|disallowedTools|deny)\s*:\s*{re.escape(name)}\b",
            lambda match, replacement=literal: f"{match.group(1)}: {replacement}",
            current,
        )
    return current


def _imported_option_builders(path: Path, source: str) -> dict[str, str]:
    result: dict[str, str] = {}
    masked = _mask_comments(source)
    pattern = re.compile(
        r"import\s*\{(?P<body>[^}]*)\}\s*from\s*"
        r"(?P<quote>[\"'])(?P<specifier>[^\"']+)(?P=quote)",
        re.DOTALL,
    )
    cache: dict[Path, str] = {}
    for match in pattern.finditer(masked):
        imported_path = _resolve_typescript_import(path, match.group("specifier"))
        if imported_path is None:
            continue
        imported_source = cache.get(imported_path)
        if imported_source is None:
            try:
                imported_source = imported_path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            cache[imported_path] = imported_source
        for raw in match.group("body").split(","):
            item = raw.strip()
            if not item or item.startswith("type "):
                continue
            parts = re.split(r"\s+as\s+", item)
            imported = parts[0].strip()
            local = parts[-1].strip()
            if not imported or not local:
                continue
            returned = _function_return_object(imported_source, imported)
            if returned is not None:
                arrays = _exported_string_arrays(imported_source)
                arrays.update(_imported_string_arrays(imported_path, imported_source))
                result[local] = _expand_string_array_constants(returned, arrays)
    return result


def _binding_builder_objects(
    source: str,
    builders: dict[str, str],
) -> dict[str, tuple[str, int]]:
    result: dict[str, tuple[str, int]] = {}
    if not builders:
        return result
    names = "|".join(re.escape(name) for name in sorted(builders))
    pattern = re.compile(
        rf"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)"
        rf"(?:\s*:\s*[^=\n]+)?\s*=\s*"
        rf"({names})\s*\(",
    )
    for match in pattern.finditer(_mask_comments(source)):
        result[match.group(1)] = (builders[match.group(2)], match.start())
    return result


def _expand_object_spreads(
    body: str,
    objects: dict[str, tuple[str, int]],
) -> str:
    current = body
    seen: set[str] = set()
    for _ in range(6):
        changed = False
        for match in list(re.finditer(r"\.\.\.([A-Za-z_$][\w$]*)", current)):
            ref = match.group(1)
            if ref not in objects or ref in seen:
                continue
            seen.add(ref)
            replacement = objects[ref][0]
            current = current[:match.start()] + replacement + current[match.end():]
            changed = True
            break
        if not changed:
            break
    return current


def _binding_objects(source: str) -> dict[str, tuple[str, int]]:
    result: dict[str, tuple[str, int]] = {}
    for binding in _BINDING_RE.finditer(_mask_comments(source)):
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
    for binding in _BINDING_RE.finditer(_mask_comments(source)):
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
    for binding in _BINDING_RE.finditer(_mask_comments(source)):
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
    builders: dict[str, str],
) -> list[tuple[str, str, int]]:
    result: list[tuple[str, str, int]] = []
    seen: set[str] = set()
    pattern = re.compile(
        r"\b(" + "|".join(re.escape(s) for s in sorted(query_symbols)) + r")\s*\(",
    ) if query_symbols else None
    if pattern is None:
        return result
    for match in pattern.finditer(_mask_comments(source)):
        open_offset = source.find("(", match.start())
        segment = _balanced(source, open_offset, "(", ")")
        if segment is None:
            continue
        body, _ = segment
        builder_match = re.search(
            r"\boptions\s*:\s*([A-Za-z_$][\w$]*)\s*\(",
            body,
        )
        if builder_match and builder_match.group(1) in builders:
            builder = builder_match.group(1)
            name = f"{builder}@{source.count(chr(10), 0, match.start()) + 1}"
            result.append((name, builders[builder], match.start()))
            continue
        outer_options = _object_segment(body, "options")
        if outer_options is not None:
            name = f"claude-query@{source.count(chr(10), 0, match.start()) + 1}"
            result.append(
                (name, _expand_object_spreads(outer_options, objects), match.start())
            )
            continue
        ref_match = re.search(r"\boptions\s*:\s*([A-Za-z_$][\w$]*)", body)
        if ref_match and ref_match.group(1) in objects:
            ref = ref_match.group(1)
            if ref in seen:
                continue
            seen.add(ref)
            option_body, offset = objects[ref]
            result.append((ref, _expand_object_spreads(option_body, objects), offset))
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
        model = _string_property(body, "model")
        if model:
            set_model_provenance(
                agent.metadata,
                identifier=model,
                provider="anthropic",
                hosting="provider_hosted",
            )
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

    builders = _imported_option_builders(path, source)
    objects = _binding_objects(source)
    objects.update(_binding_builder_objects(source, builders))
    custom_tools = _tool_bindings(path, source, tool_symbols)
    sdk_servers = _sdk_mcp_servers(path, source, server_symbols, custom_tools)

    for name, body, offset in _options_for_queries(
        source,
        query_symbols,
        objects,
        builders,
    ):
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

        model = _string_property(body, "model")
        if model:
            set_model_provenance(
                agent.metadata,
                identifier=model,
                provider="anthropic",
                hosting="provider_hosted",
            )

        tool_names = _string_array(body, "tools")
        tools_present = _has_property(body, "tools")
        tools_object = _object_segment(body, "tools")
        preset = (
            tools_object is not None
            and _string_property(tools_object, "type") == "preset"
            and _string_property(tools_object, "preset") == "claude_code"
        )
        default_surface = not tools_present or preset

        allowed_present = _has_property(body, "allowedTools")
        allowed_resolved = _string_array(body, "allowedTools")
        denied_resolved = _string_array(body, "disallowedTools")
        settings_body = _object_segment(body, "settings")
        permissions_body = (
            _object_segment(settings_body, "permissions")
            if settings_body is not None
            else None
        )
        settings_denied = (
            _string_array(permissions_body, "deny")
            if permissions_body is not None
            else None
        )
        allowed = allowed_resolved or []
        denied = denied_resolved or []
        effective_denied = list(dict.fromkeys(denied + (settings_denied or [])))

        if tool_names is not None:
            agent.metadata["tool_surface"] = "explicit"
            for tool_name in tool_names:
                agent.tools.append(_builtin(path, source, offset, tool_name))
        elif default_surface:
            projected = list(_DEFAULT_TOOLS)
            if allowed_present and allowed_resolved is not None:
                projected = [
                    tool_name
                    for tool_name in projected
                    if tool_name in allowed_resolved
                ]
                agent.metadata["tool_surface"] = "restricted_default"
                agent.metadata["tool_surface_restricted_by_allowed_tools"] = True
                agent.metadata["explicit_allowed_tool_surface"] = list(allowed_resolved)
            else:
                agent.metadata["tool_surface"] = (
                    "preset:claude_code" if preset else "runtime_default"
                )
            agent.metadata["default_tool_surface_projection"] = (
                "security_relevant_builtins"
            )
            for tool_name in projected:
                agent.tools.append(_builtin(path, source, offset, tool_name))
        else:
            agent.metadata["dynamic_tools"] = True
            agent.metadata["tool_surface"] = "dynamic"

        if allowed_present and allowed_resolved is None:
            agent.metadata["dynamic_allowed_tools"] = True
        if _has_property(body, "disallowedTools") and denied_resolved is None:
            agent.metadata["dynamic_disallowed_tools"] = True
        agent.metadata["allowed_tools_auto_approve"] = allowed
        agent.metadata["disallowed_tools"] = denied
        if settings_denied is not None:
            agent.metadata["settings_deny_rules"] = settings_denied
        can_use_tool = _has_property(body, "canUseTool")
        hooks_body = _object_segment(body, "hooks")
        pre_tool_use_guard = hooks_body is not None and _has_property(
            hooks_body, "PreToolUse"
        )
        control_mechanisms: list[str] = []
        if can_use_tool:
            agent.metadata["can_use_tool_configured"] = True
            control_mechanisms.append("claude_canUseTool")
        if pre_tool_use_guard:
            agent.metadata["pre_tool_use_guard"] = True
            control_mechanisms.append("claude_PreToolUse")
        if control_mechanisms:
            set_tool_control(
                agent.metadata,
                ToolControlState.ENFORCING,
                mechanism="+".join(control_mechanisms),
            )
        permission = _string_property(body, "permissionMode")
        if permission:
            agent.metadata["permission_mode"] = permission

        bare_denied = {
            value
            for value in effective_denied
            if "(" not in value and ")" not in value
        }
        agent.tools = [tool for tool in agent.tools if tool.name not in bare_denied]
        for tool in agent.tools:
            if tool.name in allowed:
                tool.approval = False
                tool.metadata["auto_approved"] = True
                tool.metadata["approval_basis"] = "allowedTools"
            if permission == "bypassPermissions" and tool.approval is None:
                tool.approval = False
                tool.metadata["approval_basis"] = "permissionMode_bypassPermissions"
            scoped_denies = [
                rule
                for rule in effective_denied
                if rule.startswith(f"{tool.name}(") and rule.endswith(")")
            ]
            if scoped_denies:
                tool.metadata["scoped_deny_rules"] = scoped_denies
            if can_use_tool or pre_tool_use_guard:
                tool.metadata["runtime_controlled"] = True

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
