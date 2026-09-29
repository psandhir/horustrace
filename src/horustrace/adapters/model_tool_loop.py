"""Framework-neutral discovery for source-proven model/tool agent loops.

This adapter is intentionally conservative. It recognizes an agent root only when
source shows a model invocation, tool catalogue exposure, model-selected tool calls,
and concrete dispatch, or when an unsupported framework exposes an explicit
tool-bound agent constructor with a model binding.
"""
# ruff: noqa: I001

from __future__ import annotations

import ast
import re
from pathlib import Path

from horustrace.models import Agent, Graph, MCPServer, SourceLocation
from horustrace.semantic_discovery import SemanticEntityKind, stable_entity_id


_KNOWN_FRAMEWORK_PREFIXES = (
    "google.adk",
    "pydantic_ai",
    "langgraph",
    "fast_agent",
    "mcp_agent",
)
_KNOWN_FRAMEWORK_MODULES = {"agents"}
_EXPLICIT_AGENT_MODULES = {"livekit.agents"}
_MODEL_CALL_SUFFIXES = (
    "chat.completions.create",
    "responses.create",
)
_MODEL_METHODS = {
    "send_user_message",
    "send_tool_results",
    "generate_content",
    "generate",
    "complete",
    "completion",
    "invoke",
    "ainvoke",
    "chat_collect",
}


def _location(path: Path, node: ast.AST) -> SourceLocation:
    return SourceLocation(
        path=path,
        line=getattr(node, "lineno", 1) or 1,
        column=(getattr(node, "col_offset", 0) or 0) + 1,
    )


def _dotted(node: ast.AST | None) -> str | None:
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


def _call_name(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _target_names(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        result: list[str] = []
        for element in node.elts:
            result.extend(_target_names(element))
        return result
    return []


def _subscript_key(node: ast.Subscript) -> str | None:
    value = node.slice
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value
    return None


def _dict_string_keys(node: ast.Dict) -> set[str]:
    result: set[str] = set()
    for key in node.keys:
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            result.add(key.value)
    return result


def _uses_known_framework(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module in _KNOWN_FRAMEWORK_MODULES:
                return True
            if module.startswith(_KNOWN_FRAMEWORK_PREFIXES):
                return True
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in _KNOWN_FRAMEWORK_MODULES:
                    return True
                if alias.name.startswith(_KNOWN_FRAMEWORK_PREFIXES):
                    return True
    return False


def _explicit_agent_aliases(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        module = node.module or ""
        if module not in _EXPLICIT_AGENT_MODULES:
            continue
        for alias in node.names:
            if alias.name == "Agent":
                aliases[alias.asname or alias.name] = module
    return aliases


def _is_model_callable(node: ast.AST | None) -> bool:
    called = (_dotted(node) or _call_name(node) or "").lower()
    leaf = (_call_name(node) or "").lower()
    return any(called.endswith(suffix) for suffix in _MODEL_CALL_SUFFIXES) or leaf in _MODEL_METHODS


def _class_signals(node: ast.ClassDef) -> dict[str, bool]:
    model_call = False
    tool_catalogue = False
    model_selection = False
    tool_dispatch = False
    http_request = False
    model_payload = False

    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            leaf = (_call_name(child.func) or "").lower()
            call_is_model = _is_model_callable(child.func)
            if not call_is_model:
                # Retry/instrumentation helpers often receive a bound model
                # method as a first-class callable (for example
                # retry(self.llm.chat_collect, ..., tools=...)). Treat this as
                # model invocation evidence without weakening the four-signal
                # custom-agent gate.
                call_is_model = any(
                    _is_model_callable(argument)
                    for argument in (
                        list(child.args)
                        + [keyword.value for keyword in child.keywords]
                    )
                )
            if call_is_model:
                model_call = True
            if leaf in {"set_tools", "list_tools"}:
                tool_catalogue = True
            if leaf == "call_tool":
                tool_dispatch = True
            elif leaf in {"execute", "dispatch", "invoke_tool", "run_tool"}:
                receiver = (
                    _dotted(child.func.value)
                    if isinstance(child.func, ast.Attribute)
                    else None
                )
                receiver_lower = (receiver or "").lower()
                receiver_tokens = set(
                    receiver_lower.replace("-", "_").replace(".", "_").split("_")
                )
                if receiver_tokens & {"tool", "tools", "registry"}:
                    tool_dispatch = True
            if leaf in {"post", "request"}:
                http_request = True
            for keyword in child.keywords:
                if keyword.arg == "tools" and call_is_model:
                    tool_catalogue = True

        elif isinstance(child, ast.Attribute):
            if child.attr in {"tool_calls", "function_call"}:
                model_selection = True
            if child.attr in {"tools", "tool_schema", "tool_schemas", "all_tools_schema"}:
                tool_catalogue = True

        elif isinstance(child, ast.Name):
            if child.id == "tool_calls":
                model_selection = True

        elif isinstance(child, ast.Subscript):
            key = _subscript_key(child)
            if key == "tool_calls":
                model_selection = True
            elif key == "tools":
                tool_catalogue = True

        elif isinstance(child, ast.Dict):
            keys = _dict_string_keys(child)
            if "tools" in keys:
                tool_catalogue = True
            if {"tools", "messages"} <= keys:
                model_payload = True

    if http_request and model_payload:
        model_call = True
        tool_catalogue = True

    return {
        "model_call": model_call,
        "tool_catalogue": tool_catalogue,
        "model_selection": model_selection,
        "tool_dispatch": tool_dispatch,
    }


def _mcp_loop_evidence(node: ast.ClassDef) -> dict[str, bool]:
    list_tools = False
    call_tool = False
    stdio_transport = False

    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        leaf = (_call_name(child.func) or "").lower()
        if leaf == "list_tools":
            list_tools = True
        elif leaf == "call_tool":
            call_tool = True
        elif leaf in {"stdioserverparameters", "stdio_client"}:
            stdio_transport = True

    return {
        "list_tools": list_tools,
        "call_tool": call_tool,
        "stdio_transport": stdio_transport,
    }


def _dynamic_stdio_mcp(path: Path, node: ast.ClassDef) -> MCPServer | None:
    evidence = _mcp_loop_evidence(node)
    if not all(evidence.values()):
        return None
    return MCPServer(
        name="<dynamic-stdio-mcp>",
        transport="stdio",
        command="<python-or-node>",
        args=["<caller-selected-script>"],
        authenticated=None,
        location=_location(path, node),
        metadata={
            "framework": "model-tool-loop",
            "binding_origin": "source_proven_dynamic_stdio_selection",
            "dynamic_server_selection": True,
            "tool_catalogue_dynamic": True,
            "repository_resolved": False,
        },
    )


def _snake_name(value: str) -> str:
    if value.lower() == "agent":
        return "agent"
    converted = re.sub(r"(?<!^)(?=[A-Z])", "_", value).lower()
    return converted or value.lower()


def _custom_class_agents(path: Path, tree: ast.AST) -> list[Agent]:
    if _uses_known_framework(tree):
        return []

    agents: list[Agent] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        signals = _class_signals(node)
        mcp_evidence = _mcp_loop_evidence(node)
        class_named_agent = "agent" in node.name.lower()
        source_proven_mcp_loop = (
            mcp_evidence["list_tools"] and mcp_evidence["call_tool"]
        )
        if not class_named_agent and not source_proven_mcp_loop:
            continue
        if not all(signals.values()):
            continue
        name = _snake_name(node.name)
        location = _location(path, node)
        semantic_id = stable_entity_id(
            framework="model-tool-loop",
            kind=SemanticEntityKind.AGENT,
            name=name,
            source_key=path.as_posix(),
            line=location.line,
        )
        agent = Agent(
            name=name,
            location=location,
            metadata={
                "framework": "model-tool-loop",
                "agent_type": "custom_model_tool_loop",
                "discovery_basis": "model_tools_selection_dispatch",
                "discovery_signals": sorted(
                    key for key, present in signals.items() if present
                ),
                "semantic_entity_id": semantic_id,
                "semantic_entity_kind": SemanticEntityKind.AGENT.value,
                "instance_key": f"{path.resolve()}:{location.line}:{node.name}",
                "source_class": node.name,
            },
        )
        dynamic_mcp = _dynamic_stdio_mcp(path, node)
        if dynamic_mcp is not None:
            agent.mcp_servers.append(dynamic_mcp)
            agent.metadata["dynamic_mcp_servers"] = True
        agents.append(agent)
    return agents


def _explicit_constructor_agents(
    path: Path,
    tree: ast.AST,
) -> list[Agent]:
    imported = _explicit_agent_aliases(tree)
    if not imported:
        return []

    agents: list[Agent] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        if not isinstance(value, ast.Call):
            continue
        constructor = _call_name(value.func)
        if constructor not in imported:
            continue
        keywords = {item.arg for item in value.keywords if item.arg}
        if "tools" not in keywords:
            continue
        if not (keywords & {"llm", "model", "client", "model_provider"}):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        names = [name for target in targets for name in _target_names(target)]
        for name in names:
            location = _location(path, value)
            semantic_id = stable_entity_id(
                framework="model-tool-loop",
                kind=SemanticEntityKind.AGENT,
                name=name,
                source_key=path.as_posix(),
                line=location.line,
            )
            agents.append(
                Agent(
                    name=name,
                    location=location,
                    metadata={
                        "framework": "model-tool-loop",
                        "agent_type": f"{imported[constructor]}.Agent",
                        "discovery_basis": "explicit_tool_bound_agent_constructor",
                        "semantic_entity_id": semantic_id,
                        "semantic_entity_kind": SemanticEntityKind.AGENT.value,
                        "instance_key": f"{path.resolve()}:{location.line}:{name}",
                    },
                )
            )
    return agents


def _scan_tree(path: Path, tree: ast.AST) -> Graph:
    graph = Graph()
    graph.agents.extend(_custom_class_agents(path, tree))
    graph.agents.extend(_explicit_constructor_agents(path, tree))
    return graph


def is_model_tool_loop_file(path: Path) -> bool:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return False
    return bool(_scan_tree(path, tree).agents)


def scan_python_file(path: Path) -> Graph:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return Graph()
    return _scan_tree(path, tree)
