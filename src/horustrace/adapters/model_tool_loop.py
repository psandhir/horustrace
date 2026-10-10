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


def _dict_entries(node: ast.AST | None) -> dict[str, ast.AST]:
    if not isinstance(node, ast.Dict):
        return {}
    result: dict[str, ast.AST] = {}
    for key, value in zip(node.keys, node.values):
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            result[key.value] = value
    return result


def _literal_string(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _static_command(node: ast.AST | None) -> str | None:
    literal = _literal_string(node)
    if literal is not None:
        return literal
    if _dotted(node) == "sys.executable":
        return "<python-executable>"
    return None


def _static_python_script(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    literal = _literal_string(node)
    if literal is not None and literal.endswith(".py"):
        return literal
    for child in ast.walk(node):
        value = _literal_string(child)
        if value is not None and value.endswith(".py"):
            return value
    return None


def _static_args(node: ast.AST | None) -> list[str]:
    if not isinstance(node, (ast.List, ast.Tuple)):
        return []
    result: list[str] = []
    for item in node.elts:
        literal = _literal_string(item)
        if literal is not None:
            result.append(literal)
            continue
        script = _static_python_script(item)
        if script is not None:
            result.append(script)
    return result


def _source_proven_default_mcp_servers(
    path: Path,
    tree: ast.AST,
    class_node: ast.ClassDef,
) -> list[MCPServer]:
    """Return statically named local MCP servers from a called fallback config.

    This intentionally recognizes only repository-local stdio defaults with a
    concrete Python script. It does not guess external config files or bind
    arbitrary repository MCP declarations merely because they coexist.
    """
    called = {
        _call_name(child.func)
        for child in ast.walk(class_node)
        if isinstance(child, ast.Call)
    }
    result: list[MCPServer] = []
    for function in tree.body:
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if function.name not in called:
            continue
        for child in ast.walk(function):
            if not isinstance(child, ast.Return):
                continue
            root_entries = _dict_entries(child.value)
            servers_node = root_entries.get("mcpServers") or root_entries.get("servers")
            for server_name, server_node in _dict_entries(servers_node).items():
                entries = _dict_entries(server_node)
                if not entries:
                    continue
                enabled = entries.get("enabled")
                if isinstance(enabled, ast.Constant) and enabled.value is False:
                    continue
                if "enabled_env" in entries:
                    continue
                command = _static_command(entries.get("command"))
                args = _static_args(entries.get("args"))
                transport = _literal_string(entries.get("transport")) or (
                    "stdio" if command is not None else "unknown"
                )
                if transport != "stdio":
                    continue
                if not any(arg.endswith(".py") for arg in args):
                    continue
                result.append(
                    MCPServer(
                        name=server_name,
                        transport="stdio",
                        command=command,
                        args=args,
                        authenticated=None,
                        location=_location(path, child),
                        metadata={
                            "framework": "model-tool-loop",
                            "source": "inline_default_mcp_config",
                            "binding_origin": "source_proven_default_mcp_config",
                            "config_function": function.name,
                            "default_configuration": True,
                            "tool_catalogue_dynamic": True,
                            "repository_resolved": False,
                        },
                    )
                )
    return result


def _is_function_call_discriminator(node: ast.Compare) -> bool:
    if len(node.ops) != 1 or len(node.comparators) != 1:
        return False
    left = node.left
    right = node.comparators[0]

    def _type_field(value: ast.AST) -> bool:
        if isinstance(value, ast.Attribute):
            return value.attr == "type"
        if isinstance(value, ast.Subscript):
            key = _subscript_key(value)
            return key == "type"
        return False

    def _function_call_literal(value: ast.AST) -> bool:
        return isinstance(value, ast.Constant) and value.value == "function_call"

    return (
        _type_field(left) and _function_call_literal(right)
    ) or (
        _type_field(right) and _function_call_literal(left)
    )


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

        elif isinstance(child, ast.Compare):
            if _is_function_call_discriminator(child):
                model_selection = True

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



def _dynamic_sse_mcp(path: Path, node: ast.ClassDef) -> MCPServer | None:
    """Bind a source-visible SSE ClientSession to the custom model/tool loop.

    The endpoint and tool catalogue may both be selected at runtime. Only
    the session relationship is claimed: individual operations, permissions,
    authentication and the chosen host are not inferred.
    """
    calls = [child for child in ast.walk(node) if isinstance(child, ast.Call)]
    session_catalogues = {
        _dotted(call.func.value)
        for call in calls
        if isinstance(call.func, ast.Attribute) and call.func.attr == "list_tools"
    }
    session_dispatches = {
        _dotted(call.func.value)
        for call in calls
        if isinstance(call.func, ast.Attribute) and call.func.attr == "call_tool"
    }
    shared_sessions = {
        receiver
        for receiver in session_catalogues & session_dispatches
        if receiver and receiver.startswith("self.")
    }
    if not shared_sessions:
        return None

    # Reconstruct the concrete class attribute holding the ClientSession.
    # Presence of ClientSession and an unrelated call_tool() is not enough.
    assignments = [
        child for child in ast.walk(node)
        if isinstance(child, (ast.Assign, ast.AnnAssign))
        and child.value is not None
    ]
    session_contexts: set[str] = set()
    session_receivers: set[str] = set()
    for assignment in assignments:
        value = assignment.value
        targets = (
            assignment.targets if isinstance(assignment, ast.Assign)
            else [assignment.target]
        )
        names = {
            dotted for target in targets
            if (dotted := _dotted(target)) and dotted.startswith("self.")
        }
        if isinstance(value, ast.Call) and _call_name(value.func) == "ClientSession":
            session_contexts.update(names)
            session_receivers.update(names)
    for assignment in assignments:
        value = assignment.value
        if isinstance(value, ast.Await):
            value = value.value
        if not isinstance(value, ast.Call) or not isinstance(value.func, ast.Attribute):
            continue
        if (
            value.func.attr != "__aenter__"
            or _dotted(value.func.value) not in session_contexts
        ):
            continue
        targets = (
            assignment.targets if isinstance(assignment, ast.Assign)
            else [assignment.target]
        )
        session_receivers.update(
            dotted for target in targets
            if (dotted := _dotted(target)) and dotted.startswith("self.")
        )
    shared_sessions &= session_receivers
    if not shared_sessions:
        return None

    sse_calls = [
        call for call in calls
        if _call_name(call.func) == "sse_client"
    ]
    if not sse_calls:
        return None
    if not any(
        _is_model_callable(call.func)
        and any(keyword.arg == "tools" for keyword in call.keywords)
        for call in calls
    ):
        return None

    # A literal URL is source-declared. A function parameter/expression is
    # caller-configurable, NOT necessarily selected by the model.
    sse_call = sse_calls[0]
    url_expression = next(
        (keyword.value for keyword in sse_call.keywords if keyword.arg == "url"),
        sse_call.args[0] if sse_call.args else None,
    )
    literal_url = _literal_string(url_expression)
    dynamic = literal_url is None
    return MCPServer(
        name="<dynamic-sse-mcp>" if dynamic else "<source-sse-mcp>",
        transport="sse",
        url=literal_url,
        authenticated=None,
        location=_location(path, sse_call),
        metadata={
            "framework": "model-tool-loop",
            "binding_origin": "source_proven_mcp_session_loop",
            "session_receivers": sorted(shared_sessions),
            "dynamic_mcp_endpoint": dynamic,
            "dynamic_mcp_endpoint_basis": (
                "caller_configuration" if dynamic else "source_literal"
            ),
            "endpoint_selection_actor": "caller_or_operator" if dynamic else "source",
            "tool_catalogue_dynamic": True,
            "repository_resolved": False,
            "runtime_enforcement_verified": False,
        },
    )


def _snake_name(value: str) -> str:
    if value.lower() == "agent":
        return "agent"
    converted = re.sub(r"(?<!^)(?=[A-Z])", "_", value).lower()
    return converted or value.lower()



def _delegated_orchestration_evidence(node: ast.ClassDef) -> list[str]:
    """Recognize source-proven planner/skill or planner/MCP execution loops.

    Some custom agents delegate model calls to an injected Planner or to helper
    modules. Do not require an inline llm.chat() call in the orchestrator class;
    instead require both planning and a concrete tool or skill dispatch.
    """
    calls = {
        (_dotted(child.func) or _call_name(child.func) or "").lower()
        for child in ast.walk(node) if isinstance(child, ast.Call)
    }
    planner = any(
        call.endswith((".planner.plan", ".planner.run"))
        or call == "decide_next_action"
        for call in calls
    )
    skill_dispatch = any(
        call.endswith(("_skill.run", ".skills.run"))
        for call in calls
    )
    mcp_dispatch = any(
        call.endswith((".mcp.call_tool", ".dispatcher.call_tool"))
        for call in calls
    )
    if planner and skill_dispatch:
        return ["delegated_planner", "skill_dispatch"]
    if planner and mcp_dispatch:
        return ["delegated_planner", "mcp_dispatch"]
    return []


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
        delegated_signals = (
            _delegated_orchestration_evidence(node) if class_named_agent else []
        )
        if not all(signals.values()) and not delegated_signals:
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
                "discovery_basis": (
                    "source_proven_delegated_orchestration"
                    if delegated_signals and not all(signals.values())
                    else "model_tools_selection_dispatch"
                ),
                "discovery_signals": (
                    delegated_signals if delegated_signals and not all(signals.values())
                    else sorted(key for key, present in signals.items() if present)
                ),
                "semantic_entity_id": semantic_id,
                "semantic_entity_kind": SemanticEntityKind.AGENT.value,
                "instance_key": f"{path.resolve()}:{location.line}:{node.name}",
                "source_class": node.name,
            },
        )
        default_servers = _source_proven_default_mcp_servers(path, tree, node)
        if default_servers:
            agent.mcp_servers.extend(default_servers)
            agent.metadata["default_mcp_servers"] = [
                server.name for server in default_servers
            ]
        else:
            dynamic_mcp = _dynamic_stdio_mcp(path, node)
            if dynamic_mcp is None:
                dynamic_mcp = _dynamic_sse_mcp(path, node)
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
