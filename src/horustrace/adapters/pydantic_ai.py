"""Static Pydantic AI adapter for HorusTrace.

The adapter parses Pydantic AI and Pydantic AI Harness configuration without
importing or executing the target. Security-relevant constructs are normalized
into HorusTrace's framework-neutral Agent, Tool, MCPServer and capability model.
"""
from __future__ import annotations

import ast
from copy import deepcopy
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from horustrace.coverage import add_diagnostic
from horustrace.effect_semantics import (
    http_mutation_capabilities,
    is_local_collection_mutation,
    sql_call_capabilities,
)
from horustrace.heuristics import infer_capabilities
from horustrace.models import (
    Agent,
    Graph,
    InputSource,
    MCPServer,
    NetworkDestination,
    ResourceScope,
    ScanDiagnostic,
    SourceLocation,
    Tool,
)

_PYDANTIC_PREFIXES = ("pydantic_ai", "pydantic_ai_harness")
_AGENT_RUN_METHODS = {
    "run",
    "run_sync",
    "run_stream",
    "run_stream_sync",
    "run_stream_events",
    "iter",
}

# Known abstractions that dereference caller-supplied URLs server-side. Keep
# this allowlisted rather than treating arbitrary constructors as network sinks.
_URL_LOADER_CONSTRUCTORS = {
    "webbaseloader",
    "asynchtmlloader",
    "unstructuredurlloader",
    "seleniumurlloader",
}

_CAPABILITY_TOOLS: dict[str, tuple[str, set[str]]] = {
    "FileSystem": ("filesystem", {"data.read", "data.write"}),
    "Shell": (
        "shell",
        {"process.execute", "data.read", "data.write", "network.external"},
    ),
    "ModalSandbox": (
        "sandbox",
        {"process.execute", "data.read", "data.write", "network.external"},
    ),
    "WebSearch": ("web_search", {"data.read", "network.external"}),
    "WebFetch": ("web_fetch", {"data.read", "network.external"}),
    "XSearch": ("x_search", {"data.read", "network.external"}),
    "BrowserUse": (
        "browser",
        {"computer.control", "data.read", "data.write", "external.write", "network.external"},
    ),
    "PlaywrightBrowser": (
        "browser",
        {"computer.control", "data.read", "data.write", "external.write", "network.external"},
    ),
    "ImageGeneration": ("image_generation", {"external.write", "network.external"}),
    "SubAgents": ("delegated_agent", {"agent.delegate"}),
    "Subagents": ("delegated_agent", {"agent.delegate"}),
    "Advisor": ("delegated_agent", {"agent.delegate", "network.external"}),
    "Researcher": ("researcher", {"data.read", "network.external", "agent.delegate"}),
    "Coder": (
        "coder",
        {
            "process.execute",
            "data.read",
            "data.write",
            "network.external",
            "agent.delegate",
        },
    ),
}

_NATIVE_TOOL_CAPABILITIES: dict[str, tuple[str, set[str]]] = {
    "WebSearchTool": ("web_search", {"data.read", "network.external"}),
    "XSearchTool": ("x_search", {"data.read", "network.external"}),
    "WebFetchTool": ("web_fetch", {"data.read", "network.external"}),
    "CodeExecutionTool": (
        "code_execution",
        {"process.execute", "data.read", "data.write"},
    ),
    "ImageGenerationTool": ("image_generation", {"external.write", "network.external"}),
    "MemoryTool": ("memory", {"data.read", "data.write"}),
    "FileSearchTool": ("file_search", {"data.read"}),
    "AdvisorTool": ("delegated_agent", {"agent.delegate", "network.external"}),
}

# Pydantic AI can bind third-party LangChain tools through
# pydantic_ai.ext.langchain.tool_from_langchain(). Preserve authority only for
# concrete wrapped tool classes whose execution semantics are known.
_LANGCHAIN_WRAPPED_TOOL_CAPABILITIES: dict[str, tuple[str, set[str]]] = {
    "PythonREPLTool": ("langchain_python_repl", {"process.execute"}),
    "PythonAstREPLTool": ("langchain_python_repl", {"process.execute"}),
}



_CONTROL_CAPABILITIES = {
    "Guardrails",
    "PromptInjectionDefender",
    "SpendLimits",
    "ToolOutputLimits",
    "ClearToolResults",
    "WarnNearLimits",
    "RepairToolArguments",
    "RepoContext",
    "HandleDeferredToolCalls",
    "IncludeToolReturnSchemas",
    "SetToolMetadata",
    "ProcessHistory",
}


def _location(path: Path, node: ast.AST) -> SourceLocation:
    return SourceLocation(
        path=path,
        line=getattr(node, "lineno", 1) or 1,
        column=(getattr(node, "col_offset", 0) or 0) + 1,
    )


def _call_name(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Subscript):
        return _call_name(node.value)
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _dotted(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Subscript):
        return _dotted(node.value)
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
    except (TypeError, ValueError):
        return None


def _kw(call: ast.Call, name: str) -> ast.AST | None:
    return next((item.value for item in call.keywords if item.arg == name), None)


def _mapping_key_value_before(
    scope: ast.AST,
    mapping_name: str,
    key: str,
    before_line: int,
) -> ast.AST | None:
    """Resolve a literal mapping key populated before a call in the same scope."""
    candidates: list[tuple[int, ast.AST]] = []
    for node in ast.walk(scope):
        line = getattr(node, "lineno", 0) or 0
        if line <= 0 or line >= before_line:
            continue
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name) and target.id == mapping_name:
                    if isinstance(node.value, ast.Dict):
                        for map_key, map_value in zip(node.value.keys, node.value.values):
                            if _literal(map_key) == key:
                                candidates.append((line, map_value))
                elif (
                    isinstance(target, ast.Subscript)
                    and isinstance(target.value, ast.Name)
                    and target.value.id == mapping_name
                    and _literal(target.slice) == key
                ):
                    candidates.append((line, node.value))
    return max(candidates, key=lambda item: item[0])[1] if candidates else None


def _agent_kw(
    call: ast.Call,
    name: str,
    tree: ast.AST,
    assignments: dict[str, ast.AST],
) -> ast.AST | None:
    """Resolve direct Agent kwargs plus source-visible expanded kwargs construction."""
    direct = _kw(call, name)
    if direct is not None:
        return direct

    scope: ast.AST = _enclosing_function_node(tree, call) or tree
    before_line = getattr(call, "lineno", 0) or 0
    for keyword in call.keywords:
        if keyword.arg is not None or not isinstance(keyword.value, ast.Name):
            continue
        value = _mapping_key_value_before(
            scope,
            keyword.value.id,
            name,
            before_line,
        )
        if value is not None:
            return value
        assigned = assignments.get(keyword.value.id)
        if isinstance(assigned, ast.Dict):
            for map_key, map_value in zip(assigned.keys, assigned.values):
                if _literal(map_key) == name:
                    return map_value
    return None


def _dynamic_authority_tool(
    path: Path,
    node: ast.AST,
    alias: str,
    dimension: str,
) -> Tool:
    return Tool(
        name=f"dynamic-{dimension}:{alias}",
        kind=f"pydantic_dynamic_{dimension}",
        capabilities=set(),
        location=_location(path, node),
        metadata={
            "framework": "pydantic-ai",
            "binding_origin": f"Agent.{dimension}",
            "dynamic_authority": True,
            "tool_catalogue_unresolved": True,
            "authority_dimension": dimension,
        },
    )


def _target_names(node: ast.Assign | ast.AnnAssign | ast.AST) -> list[str]:
    if isinstance(node, ast.Assign):
        targets = node.targets
    elif isinstance(node, ast.AnnAssign):
        targets = [node.target]
    else:
        targets = [node]
    names: list[str] = []
    for target in targets:
        if isinstance(target, ast.Name):
            names.append(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                names.extend(_target_names(element))
        elif isinstance(target, ast.Attribute):
            dotted = _dotted(target)
            if dotted:
                names.append(dotted)
    return names


def _uses_pydantic_ai(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module.startswith(_PYDANTIC_PREFIXES):
                return True
        elif isinstance(node, ast.Import):
            if any(alias.name.startswith(_PYDANTIC_PREFIXES) for alias in node.names):
                return True
    return False


def is_pydantic_ai_file(path: Path) -> bool:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return False
    return _uses_pydantic_ai(tree)


def _function_capabilities(node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    capabilities = set(infer_capabilities(node.name))
    # Function names remain discovery hints, but host execution/network authority
    # still require concrete source sinks. Ambiguous mutation verbs are handled
    # after body inspection so pure helpers such as add(a, b) do not become writes.
    capabilities.difference_update(
        {"process.execute", "network.external", "external.write"}
    )
    body_write_evidence = False
    smtp_receivers: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, (ast.Assign, ast.AnnAssign)) and child.value is not None:
            targets = child.targets if isinstance(child, ast.Assign) else [child.target]
            if (
                isinstance(child.value, ast.Call)
                and (_dotted(child.value.func) or "").lower()
                in {"smtplib.smtp", "smtplib.smtp_ssl"}
            ):
                smtp_receivers.update(
                    target.id for target in targets if isinstance(target, ast.Name)
                )
        elif isinstance(child, (ast.With, ast.AsyncWith)):
            for item in child.items:
                if (
                    isinstance(item.context_expr, ast.Call)
                    and (_dotted(item.context_expr.func) or "").lower()
                    in {"smtplib.smtp", "smtplib.smtp_ssl"}
                    and isinstance(item.optional_vars, ast.Name)
                ):
                    smtp_receivers.add(item.optional_vars.id)

    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        dotted = (_dotted(child.func) or _call_name(child.func) or "").lower()
        leaf = (
            _call_name(child.func)
            or (dotted.rsplit(".", 1)[-1] if dotted else "")
        ).lower()

        sql_capabilities = sql_call_capabilities(child)
        if sql_capabilities:
            capabilities.update(sql_capabilities)
            if "data.write" in sql_capabilities:
                body_write_evidence = True

        if (
            dotted in {
                "exec",
                "eval",
                "compile",
                "builtins.exec",
                "builtins.eval",
                "builtins.compile",
            }
            or dotted in {"os.system", "os.popen"}
            or dotted.startswith("subprocess.")
            or "create_subprocess_" in dotted
        ):
            capabilities.add("process.execute")
        if (
            dotted.startswith(("requests.", "httpx.", "aiohttp."))
            or "urllib" in dotted
        ):
            capabilities.add("network.external")
            http_mutation = http_mutation_capabilities(
                child,
                function_name=node.name,
            )
            capabilities.update(http_mutation)
            if "data.write" in http_mutation:
                body_write_evidence = True
        local_collection_mutation = is_local_collection_mutation(child)
        if leaf in {
            "write",
            "update",
            "save",
            "insert",
            "create",
            "put",
            "edit",
            "patch",
        } and not local_collection_mutation:
            body_write_evidence = True
            capabilities.add("data.write")
        if leaf in {
            "delete",
            "remove",
            "unlink",
            "rmdir",
            "rmtree",
            "drop",
            "purge",
        } and not local_collection_mutation:
            body_write_evidence = True
            capabilities.update({"data.write", "destructive.write"})
        if leaf in {"read", "get", "search", "retrieve", "fetch", "query", "list"}:
            capabilities.add("data.read")
        if (
            "secretmanager" in dotted
            or "vault" in dotted
            or leaf in {"get_secret", "access_secret_version"}
        ):
            capabilities.add("secrets.read")
        if (
            leaf in {"send_message", "sendmail"}
            and isinstance(child.func, ast.Attribute)
            and isinstance(child.func.value, ast.Name)
            and child.func.value.id in smtp_receivers
        ):
            capabilities.update({"external.write", "network.external"})
            body_write_evidence = True

    first_token = node.name.lower().replace("-", "_").split("_", 1)[0]
    if first_token in {"add", "set", "update"} and not body_write_evidence:
        capabilities.difference_update(
            {"data.write", "destructive.write", "external.write"}
        )

    return capabilities

def _mandatory_authorization_gate(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    """Detect source-visible mandatory authorization or runtime-policy gates."""
    gate_methods = {
        "require",
        "arequire",
        "authorize",
        "authorize_async",
        "require_permission",
        "check_permission",
        "check_command_permissions",
    }
    gate_markers = (
        ".gate.",
        ".policy.",
        ".authz.",
        ".authorization.",
        ".permissions.",
    )
    semantic_markers = (
        "allow",
        "allowed",
        "permission",
        "authorize",
        "authz",
        "policy",
        "enabled",
    )

    def is_gate_call(call: ast.Call) -> bool:
        called = (_dotted(call.func) or _call_name(call.func) or "").lower()
        leaf = (_call_name(call.func) or "").lower()
        if leaf in gate_methods and any(marker in called for marker in gate_markers):
            return True
        return any(marker in leaf for marker in semantic_markers)

    gate_variables: set[str] = set()
    for child in ast.walk(node):
        if not isinstance(child, (ast.Assign, ast.AnnAssign)):
            continue
        value = child.value
        if not isinstance(value, (ast.Call, ast.Await)):
            continue
        call = value.value if isinstance(value, ast.Await) else value
        if not isinstance(call, ast.Call) or not is_gate_call(call):
            continue
        for name in _target_names(child):
            gate_variables.add(name)

    def expression_is_gate(expr: ast.AST) -> bool:
        for part in ast.walk(expr):
            if isinstance(part, ast.Call) and is_gate_call(part):
                return True
            if isinstance(part, ast.Name) and part.id in gate_variables:
                return True
            if isinstance(part, ast.Attribute):
                dotted = (_dotted(part) or "").lower()
                leaf = part.attr.lower()
                if any(marker in leaf for marker in semantic_markers):
                    return True
                if any(marker in dotted for marker in gate_markers):
                    return True
        return False

    for child in ast.walk(node):
        if isinstance(child, ast.Call) and is_gate_call(child):
            called = (_dotted(child.func) or _call_name(child.func) or "").lower()
            leaf = (_call_name(child.func) or "").lower()
            if leaf in gate_methods and any(marker in called for marker in gate_markers):
                return True

        if not isinstance(child, ast.If):
            continue
        if not any(
            isinstance(part, ast.UnaryOp)
            and isinstance(part.op, ast.Not)
            and expression_is_gate(part.operand)
            for part in ast.walk(child.test)
        ):
            continue
        if any(
            isinstance(exit_node, (ast.Return, ast.Raise))
            for statement in child.body
            for exit_node in ast.walk(statement)
        ):
            return True
    return False


def _restricted_in_process_eval(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Identify eval-only execution where Python builtins are explicitly disabled."""
    saw_eval = False
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        dotted = (_dotted(child.func) or _call_name(child.func) or "").lower()
        if dotted in {"eval", "builtins.eval"}:
            saw_eval = True
            globals_arg = child.args[1] if len(child.args) > 1 else _kw(child, "globals")
            if not isinstance(globals_arg, ast.Dict):
                return False
            builtins_locked = any(
                isinstance(key, ast.Constant)
                and key.value == "__builtins__"
                and (
                    isinstance(value, ast.Dict)
                    and not value.keys
                    or isinstance(value, ast.Constant)
                    and value.value is None
                )
                for key, value in zip(globals_arg.keys, globals_arg.values)
            )
            if not builtins_locked:
                return False
            continue
        if (
            dotted in {"exec", "compile", "builtins.exec", "builtins.compile", "os.system", "os.popen"}
            or dotted.startswith("subprocess.")
            or "create_subprocess_" in dotted
        ):
            return False
    return saw_eval


def _expr_uses_names(node: ast.AST | None, names: set[str]) -> bool:
    if node is None or not names:
        return False
    return any(
        isinstance(child, ast.Name) and child.id in names
        for child in ast.walk(node)
    )


def _function_http_url_semantics(
    path: Path,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[list[NetworkDestination], dict[str, Any]]:
    """Find model-selected URL parameters passed to direct server-side HTTP clients."""
    params = {
        arg.arg
        for arg in [
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
        ]
    }
    if not params:
        return [], {}

    tainted = set(params)
    taint_origins: dict[str, set[str]] = {
        parameter: {parameter}
        for parameter in params
    }

    def _origins(expr: ast.AST | None) -> set[str]:
        if expr is None:
            return set()
        result: set[str] = set()
        for child in ast.walk(expr):
            if isinstance(child, ast.Name):
                result.update(taint_origins.get(child.id, set()))
        return result

    assignments = [
        child
        for child in ast.walk(node)
        if isinstance(child, (ast.Assign, ast.AnnAssign))
        and child.value is not None
    ]
    loops = [
        child
        for child in ast.walk(node)
        if isinstance(child, (ast.For, ast.AsyncFor))
    ]
    for _ in range(8):
        changed = False
        for assignment in assignments:
            origins = _origins(assignment.value)
            if not origins:
                continue
            for name in _target_names(assignment):
                previous = set(taint_origins.get(name, set()))
                combined = previous | origins
                if combined != previous:
                    taint_origins[name] = combined
                    tainted.add(name)
                    changed = True
        for loop in loops:
            origins = _origins(loop.iter)
            if not origins:
                continue
            for name in _target_names(loop.target):
                previous = set(taint_origins.get(name, set()))
                combined = previous | origins
                if combined != previous:
                    taint_origins[name] = combined
                    tainted.add(name)
                    changed = True
        if not changed:
            break

    http_clients: dict[str, bool] = {}

    def client_constructor(call: ast.Call) -> tuple[bool, bool]:
        called = (_dotted(call.func) or _call_name(call.func) or "").lower()
        is_client = (
            called in {
                "httpx.client",
                "httpx.asyncclient",
                "requests.session",
                "aiohttp.clientsession",
            }
            or called.endswith((".httpx.client", ".httpx.asyncclient"))
        )
        follow = _literal(_kw(call, "follow_redirects")) is True
        return is_client, follow

    for child in ast.walk(node):
        if isinstance(child, (ast.With, ast.AsyncWith)):
            for item in child.items:
                if not isinstance(item.context_expr, ast.Call):
                    continue
                is_client, follow = client_constructor(item.context_expr)
                if is_client and isinstance(item.optional_vars, ast.Name):
                    http_clients[item.optional_vars.id] = follow
        elif isinstance(child, (ast.Assign, ast.AnnAssign)) and isinstance(
            child.value, ast.Call
        ):
            is_client, follow = client_constructor(child.value)
            if is_client:
                for name in _target_names(child):
                    http_clients[name] = follow

    destinations: list[NetworkDestination] = []
    parameters: set[str] = set()
    follows_redirects = False
    seen_lines: set[int] = set()

    for call in (child for child in ast.walk(node) if isinstance(child, ast.Call)):
        called = (_dotted(call.func) or _call_name(call.func) or "").lower()
        leaf = (_call_name(call.func) or "").lower()
        receiver = (
            _dotted(call.func.value)
            if isinstance(call.func, ast.Attribute)
            else None
        )
        receiver_root = (receiver or "").split(".", 1)[0]

        direct_http = (
            called.startswith(("requests.", "httpx.", "aiohttp."))
            or "urllib.request" in called
        )
        client_http = (
            receiver_root in http_clients
            and leaf in {"get", "post", "put", "patch", "delete", "request", "head"}
        )
        url_loader = leaf in _URL_LOADER_CONSTRUCTORS
        if not (direct_http or client_http or url_loader):
            continue

        target: ast.AST | None
        if url_loader:
            target = call.args[0] if call.args else next(
                (
                    keyword.value
                    for keyword in call.keywords
                    if keyword.arg in {"url", "urls", "web_path", "web_paths"}
                ),
                None,
            )
        elif leaf == "request" and len(call.args) > 1:
            target = call.args[1]
        else:
            target = call.args[0] if call.args else _kw(call, "url")
        if target is None or not _expr_uses_names(target, tainted):
            continue

        selected: set[str] = set()
        for child in ast.walk(target):
            if isinstance(child, ast.Name):
                selected.update(taint_origins.get(child.id, set()))
        parameters.update(selected)
        follows_redirects = follows_redirects or http_clients.get(
            receiver_root, False
        )
        line = getattr(call, "lineno", 1)
        if line in seen_lines:
            continue
        seen_lines.add(line)
        destinations.append(
            NetworkDestination(
                target="<dynamic-url>",
                restricted=False,
                location=_location(path, call),
                metadata={
                    "source": "model_selected_url_argument",
                    "network_scope": "dynamic_destination",
                    "server_side_fetch": True,
                    "network_sink": called,
                    "network_abstraction": "url_loader" if url_loader else "http_client",
                    "follow_redirects": http_clients.get(receiver_root, False),
                },
            )
        )

    if not destinations:
        return [], {}
    return destinations, {
        "model_selected_url_fetch": True,
        "model_selected_url_parameters": sorted(parameters),
        "server_side_fetch": True,
        "follow_redirects": follows_redirects,
        "network_scope": "dynamic_destination",
    }


def _function_search_result_url_semantics(
    path: Path,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> tuple[list[NetworkDestination], dict[str, Any]]:
    """Find model-influenced provider-search result URLs passed to HTTP fetch helpers.

    This is deliberately weaker than direct model-selected URL authority.  The
    model controls a search query/angle, a provider returns URLs, and repository
    source then dereferences those URLs through a helper that performs direct HTTP.
    """
    params = {
        arg.arg
        for arg in [
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
        ]
    }
    if not params:
        return [], {}

    direct_fetch_helpers = {
        name
        for name, function in functions.items()
        if _function_http_url_semantics(path, function)[0]
    }
    if not direct_fetch_helpers:
        return [], {}

    provider_search_helpers: set[str] = set()
    for name, function in functions.items():
        lower_name = name.lower()
        provider_call = False
        result_url_field = False
        for child in ast.walk(function):
            if isinstance(child, ast.Call):
                called = (_dotted(child.func) or _call_name(child.func) or "").lower()
                leaf = (_call_name(child.func) or "").lower()
                if (
                    "duckduckgo" in called
                    or "ddgs" in called
                    or "tavily" in called
                    or (
                        ("search" in lower_name or "search" in called)
                        and leaf in {"search", "text", "results"}
                    )
                ):
                    provider_call = True
            if (
                isinstance(child, ast.Constant)
                and isinstance(child.value, str)
                and child.value.lower() in {"url", "href", "link"}
            ):
                result_url_field = True
        if provider_call and result_url_field:
            provider_search_helpers.add(name)

    if not provider_search_helpers:
        return [], {}

    tainted = set(params)
    assignments = [
        child
        for child in ast.walk(node)
        if isinstance(child, (ast.Assign, ast.AnnAssign))
        and child.value is not None
    ]
    for _ in range(8):
        changed = False
        for assignment in assignments:
            if not _expr_uses_names(assignment.value, tainted):
                continue
            for name in _target_names(assignment):
                if name not in tainted:
                    tainted.add(name)
                    changed = True
        if not changed:
            break

    search_collections: set[str] = set()
    search_helper: str | None = None
    for assignment in assignments:
        value = assignment.value
        if not isinstance(value, ast.Call):
            continue
        called = _call_name(value.func)
        if called not in provider_search_helpers:
            continue
        if value.args and not any(_expr_uses_names(arg, tainted) for arg in value.args):
            continue
        if not value.args and not any(
            _expr_uses_names(keyword.value, tainted)
            for keyword in value.keywords
        ):
            continue
        search_collections.update(_target_names(assignment))
        search_helper = called

    if not search_collections:
        return [], {}

    result_items: set[str] = set()
    for child in ast.walk(node):
        if not isinstance(child, ast.For):
            continue
        if not _expr_uses_names(child.iter, search_collections):
            continue
        result_items.update(_target_names(child.target))

    if not result_items:
        return [], {}

    def _is_result_url_expr(expr: ast.AST | None) -> bool:
        if expr is None:
            return False
        for child in ast.walk(expr):
            if isinstance(child, ast.Subscript):
                root = child.value
                key = _literal(child.slice)
                if (
                    isinstance(root, ast.Name)
                    and root.id in result_items
                    and isinstance(key, str)
                    and key.lower() in {"url", "href", "link"}
                ):
                    return True
            if (
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Attribute)
                and child.func.attr == "get"
                and isinstance(child.func.value, ast.Name)
                and child.func.value.id in result_items
                and child.args
            ):
                key = _literal(child.args[0])
                if isinstance(key, str) and key.lower() in {"url", "href", "link"}:
                    return True
        return False

    fetch_helper: str | None = None
    fetch_call: ast.Call | None = None
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        called = _call_name(child.func)
        if called not in direct_fetch_helpers:
            continue
        target = child.args[0] if child.args else _kw(child, "url")
        if _is_result_url_expr(target):
            fetch_helper = called
            fetch_call = child
            break

    if fetch_call is None:
        return [], {}

    return [
        NetworkDestination(
            target="<search-result-url>",
            restricted=False,
            location=_location(path, fetch_call),
            metadata={
                "source": "search_result_url",
                "network_scope": "search_result_derived_destination",
                "server_side_fetch": True,
                "indirect_destination": True,
            },
        )
    ], {
        "search_result_url_fetch": True,
        "model_influenced_search_query": True,
        "network_scope": "search_result_derived_destination",
        "destination_provenance": "provider_search_result",
        "search_helper": search_helper,
        "fetch_helper": fetch_helper,
    }


def _contains_conditional_approval(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for child in ast.walk(node):
        if not isinstance(child, ast.Raise) or child.exc is None:
            continue
        exc = child.exc.func if isinstance(child.exc, ast.Call) else child.exc
        if _call_name(exc) == "ApprovalRequired":
            return True
    return False


def _tool_from_function(
    path: Path,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    approval: bool | None = None,
    source: str = "function",
) -> Tool:
    capabilities = _function_capabilities(node)
    dynamic_destinations, http_metadata = _function_http_url_semantics(path, node)
    if dynamic_destinations:
        capabilities.add("network.external")

    authorization_gate = _mandatory_authorization_gate(node)
    tool = Tool(
        name=node.name,
        kind="function",
        capabilities=capabilities,
        approval=approval,
        guardrails=authorization_gate,
        destinations=dynamic_destinations,
        location=_location(path, node),
        metadata={
            "framework": "pydantic-ai",
            "source": source,
            **(
                {
                    "guardrail_mechanism": "mandatory_authorization_gate",
                    "authorization_gate": True,
                }
                if authorization_gate
                else {}
            ),
            **http_metadata,
        },
    )
    if _contains_conditional_approval(node):
        tool.metadata["conditional_approval"] = True
    if "process.execute" in capabilities and _restricted_in_process_eval(node):
        tool.metadata.update(
            {
                "process_execution_constrained": True,
                "process_execution_scope": "restricted_in_process_eval",
                "host_process_execution": False,
                "control_basis": "eval_builtins_disabled",
            }
        )

    calls = [child for child in ast.walk(node) if isinstance(child, ast.Call)]
    scoped_path_control = any(
        _call_name(child.func) == "_validate_agent_scoped_path"
        for child in calls
    )
    if scoped_path_control:
        access = capabilities & {"data.read", "data.write", "destructive.write"}
        tool.resources.append(
            ResourceScope(
                kind="file",
                selector=".shotgun/**",
                access=set(access),
                location=_location(path, node),
            )
        )
        tool.guardrails = True
        tool.metadata.update(
            {
                "filesystem_path_constrained": True,
                "filesystem_scope": ".shotgun/**",
                "agent_internal_artifact": True,
                "control_basis": "agent_scoped_path_validation",
            }
        )

    allowlist_check = any(
        isinstance(child, ast.Compare)
        and any(isinstance(op, (ast.In, ast.NotIn)) for op in child.ops)
        and any(
            isinstance(part, ast.Name) and part.id == "ALLOWED_COMMANDS"
            for part in ast.walk(child)
        )
        for child in ast.walk(node)
    )
    injection_check = any(
        isinstance(child, ast.Name) and child.id == "DANGEROUS_PATTERNS"
        for child in ast.walk(node)
    )
    if "process.execute" in capabilities and allowlist_check and injection_check:
        tool.guardrails = True
        tool.metadata.update(
            {
                "process_execution_constrained": True,
                "process_command_allowlist": True,
                "process_injection_filter": True,
                "control_basis": "command_allowlist_and_injection_filter",
            }
        )

    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            value = child.value
            if value.startswith(("http://", "https://")):
                parsed = urlparse(value)
                if parsed.hostname:
                    tool.destinations.append(
                        NetworkDestination(
                            target=value,
                            restricted=False,
                            location=_location(path, child),
                            metadata={"source": "literal_url"},
                        )
                    )
    return tool


def _approval_from_call(call: ast.Call) -> bool | None:
    value = _literal(_kw(call, "requires_approval"))
    return value if isinstance(value, bool) else None


def _tool_from_tool_call(
    path: Path,
    call: ast.Call,
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    imports: dict[str, str],
) -> Tool | None:
    if _call_name(call.func) != "Tool":
        return None
    target = call.args[0] if call.args else _kw(call, "function")
    target_name = _call_name(target)
    approval = _approval_from_call(call)
    if target_name and target_name in functions:
        tool = _tool_from_function(
            path,
            functions[target_name],
            approval=approval,
            source="Tool",
        )
        tool.metadata["definition_line"] = getattr(functions[target_name], "lineno", None)
        tool.location = _location(path, call)
        return tool
    name = str(_literal(_kw(call, "name")) or target_name or "pydantic_tool")
    return Tool(
        name=name,
        kind="function",
        capabilities=set(infer_capabilities(name)),
        approval=approval,
        location=_location(path, call),
        metadata={
            "framework": "pydantic-ai",
            "source": "Tool",
            "placeholder": bool(target_name),
            "import_module": imports.get(target_name or ""),
        },
    )


def _merge_tool(tools: list[Tool], incoming: Tool) -> None:
    current = next((tool for tool in tools if tool.name == incoming.name), None)
    if current is None:
        tools.append(incoming)
        return
    current.capabilities.update(incoming.capabilities)
    current.guardrails = current.guardrails or incoming.guardrails
    if incoming.approval is True:
        current.approval = True
    elif incoming.approval is False and current.approval is None:
        current.approval = False
    current.resources.extend(r for r in incoming.resources if r not in current.resources)
    current.destinations.extend(d for d in incoming.destinations if d not in current.destinations)
    current.metadata.update(incoming.metadata)


def _resolve_sequence(
    expr: ast.AST | None,
    sequences: dict[str, list[ast.AST]],
) -> list[ast.AST] | None:
    if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        return list(expr.elts)
    if isinstance(expr, ast.Name):
        return list(sequences[expr.id]) if expr.id in sequences else None
    return None


def _configuration_call_from_expr(
    expr: ast.AST | None,
    assignments: dict[str, ast.AST],
    *,
    visited: set[str] | None = None,
) -> ast.Call | None:
    """Resolve simple assignment/await/fallback chains to a configuration loader call."""
    visited = visited or set()
    if expr is None:
        return None
    if isinstance(expr, ast.Name):
        if expr.id in visited or expr.id not in assignments:
            return None
        return _configuration_call_from_expr(
            assignments[expr.id],
            assignments,
            visited=visited | {expr.id},
        )
    if isinstance(expr, ast.Await):
        return _configuration_call_from_expr(expr.value, assignments, visited=visited)
    if isinstance(expr, ast.Call):
        return expr
    if isinstance(expr, ast.BoolOp):
        for value in expr.values:
            resolved = _configuration_call_from_expr(value, assignments, visited=visited)
            if resolved is not None:
                return resolved
        return None
    if isinstance(expr, ast.IfExp):
        return (
            _configuration_call_from_expr(expr.body, assignments, visited=visited)
            or _configuration_call_from_expr(expr.orelse, assignments, visited=visited)
        )
    return None


def _configured_mcp_catalogue_from_expr(
    path: Path,
    expr: ast.AST | None,
    assignments: dict[str, ast.AST],
    *,
    alias: str,
) -> MCPServer | None:
    """Represent a configuration-derived MCP catalogue without inventing its tools."""
    call = _configuration_call_from_expr(expr, assignments)
    if call is None:
        return None
    called = (_dotted(call.func) or _call_name(call.func) or "").lower()
    leaf = (_call_name(call.func) or "").lower()
    looks_like_mcp_loader = (
        "mcp" in called
        and any(token in called for token in ("server", "toolset", "tools"))
        and (
            leaf.startswith(("get_", "load_", "create_", "build_", "read_"))
            or leaf in {"mcp_servers", "mcp_toolsets"}
        )
    )
    if not looks_like_mcp_loader:
        return None
    return MCPServer(
        name=alias,
        transport="unknown",
        approval=None,
        location=_location(path, call),
        metadata={
            "framework": "pydantic-ai",
            "source": "configuration_derived_mcp_catalogue",
            "binding_origin": "pydantic_toolsets",
            "dynamic_configured_mcp_catalogue": True,
            "configuration_dependent": True,
            "catalogue_source": _dotted(call.func) or _call_name(call.func),
            "dynamic_mcp_endpoint_basis": "operator_configuration",
            "per_call_approval": None,
        },
    )


def _tool_from_reference(
    path: Path,
    expr: ast.AST,
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    assignments: dict[str, ast.AST],
    imports: dict[str, str],
    *,
    visited: set[str] | None = None,
) -> Tool | None:
    visited = visited or set()
    if isinstance(expr, ast.Call):
        direct = _tool_from_tool_call(path, expr, functions, imports)
        if direct is not None:
            return direct

        call_name = _call_name(expr.func) or ""
        if call_name == "tool_from_langchain":
            wrapped = expr.args[0] if expr.args else _kw(expr, "tool")
            wrapped_name = (
                _call_name(wrapped.func)
                if isinstance(wrapped, ast.Call)
                else _call_name(wrapped)
            ) or ""
            wrapped_semantics = _LANGCHAIN_WRAPPED_TOOL_CAPABILITIES.get(
                wrapped_name
            )
            if wrapped_semantics is not None:
                kind, capabilities = wrapped_semantics
                return Tool(
                    name=wrapped_name,
                    kind=kind,
                    capabilities=set(capabilities),
                    location=_location(path, expr),
                    metadata={
                        "framework": "pydantic-ai",
                        "source": "tool_from_langchain",
                        "wrapped_framework": "langchain",
                        "wrapped_tool": wrapped_name,
                        "binding_adapter": (
                            "pydantic_ai.ext.langchain.tool_from_langchain"
                        ),
                    },
                )

        name = call_name or "tool"
        return Tool(
            name=name,
            kind="function",
            capabilities=set(infer_capabilities(name)),
            location=_location(path, expr),
            metadata={"framework": "pydantic-ai", "source": "call"},
        )
    if isinstance(expr, ast.Name):
        if expr.id in functions:
            return _tool_from_function(path, functions[expr.id])
        if expr.id in assignments and expr.id not in visited:
            return _tool_from_reference(
                path,
                assignments[expr.id],
                functions,
                assignments,
                imports,
                visited=visited | {expr.id},
            )
        return Tool(
            name=expr.id,
            kind="function",
            capabilities=set(infer_capabilities(expr.id)),
            location=_location(path, expr),
            metadata={
                "framework": "pydantic-ai",
                "placeholder": True,
                "import_module": imports.get(expr.id),
            },
        )
    if isinstance(expr, ast.Attribute):
        name = expr.attr
        return Tool(
            name=name,
            kind="function",
            capabilities=set(infer_capabilities(name)),
            location=_location(path, expr),
            metadata={"framework": "pydantic-ai", "placeholder": True},
        )
    return None


def _auth_state(call: ast.Call) -> bool | None:
    auth = _kw(call, "auth")
    if auth is not None:
        literal = _literal(auth)
        return not (literal is None and isinstance(auth, ast.Constant))
    headers = _literal(_kw(call, "headers"))
    if isinstance(headers, dict):
        names = {str(key).lower() for key in headers}
        return bool(
            {"authorization", "proxy-authorization", "x-api-key", "x-goog-api-key"} & names
        )
    if _kw(call, "http_client") is not None or _call_name(call.func) in {
        "Client",
        "StreamableHttpTransport",
        "SSETransport",
    }:
        return None
    return False


def _mcp_server_from_call(path: Path, call: ast.Call, alias: str) -> MCPServer | None:
    name = _call_name(call.func)
    canonical_name = (
        "MCP"
        if name == "MCPCapability"
        else "MCPServerStdio"
        if isinstance(name, str) and name.endswith("MCPServerStdio")
        else "MCPServerStreamableHTTP"
        if isinstance(name, str)
        and name.endswith(("MCPServerStreamableHTTP", "MCPServerHTTP"))
        else name
    )
    if canonical_name not in {
        "MCPToolset",
        "MCP",
        "MCPServerTool",
        "MCPServerStdio",
        "MCPServerStreamableHTTP",
    }:
        return None

    metadata: dict[str, Any] = {
        "framework": "pydantic-ai",
        "source": canonical_name,
    }
    if canonical_name != name:
        metadata["constructor_alias"] = name

    if canonical_name == "MCPServerStdio":
        command_node = call.args[0] if call.args else _kw(call, "command")
        args_node = call.args[1] if len(call.args) > 1 else _kw(call, "args")
        command = _literal(command_node)
        args = _literal(args_node)
        return MCPServer(
            name=alias,
            transport="stdio",
            command=command if isinstance(command, str) else None,
            args=[str(item) for item in args] if isinstance(args, (list, tuple)) else [],
            location=_location(path, call),
            metadata={
                **metadata,
                "dynamic_command": command_node is not None and not isinstance(command, str),
            },
        )

    endpoint_node = _kw(call, "url")
    if endpoint_node is None and call.args:
        endpoint_node = call.args[0]
    if canonical_name == "MCP" and endpoint_node is None:
        endpoint_node = _kw(call, "local")

    endpoint = _literal(endpoint_node)
    native = _literal(_kw(call, "native"))
    if isinstance(native, bool):
        metadata["native"] = native

    if isinstance(endpoint, str) and endpoint.startswith(("http://", "https://")):
        parsed = urlparse(endpoint)
        transport = (
            "streamable-http"
            if canonical_name == "MCPServerStreamableHTTP"
            else "sse"
            if parsed.path.rstrip("/").endswith("/sse")
            else "streamable-http"
        )
        return MCPServer(
            name=alias,
            transport=transport,
            url=endpoint,
            authenticated=_auth_state(call),
            location=_location(path, call),
            metadata=metadata,
        )

    if isinstance(endpoint, str):
        suffix = Path(endpoint).suffix.lower()
        command = (
            "python"
            if suffix == ".py"
            else "node"
            if suffix in {".js", ".mjs"}
            else None
        )
        return MCPServer(
            name=alias,
            transport="stdio",
            command=command,
            args=[endpoint],
            location=_location(path, call),
            metadata=metadata,
        )

    if canonical_name == "MCPServerStreamableHTTP":
        return MCPServer(
            name=alias,
            transport="streamable-http",
            location=_location(path, call),
            metadata={
                **metadata,
                "dynamic_mcp_endpoint": True,
                "dynamic_mcp_endpoint_basis": "operator_configuration",
            },
        )

    return MCPServer(
        name=alias,
        transport="unknown",
        location=_location(path, call),
        metadata={**metadata, "dynamic_mcp_endpoint": True},
    )


def _string_sequence_from_expr(
    expr: ast.AST | None,
    assignments: dict[str, ast.AST],
) -> tuple[list[str], bool]:
    if isinstance(expr, ast.Name):
        expr = assignments.get(expr.id)
    if not isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        return [], expr is not None
    values: list[str] = []
    dynamic = False
    for element in expr.elts:
        value = _literal(element)
        if isinstance(value, str):
            values.append(value)
        else:
            dynamic = True
    return values, dynamic


def _mcp_capability_server_from_call(
    path: Path,
    call: ast.Call,
    assignments: dict[str, ast.AST],
) -> MCPServer | None:
    local = _kw(call, "local")
    resolved_local = assignments.get(local.id) if isinstance(local, ast.Name) else local
    if isinstance(resolved_local, ast.Call) and _call_name(resolved_local.func) == "StdioTransport":
        command_node = (
            resolved_local.args[0]
            if resolved_local.args
            else _kw(resolved_local, "command")
        )
        args_node = (
            resolved_local.args[1]
            if len(resolved_local.args) > 1
            else _kw(resolved_local, "args")
        )
        command = _literal(command_node)
        args, dynamic_args = _string_sequence_from_expr(args_node, assignments)
        configured_id = _literal(_kw(call, "id"))
        return MCPServer(
            name=configured_id if isinstance(configured_id, str) else "mcp",
            transport="stdio",
            command=command if isinstance(command, str) else None,
            args=args,
            authenticated=None,
            location=_location(path, call),
            metadata={
                "framework": "pydantic-ai",
                "source": "MCP",
                "binding_origin": "pydantic_capability",
                "local_transport": "StdioTransport",
                "dynamic_command": not isinstance(command, str),
                "dynamic_args": dynamic_args,
                "partial_transport_configuration": dynamic_args
                or not isinstance(command, str),
            },
        )
    return _mcp_server_from_call(path, call, "mcp")


def _mcp_server_from_expr(
    path: Path,
    expr: ast.AST,
    alias: str,
    assignments: dict[str, ast.AST],
    *,
    visited: set[str] | None = None,
) -> MCPServer | None:
    visited = visited or set()
    if isinstance(expr, ast.Name) and expr.id in assignments and expr.id not in visited:
        return _mcp_server_from_expr(
            path,
            assignments[expr.id],
            expr.id,
            assignments,
            visited=visited | {expr.id},
        )
    if not isinstance(expr, ast.Call):
        return None
    direct = _mcp_server_from_call(path, expr, alias)
    if direct is not None:
        return direct
    if isinstance(expr.func, ast.Attribute):
        method = expr.func.attr
        receiver = expr.func.value
        if method in {"approval_required", "filtered", "defer_loading"}:
            server = _mcp_server_from_expr(path, receiver, alias, assignments, visited=visited)
            if server is None:
                return None
            if method == "approval_required":
                if not expr.args and _kw(expr, "approval_required_func") is None:
                    server.approval = True
                else:
                    server.metadata["conditional_approval"] = True
            elif method == "filtered":
                server.metadata["dynamic_tool_filter"] = True
            return server
    return None


def _toolset_tools(
    path: Path,
    expr: ast.AST,
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    assignments: dict[str, ast.AST],
    sequences: dict[str, list[ast.AST]],
    imports: dict[str, str],
    decorated: dict[str, list[Tool]],
    added: dict[str, list[Tool]],
    *,
    visited: set[str] | None = None,
) -> tuple[list[Tool], list[MCPServer], bool]:
    visited = visited or set()
    if isinstance(expr, ast.Name):
        if expr.id in visited:
            return [], [], True
        if expr.id in assignments:
            named_mcp = _mcp_server_from_expr(
                path,
                expr,
                expr.id,
                assignments,
                visited=visited,
            )
            if named_mcp is not None:
                return [], [named_mcp], bool(
                    named_mcp.metadata.get("dynamic_mcp_endpoint")
                )
            tools, servers, dynamic = _toolset_tools(
                path,
                assignments[expr.id],
                functions,
                assignments,
                sequences,
                imports,
                decorated,
                added,
                visited=visited | {expr.id},
            )
            tools.extend(deepcopy(decorated.get(expr.id, [])))
            tools.extend(deepcopy(added.get(expr.id, [])))
            return tools, servers, dynamic
        return [], [], True

    if not isinstance(expr, ast.Call):
        return [], [], True

    mcp = _mcp_server_from_expr(
        path,
        expr,
        f"mcp_{getattr(expr, 'lineno', 1)}",
        assignments,
    )
    if mcp is not None:
        return [], [mcp], bool(mcp.metadata.get("dynamic_mcp_endpoint"))

    name = _call_name(expr.func)
    if name == "Capability":
        # Pydantic AI's declarative Capability is an authority-bearing bundle:
        # it can contribute function tools and nested toolsets to any Agent that
        # receives it through capabilities=[...].  Normalize only source-visible
        # contents; lifecycle hooks/custom subclass behavior remains unresolved.
        tools: list[Tool] = []
        servers: list[MCPServer] = []
        dynamic = False

        tool_expr = _kw(expr, "tools")
        if tool_expr is not None:
            elements = _resolve_sequence(tool_expr, sequences)
            if elements is None:
                dynamic = True
            else:
                for element in elements:
                    tool = _tool_from_reference(
                        path,
                        element,
                        functions,
                        assignments,
                        imports,
                    )
                    if tool is not None:
                        _merge_tool(tools, tool)
                    else:
                        dynamic = True

        toolset_expr = _kw(expr, "toolsets") or _kw(expr, "toolset")
        if toolset_expr is not None:
            elements = _resolve_sequence(toolset_expr, sequences)
            if elements is None:
                dynamic = True
            else:
                for element in elements:
                    child_tools, child_servers, child_dynamic = _toolset_tools(
                        path,
                        element,
                        functions,
                        assignments,
                        sequences,
                        imports,
                        decorated,
                        added,
                        visited=visited,
                    )
                    for tool in child_tools:
                        _merge_tool(tools, tool)
                    servers.extend(child_servers)
                    dynamic = dynamic or child_dynamic

        return tools, servers, dynamic

    if name == "FunctionToolset":
        tools: list[Tool] = []
        tool_expr = _kw(expr, "tools")
        if tool_expr is None and expr.args:
            tool_expr = expr.args[0]
        elements = _resolve_sequence(tool_expr, sequences) if tool_expr is not None else []
        if elements is None:
            return [], [], True
        default_approval = _approval_from_call(expr)
        for element in elements:
            tool = _tool_from_reference(path, element, functions, assignments, imports)
            if tool is not None:
                if default_approval is not None and tool.approval is None:
                    tool.approval = default_approval
                _merge_tool(tools, tool)
        return tools, [], False

    if name == "ApprovalRequiredToolset":
        wrapped = expr.args[0] if expr.args else _kw(expr, "wrapped")
        if wrapped is None:
            return [], [], True
        tools, servers, dynamic = _toolset_tools(
            path,
            wrapped,
            functions,
            assignments,
            sequences,
            imports,
            decorated,
            added,
            visited=visited,
        )
        predicate = (
            expr.args[1]
            if len(expr.args) > 1
            else _kw(expr, "approval_required_func")
        )
        if predicate is None:
            for tool in tools:
                tool.approval = True
            for server in servers:
                server.approval = True
        else:
            for tool in tools:
                tool.metadata["conditional_approval"] = True
            for server in servers:
                server.metadata["conditional_approval"] = True
        return tools, servers, dynamic

    if name == "CombinedToolset":
        value = expr.args[0] if expr.args else _kw(expr, "toolsets")
        elements = _resolve_sequence(value, sequences)
        if elements is None:
            return [], [], True
        tools: list[Tool] = []
        servers: list[MCPServer] = []
        dynamic = False
        for element in elements:
            child_tools, child_servers, child_dynamic = _toolset_tools(
                path,
                element,
                functions,
                assignments,
                sequences,
                imports,
                decorated,
                added,
                visited=visited,
            )
            for tool in child_tools:
                _merge_tool(tools, tool)
            servers.extend(child_servers)
            dynamic = dynamic or child_dynamic
        return tools, servers, dynamic

    if isinstance(expr.func, ast.Attribute):
        method = expr.func.attr
        if method in {
            "approval_required",
            "filtered",
            "prepared",
            "defer_loading",
            "include_return_schemas",
            "with_metadata",
        }:
            tools, servers, dynamic = _toolset_tools(
                path,
                expr.func.value,
                functions,
                assignments,
                sequences,
                imports,
                decorated,
                added,
                visited=visited,
            )
            if method == "approval_required":
                if not expr.args:
                    for tool in tools:
                        tool.approval = True
                    for server in servers:
                        server.approval = True
                else:
                    for tool in tools:
                        tool.metadata["conditional_approval"] = True
                    for server in servers:
                        server.metadata["conditional_approval"] = True
            elif method in {"filtered", "prepared"}:
                dynamic = True
                for tool in tools:
                    tool.metadata["dynamic_tool_filter"] = True
                for server in servers:
                    server.metadata["dynamic_tool_filter"] = True
            return tools, servers, dynamic

    if name == "load_mcp_toolsets":
        return [], [], True

    if name:
        return [
            Tool(
                name=f"toolset:{name}",
                kind="pydantic_function_toolset",
                capabilities=set(),
                location=_location(path, expr),
                metadata={
                    "framework": "pydantic-ai",
                    "binding_origin": "Agent.toolsets",
                    "dynamic_authority": True,
                    "tool_catalogue_unresolved": True,
                    "toolset_class_candidate": name,
                    "import_module": imports.get(name),
                },
            )
        ], [], True

    return [], [], True


def _is_declarative_capability_expr(
    expr: ast.AST,
    assignments: dict[str, ast.AST],
    *,
    visited: set[str] | None = None,
) -> bool:
    """Return True for source-visible pydantic_ai.capabilities.Capability bundles."""
    visited = visited or set()
    if isinstance(expr, ast.Name):
        if expr.id in visited or expr.id not in assignments:
            return False
        return _is_declarative_capability_expr(
            assignments[expr.id],
            assignments,
            visited=visited | {expr.id},
        )
    return isinstance(expr, ast.Call) and _call_name(expr.func) == "Capability"



def _resolved_expr(
    expr: ast.AST,
    assignments: dict[str, ast.AST],
    *,
    visited: set[str] | None = None,
) -> ast.AST:
    """Resolve simple repository-local aliases without executing target code."""
    visited = visited or set()
    if isinstance(expr, ast.Name) and expr.id in assignments and expr.id not in visited:
        return _resolved_expr(
            assignments[expr.id],
            assignments,
            visited=visited | {expr.id},
        )
    return expr


def _string_expr(
    expr: ast.AST | None,
    assignments: dict[str, ast.AST],
) -> str | None:
    if expr is None:
        return None
    expr = _resolved_expr(expr, assignments)
    value = _literal(expr)
    if isinstance(value, str):
        return value
    if isinstance(expr, ast.Call) and _call_name(expr.func) in {"Path", "PurePath"}:
        value = _literal(expr.args[0]) if expr.args else None
        return value if isinstance(value, str) else None
    return None


def _workspace_spec_from_expr(
    expr: ast.AST,
    assignments: dict[str, ast.AST],
) -> dict[str, Any] | None:
    expr = _resolved_expr(expr, assignments)
    if not isinstance(expr, ast.Call):
        return None
    name = _call_name(expr.func) or ""

    if name == "BubblewrapSandbox":
        wrapped = expr.args[0] if expr.args else _kw(expr, "workspace")
        spec = (
            _workspace_spec_from_expr(wrapped, assignments)
            if wrapped is not None
            else {}
        ) or {}
        network = _literal(_kw(expr, "network"))
        spec.update(
            {
                "sandbox": "bubblewrap",
                "sandboxed": True,
                "execution_boundary": (
                    "remote-sandbox"
                    if spec.get("remote")
                    else "local-sandbox"
                ),
                "network_allowed": bool(network) if isinstance(network, bool) else False,
            }
        )
        return spec

    if name == "LocalWorkspace":
        root = _string_expr(
            expr.args[0] if expr.args else _kw(expr, "root"),
            assignments,
        )
        read_only = _literal(_kw(expr, "read_only"))
        return {
            "provider": "local",
            "root": root,
            "working_dir": root,
            "remote": False,
            "sandboxed": False,
            "read_only": read_only is True,
            "execution_boundary": "local-host",
        }

    if name in {"E2BSandbox", "SpritesSandbox"}:
        provider = "e2b" if name == "E2BSandbox" else "sprites"
        working_dir = _string_expr(_kw(expr, "working_dir"), assignments)
        spec: dict[str, Any] = {
            "provider": provider,
            "working_dir": working_dir,
            "root": working_dir,
            "remote": True,
            "sandboxed": True,
            "execution_boundary": "remote-sandbox",
        }
        internet = _literal(_kw(expr, "allow_internet_access"))
        if isinstance(internet, bool):
            spec["network_allowed"] = internet
        return spec

    if name == "SSHWorkspace":
        destination = _string_expr(
            expr.args[0] if expr.args else _kw(expr, "destination"),
            assignments,
        )
        working_dir = _string_expr(_kw(expr, "working_dir"), assignments)
        return {
            "provider": "ssh",
            "destination": destination,
            "working_dir": working_dir,
            "root": working_dir,
            "remote": True,
            "sandboxed": False,
            "network_allowed": True,
            "execution_boundary": "remote-host",
        }

    return None


def _resource_once(
    tool: Tool,
    *,
    kind: str,
    selector: str | None,
    access: set[str],
    location: SourceLocation,
    metadata: dict[str, Any] | None = None,
) -> None:
    if not selector:
        return
    key = (kind, selector, tuple(sorted(access)))
    if any(
        (item.kind, item.selector, tuple(sorted(item.access))) == key
        for item in tool.resources
    ):
        return
    tool.resources.append(
        ResourceScope(
            kind=kind,
            selector=selector,
            access=set(access),
            location=location,
            metadata=dict(metadata or {}),
        )
    )


def _apply_workspace_semantics(agent: Agent, spec: dict[str, Any]) -> None:
    """Apply current Pydantic workspace/sandbox constraints to model-callable tools."""
    provider = str(spec.get("provider") or "unknown")
    root = spec.get("root") or spec.get("working_dir")
    read_only = spec.get("read_only") is True
    network_allowed = spec.get("network_allowed")
    sandboxed = spec.get("sandboxed") is True
    sandbox = spec.get("sandbox")
    boundary = str(spec.get("execution_boundary") or "workspace")

    public_spec = {
        key: value
        for key, value in spec.items()
        if value is not None
    }
    agent.metadata["workspace"] = public_spec
    agent.metadata["workspace_provider"] = provider
    agent.metadata["execution_boundary"] = boundary
    agent.metadata["workspace_remote"] = spec.get("remote") is True
    agent.metadata["workspace_sandboxed"] = sandboxed
    if read_only:
        agent.metadata["workspace_read_only"] = True
    else:
        agent.metadata["workspace_writable"] = True
    if sandbox:
        agent.metadata["sandbox"] = sandbox
    if isinstance(network_allowed, bool):
        agent.metadata["workspace_network_allowed"] = network_allowed

    destination = spec.get("destination")
    if isinstance(destination, str) and destination:
        target = destination if "://" in destination else f"ssh://{destination}"
        if not any(item.target == target for item in agent.network):
            agent.network.append(
                NetworkDestination(
                    target=target,
                    restricted=True,
                    location=agent.location,
                    metadata={
                        "source": "pydantic_workspace",
                        "network_scope": "fixed_execution_target",
                        "destination_provenance": "operator_configuration",
                        "workspace_provider": provider,
                    },
                )
            )

    workspace_tools = {
        "FileSystem",
        "Shell",
        "Coder",
        "Memory",
        "Skills",
        "CapabilityCreation",
    }
    for tool in agent.tools:
        if tool.name not in workspace_tools and tool.kind not in {
            "filesystem",
            "shell",
            "coder",
            "persistent_memory",
            "skills",
            "capability_creation",
        }:
            continue

        tool.metadata["workspace_provider"] = provider
        tool.metadata["execution_boundary"] = boundary
        if sandboxed:
            tool.metadata["sandboxed"] = True
        if sandbox:
            tool.metadata["sandbox"] = sandbox
        if read_only:
            tool.metadata["workspace_read_only"] = True
        if isinstance(network_allowed, bool):
            tool.metadata["network_allowed"] = network_allowed

        if root and tool.kind in {"filesystem", "shell", "coder"}:
            access = tool.capabilities & {
                "data.read",
                "data.write",
                "destructive.write",
            }
            _resource_once(
                tool,
                kind="file",
                selector=str(root),
                access=access,
                location=tool.location or agent.location or SourceLocation(Path(".")),
                metadata={
                    "source": "pydantic_workspace",
                    "workspace_provider": provider,
                },
            )

        if read_only and tool.kind in {"filesystem", "persistent_memory"}:
            tool.capabilities.difference_update(
                {"data.write", "destructive.write", "external.write"}
            )
            for resource in tool.resources:
                resource.access.difference_update(
                    {"data.write", "destructive.write", "external.write"}
                )

        if network_allowed is False and tool.kind in {"shell", "coder"}:
            tool.capabilities.discard("network.external")
            tool.metadata["network_isolated"] = True

        if isinstance(destination, str) and destination and tool.kind in {"shell", "coder"}:
            target = destination if "://" in destination else f"ssh://{destination}"
            if not any(item.target == target for item in tool.destinations):
                tool.destinations.append(
                    NetworkDestination(
                        target=target,
                        restricted=True,
                        location=tool.location or agent.location,
                        metadata={
                            "source": "pydantic_workspace",
                            "network_scope": "fixed_execution_target",
                            "destination_provenance": "operator_configuration",
                            "workspace_provider": provider,
                        },
                    )
                )


def _harness_special_capability(
    path: Path,
    expr: ast.AST,
    assignments: dict[str, ast.AST],
    agent: Agent,
) -> bool:
    """Normalize authority-bearing current Harness capabilities and boundaries."""
    resolved = _resolved_expr(expr, assignments)
    if not isinstance(resolved, ast.Call):
        return False
    name = _call_name(resolved.func) or ""

    workspace = _workspace_spec_from_expr(resolved, assignments)
    if workspace is not None:
        existing = dict(agent.metadata.get("_workspace_spec") or {})
        existing.update({key: value for key, value in workspace.items() if value is not None})
        agent.metadata["_workspace_spec"] = existing
        return True

    if name == "Memory":
        store = resolved.args[0] if resolved.args else _kw(resolved, "store")
        store = _resolved_expr(store, assignments) if store is not None else None
        selector: str | None = None
        store_name = "unknown"
        if isinstance(store, ast.Call):
            store_name = _call_name(store.func) or "unknown"
            selector = _string_expr(
                store.args[0] if store.args else _kw(store, "directory"),
                assignments,
            )
            if selector is None:
                selector = _string_expr(_kw(store, "database"), assignments)
        tool = Tool(
            name="Memory",
            kind="persistent_memory",
            capabilities={"data.read", "data.write"},
            location=_location(path, resolved),
            metadata={
                "framework": "pydantic-ai",
                "capability": "Memory",
                "store": store_name,
                "persistent_state": store_name not in {"InMemoryStore", "unknown"},
            },
        )
        if selector:
            _resource_once(
                tool,
                kind="memory",
                selector=selector,
                access={"data.read", "data.write"},
                location=tool.location or _location(path, resolved),
                metadata={"source": "pydantic_harness_memory", "store": store_name},
            )
        _merge_tool(agent.tools, tool)
        return True

    if name == "Skills":
        selector = _string_expr(
            resolved.args[0] if resolved.args else _kw(resolved, "directory"),
            assignments,
        )
        tool = Tool(
            name="Skills",
            kind="skills",
            capabilities={"data.read"},
            location=_location(path, resolved),
            metadata={
                "framework": "pydantic-ai",
                "capability": "Skills",
                "deferred_capability_catalogue": True,
                "dynamic_authority": True,
                "scripts_executed": False,
            },
        )
        if selector:
            _resource_once(
                tool,
                kind="file",
                selector=selector,
                access={"data.read"},
                location=tool.location or _location(path, resolved),
                metadata={"source": "pydantic_harness_skills"},
            )
        _merge_tool(agent.tools, tool)
        agent.metadata["dynamic_tools"] = True
        return True

    if name == "CapabilityCreation":
        selector = _string_expr(_kw(resolved, "directory"), assignments)
        if selector is None and resolved.args:
            selector = _string_expr(resolved.args[0], assignments)
        tool = Tool(
            name="CapabilityCreation",
            kind="capability_creation",
            capabilities={"process.execute", "data.read", "data.write"},
            location=_location(path, resolved),
            metadata={
                "framework": "pydantic-ai",
                "capability": "CapabilityCreation",
                "dynamic_authority": True,
                "model_authored_code": True,
                "host_process_execution": True,
                "requires_writable_local_workspace": True,
            },
        )
        if selector:
            _resource_once(
                tool,
                kind="file",
                selector=selector,
                access={"data.read", "data.write", "process.execute"},
                location=tool.location or _location(path, resolved),
                metadata={"source": "pydantic_harness_capability_creation"},
            )
        _merge_tool(agent.tools, tool)
        agent.metadata["dynamic_tools"] = True
        return True

    if name in {"GitHub", "Slack"}:
        service = name.lower()
        default_url = (
            "https://api.githubcopilot.com/mcp/"
            if name == "GitHub"
            else "https://mcp.slack.com/mcp"
        )
        configured_url = _string_expr(_kw(resolved, "url"), assignments)
        url = configured_url or default_url
        auth_node = _kw(resolved, "auth")
        authenticated = True if auth_node is not None else None
        read_only = _literal(_kw(resolved, "read_only")) is True
        server = MCPServer(
            name=str(_literal(_kw(resolved, "id")) or service),
            transport="streamable-http",
            url=url,
            authenticated=authenticated,
            location=_location(path, resolved),
            metadata={
                "framework": "pydantic-ai",
                "source": f"pydantic_harness.{service}",
                "hosted_harness_capability": True,
                "service": service,
                "read_only": read_only,
                "dynamic_tool_catalogue": True,
                "credential_source": (
                    "explicit"
                    if auth_node is not None
                    else ("GITHUB_TOKEN" if name == "GitHub" else "SLACK_USER_TOKEN")
                ),
            },
        )
        agent.mcp_servers.append(server)
        if read_only:
            agent.metadata.setdefault("read_only_integrations", []).append(service)
        return True

    if name in {"SubAgents", "Subagents"}:
        targets: list[str] = []
        roster = _kw(resolved, "agents")
        if isinstance(roster, (ast.List, ast.Tuple, ast.Set)):
            for member in roster.elts:
                member = _resolved_expr(member, assignments)
                target: ast.AST | None = member
                if isinstance(member, ast.Call) and _call_name(member.func) == "SubAgent":
                    target = member.args[0] if member.args else _kw(member, "agent")
                if isinstance(target, ast.Name):
                    targets.append(target.id)
        include_self = _literal(_kw(resolved, "include_self")) is True
        if include_self:
            targets.append("self")
        targets = list(dict.fromkeys(targets))
        max_depth = _literal(_kw(resolved, "max_depth"))
        tool = Tool(
            name="SubAgents",
            kind="delegated_agent",
            capabilities={"agent.delegate"},
            location=_location(path, resolved),
            metadata={
                "framework": "pydantic-ai",
                "capability": "SubAgents",
                "delegate_targets": targets,
                "include_self": include_self,
                **({"max_depth": max_depth} if isinstance(max_depth, int) else {}),
                "delegation_basis": "pydantic_harness_subagents",
            },
        )
        if len(targets) == 1:
            tool.metadata["delegate_target"] = targets[0]
        _merge_tool(agent.tools, tool)
        return True

    return False


def _bind_local_agent_delegations(
    agents: dict[str, Agent],
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> None:
    """Bind only calls whose receiver is a normalized Pydantic Agent alias."""
    for parent in agents.values():
        for tool in parent.tools:
            function = functions.get(tool.name)
            if function is None:
                continue
            targets = sorted(
                {
                    child.func.value.id
                    for child in ast.walk(function)
                    if isinstance(child, ast.Call)
                    and isinstance(child.func, ast.Attribute)
                    and child.func.attr in _AGENT_RUN_METHODS
                    and isinstance(child.func.value, ast.Name)
                    and child.func.value.id in agents
                }
            )
            if not targets:
                continue
            tool.capabilities.add("agent.delegate")
            tool.metadata["delegate_target"] = targets[0]
            tool.metadata["delegate_targets"] = targets
            tool.metadata["delegation_basis"] = "pydantic_agent_run"


def _capability_from_expr(
    path: Path,
    expr: ast.AST,
    assignments: dict[str, ast.AST],
    *,
    visited: set[str] | None = None,
) -> tuple[Tool | None, MCPServer | None, str | None]:
    visited = visited or set()
    if isinstance(expr, ast.Name) and expr.id in assignments and expr.id not in visited:
        return _capability_from_expr(
            path,
            assignments[expr.id],
            assignments,
            visited=visited | {expr.id},
        )
    if not isinstance(expr, ast.Call):
        return None, None, None

    name = _call_name(expr.func) or ""
    if name in {"MCP", "MCPCapability"}:
        return None, _mcp_capability_server_from_call(path, expr, assignments), None
    if name == "NativeTool":
        wrapped = expr.args[0] if expr.args else _kw(expr, "tool")
        if isinstance(wrapped, ast.Call):
            wrapped_name = _call_name(wrapped.func) or ""
            if wrapped_name == "MCPServerTool":
                server = _mcp_server_from_call(path, wrapped, "native_mcp")
                if server is not None:
                    server.metadata["native"] = True
                return None, server, None
            if wrapped_name in _NATIVE_TOOL_CAPABILITIES:
                kind, capabilities = _NATIVE_TOOL_CAPABILITIES[wrapped_name]
                return (
                    Tool(
                        name=wrapped_name,
                        kind=kind,
                        capabilities=set(capabilities),
                        location=_location(path, wrapped),
                        metadata={
                            "framework": "pydantic-ai",
                            "native_tool": wrapped_name,
                            "provider_managed": True,
                        },
                    ),
                    None,
                    None,
                )
        return None, None, None
    if name in _CONTROL_CAPABILITIES:
        return None, None, name
    if name not in _CAPABILITY_TOOLS:
        inferred = set(infer_capabilities(name))
        if not inferred:
            return None, None, None
        return (
            Tool(
                name=name,
                kind="pydantic_capability",
                capabilities=inferred,
                location=_location(path, expr),
                metadata={"framework": "pydantic-ai", "capability": name},
            ),
            None,
            None,
        )

    kind, capabilities = _CAPABILITY_TOOLS[name]
    tool = Tool(
        name=name,
        kind=kind,
        capabilities=set(capabilities),
        location=_location(path, expr),
        metadata={"framework": "pydantic-ai", "capability": name},
    )
    if name == "ModalSandbox":
        tool.metadata["sandboxed"] = True
    if name == "FileSystem":
        root = _literal(expr.args[0]) if expr.args else _literal(_kw(expr, "root"))
        if isinstance(root, str):
            tool.resources.append(
                ResourceScope(
                    kind="file",
                    selector=root,
                    access={"data.read", "data.write"},
                    location=_location(path, expr),
                )
            )
    return tool, None, None


def _decorator_target(
    decorator: ast.AST,
) -> tuple[str | None, str | None, ast.Call | None]:
    call = decorator if isinstance(decorator, ast.Call) else None
    base = call.func if call is not None else decorator
    if not isinstance(base, ast.Attribute):
        return None, None, call
    return _dotted(base.value) or _call_name(base.value), base.attr, call


def _diagnostic(graph: Graph, path: Path, node: ast.AST, message: str) -> None:
    add_diagnostic(
        graph.coverage,
        ScanDiagnostic(
            "dynamic_configuration",
            message,
            _location(path, node),
            details={"framework": "pydantic-ai"},
        ),
    )




def _expr_has_untrusted_cli_input(node: ast.AST | None, tainted: set[str]) -> bool:
    if node is None:
        return False
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in tainted:
            return True
        if (
            isinstance(child, ast.Call)
            and _call_name(child.func) == "input"
        ):
            return True
    return False


def _annotate_cli_run_inputs(
    path: Path,
    tree: ast.AST,
    agents: dict[str, Agent],
) -> None:
    """Attach untrusted CLI input only when it reaches a Pydantic AI run call."""
    functions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    if not functions or not agents:
        return

    def enclosing_function(line: int) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
        matches = [
            fn
            for fn in functions
            if (getattr(fn, "lineno", 0) or 0)
            <= line
            <= (getattr(fn, "end_lineno", 0) or 0)
        ]
        if not matches:
            return None
        return max(matches, key=lambda fn: getattr(fn, "lineno", 0) or 0)

    module_agents = {
        alias: agent
        for alias, agent in agents.items()
        if agent.location is not None
        and enclosing_function(agent.location.line) is None
    }

    for fn in functions:
        available = dict(module_agents)
        for alias, agent in agents.items():
            if agent.location is None:
                continue
            owner = enclosing_function(agent.location.line)
            if owner is fn:
                available[alias] = agent
        if not available:
            continue

        tainted: set[str] = set()
        assignments = [
            node
            for node in ast.walk(fn)
            if isinstance(node, (ast.Assign, ast.AnnAssign))
            and node.value is not None
        ]

        changed = True
        while changed:
            changed = False
            for assignment in assignments:
                if not _expr_has_untrusted_cli_input(assignment.value, tainted):
                    continue
                for target in _target_names(assignment):
                    if target not in tainted:
                        tainted.add(target)
                        changed = True

        for call in (node for node in ast.walk(fn) if isinstance(node, ast.Call)):
            if not isinstance(call.func, ast.Attribute):
                continue
            if call.func.attr not in _AGENT_RUN_METHODS:
                continue
            owner = _dotted(call.func.value) or _call_name(call.func.value)
            agent = available.get(owner or "")
            if agent is None:
                continue
            prompt = call.args[0] if call.args else next(
                (
                    keyword.value
                    for keyword in call.keywords
                    if keyword.arg in {"user_prompt", "prompt", "input"}
                ),
                None,
            )
            if not _expr_has_untrusted_cli_input(prompt, tainted):
                continue
            if any(
                item.metadata.get("basis") == "pydantic_ai_cli_input_to_run"
                for item in agent.inputs
            ):
                continue
            agent.inputs.append(
                InputSource(
                    name="cli-input",
                    trust="untrusted",
                    kind="user",
                    location=_location(path, call),
                    metadata={"basis": "pydantic_ai_cli_input_to_run"},
                )
            )


def _annotate_public_wrapper_run_inputs(
    path: Path,
    tree: ast.AST,
    agents: dict[str, Agent],
) -> None:
    """Bind source-proven public wrapper parameters to Pydantic AI run calls.

    This covers repository APIs such as run_agent(prompt) -> helper(query) ->
    agent.run_sync(derived_prompt) without assuming arbitrary function parameters
    are external ingress.
    """
    functions = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    if not functions or not agents:
        return

    public_entry_names = {
        "run_agent",
        "chat",
        "ask",
        "query",
        "respond",
        "process_message",
        "handle_message",
    }

    def _tainted(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
        names = {
            arg.arg
            for arg in [
                *fn.args.posonlyargs,
                *fn.args.args,
                *fn.args.kwonlyargs,
            ]
        }
        assignments = [
            node
            for node in ast.walk(fn)
            if isinstance(node, (ast.Assign, ast.AnnAssign))
            and node.value is not None
        ]
        for _ in range(8):
            changed = False
            for assignment in assignments:
                if not _expr_uses_names(assignment.value, names):
                    continue
                for target in _target_names(assignment):
                    if target not in names:
                        names.add(target)
                        changed = True
            if not changed:
                break
        return names

    tainted_by_function = {
        name: _tainted(fn)
        for name, fn in functions.items()
    }
    reaches: dict[str, set[str]] = {name: set() for name in functions}

    for name, fn in functions.items():
        tainted = tainted_by_function[name]
        for call in (node for node in ast.walk(fn) if isinstance(node, ast.Call)):
            if not isinstance(call.func, ast.Attribute):
                continue
            if call.func.attr not in _AGENT_RUN_METHODS:
                continue
            owner = _dotted(call.func.value) or _call_name(call.func.value)
            if owner not in agents:
                continue
            prompt = call.args[0] if call.args else next(
                (
                    keyword.value
                    for keyword in call.keywords
                    if keyword.arg in {"user_prompt", "prompt", "input"}
                ),
                None,
            )
            if prompt is not None and _expr_uses_names(prompt, tainted):
                reaches[name].add(owner)

    for _ in range(8):
        changed = False
        for name, fn in functions.items():
            tainted = tainted_by_function[name]
            for call in (node for node in ast.walk(fn) if isinstance(node, ast.Call)):
                called = _call_name(call.func)
                if called not in reaches or not reaches[called]:
                    continue
                values = [*call.args, *(keyword.value for keyword in call.keywords)]
                if not any(_expr_uses_names(value, tainted) for value in values):
                    continue
                before = len(reaches[name])
                reaches[name].update(reaches[called])
                changed = changed or len(reaches[name]) != before
        if not changed:
            break

    for function_name in sorted(public_entry_names & set(functions)):
        fn = functions[function_name]
        params = [
            arg.arg
            for arg in [
                *fn.args.posonlyargs,
                *fn.args.args,
                *fn.args.kwonlyargs,
            ]
        ]
        if not params:
            continue
        for alias in sorted(reaches[function_name]):
            agent = agents.get(alias)
            if agent is None:
                continue
            basis = "pydantic_ai_public_wrapper_input_to_run"
            if any(item.metadata.get("basis") == basis for item in agent.inputs):
                continue
            agent.inputs.append(
                InputSource(
                    name=f"{function_name}:{params[0]}",
                    trust="untrusted",
                    kind="application",
                    location=_location(path, fn),
                    metadata={
                        "basis": basis,
                        "runtime_invocation_proven": True,
                        "wrapper_function": function_name,
                    },
                )
            )


def _enclosing_function_node(
    tree: ast.AST,
    node: ast.AST,
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    line = getattr(node, "lineno", 0) or 0
    candidates = [
        item
        for item in ast.walk(tree)
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        and (getattr(item, "lineno", 0) or 0) <= line
        <= (getattr(item, "end_lineno", 0) or 0)
    ]
    if not candidates:
        return None
    return min(
        candidates,
        key=lambda item: (
            (getattr(item, "end_lineno", 0) or 0)
            - (getattr(item, "lineno", 0) or 0)
        ),
    )


def _assignment_value_before(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    name: str,
    before_line: int,
) -> ast.AST | None:
    candidates: list[tuple[int, ast.AST]] = []
    for assignment in ast.walk(function):
        if not isinstance(assignment, (ast.Assign, ast.AnnAssign)):
            continue
        line = getattr(assignment, "lineno", 0) or 0
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


def _local_tool_factory_members(
    factory: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, bool]]:
    """Resolve nested callables returned through a local list-valued tool factory.

    Returns (function, conditional) pairs. Conditional members are those only
    appended under a source-level branch and are preserved as possible authority
    rather than asserted as unconditional runtime availability.
    """
    nested = {
        item.name: item
        for item in factory.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    if not nested:
        return []

    collections: dict[str, list[tuple[str, bool]]] = {}

    def names_from_sequence(value: ast.AST | None) -> list[str]:
        if not isinstance(value, (ast.List, ast.Tuple, ast.Set)):
            return []
        return [
            element.id
            for element in value.elts
            if isinstance(element, ast.Name) and element.id in nested
        ]

    for statement in factory.body:
        if isinstance(statement, (ast.Assign, ast.AnnAssign)) and statement.value is not None:
            names = names_from_sequence(statement.value)
            targets = (
                statement.targets
                if isinstance(statement, ast.Assign)
                else [statement.target]
            )
            for target in targets:
                if isinstance(target, ast.Name) and names:
                    collections[target.id] = [(name, False) for name in names]

    def collect_appends(node: ast.AST, *, conditional: bool) -> None:
        for child in ast.walk(node):
            if not isinstance(child, ast.Call) or not isinstance(child.func, ast.Attribute):
                continue
            if child.func.attr != "append" or len(child.args) != 1:
                continue
            if not isinstance(child.func.value, ast.Name):
                continue
            collection = child.func.value.id
            member = child.args[0]
            if not isinstance(member, ast.Name) or member.id not in nested:
                continue
            collections.setdefault(collection, []).append((member.id, conditional))

    for statement in factory.body:
        if isinstance(statement, ast.If):
            collect_appends(statement, conditional=True)
        elif not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            collect_appends(statement, conditional=False)

    selected: list[tuple[str, bool]] = []
    for statement in factory.body:
        if not isinstance(statement, ast.Return):
            continue
        if isinstance(statement.value, ast.Name):
            selected.extend(collections.get(statement.value.id, []))
        else:
            selected.extend(
                (name, False)
                for name in names_from_sequence(statement.value)
            )

    result: list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, bool]] = []
    seen: set[str] = set()
    for name, conditional in selected:
        if name in seen:
            continue
        seen.add(name)
        result.append((nested[name], conditional))
    return result


def scan_python_file(path: Path) -> Graph:
    graph = Graph()
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return graph
    if not _uses_pydantic_ai(tree):
        return graph

    functions = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assignments: dict[str, ast.AST] = {}
    sequences: dict[str, list[ast.AST]] = {}
    imports: dict[str, str] = {}
    agent_calls: dict[str, ast.Call] = {}
    factory_agent_aliases: set[str] = set()
    factory_alias_sources: dict[str, str] = {}
    factory_returns: dict[str, ast.Call] = {}
    declared_mcp_servers: dict[str, MCPServer] = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                imports[alias.asname or alias.name] = module
        elif isinstance(node, ast.Import):
            for alias in node.names:
                imports[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            for target in _target_names(node):
                assignments[target] = node.value
                if isinstance(node.value, (ast.List, ast.Tuple, ast.Set)):
                    sequences[target] = list(node.value.elts)
                if isinstance(node.value, ast.Call):
                    declared_mcp = _mcp_server_from_call(
                        path,
                        node.value,
                        target,
                    )
                    if declared_mcp is not None:
                        declared_mcp_servers[target] = declared_mcp
                if (
                    isinstance(node.value, ast.Call)
                    and _call_name(node.value.func) == "Agent"
                ):
                    agent_calls[target] = node.value

    # Normalize direct factory returns such as
    # `def create_agent(...): return Agent(...)`. The source proves an Agent
    # construction even when no module-level variable is assigned.
    class _FactoryReturnVisitor(ast.NodeVisitor):
        def __init__(
            self,
            root: ast.FunctionDef | ast.AsyncFunctionDef,
        ) -> None:
            self.root = root
            self.calls: list[ast.Call] = []

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            if node is self.root:
                self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            if node is self.root:
                self.generic_visit(node)

        def visit_Lambda(self, node: ast.Lambda) -> None:
            return

        def visit_Return(self, node: ast.Return) -> None:
            value = node.value
            if isinstance(value, ast.Call) and _call_name(value.func) == "Agent":
                self.calls.append(value)
            self.generic_visit(node)

    for function in functions.values():
        visitor = _FactoryReturnVisitor(function)
        visitor.visit(function)
        if len(visitor.calls) != 1:
            continue
        factory_returns[function.name] = visitor.calls[0]

    # Materialize source-visible factory instances. Assignment from a local
    # factory proves a concrete agent instance, and later agent.tool(...)
    # registrations must bind to that instance rather than to a synthetic
    # factory-level agent.
    instantiated_factories: set[str] = set()
    for alias, value in list(assignments.items()):
        if not isinstance(value, ast.Call):
            continue
        factory_name = _call_name(value.func) or ""
        returned = factory_returns.get(factory_name)
        if returned is None:
            continue
        agent_calls[alias] = returned
        factory_agent_aliases.add(alias)
        factory_alias_sources[alias] = factory_name
        instantiated_factories.add(factory_name)

    # Preserve a factory-level construction only when the source exposes no
    # concrete assignment from that factory. This keeps discovery for pure
    # factory modules without double-counting every factory plus its instances.
    for factory_name, returned in factory_returns.items():
        if factory_name in instantiated_factories or factory_name in agent_calls:
            continue
        agent_calls[factory_name] = returned
        factory_agent_aliases.add(factory_name)
        factory_alias_sources[factory_name] = factory_name

    decorated_toolsets: dict[str, list[Tool]] = {}
    added_toolsets: dict[str, list[Tool]] = {}
    decorated_agents: dict[str, list[Tool]] = {}
    dynamic_agent_toolsets: dict[str, list[str]] = {}

    for node in functions.values():
        for decorator in node.decorator_list:
            owner, kind, call = _decorator_target(decorator)
            if kind not in {"tool", "tool_plain", "toolset"} or not owner:
                continue
            if kind == "toolset":
                if owner in agent_calls:
                    dynamic_agent_toolsets.setdefault(owner, []).append(node.name)
                    _diagnostic(
                        graph,
                        path,
                        decorator,
                        "Dynamic @agent.toolset provider cannot be fully resolved statically.",
                    )
                continue
            approval = _approval_from_call(call) if call is not None else None
            tool = _tool_from_function(
                path,
                node,
                approval=approval,
                source=f"@{owner}.{kind}",
            )
            if owner in agent_calls:
                decorated_agents.setdefault(owner, []).append(tool)
            else:
                decorated_toolsets.setdefault(owner, []).append(tool)

    for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
        if not isinstance(call.func, ast.Attribute):
            continue
        owner = _dotted(call.func.value) or _call_name(call.func.value)
        if not owner or call.func.attr not in {"add_function", "add_tool"}:
            continue
        target = call.args[0] if call.args else _kw(call, "function")
        if target is None:
            continue
        if call.func.attr == "add_tool" and isinstance(target, ast.Call):
            tool = _tool_from_tool_call(path, target, functions, imports)
        else:
            tool = _tool_from_reference(
                path,
                target,
                functions,
                assignments,
                imports,
            )
            approval = _approval_from_call(call)
            if tool is not None and approval is not None:
                tool.approval = approval
        if tool is not None:
            added_toolsets.setdefault(owner, []).append(tool)

    agents: dict[str, Agent] = {}
    for alias, call in agent_calls.items():
        model_node = _kw(call, "model")
        if model_node is None and call.args:
            model_node = call.args[0]
        model = _literal(model_node)

        agent = Agent(
            name=alias,
            location=_location(path, call),
            metadata={
                "framework": "pydantic-ai",
                "agent_type": "Agent",
                "model": model if isinstance(model, str) else None,
                "instance_key": f"{path.resolve()}:{call.lineno}:{alias}",
                **(
                    {
                        "factory_function": factory_alias_sources.get(alias, alias),
                        "factory_return": True,
                        "factory_instance": (
                            factory_alias_sources.get(alias, alias) != alias
                        ),
                        "binding_origin": (
                            "factory_assignment"
                            if factory_alias_sources.get(alias, alias) != alias
                            else "direct_factory_return"
                        ),
                    }
                    if alias in factory_agent_aliases
                    else {}
                ),
            },
        )

        for provider_name in dynamic_agent_toolsets.get(alias, []):
            provider = functions.get(provider_name)
            placeholder = Tool(
                name=f"dynamic-toolset:{provider_name}",
                kind="pydantic_dynamic_toolset",
                capabilities=set(),
                location=_location(path, provider or call),
                metadata={
                    "framework": "pydantic-ai",
                    "binding_origin": "@agent.toolset",
                    "dynamic_authority": True,
                    "tool_catalogue_unresolved": True,
                    "provider_function": provider_name,
                },
            )
            _merge_tool(agent.tools, placeholder)
            agent.metadata["dynamic_tools"] = True
            agent.metadata.setdefault("dynamic_toolset_providers", []).append(
                provider_name
            )

        tools_expr = _agent_kw(call, "tools", tree, assignments)
        if tools_expr is not None:
            elements = _resolve_sequence(tools_expr, sequences)
            if elements is None:
                agent.metadata["dynamic_tools"] = True
                _merge_tool(
                    agent.tools,
                    _dynamic_authority_tool(path, tools_expr, alias, "tools"),
                )
                _diagnostic(
                    graph,
                    path,
                    tools_expr,
                    "Pydantic AI tools collection could not be statically resolved.",
                )
            else:
                for element in elements:
                    tool = _tool_from_reference(
                        path,
                        element,
                        functions,
                        assignments,
                        imports,
                    )
                    if tool is not None:
                        _merge_tool(agent.tools, tool)

        for tool in decorated_agents.get(alias, []):
            _merge_tool(agent.tools, deepcopy(tool))

        builtin_tools_expr = _agent_kw(call, "builtin_tools", tree, assignments)
        if builtin_tools_expr is not None:
            builtin_elements = _resolve_sequence(builtin_tools_expr, sequences)
            if builtin_elements is None:
                agent.metadata["dynamic_tools"] = True
                _merge_tool(
                    agent.tools,
                    _dynamic_authority_tool(
                        path,
                        builtin_tools_expr,
                        alias,
                        "builtin_tools",
                    ),
                )
                _diagnostic(
                    graph,
                    path,
                    builtin_tools_expr,
                    "Pydantic AI builtin tools collection could not be statically resolved.",
                )

        mcp_servers_expr = _kw(call, "mcp_servers")
        if mcp_servers_expr is not None:
            elements = _resolve_sequence(mcp_servers_expr, sequences)
            if elements is None:
                _diagnostic(
                    graph,
                    path,
                    mcp_servers_expr,
                    "Pydantic AI MCP server collection could not be statically resolved.",
                )
            else:
                for element in elements:
                    server = _mcp_server_from_expr(
                        path,
                        element,
                        _call_name(element) or "mcp",
                        assignments,
                    )
                    if server is not None:
                        agent.mcp_servers.append(server)
                    else:
                        _diagnostic(
                            graph,
                            path,
                            element,
                            "Pydantic AI MCP server reference could not be normalized.",
                        )

        toolsets_expr = _agent_kw(call, "toolsets", tree, assignments)
        if toolsets_expr is not None:
            elements = _resolve_sequence(toolsets_expr, sequences)
            if elements is None:
                agent.metadata["dynamic_tools"] = True
                configured_mcp = _configured_mcp_catalogue_from_expr(
                    path,
                    toolsets_expr,
                    assignments,
                    alias=f"{alias}:configured-mcp",
                )
                if configured_mcp is not None:
                    agent.mcp_servers.append(configured_mcp)
                    agent.metadata["configuration_dependent_mcp_toolsets"] = True
                else:
                    _merge_tool(
                        agent.tools,
                        _dynamic_authority_tool(path, toolsets_expr, alias, "toolsets"),
                    )
                _diagnostic(
                    graph,
                    path,
                    toolsets_expr,
                    (
                        "Pydantic AI toolsets are configuration-derived; the MCP "
                        "catalogue is bound but its concrete tools/transports are unresolved."
                        if configured_mcp is not None
                        else "Pydantic AI toolsets collection could not be statically resolved."
                    ),
                )
            else:
                for element in elements:
                    tools, servers, dynamic = _toolset_tools(
                        path,
                        element,
                        functions,
                        assignments,
                        sequences,
                        imports,
                        decorated_toolsets,
                        added_toolsets,
                    )
                    for tool in tools:
                        _merge_tool(agent.tools, tool)
                    agent.mcp_servers.extend(servers)
                    if dynamic:
                        agent.metadata["dynamic_tools"] = True

        capabilities_expr = _agent_kw(call, "capabilities", tree, assignments)
        safety_capabilities: list[str] = []
        unmodeled_capabilities: list[str] = []
        if capabilities_expr is not None:
            elements = _resolve_sequence(capabilities_expr, sequences)
            if elements is None:
                agent.metadata["dynamic_tools"] = True
                _merge_tool(
                    agent.tools,
                    _dynamic_authority_tool(path, capabilities_expr, alias, "capabilities"),
                )
                _diagnostic(
                    graph,
                    path,
                    capabilities_expr,
                    "Pydantic AI capability collection could not be statically resolved.",
                )
            else:
                for element in elements:
                    if _harness_special_capability(
                        path,
                        element,
                        assignments,
                        agent,
                    ):
                        continue
                    if _is_declarative_capability_expr(element, assignments):
                        capability_tools, capability_servers, dynamic = _toolset_tools(
                            path,
                            element,
                            functions,
                            assignments,
                            sequences,
                            imports,
                            decorated_toolsets,
                            added_toolsets,
                        )
                        bundle_name = _call_name(element) or "Capability"
                        for capability_tool in capability_tools:
                            capability_tool.metadata["binding_origin"] = (
                                "pydantic_capability"
                            )
                            capability_tool.metadata["capability_bundle"] = (
                                bundle_name
                            )
                            _merge_tool(agent.tools, capability_tool)
                        for capability_server in capability_servers:
                            capability_server.metadata["binding_origin"] = (
                                "pydantic_capability"
                            )
                            capability_server.metadata["capability_bundle"] = (
                                bundle_name
                            )
                            agent.mcp_servers.append(capability_server)
                        if dynamic:
                            agent.metadata["dynamic_tools"] = True
                            agent.metadata.setdefault(
                                "partially_resolved_capabilities", []
                            ).append(bundle_name)
                        continue

                    tool, server, control = _capability_from_expr(
                        path,
                        element,
                        assignments,
                    )
                    if tool is not None:
                        _merge_tool(agent.tools, tool)
                        if tool.kind in {
                            "web_search",
                            "web_fetch",
                            "x_search",
                            "browser",
                        }:
                            agent.inputs.append(
                                InputSource(
                                    name=tool.name,
                                    trust="untrusted",
                                    kind="web",
                                    location=tool.location,
                                )
                            )
                    elif server is not None:
                        agent.mcp_servers.append(server)
                    elif control is not None:
                        safety_capabilities.append(control)
                    else:
                        unmodeled_capabilities.append(
                            _call_name(element.func)
                            if isinstance(element, ast.Call)
                            else _call_name(element) or "dynamic"
                        )
        if safety_capabilities:
            agent.metadata["safety_capabilities"] = sorted(set(safety_capabilities))
        if unmodeled_capabilities:
            agent.metadata["unmodeled_capabilities"] = sorted(
                set(unmodeled_capabilities)
            )
            _diagnostic(
                graph,
                path,
                capabilities_expr or call,
                "One or more Pydantic AI capabilities could not be semantically normalized.",
            )

        agents[alias] = agent
        graph.agents.append(agent)

    # Expand repository-local list-valued tool factories used through
    # post-construction registrar loops:
    #   tools = make_tools(...)
    #   for tool_fn in tools:
    #       agent.tool_plain(tool_fn)
    # Only statically enumerable nested functions are materialized.
    expanded_registrar_tools: dict[str, list[Tool]] = {}
    expanded_registrar_call_lines: set[int] = set()
    for loop in (
        node for node in ast.walk(tree)
        if isinstance(node, (ast.For, ast.AsyncFor))
        and isinstance(node.target, ast.Name)
    ):
        registrar_calls = [
            child
            for statement in loop.body
            for child in ast.walk(statement)
            if isinstance(child, ast.Call)
            and isinstance(child.func, ast.Attribute)
            and child.func.attr in {"tool", "tool_plain"}
            and child.args
            and isinstance(child.args[0], ast.Name)
            and child.args[0].id == loop.target.id
        ]
        if not registrar_calls:
            continue
        owner_function = _enclosing_function_node(tree, loop)
        iterable = loop.iter
        factory_call: ast.Call | None = iterable if isinstance(iterable, ast.Call) else None
        if isinstance(iterable, ast.Name) and owner_function is not None:
            value = _assignment_value_before(
                owner_function,
                iterable.id,
                getattr(loop, "lineno", 0) or 0,
            )
            if isinstance(value, ast.Call):
                factory_call = value
        if factory_call is None:
            continue
        factory_name = _call_name(factory_call.func)
        factory = functions.get(factory_name or "")
        if factory is None:
            continue
        members = _local_tool_factory_members(factory)
        if not members:
            continue
        for call in registrar_calls:
            owner = _dotted(call.func.value) or _call_name(call.func.value)
            if owner not in agents:
                continue
            expanded_registrar_call_lines.add(getattr(call, "lineno", 0) or 0)
            for member, conditional in members:
                tool = _tool_from_function(
                    path,
                    member,
                    source=f"local_factory:{factory.name}",
                )
                tool.metadata.update(
                    {
                        "binding_origin": f"agent.{call.func.attr}:local_tool_factory",
                        "tool_factory": factory.name,
                        "factory_collection_expanded": True,
                        "conditional_factory_member": conditional,
                    }
                )
                expanded_registrar_tools.setdefault(owner, []).append(tool)

    for owner, tools_from_factory in expanded_registrar_tools.items():
        for tool in tools_from_factory:
            _merge_tool(agents[owner].tools, tool)
        agents[owner].metadata["local_tool_factory_expanded"] = True

    # Pydantic AI also supports post-construction registration such as
    # `agent.tool(fn)` / `agent.tool_plain(fn)`. These calls are explicit
    # authority bindings and must not be confused with decorator-only syntax.
    for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
        if not isinstance(call.func, ast.Attribute):
            continue
        owner = _dotted(call.func.value) or _call_name(call.func.value)
        if owner not in agents or call.func.attr not in {"tool", "tool_plain"}:
            continue
        target = call.args[0] if call.args else _kw(call, "func")
        if target is None:
            continue
        if (getattr(call, "lineno", 0) or 0) in expanded_registrar_call_lines:
            continue
        tool = _tool_from_reference(
            path,
            target,
            functions,
            assignments,
            imports,
        )
        if tool is None:
            continue
        approval = _approval_from_call(call)
        if approval is not None:
            tool.approval = approval
        tool.metadata["binding_origin"] = f"agent.{call.func.attr}"
        _merge_tool(agents[owner].tools, tool)

    for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
        if not isinstance(call.func, ast.Attribute):
            continue
        owner = _dotted(call.func.value) or _call_name(call.func.value)
        if owner not in agents or call.func.attr not in _AGENT_RUN_METHODS:
            continue
        toolsets_expr = _agent_kw(call, "toolsets", tree, assignments)
        if toolsets_expr is None:
            continue
        elements = _resolve_sequence(toolsets_expr, sequences)
        if elements is None:
            agent = agents[owner]
            configured_mcp = _configured_mcp_catalogue_from_expr(
                path,
                toolsets_expr,
                assignments,
                alias=f"{owner}:runtime-configured-mcp",
            )
            if configured_mcp is not None:
                agent.mcp_servers.append(configured_mcp)
                agent.metadata["runtime_toolsets"] = True
                agent.metadata["configuration_dependent_mcp_toolsets"] = True
            _diagnostic(
                graph,
                path,
                toolsets_expr,
                (
                    "Runtime Pydantic AI toolsets are configuration-derived; the MCP "
                    "catalogue is bound but its concrete tools/transports are unresolved."
                    if configured_mcp is not None
                    else "Runtime Pydantic AI toolsets could not be statically resolved."
                ),
            )
            continue
        agent = agents[owner]
        agent.metadata["runtime_toolsets"] = True
        for element in elements:
            tools, servers, dynamic = _toolset_tools(
                path,
                element,
                functions,
                assignments,
                sequences,
                imports,
                decorated_toolsets,
                added_toolsets,
            )
            for tool in tools:
                _merge_tool(agent.tools, tool)
            agent.mcp_servers.extend(servers)
            if dynamic:
                agent.metadata["dynamic_tools"] = True

    for agent in graph.agents:
        workspace_spec = agent.metadata.pop("_workspace_spec", None)
        if isinstance(workspace_spec, dict):
            _apply_workspace_semantics(agent, workspace_spec)

    _bind_local_agent_delegations(agents, functions)

    for agent in graph.agents:
        for tool in agent.tools:
            function = functions.get(tool.name)
            if function is None:
                continue
            derived_destinations, derived_metadata = _function_search_result_url_semantics(
                path,
                function,
                functions,
            )
            if not derived_destinations:
                continue
            tool.capabilities.add("network.external")
            tool.destinations.extend(
                destination
                for destination in derived_destinations
                if destination not in tool.destinations
            )
            tool.metadata.update(derived_metadata)

    # Agent.to_web() explicitly exposes the configured agent through
    # Pydantic AI's generated web application. Preserve that public/user-facing
    # ingress so externally wrapped tools can participate in end-to-end authority
    # paths even when their implementation lives outside the repository.
    for web_call in (
        node for node in ast.walk(tree) if isinstance(node, ast.Call)
    ):
        if not isinstance(web_call.func, ast.Attribute):
            continue
        if web_call.func.attr != "to_web":
            continue
        owner = _dotted(web_call.func.value) or _call_name(web_call.func.value)
        agent = agents.get(owner or "")
        if agent is None:
            continue
        basis = "pydantic_ai_to_web_input"
        if any(item.metadata.get("basis") == basis for item in agent.inputs):
            continue
        agent.inputs.append(
            InputSource(
                name="to_web:public-input",
                trust="untrusted",
                kind="web",
                location=_location(path, web_call),
                metadata={
                    "basis": basis,
                    "runtime_invocation_proven": True,
                    "surface": "pydantic_ai.to_web",
                },
            )
        )

    _annotate_cli_run_inputs(path, tree, agents)
    _annotate_public_wrapper_run_inputs(path, tree, agents)

    bound_mcp_keys = {
        (
            server.name,
            str(server.location.path) if server.location else "",
            server.location.line if server.location else 0,
        )
        for agent in graph.agents
        for server in agent.mcp_servers
    }
    for server in declared_mcp_servers.values():
        key = (
            server.name,
            str(server.location.path) if server.location else "",
            server.location.line if server.location else 0,
        )
        if key in bound_mcp_keys:
            continue
        server.metadata.setdefault("topology_visible_unbound", True)
        server.metadata.setdefault("binding_state", "unbound")
        server.metadata.setdefault("discovery_source", "pydantic_ai_mcp_declaration")
        graph.unbound_mcp_servers.append(server)

    return graph
