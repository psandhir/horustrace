from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

from horustrace.heuristics import (
    corroborate_name_inferred_authority,
    infer_capabilities,
    resource_is_broad,
)
from horustrace.effect_semantics import is_local_collection_mutation\nfrom horustrace.models import (
    Agent,
    Graph,
    Identity,
    InputSource,
    MCPServer,
    NetworkDestination,
    ResourceScope,
    SourceLocation,
    Tool,
)

AGENT_TYPES = {"Agent", "LlmAgent", "SequentialAgent", "ParallelAgent", "LoopAgent", "Workflow", "RemoteA2aAgent"}
WORKFLOW_TYPES = {"SequentialAgent", "ParallelAgent", "LoopAgent", "Workflow"}
CODE_EXECUTORS = {
    "UnsafeLocalCodeExecutor": (False, "local"),
    "BuiltInCodeExecutor": (True, "provider-managed"),
    "AgentEngineSandboxCodeExecutor": (True, "agent-runtime"),
    "GkeCodeExecutor": (True, "gke"),
}
REMOTE_MCP_PARAMS = {"SseConnectionParams": "sse", "StreamableHTTPConnectionParams": "streamable-http"}
STDIO_MCP_PARAMS = {"StdioConnectionParams", "StdioServerParameters"}

# Security semantics for current ADK built-ins. Unknown toolsets still receive name-based inference.
BUILTIN_TOOL_CAPABILITIES: dict[str, set[str]] = {
    "ExecuteBashTool": {"process.execute", "data.read", "data.write", "network.external"},
    "EnvironmentToolset": {"process.execute", "data.read", "data.write"},
    "ComputerUseToolset": {"computer.control", "data.read", "data.write", "external.write", "network.external"},
    "GoogleSearchTool": {"data.read", "network.external"},
    "google_search": {"data.read", "network.external"},
    "UrlContextTool": {"data.read", "network.external"},
    "url_context": {"data.read", "network.external"},
    "load_web_page": {"data.read", "network.external"},
    "DiscoveryEngineSearchTool": {"data.read", "network.external"},
    "VertexAiSearchTool": {"data.read", "network.external"},
    "VertexAiRagRetrieval": {"data.read", "network.external"},
    "EnterpriseWebSearchTool": {"data.read", "network.external"},
    "BigQueryToolset": {"data.read", "data.write", "network.external"},
    "BigtableToolset": {"data.read", "data.write", "network.external"},
    "DataAgentToolset": {"data.read", "data.write", "network.external"},
    "GmailToolset": {"data.read", "data.write", "external.write", "network.external"},
    "CalendarToolset": {"data.read", "data.write", "external.write", "network.external"},
    "DocsToolset": {"data.read", "data.write", "network.external"},
    "SheetsToolset": {"data.read", "data.write", "network.external"},
    "SlidesToolset": {"data.read", "data.write", "network.external"},
    "YoutubeToolset": {"data.read", "data.write", "external.write", "network.external"},
    "GoogleApiToolset": {"data.read", "data.write", "external.write", "network.external"},
    "APIHubToolset": {"data.read", "data.write", "external.write", "network.external"},
    "ApplicationIntegrationToolset": {"data.read", "data.write", "external.write", "network.external"},
    "OpenAPIToolset": {"data.read", "data.write", "external.write", "network.external"},
    "RestApiTool": {"data.read", "data.write", "external.write", "network.external"},
    "LoadMemoryTool": {"data.read"},
    "load_memory": {"data.read"},
    "LoadArtifactsTool": {"data.read"},
    "load_artifacts_tool": {"data.read"},
    "load_artifacts": {"data.read"},
    "LoadMcpResourceTool": {"data.read", "mcp.remote"},
    "TransferToAgentTool": {"agent.delegate"},
}


# Positive, source-backed minimum role hints for managed ADK tools.
# These are deliberately incomplete and must not be used as a complete
# least-privilege baseline for excess-authority decisions.
BUILTIN_TOOL_REQUIRED_ROLES: dict[str, set[str]] = {
    "BigQueryToolset": {
        "roles/bigquery.jobUser",
        "roles/bigquery.dataViewer",
    },
    "DiscoveryEngineSearchTool": {"roles/discoveryengine.viewer"},
    "VertexAiSearchTool": {"roles/discoveryengine.viewer"},
}

RETRIEVAL_TOOLS = {
    "GoogleSearchTool", "google_search", "UrlContextTool", "url_context", "load_web_page",
    "DiscoveryEngineSearchTool", "VertexAiSearchTool", "VertexAiRagRetrieval",
    "EnterpriseWebSearchTool",
}

URL_CONTEXT_TOOLS = {"UrlContextTool", "url_context", "load_web_page"}
BROAD_TOOLSETS = {
    "GoogleApiToolset", "GmailToolset", "CalendarToolset", "DocsToolset", "SheetsToolset", "SlidesToolset",
    "YoutubeToolset", "APIHubToolset", "ApplicationIntegrationToolset", "OpenAPIToolset", "BigQueryToolset",
    "BigtableToolset", "DataAgentToolset",
}


def _location(path: Path, node: ast.AST) -> SourceLocation:
    return SourceLocation(path=path, line=getattr(node, "lineno", 1), column=getattr(node, "col_offset", 0) + 1)


def _apply_retrieval_network_semantics(tool: Tool, tool_name: str) -> None:
    """Distinguish the managed retrieval service from the content destination."""
    if tool_name not in RETRIEVAL_TOOLS:
        return
    tool.metadata["untrusted_input"] = True
    tool.metadata["network_provider"] = "google"

    if tool_name in URL_CONTEXT_TOOLS:
        # Google hosts the retrieval mechanism, but the model/tool argument can
        # still select the content URL being dereferenced. Keep those two
        # dimensions separate instead of treating the target as provider-fixed.
        tool.metadata.update(
            {
                "network_scope": "dynamic_destination",
                "provider_network_scope": "fixed_managed_service",
                "model_selected_url_fetch": True,
                "destination_provenance": "model_selected_url_argument",
                "network_abstraction": "url_context",
            }
        )
        if not any(
            destination.target == "<model-selected-url>"
            for destination in tool.destinations
        ):
            tool.destinations.append(
                NetworkDestination(
                    target="<model-selected-url>",
                    restricted=False,
                    location=tool.location,
                    metadata={
                        "source": "model_selected_url_argument",
                        "network_scope": "dynamic_destination",
                        "server_side_fetch": True,
                        "provider_network_scope": "fixed_managed_service",
                        "network_abstraction": "url_context",
                    },
                )
            )
    else:
        tool.metadata["network_scope"] = "fixed_managed_service"


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _dotted_name(node: ast.AST) -> str | None:
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
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
    return next((kw.value for kw in call.keywords if kw.arg == name), None)


def _arg(call: ast.Call, pos: int, kw_name: str) -> ast.AST | None:
    value = _kw(call, kw_name)
    if value is not None:
        return value
    return call.args[pos] if len(call.args) > pos else None


def _bool(node: ast.AST | None) -> bool | None:
    value = _literal(node)
    return value if isinstance(value, bool) else None


def _string(node: ast.AST | None) -> str | None:
    value = _literal(node)
    return value if isinstance(value, str) else None


def _list_strings(node: ast.AST | None) -> list[str]:
    value = _literal(node)
    if isinstance(value, (list, tuple, set)):
        return [str(x) for x in value if isinstance(x, (str, int, float))]
    if isinstance(value, str):
        return [value]
    return []


def _fixed_url_origin(node: ast.AST | None) -> str | None:
    """Return a fixed scheme/host when only the URL path/query is dynamic."""
    if node is None:
        return None

    prefix = ""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        prefix = node.value
    elif isinstance(node, ast.JoinedStr):
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                prefix += value.value
            else:
                break
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _fixed_url_origin(node.left)
        if left:
            return left
        if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
            prefix = node.left.value

    if not prefix.startswith(("http://", "https://")):
        return None
    from urllib.parse import urlparse

    parsed = urlparse(prefix)
    if not parsed.scheme or not parsed.hostname:
        return None
    port = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme}://{parsed.hostname}{port}"


def _uses_google_adk(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("google.adk"):
            return True
        if isinstance(node, ast.Import) and any(alias.name.startswith("google.adk") for alias in node.names):
            return True
    return False


def is_google_adk_file(path: Path) -> bool:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return False
    return _uses_google_adk(tree)


def _infer_function_capabilities(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[set[str], list[NetworkDestination]]:
    name_capabilities = set(infer_capabilities(node.name))
    caps: set[str] = set()

    # Generic "execute" in a function name is not enough to prove process
    # execution (for example execute_sql or Google API .execute()).
    name_tokens = set(
        node.name.lower().replace("-", "_").replace(".", "_").split("_")
    )
    if "process.execute" in caps and not (
        name_tokens
        & {"shell", "bash", "powershell", "command", "terminal", "exec"}
    ):
        caps.discard("process.execute")

    destinations: list[NetworkDestination] = []

    literal_urls: dict[str, str] = {}
    fixed_url_origins: dict[str, str] = {}
    for statement in ast.walk(node):
        if (
            isinstance(statement, ast.Assign)
            and isinstance(statement.value, ast.Constant)
            and isinstance(statement.value.value, str)
            and statement.value.value.startswith(("http://", "https://"))
        ):
            for target_node in statement.targets:
                if isinstance(target_node, ast.Name):
                    literal_urls[target_node.id] = statement.value.value
                    origin = _fixed_url_origin(statement.value)
                    if origin:
                        fixed_url_origins[target_node.id] = origin
        elif (
            isinstance(statement, ast.AnnAssign)
            and isinstance(statement.target, ast.Name)
            and isinstance(statement.value, ast.Constant)
            and isinstance(statement.value.value, str)
            and statement.value.value.startswith(("http://", "https://"))
        ):
            literal_urls[statement.target.id] = statement.value.value
            origin = _fixed_url_origin(statement.value)
            if origin:
                fixed_url_origins[statement.target.id] = origin
        elif isinstance(statement, ast.Assign):
            origin = _fixed_url_origin(statement.value)
            if origin:
                for target_node in statement.targets:
                    if isinstance(target_node, ast.Name):
                        fixed_url_origins[target_node.id] = origin
        elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
            origin = _fixed_url_origin(statement.value)
            if origin:
                fixed_url_origins[statement.target.id] = origin

    # urllib.request.Request(url, ...) is a fixed wrapper around the URL
    # expression, not a new caller-selected destination. Track simple request
    # aliases so urlopen(req) preserves the underlying fixed host.
    request_origins: dict[str, str] = {}
    for statement in ast.walk(node):
        if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
            continue
        value = statement.value
        if not isinstance(value, ast.Call):
            continue
        called = (_dotted_name(value.func) or _call_name(value.func) or "").lower()
        if called not in {"urllib.request.request", "request"}:
            continue
        url_expr = value.args[0] if value.args else _kw(value, "url")
        origin = None
        if isinstance(url_expr, ast.Name):
            origin = fixed_url_origins.get(url_expr.id)
        origin = origin or _fixed_url_origin(url_expr)
        if origin is None:
            continue
        targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
        for target_node in targets:
            if isinstance(target_node, ast.Name):
                request_origins[target_node.id] = origin

    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue

        called = (_dotted_name(child.func) or _call_name(child.func) or "").lower()
        leaf = (_call_name(child.func) or "").lower()

        sql_capabilities = sql_call_capabilities(child)
        if sql_capabilities:
            caps.update(sql_capabilities)

        # Only known execution APIs establish process execution.
        if (
            called in {"exec", "eval", "compile", "builtins.exec", "builtins.eval", "builtins.compile"}
            or called == "os.system"
            or called == "os.popen"
            or called.startswith("subprocess.")
            or "create_subprocess_" in called
            or called.endswith(".popen")
        ):
            caps.add("process.execute")

        if called.endswith("open") or called == "open":
            mode = _string(_arg(child, 1, "mode")) or "r"
            caps.add(
                "data.write"
                if any(ch in mode for ch in "wax+")
                else "data.read"
            )

        if leaf in {
            "get",
            "list",
            "search",
            "fetch",
            "download",
            "export",
            "get_media",
        }:
            caps.add("data.read")
        local_collection_mutation = is_local_collection_mutation(child)
        if leaf in {
            "set",
            "create",
            "update",
            "insert",
            "upload",
            "write",
            "save_artifact",
        } and not local_collection_mutation:
            caps.add("data.write")
        if leaf in {"delete", "remove", "destroy", "purge"} and not local_collection_mutation:
            caps.update({"data.write", "destructive.write"})

        gcs_write_methods = {
            "upload_from_file",
            "upload_from_filename",
            "upload_from_string",
            "compose",
            "rewrite",
        }
        gcs_read_methods = {
            "download_as_bytes",
            "download_as_string",
            "download_as_text",
            "download_to_file",
            "download_to_filename",
        }
        if leaf in gcs_write_methods | gcs_read_methods:
            if leaf in gcs_write_methods:
                caps.update({"data.write", "external.write"})
            else:
                caps.add("data.read")
            caps.add("network.external")
            destinations.append(
                NetworkDestination(
                    target="<google-cloud-storage>",
                    restricted=True,
                    metadata={
                        "source": "provider_sdk",
                        "network_scope": "fixed_provider_network",
                        "provider": "google",
                        "service": "cloud-storage",
                    },
                )
            )

        network_call = any(
            marker in called
            for marker in (
                "requests.",
                "httpx.",
                "aiohttp",
                "urllib.request",
                "session.get",
                "session.post",
                "session.put",
                "session.patch",
                "session.delete",
            )
        )
        if network_call:
            caps.add("network.external")
            caps.update(
                http_mutation_capabilities(
                    child,
                    function_name=node.name,
                )
            )

            target_expr = child.args[0] if child.args else None
            target = _string(target_expr)

            if target and target.startswith(("http://", "https://")):
                destinations.append(
                    NetworkDestination(
                        target=target,
                        restricted=False,
                        metadata={"source": "literal_url", "network_scope": "fixed_literal_destination"},
                    )
                )
            else:
                fixed_origin = None
                if isinstance(target_expr, ast.Name):
                    fixed_origin = (
                        fixed_url_origins.get(target_expr.id)
                        or request_origins.get(target_expr.id)
                    )
                fixed_origin = fixed_origin or _fixed_url_origin(target_expr)
                if fixed_origin:
                    destinations.append(
                        NetworkDestination(
                            target=fixed_origin,
                            restricted=True,
                            metadata={
                                "source": "fixed_url_origin",
                                "network_scope": "fixed_provider_network",
                                "dynamic_path": True,
                            },
                        )
                    )
                    continue

                # Retain literal fallbacks as possible destinations, but also
                # record that the actual call target can be dynamic.
                possible_urls: list[str] = []
                if target_expr is not None:
                    for part in ast.walk(target_expr):
                        possible: str | None = None
                        if (
                            isinstance(part, ast.Constant)
                            and isinstance(part.value, str)
                            and part.value.startswith(("http://", "https://"))
                        ):
                            possible = part.value
                        elif isinstance(part, ast.Name):
                            possible = literal_urls.get(part.id)

                        if possible and possible not in possible_urls:
                            possible_urls.append(possible)

                for possible in possible_urls:
                    destinations.append(
                        NetworkDestination(
                            target=possible,
                            restricted=False,
                            metadata={"source": "literal_url", "network_scope": "fixed_literal_destination"},
                        )
                    )

                destinations.append(
                    NetworkDestination(
                        target="<dynamic-url>",
                        restricted=False,
                        metadata={"source": "dynamic_network_call", "network_scope": "dynamic_destination"},
                    )
                )

        # High-signal secret access only; arbitrary dict.get() is not secret
        # access.
        if (
            "secretmanager" in called
            or leaf in {"get_secret", "access_secret_version"}
            or "vault" in called
        ):
            caps.add("secrets.read")

        if called in {"os.getenv", "os.environ.get"}:
            env_name = _string(child.args[0]) if child.args else None
            if env_name and any(
                marker in env_name.lower()
                for marker in (
                    "secret",
                    "token",
                    "password",
                    "api_key",
                    "apikey",
                    "private_key",
                    "credential",
                )
            ):
                caps.add("secrets.read")

    body_capabilities = set(caps)
    corroborated_name_capabilities, _ = corroborate_name_inferred_authority(
        name_capabilities,
        body_capabilities,
    )
    caps = body_capabilities | corroborated_name_capabilities

    unique: list[NetworkDestination] = []
    seen: set[tuple[str, bool, str]] = set()
    for destination in destinations:
        key = (
            destination.target,
            destination.restricted,
            str(destination.metadata.get("source") or ""),
        )
        if key not in seen:
            seen.add(key)
            unique.append(destination)

    return caps, unique

def _resolve_sequence(expr: ast.AST | None, sequences: dict[str, list[ast.AST]]) -> list[ast.AST]:
    if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        return list(expr.elts)
    if isinstance(expr, ast.Name):
        return list(sequences.get(expr.id, []))
    return [expr] if expr is not None else []


def _resolve_call(expr: ast.AST | None, calls: dict[str, ast.Call]) -> ast.Call | None:
    if isinstance(expr, ast.Call):
        return expr
    if isinstance(expr, ast.Name):
        return calls.get(expr.id)
    return None


def _dynamic_tool_collection(
    path: Path,
    expr: ast.AST | None,
    calls: dict[str, ast.Call],
) -> Tool | None:
    """Preserve source-bound runtime tool collections without inventing members."""
    if not isinstance(expr, ast.Name):
        return None
    source_call = calls.get(expr.id)
    if source_call is None:
        return None
    called = _dotted_name(source_call.func) or _call_name(source_call.func) or ""
    leaf = (_call_name(source_call.func) or "").lower()
    if "tool" not in leaf and "tool" not in called.lower():
        return None
    catalogue = _string(source_call.args[0]) if source_call.args else None
    return Tool(
        name=expr.id,
        kind="dynamic_tool_collection",
        capabilities=set(),
        location=_location(path, source_call),
        metadata={
            "framework": "google-adk",
            "binding_origin": "source_bound_dynamic_tool_collection",
            "dynamic_bound_collection": True,
            "catalogue_source": called,
            "catalogue_name": catalogue,
            "tool_scope_unresolved": True,
        },
    )


def _tool_filter(call: ast.Call) -> tuple[list[str], bool]:
    node = _kw(call, "tool_filter")
    values = _list_strings(node)
    if values:
        return values, False
    if node is not None:
        return [], True
    return [], False


def _execution_constraints(call: ast.Call) -> dict[str, bool]:
    """Extract explicit sandbox limits without assuming executor defaults."""
    timeout = False
    for key in ("timeout", "timeout_seconds", "max_execution_time", "max_execution_time_seconds"):
        value = _literal(_kw(call, key))
        if isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0:
            timeout = True
            break

    network_disabled = False
    for key in ("allow_network", "network_access", "network_enabled"):
        value = _literal(_kw(call, key))
        if value is False or isinstance(value, str) and value.lower() in {"none", "disabled", "deny"}:
            network_disabled = True
            break

    filesystem_constrained = False
    for key in ("working_dir", "workspace", "allowed_paths", "allowed_directories"):
        value = _literal(_kw(call, key))
        values = value if isinstance(value, list) else [value]
        if any(isinstance(item, str) and item and not resource_is_broad(item) for item in values):
            filesystem_constrained = True
            break

    return {
        "sandbox_timeout_configured": timeout,
        "sandbox_network_disabled": network_disabled,
        "sandbox_filesystem_constrained": filesystem_constrained,
        "sandbox_constraints_complete": timeout and network_disabled and filesystem_constrained,
    }


def _auth_present(call: ast.Call, nested: ast.Call | None = None) -> bool | None:
    auth_headers = {"authorization", "x-api-key", "x-goog-api-key", "proxy-authorization"}
    for c in (call, nested):
        if c is None:
            continue
        if any(_kw(c, name) is not None for name in ("auth_scheme", "auth_credential", "header_provider")):
            return True
        headers_node = _kw(c, "headers")
        if isinstance(headers_node, ast.Dict):
            for key_node in headers_node.keys:
                key = _string(key_node)
                if key and key.lower() in auth_headers:
                    return True
        elif headers_node is not None:
            return None
        headers = _literal(headers_node)
        if isinstance(headers, dict) and auth_headers & {str(k).lower() for k in headers}:
            return True
    return False


def _environment_subscript_key(node: ast.AST | None) -> str | None:
    if not isinstance(node, ast.Subscript):
        return None
    owner = _dotted_name(node.value)
    if owner != "os.environ":
        return None
    return _string(node.slice)


def _module_configuration_sources(tree: ast.AST) -> dict[str, str]:
    """Map module-level aliases to source-visible operator configuration keys."""
    result: dict[str, str] = {}
    for node in getattr(tree, "body", []):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        aliases = [target.id for target in targets if isinstance(target, ast.Name)]
        if not aliases:
            continue

        source: str | None = _environment_subscript_key(node.value)
        if source is None and isinstance(node.value, ast.Call):
            called = (_dotted_name(node.value.func) or "").lower()
            if called in {"os.getenv", "os.environ.get"}:
                source = _string(node.value.args[0]) if node.value.args else None
                source = source or "environment"
        if source is None and isinstance(node.value, ast.Name):
            source = result.get(node.value.id)
        if source is None:
            continue
        for alias in aliases:
            result[alias] = source
    return result


def _configuration_source_from_expr(
    node: ast.AST | None,
    configuration_sources: dict[str, str],
) -> str | None:
    """Resolve an expression made only from constants and one configuration source."""
    if node is None:
        return None
    direct = _environment_subscript_key(node)
    if direct:
        return direct
    if isinstance(node, ast.Call):
        called = (_dotted_name(node.func) or "").lower()
        if called in {"os.getenv", "os.environ.get"}:
            key = _string(node.args[0]) if node.args else None
            return key or "environment"
        return None
    if isinstance(node, ast.Name):
        return configuration_sources.get(node.id)
    if isinstance(node, ast.Constant):
        return None
    if isinstance(node, ast.JoinedStr):
        sources: set[str] = set()
        for value in node.values:
            if isinstance(value, ast.Constant):
                continue
            expr = value.value if isinstance(value, ast.FormattedValue) else value
            source = _configuration_source_from_expr(expr, configuration_sources)
            if source is None:
                return None
            sources.add(source)
        return next(iter(sources)) if len(sources) == 1 else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        sources: set[str] = set()
        for part in (node.left, node.right):
            if isinstance(part, ast.Constant):
                continue
            source = _configuration_source_from_expr(part, configuration_sources)
            if source is None:
                return None
            sources.add(source)
        return next(iter(sources)) if len(sources) == 1 else None
    return None


def _apply_operator_configured_function_destinations(
    tool: Tool,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    configuration_sources: dict[str, str],
) -> None:
    """Replace generic dynamic HTTP destinations with source-proven operator config."""
    local_configuration_sources = dict(configuration_sources)
    changed = True
    while changed:
        changed = False
        for statement in ast.walk(function):
            if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
                continue
            value = statement.value
            if value is None:
                continue
            source = _configuration_source_from_expr(
                value,
                local_configuration_sources,
            )
            if source is None and isinstance(value, ast.Call):
                called = (_dotted_name(value.func) or _call_name(value.func) or "").lower()
                if called in {"urllib.request.request", "request"}:
                    url_expr = value.args[0] if value.args else _kw(value, "url")
                    source = _configuration_source_from_expr(
                        url_expr,
                        local_configuration_sources,
                    )
            if source is None:
                continue
            targets = (
                statement.targets
                if isinstance(statement, ast.Assign)
                else [statement.target]
            )
            for target in targets:
                if (
                    isinstance(target, ast.Name)
                    and local_configuration_sources.get(target.id) != source
                ):
                    local_configuration_sources[target.id] = source
                    changed = True

    operator_destinations: list[NetworkDestination] = []
    for call in (node for node in ast.walk(function) if isinstance(node, ast.Call)):
        called = (_dotted_name(call.func) or _call_name(call.func) or "").lower()
        if not any(
            marker in called
            for marker in (
                "requests.",
                "httpx.",
                "aiohttp",
                "urllib.request",
                "session.get",
                "session.post",
                "session.put",
                "session.patch",
                "session.delete",
            )
        ):
            continue
        target_expr = call.args[0] if call.args else _kw(call, "url")
        source = _configuration_source_from_expr(
            target_expr,
            local_configuration_sources,
        )
        if source is None:
            continue
        operator_destinations.append(
            NetworkDestination(
                target=f"<operator-configured:{source}>",
                restricted=True,
                location=tool.location,
                metadata={
                    "source": "operator_configuration",
                    "network_scope": "operator_configured_destination",
                    "configuration_source": source,
                    "destination_constraint_basis": "operator_configuration",
                },
            )
        )

    if not operator_destinations:
        return

    tool.destinations = [
        destination
        for destination in tool.destinations
        if not (
            destination.target == "<dynamic-url>"
            and destination.metadata.get("network_scope") == "dynamic_destination"
        )
    ]
    seen = {
        (destination.target, destination.restricted)
        for destination in tool.destinations
    }
    for destination in operator_destinations:
        key = (destination.target, destination.restricted)
        if key not in seen:
            tool.destinations.append(destination)
            seen.add(key)
    tool.metadata["network_scope"] = "operator_configured_destination"
    tool.metadata["destination_constraint_basis"] = "operator_configuration"
    tool.metadata["configuration_sources"] = sorted(
        {
            str(destination.metadata["configuration_source"])
            for destination in operator_destinations
        }
    )


def _operator_configuration_source(
    node: ast.AST | None,
    calls: dict[str, ast.Call],
) -> str | None:
    """Return the configuration key for an environment-derived expression."""
    subscript_key = _environment_subscript_key(node)
    if subscript_key:
        return subscript_key
    resolved = _resolve_call(node, calls)
    if resolved is not None:
        called = (_dotted_name(resolved.func) or "").lower()
        if called in {"os.getenv", "os.environ.get"}:
            key = _string(resolved.args[0]) if resolved.args else None
            return key or "environment"

    if node is None:
        return None
    sources: set[str] = set()
    for child in ast.walk(node):
        if child is node or not isinstance(child, ast.Name):
            continue
        nested = _resolve_call(child, calls)
        if nested is None:
            continue
        called = (_dotted_name(nested.func) or "").lower()
        if called not in {"os.getenv", "os.environ.get"}:
            continue
        key = _string(nested.args[0]) if nested.args else None
        sources.add(key or "environment")
    return next(iter(sources)) if len(sources) == 1 else None


def _openapi_servers(
    path: Path,
    call: ast.Call,
    calls: dict[str, ast.Call],
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> list[str]:
    """Recover fixed OpenAPI server origins from source-visible local specs."""
    spec_node = _kw(call, "spec_dict") or _kw(call, "spec_str")
    payload: object | None = None

    literal = _literal(spec_node)
    if isinstance(literal, dict):
        payload = literal
    elif isinstance(literal, str):
        try:
            decoded = json.loads(literal)
        except json.JSONDecodeError:
            decoded = None
        if isinstance(decoded, dict):
            payload = decoded

    if payload is None and isinstance(spec_node, ast.Name):
        loader_call = calls.get(spec_node.id)
        loader_name = _call_name(loader_call.func) if loader_call is not None else None
        loader = functions.get(loader_name or "")
        if loader is not None:
            base = path.parent.resolve()
            for child in ast.walk(loader):
                if not (
                    isinstance(child, ast.Constant)
                    and isinstance(child.value, str)
                    and child.value.lower().endswith(".json")
                ):
                    continue
                candidate = (path.parent / child.value).resolve()
                try:
                    candidate.relative_to(base)
                except ValueError:
                    continue
                try:
                    decoded = json.loads(candidate.read_text(encoding="utf-8"))
                except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                    continue
                if isinstance(decoded, dict):
                    payload = decoded
                    break

    if not isinstance(payload, dict):
        return []

    servers: list[str] = []
    for item in payload.get("servers", []) or []:
        if not isinstance(item, dict):
            continue
        value = item.get("url")
        if not isinstance(value, str) or not value.startswith(("http://", "https://")):
            continue
        origin = _fixed_url_origin(ast.Constant(value=value))
        if origin and origin not in servers:
            servers.append(origin)
    return servers


def _mcp_from_toolset(path: Path, call: ast.Call, alias: str, calls: dict[str, ast.Call]) -> MCPServer | None:
    if _call_name(call.func) not in {"McpToolset", "MCPToolset"}:
        return None
    conn = _resolve_call(_kw(call, "connection_params"), calls)
    transport = "unknown"
    url: str | None = None
    command: str | None = None
    args: list[str] = []
    auth: bool | None = None
    metadata: dict[str, Any] = {"framework": "google-adk"}

    if conn:
        conn_name = _call_name(conn.func) or ""
        if conn_name in REMOTE_MCP_PARAMS:
            transport = REMOTE_MCP_PARAMS[conn_name]
            url_node = _kw(conn, "url")
            url = _string(url_node)
            if url_node is not None and url is None:
                metadata["dynamic_mcp_endpoint"] = True
                configuration_source = _operator_configuration_source(
                    url_node, calls
                )
                if configuration_source is not None:
                    metadata["dynamic_mcp_endpoint_basis"] = (
                        "operator_configuration"
                    )
                    metadata["configuration_source"] = configuration_source
            auth = _auth_present(call, conn)
        elif conn_name in STDIO_MCP_PARAMS:
            transport = "stdio"
            server_params = _resolve_call(_kw(conn, "server_params"), calls) or conn
            command = _string(_kw(server_params, "command"))
            args = _list_strings(_kw(server_params, "args"))
        metadata["connection_type"] = conn_name
    allowed, dynamic_filter = _tool_filter(call)
    if dynamic_filter:
        metadata["dynamic_tool_filter"] = True
    require_confirmation = _bool(_kw(call, "require_confirmation"))
    return MCPServer(
        name=alias,
        transport=transport,
        url=url,
        command=command,
        args=args,
        authenticated=auth if url else None,
        approval=require_confirmation,
        allowed_tools=allowed,
        guardrails=require_confirmation is True,
        location=_location(path, call),
        metadata=metadata,
    )


def _tool_from_call(
    path: Path,
    call: ast.Call,
    alias: str,
    calls: dict[str, ast.Call],
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> Tool | None:
    name = _call_name(call.func) or ""

    if name in {"FunctionTool", "LongRunningFunctionTool", "AuthenticatedFunctionTool"}:
        func_node = _arg(call, 0, "func")
        func_name = _call_name(func_node) or alias
        caps = set(infer_capabilities(func_name))
        destinations: list[NetworkDestination] = []
        if func_name in functions:
            inferred, destinations = _infer_function_capabilities(functions[func_name])
            caps.update(inferred)
        approval = _bool(_kw(call, "require_confirmation"))
        return Tool(
            name=func_name,
            kind="adk_function",
            capabilities=caps,
            approval=approval,
            guardrails=approval is True,
            destinations=destinations,
            location=_location(path, call),
            metadata={"framework": "google-adk", "wrapper": name, "authenticated": name == "AuthenticatedFunctionTool"},
        )

    if name == "AgentTool":
        target_node = _arg(call, 0, "agent")
        target = _call_name(target_node) or _string(target_node) or "unknown-agent"
        if isinstance(target_node, ast.Name) and target_node.id in calls:
            target_call = calls[target_node.id]
            if (_call_name(target_call.func) or "") in AGENT_TYPES:
                target = _string(_kw(target_call, "name")) or target
        return Tool(
            name=alias,
            kind="adk_agent_tool",
            capabilities={"agent.delegate"},
            location=_location(path, call),
            metadata={
                "framework": "google-adk",
                "delegate_target": target,
                "include_plugins": _bool(_kw(call, "include_plugins")),
                "skip_summarization": _bool(_kw(call, "skip_summarization")),
            },
        )

    if name in CODE_EXECUTORS:
        sandboxed, executor_kind = CODE_EXECUTORS[name]
        metadata = {
            "framework": "google-adk", "code_executor": name, "sandboxed": sandboxed,
            "executor_kind": executor_kind,
        }
        if sandboxed and executor_kind != "provider-managed":
            metadata.update(_execution_constraints(call))
        elif executor_kind == "provider-managed":
            metadata.update({"execution_boundary": "provider-managed", "sandbox_constraints_applicable": False})
        capabilities = (
            {"provider.code.execute"}
            if executor_kind == "provider-managed"
            else {"process.execute", "data.read", "data.write"}
        )
        return Tool(
            name=alias,
            kind="adk_code_executor",
            capabilities=capabilities,
            approval=None,
            guardrails=sandboxed,
            location=_location(path, call),
            metadata=metadata,
        )

    if name in BUILTIN_TOOL_CAPABILITIES or name.endswith(("Toolset", "Tool")):
        caps = set(BUILTIN_TOOL_CAPABILITIES.get(name, set())) or set(infer_capabilities(name))
        approval = _bool(_kw(call, "require_confirmation"))
        allowed, dynamic_filter = _tool_filter(call)
        metadata: dict[str, Any] = {
            "framework": "google-adk",
            "adk_builtin": name,
            "tool_filter": allowed,
            "dynamic_tool_filter": dynamic_filter,
        }
        if name == "OpenAPIToolset":
            openapi_servers = _openapi_servers(
                path, call, calls, functions
            )
            if openapi_servers:
                metadata["network_scope"] = "explicit_destination"
                metadata["openapi_servers"] = openapi_servers
                metadata["destination_constraint_basis"] = (
                    "openapi_servers"
                )
        if name == "ApplicationIntegrationToolset":
            integration = _string(_kw(call, "integration"))
            triggers = _list_strings(_kw(call, "triggers"))
            if integration:
                metadata["integration"] = integration
                metadata["integration_triggers"] = triggers
                metadata["network_scope"] = "fixed_managed_service"
                metadata["network_provider"] = "google-application-integration"
                metadata["destination_constraint_basis"] = "application_integration_name"
                if triggers:
                    metadata["explicit_surface_constraint"] = True
                    metadata["surface_constraint_basis"] = "integration_and_triggers"
        if name == "ExecuteBashTool":
            approval = True
            metadata["built_in_confirmation"] = True
            metadata["confirmation_source"] = "google-adk"
            policy = _resolve_call(_kw(call, "policy"), calls)
            metadata["bash_policy_present"] = policy is not None
            if policy:
                allowed_prefixes = []
                for key in ("allowed_command_prefixes", "allowed_commands", "allowed_command_patterns"):
                    allowed_prefixes.extend(_list_strings(_kw(policy, key)))
                blocked_operators = []
                for key in ("blocked_operators", "denied_commands", "blocked_commands"):
                    blocked_operators.extend(_list_strings(_kw(policy, key)))
                metadata["allowed_command_prefixes"] = list(dict.fromkeys(allowed_prefixes))
                metadata["blocked_operators"] = list(dict.fromkeys(blocked_operators))
                metadata["bash_policy_restrictive"] = bool(allowed_prefixes and blocked_operators)
        if name == "EnvironmentToolset":
            env_call = _resolve_call(_kw(call, "environment"), calls)
            env_name = _call_name(env_call.func) if env_call else None
            metadata["environment"] = env_name
            if env_name == "LocalEnvironment" and env_call:
                working_dir = _string(_kw(env_call, "working_dir")) or "temporary-directory"
                metadata["working_dir"] = working_dir
        if name == "BigQueryToolset":
            config = _resolve_call(_kw(call, "bigquery_tool_config"), calls)
            write_mode = None
            if config:
                raw = _kw(config, "write_mode")
                write_mode = _dotted_name(raw) or _string(raw)
            metadata["write_mode"] = write_mode
            if write_mode and write_mode.lower().endswith("blocked"):
                caps.discard("data.write")

        required_roles = set(BUILTIN_TOOL_REQUIRED_ROLES.get(name, set()))
        if name == "BigQueryToolset" and "data.write" in caps:
            required_roles.add("roles/bigquery.dataEditor")
        if required_roles:
            metadata["required_authority_provider"] = "gcp"
            metadata["required_roles"] = sorted(required_roles)
            metadata["required_roles_complete"] = False
            metadata["required_role_evidence"] = [
                {
                    "provider": "gcp",
                    "role": role,
                    "operation": f"adk_builtin:{name}",
                    "line": getattr(call, "lineno", 1),
                }
                for role in sorted(required_roles)
            ]
        if name in {"GoogleApiToolset", "GmailToolset", "CalendarToolset", "DocsToolset", "SheetsToolset", "SlidesToolset", "YoutubeToolset"}:
            metadata["additional_scopes"] = _list_strings(_kw(call, "additional_scopes"))
            metadata["service_account"] = _kw(call, "service_account") is not None
            metadata["client_secret_literal"] = bool(_string(_kw(call, "client_secret")))
        if name == "ComputerUseToolset":
            metadata["interactive_control"] = True
        if name in {"BigQueryToolset", "BigtableToolset", "DataAgentToolset"}:
            metadata["network_scope"] = "fixed_managed_service"
            metadata["network_provider"] = "google-cloud"
        tool = Tool(
            name=alias,
            kind="adk_builtin",
            capabilities=caps,
            approval=approval,
            guardrails=approval is True,
            location=_location(path, call),
            metadata=metadata,
        )
        if name == "OpenAPIToolset":
            for server in metadata.get("openapi_servers", []):
                tool.destinations.append(
                    NetworkDestination(
                        target=str(server),
                        restricted=True,
                        location=tool.location,
                        metadata={
                            "source": "openapi_server",
                            "network_scope": "explicit_destination",
                        },
                    )
                )
        if name == "ApplicationIntegrationToolset" and metadata.get("integration"):
            tool.destinations.append(
                NetworkDestination(
                    target="<google-application-integration:" + str(metadata["integration"]) + ">",
                    restricted=True,
                    location=tool.location,
                    metadata={
                        "source": "application_integration",
                        "network_scope": "fixed_managed_service",
                        "integration": metadata["integration"],
                        "triggers": list(metadata.get("integration_triggers") or []),
                    },
                )
            )
        # Search/retrieval tools ingest external content. URL-context
        # tools additionally expose model-selected content destinations.
        _apply_retrieval_network_semantics(tool, name)
        # Resource scoping where ADK exposes a literal data source identifier.
        for key, kind in (("data_store_id", "vertex-search"), ("search_engine_id", "vertex-search"), ("project", "gcp-project"), ("dataset", "bigquery")):
            value = _string(_kw(call, key))
            if value:
                tool.resources.append(ResourceScope(kind=kind, selector=value, access=set(caps), location=tool.location))
        return tool

    return None


def _plain_function_tool(path: Path, func: ast.FunctionDef | ast.AsyncFunctionDef) -> Tool:
    caps, destinations = _infer_function_capabilities(func)
    return Tool(
        name=func.name,
        kind="adk_function",
        capabilities=caps,
        destinations=[NetworkDestination(target=d.target, restricted=d.restricted,
                                         location=_location(path, func), metadata=dict(d.metadata)) for d in destinations],
        location=_location(path, func),
        metadata={"framework": "google-adk", "plain_function": True},
    )


def _identity_from_call(path: Path, alias: str, call: ast.Call) -> Identity | None:
    name = _call_name(call.func) or ""
    if name in {"BigQueryCredentialsConfig", "BigtableCredentialsConfig", "DataAgentCredentialsConfig"}:
        source = "workload/default"
        if _string(_kw(call, "client_secret")):
            source = "hardcoded"
        elif _kw(call, "credentials") is not None:
            source = "application-default-credentials"
        elif _kw(call, "external_access_token_key") is not None:
            source = "session-token"
        return Identity(name=alias, provider="gcp", credential_source=source, location=_location(path, call), metadata={"framework": "google-adk"})
    dotted = (_dotted_name(call.func) or "").lower()
    if dotted.endswith("from_service_account_file"):
        return Identity(name=alias, provider="gcp", credential_source="file", location=_location(path, call), metadata={"framework": "google-adk"})
    if dotted.endswith("google.auth.default") or dotted == "google.auth.default":
        return Identity(name=alias, provider="gcp", oauth_scopes=set(_list_strings(_kw(call, "scopes"))), credential_source="application-default-credentials", location=_location(path, call), metadata={"framework": "google-adk"})
    return None


def _callbacks(call: ast.Call) -> dict[str, str]:
    names = (
        "before_agent_callback", "after_agent_callback", "before_model_callback", "after_model_callback",
        "before_tool_callback", "after_tool_callback", "on_model_error_callback", "on_tool_error_callback",
    )
    result: dict[str, str] = {}
    for key in names:
        node = _kw(call, key)
        if node is not None:
            result[key] = _call_name(node) or _dotted_name(node) or "configured"
    return result


def _custom_base_agent_classes(tree: ast.AST) -> dict[str, ast.ClassDef]:
    """Return source-defined ADK BaseAgent subclasses without executing them."""
    result: dict[str, ast.ClassDef] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        inherits_base_agent = any(
            (_call_name(base) == "BaseAgent")
            or ((_dotted_name(base) or "").endswith(".BaseAgent"))
            for base in node.bases
        )
        if inherits_base_agent:
            result[node.name] = node
    return result


def _agent_from_call(
    path: Path,
    call: ast.Call,
    alias: str,
    tools: dict[str, Tool],
    mcp_servers: dict[str, MCPServer],
    calls: dict[str, ast.Call],
    sequences: dict[str, list[ast.AST]],
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    custom_agent_classes: dict[str, ast.ClassDef] | None = None,
) -> Agent | None:
    agent_type = _call_name(call.func) or ""
    custom_agent_classes = custom_agent_classes or {}
    custom_base_agent = agent_type in custom_agent_classes
    if agent_type not in AGENT_TYPES and not custom_base_agent:
        return None
    name = _string(_kw(call, "name")) or alias
    metadata: dict[str, Any] = {
        "framework": "google-adk",
        "agent_type": agent_type,
        "source_alias": alias,
        "instance_key": (
            f"{path.resolve()}:{getattr(call, 'lineno', 1) or 1}:{alias}"
        ),
        "custom_base_agent": custom_base_agent,
    }
    if custom_base_agent:
        class_node = custom_agent_classes[agent_type]
        entrypoints = [
            item.name
            for item in class_node.body
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            and item.name in {"_run_async_impl", "run_async", "run", "invoke"}
        ]
        if entrypoints:
            metadata["semantic_entrypoints"] = entrypoints
    instruction = _string(_kw(call, "instruction")) or _string(_kw(call, "instructions"))
    if instruction:
        metadata["instruction"] = instruction
    model = _string(_kw(call, "model"))
    if model:
        metadata["model"] = model
    callbacks = _callbacks(call)
    if callbacks:
        metadata["callbacks"] = callbacks
    metadata["disallow_transfer_to_parent"] = _bool(_kw(call, "disallow_transfer_to_parent"))
    metadata["disallow_transfer_to_peers"] = _bool(_kw(call, "disallow_transfer_to_peers"))
    metadata["mode"] = _string(_kw(call, "mode"))

    agent = Agent(name=name, location=_location(path, call), metadata=metadata)
    # A top-level LLM agent receives user-controlled input unless the manifest later narrows trust.
    if alias == "root_agent" or agent_type == "RemoteA2aAgent":
        agent.inputs.append(InputSource(name="user-or-remote-input", trust="untrusted", kind="external" if agent_type == "RemoteA2aAgent" else "user", location=agent.location,
                                         metadata={"inferred": True}))

    if agent_type == "RemoteA2aAgent":
        card_node = _arg(call, 1, "agent_card")
        card = _string(card_node)
        configuration_source = _operator_configuration_source(card_node, calls)
        auth = any(_kw(call, k) is not None for k in ("auth_scheme", "auth_credential", "credential_key"))
        agent.metadata.update({
            "remote_a2a": True,
            "agent_card": card,
            "authenticated": auth,
            "configuration_source": configuration_source,
        })
        remote_metadata: dict[str, Any] = {
            "framework": "google-adk",
            "authenticated": auth,
            "agent_card": card,
        }
        if configuration_source:
            remote_metadata["network_scope"] = "operator_configured_destination"
            remote_metadata["destination_constraint_basis"] = "operator_configuration"
            remote_metadata["configuration_source"] = configuration_source
        remote_tool = Tool(
            name=f"{name}:a2a",
            kind="adk_a2a_remote",
            capabilities={"agent.delegate", "data.read", "external.write", "network.external"},
            location=agent.location,
            metadata=remote_metadata,
        )
        if card and card.startswith(("http://", "https://")):
            remote_tool.destinations.append(
                NetworkDestination(
                    target=card,
                    restricted=True,
                    location=agent.location,
                    metadata={"network_scope": "explicit_destination", "source": "agent_card"},
                )
            )
        elif configuration_source:
            remote_tool.destinations.append(
                NetworkDestination(
                    target="<operator-configured-a2a>",
                    restricted=True,
                    location=agent.location,
                    metadata={
                        "network_scope": "operator_configured_destination",
                        "source": "operator_configuration",
                        "configuration_source": configuration_source,
                    },
                )
            )
        agent.tools.append(remote_tool)
        return agent

    tools_expr = _kw(call, "tools")
    dynamic_collection = _dynamic_tool_collection(path, tools_expr, calls)
    if dynamic_collection is not None and isinstance(tools_expr, ast.Name) and tools_expr.id not in sequences:
        agent.tools.append(dynamic_collection)
        agent.metadata["dynamic_tools"] = True
        agent.metadata["dynamic_tools_source_bound"] = True

    for element in _resolve_sequence(tools_expr, sequences):
        if isinstance(element, ast.Name):
            if element.id in mcp_servers:
                agent.mcp_servers.append(mcp_servers[element.id])
            elif element.id in tools:
                agent.tools.append(tools[element.id])
            elif element.id in functions:
                agent.tools.append(_plain_function_tool(path, functions[element.id]))
            elif element.id in BUILTIN_TOOL_CAPABILITIES:
                tool = Tool(
                    name=element.id, kind="adk_builtin",
                    capabilities=set(BUILTIN_TOOL_CAPABILITIES[element.id]),
                    location=_location(path, element),
                    metadata={"framework": "google-adk", "adk_builtin": element.id},
                )
                _apply_retrieval_network_semantics(tool, element.id)
                agent.tools.append(tool)
            elif element.id in calls:
                direct_mcp = _mcp_from_toolset(
                    path,
                    calls[element.id],
                    element.id,
                    calls,
                )
                if direct_mcp:
                    agent.mcp_servers.append(direct_mcp)
                else:
                    direct = _tool_from_call(
                        path,
                        calls[element.id],
                        element.id,
                        calls,
                        functions,
                    )
                    if direct:
                        agent.tools.append(direct)
            else:
                # Imported or arbitrary helpers can carry capabilities that
                # static analysis cannot safely infer.
                agent.metadata["external_helper_semantics_unresolved"] = True
                agent.metadata.setdefault("unresolved_helpers", []).append(element.id)
        elif isinstance(element, ast.Call):
            direct_mcp = _mcp_from_toolset(path, element, _call_name(element.func) or "mcp", calls)
            if direct_mcp:
                agent.mcp_servers.append(direct_mcp)
            else:
                direct = _tool_from_call(path, element, _call_name(element.func) or "tool", calls, functions)
                if direct:
                    agent.tools.append(direct)
        elif isinstance(element, ast.Attribute):
            tool_name = _call_name(element) or "tool"
            caps = set(BUILTIN_TOOL_CAPABILITIES.get(tool_name, set())) or set(infer_capabilities(tool_name))
            tool = Tool(name=tool_name, kind="adk_builtin", capabilities=caps, location=_location(path, element), metadata={"framework": "google-adk", "adk_builtin": tool_name})
            _apply_retrieval_network_semantics(tool, tool_name)
            agent.tools.append(tool)

    code_node = _kw(call, "code_executor")
    code_call = _resolve_call(code_node, calls)
    if code_call:
        executor = _tool_from_call(path, code_call, _call_name(code_call.func) or "code_executor", calls, functions)
        if executor:
            agent.tools.append(executor)

    delegates: list[str] = []
    for element in _resolve_sequence(_kw(call, "sub_agents"), sequences):
        target = _call_name(element)
        if isinstance(element, ast.Name) and element.id in calls:
            target_call = calls[element.id]
            if (_call_name(target_call.func) or "") in AGENT_TYPES:
                target = _string(_kw(target_call, "name")) or target
        if isinstance(element, ast.Call):
            target = _string(_kw(element, "name")) or _call_name(element.func)
        if target:
            delegates.append(target)
    for tool in agent.tools:
        target = tool.metadata.get("delegate_target")
        if isinstance(target, str):
            delegates.append(target)
    if delegates:
        agent.metadata["delegates_to"] = list(dict.fromkeys(delegates))

    if agent_type in WORKFLOW_TYPES:
        agent.metadata["workflow"] = agent_type

    if any(t.metadata.get("untrusted_input") for t in agent.tools) or any(s.url for s in agent.mcp_servers):
        agent.inputs.append(InputSource(name="retrieved-external-content", trust="untrusted", kind="retrieval", location=agent.location, metadata={"inferred": True}))

    return agent


def _lexical_scope(tree: ast.AST, node: ast.AST) -> str:
    """Return the innermost function/class scope containing a source node."""
    line = getattr(node, "lineno", 0) or 0
    candidates: list[tuple[int, int, str]] = []
    for item in ast.walk(tree):
        if not isinstance(
            item,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
        ):
            continue
        start = getattr(item, "lineno", 0) or 0
        end = getattr(item, "end_lineno", start) or start
        if start <= line <= end:
            candidates.append((end - start, -start, f"{item.name}@{start}"))
    if not candidates:
        return "__module__"
    return min(candidates)[2]


def _construction_key(item: Tool | MCPServer) -> tuple[str, int, str]:
    location = item.location
    return (
        location.path.resolve().as_posix() if location else "",
        location.line if location else 0,
        item.name,
    )


def scan_python_file(path: Path) -> Graph:
    graph = Graph()
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (SyntaxError, UnicodeDecodeError, OSError):
        return graph
    if not _uses_google_adk(tree):
        return graph

    configuration_sources = _module_configuration_sources(tree)
    functions = {node.name: node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    custom_agent_classes = _custom_base_agent_classes(tree)
    imported_functions: dict[str, str] = {}
    for node in tree.body:
        if not isinstance(node, ast.ImportFrom) or not node.module:
            continue
        for imported in node.names:
            if imported.name == "*":
                continue
            imported_functions[imported.asname or imported.name] = node.module

    calls: dict[str, ast.Call] = {}
    sequences: dict[str, list[ast.AST]] = {}
    tools: dict[str, Tool] = {}
    mcp_servers: dict[str, MCPServer] = {}
    identities: dict[str, Identity] = {}
    agent_calls: list[tuple[str, ast.Call, str]] = []
    scoped_calls: dict[str, dict[str, ast.Call]] = {}
    scoped_sequences: dict[str, dict[str, list[ast.AST]]] = {}
    safety_plugins: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            alias = next((t.id for t in targets if isinstance(t, ast.Name)), None)
            if not alias:
                continue
            scope = _lexical_scope(tree, node)
            if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
                sequences[alias] = list(value.elts)
                scoped_sequences.setdefault(scope, {})[alias] = list(value.elts)
                continue
            if isinstance(value, ast.Call):
                calls[alias] = value
                scoped_calls.setdefault(scope, {})[alias] = value
                call_name = _call_name(value.func) or ""
                if call_name in AGENT_TYPES or call_name in custom_agent_classes:
                    agent_calls.append((alias, value, scope))
                    continue
                mcp = _mcp_from_toolset(path, value, alias, calls)
                if mcp:
                    mcp_servers[alias] = mcp
                    continue
                identity = _identity_from_call(path, alias, value)
                if identity:
                    identities[alias] = identity
                tool = _tool_from_call(path, value, alias, calls, functions)
                if tool:
                    tools[alias] = tool
                if "plugin" in call_name.lower() and any(k in call_name.lower() for k in ("guard", "security", "safety", "defense", "threat", "policy")):
                    safety_plugins.add(alias)

    # Resolve common flow-sensitive collection construction without executing code.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if not isinstance(node.func.value, ast.Name):
            continue
        sequence = sequences.get(node.func.value.id)
        if sequence is None:
            continue
        if node.func.attr == "append" and len(node.args) == 1:
            sequence.append(node.args[0])
        elif node.func.attr == "extend" and len(node.args) == 1:
            arg = node.args[0]
            if isinstance(arg, (ast.List, ast.Tuple, ast.Set)):
                sequence.extend(arg.elts)
            elif isinstance(arg, ast.Name) and arg.id in sequences:
                sequence.extend(sequences[arg.id])

    # Build lexical-scope views so repeated aliases inside separate functions
    # resolve to the construction visible in that function rather than the last
    # same-named assignment encountered elsewhere in the module.
    module_calls = scoped_calls.get("__module__", {})
    module_sequences = scoped_sequences.get("__module__", {})
    scoped_tools: dict[str, dict[str, Tool]] = {}
    scoped_mcp_servers: dict[str, dict[str, MCPServer]] = {}
    for scope, scope_calls in scoped_calls.items():
        visible_calls = {**module_calls, **scope_calls}
        visible_sequences = {
            **module_sequences,
            **scoped_sequences.get(scope, {}),
        }
        for alias, scoped_call in scope_calls.items():
            mcp = _mcp_from_toolset(
                path,
                scoped_call,
                alias,
                visible_calls,
            )
            if mcp:
                filter_node = _kw(scoped_call, "tool_filter")
                if (
                    isinstance(filter_node, ast.Name)
                    and filter_node.id in visible_sequences
                ):
                    values = [
                        value
                        for element in visible_sequences[filter_node.id]
                        if (
                            value := (
                                _string(element)
                                or _dotted_name(element)
                            )
                        )
                        is not None
                    ]
                    if values:
                        mcp.allowed_tools = values
                        mcp.metadata["dynamic_tool_filter"] = False
                scoped_mcp_servers.setdefault(scope, {})[alias] = mcp
                continue
            tool = _tool_from_call(
                path,
                scoped_call,
                alias,
                visible_calls,
                functions,
            )
            if tool:
                filter_node = _kw(scoped_call, "tool_filter")
                if (
                    isinstance(filter_node, ast.Name)
                    and filter_node.id in visible_sequences
                ):
                    values = [
                        value
                        for element in visible_sequences[filter_node.id]
                        if (
                            value := (
                                _string(element)
                                or _dotted_name(element)
                            )
                        )
                        is not None
                    ]
                    if values:
                        tool.metadata["tool_filter"] = values
                        tool.metadata["dynamic_tool_filter"] = False
                scoped_tools.setdefault(scope, {})[alias] = tool

    # Second pass catches aliases whose nested calls were declared later in the file.
    for alias, call in list(calls.items()):
        mcp = _mcp_from_toolset(path, call, alias, calls)
        if mcp:
            mcp_servers[alias] = mcp
        tool = _tool_from_call(path, call, alias, calls, functions)
        if tool:
            tools[alias] = tool

    # Resolve named literal tool-filter constants after all assignments are known.
    for alias, call in calls.items():
        filter_node = _kw(call, "tool_filter")
        if not isinstance(filter_node, ast.Name) or filter_node.id not in sequences:
            continue
        values = [
            value
            for element in sequences[filter_node.id]
            if (value := (_string(element) or _dotted_name(element))) is not None
        ]
        if not values:
            continue
        if alias in tools:
            tools[alias].metadata["tool_filter"] = values
            tools[alias].metadata["dynamic_tool_filter"] = False
        if alias in mcp_servers:
            mcp_servers[alias].allowed_tools = values
            mcp_servers[alias].metadata["dynamic_tool_filter"] = False

    agents_by_alias: dict[str, Agent] = {}
    for alias, call, scope in agent_calls:
        visible_calls = {
            **module_calls,
            **scoped_calls.get(scope, {}),
        }
        visible_sequences = {
            **module_sequences,
            **scoped_sequences.get(scope, {}),
        }
        visible_tools = {
            **{
                name: item
                for name, item in tools.items()
                if name in module_calls
            },
            **scoped_tools.get(scope, {}),
        }
        visible_mcp_servers = {
            **{
                name: item
                for name, item in mcp_servers.items()
                if name in module_calls
            },
            **scoped_mcp_servers.get(scope, {}),
        }
        agent = _agent_from_call(
            path,
            call,
            alias,
            visible_tools,
            visible_mcp_servers,
            visible_calls,
            visible_sequences,
            functions,
            custom_agent_classes,
        )
        if agent:
            agents_by_alias[alias] = agent
            graph.agents.append(agent)

    # App/Runner plugins and A2A exposure are security controls/exposure points.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        call_name = _call_name(node.func) or ""
        if call_name in {"App", "Runner", "InMemoryRunner"}:
            agent_ref = _call_name(_kw(node, "root_agent")) or _call_name(_kw(node, "agent"))
            plugin_nodes = _resolve_sequence(_kw(node, "plugins"), sequences)
            plugin_specs: list[tuple[str, list[str]]] = []
            for plugin_node in plugin_nodes:
                if isinstance(plugin_node, ast.Call):
                    plugin_name = _call_name(plugin_node.func)
                    sensitive_tools = _list_strings(_kw(plugin_node, "sensitive_tools"))
                else:
                    plugin_name = _call_name(plugin_node)
                    sensitive_tools = []
                if plugin_name:
                    plugin_specs.append((plugin_name, sensitive_tools))

            plugin_names = [name for name, _ in plugin_specs]
            if agent_ref in agents_by_alias and plugin_names:
                target_agent = agents_by_alias[agent_ref]
                target_agent.metadata["plugins"] = plugin_names

                if any(
                    any(
                        marker in plugin_name.lower()
                        for marker in ("guard", "security", "safety", "defense", "threat", "policy")
                    )
                    for plugin_name in plugin_names
                ):
                    target_agent.metadata["safety_plugin"] = True

                approval_plugins: list[dict[str, Any]] = []
                for plugin_name, sensitive_tools in plugin_specs:
                    if plugin_name != "HITLToolPlugin":
                        continue
                    approval_plugins.append(
                        {"name": plugin_name, "sensitive_tools": sensitive_tools}
                    )
                    if sensitive_tools:
                        for tool in target_agent.tools:
                            if tool.name not in sensitive_tools:
                                continue
                            tool.approval = True
                            tool.guardrails = True
                            tool.metadata["approval_mechanism"] = "adk_hitl_tool_plugin"
                            tool.metadata["approval_scope"] = "tool"
                            tool.metadata["approval_mandatory"] = True
                            tool.metadata["approval_plugin"] = plugin_name
                    else:
                        target_agent.metadata["approval_plugin_scope_unresolved"] = True

                if approval_plugins:
                    target_agent.metadata["approval_plugin"] = True
                    target_agent.metadata["approval_plugins"] = approval_plugins
        if call_name == "to_a2a":
            ref = _call_name(_arg(node, 0, "agent"))
            if ref in agents_by_alias:
                agents_by_alias[ref].metadata["a2a_exposed"] = True
                if not any(i.name == "a2a-request" for i in agents_by_alias[ref].inputs):
                    agents_by_alias[ref].inputs.append(InputSource(name="a2a-request", trust="untrusted", kind="external", location=_location(path, node)))

    # Attach credentials to toolsets when directly referenced by alias, and
    # materialize OAuth/service-account authority exposed directly on Google
    # API toolsets so Layer 3 can reason about scopes and credential source.
    for alias, tool in tools.items():
        call = calls.get(alias)
        if not call:
            continue
        cred_ref = _call_name(_kw(call, "credentials_config")) or _call_name(_kw(call, "service_account"))
        if cred_ref and cred_ref in identities:
            tool.identity = identities[cred_ref].name

        scopes = set(tool.metadata.get("additional_scopes") or [])
        client_secret_literal = bool(tool.metadata.get("client_secret_literal"))
        service_account_configured = bool(tool.metadata.get("service_account"))
        if scopes or client_secret_literal or service_account_configured:
            identity_name = f"{alias}:google-api-auth"
            credential_source = (
                "hardcoded" if client_secret_literal
                else "service-account" if service_account_configured
                else "oauth"
            )
            synthetic = Identity(
                name=identity_name,
                provider="gcp",
                oauth_scopes=scopes,
                credential_source=credential_source,
                location=tool.location,
                metadata={"framework": "google-adk", "source_tool": alias},
            )
            existing = identities.get(identity_name)
            if existing:
                existing.oauth_scopes.update(synthetic.oauth_scopes)
                existing.credential_source = synthetic.credential_source or existing.credential_source
            else:
                identities[identity_name] = synthetic
            tool.identity = identity_name

    for agent in graph.agents:
        for tool in agent.tools:
            import_module = imported_functions.get(tool.name)
            if (
                import_module
                and tool.metadata.get("framework") == "google-adk"
                and tool.metadata.get("source_function_key") is None
            ):
                tool.metadata["import_module"] = import_module
                tool.metadata.setdefault("source_function", tool.name)

    for tool in tools.values():
        import_module = imported_functions.get(tool.name)
        if (
            import_module
            and tool.metadata.get("framework") == "google-adk"
            and tool.metadata.get("source_function_key") is None
        ):
            tool.metadata["import_module"] = import_module
            tool.metadata.setdefault("source_function", tool.name)

    graph.identities.extend(identities.values())
    bound_tool_keys = {
        _construction_key(tool)
        for agent in graph.agents
        for tool in agent.tools
    }
    bound_mcp_keys = {
        _construction_key(server)
        for agent in graph.agents
        for server in agent.mcp_servers
    }
    graph.unbound_tools.extend(
        tool
        for tool in tools.values()
        if _construction_key(tool) not in bound_tool_keys
    )
    graph.unbound_mcp_servers.extend(
        server
        for server in mcp_servers.values()
        if _construction_key(server) not in bound_mcp_keys
    )
    for agent in graph.agents:
        for tool in agent.tools:
            function = functions.get(tool.name)
            if function is None:
                continue
            _apply_operator_configured_function_destinations(
                tool,
                function,
                configuration_sources,
            )

    return graph
