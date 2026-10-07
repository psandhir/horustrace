from __future__ import annotations

import ast
import hashlib
import json
from itertools import pairwise
from pathlib import Path
from typing import Any

from horustrace.effect_semantics import (
    http_mutation_capabilities,
    is_local_collection_mutation,
    sql_call_capabilities,
)
from horustrace.heuristics import (
    corroborate_name_inferred_authority,
    infer_capabilities,
    resource_is_broad,
)
from horustrace.models import (
    Agent,
    Graph,
    Identity,
    InputSource,
    MCPServer,
    NetworkDestination,
    ResourceScope,
    Skill,
    SourceLocation,
    Tool,
)
from horustrace.semantic_contract import set_model_provenance, set_tool_control
from horustrace.skills import instruction_capability_signals

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


def _path_expr_string(
    node: ast.AST | None,
    values: dict[str, ast.AST] | None = None,
) -> str | None:
    """Resolve a source-visible repository-relative path expression."""
    values = values or {}
    if node is None:
        return None
    if isinstance(node, ast.Name):
        if node.id == "__file__":
            return "__file__"
        if node.id in values:
            return _path_expr_string(values[node.id], values)
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Attribute) and node.attr == "parent":
        base = _path_expr_string(node.value, values)
        if base == "__file__":
            return "."
        if base:
            return Path(base).parent.as_posix()
        return None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        left = _path_expr_string(node.left, values)
        right = _path_expr_string(node.right, values)
        if left is None or right is None:
            return None
        if left == "__file__":
            return None
        return (Path(left) / right).as_posix()
    if isinstance(node, ast.Call):
        called = _dotted_name(node.func) or _call_name(node.func) or ""
        if called.rsplit(".", 1)[-1] in {"Path", "PurePath"}:
            if not node.args:
                return "."
            return _path_expr_string(node.args[0], values)
        if called.endswith(".join") or called == "join":
            parts = [_path_expr_string(item, values) for item in node.args]
            if parts and all(part is not None for part in parts):
                return Path(str(parts[0])).joinpath(
                    *(str(part) for part in parts[1:])
                ).as_posix()
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"resolve", "absolute"}
        ):
            return _path_expr_string(node.func.value, values)
    return None


def _inline_adk_skill(
    path: Path,
    call: ast.Call,
    calls: dict[str, ast.Call],
) -> Skill | None:
    if (_call_name(call.func) or "") != "Skill":
        return None
    frontmatter_node = _kw(call, "frontmatter")
    if frontmatter_node is None and call.args:
        frontmatter_node = call.args[0]
    frontmatter = _resolve_call(frontmatter_node, calls)
    if frontmatter is None or (_call_name(frontmatter.func) or "") != "Frontmatter":
        return None

    name = _string(_kw(frontmatter, "name"))
    description = _string(_kw(frontmatter, "description"))
    if not name or not description:
        return None

    raw_metadata = _literal(_kw(frontmatter, "metadata"))
    metadata_map = raw_metadata if isinstance(raw_metadata, dict) else {}
    instructions = _string(_kw(call, "instructions")) or ""
    scripts: list[str] = []
    inline_scripts: dict[str, str] = {}

    resources = _resolve_call(_kw(call, "resources"), calls)
    if resources is not None and (_call_name(resources.func) or "") == "Resources":
        scripts_node = _kw(resources, "scripts")
        if isinstance(scripts_node, ast.Dict):
            for key_node, value_node in zip(scripts_node.keys, scripts_node.values):
                script_name = _string(key_node)
                if not script_name:
                    continue
                script_source = _string(value_node)
                if isinstance(value_node, ast.Call):
                    script_source = (
                        _string(_kw(value_node, "src"))
                        or _string(value_node.args[0] if value_node.args else None)
                    )
                relative = (
                    script_name
                    if script_name.startswith("scripts/")
                    else f"scripts/{script_name}"
                )
                scripts.append(relative)
                if script_source is not None:
                    inline_scripts[relative] = script_source

    metadata: dict[str, Any] = {
        "framework": "google-adk",
        "inline_skill": True,
        "binding_state": "bound",
        "binding_origin": "adk_inline_skilltoolset",
        "instructions_sha256": hashlib.sha256(
            instructions.encode("utf-8")
        ).hexdigest(),
        "instructions_length": len(instructions),
        "declared_instruction_capabilities": sorted(
            instruction_capability_signals(instructions)
        ),
        "content_included": False,
        "has_scripts": bool(scripts),
        "script_count": len(scripts),
        "metadata": metadata_map,
    }
    if inline_scripts:
        metadata["inline_scripts"] = inline_scripts

    return Skill(
        name=name,
        description=description,
        source="inline",
        scripts=scripts,
        location=_location(path, call),
        metadata=metadata,
    )


def _tool_semantics_doc(tool: Tool) -> dict[str, Any]:
    return {
        "name": tool.name,
        "kind": tool.kind,
        "capabilities": sorted(tool.capabilities),
        "approval": tool.approval,
        "guardrails": tool.guardrails,
        "resources": [
            {
                "kind": item.kind,
                "selector": item.selector,
                "access": sorted(item.access),
                "classification": item.classification,
            }
            for item in tool.resources
        ],
        "destinations": [
            {
                "target": item.target,
                "direction": item.direction,
                "restricted": item.restricted,
            }
            for item in tool.destinations
        ],
        "metadata": {
            key: tool.metadata.get(key)
            for key in (
                "sandboxed",
                "executor_kind",
                "network_scope",
                "approval_mechanism",
            )
            if key in tool.metadata
        },
    }


def _adk_skill_toolset_spec(
    path: Path,
    call: ast.Call,
    alias: str,
    tools: dict[str, Tool],
    calls: dict[str, ast.Call],
    sequences: dict[str, list[ast.AST]],
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    values: dict[str, ast.AST],
    custom_tool_classes: dict[str, ast.ClassDef] | None = None,
) -> tuple[dict[str, Any], list[Skill]]:
    """Normalize one ADK SkillToolset without treating it as a normal tool."""
    custom_tool_classes = custom_tool_classes or {}
    source_paths: list[str] = []
    inline_skills: list[Skill] = []
    remote_sources: list[dict[str, Any]] = []
    dynamic_skills = False

    skills_node = _arg(call, 0, "skills")
    if skills_node is not None:
        for element in _resolve_sequence(skills_node, sequences):
            skill_call = (
                calls.get(element.id)
                if isinstance(element, ast.Name)
                else element
                if isinstance(element, ast.Call)
                else None
            )
            if skill_call is None:
                dynamic_skills = True
                continue
            skill_call_name = _call_name(skill_call.func) or ""
            if skill_call_name in {"load_skill_from_dir", "load_skills_from_dir"}:
                source_node = _arg(skill_call, 0, "skill_dir")
                if skill_call_name == "load_skills_from_dir":
                    source_node = _arg(skill_call, 0, "skills_dir")
                source = _path_expr_string(source_node, values)
                if source and source != "__file__":
                    if source not in source_paths:
                        source_paths.append(source)
                else:
                    dynamic_skills = True
                continue
            if skill_call_name == "load_skill_from_gcs_dir":
                bucket_node = _kw(skill_call, "bucket_name")
                prefix_node = _kw(skill_call, "skills_base_path")
                bucket = _path_expr_string(bucket_node, values)
                prefix = _path_expr_string(prefix_node, values)
                remote_sources.append(
                    {
                        "provider": "google-adk",
                        "source": "Google Cloud Storage Skill catalogue",
                        "bucket": bucket or "<dynamic-bucket>",
                        "prefix": prefix or "<dynamic-prefix>",
                        "binding": alias,
                    }
                )
                continue
            if skill_call_name == "Skill":
                inline = _inline_adk_skill(path, skill_call, calls)
                if inline is not None:
                    inline_skills.append(inline)
                else:
                    dynamic_skills = True
                continue
            dynamic_skills = True

    additional_tools: list[dict[str, Any]] = []
    unresolved_additional_tools: list[str] = []
    for element in _resolve_sequence(_kw(call, "additional_tools"), sequences):
        candidate: Tool | None = None
        candidate_name = _call_name(element) or ""
        if isinstance(element, ast.Name):
            candidate_name = element.id
            nested = calls.get(element.id)
            nested_name = _call_name(nested.func) if nested is not None else None
            if nested is not None and nested_name in custom_tool_classes:
                candidate = _custom_tool_from_call(
                    path,
                    nested,
                    element.id,
                    custom_tool_classes,
                )
            if candidate is None:
                candidate = tools.get(element.id)
            if candidate is None and element.id in functions:
                candidate = _plain_function_tool(path, functions[element.id])
            if (
                candidate is None
                and nested is not None
                and nested_name != "SkillToolset"
            ):
                candidate = _tool_from_call(
                    path,
                    nested,
                    element.id,
                    calls,
                    functions,
                    values,
                    custom_tool_classes,
                )
        elif isinstance(element, ast.Call):
            candidate_name = _call_name(element.func) or "additional_tool"
            if candidate_name in custom_tool_classes:
                candidate = _custom_tool_from_call(
                    path,
                    element,
                    candidate_name,
                    custom_tool_classes,
                )
            elif candidate_name != "SkillToolset":
                candidate = _tool_from_call(
                    path,
                    element,
                    candidate_name,
                    calls,
                    functions,
                    values,
                    custom_tool_classes,
                )
        if candidate is not None:
            additional_tools.append(_tool_semantics_doc(candidate))
        elif candidate_name:
            unresolved_additional_tools.append(candidate_name)

    script_execution: dict[str, Any] = {"available": False}
    executor_node = _kw(call, "code_executor")
    executor_call = _resolve_call(executor_node, calls)
    if executor_call is not None:
        executor = _tool_from_call(
            path,
            executor_call,
            _call_name(executor_call.func) or "skill_code_executor",
            calls,
            functions,
            values,
        )
        if executor is not None and executor.kind == "adk_code_executor":
            script_execution = {
                "available": True,
                "source": "skilltoolset_code_executor",
                "executor": executor.metadata.get("code_executor") or executor.name,
                "sandboxed": executor.metadata.get("sandboxed"),
                "executor_kind": executor.metadata.get("executor_kind"),
                "capabilities": sorted(executor.capabilities),
                "sandbox_network_disabled": executor.metadata.get(
                    "sandbox_network_disabled"
                ),
                "sandbox_filesystem_constrained": executor.metadata.get(
                    "sandbox_filesystem_constrained"
                ),
            }

    environment_node = _kw(call, "environment")
    environment_call = _resolve_call(environment_node, calls)
    if environment_node is not None:
        environment_name = (
            _call_name(environment_call.func)
            if environment_call is not None
            else _call_name(environment_node)
            or "dynamic_environment"
        )
        environment_leaf = (environment_name or "").rsplit(".", 1)[-1]
        if environment_leaf == "LocalEnvironment":
            sandboxed: bool | None = False
            executor_kind = "local_environment"
        elif environment_leaf == "E2BEnvironment":
            sandboxed = True
            executor_kind = "remote_sandbox_environment"
        else:
            sandboxed = None
            executor_kind = "adk_environment"
        script_execution = {
            "available": True,
            "source": "skilltoolset_environment",
            "executor": environment_name,
            "sandboxed": sandboxed,
            "executor_kind": executor_kind,
            "capabilities": ["process.execute"],
        }

    registry_node = _kw(call, "registry")
    spec: dict[str, Any] = {
        "alias": alias,
        "source_paths": source_paths,
        "skill_names": [skill.name for skill in inline_skills],
        "dynamic_skills": dynamic_skills,
        "registry": registry_node is not None,
        "remote_sources": remote_sources,
        "additional_tools": additional_tools,
        "unresolved_additional_tools": sorted(set(unresolved_additional_tools)),
        "script_execution": script_execution,
        "save_output_artifacts": _bool(_kw(call, "save_output_artifacts")),
        "script_timeout": _literal(_kw(call, "script_timeout")),
    }
    return spec, inline_skills


def _apply_adk_skill_toolset(
    agent: Agent,
    spec: dict[str, Any],
    inline_skills: list[Skill],
) -> None:
    agent.metadata.setdefault("adk_skill_toolsets", []).append(spec)

    source_paths = spec.get("source_paths")
    if isinstance(source_paths, list) and source_paths:
        existing = list(agent.metadata.get("skill_source_paths") or [])
        agent.metadata["skill_source_paths"] = list(
            dict.fromkeys([*existing, *source_paths])
        )

    if spec.get("dynamic_skills") is True:
        agent.metadata["dynamic_skill_sources"] = True

    remote = list(agent.metadata.get("remote_skill_sources") or [])
    if spec.get("registry") is True:
        remote.append(
            {
                "provider": "google-adk",
                "source": "SkillRegistry",
                "binding": spec.get("alias"),
            }
        )
    configured_remote = spec.get("remote_sources")
    if isinstance(configured_remote, list):
        remote.extend(
            item for item in configured_remote if isinstance(item, dict)
        )
    if remote:
        unique_remote: list[dict[str, Any]] = []
        seen_remote: set[str] = set()
        for item in remote:
            key = repr(sorted(item.items()))
            if key in seen_remote:
                continue
            seen_remote.add(key)
            unique_remote.append(item)
        agent.metadata["remote_skill_sources"] = unique_remote

    existing = {
        (skill.name, skill.location.line if skill.location else 0)
        for skill in agent.skills
    }
    for skill in inline_skills:
        key = (skill.name, skill.location.line if skill.location else 0)
        if key in existing:
            continue
        skill.metadata["bound_agent"] = agent.name
        agent.skills.append(skill)
        existing.add(key)


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
    *,
    operation_name: str | None = None,
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
                    function_name=operation_name or node.name,
                    context=node,
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
    if isinstance(expr, ast.Starred):
        return _resolve_sequence(expr.value, sequences)
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        return _resolve_sequence(expr.left, sequences) + _resolve_sequence(expr.right, sequences)
    if isinstance(expr, ast.Name):
        # A source-bound name that cannot be statically enumerated must remain
        # visible to the binding layer instead of collapsing to an empty list.
        return list(sequences[expr.id]) if expr.id in sequences else [expr]
    return [expr] if expr is not None else []


def _workflow_node_reference(
    node: ast.AST | None,
    calls: dict[str, ast.Call],
) -> tuple[str | None, bool]:
    """Return a stable workflow-node name and whether it is an ADK agent."""
    if node is None:
        return None, False
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value, False
    if isinstance(node, ast.Name):
        if node.id == "START":
            return "START", False
        call = calls.get(node.id)
        if call is not None and (_call_name(call.func) or "") in AGENT_TYPES:
            return _string(_kw(call, "name")) or node.id, True
        return node.id, False
    if isinstance(node, ast.Attribute):
        return _dotted_name(node) or _call_name(node), False
    if isinstance(node, ast.Call):
        call_name = _call_name(node.func) or ""
        if call_name in AGENT_TYPES:
            return _string(_kw(node, "name")) or call_name, True
        return call_name or _dotted_name(node.func), False
    try:
        return ast.unparse(node), False
    except (AttributeError, ValueError):
        return None, False


def _workflow_graph_topology(
    call: ast.Call,
    calls: dict[str, ast.Call],
    sequences: dict[str, list[ast.AST]],
) -> tuple[list[dict[str, Any]], list[str], bool]:
    """Normalize ADK 2.x Workflow edges without executing routing code."""
    edges_expr = _kw(call, "edges")
    if edges_expr is None:
        return [], [], False

    edges: list[dict[str, Any]] = []
    agent_nodes: list[str] = []
    unresolved = False

    def add_edge(
        source_node: ast.AST | None,
        target_node: ast.AST | None,
        route_node: ast.AST | None = None,
    ) -> None:
        nonlocal unresolved
        source, source_is_agent = _workflow_node_reference(source_node, calls)
        target, target_is_agent = _workflow_node_reference(target_node, calls)
        if not source or not target:
            unresolved = True
            return
        route = _literal(route_node)
        if route_node is not None and route is None:
            route, _ = _workflow_node_reference(route_node, calls)
        entry: dict[str, Any] = {"source": source, "target": target}
        if route is not None:
            entry["route"] = route
        edges.append(entry)
        if source_is_agent and source not in agent_nodes:
            agent_nodes.append(source)
        if target_is_agent and target not in agent_nodes:
            agent_nodes.append(target)

    for row in _resolve_sequence(edges_expr, sequences):
        if isinstance(row, ast.Call) and (_call_name(row.func) or "") == "Edge":
            add_edge(
                _arg(row, 0, "from_node") or _kw(row, "from"),
                _arg(row, 1, "to_node") or _kw(row, "to"),
                _arg(row, 2, "route"),
            )
            continue
        if not isinstance(row, (ast.Tuple, ast.List)) or len(row.elts) < 2:
            unresolved = True
            continue
        first, second, *rest = row.elts
        if isinstance(second, ast.Dict) and not rest:
            for route_node, target_node in zip(second.keys, second.values):
                add_edge(first, target_node, route_node)
            continue
        chain = [first, second, *rest]
        for source_node, target_node in pairwise(chain):
            add_edge(source_node, target_node)

    return edges, agent_nodes, unresolved


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
    """Preserve a source-proven tool binding when catalogue enumeration stops."""
    if expr is None:
        return None

    alias: str | None = None
    source_call: ast.Call | None = None
    source_node = expr
    if isinstance(expr, ast.Name):
        alias = expr.id
        source_call = calls.get(expr.id)
        if source_call is None:
            # A bare unresolved symbol proves only that configuration exists,
            # not that the symbol is a runtime tool collection. Repository
            # resolution may later prove an imported construction.
            return None
    elif isinstance(expr, ast.Await) and isinstance(expr.value, ast.Call):
        source_call = expr.value
        alias = _call_name(source_call.func) or "dynamic_tools"
        source_node = source_call
    elif isinstance(expr, ast.Call):
        source_call = expr
        alias = _call_name(expr.func) or "dynamic_tools"
    elif isinstance(expr, ast.Starred):
        return _dynamic_tool_collection(path, expr.value, calls)
    else:
        try:
            alias = ast.unparse(expr)
        except (AttributeError, ValueError):
            alias = "dynamic_tools"

    called = ""
    catalogue: Any = None
    if source_call is not None:
        called = _dotted_name(source_call.func) or _call_name(source_call.func) or ""
        catalogue = _string(source_call.args[0]) if source_call.args else None

    return Tool(
        name=alias or "dynamic_tools",
        kind="dynamic_tool_collection" if source_call is not None else "unresolved_bound_tool",
        capabilities=set(),
        location=_location(path, source_node),
        metadata={
            "framework": "google-adk",
            "binding_origin": "source_bound_unresolved_tool_binding",
            "dynamic_bound_collection": True,
            "catalogue_source": called or "unresolved_source_binding",
            "catalogue_name": catalogue,
            "tool_scope_unresolved": True,
            "binding_unresolved": True,
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
        origin_source: str | None = None
        first_dynamic = True
        for value in node.values:
            if isinstance(value, ast.Constant):
                continue
            expr = value.value if isinstance(value, ast.FormattedValue) else value
            source = _configuration_source_from_expr(expr, configuration_sources)
            if first_dynamic:
                first_dynamic = False
                if source is None:
                    return None
                origin_source = source
                continue
            if source is not None and source != origin_source:
                return None
        return origin_source
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


def _openapi_payload(
    path: Path,
    call: ast.Call,
    calls: dict[str, ast.Call],
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    values: dict[str, ast.AST] | None = None,
) -> dict[str, Any] | None:
    """Recover a source-visible OpenAPI document without executing target code."""
    spec_node = _kw(call, "spec_dict") or _kw(call, "spec_str")
    values = values or {}
    payload: object | None = None

    literal = _literal(spec_node)
    if literal is None and isinstance(spec_node, ast.Name):
        literal = _literal(values.get(spec_node.id))
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

    return payload if isinstance(payload, dict) else None


def _openapi_servers(payload: dict[str, Any]) -> list[str]:
    """Recover fixed OpenAPI server origins."""
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


def _openapi_operation_semantics(
    payload: dict[str, Any],
) -> tuple[set[str], list[dict[str, Any]], list[str], bool]:
    """Project source-visible OpenAPI methods, mutation risk and auth posture."""
    methods = {"get", "put", "post", "delete", "patch", "head", "options", "trace"}
    operations: list[dict[str, Any]] = []
    capabilities: set[str] = {"network.external"}
    auth_required = bool(payload.get("security"))

    paths = payload.get("paths")
    if isinstance(paths, dict):
        for route, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            for method, operation in path_item.items():
                method_lower = str(method).lower()
                if method_lower not in methods or not isinstance(operation, dict):
                    continue
                mutating = method_lower in {"post", "put", "patch", "delete"}
                destructive = method_lower == "delete"
                operation_security = operation.get("security")
                if operation_security:
                    auth_required = True
                operations.append(
                    {
                        "method": method_lower.upper(),
                        "path": str(route),
                        "operation_id": operation.get("operationId"),
                        "mutating": mutating,
                        "destructive": destructive,
                        "security_required": bool(operation_security),
                    }
                )
                if method_lower in {"get", "head", "options"}:
                    capabilities.add("data.read")
                if mutating:
                    capabilities.update({"data.write", "external.write"})
                if destructive:
                    capabilities.add("destructive.write")

    # API calls return data even when the operation mutates state.
    if operations:
        capabilities.add("data.read")

    schemes: list[str] = []
    components = payload.get("components")
    if isinstance(components, dict):
        raw_schemes = components.get("securitySchemes")
        if isinstance(raw_schemes, dict):
            schemes = sorted(str(name) for name in raw_schemes)

    return capabilities, operations, schemes, auth_required


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
            declaration_line = getattr(server_params, "lineno", None)
            if isinstance(declaration_line, int):
                metadata["wrapped_mcp_declaration_lines"] = [declaration_line]
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
    values: dict[str, ast.AST] | None = None,
    custom_tool_classes: dict[str, ast.ClassDef] | None = None,
) -> Tool | None:
    name = _call_name(call.func) or ""
    custom_tool_classes = custom_tool_classes or {}

    if name in custom_tool_classes:
        custom = _custom_tool_from_call(
            path,
            call,
            alias,
            custom_tool_classes,
        )
        if custom is not None:
            return custom

    if name == "SkillToolset":
        return None

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
            openapi_payload = _openapi_payload(
                path, call, calls, functions, values
            )
            if openapi_payload:
                openapi_servers = _openapi_servers(openapi_payload)
                openapi_caps, openapi_operations, security_schemes, auth_required = (
                    _openapi_operation_semantics(openapi_payload)
                )
                if openapi_operations:
                    caps = openapi_caps
                    metadata["openapi_operations"] = openapi_operations
                    metadata["openapi_methods"] = sorted(
                        {item["method"] for item in openapi_operations}
                    )
                    metadata["operation_semantics_source"] = "openapi_spec"
                if security_schemes:
                    metadata["openapi_security_schemes"] = security_schemes
                metadata["openapi_auth_required"] = auth_required
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


def _before_tool_control_state(
    call: ast.Call,
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> str | None:
    """Classify whether a before-tool callback is source-proven to override execution."""
    callback = _kw(call, "before_tool_callback")
    if callback is None:
        return None
    if isinstance(callback, ast.Lambda):
        return (
            "non_enforcing"
            if isinstance(callback.body, ast.Constant) and callback.body.value is None
            else "enforcing"
        )
    callback_name = _call_name(callback)
    function = functions.get(callback_name or "")
    if function is None:
        return "unresolved"

    returns = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Return)
    ]
    if not returns:
        return "non_enforcing"
    if any(
        node.value is not None
        and not (isinstance(node.value, ast.Constant) and node.value.value is None)
        for node in returns
    ):
        # In ADK, a non-None before_tool_callback return overrides the tool
        # execution. This proves an enforcement path without claiming that the
        # callback always blocks or that its policy is complete.
        return "enforcing"
    return "non_enforcing"


def _custom_base_tool_classes(tree: ast.AST) -> dict[str, ast.ClassDef]:
    """Return source-defined ADK BaseTool subclasses without executing them."""
    classes = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef)
    }
    result: dict[str, ast.ClassDef] = {}
    changed = True
    while changed:
        changed = False
        known_bases = {"BaseTool", *result.keys()}
        for name, node in classes.items():
            if name in result:
                continue
            base_names = {
                (_call_name(base) or (_dotted_name(base) or "").rsplit(".", 1)[-1])
                for base in node.bases
            }
            if base_names & known_bases:
                result[name] = node
                changed = True
    return result


def _custom_tool_runtime_name(
    call: ast.Call,
    alias: str,
    custom_tool_classes: dict[str, ast.ClassDef],
) -> str:
    class_node = custom_tool_classes.get(_call_name(call.func) or "")
    if class_node is None:
        return alias
    init = _custom_class_init(class_node)
    if init is None:
        return alias
    bindings = _custom_constructor_bindings(call, init)
    for super_call in _custom_super_init_calls(init):
        runtime_name = _string(
            _custom_bound_expr(_kw(super_call, "name"), bindings)
        )
        if runtime_name:
            return runtime_name
    return alias


def _custom_tool_from_call(
    path: Path,
    call: ast.Call,
    alias: str,
    custom_tool_classes: dict[str, ast.ClassDef],
) -> Tool | None:
    class_name = _call_name(call.func) or ""
    class_node = custom_tool_classes.get(class_name)
    if class_node is None:
        return None

    runtime_name = _custom_tool_runtime_name(
        call,
        alias,
        custom_tool_classes,
    )
    capabilities: set[str] = set()
    destinations: list[NetworkDestination] = []
    seen_destinations: set[tuple[str, bool, str]] = set()
    for method in class_node.body:
        if not isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if method.name not in {"run", "run_async", "invoke"}:
            continue
        inferred, method_destinations = _infer_function_capabilities(
            method,
            operation_name=runtime_name,
        )
        capabilities.update(inferred)
        for destination in method_destinations:
            key = (
                destination.target,
                destination.restricted,
                str(destination.metadata.get("source") or ""),
            )
            if key in seen_destinations:
                continue
            seen_destinations.add(key)
            destinations.append(destination)

    return Tool(
        name=runtime_name,
        kind="adk_custom_tool",
        capabilities=capabilities,
        destinations=[
            NetworkDestination(
                target=item.target,
                direction=item.direction,
                restricted=item.restricted,
                location=_location(path, call),
                metadata=dict(item.metadata),
            )
            for item in destinations
        ],
        location=_location(path, call),
        metadata={
            "framework": "google-adk",
            "custom_base_tool": True,
            "custom_tool_class": class_name,
            "source_alias": alias,
        },
    )


def _custom_base_agent_classes(tree: ast.AST) -> dict[str, ast.ClassDef]:
    """Return source-defined ADK agent subclasses without executing them."""
    classes = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef)
    }
    result: dict[str, ast.ClassDef] = {}
    changed = True
    while changed:
        changed = False
        known_bases = {"BaseAgent", *AGENT_TYPES, *result.keys()}
        for name, node in classes.items():
            if name in result:
                continue
            base_names = {
                (_call_name(base) or (_dotted_name(base) or "").rsplit(".", 1)[-1])
                for base in node.bases
            }
            if base_names & known_bases:
                result[name] = node
                changed = True
    return result


def _custom_class_init(
    class_node: ast.ClassDef,
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    return next(
        (
            node
            for node in class_node.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == "__init__"
        ),
        None,
    )


def _custom_constructor_bindings(
    call: ast.Call,
    init: ast.FunctionDef | ast.AsyncFunctionDef,
) -> dict[str, ast.AST]:
    positional = [*init.args.posonlyargs, *init.args.args]
    if positional and positional[0].arg in {"self", "cls"}:
        positional = positional[1:]
    bindings: dict[str, ast.AST] = {}

    defaults = list(init.args.defaults)
    if defaults:
        for param, default in zip(positional[-len(defaults):], defaults):
            bindings[param.arg] = default
    for param, value in zip(positional, call.args):
        bindings[param.arg] = value

    for param, default in zip(init.args.kwonlyargs, init.args.kw_defaults):
        if default is not None:
            bindings[param.arg] = default
    for keyword in call.keywords:
        if keyword.arg is not None:
            bindings[keyword.arg] = keyword.value
    return bindings


def _custom_bound_expr(
    node: ast.AST | None,
    bindings: dict[str, ast.AST],
) -> ast.AST | None:
    seen: set[str] = set()
    while isinstance(node, ast.Name) and node.id in bindings and node.id not in seen:
        seen.add(node.id)
        node = bindings[node.id]
    return node


def _custom_super_init_calls(
    init: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[ast.Call]:
    result: list[ast.Call] = []
    for node in ast.walk(init):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "__init__" or not isinstance(node.func.value, ast.Call):
            continue
        if _call_name(node.func.value.func) == "super":
            result.append(node)
    return result


def _custom_agent_runtime_name(
    call: ast.Call,
    alias: str,
    custom_agent_classes: dict[str, ast.ClassDef],
) -> str:
    explicit = _string(_kw(call, "name"))
    if explicit:
        return explicit
    class_node = custom_agent_classes.get(_call_name(call.func) or "")
    if class_node is None:
        return alias
    init = _custom_class_init(class_node)
    if init is None:
        return alias
    bindings = _custom_constructor_bindings(call, init)
    for super_call in _custom_super_init_calls(init):
        runtime_name = _string(
            _custom_bound_expr(_kw(super_call, "name"), bindings)
        )
        if runtime_name:
            return runtime_name
    return alias


def _custom_agent_delegates(
    call: ast.Call,
    calls: dict[str, ast.Call],
    custom_agent_classes: dict[str, ast.ClassDef],
) -> list[str]:
    class_node = custom_agent_classes.get(_call_name(call.func) or "")
    if class_node is None:
        return []
    init = _custom_class_init(class_node)
    if init is None:
        return []

    bindings = _custom_constructor_bindings(call, init)
    local_sequences: dict[str, list[ast.AST]] = {}
    for node in ast.walk(init):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        alias = next((item.id for item in targets if isinstance(item, ast.Name)), None)
        if alias and isinstance(node.value, (ast.List, ast.Tuple, ast.Set)):
            local_sequences[alias] = list(node.value.elts)

    def target_name(expr: ast.AST) -> str | None:
        resolved = expr
        if isinstance(expr, ast.Name) and expr.id in bindings:
            resolved = _custom_bound_expr(expr, bindings) or expr
        if isinstance(resolved, ast.Name) and resolved.id in calls:
            child_call = calls[resolved.id]
            child_type = _call_name(child_call.func) or ""
            if child_type in AGENT_TYPES or child_type in custom_agent_classes:
                if child_type in custom_agent_classes:
                    return _custom_agent_runtime_name(
                        child_call, resolved.id, custom_agent_classes
                    )
                return _string(_kw(child_call, "name")) or resolved.id
        if isinstance(resolved, ast.Call):
            child_type = _call_name(resolved.func) or ""
            if child_type in custom_agent_classes:
                return _custom_agent_runtime_name(
                    resolved, child_type, custom_agent_classes
                )
            if child_type in AGENT_TYPES:
                return _string(_kw(resolved, "name")) or child_type
        return _call_name(resolved)

    delegates: list[str] = []
    for super_call in _custom_super_init_calls(init):
        for child in _resolve_sequence(_kw(super_call, "sub_agents"), local_sequences):
            target = target_name(child)
            if target and target not in delegates:
                delegates.append(target)
    return delegates


def _agent_from_call(
    path: Path,
    call: ast.Call,
    alias: str,
    tools: dict[str, Tool],
    mcp_servers: dict[str, MCPServer],
    calls: dict[str, ast.Call],
    sequences: dict[str, list[ast.AST]],
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    values: dict[str, ast.AST] | None = None,
    custom_agent_classes: dict[str, ast.ClassDef] | None = None,
    custom_tool_classes: dict[str, ast.ClassDef] | None = None,
) -> Agent | None:
    agent_type = _call_name(call.func) or ""
    values = values or {}
    custom_agent_classes = custom_agent_classes or {}
    custom_tool_classes = custom_tool_classes or {}
    custom_base_agent = agent_type in custom_agent_classes
    if agent_type not in AGENT_TYPES and not custom_base_agent:
        return None
    name = (
        _custom_agent_runtime_name(call, alias, custom_agent_classes)
        if custom_base_agent
        else (_string(_kw(call, "name")) or alias)
    )
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
        google_model = model.lower().startswith(("gemini-", "models/gemini"))
        set_model_provenance(
            metadata,
            identifier=model,
            provider="google" if google_model else None,
            hosting="provider_hosted" if google_model else None,
        )
    callbacks = _callbacks(call)
    if callbacks:
        metadata["callbacks"] = callbacks
    tool_control_state = _before_tool_control_state(call, functions)
    if tool_control_state is not None:
        set_tool_control(
            metadata,
            tool_control_state,
            mechanism="adk_before_tool_callback",
        )
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
                source_call = calls[element.id]
                if (_call_name(source_call.func) or "") == "SkillToolset":
                    spec, inline_skills = _adk_skill_toolset_spec(
                        path,
                        source_call,
                        element.id,
                        tools,
                        calls,
                        sequences,
                        functions,
                        values,
                        custom_tool_classes,
                    )
                    _apply_adk_skill_toolset(agent, spec, inline_skills)
                    continue
                direct_mcp = _mcp_from_toolset(
                    path,
                    source_call,
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
                        values,
                        custom_tool_classes,
                    )
                    if direct:
                        agent.tools.append(direct)
                    else:
                        unresolved_binding = _dynamic_tool_collection(path, element, calls)
                        if unresolved_binding:
                            agent.tools.append(unresolved_binding)
            else:
                # Imported or arbitrary helpers remain source-proven bindings
                # even when their runtime type/catalogue cannot be enumerated.
                agent.metadata["external_helper_semantics_unresolved"] = True
                agent.metadata.setdefault("unresolved_helpers", []).append(element.id)
                unresolved_binding = _dynamic_tool_collection(path, element, calls)
                if unresolved_binding:
                    agent.tools.append(unresolved_binding)
        elif isinstance(element, ast.Call):
            if (_call_name(element.func) or "") == "SkillToolset":
                spec, inline_skills = _adk_skill_toolset_spec(
                    path,
                    element,
                    "SkillToolset",
                    tools,
                    calls,
                    sequences,
                    functions,
                    values,
                    custom_tool_classes,
                )
                _apply_adk_skill_toolset(agent, spec, inline_skills)
                continue
            direct_mcp = _mcp_from_toolset(path, element, _call_name(element.func) or "mcp", calls)
            if direct_mcp:
                agent.mcp_servers.append(direct_mcp)
            else:
                direct = _tool_from_call(
                    path,
                    element,
                    _call_name(element.func) or "tool",
                    calls,
                    functions,
                    values,
                    custom_tool_classes,
                )
                if direct:
                    agent.tools.append(direct)
                else:
                    unresolved_binding = _dynamic_tool_collection(path, element, calls)
                    if unresolved_binding:
                        agent.tools.append(unresolved_binding)
        elif isinstance(element, ast.Attribute):
            tool_name = _call_name(element) or "tool"
            caps = set(BUILTIN_TOOL_CAPABILITIES.get(tool_name, set())) or set(infer_capabilities(tool_name))
            tool = Tool(name=tool_name, kind="adk_builtin", capabilities=caps, location=_location(path, element), metadata={"framework": "google-adk", "adk_builtin": tool_name})
            _apply_retrieval_network_semantics(tool, tool_name)
            agent.tools.append(tool)
        else:
            unresolved_binding = _dynamic_tool_collection(path, element, calls)
            if unresolved_binding:
                agent.tools.append(unresolved_binding)

    if any(tool.metadata.get("dynamic_bound_collection") for tool in agent.tools):
        agent.metadata["dynamic_tools"] = True
        agent.metadata["dynamic_tools_source_bound"] = True

    code_node = _kw(call, "code_executor")
    code_call = _resolve_call(code_node, calls)
    if code_call:
        executor = _tool_from_call(path, code_call, _call_name(code_call.func) or "code_executor", calls, functions)
        if executor:
            agent.tools.append(executor)

    delegates: list[str] = []
    if agent_type == "Workflow":
        workflow_edges, workflow_agents, workflow_unresolved = _workflow_graph_topology(
            call,
            calls,
            sequences,
        )
        if workflow_edges:
            agent.metadata["workflow_edges"] = workflow_edges
        if workflow_unresolved:
            agent.metadata["workflow_topology_unresolved"] = True
        delegates.extend(workflow_agents)

    for element in _resolve_sequence(_kw(call, "sub_agents"), sequences):
        target = _call_name(element)
        if isinstance(element, ast.Name) and element.id in calls:
            target_call = calls[element.id]
            target_type = _call_name(target_call.func) or ""
            if target_type in custom_agent_classes:
                target = _custom_agent_runtime_name(
                    target_call, element.id, custom_agent_classes
                )
            elif target_type in AGENT_TYPES:
                target = _string(_kw(target_call, "name")) or target
        if isinstance(element, ast.Call):
            target = _string(_kw(element, "name")) or _call_name(element.func)
        if target:
            delegates.append(target)
    if custom_base_agent:
        delegates.extend(
            _custom_agent_delegates(call, calls, custom_agent_classes)
        )
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
    custom_tool_classes = _custom_base_tool_classes(tree)
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
    values: dict[str, ast.AST] = {}
    tools: dict[str, Tool] = {}
    mcp_servers: dict[str, MCPServer] = {}
    identities: dict[str, Identity] = {}
    agent_calls: list[tuple[str, ast.Call, str]] = []
    scoped_calls: dict[str, dict[str, ast.Call]] = {}
    scoped_sequences: dict[str, dict[str, list[ast.AST]]] = {}
    scoped_values: dict[str, dict[str, ast.AST]] = {}
    safety_plugins: set[str] = set()

    # ADK applications commonly construct and return an Agent from a local
    # factory, then expose it as `root_agent = create_agent()`. Preserve the
    # returned Agent's lexical scope so locally-created Tool/MCPToolset aliases
    # remain visible when the factory invocation is normalized.
    factory_agent_returns: dict[str, tuple[ast.Call, str]] = {}
    for function_name, function in functions.items():
        function_scope = (
            f"{function.name}@{getattr(function, 'lineno', 0) or 0}"
        )
        returned_agents: list[ast.Call] = []
        for candidate in ast.walk(function):
            if (
                not isinstance(candidate, ast.Return)
                or not isinstance(candidate.value, ast.Call)
                or _lexical_scope(tree, candidate) != function_scope
            ):
                continue
            returned_type = _call_name(candidate.value.func) or ""
            if returned_type in AGENT_TYPES or returned_type in custom_agent_classes:
                returned_agents.append(candidate.value)
        if len(returned_agents) == 1:
            factory_agent_returns[function_name] = (
                returned_agents[0],
                function_scope,
            )

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
            if not isinstance(value, ast.Call):
                values[alias] = value
                scoped_values.setdefault(scope, {})[alias] = value
                continue
            if isinstance(value, ast.Call):
                calls[alias] = value
                scoped_calls.setdefault(scope, {})[alias] = value
                call_name = _call_name(value.func) or ""
                if call_name in AGENT_TYPES or call_name in custom_agent_classes:
                    agent_calls.append((alias, value, scope))
                    continue
                factory_return = factory_agent_returns.get(call_name)
                if factory_return is not None:
                    returned_agent, factory_scope = factory_return
                    agent_calls.append((alias, returned_agent, factory_scope))
                    continue
                mcp = _mcp_from_toolset(path, value, alias, calls)
                if mcp:
                    mcp_servers[alias] = mcp
                    continue
                identity = _identity_from_call(path, alias, value)
                if identity:
                    identities[alias] = identity
                tool = _tool_from_call(
                    path,
                    value,
                    alias,
                    calls,
                    functions,
                    values,
                    custom_tool_classes,
                )
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
        alias = node.func.value.id
        sequence = sequences.get(alias)
        if sequence is None:
            continue
        scope = _lexical_scope(tree, node)
        scoped_sequence = scoped_sequences.get(scope, {}).get(alias)
        targets = [sequence]
        if scoped_sequence is not None and scoped_sequence is not sequence:
            targets.append(scoped_sequence)
        if node.func.attr == "append" and len(node.args) == 1:
            for target in targets:
                target.append(node.args[0])
        elif node.func.attr == "extend" and len(node.args) == 1:
            arg = node.args[0]
            additions: list[ast.AST] = []
            if isinstance(arg, (ast.List, ast.Tuple, ast.Set)):
                additions = list(arg.elts)
            elif isinstance(arg, ast.Name) and arg.id in sequences:
                additions = list(sequences[arg.id])
            for target in targets:
                target.extend(additions)

    # Build lexical-scope views so repeated aliases inside separate functions
    # resolve to the construction visible in that function rather than the last
    # same-named assignment encountered elsewhere in the module.
    module_calls = scoped_calls.get("__module__", {})
    module_sequences = scoped_sequences.get("__module__", {})
    module_values = scoped_values.get("__module__", {})
    scoped_tools: dict[str, dict[str, Tool]] = {}
    scoped_mcp_servers: dict[str, dict[str, MCPServer]] = {}
    for scope, scope_calls in scoped_calls.items():
        visible_calls = {**module_calls, **scope_calls}
        visible_sequences = {
            **module_sequences,
            **scoped_sequences.get(scope, {}),
        }
        visible_values = {
            **module_values,
            **scoped_values.get(scope, {}),
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
                visible_values,
                custom_tool_classes,
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
        tool = _tool_from_call(
            path,
            call,
            alias,
            calls,
            functions,
            values,
            custom_tool_classes,
        )
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
            visible_values,
            custom_agent_classes,
            custom_tool_classes,
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

            pending = [function]
            visited: set[str] = set()
            while pending:
                current = pending.pop()
                if current.name in visited:
                    continue
                visited.add(current.name)
                _apply_operator_configured_function_destinations(
                    tool,
                    current,
                    configuration_sources,
                )
                for call in (
                    node
                    for node in ast.walk(current)
                    if isinstance(node, ast.Call)
                ):
                    helper_name = _call_name(call.func)
                    helper = functions.get(helper_name or "")
                    if helper is not None and helper.name not in visited:
                        pending.append(helper)

    return graph
