from __future__ import annotations

import ast
import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

from horustrace.heuristics import infer_capabilities
from horustrace.models import (
    Agent,
    DataSource,
    Graph,
    Identity,
    MCPServer,
    NetworkDestination,
    ResourceScope,
    SourceLocation,
    Tool,
)

STRANDS_FRAMEWORK = "strands-agents"
BEDROCK_FRAMEWORK = "amazon-bedrock-agents"
AGENTCORE_FRAMEWORK = "amazon-bedrock-agentcore"

AMAZON_AGENTIC_CONFIG_FILENAMES = {
    "agentcore.json",
    ".bedrock_agentcore.yaml",
    ".bedrock_agentcore.yml",
}

_URL_RE = re.compile(r"https?://[^\s\"'<>]+")
_ARN_RE = re.compile(r"arn:aws(?:-[^:]+)?:[A-Za-z0-9_-]+:[^\s\"']+")
_S3_RE = re.compile(r"s3://[^\s\"']+")

_VENDED_TOOL_CAPABILITIES: dict[str, set[str]] = {
    "file_editor": {"data.read", "data.write"},
    "file_read": {"data.read"},
    "file_write": {"data.write"},
    "editor": {"data.read", "data.write"},
    "shell": {
        "data.read",
        "data.write",
        "process.execute",
        "network.external",
        "external.write",
        "destructive.write",
    },
    "python_repl": {"data.read", "data.write", "process.execute"},
    "http_request": {"data.read", "network.external", "external.write"},
    "retrieve": {"data.read", "network.external"},
    "use_aws": {"data.read", "data.write", "network.external", "external.write"},
}


def _location(path: Path, node: ast.AST | None = None, line: int = 1) -> SourceLocation:
    if node is None:
        return SourceLocation(path, line, 1)
    return SourceLocation(
        path,
        getattr(node, "lineno", line) or line,
        (getattr(node, "col_offset", 0) or 0) + 1,
    )


def _leaf(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _literal(node: ast.AST | None) -> Any:
    if node is None:
        return None
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError):
        return None


def _literal_string(node: ast.AST | None) -> str | None:
    value = _literal(node)
    return value if isinstance(value, str) else None


def _keyword(call: ast.Call, name: str) -> ast.AST | None:
    return next((item.value for item in call.keywords if item.arg == name), None)


def _assignment_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Assign):
        return next((target.id for target in node.targets if isinstance(target, ast.Name)), None)
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return node.target.id
    return None


def _call_value(node: ast.AST) -> ast.Call | None:
    value = node.value if isinstance(node, (ast.Assign, ast.AnnAssign)) else None
    if isinstance(value, ast.Call):
        return value
    if isinstance(value, ast.Await) and isinstance(value.value, ast.Call):
        return value.value
    return None


def _attach_literal_destinations(tool: Tool, text: str) -> None:
    if "network.external" not in tool.capabilities:
        return
    seen = {item.target for item in tool.destinations}
    for raw in _URL_RE.findall(text):
        target = raw.rstrip('",);]}')
        if target in seen:
            continue
        tool.destinations.append(
            NetworkDestination(
                target=target,
                restricted=True,
                location=tool.location,
                metadata={"source": "literal_url", "network_scope": "fixed_literal_destination"},
            )
        )
        seen.add(target)


def _attach_literal_resources(tool: Tool, text: str) -> None:
    seen = {(item.kind, item.selector) for item in tool.resources}
    for arn in _ARN_RE.findall(text):
        key = ("aws_arn", arn)
        if key in seen:
            continue
        tool.resources.append(
            ResourceScope(
                kind="aws_arn",
                selector=arn,
                access=set(tool.capabilities),
                location=tool.location,
                metadata={"source": "literal_arn"},
            )
        )
        seen.add(key)
    for uri in _S3_RE.findall(text):
        selector = uri.rstrip('",);]}')
        key = ("s3", selector)
        if key in seen:
            continue
        access = {cap for cap in tool.capabilities if cap in {"data.read", "data.write"}}
        tool.resources.append(
            ResourceScope(
                kind="s3",
                selector=selector,
                access=access or {"data.read"},
                location=tool.location,
                metadata={"source": "literal_s3_uri"},
            )
        )
        seen.add(key)


def _python_effect_capabilities(node: ast.AST) -> set[str]:
    text = ast.unparse(node).lower()
    capabilities = set(infer_capabilities(getattr(node, "name", "")))
    if any(
        marker in text
        for marker in ("subprocess.", "os.system(", "os.popen(", "create_subprocess")
    ):
        capabilities.add("process.execute")
    if any(
        marker in text
        for marker in (
            "requests.",
            "httpx.",
            "aiohttp.",
            "urllib.request",
            "socket.",
        )
    ):
        capabilities.add("network.external")
    if any(
        marker in text
        for marker in (".post(", ".put(", ".patch(", "send_message", "send_email")
    ):
        capabilities.update({"data.write", "external.write"})
    if any(marker in text for marker in (".delete(", "os.remove(", "os.unlink(", "shutil.rmtree(")):
        capabilities.update({"data.write", "destructive.write"})
    if any(marker in text for marker in ("get_secret_value", "secretsmanager", "secretclient")):
        capabilities.add("secrets.read")
    if any(marker in text for marker in ("get_object", "download_file", "query(", "scan(")):
        capabilities.add("data.read")
    if any(marker in text for marker in ("put_object", "upload_file", "put_item", "update_item")):
        capabilities.add("data.write")
    if "delete_item" in text or "delete_object" in text:
        capabilities.update({"data.write", "destructive.write"})
    if "boto3.client(" in text or "boto3.resource(" in text:
        capabilities.add("network.external")
    return capabilities


def _custom_tools(path: Path, tree: ast.AST) -> dict[str, Tool]:
    result: dict[str, Tool] = {}
    functions = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    for name, node in functions.items():
        if not any(
            _leaf(dec.func if isinstance(dec, ast.Call) else dec) == "tool"
            for dec in node.decorator_list
        ):
            continue
        explicit_name = None
        for dec in node.decorator_list:
            if isinstance(dec, ast.Call) and _leaf(dec.func) == "tool":
                explicit_name = _literal_string(_keyword(dec, "name"))
                if explicit_name is None and dec.args:
                    explicit_name = _literal_string(dec.args[0])
        tool = Tool(
            name=explicit_name or name,
            kind="function",
            capabilities=_python_effect_capabilities(node),
            location=_location(path, node),
            metadata={"framework": STRANDS_FRAMEWORK, "binding_origin": "@tool", "wrapped": name},
        )
        text = ast.unparse(node)
        _attach_literal_destinations(tool, text)
        _attach_literal_resources(tool, text)
        result[name] = tool

    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        name = _assignment_name(node)
        call = _call_value(node)
        if not name or not call or _leaf(call.func) != "tool":
            continue
        wrapped = call.args[0].id if call.args and isinstance(call.args[0], ast.Name) else None
        body = functions.get(wrapped) if wrapped else None
        explicit_name = _literal_string(_keyword(call, "name"))
        item = Tool(
            name=explicit_name or name,
            kind="function",
            capabilities=_python_effect_capabilities(body) if body else set(),
            location=_location(path, node),
            metadata={
                "framework": STRANDS_FRAMEWORK,
                "binding_origin": "tool()",
                "wrapped": wrapped,
                "declaration_only": body is None,
            },
        )
        if body:
            text = ast.unparse(body)
            _attach_literal_destinations(item, text)
            _attach_literal_resources(item, text)
        result[name] = item
    return result


def _vended_tool_imports(tree: ast.AST, path: Path) -> dict[str, Tool]:
    result: dict[str, Tool] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        module = node.module or ""
        if not (
            module == "strands_tools"
            or module.startswith(("strands.vended_tools", "strands_tools."))
        ):
            continue
        for alias in node.names:
            local_name = alias.asname or alias.name
            capabilities = set(
                _VENDED_TOOL_CAPABILITIES.get(alias.name, infer_capabilities(alias.name))
            )
            result[local_name] = Tool(
                name=alias.name,
                kind="strands_vended_tool",
                capabilities=capabilities,
                location=_location(path, node),
                metadata={
                    "framework": STRANDS_FRAMEWORK,
                    "source_module": module,
                    "import_name": local_name,
                },
            )
    return result


def _mcp_filters(call: ast.Call) -> tuple[list[str], list[str]]:
    value = _literal(_keyword(call, "tool_filters"))
    if not isinstance(value, dict):
        return [], []
    allowed = value.get("allowed") or value.get("allow") or []
    denied = value.get("denied") or value.get("deny") or []
    return (
        [str(item) for item in allowed] if isinstance(allowed, list) else [],
        [str(item) for item in denied] if isinstance(denied, list) else [],
    )


def _mcp_server_from_call(path: Path, name: str, call: ast.Call) -> MCPServer:
    allowed, denied = _mcp_filters(call)
    nested_calls = [item for item in ast.walk(call) if isinstance(item, ast.Call)]
    url: str | None = None
    command: str | None = None
    args: list[str] = []
    authenticated: bool | None = None
    transport = "unknown"
    for nested in nested_calls:
        leaf = (_leaf(nested.func) or "").lower()
        if leaf in {"sse_client", "streamablehttp_client", "streamable_http_client"}:
            transport = "sse" if leaf == "sse_client" else "streamable-http"
            if nested.args:
                url = _literal_string(nested.args[0])
            url = url or _literal_string(_keyword(nested, "url"))
            headers = _literal(_keyword(nested, "headers"))
            authenticated = bool(headers) if isinstance(headers, dict) else None
        elif leaf == "stdioserverparameters":
            transport = "stdio"
            command = _literal_string(_keyword(nested, "command"))
            raw_args = _literal(_keyword(nested, "args"))
            if isinstance(raw_args, list):
                args = [str(item) for item in raw_args]
    metadata: dict[str, Any] = {"framework": STRANDS_FRAMEWORK, "provider": "strands"}
    if transport in {"sse", "streamable-http"} and url is None:
        metadata.update(
            {
                "dynamic_mcp_endpoint_basis": "operator_configuration",
                "network_scope": "operator_configured_destination",
            }
        )
    return MCPServer(
        name=name,
        transport=transport,
        url=url,
        command=command,
        args=args,
        authenticated=authenticated,
        allowed_tools=allowed,
        denied_tools=denied,
        location=_location(path, call),
        metadata=metadata,
    )


def _model_metadata(node: ast.AST | None) -> dict[str, Any]:
    if node is None:
        return {"model_provider": "amazon-bedrock", "model_default": True}
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {"model": node.value}
    if isinstance(node, ast.Call):
        leaf = _leaf(node.func) or ""
        model_id = _literal_string(_keyword(node, "model_id")) or _literal_string(
            _keyword(node, "model")
        )
        provider = {
            "BedrockModel": "amazon-bedrock",
            "AnthropicModel": "anthropic",
            "OpenAIModel": "openai",
            "GeminiModel": "google",
            "OllamaModel": "ollama",
        }.get(leaf, leaf or "custom")
        result: dict[str, Any] = {"model_provider": provider}
        if model_id:
            result["model"] = model_id
        return result
    if isinstance(node, ast.Name):
        return {"model_reference": node.id}
    return {"model_dynamic": True}


def _aws_runtime_identity(
    path: Path,
    location: SourceLocation,
    model_meta: dict[str, Any],
) -> Identity | None:
    provider = model_meta.get("model_provider")
    if provider != "amazon-bedrock" and not model_meta.get("model_default"):
        return None
    return Identity(
        name="aws-runtime-credentials",
        provider="aws",
        credential_source="aws_default_credential_chain",
        location=location,
        metadata={"runtime_resolved": True, "framework": STRANDS_FRAMEWORK},
    )


def _tool_expressions(node: ast.AST | None) -> list[ast.AST]:
    """Flatten statically visible Strands tool collection composition."""
    if node is None:
        return []
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        result: list[ast.AST] = []
        for item in node.elts:
            result.extend(_tool_expressions(item))
        return result
    if isinstance(node, ast.Starred):
        return _tool_expressions(node.value)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return [*_tool_expressions(node.left), *_tool_expressions(node.right)]
    if isinstance(node, ast.IfExp):
        return [*_tool_expressions(node.body), *_tool_expressions(node.orelse)]
    return [node]


def _delegated_agent_tool(
    parent: Agent,
    child: Agent,
    *,
    name: str | None = None,
    basis: str = "strands_agent_as_tool",
) -> Tool:
    return Tool(
        name=name or child.name,
        kind="delegated_agent",
        capabilities={"agent.delegate"} | set(child.capabilities),
        resources=deepcopy(child.effective_resources),
        destinations=deepcopy(child.effective_destinations),
        location=parent.location,
        metadata={
            "framework": STRANDS_FRAMEWORK,
            "delegate_target": child.name,
            "authority_binding": "delegation_projection",
            "authority_binding_basis": basis,
        },
    )


def _hook_classes(tree: ast.AST) -> dict[str, ast.ClassDef]:
    return {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef)
    }


def _hook_class_control_state(node: ast.ClassDef) -> str:
    """Classify source-visible Strands hook enforcement without executing it."""
    for child in ast.walk(node):
        if isinstance(child, (ast.Assign, ast.AnnAssign)):
            targets = child.targets if isinstance(child, ast.Assign) else [child.target]
            if any(
                isinstance(target, ast.Attribute)
                and target.attr in {"cancel_tool", "cancel_node"}
                for target in targets
            ):
                return "enforcing"
        if isinstance(child, ast.Call):
            leaf = (_leaf(child.func) or "").lower()
            if leaf in {"interrupt", "cancel_tool", "cancel_node"}:
                return "enforcing"
    return "non_enforcing"


def _hooks_control_state(
    tree: ast.AST,
    node: ast.AST | None,
) -> tuple[str | None, list[str]]:
    if node is None:
        return None, []
    classes = _hook_classes(tree)
    states: list[str] = []
    names: list[str] = []
    for item in _tool_expressions(node):
        name: str | None = None
        if isinstance(item, ast.Call):
            name = _leaf(item.func)
        elif isinstance(item, ast.Name):
            name = item.id
        if not name:
            continue
        names.append(name)
        hook_class = classes.get(name)
        states.append(
            _hook_class_control_state(hook_class)
            if hook_class is not None
            else "unresolved"
        )
    if not states:
        return "unresolved", names
    if "enforcing" in states:
        return "enforcing", names
    if all(state == "non_enforcing" for state in states):
        return "non_enforcing", names
    return "unresolved", names


def _a2a_provider_tool(
    path: Path,
    name: str,
    call: ast.Call,
    assignment_calls: dict[str, ast.Call],
) -> Tool:
    known_urls = _keyword(call, "known_agent_urls")
    destinations: list[NetworkDestination] = []
    dynamic = False
    if isinstance(known_urls, (ast.List, ast.Tuple, ast.Set)):
        for item in known_urls.elts:
            literal = _literal_string(item)
            if literal and literal.startswith(("http://", "https://")):
                destinations.append(
                    NetworkDestination(
                        target=literal,
                        restricted=True,
                        location=_location(path, item),
                        metadata={
                            "source": "a2a_known_agent_url",
                            "network_scope": "fixed_literal_destination",
                        },
                    )
                )
            else:
                dynamic = True
    elif known_urls is not None:
        dynamic = True

    if dynamic or not destinations:
        destinations.append(
            NetworkDestination(
                target="<runtime-discovered-a2a-agent>",
                restricted=False,
                location=_location(path, call),
                metadata={
                    "source": "a2a_known_agent_urls",
                    "network_scope": "dynamic_destination",
                },
            )
        )

    authenticated = False
    auth_scheme: str | None = None
    httpx_args = _keyword(call, "httpx_client_args")
    if isinstance(httpx_args, ast.Dict):
        for key, value in zip(httpx_args.keys, httpx_args.values):
            if _literal_string(key) != "auth":
                continue
            authenticated = True
            if isinstance(value, ast.Name):
                auth_call = assignment_calls.get(value.id)
                if auth_call and (_leaf(auth_call.func) or "").lower() == "sigv4httpxauth":
                    auth_scheme = "sigv4"
            elif isinstance(value, ast.Call):
                if (_leaf(value.func) or "").lower() == "sigv4httpxauth":
                    auth_scheme = "sigv4"

    return Tool(
        name=name,
        kind="strands_a2a_provider",
        capabilities={"agent.delegate", "network.external", "external.write"},
        destinations=destinations,
        guardrails=authenticated,
        location=_location(path, call),
        metadata={
            "framework": STRANDS_FRAMEWORK,
            "a2a": True,
            "binding_origin": "A2AClientToolProvider.tools",
            "dynamic_bound_collection": True,
            "binding_unresolved": True,
            "tool_catalogue_unresolved": True,
            "remote_catalogue_unresolved": True,
            "destination_provenance": "known_agent_urls",
            "dynamic_destination": dynamic or not any(d.restricted for d in destinations),
            "authenticated": authenticated,
            "auth_scheme": auth_scheme,
        },
    )


def _scan_strands_python(path: Path, tree: ast.AST) -> Graph:
    graph = Graph()
    imports_strands = False
    agent_symbols: set[str] = set()
    harness_symbols: set[str] = set()
    mcp_symbols: set[str] = set()
    graph_builder_symbols: set[str] = set()
    swarm_symbols: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if (
                    alias.name == "strands"
                    or alias.name.startswith("strands.")
                    or alias.name == "strands_harness"
                    or alias.name.startswith("strands_harness.")
                ):
                    imports_strands = True
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module in {"strands", "strands_harness"} or module.startswith(
                ("strands.", "strands_harness.")
            ):
                imports_strands = True
            if module == "strands_harness":
                for alias in node.names:
                    if alias.name == "create_harness":
                        harness_symbols.add(alias.asname or alias.name)
            if module == "strands":
                for alias in node.names:
                    if alias.name == "Agent":
                        agent_symbols.add(alias.asname or alias.name)
            if module == "strands.tools.mcp" or module.startswith("strands.tools.mcp."):
                for alias in node.names:
                    if alias.name == "MCPClient":
                        mcp_symbols.add(alias.asname or alias.name)
            if module == "strands.multiagent" or module.startswith("strands.multiagent."):
                for alias in node.names:
                    if alias.name == "GraphBuilder":
                        graph_builder_symbols.add(alias.asname or alias.name)
                    elif alias.name == "Swarm":
                        swarm_symbols.add(alias.asname or alias.name)
    if not imports_strands:
        return graph

    custom_tools = _custom_tools(path, tree)
    vended_tools = _vended_tool_imports(tree, path)
    tool_lookup = {**vended_tools, **custom_tools}

    assignment_calls: dict[str, ast.Call] = {}
    mcp_lookup: dict[str, MCPServer] = {}
    a2a_lookup: dict[str, Tool] = {}
    agent_calls: list[tuple[str, ast.Call, ast.AST]] = []
    graph_builders: dict[str, dict[str, Any]] = {}
    graph_results: list[tuple[str, str, ast.AST]] = []
    swarm_calls: list[tuple[str, ast.Call, ast.AST]] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        name = _assignment_name(node)
        call = _call_value(node)
        if not name or call is None:
            continue
        assignment_calls[name] = call
        leaf = _leaf(call.func)
        if leaf in mcp_symbols or leaf == "MCPClient":
            mcp_lookup[name] = _mcp_server_from_call(path, name, call)
        if leaf in agent_symbols or leaf == "Agent" or leaf in harness_symbols or leaf == "create_harness":
            agent_calls.append((name, call, node))
        if leaf == "A2AClientToolProvider":
            a2a_lookup[name] = _a2a_provider_tool(
                path, name, call, assignment_calls
            )
        if leaf in graph_builder_symbols or leaf == "GraphBuilder":
            graph_builders[name] = {
                "nodes": {},
                "edges": [],
                "entry_point": None,
                "max_node_executions": None,
                "execution_timeout": None,
                "node_timeout": None,
                "hooks": None,
            }
        if leaf in swarm_symbols or leaf == "Swarm":
            swarm_calls.append((name, call, node))
        if (
            isinstance(call.func, ast.Attribute)
            and call.func.attr == "build"
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id in graph_builders
        ):
            graph_results.append((name, call.func.value.id, node))

    # Recover GraphBuilder topology from method calls.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if not isinstance(node.func.value, ast.Name):
            continue
        builder_name = node.func.value.id
        spec = graph_builders.get(builder_name)
        if spec is None:
            continue
        method = node.func.attr
        if method == "add_node" and node.args:
            executor = node.args[0]
            if isinstance(executor, ast.Name):
                node_id = (
                    _literal_string(node.args[1])
                    if len(node.args) > 1
                    else executor.id
                ) or executor.id
                spec["nodes"][node_id] = executor.id
        elif method == "add_edge" and len(node.args) >= 2:
            source = _literal_string(node.args[0])
            target = _literal_string(node.args[1])
            if source and target:
                spec["edges"].append({"source": source, "target": target})
        elif method == "set_entry_point" and node.args:
            spec["entry_point"] = _literal_string(node.args[0])
        elif method == "set_max_node_executions" and node.args:
            spec["max_node_executions"] = _literal(node.args[0])
        elif method == "set_execution_timeout" and node.args:
            spec["execution_timeout"] = _literal(node.args[0])
        elif method == "set_node_timeout" and node.args:
            spec["node_timeout"] = _literal(node.args[0])
        elif method == "set_hook_providers" and node.args:
            spec["hooks"] = node.args[0]

    agents: dict[str, Agent] = {}
    raw_tools: dict[str, list[ast.AST]] = {}
    for name, call, binding in agent_calls:
        location = _location(path, binding)
        model_meta = _model_metadata(_keyword(call, "model"))
        agent = Agent(
            name=name,
            location=location,
            metadata={
                "framework": STRANDS_FRAMEWORK,
                "language": "python",
                **model_meta,
            },
        )
        if _leaf(call.func) in harness_symbols or _leaf(call.func) == "create_harness":
            agent.metadata["agent_type"] = "strands_harness"
            skills_node = _keyword(call, "skills")
            if skills_node is None:
                agent.metadata["skill_source_paths"] = ["./.agent/skills"]
            elif not (
                isinstance(skills_node, ast.Constant) and skills_node.value is None
            ):
                raw_skills = _literal(skills_node)
                if isinstance(raw_skills, str):
                    agent.metadata["skill_source_paths"] = [raw_skills]
                elif isinstance(raw_skills, (list, tuple)):
                    agent.metadata["skill_source_paths"] = [
                        str(item) for item in raw_skills if isinstance(item, str)
                    ]
                else:
                    agent.metadata["dynamic_skill_sources"] = True
        system_prompt = _literal_string(_keyword(call, "system_prompt"))
        if system_prompt is not None:
            agent.metadata["system_prompt_declared"] = True
        identity = _aws_runtime_identity(path, location, model_meta)
        if identity is not None:
            agent.identities.append(identity)

        hook_state, hook_names = _hooks_control_state(tree, _keyword(call, "hooks"))
        if hook_names:
            agent.metadata["hooks"] = hook_names
            agent.metadata["hook_control_state"] = hook_state
            agent.metadata["tool_control_state"] = hook_state
            agent.metadata["tool_control_enforcing"] = hook_state == "enforcing"

        raw_tools[name] = _tool_expressions(_keyword(call, "tools"))
        agents[name] = agent

    def bind_tool_expression(agent: Agent, expr: ast.AST) -> None:
        if isinstance(expr, ast.Name):
            ref = expr.id
            if ref in tool_lookup:
                agent.tools.append(deepcopy(tool_lookup[ref]))
                return
            if ref in mcp_lookup:
                agent.mcp_servers.append(deepcopy(mcp_lookup[ref]))
                return
            if ref in a2a_lookup:
                agent.tools.append(deepcopy(a2a_lookup[ref]))
                return
            child = agents.get(ref)
            if child is not None and child is not agent:
                agent.tools.append(_delegated_agent_tool(agent, child))
                agent.metadata.setdefault("delegates_to", []).append(child.name)
                return

        if (
            isinstance(expr, ast.Attribute)
            and expr.attr == "tools"
            and isinstance(expr.value, ast.Name)
            and expr.value.id in a2a_lookup
        ):
            agent.tools.append(deepcopy(a2a_lookup[expr.value.id]))
            return

        if (
            isinstance(expr, ast.Call)
            and isinstance(expr.func, ast.Attribute)
            and expr.func.attr in {"as_tool", "asTool"}
            and isinstance(expr.func.value, ast.Name)
        ):
            child = agents.get(expr.func.value.id)
            if child is not None and child is not agent:
                alias = _literal_string(_keyword(expr, "name")) or child.name
                agent.tools.append(
                    _delegated_agent_tool(
                        agent,
                        child,
                        name=alias,
                        basis="strands_agent_as_tool_explicit",
                    )
                )
                agent.metadata.setdefault("delegates_to", []).append(child.name)

    for name, agent in agents.items():
        for expr in raw_tools.get(name, []):
            bind_tool_expression(agent, expr)
        graph.agents.append(agent)

    # Materialize GraphBuilder results as authority-bearing orchestrators.
    for result_name, builder_name, binding in graph_results:
        spec = graph_builders[builder_name]
        orchestrator = Agent(
            name=result_name,
            location=_location(path, binding),
            metadata={
                "framework": STRANDS_FRAMEWORK,
                "language": "python",
                "multiagent_type": "graph",
                "workflow": "graph",
                "workflow_edges": list(spec["edges"]),
                "entry_point": spec["entry_point"],
                "max_node_executions": spec["max_node_executions"],
                "execution_timeout": spec["execution_timeout"],
                "node_timeout": spec["node_timeout"],
            },
        )
        hook_state, hook_names = _hooks_control_state(tree, spec.get("hooks"))
        if hook_names:
            orchestrator.metadata["hooks"] = hook_names
            orchestrator.metadata["hook_control_state"] = hook_state
            orchestrator.metadata["tool_control_state"] = hook_state
            orchestrator.metadata["tool_control_enforcing"] = hook_state == "enforcing"
        delegates: list[str] = []
        for node_id, ref in spec["nodes"].items():
            child = agents.get(ref)
            if child is None:
                continue
            delegates.append(child.name)
            orchestrator.tools.append(
                _delegated_agent_tool(
                    orchestrator,
                    child,
                    name=node_id,
                    basis="strands_graph_node",
                )
            )
        if delegates:
            orchestrator.metadata["delegates_to"] = list(dict.fromkeys(delegates))
        graph.agents.append(orchestrator)

    # Materialize Swarm membership and safety bounds.
    for name, call, binding in swarm_calls:
        members_node = call.args[0] if call.args else _keyword(call, "nodes")
        member_refs = [
            item.id
            for item in _tool_expressions(members_node)
            if isinstance(item, ast.Name)
        ]
        swarm = Agent(
            name=name,
            location=_location(path, binding),
            metadata={
                "framework": STRANDS_FRAMEWORK,
                "language": "python",
                "multiagent_type": "swarm",
                "workflow": "swarm",
                "handoff_topology": "dynamic",
                "max_handoffs": _literal(_keyword(call, "max_handoffs")),
                "max_iterations": _literal(_keyword(call, "max_iterations")),
                "execution_timeout": _literal(_keyword(call, "execution_timeout")),
                "node_timeout": _literal(_keyword(call, "node_timeout")),
                "entry_point": (
                    _literal_string(_keyword(call, "entry_point"))
                    or (member_refs[0] if member_refs else None)
                ),
            },
        )
        delegates: list[str] = []
        for ref in member_refs:
            child = agents.get(ref)
            if child is None:
                continue
            delegates.append(child.name)
            swarm.tools.append(
                _delegated_agent_tool(
                    swarm,
                    child,
                    basis="strands_swarm_member",
                )
            )
        if delegates:
            swarm.metadata["delegates_to"] = list(dict.fromkeys(delegates))
        graph.agents.append(swarm)

    bound_mcp = {server.name for agent in graph.agents for server in agent.mcp_servers}
    graph.unbound_mcp_servers.extend(
        server for name, server in mcp_lookup.items() if name not in bound_mcp
    )
    bound_tools = {tool.name for agent in graph.agents for tool in agent.tools}
    graph.unbound_tools.extend(
        tool for tool in tool_lookup.values() if tool.name not in bound_tools
    )
    return graph


def is_amazon_agentic_python_file(path: Path) -> bool:
    if path.suffix.lower() != ".py":
        return False
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False
    return (
        "from strands" in source
        or "import strands" in source
        or "bedrock_agentcore" in source
        or "bedrock-agentcore" in source
    )


def scan_amazon_agentic_python_file(path: Path) -> Graph:
    if not is_amazon_agentic_python_file(path):
        return Graph()
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return Graph()
    return _scan_strands_python(path, tree)


def _identity_from_role(role: Any, location: SourceLocation, *, source: str) -> Identity | None:
    if not isinstance(role, str) or not role:
        return None
    return Identity(
        name=role,
        provider="aws",
        roles={role},
        credential_source="iam_role",
        location=location,
        metadata={"framework": AGENTCORE_FRAMEWORK, "source": source},
    )


def _agentcore_runtime_from_dict(path: Path, raw: dict[str, Any], *, source: str) -> Agent | None:
    name = raw.get("name") or raw.get("agentRuntimeName") or raw.get("AgentRuntimeName")
    if not isinstance(name, str) or not name:
        return None
    location = SourceLocation(path)
    agent = Agent(
        name=name,
        location=location,
        metadata={
            "framework": AGENTCORE_FRAMEWORK,
            "runtime": "bedrock-agentcore",
            "configuration_source": source,
        },
    )
    for key in ("build", "entrypoint", "codeLocation", "runtimeVersion", "networkMode", "protocol"):
        if key in raw:
            agent.metadata[key] = raw[key]
    role = (
        raw.get("executionRole")
        or raw.get("executionRoleArn")
        or raw.get("roleArn")
        or raw.get("RoleArn")
    )
    identity = _identity_from_role(role, location, source=source)
    if identity:
        agent.identities.append(identity)
    return agent


def _gateway_target(
    path: Path,
    gateway: str,
    target: dict[str, Any],
) -> tuple[MCPServer | None, Tool | None]:
    name = str(target.get("name") or "gateway-target")
    target_type = str(target.get("targetType") or "").lower()
    outbound = target.get("outboundAuth")
    auth_type = "NONE"
    credential_name = None
    scopes: list[str] = []
    if isinstance(outbound, dict):
        auth_type = str(outbound.get("type") or "NONE").upper()
        credential_name = outbound.get("credentialName")
        if isinstance(outbound.get("scopes"), list):
            scopes = [str(item) for item in outbound["scopes"]]
    metadata = {
        "framework": AGENTCORE_FRAMEWORK,
        "gateway": gateway,
        "target_type": target_type,
        "outbound_auth": auth_type,
        "credential_name": credential_name,
        "oauth_scopes": scopes,
    }
    endpoint = target.get("endpoint")
    if target_type == "mcpserver":
        return (
            MCPServer(
                name=name,
                transport="streamable-http",
                url=endpoint if isinstance(endpoint, str) else None,
                authenticated=auth_type != "NONE",
                identity=str(credential_name) if credential_name else None,
                location=SourceLocation(path),
                metadata=metadata,
            ),
            None,
        )
    capabilities = set(infer_capabilities(name))
    resources: list[ResourceScope] = []
    destinations: list[NetworkDestination] = []
    if target_type in {"lambda", "lambdafunctionarn"}:
        compute = target.get("compute")
        arn = target.get("lambdaFunctionArn")
        if isinstance(compute, dict):
            arn = arn or compute.get("lambdaArn") or compute.get("functionArn")
        if isinstance(arn, str):
            resources.append(
                ResourceScope(
                    kind="lambda",
                    selector=arn,
                    access=capabilities,
                    location=SourceLocation(path),
                )
            )
    if isinstance(endpoint, str):
        capabilities.add("network.external")
        destinations.append(
            NetworkDestination(
                target=endpoint,
                restricted=True,
                location=SourceLocation(path),
                metadata={"source": "agentcore_gateway_target"},
            )
        )
    return (
        None,
        Tool(
            name=name,
            kind="agentcore_gateway_target",
            capabilities=capabilities,
            resources=resources,
            destinations=destinations,
            identity=str(credential_name) if credential_name else None,
            location=SourceLocation(path),
            metadata=metadata,
        ),
    )


def _scan_agentcore_json(path: Path, document: dict[str, Any]) -> Graph:
    graph = Graph()
    for raw in document.get("runtimes", []):
        if isinstance(raw, dict):
            agent = _agentcore_runtime_from_dict(path, raw, source="agentcore.json")
            if agent:
                graph.agents.append(agent)

    for raw in document.get("credentials", []):
        if not isinstance(raw, dict):
            continue
        name = raw.get("name")
        if not isinstance(name, str):
            continue
        credential_type = str(raw.get("authorizerType") or raw.get("type") or raw.get("credentialType") or "credential")
        graph.identities.append(
            Identity(
                name=name,
                provider="aws",
                credential_source=credential_type.lower(),
                location=SourceLocation(path),
                metadata={"framework": AGENTCORE_FRAMEWORK, "source": "agentcore.json"},
            )
        )

    for gateway in document.get("agentCoreGateways", []):
        if not isinstance(gateway, dict):
            continue
        gateway_name = str(gateway.get("name") or "agentcore-gateway")
        gateway_role = gateway.get("roleArn") or gateway.get("roleARN")
        identity = _identity_from_role(gateway_role, SourceLocation(path), source="agentcore.json")
        if identity:
            graph.identities.append(identity)
        for target in gateway.get("targets", []):
            if not isinstance(target, dict):
                continue
            server, tool = _gateway_target(path, gateway_name, target)
            if server:
                graph.unbound_mcp_servers.append(server)
            if tool:
                graph.unbound_tools.append(tool)

    for kb in document.get("knowledgeBases", []):
        if not isinstance(kb, dict):
            continue
        name = str(kb.get("name") or "knowledge-base")
        tool = Tool(
            name=f"retrieve:{name}",
            kind="bedrock_knowledge_base",
            capabilities={"data.read"},
            location=SourceLocation(path),
            metadata={"framework": AGENTCORE_FRAMEWORK, "knowledge_base": name},
        )
        for source in kb.get("dataSources", []):
            if not isinstance(source, dict):
                continue
            uri = source.get("uri")
            if isinstance(uri, str):
                tool.resources.append(
                    ResourceScope(
                        kind=str(source.get("type") or "data").lower(),
                        selector=uri,
                        access={"data.read"},
                        location=SourceLocation(path),
                    )
                )
        graph.unbound_tools.append(tool)

    for browser in document.get("browsers", []):
        if isinstance(browser, dict):
            graph.unbound_tools.append(
                Tool(
                    name=str(browser.get("name") or "agentcore-browser"),
                    kind="agentcore_browser",
                    capabilities={"data.read", "network.external", "external.write"},
                    location=SourceLocation(path),
                    metadata={"framework": AGENTCORE_FRAMEWORK},
                )
            )
    for interpreter in document.get("codeInterpreters", []):
        if isinstance(interpreter, dict):
            graph.unbound_tools.append(
                Tool(
                    name=str(interpreter.get("name") or "agentcore-code-interpreter"),
                    kind="agentcore_code_interpreter",
                    capabilities={"data.read", "data.write", "process.execute"},
                    location=SourceLocation(path),
                    metadata={"framework": AGENTCORE_FRAMEWORK},
                )
            )
    return graph


def _scan_legacy_agentcore_yaml(path: Path, document: dict[str, Any]) -> Graph:
    graph = Graph()
    agents = document.get("agents")
    if not isinstance(agents, dict):
        return graph
    for key, raw in agents.items():
        if not isinstance(raw, dict):
            continue
        name = raw.get("name") or key
        if not isinstance(name, str):
            continue
        location = SourceLocation(path)
        agent = Agent(
            name=name,
            location=location,
            metadata={
                "framework": AGENTCORE_FRAMEWORK,
                "runtime": "bedrock-agentcore",
                "configuration_source": ".bedrock_agentcore.yaml",
                "entrypoint": raw.get("entrypoint"),
                "deployment_type": raw.get("deployment_type"),
            },
        )
        aws = raw.get("aws") if isinstance(raw.get("aws"), dict) else {}
        role = aws.get("execution_role")
        identity = _identity_from_role(role, location, source=".bedrock_agentcore.yaml")
        if identity:
            agent.identities.append(identity)
        network = aws.get("network_configuration")
        if isinstance(network, dict):
            agent.metadata["network_mode"] = network.get("network_mode")
        protocol = aws.get("protocol_configuration")
        if isinstance(protocol, dict):
            agent.metadata["protocol"] = protocol.get("server_protocol")
        memory = raw.get("memory")
        if isinstance(memory, dict) and str(memory.get("mode") or "").upper() != "NO_MEMORY":
            memory_id = str(memory.get("memory_id") or "agentcore-memory")
            agent.tools.append(
                Tool(
                    name=memory_id,
                    kind="agentcore_memory",
                    capabilities={"data.read", "data.write"},
                    resources=[
                        ResourceScope(
                            kind="agentcore_memory",
                            selector=memory_id,
                            access={"data.read", "data.write"},
                            location=location,
                        )
                    ],
                    location=location,
                    metadata={"framework": AGENTCORE_FRAMEWORK, "mode": memory.get("mode")},
                )
            )
        graph.agents.append(agent)
    return graph


def scan_amazon_agentic_config_file(path: Path) -> Graph:
    if path.name not in AMAZON_AGENTIC_CONFIG_FILENAMES:
        return Graph()
    try:
        text = path.read_text(encoding="utf-8")
        if path.name == "agentcore.json":
            raw = json.loads(text)
        else:
            raw = yaml.safe_load(text)
    except (OSError, UnicodeDecodeError, ValueError, yaml.YAMLError):
        return Graph()
    if not isinstance(raw, dict):
        return Graph()
    if path.name == "agentcore.json":
        return _scan_agentcore_json(path, raw)
    return _scan_legacy_agentcore_yaml(path, raw)


def _cfn_value(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        if "Ref" in value and isinstance(value["Ref"], str):
            return f"Ref:{value['Ref']}"
        if "Fn::GetAtt" in value:
            raw = value["Fn::GetAtt"]
            if isinstance(raw, list) and raw:
                return "GetAtt:" + ".".join(str(item) for item in raw)
            if isinstance(raw, str):
                return f"GetAtt:{raw}"
    return None


def _bedrock_action_group(path: Path, raw: dict[str, Any]) -> Tool:
    name = str(
        raw.get("ActionGroupName")
        or raw.get("ParentActionGroupSignature")
        or "action-group"
    )
    capabilities = set(infer_capabilities(name))
    resources: list[ResourceScope] = []
    signature = str(raw.get("ParentActionGroupSignature") or "")
    if signature == "AMAZON.CodeInterpreter":
        capabilities.update({"data.read", "data.write", "process.execute"})
    executor = raw.get("ActionGroupExecutor")
    if isinstance(executor, dict):
        lambda_arn = _cfn_value(executor.get("Lambda"))
        if lambda_arn:
            resources.append(
                ResourceScope(
                    kind="lambda",
                    selector=lambda_arn,
                    access=set(capabilities),
                    location=SourceLocation(path),
                )
            )
    return Tool(
        name=name,
        kind="bedrock_action_group",
        capabilities=capabilities,
        resources=resources,
        location=SourceLocation(path),
        metadata={"framework": BEDROCK_FRAMEWORK, "parent_signature": signature or None},
    )


def scan_amazon_cloudformation_file(path: Path) -> Graph:
    if path.suffix.lower() not in {".yaml", ".yml"} or path.name in AMAZON_AGENTIC_CONFIG_FILENAMES:
        return Graph()
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        return Graph()
    if not isinstance(raw, dict) or not isinstance(raw.get("Resources"), dict):
        return Graph()
    graph = Graph()
    resources = raw["Resources"]
    for logical_id, resource in resources.items():
        if not isinstance(resource, dict):
            continue
        resource_type = resource.get("Type")
        props = resource.get("Properties") if isinstance(resource.get("Properties"), dict) else {}
        location = SourceLocation(path)
        if resource_type == "AWS::Bedrock::Agent":
            name = (
                props.get("AgentName")
                if isinstance(props.get("AgentName"), str)
                else str(logical_id)
            )
            agent = Agent(
                name=name,
                location=location,
                metadata={
                    "framework": BEDROCK_FRAMEWORK,
                    "configuration_source": "cloudformation",
                    "foundation_model": props.get("FoundationModel"),
                    "guardrail_configured": isinstance(props.get("GuardrailConfiguration"), dict),
                },
            )
            role = _cfn_value(props.get("AgentResourceRoleArn"))
            identity = _identity_from_role(role, location, source="cloudformation")
            if identity:
                agent.identities.append(identity)
            action_groups = props.get("ActionGroups")
            if isinstance(action_groups, list):
                agent.tools.extend(
                    _bedrock_action_group(path, item)
                    for item in action_groups
                    if isinstance(item, dict)
                )
            knowledge_bases = props.get("KnowledgeBases")
            if isinstance(knowledge_bases, list):
                for item in knowledge_bases:
                    if not isinstance(item, dict):
                        continue
                    kb_id = _cfn_value(item.get("KnowledgeBaseId")) or str(
                        item.get("KnowledgeBaseId") or "knowledge-base"
                    )
                    agent.data_sources.append(
                        DataSource(
                            name=str(item.get("Description") or kb_id),
                            selector=kb_id,
                            capability="data.read",
                            location=location,
                        )
                    )
            collaborators = props.get("AgentCollaborators")
            if isinstance(collaborators, list):
                for item in collaborators:
                    if not isinstance(item, dict):
                        continue
                    collaborator = str(item.get("CollaboratorName") or "bedrock-collaborator")
                    descriptor = item.get("AgentDescriptor")
                    alias_arn = (
                        _cfn_value(descriptor.get("AliasArn"))
                        if isinstance(descriptor, dict)
                        else None
                    )
                    tool = Tool(
                        name=collaborator,
                        kind="delegated_agent",
                        capabilities={"agent.delegate"},
                        location=location,
                        metadata={
                            "framework": BEDROCK_FRAMEWORK,
                            "delegate_target": collaborator,
                            "delegate_alias_arn": alias_arn,
                            "authority_binding": "delegation_projection",
                            "authority_binding_basis": "bedrock_agent_collaborator",
                        },
                    )
                    if alias_arn:
                        tool.resources.append(
                            ResourceScope(
                                kind="bedrock_agent_alias",
                                selector=alias_arn,
                                access={"agent.delegate"},
                                location=location,
                            )
                        )
                    agent.tools.append(tool)
                    agent.metadata.setdefault("delegates_to", []).append(collaborator)
            graph.agents.append(agent)
        elif resource_type == "AWS::BedrockAgentCore::Runtime":
            normalized = {
                "name": props.get("AgentRuntimeName") or str(logical_id),
                "roleArn": _cfn_value(props.get("RoleArn")),
                "networkMode": (
                    props.get("NetworkConfiguration", {}).get("NetworkMode")
                    if isinstance(props.get("NetworkConfiguration"), dict)
                    else None
                ),
                "protocol": props.get("ProtocolConfiguration"),
            }
            agent = _agentcore_runtime_from_dict(path, normalized, source="cloudformation")
            if agent:
                graph.agents.append(agent)
        elif resource_type == "AWS::BedrockAgentCore::Gateway":
            role = _cfn_value(props.get("RoleArn"))
            identity = _identity_from_role(role, location, source="cloudformation")
            if identity:
                graph.identities.append(identity)
        elif resource_type == "AWS::BedrockAgentCore::GatewayTarget":
            target = props.get("TargetConfiguration")
            metadata = {
                "framework": AGENTCORE_FRAMEWORK,
                "configuration_source": "cloudformation",
                "gateway_identifier": _cfn_value(props.get("GatewayIdentifier")),
            }
            name = str(props.get("Name") or logical_id)
            credential_configs = props.get("CredentialProviderConfigurations")
            credential_type = None
            if isinstance(credential_configs, list) and credential_configs:
                first = credential_configs[0]
                if isinstance(first, dict):
                    credential_type = first.get("CredentialProviderType")
            if isinstance(target, dict) and isinstance(target.get("Mcp"), dict):
                mcp = target["Mcp"]
                server = mcp.get("McpServer") if isinstance(mcp.get("McpServer"), dict) else None
                if server is not None:
                    endpoint = _cfn_value(server.get("Endpoint"))
                    graph.unbound_mcp_servers.append(
                        MCPServer(
                            name=name,
                            transport="streamable-http",
                            url=endpoint,
                            authenticated=bool(credential_type and credential_type != "NONE"),
                            location=location,
                            metadata={**metadata, "credential_provider_type": credential_type},
                        )
                    )
                    continue
                lambda_target = mcp.get("Lambda") if isinstance(mcp.get("Lambda"), dict) else None
                if lambda_target is not None:
                    arn = _cfn_value(lambda_target.get("LambdaArn"))
                    graph.unbound_tools.append(
                        Tool(
                            name=name,
                            kind="agentcore_gateway_lambda",
                            capabilities=set(infer_capabilities(name)),
                            resources=(
                                [
                                    ResourceScope(
                                        kind="lambda",
                                        selector=arn,
                                        access=set(infer_capabilities(name)),
                                        location=location,
                                    )
                                ]
                                if arn
                                else []
                            ),
                            location=location,
                            metadata={**metadata, "credential_provider_type": credential_type},
                        )
                    )
        elif resource_type == "AWS::BedrockAgentCore::BrowserCustom":
            graph.unbound_tools.append(
                Tool(
                    name=str(props.get("Name") or logical_id),
                    kind="agentcore_browser",
                    capabilities={"data.read", "network.external", "external.write"},
                    location=location,
                    metadata={
                        "framework": AGENTCORE_FRAMEWORK,
                        "configuration_source": "cloudformation",
                    },
                )
            )
        elif resource_type == "AWS::BedrockAgentCore::CodeInterpreterCustom":
            graph.unbound_tools.append(
                Tool(
                    name=str(props.get("Name") or logical_id),
                    kind="agentcore_code_interpreter",
                    capabilities={"data.read", "data.write", "process.execute"},
                    location=location,
                    metadata={
                        "framework": AGENTCORE_FRAMEWORK,
                        "configuration_source": "cloudformation",
                    },
                )
            )
    return graph


_TF_RESOURCE_RE = re.compile(r'^\s*resource\s+"([^"]+)"\s+"([^"]+)"\s*\{', re.MULTILINE)
_TF_STRING_ASSIGN_RE = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"([^"]+)"')
_TF_VALUE_ASSIGN_RE = re.compile(
    r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^\n#]+?)\s*$',
    re.MULTILINE,
)


def _tf_blocks(text: str):
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        match = re.match(r'^\s*resource\s+"([^"]+)"\s+"([^"]+)"\s*\{', lines[index])
        if not match:
            index += 1
            continue
        resource_type, name = match.groups()
        start = index
        depth = lines[index].count("{") - lines[index].count("}")
        index += 1
        while index < len(lines) and depth > 0:
            depth += lines[index].count("{") - lines[index].count("}")
            index += 1
        yield resource_type, name, start + 1, "\n".join(lines[start:index])


def _tf_string(block: str, *names: str) -> str | None:
    assignments = dict(_TF_STRING_ASSIGN_RE.findall(block))
    return next((assignments[name] for name in names if name in assignments), None)


def _tf_value(block: str, *names: str) -> str | None:
    assignments = {
        name: value.strip().rstrip(",")
        for name, value in _TF_VALUE_ASSIGN_RE.findall(block)
    }
    for name in names:
        value = assignments.get(name)
        if value is None:
            continue
        if len(value) >= 2 and value[0] == value[-1] == '"':
            return value[1:-1]
        return value
    return None


def scan_amazon_agentic_terraform_file(path: Path) -> Graph:
    if path.suffix.lower() != ".tf":
        return Graph()
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return Graph()
    graph = Graph()
    for resource_type, resource_name, line, block in _tf_blocks(text):
        location = SourceLocation(path, line, 1)
        if resource_type == "aws_bedrockagent_agent":
            name = _tf_string(block, "agent_name") or resource_name
            role = _tf_value(block, "agent_resource_role_arn")
            agent = Agent(
                name=name,
                location=location,
                metadata={
                    "framework": BEDROCK_FRAMEWORK,
                    "configuration_source": "terraform",
                    "foundation_model": _tf_string(block, "foundation_model"),
                    "terraform_resource_ref": f"aws_bedrockagent_agent.{resource_name}",
                },
            )
            identity = _identity_from_role(role, location, source="terraform")
            if identity:
                agent.identities.append(identity)
            graph.agents.append(agent)
        elif resource_type in {
            "aws_bedrockagent_agent_action_group",
            "aws_bedrockagent_action_group",
        }:
            name = _tf_string(block, "action_group_name") or resource_name
            lambda_arn = _tf_value(block, "lambda", "lambda_arn")
            agent_reference = _tf_value(block, "agent_id")
            capabilities = set(infer_capabilities(name))
            tool = Tool(
                name=name,
                kind="bedrock_action_group",
                capabilities=capabilities,
                location=location,
                metadata={
                    "framework": BEDROCK_FRAMEWORK,
                    "configuration_source": "terraform",
                    "agent_reference": agent_reference,
                },
            )
            if lambda_arn:
                tool.resources.append(
                    ResourceScope(
                        kind="lambda",
                        selector=lambda_arn,
                        access=capabilities,
                        location=location,
                    )
                )
            graph.unbound_tools.append(tool)
        elif resource_type in {
            "aws_bedrockagentcore_agent_runtime",
            "aws_bedrockagentcore_runtime",
        }:
            normalized = {
                "name": _tf_string(block, "agent_runtime_name", "name") or resource_name,
                "roleArn": _tf_value(block, "role_arn", "execution_role_arn"),
                "networkMode": _tf_string(block, "network_mode"),
                "protocol": _tf_string(
                    block, "server_protocol", "protocol_configuration", "protocol"
                ),
            }
            agent = _agentcore_runtime_from_dict(path, normalized, source="terraform")
            if agent:
                agent.location = location
                agent.metadata["terraform_resource_ref"] = (
                    f"{resource_type}.{resource_name}"
                )
                graph.agents.append(agent)
        elif resource_type in {"aws_bedrockagentcore_gateway", "aws_bedrock_agentcore_gateway"}:
            role = _tf_value(block, "role_arn")
            identity = _identity_from_role(role, location, source="terraform")
            if identity:
                graph.identities.append(identity)
        elif resource_type in {
            "aws_bedrockagentcore_gateway_target",
            "aws_bedrock_agentcore_gateway_target",
        }:
            name = _tf_string(block, "name") or resource_name
            endpoint = _tf_string(block, "endpoint", "url")
            lambda_arn = _tf_value(block, "lambda_arn")
            credential_type = _tf_string(block, "credential_provider_type")
            if credential_type is None:
                for marker, value in (
                    ("caller_iam_credentials", "CALLER_IAM_CREDENTIALS"),
                    ("gateway_iam_role", "GATEWAY_IAM_ROLE"),
                    ("jwt_passthrough", "JWT_PASSTHROUGH"),
                    ("api_key", "API_KEY"),
                    ("oauth", "OAUTH"),
                ):
                    if re.search(rf"\b{marker}\s*\{{", block):
                        credential_type = value
                        break
            metadata = {
                "framework": AGENTCORE_FRAMEWORK,
                "configuration_source": "terraform",
                "credential_provider_type": credential_type,
                "gateway_identifier": _tf_value(block, "gateway_identifier"),
            }
            if endpoint:
                graph.unbound_mcp_servers.append(
                    MCPServer(
                        name=name,
                        transport="streamable-http",
                        url=endpoint,
                        authenticated=bool(credential_type),
                        location=location,
                        metadata=metadata,
                    )
                )
            elif lambda_arn:
                capabilities = set(infer_capabilities(name))
                graph.unbound_tools.append(
                    Tool(
                        name=name,
                        kind="agentcore_gateway_lambda",
                        capabilities=capabilities,
                        resources=[
                            ResourceScope(
                                kind="lambda",
                                selector=lambda_arn,
                                access=capabilities,
                                location=location,
                            )
                        ],
                        location=location,
                        metadata=metadata,
                    )
                )
    return graph
