from __future__ import annotations

import ast
from copy import deepcopy
from pathlib import Path
from typing import Any

from horustrace.models import (
    Agent,
    Graph,
    MCPServer,
    NetworkDestination,
    SourceLocation,
    Tool,
)

FRAMEWORK = "claude-managed-agents"

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


def _location(path: Path, node: ast.AST) -> SourceLocation:
    return SourceLocation(
        path,
        getattr(node, "lineno", 1) or 1,
        (getattr(node, "col_offset", 0) or 0) + 1,
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


def _literal(node: ast.AST | None) -> Any:
    if node is None:
        return None
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError):
        return None


def _kw(call: ast.Call, name: str) -> ast.AST | None:
    return next((item.value for item in call.keywords if item.arg == name), None)


def _dict_nodes(node: ast.AST | None) -> dict[str, ast.AST]:
    if not isinstance(node, ast.Dict):
        return {}
    result: dict[str, ast.AST] = {}
    for key, value in zip(node.keys, node.values):
        literal = _literal(key)
        if isinstance(literal, str):
            result[literal] = value
    return result


def _expr_text(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    try:
        return ast.unparse(node)
    except (AttributeError, ValueError):
        return _dotted(node)


def _expression_root_name(node: ast.AST | None) -> str | None:
    current = node
    while isinstance(current, ast.Call) and isinstance(current.func, ast.Attribute):
        current = current.func.value
    while isinstance(current, ast.Attribute):
        current = current.value
    if isinstance(current, ast.Name):
        return current.id
    if node is not None:
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                return child.id
    return None


def _assigned_call(node: ast.Assign | ast.AnnAssign) -> ast.Call | None:
    value: ast.AST = node.value
    while isinstance(value, ast.Await):
        value = value.value
    return value if isinstance(value, ast.Call) else None


def _assignment_names(node: ast.Assign | ast.AnnAssign) -> list[str]:
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    return [target.id for target in targets if isinstance(target, ast.Name)]


def _permission_policy(config: Any, *, default: str) -> str:
    if not isinstance(config, dict):
        return default
    raw = config.get("permission_policy")
    if isinstance(raw, dict):
        value = raw.get("type")
        if isinstance(value, str):
            return value
    return default


def _apply_policy(tool: Tool | MCPServer, policy: str) -> None:
    tool.metadata["permission_policy"] = policy
    if policy == "always_ask":
        tool.approval = True
        tool.metadata["approval_basis"] = "managed_permission_policy"
    elif policy == "always_allow":
        tool.approval = False
        tool.metadata["approval_basis"] = "managed_permission_policy"
    elif policy == "auto":
        tool.approval = None
        tool.metadata["approval_basis"] = "managed_auto_policy"
        tool.metadata["automatic_safety_review"] = True


def _managed_builtin(
    path: Path,
    node: ast.AST,
    name: str,
    config: dict[str, Any] | None,
    default_policy: str,
) -> Tool:
    kind, capabilities = _MANAGED_BUILTINS.get(name, ("managed_builtin", set()))
    tool = Tool(
        name=name,
        kind=kind,
        capabilities=set(capabilities),
        location=_location(path, node),
        metadata={
            "framework": FRAMEWORK,
            "managed_tool": True,
            "execution_boundary": (
                "managed-sandbox"
                if name in {"read", "glob", "grep", "write", "edit", "bash"}
                else "server-managed"
            ),
        },
    )
    policy = _permission_policy(config, default=default_policy)
    _apply_policy(tool, policy)

    if isinstance(config, dict):
        allowed_domains = config.get("allowed_domains")
        blocked_domains = config.get("blocked_domains")
        if isinstance(allowed_domains, list):
            tool.metadata["allowed_domains"] = [
                str(item) for item in allowed_domains if isinstance(item, str)
            ]
            for domain in tool.metadata["allowed_domains"]:
                target = domain if "://" in domain else f"https://{domain}"
                tool.destinations.append(
                    NetworkDestination(
                        target=target,
                        restricted=True,
                        location=tool.location,
                        metadata={
                            "source": "managed_tool_allowed_domains",
                            "network_scope": "fixed_domain_allowlist",
                        },
                    )
                )
        if isinstance(blocked_domains, list):
            tool.metadata["blocked_domains"] = [
                str(item) for item in blocked_domains if isinstance(item, str)
            ]

    if name == "web_fetch" and not tool.destinations:
        tool.destinations.append(
            NetworkDestination(
                target="<model-selected-url>",
                restricted=False,
                location=tool.location,
                metadata={
                    "source": "managed_web_fetch",
                    "network_scope": "dynamic_destination",
                },
            )
        )
    elif name == "web_search":
        tool.destinations.append(
            NetworkDestination(
                target="<web-search>",
                restricted=False,
                location=tool.location,
                metadata={
                    "source": "managed_web_search",
                    "network_scope": "dynamic_search_results",
                },
            )
        )
    return tool


def _mcp_servers(path: Path, call: ast.Call) -> dict[str, MCPServer]:
    node = _kw(call, "mcp_servers")
    raw = _literal(node)
    entries: list[tuple[dict[str, Any] | None, dict[str, ast.AST] | None]] = []
    if isinstance(raw, list):
        entries.extend(
            (item, None)
            for item in raw
            if isinstance(item, dict)
        )
    elif isinstance(node, (ast.List, ast.Tuple)):
        entries.extend(
            (None, _dict_nodes(item))
            for item in node.elts
            if isinstance(item, ast.Dict)
        )
    else:
        return {}

    result: dict[str, MCPServer] = {}
    for literal_item, ast_item in entries:
        if literal_item is not None:
            name = literal_item.get("name")
            url = literal_item.get("url")
            type_value = literal_item.get("type")
            url_expression = None
        else:
            assert ast_item is not None
            name = _literal(ast_item.get("name"))
            url = _literal(ast_item.get("url"))
            type_value = _literal(ast_item.get("type"))
            url_expression = _expr_text(ast_item.get("url"))

        if not isinstance(name, str) or not name:
            continue
        transport = "http" if type_value == "url" else str(type_value or "unknown")
        dynamic_url = not isinstance(url, str)
        metadata: dict[str, Any] = {
            "framework": FRAMEWORK,
            "managed_mcp": True,
            "configuration_source": "agents.create.mcp_servers",
            "dynamic_mcp_endpoint": dynamic_url,
        }
        if dynamic_url and url_expression:
            metadata["mcp_url_expression"] = url_expression
            root_name = _expression_root_name(
                ast_item.get("url") if ast_item is not None else None
            )
            if root_name:
                metadata["mcp_url_source"] = root_name
        result[name] = MCPServer(
            name=name,
            transport=transport,
            url=url if isinstance(url, str) else None,
            authenticated=None,
            location=_location(path, call),
            metadata=metadata,
        )
    return result


def _toolsets(
    path: Path,
    call: ast.Call,
    servers: dict[str, MCPServer],
) -> list[Tool]:
    raw = _literal(_kw(call, "tools"))
    if not isinstance(raw, list):
        return []
    tools: list[Tool] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        toolset_type = str(item.get("type") or "")
        if toolset_type.startswith("agent_toolset"):
            default_policy = _permission_policy(
                item.get("default_config"),
                default="always_allow",
            )
            configs = item.get("configs")
            by_name: dict[str, dict[str, Any]] = {}
            if isinstance(configs, list):
                for config in configs:
                    if isinstance(config, dict) and isinstance(config.get("name"), str):
                        by_name[str(config["name"])] = config
            # A managed agent toolset enables the built-in surface. Per-tool
            # configs constrain or override that surface rather than defining it.
            for name in _MANAGED_BUILTINS:
                tools.append(
                    _managed_builtin(
                        path,
                        call,
                        name,
                        by_name.get(name),
                        default_policy,
                    )
                )
            continue

        if toolset_type == "mcp_toolset":
            server_name = item.get("mcp_server_name")
            if not isinstance(server_name, str):
                continue
            server = servers.get(server_name)
            if server is None:
                server = MCPServer(
                    name=server_name,
                    transport="managed",
                    authenticated=None,
                    location=_location(path, call),
                    metadata={
                        "framework": FRAMEWORK,
                        "managed_mcp": True,
                        "reference_only": True,
                        "tool_catalogue_unresolved": True,
                    },
                )
                servers[server_name] = server
            default_policy = _permission_policy(
                item.get("default_config"),
                default="always_ask",
            )
            _apply_policy(server, default_policy)
            configs = item.get("configs")
            if isinstance(configs, list):
                server.metadata["per_tool_permission_policies"] = [
                    {
                        "name": config.get("name"),
                        "permission_policy": _permission_policy(
                            config,
                            default=default_policy,
                        ),
                    }
                    for config in configs
                    if isinstance(config, dict)
                ]
    return tools


def _dynamic_tool_catalogue(
    path: Path,
    call: ast.Call,
) -> Tool | None:
    """Represent a source-proven Managed Agent tool catalogue we cannot enumerate."""
    tools_node = _kw(call, "tools")
    if tools_node is None:
        return None
    if isinstance(_literal(tools_node), list):
        return None

    expression = _expr_text(tools_node)
    return Tool(
        name="<dynamic-managed-tool-catalogue>",
        kind="dynamic_tool_collection",
        capabilities=set(),
        location=_location(path, tools_node),
        metadata={
            "framework": FRAMEWORK,
            "managed_tool_catalogue": True,
            "dynamic_bound_collection": True,
            "dynamic_authority": True,
            "tool_catalogue_unresolved": True,
            "authority_binding": "managed_agent_tools",
            "authority_binding_basis": "managed_agent_tools_expression",
            "binding_expression": expression,
            "execution_boundary": "server-managed",
        },
    )


def _multiagent_tools(
    path: Path,
    call: ast.Call,
    agent: Agent,
) -> list[Tool]:
    raw = _literal(_kw(call, "multiagent"))
    if not isinstance(raw, dict):
        return []
    agent.metadata["multiagent_type"] = raw.get("type")
    roster = raw.get("agents")
    if not isinstance(roster, list):
        agent.metadata["dynamic_multiagent_roster"] = True
        return [
            Tool(
                name="<dynamic-managed-agents>",
                kind="delegated_agent",
                capabilities={"agent.delegate"},
                location=_location(path, call),
                metadata={
                    "framework": FRAMEWORK,
                    "delegate_target_unresolved": True,
                    "conditional": True,
                    "authority_binding": "managed_multiagent",
                },
            )
        ]

    result: list[Tool] = []
    delegates: list[str] = []
    for item in roster:
        if not isinstance(item, dict):
            continue
        item_type = str(item.get("type") or "")
        target: str | None = None
        if item_type == "agent" and isinstance(item.get("id"), str):
            target = str(item["id"])
        elif item_type == "advisor" and isinstance(item.get("model"), str):
            target = str(item["model"])
        if not target:
            continue
        delegates.append(target)
        result.append(
            Tool(
                name=target,
                kind="delegated_agent",
                capabilities={"agent.delegate"},
                location=_location(path, call),
                metadata={
                    "framework": FRAMEWORK,
                    "delegate_target": target,
                    "delegate_type": item_type,
                    "delegate_version": item.get("version"),
                    "authority_binding": "delegation_projection",
                    "authority_binding_basis": "managed_multiagent_roster",
                    "execution_boundary": "server-managed",
                },
            )
        )
    if delegates:
        agent.metadata["delegates_to"] = delegates
    return result


def _skills(call: ast.Call) -> tuple[list[str], list[dict[str, Any]]]:
    raw = _literal(_kw(call, "skills"))
    if not isinstance(raw, list):
        return [], []
    ids: list[str] = []
    refs: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        skill_id = item.get("skill_id")
        if isinstance(skill_id, str):
            ids.append(skill_id)
            refs.append(
                {
                    "skill_id": skill_id,
                    "type": item.get("type"),
                    "version": item.get("version"),
                }
            )
    return ids, refs


def _agent_from_call(
    path: Path,
    binding: str,
    call: ast.Call,
) -> tuple[Agent, dict[str, MCPServer]]:
    explicit_name = _literal(_kw(call, "name"))
    name = explicit_name if isinstance(explicit_name, str) else binding
    agent = Agent(
        name=name,
        location=_location(path, call),
        metadata={
            "framework": FRAMEWORK,
            "managed_runtime": True,
            "execution_boundary": "server-managed",
            "source_alias": binding,
        },
    )
    model = _literal(_kw(call, "model"))
    if isinstance(model, str):
        agent.metadata["model"] = model
    elif isinstance(model, dict):
        agent.metadata["model"] = model.get("id")
        if model.get("effort") is not None:
            agent.metadata["model_effort"] = model.get("effort")

    server_lookup = _mcp_servers(path, call)
    agent.tools.extend(_toolsets(path, call, server_lookup))
    dynamic_catalogue = _dynamic_tool_catalogue(path, call)
    if dynamic_catalogue is not None:
        agent.tools.append(dynamic_catalogue)
        agent.metadata["dynamic_tool_catalogue"] = True
        agent.metadata["dynamic_tool_catalogue_expression"] = (
            dynamic_catalogue.metadata.get("binding_expression")
        )
    agent.mcp_servers.extend(deepcopy(server) for server in server_lookup.values())
    agent.tools.extend(_multiagent_tools(path, call, agent))

    skill_ids, skill_refs = _skills(call)
    if skill_ids:
        agent.metadata["skills"] = skill_ids
        agent.metadata["skill_references"] = skill_refs

    return agent, server_lookup


def _environment_from_call(call: ast.Call) -> dict[str, Any]:
    config_node = _kw(call, "config")
    raw = _literal(config_node)
    if isinstance(raw, dict):
        result: dict[str, Any] = {}
        env_type = raw.get("type")
        if isinstance(env_type, str):
            result["environment_type"] = env_type
        networking = raw.get("networking")
        if isinstance(networking, dict):
            if isinstance(networking.get("type"), str):
                result["networking_type"] = networking["type"]
            allowed = networking.get("allowed_hosts")
            if isinstance(allowed, list):
                result["allowed_hosts"] = [
                    str(item) for item in allowed if isinstance(item, str)
                ]
            for key in ("allow_mcp_servers", "allow_package_managers"):
                if isinstance(networking.get(key), bool):
                    result[key] = networking[key]
        return result

    config = _dict_nodes(config_node)
    if not config:
        return {"environment_config_dynamic": True}

    result = {"environment_config_partially_resolved": True}
    env_type = _literal(config.get("type"))
    if isinstance(env_type, str):
        result["environment_type"] = env_type

    networking = _dict_nodes(config.get("networking"))
    if networking:
        network_type = _literal(networking.get("type"))
        if isinstance(network_type, str):
            result["networking_type"] = network_type

        allowed_node = networking.get("allowed_hosts")
        if isinstance(allowed_node, (ast.List, ast.Tuple)):
            allowed_hosts: list[str] = []
            allowed_sources: list[str] = []
            for item in allowed_node.elts:
                literal = _literal(item)
                if isinstance(literal, str):
                    allowed_hosts.append(literal)
                    continue
                root = _expression_root_name(item)
                if root:
                    allowed_hosts.append(f"<configured-host:{root}>")
                    allowed_sources.append(root)
                else:
                    expression = _expr_text(item)
                    if expression:
                        allowed_hosts.append(f"<dynamic-host:{expression}>")
            result["allowed_hosts"] = allowed_hosts
            if allowed_sources:
                result["allowed_hosts_dynamic"] = True
                result["allowed_host_sources"] = sorted(set(allowed_sources))

        for key in ("allow_mcp_servers", "allow_package_managers"):
            value = _literal(networking.get(key))
            if isinstance(value, bool):
                result[key] = value
    return result


def _ref_base(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return node.value.id
    return None


def is_anthropic_managed_agents_file(path: Path) -> bool:
    if path.suffix.lower() != ".py":
        return False
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False
    return ".beta.agents.create(" in source and (
        "from anthropic import " in source or "import anthropic" in source
    )


def scan_anthropic_managed_agents_file(path: Path) -> Graph:
    graph = Graph()
    if not is_anthropic_managed_agents_file(path):
        return graph
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return graph

    agents_by_alias: dict[str, Agent] = {}
    environments: dict[str, dict[str, Any]] = {}

    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        call = _assigned_call(node)
        if call is None:
            continue
        dotted = _dotted(call.func) or ""
        names = _assignment_names(node)
        for name in names:
            if dotted.endswith(".beta.agents.create"):
                agent, _ = _agent_from_call(path, name, call)
                agents_by_alias[name] = agent
            elif dotted.endswith(".beta.environments.create"):
                environments[name] = _environment_from_call(call)

    # Sessions bind persisted agents to an execution environment and vault
    # configuration. Correlate source aliases without assuming runtime IDs.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        dotted = _dotted(node.func) or ""
        if not dotted.endswith(".beta.sessions.create"):
            continue
        agent_alias = _ref_base(_kw(node, "agent"))
        env_alias = _ref_base(_kw(node, "environment_id"))
        agent = agents_by_alias.get(agent_alias or "")
        if agent is None:
            continue
        if env_alias and env_alias in environments:
            agent.metadata.update(environments[env_alias])
            agent.metadata["environment_reference"] = env_alias
        vault_ids = _literal(_kw(node, "vault_ids"))
        if isinstance(vault_ids, list):
            agent.metadata["vault_ids"] = [
                str(item) for item in vault_ids if isinstance(item, str)
            ]
            for server in agent.mcp_servers:
                server.metadata["vault_ids_available"] = list(agent.metadata["vault_ids"])
                server.metadata["session_scoped_auth"] = True

    graph.agents.extend(agents_by_alias.values())
    return graph
