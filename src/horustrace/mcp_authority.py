"""Evidence-backed MCP client-to-agent authority reconstruction."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from horustrace.models import Graph, Identity, MCPServer, ResourceScope

_AGENT_FACTORIES = {
    "Agent",
    "LlmAgent",
    "ChatAgent",
}
_MCP_CLIENT_FACTORIES = {"MultiServerMCPClient", "MCPClient"}


@dataclass(slots=True)
class _Client:
    alias: str
    path: Path
    server_names: set[str] = field(default_factory=set)


def _name(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


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


def _kw(call: ast.Call, name: str) -> ast.AST | None:
    return next((item.value for item in call.keywords if item.arg == name), None)


def _literal_string(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _dict_keys(node: ast.AST | None) -> set[str]:
    if not isinstance(node, ast.Dict):
        return set()
    result: set[str] = set()
    for key in node.keys:
        value = _literal_string(key)
        if value:
            result.add(value)
    return result


def _target_aliases(node: ast.Assign | ast.AnnAssign) -> list[str]:
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    return [target.id for target in targets if isinstance(target, ast.Name)]


def _unwrap_await(node: ast.AST | None) -> ast.AST | None:
    return node.value if isinstance(node, ast.Await) else node


def _get_tools_client(node: ast.AST | None) -> str | None:
    node = _unwrap_await(node)
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
        return None
    if node.func.attr != "get_tools":
        return None
    return _dotted(node.func.value) or _name(node.func.value)


def _agent_runtime_name(call: ast.Call, alias: str) -> str:
    return _literal_string(_kw(call, "name")) or alias


def _tools_expr(call: ast.Call) -> ast.AST | None:
    value = _kw(call, "tools")
    if value is not None:
        return value
    return None


def _client_server_names(call: ast.Call) -> set[str]:
    config = call.args[0] if call.args else _kw(call, "connections")
    return _dict_keys(config)


def _parse_relationships(
    path: Path,
) -> tuple[dict[str, _Client], dict[str, str], list[tuple[str, str]]]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return {}, {}, []

    clients: dict[str, _Client] = {}
    tools_alias_to_client: dict[str, str] = {}
    agent_to_client: list[tuple[str, str]] = []
    agent_factories = set(_AGENT_FACTORIES)

    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        aliases = _target_aliases(node)
        value = _unwrap_await(node.value)
        if not isinstance(value, ast.Call):
            continue

        call_name = _name(value.func) or ""
        dotted = _dotted(value.func) or ""
        if (
            call_name in _MCP_CLIENT_FACTORIES
            or dotted.endswith("MCPClient.from_dict")
        ):
            for alias in aliases:
                clients[alias] = _Client(
                    alias,
                    path,
                    _client_server_names(value),
                )

        client_alias = _get_tools_client(value)
        if client_alias:
            for alias in aliases:
                tools_alias_to_client[alias] = client_alias

    for node in ast.walk(tree):
        if not isinstance(node, (ast.With, ast.AsyncWith)):
            continue
        for item in node.items:
            expr = item.context_expr
            if not isinstance(expr, ast.Call):
                continue
            call_name = _name(expr.func) or ""
            alias = _name(item.optional_vars)
            if call_name in _MCP_CLIENT_FACTORIES and alias:
                clients[alias] = _Client(
                    alias,
                    path,
                    _client_server_names(expr),
                )

    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        aliases = _target_aliases(node)
        value = _unwrap_await(node.value)
        if not isinstance(value, ast.Call):
            continue
        if (_name(value.func) or "") not in agent_factories:
            continue

        tool_expr = _tools_expr(value)
        client_alias = _get_tools_client(tool_expr)
        if client_alias is None and isinstance(tool_expr, ast.Name):
            client_alias = tools_alias_to_client.get(tool_expr.id)
        if client_alias:
            for alias in aliases:
                relation = (_agent_runtime_name(value, alias), client_alias)
                if relation not in agent_to_client:
                    agent_to_client.append(relation)

    return clients, tools_alias_to_client, agent_to_client


def _auth_mechanism(server: MCPServer) -> str:
    keys = {str(key).lower() for key in server.metadata.get("auth_keys", [])}
    keys.update(str(key).lower() for key in server.metadata.get("auth_headers", []))
    if "oauth" in keys:
        return "oauth"
    if "x-api-key" in keys or "x-goog-api-key" in keys:
        return "api-key-header"
    if "authorization" in keys or "proxy-authorization" in keys:
        return "authorization-header"
    if "token" in keys:
        return "token"
    if server.authenticated is True:
        return "configured-auth"
    if server.authenticated is False:
        return "none"
    return "unknown"


def _filesystem_resources(server: MCPServer) -> list[ResourceScope]:
    text = " ".join([server.name, server.command or "", *server.args]).lower()
    if "filesystem" not in text:
        return []

    resources: list[ResourceScope] = []
    for arg in server.args:
        if not arg or arg.startswith("-"):
            continue
        lower = arg.lower()
        if "server-filesystem" in lower or lower.startswith(
            "@modelcontextprotocol/"
        ):
            continue
        if not (
            arg.startswith(("/", "~", ".", ".."))
            or "/" in arg
            or "\\" in arg
        ):
            continue
        resources.append(
            ResourceScope(
                kind="filesystem",
                selector=arg,
                access={"data.read", "data.write"},
                location=server.location,
                metadata={"source": "mcp_stdio_argument"},
            )
        )
    return resources


def _ensure_configured_identity(agent, server: MCPServer) -> None:
    mechanism = _auth_mechanism(server)
    server.metadata["auth_mechanism"] = mechanism
    if server.authenticated is not True or server.identity:
        return

    credential_source = server.metadata.get("credential_source")
    if isinstance(credential_source, str) and credential_source:
        # reconstruct_mcp_context() will create the richer credential-source
        # identity using the repository-wide MCP identity convention.
        return

    identity_name = f"{agent.name}:{server.name}:mcp-config-auth"
    server.identity = identity_name
    if any(identity.name == identity_name for identity in agent.identities):
        return
    agent.identities.append(
        Identity(
            name=identity_name,
            provider="mcp",
            location=server.location,
            metadata={
                "source": "mcp_auth_configuration",
                "auth_mechanism": mechanism,
                "runtime_verified": False,
            },
        )
    )


def _attach_filesystem_resources(server: MCPServer) -> None:
    for resource in _filesystem_resources(server):
        if all(
            (existing.kind, existing.selector)
            != (resource.kind, resource.selector)
            for existing in server.resources
        ):
            server.resources.append(resource)


def reconstruct_mcp_authority(
    graph: Graph,
    python_paths: list[Path],
) -> None:
    """Bind static MCP client.get_tools() relationships to normalized agents."""
    agents_by_path_name: dict[tuple[Path, str], list] = {}
    for agent in graph.agents:
        if agent.location is None:
            continue
        agents_by_path_name.setdefault(
            (agent.location.path.resolve(), agent.name),
            [],
        ).append(agent)

    for path in sorted(set(python_paths)):
        clients, _, relations = _parse_relationships(path)
        if not clients or not relations:
            continue

        resolved_path = path.resolve()
        file_servers = [
            server
            for server in list(graph.unbound_mcp_servers)
            if server.location is not None
            and server.location.path.resolve() == resolved_path
        ]

        for agent_name, client_alias in relations:
            client = clients.get(client_alias)
            if client is None:
                continue
            candidates = agents_by_path_name.get(
                (resolved_path, agent_name),
                [],
            )
            if len(candidates) != 1:
                continue

            agent = candidates[0]
            selected = [
                server
                for server in file_servers
                if not client.server_names
                or server.name in client.server_names
            ]
            for server in selected:
                if all(existing is not server for existing in agent.mcp_servers):
                    agent.mcp_servers.append(server)
                if server in graph.unbound_mcp_servers:
                    graph.unbound_mcp_servers.remove(server)

                server.metadata["binding_origin"] = "mcp_client_get_tools"
                server.metadata["client_alias"] = client_alias
                server.metadata["effective_agent"] = agent.name
                _ensure_configured_identity(agent, server)
                _attach_filesystem_resources(server)

    for agent in graph.agents:
        for server in agent.mcp_servers:
            server.metadata.setdefault("effective_agent", agent.name)
            server.metadata.setdefault(
                "auth_mechanism",
                _auth_mechanism(server),
            )
            _ensure_configured_identity(agent, server)
            _attach_filesystem_resources(server)
