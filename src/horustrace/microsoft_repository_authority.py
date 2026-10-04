from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from horustrace.limits import validate_json_safety
from horustrace.models import Agent, Graph, Identity, MCPServer, SourceLocation

_AGENT365_FRAMEWORK = "microsoft-agent365"
_M365_FRAMEWORK = "microsoft-365-agents-sdk-dotnet"
_RUNTIME_AGENT_FRAMEWORKS = {
    "microsoft-agent-framework",
    "microsoft-agent-framework-dotnet",
    _M365_FRAMEWORK,
}
_TOOLING_MANIFEST = "ToolingManifest.json"


def _load_json(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    validate_json_safety(text)
    value = json.loads(text)
    return value if isinstance(value, dict) else {}


def _strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [
        item.strip()
        for item in value
        if isinstance(item, str) and item.strip()
    ]


def _within(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except (OSError, ValueError):
        return False


def _display(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return path.as_posix()


def _binding_evidence(
    manifest_path: Path,
    source_paths: list[Path],
    root: Path,
) -> list[str]:
    evidence: list[str] = []
    for path in source_paths:
        if path.suffix.lower() not in {".py", ".cs", ".js", ".ts"}:
            continue
        if not _within(path, manifest_path.parent):
            continue
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue

        marker: str | None = None
        if (
            "microsoft_agents_a365.tooling" in source
            and (
                "add_tool_servers_to_agent(" in source
                or "get_mcp_tools_async(" in source
            )
        ):
            marker = "agent365_python_tooling_registration"
        elif (
            "Microsoft.Agents.A365.Tooling" in source
            and (
                "AddToolServersToAgentAsync(" in source
                or "GetMcpToolsAsync(" in source
            )
        ):
            marker = "agent365_dotnet_tooling_registration"
        elif (
            "@microsoft/agents-a365-tooling" in source
            and "addToolServersToAgent(" in source
        ):
            marker = "agent365_node_tooling_registration"
        elif (
            _TOOLING_MANIFEST in source
            and (
                "HttpClientTransport" in source
                or "McpClient.CreateAsync" in source
                or "McpClient.create" in source
            )
        ):
            marker = "agent365_direct_manifest_mcp_binding"

        if marker is not None:
            evidence.append(f"{_display(path, root)}:{marker}")
    return sorted(set(evidence))


def _tooling_servers(path: Path) -> list[MCPServer]:
    raw = _load_json(path)
    servers = raw.get("mcpServers")
    if not isinstance(servers, list):
        return []

    result: list[MCPServer] = []
    for item in servers:
        if not isinstance(item, dict):
            continue
        name = str(
            item.get("mcpServerName")
            or item.get("mcpServerUniqueName")
            or "agent365-mcp"
        ).strip()
        url = str(item.get("url") or "").strip() or None
        scope = str(item.get("scope") or "").strip()
        audience = str(item.get("audience") or "").strip()
        result.append(
            MCPServer(
                name=name,
                transport="streamable-http" if url else "provider",
                url=url,
                authenticated=True if (scope or audience) else None,
                location=SourceLocation(path),
                metadata={
                    "framework": _AGENT365_FRAMEWORK,
                    "provider": "microsoft-agent365",
                    "source": "agent365_tooling_manifest",
                    "scope": scope or None,
                    "audience": audience or None,
                    "publisher": item.get("publisher"),
                    "server_id": item.get("id"),
                    "capabilities": _strings(item.get("capabilities")),
                    "permission_model": "delegated",
                    "requires_user_context": True,
                    "requires_admin_consent": True,
                    "permission_grant_state": "not_source_proven",
                    "consent_granted": None,
                },
            )
        )
    return result


def _project_overlay_agents(
    graph: Graph,
    manifest_path: Path,
) -> list[Agent]:
    return [
        agent
        for agent in graph.agents
        if (
            agent.metadata.get("framework") == _AGENT365_FRAMEWORK
            and agent.location is not None
            and agent.location.path.parent.resolve()
            == manifest_path.parent.resolve()
        )
    ]


def _project_runtime_agents(
    graph: Graph,
    manifest_path: Path,
) -> list[Agent]:
    return [
        agent
        for agent in graph.agents
        if (
            agent.metadata.get("framework") in _RUNTIME_AGENT_FRAMEWORKS
            and agent.location is not None
            and _within(agent.location.path, manifest_path.parent)
        )
    ]


def _identity_for_tooling(agent: Agent, server: MCPServer) -> Identity:
    identity = next(
        (
            item
            for item in agent.identities
            if item.provider == "microsoft-entra-agent365"
        ),
        None,
    )
    if identity is None:
        identity = next(
            (
                item
                for item in agent.identities
                if item.name == "agent365-delegated-user"
            ),
            None,
        )
    if identity is None:
        identity = Identity(
            name="agent365-delegated-user",
            provider="microsoft-entra",
            credential_source="agent365-tooling-runtime",
            location=server.location,
            metadata={
                "framework": _AGENT365_FRAMEWORK,
                "identity_type": "delegated_user",
                "permission_model": "delegated",
                "token_subject": "signed_in_or_agentic_user",
                "runtime_resolved": True,
                "credential_value_retained": False,
            },
        )
        agent.identities.append(identity)

    scope = str(server.metadata.get("scope") or "").strip()
    if scope:
        identity.oauth_scopes.add(f"{server.name}:{scope}")
        declared = identity.metadata.setdefault(
            "declared_tooling_scopes",
            [],
        )
        entry = {
            "server": server.name,
            "scope": scope,
            "audience": server.metadata.get("audience"),
            "consent_granted": None,
        }
        if entry not in declared:
            declared.append(entry)
    return identity


def _attach_server(agent: Agent, server: MCPServer) -> None:
    identity = _identity_for_tooling(agent, server)
    server.identity = identity.name
    mode = str(agent.metadata.get("execution_mode") or "").lower()
    server.metadata["token_subject"] = (
        "agentic_user"
        if agent.metadata.get("ai_teammate") is True
        else "signed_in_user"
        if mode in {"obo", "both"}
        else identity.metadata.get("token_subject")
    )
    existing = next(
        (item for item in agent.mcp_servers if item.name == server.name),
        None,
    )
    if existing is None:
        agent.mcp_servers.append(server)
        return

    existing.url = server.url or existing.url
    existing.authenticated = (
        server.authenticated
        if server.authenticated is not None
        else existing.authenticated
    )
    existing.identity = server.identity or existing.identity
    existing.metadata.update(server.metadata)


def _append_unbound(graph: Graph, server: MCPServer) -> None:
    key = (
        server.name,
        server.url,
        str(server.location.path) if server.location else "",
    )
    for current in graph.unbound_mcp_servers:
        current_key = (
            current.name,
            current.url,
            str(current.location.path) if current.location else "",
        )
        if current_key == key:
            current.metadata.update(server.metadata)
            return
    graph.unbound_mcp_servers.append(server)


def _enrich_agent365_tooling(
    graph: Graph,
    root: Path,
    candidate_paths: list[Path],
) -> None:
    manifests = [
        path
        for path in candidate_paths
        if path.name == _TOOLING_MANIFEST
    ]
    source_paths = [
        path
        for path in candidate_paths
        if path.suffix.lower() in {".py", ".cs", ".js", ".ts"}
    ]

    for manifest in manifests:
        evidence = _binding_evidence(manifest, source_paths, root)
        overlays = _project_overlay_agents(graph, manifest)
        runtime_agents = _project_runtime_agents(graph, manifest)

        if overlays:
            targets = overlays
        elif len(runtime_agents) == 1:
            targets = runtime_agents
        else:
            targets = []

        for server in _tooling_servers(manifest):
            server.metadata["runtime_binding_evidence"] = evidence
            server.metadata["authority_binding"] = "agent365_workiq"

            pure_s2s = bool(
                targets
                and all(
                    str(agent.metadata.get("execution_mode") or "").lower()
                    == "s2s"
                    for agent in targets
                )
            )
            if pure_s2s:
                server.metadata["binding_state"] = "incompatible_s2s"
                server.metadata["binding_reason"] = (
                    "WorkIQ MCP requires delegated user context"
                )
                _append_unbound(graph, server)
                continue

            if evidence and targets:
                server.metadata["binding_state"] = "source_proven"
                server.metadata["context_binding"] = "bound"
                for agent in targets:
                    _attach_server(agent, server)
                continue

            server.metadata["binding_state"] = (
                "runtime_agent_ambiguous"
                if evidence and len(runtime_agents) > 1 and not overlays
                else "declared_unbound"
            )
            server.metadata["context_binding"] = "unbound"
            _append_unbound(graph, server)


def _project_root_for(
    path: Path,
    project_roots: list[Path],
) -> Path | None:
    matches = [
        root
        for root in project_roots
        if _within(path, root)
    ]
    if not matches:
        return None
    return max(matches, key=lambda item: len(item.parts))


def _m365_agents_for_config(
    graph: Graph,
    config_path: Path,
    project_roots: list[Path],
) -> list[Agent]:
    config_project = _project_root_for(config_path, project_roots)
    result: list[Agent] = []
    for agent in graph.agents:
        if (
            agent.metadata.get("framework") != _M365_FRAMEWORK
            or agent.location is None
        ):
            continue
        agent_project = _project_root_for(
            agent.location.path,
            project_roots,
        )
        if config_project is not None:
            if agent_project == config_project:
                result.append(agent)
            continue
        if (
            agent_project is None
            and agent.location.path.parent.resolve()
            == config_path.parent.resolve()
        ):
            result.append(agent)
    return result


def _auth_handlers(raw: dict[str, Any]) -> dict[str, dict[str, Any]]:
    application = raw.get("AgentApplication")
    if not isinstance(application, dict):
        return {}
    user_auth = application.get("UserAuthorization")
    if not isinstance(user_auth, dict):
        return {}
    handlers = user_auth.get("Handlers")
    if not isinstance(handlers, dict):
        return {}

    result: dict[str, dict[str, Any]] = {}
    for name, value in handlers.items():
        if not isinstance(name, str) or not isinstance(value, dict):
            continue
        settings = value.get("Settings")
        if not isinstance(settings, dict):
            settings = {}
        result[name] = {
            "type": str(value.get("Type") or "").strip() or None,
            "scopes": _strings(settings.get("Scopes")),
            "alternate_blueprint_connection": (
                str(settings.get("AlternateBlueprintConnectionName") or "").strip()
                or None
            ),
        }
    return result


def _turn_identity(agent: Agent, config_path: Path) -> Identity:
    identity = next(
        (
            item
            for item in agent.identities
            if item.credential_source == "m365-turn-context"
        ),
        None,
    )
    if identity is not None:
        return identity

    identity = Identity(
        name="signed-in-turn-user",
        provider="microsoft-entra",
        credential_source="m365-turn-context",
        location=SourceLocation(config_path),
        metadata={
            "framework": _M365_FRAMEWORK,
            "identity_type": "delegated_user",
            "permission_model": "delegated",
            "token_subject": "signed_in_user",
            "runtime_resolved": True,
        },
    )
    agent.identities.append(identity)
    return identity


def _apply_handler_authority(
    agent: Agent,
    handlers: dict[str, dict[str, Any]],
    config_path: Path,
    root: Path,
) -> None:
    selected = {
        str(item.metadata.get("auto_sign_in_handler"))
        for item in agent.inputs
        if item.metadata.get("auto_sign_in_handler")
    }
    if (
        not selected
        and agent.metadata.get("turn_user_authorization")
        and len(handlers) == 1
    ):
        selected = set(handlers)

    resolved = [
        (name, handlers[name])
        for name in sorted(selected)
        if name in handlers
    ]
    if not resolved:
        return

    identity = _turn_identity(agent, config_path)
    agentic = False
    metadata_handlers: list[dict[str, Any]] = []
    for name, item in resolved:
        scopes = list(item.get("scopes") or [])
        identity.oauth_scopes.update(scopes)
        handler_type = str(item.get("type") or "")
        agentic = agentic or "AgenticUserAuthorization" in handler_type
        metadata_handlers.append(
            {
                "name": name,
                "type": item.get("type"),
                "scopes": scopes,
                "alternate_blueprint_connection": item.get(
                    "alternate_blueprint_connection"
                ),
            }
        )

    identity.metadata["authorization_handlers"] = metadata_handlers
    identity.metadata["authorization_config_source"] = _display(
        config_path,
        root,
    )
    if agentic:
        identity.metadata["identity_type"] = "agentic_user_delegated"
        identity.metadata["token_subject"] = "agentic_user"
        agent.metadata["agentic_user_authorization"] = True
    agent.metadata["authorization_handlers"] = metadata_handlers


def _connection_identities(
    raw: dict[str, Any],
    config_path: Path,
) -> list[Identity]:
    connections = raw.get("Connections")
    if not isinstance(connections, dict):
        return []

    result: list[Identity] = []
    for name, value in connections.items():
        if not isinstance(name, str) or not isinstance(value, dict):
            continue
        settings = value.get("Settings")
        if not isinstance(settings, dict):
            continue
        client_id = str(settings.get("ClientId") or "").strip()
        scopes = _strings(settings.get("Scopes"))
        if not (client_id or scopes):
            continue

        auth_type = str(settings.get("AuthType") or "").strip()
        application_auth = auth_type.lower() in {
            "clientsecret",
            "certificate",
            "managedidentity",
        }
        identity = Identity(
            name=f"m365-connection:{name}",
            provider="microsoft-entra",
            credential_source=(
                "m365-connection-client-credential"
                if application_auth
                else "m365-connection"
            ),
            location=SourceLocation(config_path),
            metadata={
                "framework": _M365_FRAMEWORK,
                "identity_type": "service_connection",
                "permission_model": (
                    "application" if application_auth else "unknown"
                ),
                "token_subject": (
                    "service_principal" if application_auth else "unknown"
                ),
                "connection_name": name,
                "auth_type": auth_type or None,
                "client_id": client_id or None,
                "authority_endpoint": (
                    str(settings.get("AuthorityEndpoint") or "").strip()
                    or None
                ),
                "client_secret_present": bool(settings.get("ClientSecret")),
                "credential_value_retained": False,
            },
        )
        if application_auth:
            identity.permissions.update(scopes)
        else:
            identity.oauth_scopes.update(scopes)
        result.append(identity)
    return result


def _merge_identity(agent: Agent, incoming: Identity) -> None:
    existing = next(
        (item for item in agent.identities if item.name == incoming.name),
        None,
    )
    if existing is None:
        agent.identities.append(incoming)
        return
    existing.roles.update(incoming.roles)
    existing.permissions.update(incoming.permissions)
    existing.oauth_scopes.update(incoming.oauth_scopes)
    existing.credential_source = (
        incoming.credential_source or existing.credential_source
    )
    existing.metadata.update(incoming.metadata)


def _apply_m365_config_metadata(
    agent: Agent,
    raw: dict[str, Any],
    config_path: Path,
    root: Path,
) -> None:
    token_validation = raw.get("TokenValidation")
    if isinstance(token_validation, dict):
        agent.metadata["token_validation"] = {
            "audiences": _strings(token_validation.get("Audiences")),
            "tenant_id": token_validation.get("TenantId"),
            "source": _display(config_path, root),
        }

    outbound = raw.get("OutboundHostValidator")
    if isinstance(outbound, dict):
        agent.metadata["outbound_host_validator"] = {
            "enabled": outbound.get("Enabled"),
            "include_default_microsoft_hosts": outbound.get(
                "IncludeDefaultMicrosoftHosts"
            ),
            "allow_private_network_addresses": outbound.get(
                "AllowPrivateNetworkAddresses"
            ),
            "hosts": _strings(outbound.get("Hosts")),
            "source": _display(config_path, root),
        }


def _enrich_m365_authorization(
    graph: Graph,
    root: Path,
    candidate_paths: list[Path],
) -> None:
    project_roots = sorted(
        {
            path.parent.resolve()
            for path in candidate_paths
            if path.suffix.lower() == ".csproj"
        },
        key=lambda item: len(item.parts),
    )
    config_paths = [
        path
        for path in candidate_paths
        if (
            path.name == "appsettings.json"
            or (
                path.name.startswith("appsettings.")
                and path.suffix.lower() == ".json"
            )
        )
    ]
    for config_path in config_paths:
        try:
            raw = _load_json(config_path)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
            continue
        agents = _m365_agents_for_config(
            graph,
            config_path,
            project_roots,
        )
        if not agents:
            continue

        handlers = _auth_handlers(raw)
        connections = _connection_identities(raw, config_path)
        for agent in agents:
            _apply_handler_authority(
                agent,
                handlers,
                config_path,
                root,
            )
            for identity in connections:
                _merge_identity(agent, identity)
            _apply_m365_config_metadata(
                agent,
                raw,
                config_path,
                root,
            )


def enrich_microsoft_repository_authority(
    graph: Graph,
    root: Path,
    candidate_paths: list[Path],
) -> None:
    """Enrich Microsoft Agent 365 and M365 Agents SDK authority cross-file.

    ToolingManifest.json is treated as declared MCP topology. It becomes
    effective authority only when source in the same project proves runtime
    registration. Microsoft 365 Agents SDK appsettings authorization is merged
    into the source-proven AgentApplication identity without retaining secrets.
    """

    _enrich_agent365_tooling(graph, root, candidate_paths)
    _enrich_m365_authorization(graph, root, candidate_paths)
