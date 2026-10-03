from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from horustrace.limits import validate_json_safety
from horustrace.models import (
    Agent,
    Graph,
    Identity,
    InputSource,
    MCPServer,
    NetworkDestination,
    SourceLocation,
)

AGENT365_CONFIG_FILENAMES = {"a365.config.json", "a365.generated.config.json"}
_PROVIDER = "microsoft-agent365"


def _load(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    validate_json_safety(text)
    raw = json.loads(text)
    if not isinstance(raw, dict):
        raise TypeError("Agent 365 configuration must be a JSON object")
    return raw


def _strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]


def _permission_entries(static: dict[str, Any], generated: dict[str, Any]) -> list[tuple[str, str, list[str], bool | None]]:
    result: list[tuple[str, str, list[str], bool | None]] = []
    custom = static.get("customBlueprintPermissions")
    if isinstance(custom, list):
        for item in custom:
            if not isinstance(item, dict):
                continue
            app_id = str(item.get("resourceAppId") or "").strip()
            name = str(item.get("resourceName") or app_id or "resource").strip()
            scopes = _strings(item.get("scopes"))
            if scopes:
                result.append((name, app_id, scopes, None))

    consents = generated.get("resourceConsents")
    if isinstance(consents, list):
        for item in consents:
            if not isinstance(item, dict):
                continue
            app_id = str(item.get("resourceAppId") or "").strip()
            name = str(item.get("resourceName") or app_id or "resource").strip()
            scopes = _strings(item.get("scopes"))
            if scopes:
                result.append((
                    name,
                    app_id,
                    scopes,
                    item.get("consentGranted") if isinstance(item.get("consentGranted"), bool) else None,
                ))
    return result


def _identity_name(static: dict[str, Any], generated: dict[str, Any]) -> str:
    return str(
        static.get("agentIdentityDisplayName")
        or static.get("agentBlueprintDisplayName")
        or generated.get("agenticAppId")
        or generated.get("agentInstanceId")
        or generated.get("agentBlueprintId")
        or "agent365-agent"
    ).strip()


def _mode(static: dict[str, Any]) -> str:
    if static.get("aiTeammate") is True:
        return "obo"
    value = str(static.get("authMode") or "obo").strip().lower()
    return value if value in {"obo", "s2s", "both"} else "unknown"


def _apply_permissions(
    identity: Identity,
    entries: list[tuple[str, str, list[str], bool | None]],
    mode: str,
) -> None:
    declared: list[dict[str, Any]] = []
    for resource_name, resource_app_id, scopes, consent_granted in entries:
        qualified = {
            f"{resource_name}:{scope}"
            for scope in scopes
        }
        if mode in {"obo", "both"}:
            identity.oauth_scopes.update(qualified)
        if mode in {"s2s", "both"}:
            identity.permissions.update(qualified)
        declared.append({
            "resource": resource_name,
            "resource_app_id": resource_app_id or None,
            "scopes": scopes,
            "consent_granted": consent_granted,
        })
    if declared:
        identity.metadata["declared_resource_permissions"] = declared


def _agent_user_identity(
    static: dict[str, Any],
    generated: dict[str, Any],
    path: Path,
) -> Identity | None:
    upn = str(static.get("agentUserPrincipalName") or "").strip()
    user_id = str(generated.get("agenticUserId") or "").strip()
    if not (upn or user_id):
        return None
    return Identity(
        name=upn or user_id,
        provider="microsoft-entra",
        credential_source="agentic-user",
        location=SourceLocation(path),
        metadata={
            "framework": _PROVIDER,
            "identity_type": "agentic_user",
            "execution_mode": "agentic-user",
            "user_id": user_id or None,
            "user_principal_name": upn or None,
        },
    )


def _mcp_servers(
    static: dict[str, Any],
    identity_name: str,
    path: Path,
) -> list[MCPServer]:
    result: list[MCPServer] = []
    servers = static.get("mcpDefaultServers")
    if not isinstance(servers, list):
        return result
    for item in servers:
        if not isinstance(item, dict):
            continue
        name = str(item.get("mcpServerName") or item.get("mcpServerUniqueName") or "agent365-mcp").strip()
        url = str(item.get("url") or "").strip() or None
        scope = str(item.get("scope") or "").strip()
        audience = str(item.get("audience") or "").strip()
        server = MCPServer(
            name=name,
            transport="streamable-http" if url else "provider",
            url=url,
            authenticated=True if (scope or audience) else None,
            identity=identity_name,
            location=SourceLocation(path),
            metadata={
                "framework": _PROVIDER,
                "provider": "microsoft-agent365",
                "scope": scope or None,
                "audience": audience or None,
                "publisher": item.get("publisher"),
                "server_id": item.get("id"),
                "capabilities": _strings(item.get("capabilities")),
                "authority_binding": "agent365_identity",
            },
        )
        result.append(server)
    return result


def scan_agent365_config(path: Path) -> Graph:
    graph = Graph()
    if path.name not in AGENT365_CONFIG_FILENAMES:
        return graph

    static_path = path.parent / "a365.config.json"
    generated_path = path.parent / "a365.generated.config.json"

    # When both files exist, the static config owns the merged repository overlay.
    if path.name == "a365.generated.config.json" and static_path.exists():
        return graph

    static = _load(static_path) if static_path.exists() else {}
    generated = _load(generated_path) if generated_path.exists() else {}
    if path.name == "a365.generated.config.json" and not static:
        generated = _load(path)

    identity_name = _identity_name(static, generated)
    mode = _mode(static)
    secret_present = bool(generated.get("agentBlueprintClientSecret"))
    secret_protected = generated.get("agentBlueprintClientSecretProtected") is True

    identity = Identity(
        name=identity_name,
        provider="microsoft-entra-agent365",
        credential_source=(
            "agent-blueprint-client-secret"
            if secret_present
            else "agent365-platform"
        ),
        location=SourceLocation(path),
        metadata={
            "framework": _PROVIDER,
            "identity_type": "agent_identity",
            "execution_mode": mode,
            "permission_model": {
                "obo": "delegated",
                "s2s": "application",
                "both": "delegated_and_application",
            }.get(mode, "unknown"),
            "token_subject": (
                "signed_in_user" if mode == "obo"
                else "agent_identity" if mode == "s2s"
                else "mode_dependent"
            ),
            "actor": "agent_identity" if mode in {"obo", "both"} else None,
            "tenant_id": static.get("tenantId"),
            "blueprint_id": generated.get("agentBlueprintId"),
            "agent_instance_id": generated.get("agentInstanceId"),
            "agent_registration_id": generated.get("agentRegistrationId"),
            "agentic_app_id": generated.get("agenticAppId"),
            "client_secret_present": secret_present,
            "client_secret_protected": secret_protected if secret_present else None,
            "credential_value_retained": False,
        },
    )
    _apply_permissions(identity, _permission_entries(static, generated), mode)

    agent = Agent(
        name=identity_name,
        location=SourceLocation(path),
        identities=[identity],
        metadata={
            "framework": _PROVIDER,
            "identity_overlay": True,
            "execution_mode": mode,
            "agent365_environment": static.get("environment") or "prod",
            "blueprint_id": generated.get("agentBlueprintId"),
            "agent_instance_id": generated.get("agentInstanceId"),
            "ai_teammate": static.get("aiTeammate"),
            "use_blueprint": static.get("useBlueprint"),
        },
    )

    agent_user = _agent_user_identity(static, generated, path)
    if agent_user is not None:
        agent.identities.append(agent_user)
        agent.metadata["agentic_user_configured"] = True

    messaging_endpoint = str(
        static.get("messagingEndpoint")
        or generated.get("messagingEndpoint")
        or ""
    ).strip()
    if messaging_endpoint:
        agent.inputs.append(InputSource(
            name="agent365-messaging-endpoint",
            trust="untrusted",
            kind="channel",
            location=SourceLocation(path),
            metadata={
                "framework": _PROVIDER,
                "basis": "a365_messaging_endpoint",
                "endpoint": messaging_endpoint,
                "runtime_ingress": True,
            },
        ))
        agent.network.append(NetworkDestination(
            target=messaging_endpoint,
            direction="inbound",
            restricted=True,
            location=SourceLocation(path),
            metadata={
                "framework": _PROVIDER,
                "source": "agent365_messaging_endpoint",
            },
        ))

    agent.mcp_servers.extend(_mcp_servers(static, identity_name, path))
    graph.agents.append(agent)
    return graph
