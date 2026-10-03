import json
from pathlib import Path

from horustrace.adapters.microsoft_agent365 import scan_agent365_config
from horustrace.scanner import scan


def _write(path: Path, name: str, payload: dict) -> Path:
    target = path / name
    target.write_text(json.dumps(payload), encoding="utf-8")
    return target


def test_agent365_obo_identity_and_messaging_ingress(tmp_path: Path) -> None:
    static = _write(
        tmp_path,
        "a365.config.json",
        {
            "tenantId": "tenant-1",
            "agentIdentityDisplayName": "SupportAgent",
            "authMode": "obo",
            "messagingEndpoint": "https://agent.example.test/api/messages",
            "customBlueprintPermissions": [
                {
                    "resourceAppId": "graph-app",
                    "resourceName": "Microsoft Graph",
                    "scopes": ["Mail.Read", "Files.Read.All"],
                }
            ],
        },
    )

    graph = scan_agent365_config(static)
    agent = graph.agents[0]
    identity = agent.identities[0]

    assert agent.name == "SupportAgent"
    assert agent.metadata["execution_mode"] == "obo"
    assert identity.metadata["permission_model"] == "delegated"
    assert identity.metadata["token_subject"] == "signed_in_user"
    assert identity.metadata["actor"] == "agent_identity"
    assert "Microsoft Graph:Mail.Read" in identity.oauth_scopes
    assert identity.permissions == set()

    assert len(agent.inputs) == 1
    assert agent.inputs[0].trust == "untrusted"
    assert agent.inputs[0].kind == "channel"
    assert agent.inputs[0].metadata["runtime_ingress"] is True


def test_agent365_s2s_permissions_and_mcp_identity(tmp_path: Path) -> None:
    static = _write(
        tmp_path,
        "a365.config.json",
        {
            "agentIdentityDisplayName": "BackgroundAgent",
            "authMode": "s2s",
            "mcpDefaultServers": [
                {
                    "mcpServerName": "Finance MCP",
                    "url": "https://mcp.example.test",
                    "scope": "api://finance/.default",
                    "audience": "api://finance",
                }
            ],
            "customBlueprintPermissions": [
                {
                    "resourceName": "Microsoft Graph",
                    "resourceAppId": "graph-app",
                    "scopes": ["Sites.Read.All"],
                }
            ],
        },
    )

    graph = scan_agent365_config(static)
    agent = graph.agents[0]
    identity = agent.identities[0]

    assert identity.metadata["execution_mode"] == "s2s"
    assert identity.metadata["permission_model"] == "application"
    assert identity.metadata["token_subject"] == "agent_identity"
    assert "Microsoft Graph:Sites.Read.All" in identity.permissions
    assert identity.oauth_scopes == set()

    server = agent.mcp_servers[0]
    assert server.name == "Finance MCP"
    assert server.url == "https://mcp.example.test"
    assert server.authenticated is True
    assert server.identity == "BackgroundAgent"
    assert server.metadata["scope"] == "api://finance/.default"


def test_agent365_both_uses_declared_permissions_for_both_models(
    tmp_path: Path,
) -> None:
    static = _write(
        tmp_path,
        "a365.config.json",
        {
            "agentIdentityDisplayName": "DualMode",
            "authMode": "both",
            "customBlueprintPermissions": [
                {
                    "resourceName": "Custom API",
                    "resourceAppId": "custom-app",
                    "scopes": ["Records.ReadWrite"],
                }
            ],
        },
    )

    graph = scan_agent365_config(static)
    identity = graph.agents[0].identities[0]

    assert "Custom API:Records.ReadWrite" in identity.oauth_scopes
    assert "Custom API:Records.ReadWrite" in identity.permissions
    assert identity.metadata["permission_model"] == (
        "delegated_and_application"
    )


def test_agent365_generated_config_never_retains_secret_value(
    tmp_path: Path,
) -> None:
    static = _write(
        tmp_path,
        "a365.config.json",
        {
            "tenantId": "tenant-1",
            "agentIdentityDisplayName": "SecureAgent",
            "authMode": "s2s",
        },
    )
    _write(
        tmp_path,
        "a365.generated.config.json",
        {
            "agentBlueprintId": "blueprint-id",
            "agentInstanceId": "instance-id",
            "agenticAppId": "app-id",
            "agentBlueprintClientSecret": "TOP-SECRET-VALUE",
            "agentBlueprintClientSecretProtected": True,
            "resourceConsents": [
                {
                    "resourceName": "Microsoft Graph",
                    "resourceAppId": "graph-app",
                    "scopes": ["User.Read.All"],
                    "consentGranted": True,
                }
            ],
        },
    )

    graph = scan_agent365_config(static)
    agent = graph.agents[0]
    identity = agent.identities[0]

    assert identity.metadata["client_secret_present"] is True
    assert identity.metadata["client_secret_protected"] is True
    assert identity.metadata["credential_value_retained"] is False
    assert identity.credential_source == "agent-blueprint-client-secret"
    assert "TOP-SECRET-VALUE" not in repr(graph)
    assert "Microsoft Graph:User.Read.All" in identity.permissions


def test_agent365_agentic_user_identity_is_inventory_entry(
    tmp_path: Path,
) -> None:
    static = _write(
        tmp_path,
        "a365.config.json",
        {
            "agentIdentityDisplayName": "MailAgent",
            "aiTeammate": True,
            "agentUserPrincipalName": "mail-agent@example.test",
        },
    )
    _write(
        tmp_path,
        "a365.generated.config.json",
        {"agenticUserId": "agent-user-id"},
    )

    graph = scan_agent365_config(static)
    agent = graph.agents[0]

    assert agent.metadata["execution_mode"] == "obo"
    user = next(
        item for item in agent.identities
        if item.metadata.get("identity_type") == "agentic_user"
    )
    assert user.name == "mail-agent@example.test"
    assert user.metadata["execution_mode"] == "agentic-user"
    assert user.metadata["user_id"] == "agent-user-id"


def test_agent365_overlay_merges_with_framework_agent(tmp_path: Path) -> None:
    (tmp_path / "Program.cs").write_text(
        """
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

AIAgent agent = chatClient.AsAIAgent(name: "SupportAgent");
""",
        encoding="utf-8",
    )
    _write(
        tmp_path,
        "a365.config.json",
        {
            "agentIdentityDisplayName": "SupportAgent",
            "authMode": "obo",
        },
    )

    graph, _ = scan(tmp_path)
    matches = [item for item in graph.agents if item.name == "SupportAgent"]

    assert len(matches) == 1
    agent = matches[0]
    assert agent.metadata["framework"] in {
        "microsoft-agent-framework-dotnet",
        "microsoft-agent365",
    }
    assert any(
        identity.provider == "microsoft-entra-agent365"
        for identity in agent.identities
    )
