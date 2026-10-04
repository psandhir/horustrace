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


def test_agent365_tooling_manifest_becomes_effective_when_runtime_is_wired(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path,
        "a365.config.json",
        {
            "agentIdentityDisplayName": "WorkAgent",
            "authMode": "obo",
        },
    )
    _write(
        tmp_path,
        "ToolingManifest.json",
        {
            "mcpServers": [
                {
                    "mcpServerName": "mcp_MailTools",
                    "url": "https://agent365.example.test/mail",
                    "scope": "Tools.ListInvoke.All",
                    "audience": "mail-audience",
                    "publisher": "Microsoft",
                },
                {
                    "mcpServerName": "mcp_CalendarTools",
                    "url": "https://agent365.example.test/calendar",
                    "scope": "Tools.ListInvoke.All",
                    "audience": "calendar-audience",
                    "publisher": "Microsoft",
                },
            ]
        },
    )
    (tmp_path / "Agent365Tools.cs").write_text(
        """
using Microsoft.Agents.A365.Tooling;

await toolService.AddToolServersToAgentAsync(
    agent,
    userAuthorization,
    authHandlerName,
    turnContext);
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "WorkAgent")

    assert {item.name for item in agent.mcp_servers} == {
        "mcp_MailTools",
        "mcp_CalendarTools",
    }
    mail = next(
        item for item in agent.mcp_servers
        if item.name == "mcp_MailTools"
    )
    assert mail.metadata["binding_state"] == "source_proven"
    assert mail.metadata["permission_model"] == "delegated"
    assert mail.metadata["requires_user_context"] is True
    assert mail.metadata["requires_admin_consent"] is True
    assert mail.metadata["permission_grant_state"] == "not_source_proven"
    assert mail.identity == "WorkAgent"

    identity = next(
        item for item in agent.identities
        if item.provider == "microsoft-entra-agent365"
    )
    assert "mcp_MailTools:Tools.ListInvoke.All" in identity.oauth_scopes
    assert any(
        "agent365_dotnet_tooling_registration" in evidence
        for evidence in mail.metadata["runtime_binding_evidence"]
    )


def test_agent365_tooling_manifest_stays_unbound_without_runtime_wiring(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path,
        "a365.config.json",
        {
            "agentIdentityDisplayName": "DeclaredOnlyAgent",
            "authMode": "obo",
        },
    )
    _write(
        tmp_path,
        "ToolingManifest.json",
        {
            "mcpServers": [
                {
                    "mcpServerName": "mcp_TeamsServer",
                    "url": "https://agent365.example.test/teams",
                    "scope": "Tools.ListInvoke.All",
                    "audience": "teams-audience",
                }
            ]
        },
    )

    graph, _ = scan(tmp_path)
    agent = next(
        item for item in graph.agents
        if item.name == "DeclaredOnlyAgent"
    )

    assert agent.mcp_servers == []
    assert len(graph.unbound_mcp_servers) == 1
    server = graph.unbound_mcp_servers[0]
    assert server.name == "mcp_TeamsServer"
    assert server.metadata["binding_state"] == "declared_unbound"
    assert server.metadata["permission_grant_state"] == "not_source_proven"


def test_agent365_workiq_is_not_effective_for_pure_s2s(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path,
        "a365.config.json",
        {
            "agentIdentityDisplayName": "BackgroundAgent",
            "authMode": "s2s",
        },
    )
    _write(
        tmp_path,
        "ToolingManifest.json",
        {
            "mcpServers": [
                {
                    "mcpServerName": "mcp_MailTools",
                    "url": "https://agent365.example.test/mail",
                    "scope": "Tools.ListInvoke.All",
                    "audience": "mail-audience",
                }
            ]
        },
    )
    (tmp_path / "Agent365Tools.cs").write_text(
        """
using Microsoft.Agents.A365.Tooling;

await toolService.AddToolServersToAgentAsync(
    agent,
    userAuthorization,
    authHandlerName,
    turnContext);
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(
        item for item in graph.agents
        if item.name == "BackgroundAgent"
    )

    assert agent.mcp_servers == []
    server = graph.unbound_mcp_servers[0]
    assert server.metadata["binding_state"] == "incompatible_s2s"
    assert "delegated user context" in server.metadata["binding_reason"]


def test_agent365_python_tooling_binds_to_unique_maf_agent(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from agent_framework import Agent
from microsoft_agents_a365.tooling.extensions.agentframework.services.mcp_tool_registration_service import (
    McpToolRegistrationService,
)

agent = Agent(client=client, instructions="help", tools=[])
service = McpToolRegistrationService()
agent = await service.add_tool_servers_to_agent(
    chat_client=client,
    agent_instructions="help",
    initial_tools=[],
    auth=auth,
    auth_handler_name="agentic",
    turn_context=context,
)
""",
        encoding="utf-8",
    )
    _write(
        tmp_path,
        "ToolingManifest.json",
        {
            "mcpServers": [
                {
                    "mcpServerName": "mcp_MailTools",
                    "url": "https://agent365.example.test/mail",
                    "scope": "McpServers.Mail.All",
                    "audience": "agent365-audience",
                }
            ]
        },
    )

    graph, _ = scan(tmp_path)
    agent = next(
        item for item in graph.agents
        if item.metadata.get("framework") == "microsoft-agent-framework"
    )

    assert {item.name for item in agent.mcp_servers} == {"mcp_MailTools"}
    identity = next(
        item for item in agent.identities
        if item.name == "agent365-delegated-user"
    )
    assert identity.metadata["permission_model"] == "delegated"
    assert "mcp_MailTools:McpServers.Mail.All" in identity.oauth_scopes


def test_agent365_direct_manifest_binding_requires_manifest_load_evidence(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path,
        "a365.config.json",
        {
            "agentIdentityDisplayName": "DirectWorkIqAgent",
            "authMode": "obo",
        },
    )
    _write(
        tmp_path,
        "ToolingManifest.json",
        {
            "mcpServers": [
                {
                    "mcpServerName": "mcp_MailTools",
                    "url": "https://agent365.example.test/mail",
                    "scope": "Tools.ListInvoke.All",
                    "audience": "mail-audience",
                }
            ]
        },
    )
    (tmp_path / "WorkIqToolProvider.cs").write_text(
        """
using System.Text.Json;
using ModelContextProtocol.Client;

var manifestPath = Path.Combine(root, "ToolingManifest.json");
using var stream = File.OpenRead(manifestPath);
var manifest = JsonSerializer.Deserialize<object>(stream);
var transport = new HttpClientTransport(options);
var client = await McpClient.CreateAsync(transport);
""",
        encoding="utf-8",
    )
    (tmp_path / "Program.cs").write_text(
        """
using ModelContextProtocol.Client;

// ToolingManifest.json defines Work IQ servers elsewhere.
var learnTransport = new HttpClientTransport(options);
var learnClient = await McpClient.CreateAsync(learnTransport);
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(
        item for item in graph.agents
        if item.name == "DirectWorkIqAgent"
    )
    server = next(
        item for item in agent.mcp_servers
        if item.name == "mcp_MailTools"
    )

    assert server.metadata["runtime_binding_evidence"] == [
        "WorkIqToolProvider.cs:agent365_direct_manifest_mcp_binding"
    ]
