from pathlib import Path

from horustrace.adapters.microsoft_365_agents_dotnet import (
    scan_microsoft_365_agents_dotnet_file,
)
from horustrace.scanner import scan


def _write(tmp_path: Path, text: str, name: str = "MyAgent.cs") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_m365_agents_message_route_is_untrusted_ingress(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        r'''
using Microsoft.Agents.Builder.App;
using Microsoft.Agents.Builder.State;
using Microsoft.Agents.Core.Models;

[Agent(name: "SupportAgent", description: "support", version: "1")]
public class MyAgent(AgentApplicationOptions options) : AgentApplication(options)
{
    [MessageRoute]
    private async Task OnMessageAsync(
        ITurnContext turnContext,
        ITurnState turnState,
        CancellationToken cancellationToken)
    {
        await turnContext.SendActivityAsync(turnContext.Activity.Text);
    }
}
''',
    )

    graph = scan_microsoft_365_agents_dotnet_file(path)
    agent = graph.agents[0]

    assert agent.name == "SupportAgent"
    assert agent.metadata["agent_type"] == "AgentApplication"
    assert agent.metadata["class_name"] == "MyAgent"
    assert len(agent.inputs) == 1
    ingress = agent.inputs[0]
    assert ingress.kind == "m365_activity"
    assert ingress.trust == "untrusted"
    assert ingress.metadata["message_route"] is True
    assert ingress.metadata["runtime_ingress"] is True


def test_m365_agents_teams_route_identifies_teams_channel(
    tmp_path: Path,
) -> None:
    path = _write(
        tmp_path,
        r'''
using Microsoft.Agents.Builder.App;
using Microsoft.Agents.Extensions.MSTeams.App;

public class TeamsAgent(AgentApplicationOptions options) : AgentApplication(options)
{
    [TeamsMessageRoute("whoami")]
    public async Task WhoAmIAsync(
        ITeamsTurnContext turnContext,
        ITurnState turnState,
        CancellationToken cancellationToken)
    {
        await turnContext.SendActivityAsync("hello");
    }
}
''',
    )

    graph = scan_microsoft_365_agents_dotnet_file(path)
    ingress = graph.agents[0].inputs[0]

    assert ingress.kind == "teams"
    assert ingress.metadata["teams_channel"] is True
    assert ingress.metadata["route_attribute"] == "TeamsMessageRoute"


def test_m365_agents_default_endpoints_capture_authentication_posture(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path,
        r'''
using Microsoft.Agents.Hosting.AspNetCore;
using Microsoft.AspNetCore.Builder;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

builder.AddAgentDefaults()
    .AddAgent<MyAgent>()
    .AddAgentAuthorization(b => b.AddAgentAspNetAuthentication());

WebApplication app = builder.Build();
app.UseAgents();
app.MapDefaultAgentEndpoints();
app.Run();
''',
        "Program.cs",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "MyAgent")
    ingress = next(
        item
        for item in agent.inputs
        if item.name == "m365-agent-default-message-endpoint"
    )

    assert agent.metadata["authentication_configured"] is True
    assert ingress.trust == "untrusted"
    assert ingress.metadata["authenticated"] is True
    assert "AddAgentAuthorization" in ingress.metadata["authentication_basis"]


def test_m365_agents_missing_authentication_is_not_invented(
    tmp_path: Path,
) -> None:
    path = _write(
        tmp_path,
        r'''
using Microsoft.Agents.Hosting.AspNetCore;

builder.AddAgentDefaults().AddAgent<MyAgent>();
app.MapDefaultAgentEndpoints();
''',
        "Program.cs",
    )

    graph = scan_microsoft_365_agents_dotnet_file(path)
    agent = graph.agents[0]
    ingress = agent.inputs[0]

    assert agent.metadata["authentication_configured"] is False
    assert ingress.metadata["authenticated"] is False
    assert ingress.metadata["authentication_basis"] == "not_source_proven"


def test_m365_agents_agentic_route_and_turn_token_identity(
    tmp_path: Path,
) -> None:
    path = _write(
        tmp_path,
        r'''
using Microsoft.Agents.Builder.App;

public class AgenticAgent(AgentApplicationOptions options) : AgentApplication(options)
{
    [MessageRoute(isAgenticOnly: true, autoSignInHandlers: "agentic")]
    public async Task OnMessageAsync(
        ITurnContext turnContext,
        ITurnState turnState,
        CancellationToken cancellationToken)
    {
        var token = await UserAuthorization.GetTurnTokenAsync(
            turnContext,
            "agentic",
            cancellationToken);
    }
}
''',
    )

    graph = scan_microsoft_365_agents_dotnet_file(path)
    agent = graph.agents[0]
    ingress = agent.inputs[0]

    assert ingress.metadata["agentic_only"] is True
    assert ingress.metadata["auto_sign_in_handler"] == "agentic"
    assert agent.metadata["turn_user_authorization"] is True
    identity = agent.identities[0]
    assert identity.provider == "microsoft-entra"
    assert identity.metadata["permission_model"] == "delegated"
    assert identity.metadata["runtime_resolved"] is True


def test_m365_agents_class_and_host_registration_merge_repository_wide(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path,
        r'''
using Microsoft.Agents.Builder.App;

public class MyAgent(AgentApplicationOptions options) : AgentApplication(options)
{
    [MessageRoute]
    public Task OnMessageAsync(
        ITurnContext turnContext,
        ITurnState turnState,
        CancellationToken cancellationToken) => Task.CompletedTask;
}
''',
    )
    _write(
        tmp_path,
        r'''
using Microsoft.Agents.Hosting.AspNetCore;

builder.AddAgentDefaults()
    .AddAgent<MyAgent>()
    .AddAgentAuthorization(b => b.AddAgentAspNetAuthentication());

app.UseAgents();
app.MapDefaultAgentEndpoints();
''',
        "Program.cs",
    )

    graph, _ = scan(tmp_path)
    agents = [item for item in graph.agents if item.name == "MyAgent"]

    assert len(agents) == 1
    agent = agents[0]
    assert any(
        item.metadata.get("basis") == "m365_agents_route_attribute"
        for item in agent.inputs
    )
    assert any(
        item.metadata.get("basis") == "MapDefaultAgentEndpoints"
        for item in agent.inputs
    )



def test_m365_agents_agent_attribute_survives_modifier_and_attribute_stack(
    tmp_path: Path,
) -> None:
    path = _write(
        tmp_path,
        r"""
using System;
using Microsoft.Agents.Builder.App;

[Agent(name: "LayeredAgent", description: "support", version: "1")]
[Obsolete]
public sealed partial class LayeredAgentClass(
    AgentApplicationOptions options
) : AgentApplication(options)
{
    [MessageRoute]
    public Task OnMessageAsync(
        ITurnContext turnContext,
        ITurnState turnState,
        CancellationToken cancellationToken) => Task.CompletedTask;
}
""",
    )

    graph = scan_microsoft_365_agents_dotnet_file(path)
    agent = graph.agents[0]

    assert agent.name == "LayeredAgent"
    assert agent.metadata["class_name"] == "LayeredAgentClass"
    assert agent.inputs[0].metadata["route_attribute"] == "MessageRoute"


def test_m365_agents_appsettings_reconstructs_authorization_authority(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path,
        r'''
using Microsoft.Agents.Builder.App;

public class AgenticAgent(AgentApplicationOptions options) : AgentApplication(options)
{
    [MessageRoute(isAgenticOnly: true, autoSignInHandlers: "agentic")]
    public async Task OnMessageAsync(
        ITurnContext turnContext,
        ITurnState turnState,
        CancellationToken cancellationToken)
    {
        var token = await UserAuthorization.GetTurnTokenAsync(
            turnContext,
            "agentic",
            cancellationToken);
    }
}
''',
    )
    _write(
        tmp_path,
        r'''
using Microsoft.Agents.Hosting.AspNetCore;

builder.AddAgentDefaults()
    .AddAgent<AgenticAgent>()
    .AddAgentAuthorization(b => b.AddAgentAspNetAuthentication());

app.UseAgents();
app.MapDefaultAgentEndpoints();
''',
        "Program.cs",
    )
    (tmp_path / "appsettings.json").write_text(
        """
{
  "OutboundHostValidator": {
    "Enabled": false,
    "IncludeDefaultMicrosoftHosts": true,
    "AllowPrivateNetworkAddresses": false,
    "Hosts": []
  },
  "TokenValidation": {
    "Audiences": ["blueprint-id"],
    "TenantId": "tenant-id"
  },
  "AgentApplication": {
    "UserAuthorization": {
      "Handlers": {
        "agentic": {
          "Type": "AgenticUserAuthorization",
          "Settings": {
            "Scopes": ["https://graph.microsoft.com/.default"]
          }
        }
      }
    }
  },
  "Connections": {
    "ServiceConnection": {
      "Settings": {
        "AuthType": "ClientSecret",
        "AuthorityEndpoint": "https://login.microsoftonline.com/tenant-id",
        "ClientSecret": "TOP-SECRET-VALUE",
        "ClientId": "blueprint-id",
        "Scopes": ["agent-channel/.default"]
      }
    }
  }
}
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "AgenticAgent")

    turn_identity = next(
        item for item in agent.identities
        if item.credential_source == "m365-turn-context"
    )
    assert "https://graph.microsoft.com/.default" in turn_identity.oauth_scopes
    assert turn_identity.metadata["identity_type"] == "agentic_user_delegated"
    assert turn_identity.metadata["token_subject"] == "agentic_user"
    assert turn_identity.metadata["authorization_handlers"][0]["name"] == (
        "agentic"
    )
    assert agent.metadata["agentic_user_authorization"] is True

    connection = next(
        item for item in agent.identities
        if item.name == "m365-connection:ServiceConnection"
    )
    assert connection.metadata["permission_model"] == "application"
    assert connection.metadata["client_secret_present"] is True
    assert connection.metadata["credential_value_retained"] is False
    assert "agent-channel/.default" in connection.permissions
    assert "TOP-SECRET-VALUE" not in repr(graph)

    assert agent.metadata["token_validation"]["audiences"] == ["blueprint-id"]
    assert agent.metadata["token_validation"]["tenant_id"] == "tenant-id"
    assert agent.metadata["outbound_host_validator"]["enabled"] is False
    assert (
        agent.metadata["outbound_host_validator"][
            "allow_private_network_addresses"
        ]
        is False
    )


def test_m365_agents_unrelated_appsettings_does_not_cross_project_boundary(
    tmp_path: Path,
) -> None:
    project = tmp_path / "agent-project"
    project.mkdir()
    _write(
        project,
        r'''
using Microsoft.Agents.Builder.App;

public class ScopedAgent(AgentApplicationOptions options) : AgentApplication(options)
{
    [MessageRoute]
    public async Task OnMessageAsync(
        ITurnContext turnContext,
        ITurnState turnState,
        CancellationToken cancellationToken)
    {
        var token = await UserAuthorization.GetTurnTokenAsync(
            turnContext,
            "agentic",
            cancellationToken);
    }
}
''',
    )
    (tmp_path / "appsettings.json").write_text(
        """
{
  "AgentApplication": {
    // .NET appsettings commonly permits JSONC comments.
    "UserAuthorization": {
      "Handlers": {
        "agentic": {
          "Type": "AgenticUserAuthorization",
          "Settings": {
            "Scopes": ["https://graph.microsoft.com/.default"]
          }
        }
      }
    }
  }
}
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "ScopedAgent")
    identity = next(
        item for item in agent.identities
        if item.credential_source == "m365-turn-context"
    )

    assert identity.oauth_scopes == set()
    assert "authorization_handlers" not in identity.metadata
