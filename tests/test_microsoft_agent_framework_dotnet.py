from pathlib import Path

from horustrace.adapters.microsoft_agent_framework_dotnet import (
    is_microsoft_agent_framework_dotnet_file,
    scan_dotnet_file,
)
from horustrace.scanner import scan


def write(tmp_path: Path, text: str, name: str = "Program.cs") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_dotnet_maf_foundry_agent_and_function_tool(tmp_path: Path) -> None:
    source = write(
        tmp_path,
        r'''
using Azure.AI.Projects;
using Azure.Identity;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

var endpoint = Environment.GetEnvironmentVariable("FOUNDRY_PROJECT_ENDPOINT");
var model = Environment.GetEnvironmentVariable("FOUNDRY_MODEL");

static string GetWeather(string location)
    => $"Weather for {location}";

AIAgent agent = new AIProjectClient(
    new Uri(endpoint),
    new DefaultAzureCredential())
    .AsAIAgent(
        model: model,
        name: "WeatherAgent",
        tools: [AIFunctionFactory.Create(GetWeather)]);
''',
    )

    assert is_microsoft_agent_framework_dotnet_file(source)
    graph, _ = scan(tmp_path)

    agent = next(item for item in graph.agents if item.name == "WeatherAgent")
    assert agent.metadata["framework"] == "microsoft-agent-framework-dotnet"
    assert agent.metadata["language"] == "csharp"
    assert agent.metadata["foundry_backed"] is True
    assert agent.metadata["provider"] == "microsoft-foundry"

    tool = next(item for item in agent.tools if item.name == "GetWeather")
    assert tool.kind == "function"
    assert tool.metadata["binding_origin"] == "AIFunctionFactory.Create"


def test_dotnet_maf_approval_required_function_preserves_process_authority(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        r'''
using System.Diagnostics;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

static string RunCommand(string command)
{
    Process.Start(new ProcessStartInfo("cmd.exe", command));
    return "ok";
}

AITool commandTool = new ApprovalRequiredAIFunction(
    AIFunctionFactory.Create(RunCommand));

AIAgent agent = chatClient.AsAIAgent(
    name: "OpsAgent",
    tools: [commandTool]);
''',
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "OpsAgent")
    tool = next(item for item in agent.tools if item.name == "RunCommand")

    assert tool.approval is True
    assert "process.execute" in tool.capabilities


def test_dotnet_maf_agent_as_function_projects_child_authority(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        r'''
using System.Diagnostics;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

static string RunCommand(string command)
{
    Process.Start(command);
    return "done";
}

AIAgent child = chatClient.AsAIAgent(
    name: "PrivilegedChild",
    tools: [AIFunctionFactory.Create(RunCommand)]);

AIAgent parent = chatClient.AsAIAgent(
    name: "Coordinator",
    tools: [child.AsAIFunction()]);
''',
    )

    graph, _ = scan(tmp_path)
    parent = next(item for item in graph.agents if item.name == "Coordinator")
    delegated = next(item for item in parent.tools if item.kind == "delegated_agent")

    assert "agent.delegate" in delegated.capabilities
    assert "process.execute" in delegated.capabilities
    assert delegated.metadata["delegated_agent_targets"] == ["PrivilegedChild"]
    assert delegated.metadata["authority_binding"] == "delegation_projection"
    assert (
        delegated.metadata["authority_binding_basis"]
        == "microsoft_dotnet_agent_as_function"
    )


def test_dotnet_maf_stdio_mcp_tools_bind_to_agent(tmp_path: Path) -> None:
    write(
        tmp_path,
        r'''
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using ModelContextProtocol.Client;

await using McpClient mcpClient = await McpClient.CreateAsync(
    new StdioClientTransport(new()
    {
        Name = "calculator",
        Command = "dotnet",
        Arguments = ["calculator-server.dll"],
    }));

IList<McpClientTool> mcpTools = await mcpClient.ListToolsAsync();

AIAgent agent = chatClient.AsAIAgent(
    name: "MathAgent",
    tools: [.. mcpTools.Cast<AITool>()]);
''',
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "MathAgent")
    server = next(item for item in agent.mcp_servers if item.name == "calculator")

    assert server.transport == "stdio"
    assert server.command == "dotnet"
    assert server.args == ["calculator-server.dll"]
    assert not any(item.name == "calculator" for item in graph.unbound_mcp_servers)


def test_dotnet_maf_foundry_toolbox_http_mcp_preserves_operator_boundary_and_auth(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        r'''
using Azure.Core;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using ModelContextProtocol.Client;

string toolboxMcpServerUrl =
    Environment.GetEnvironmentVariable("FOUNDRY_TOOLBOX_MCP_SERVER_URL")
    ?? throw new InvalidOperationException();

TokenCredential credential = new DefaultAzureCredential();
using var httpClient = new HttpClient(
    new BearerTokenHandler(credential, "https://ai.azure.com/.default"));

await using McpClient mcpClient = await McpClient.CreateAsync(
    new HttpClientTransport(
        new HttpClientTransportOptions
        {
            Endpoint = new Uri(toolboxMcpServerUrl),
            Name = "foundry_toolbox",
            TransportMode = HttpTransportMode.StreamableHttp,
            AdditionalHeaders = new Dictionary<string, string>
            {
                ["Foundry-Features"] = "Toolboxes=V1Preview",
            },
        },
        httpClient));

IList<McpClientTool> mcpTools = await mcpClient.ListToolsAsync();

AIAgent agent = chatClient.AsAIAgent(
    name: "ResearchAgent",
    tools: [.. mcpTools.Cast<AITool>()]);
''',
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "ResearchAgent")
    server = next(item for item in agent.mcp_servers if item.name == "foundry_toolbox")

    assert server.transport == "streamable-http"
    assert server.url is None
    assert server.authenticated is True
    assert server.metadata["dynamic_mcp_endpoint_basis"] == "operator_configuration"
    assert (
        server.metadata["configuration_source"]
        == "FOUNDRY_TOOLBOX_MCP_SERVER_URL"
    )
    assert server.metadata["network_scope"] == "operator_configured_destination"
    assert server.metadata["provider"] == "microsoft-foundry"
    assert server.metadata["foundry_toolbox"] is True


def test_dotnet_maf_hosted_mcp_preserves_allowlist_and_approval(tmp_path: Path) -> None:
    write(
        tmp_path,
        r'''
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

var mcpTool = new HostedMcpServerTool(
    serverName: "microsoft_learn",
    serverAddress: "https://learn.microsoft.com/api/mcp")
{
    AllowedTools = ["microsoft_docs_search"],
    ApprovalMode = HostedMcpServerToolApprovalMode.NeverRequire,
};

AIAgent agent = chatClient.AsAIAgent(
    name: "DocsAgent",
    tools: [mcpTool]);
''',
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "DocsAgent")
    server = next(item for item in agent.mcp_servers if item.name == "microsoft_learn")

    assert server.transport == "hosted"
    assert server.url == "https://learn.microsoft.com/api/mcp"
    assert server.allowed_tools == ["microsoft_docs_search"]
    assert server.approval is False
    assert server.metadata["provider_managed"] is True
    assert not any(
        item.name == "microsoft_learn"
        for item in graph.unbound_mcp_servers
    )


def test_dotnet_maf_mcp_skills_are_effective_agent_authority(tmp_path: Path) -> None:
    write(
        tmp_path,
        r'''
using Microsoft.Agents.AI;
using ModelContextProtocol.Client;

await using McpClient mcpClient = await McpClient.CreateAsync(
    new StdioClientTransport(new()
    {
        Name = "skills-server",
        Command = "dotnet",
        Arguments = ["skills-server.dll"],
    }));

var skillsProvider = new AgentSkillsProviderBuilder()
    .UseMcpSkills(mcpClient)
    .Build();

AIAgent agent = chatClient.AsAIAgent(
    new ChatClientAgentOptions
    {
        Name = "SkillsAgent",
        AIContextProviders = [skillsProvider],
    });
''',
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "SkillsAgent")
    server = next(item for item in agent.mcp_servers if item.name == "skills-server")

    assert server.metadata["mcp_skills"] is True
    assert server.metadata["binding_origin"] == "UseMcpSkills"

    skills_tool = next(
        item
        for item in agent.tools
        if item.kind == "microsoft_dotnet_mcp_skills"
    )
    assert "data.read" in skills_tool.capabilities
    assert "process.execute" in skills_tool.capabilities
    assert skills_tool.approval is True


def test_dotnet_maf_chat_client_agent_options_tools(tmp_path: Path) -> None:
    write(
        tmp_path,
        r'''
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

static string ReadFile(string path) => File.ReadAllText(path);
AITool readFile = AIFunctionFactory.Create(ReadFile);

AIAgent agent = new ChatClientAgent(
    chatClient,
    new ChatClientAgentOptions
    {
        Name = "FilesAgent",
        ChatOptions = new()
        {
            Tools = [readFile],
        },
    });
''',
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "FilesAgent")
    tool = next(item for item in agent.tools if item.name == "ReadFile")

    assert agent.metadata["agent_type"] == "ChatClientAgent"
    assert "data.read" in tool.capabilities


def test_unrelated_csharp_does_not_create_agent_targets(tmp_path: Path) -> None:
    path = write(
        tmp_path,
        r'''
using System;

public static class Utility
{
    public static string Format(string value) => value.Trim();
}
''',
        name="Utility.cs",
    )

    assert is_microsoft_agent_framework_dotnet_file(path) is False
    graph = scan_dotnet_file(path)
    assert graph.agents == []
    assert graph.unbound_mcp_servers == []
