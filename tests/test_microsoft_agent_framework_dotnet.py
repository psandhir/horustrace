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


def test_dotnet_maf_target_typed_chat_client_agent_is_inventory_target(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        r'''
using Microsoft.Agents.AI;

ChatClientAgent triageAgent = new(
    chatClient,
    instructions: "Route requests.",
    name: "triage_agent");

ChatClientAgent specialist = new(
    chatClient,
    instructions: "Handle specialist requests.",
    name: "specialist");
''',
    )

    graph, _ = scan(tmp_path)
    names = {item.name for item in graph.agents}

    assert {"triage_agent", "specialist"} <= names
    triage = next(item for item in graph.agents if item.name == "triage_agent")
    assert triage.metadata["agent_type"] == "ChatClientAgent"
    assert triage.metadata["target_typed_constructor"] is True


def test_dotnet_maf_hosting_add_ai_agent_binds_fluent_function_tools(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        r'''
using Microsoft.Agents.AI;
using Microsoft.Agents.AI.Hosting;
using Microsoft.Extensions.AI;

static string GetWeather(string city) => "sunny";
static string GetCurrentTime() => DateTime.UtcNow.ToString("O");

builder.AddAIAgent(
    "assistant",
    "You are helpful.")
    .WithAITools(
        AIFunctionFactory.Create(GetWeather, name: "get_weather"),
        AIFunctionFactory.Create(GetCurrentTime, name: "get_current_time"));

builder.AddAIAgent(
    name: "poet",
    instructions: "Write poetry.");
''',
    )

    graph, _ = scan(tmp_path)
    assistant = next(item for item in graph.agents if item.name == "assistant")
    poet = next(item for item in graph.agents if item.name == "poet")

    assert assistant.metadata["hosting_registration"] is True
    assert assistant.metadata["binding_origin"] == "AddAIAgent"
    assert {item.name for item in assistant.tools} == {
        "get_weather",
        "get_current_time",
    }
    assert poet.metadata["hosting_registration"] is True
    assert poet.tools == []


def test_dotnet_maf_hosting_add_ai_agent_binds_mcp_tool_collection(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        r'''
using Microsoft.Agents.AI;
using Microsoft.Agents.AI.Hosting;
using Microsoft.Extensions.AI;
using ModelContextProtocol.Client;

await using McpClient mcpClient = await McpClient.CreateAsync(
    new HttpClientTransport(new()
    {
        Endpoint = new Uri("https://learn.microsoft.com/api/mcp"),
        Name = "Microsoft Learn MCP",
    }));

var mcpTools = await mcpClient.ListToolsAsync();

builder.AddAIAgent(
    name: "tool-agent",
    instructions: "Use Microsoft documentation.",
    chatClient: chatClient)
    .WithAITools(mcpTools.Cast<AITool>().ToArray());
''',
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "tool-agent")
    server = next(
        item
        for item in agent.mcp_servers
        if item.name == "Microsoft Learn MCP"
    )

    assert server.url == "https://learn.microsoft.com/api/mcp"
    assert server.transport == "streamable-http"
    assert not any(
        item.name == "Microsoft Learn MCP"
        for item in graph.unbound_mcp_servers
    )


def test_dotnet_maf_inline_agent_skill_is_effective_authority(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        r'''
using Microsoft.Agents.AI;

var lookupSkill = new AgentInlineSkill(
    name: "lookup-skill",
    description: "Lookup data.",
    instructions: "Use the lookup resource and script.")
    .AddResource("lookup-table", "table")
    .AddScript("fetch", (string url) =>
    {
        using var client = new HttpClient();
        return client.GetStringAsync(url).Result;
    });

var skillsProvider = new AgentSkillsProvider(lookupSkill);

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
    skill = next(
        item
        for item in agent.tools
        if item.kind == "microsoft_dotnet_agent_skill"
    )

    assert skill.name == "lookup-skill"
    assert skill.metadata["skill_source"] == "inline"
    assert skill.metadata["resources"] == ["lookup-table"]
    assert skill.metadata["scripts"] == ["fetch"]
    assert "data.read" in skill.capabilities
    assert "network.external" in skill.capabilities


def test_dotnet_maf_class_agent_skill_is_effective_authority(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        r'''
using Microsoft.Agents.AI;

var converter = new UnitConverterSkill();
var skillsProvider = new AgentSkillsProvider(converter);

AIAgent agent = chatClient.AsAIAgent(
    new ChatClientAgentOptions
    {
        Name = "ConverterAgent",
        AIContextProviders = [skillsProvider],
    });

internal sealed class UnitConverterSkill : AgentClassSkill<UnitConverterSkill>
{
    public override AgentSkillFrontmatter Frontmatter { get; } = new(
        "unit-converter",
        "Convert units.");

    [AgentSkillResource("conversion-table")]
    public string Table => "table";

    [AgentSkillScript("convert")]
    private static string Convert(double value) => value.ToString();
}
''',
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "ConverterAgent")
    skill = next(
        item
        for item in agent.tools
        if item.kind == "microsoft_dotnet_agent_skill"
    )

    assert skill.name == "unit-converter"
    assert skill.metadata["skill_source"] == "class"
    assert skill.metadata["class_name"] == "UnitConverterSkill"
    assert skill.metadata["resources"] == ["conversion-table"]
    assert skill.metadata["scripts"] == ["convert"]
    assert "data.read" in skill.capabilities


def test_dotnet_maf_file_skills_with_subprocess_runner_are_effective_authority(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        r'''
using Microsoft.Agents.AI;

var skillsBuilder = new AgentSkillsProviderBuilder()
    .UseFileSkills(
        [skillsDir],
        scriptRunner: new SubprocessScriptRunner().RunAsync);

var skillsProvider = skillsBuilder.Build();

AIAgent agent = chatClient.AsAIAgent(
    new ChatClientAgentOptions
    {
        Name = "FileSkillsAgent",
        AIContextProviders = [skillsProvider],
    });
''',
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "FileSkillsAgent")
    skill = next(
        item
        for item in agent.tools
        if item.kind == "microsoft_dotnet_agent_skill"
    )

    assert skill.metadata["skill_source"] == "file"
    assert skill.metadata["script_runner"] == "subprocess"
    assert skill.metadata["dynamic_tool_catalogue"] is True
    assert skill.approval is True
    assert "data.read" in skill.capabilities
    assert "process.execute" in skill.capabilities


def test_dotnet_maf_hosted_code_interpreter_is_effective_authority(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        r'''
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

AIAgent agent = chatClient.AsAIAgent(
    name: "Coder",
    tools: [new HostedCodeInterpreterTool() { Inputs = [] }]);
''',
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "Coder")
    tool = next(
        item
        for item in agent.tools
        if item.metadata.get("provider_tool_type") == "HostedCodeInterpreterTool"
    )

    assert tool.kind == "provider_tool"
    assert tool.metadata["provider_managed"] is True
    assert "process.execute" in tool.capabilities
    assert "data.read" in tool.capabilities
    assert "data.write" in tool.capabilities


def test_dotnet_maf_hosted_web_and_file_search_preserve_read_authority(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        r'''
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

AIAgent agent = chatClient.AsAIAgent(
    name: "Researcher",
    tools: [
        new HostedWebSearchTool(),
        new HostedFileSearchTool(),
    ]);
''',
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "Researcher")
    tools = {
        item.metadata.get("provider_tool_type"): item
        for item in agent.tools
        if item.kind == "provider_tool"
    }

    assert tools["HostedWebSearchTool"].capabilities == {
        "data.read",
        "network.external",
    }
    assert tools["HostedFileSearchTool"].capabilities == {"data.read"}


def test_dotnet_maf_foundry_openapi_tool_uses_source_visible_http_effects(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        r'''
using Microsoft.Agents.AI;
using Microsoft.Agents.AI.Foundry;

AITool openApiTool =
    FoundryAITool.CreateOpenApiTool(CreateOpenAPIFunctionDefinition());

AIAgent agent = chatClient.AsAIAgent(
    name: "ApiAgent",
    tools: [openApiTool]);

OpenApiFunctionDefinition CreateOpenAPIFunctionDefinition()
{
    const string Spec = """
    {
      "servers": [{"url": "https://api.example.test/v1"}],
      "paths": {
        "/records": {
          "get": {},
          "post": {}
        }
      }
    }
    """;
    return BuildDefinition(Spec);
}
''',
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "ApiAgent")
    tool = next(
        item
        for item in agent.tools
        if item.metadata.get("provider_tool_type") == "CreateOpenApiTool"
    )

    assert "network.external" in tool.capabilities
    assert "data.read" in tool.capabilities
    assert "data.write" in tool.capabilities
    assert "external.write" in tool.capabilities
    assert tool.metadata["http_effect_basis"] == "source_visible_openapi_schema"
    assert any(
        destination.target == "https://api.example.test/v1"
        for destination in tool.destinations
    )


def test_dotnet_maf_foundry_data_tools_are_bound_from_variables(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        r'''
using Microsoft.Agents.AI;
using Microsoft.Agents.AI.Foundry;

AITool sharepoint = FoundryAITool.CreateSharepointTool(sharepointOptions);
AITool fabric = FoundryAITool.CreateMicrosoftFabricTool(fabricOptions);

AIAgent agent = chatClient.AsAIAgent(
    name: "EnterpriseDataAgent",
    tools: [sharepoint, fabric]);
''',
    )

    graph, _ = scan(tmp_path)
    agent = next(
        item for item in graph.agents if item.name == "EnterpriseDataAgent"
    )
    types = {
        item.metadata.get("provider_tool_type"): item
        for item in agent.tools
        if item.kind == "provider_tool"
    }

    assert types["CreateSharepointTool"].capabilities == {
        "data.read",
        "network.external",
    }
    assert types["CreateMicrosoftFabricTool"].capabilities == {
        "data.read",
        "network.external",
    }


def test_dotnet_maf_codeact_provider_is_effective_only_when_attached(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        r'''
using Microsoft.Agents.AI;
using Microsoft.Agents.AI.LocalCodeAct;

var attachedCodeAct = new LocalCodeActProvider(pythonExecutable, options);
var unusedCodeAct = new LocalCodeActProvider(otherPython, otherOptions);

AIAgent agent = chatClient.AsAIAgent(
    new ChatClientAgentOptions
    {
        Name = "CodeActAgent",
        AIContextProviders = [attachedCodeAct],
    });
''',
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "CodeActAgent")
    codeact = [
        item
        for item in agent.tools
        if item.kind == "microsoft_dotnet_codeact"
    ]

    assert len(codeact) == 1
    assert codeact[0].name == "attachedCodeAct"
    assert codeact[0].metadata["binding_origin"] == "LocalCodeActProvider"
    assert codeact[0].metadata["sandbox"] == "host-process"
    assert codeact[0].capabilities == {"process.execute"}


def test_dotnet_maf_handoff_workflow_as_agent_projects_participant_authority(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        r'''
using System.Diagnostics;
using Microsoft.Agents.AI;
using Microsoft.Agents.AI.Workflows;
using Microsoft.Extensions.AI;

static string RunCommand(string command)
{
    Process.Start(new ProcessStartInfo("cmd.exe", command));
    return "ok";
}

AIAgent triageAgent = chatClient.AsAIAgent(name: "triage");
AIAgent opsAgent = chatClient.AsAIAgent(
    name: "ops",
    tools: [AIFunctionFactory.Create(RunCommand)]);

Workflow workflow = AgentWorkflowBuilder
    .CreateHandoffBuilderWith(triageAgent)
    .WithHandoffs(triageAgent, [opsAgent])
    .WithHandoffs(opsAgent, triageAgent)
    .Build();

AIAgent supportAgent = workflow.AsAIAgent(name: "support-workflow");
''',
    )

    graph, _ = scan(tmp_path)
    workflow_agent = next(
        item for item in graph.agents if item.name == "support-workflow"
    )

    assert workflow_agent.metadata["workflow_kind"] == "handoff"
    delegated = {
        item.name: item
        for item in workflow_agent.tools
        if item.kind == "delegated_agent"
    }
    assert {"triage", "ops"} <= delegated.keys()
    assert "process.execute" in delegated["ops"].capabilities
    assert delegated["ops"].metadata["authority_binding_basis"] == (
        "microsoft_dotnet_workflow_projection"
    )
    assert "process.execute" in workflow_agent.capabilities


def test_dotnet_maf_hosted_addworkflow_as_agent_projects_participants(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        r'''
using Microsoft.Agents.AI;
using Microsoft.Agents.AI.Hosting;
using Microsoft.Agents.AI.Workflows;

var writerBuilder = builder.AddAIAgent(
    "writer",
    "Write a draft.");

var reviewerBuilder = builder.AddAIAgent(
    "reviewer",
    "Review the draft.");

builder.AddWorkflow("review-workflow", (sp, key) =>
{
    var agents = new List<IHostedAgentBuilder>()
    {
        writerBuilder,
        reviewerBuilder,
    }.Select(ab => sp.GetRequiredKeyedService<AIAgent>(ab.Name));

    return AgentWorkflowBuilder.BuildSequential(
        workflowName: key,
        agents: agents);
}).AddAsAIAgent();
''',
    )

    graph, _ = scan(tmp_path)
    workflow_agent = next(
        item for item in graph.agents if item.name == "review-workflow"
    )

    assert workflow_agent.metadata["agent_type"] == "WorkflowAgent"
    assert workflow_agent.metadata["workflow_kind"] == "sequential"
    delegated = {
        item.name
        for item in workflow_agent.tools
        if item.kind == "delegated_agent"
    }
    assert delegated == {"writer", "reviewer"}


def test_dotnet_maf_per_run_tools_extend_effective_authority(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        r'''
using System.IO;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

static string DeleteFile(string path)
{
    File.Delete(path);
    return "deleted";
}

AIAgent agent = chatClient.AsAIAgent(name: "RuntimeAgent");

var options = new ChatClientAgentRunOptions(new()
{
    Tools =
    [
        new ApprovalRequiredAIFunction(
            AIFunctionFactory.Create(DeleteFile))
    ]
});

await agent.RunAsync("Delete the temporary file.", null, options);
''',
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "RuntimeAgent")
    tool = next(item for item in agent.tools if item.name == "DeleteFile")

    assert tool.approval is True
    assert {"data.write", "destructive.write"} <= tool.capabilities
    assert tool.metadata["runtime_scope"] == "per_run"
    assert tool.metadata["conditional_authority"] is True
    assert tool.metadata["binding_origin"] == "ChatClientAgentRunOptions"


def test_dotnet_maf_dynamic_tool_catalogue_is_projected_conditionally(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        r'''
using System.IO;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

static string DeleteFile(string path)
{
    File.Delete(path);
    return "deleted";
}

Dictionary<string, List<AITool>> toolCatalog = new()
{
    ["delete"] =
    [
        AIFunctionFactory.Create(DeleteFile, name: "delete_file")
    ],
};

AIFunction requestToolsFunction = AIFunctionFactory.Create(
    (string description) =>
    {
        var context = FunctionInvokingChatClient.CurrentContext
            ?? throw new InvalidOperationException();

        var tools = context.Options?.Tools;
        foreach (var kvp in toolCatalog)
        {
            foreach (var tool in kvp.Value)
            {
                tools!.Add(tool);
            }
        }
        return "loaded";
    },
    name: "RequestTools");

AIAgent agent = chatClient.AsAIAgent(
    name: "DynamicAgent",
    tools: [requestToolsFunction]);
''',
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "DynamicAgent")

    loader = next(
        item
        for item in agent.tools
        if item.kind == "microsoft_dotnet_dynamic_tool_loader"
    )
    dynamic = next(item for item in agent.tools if item.name == "delete_file")

    assert loader.metadata["dynamic_tool_catalogue"] is True
    assert loader.metadata["catalogue_tools"] == ["delete_file"]
    assert "destructive.write" in loader.capabilities
    assert dynamic.metadata["runtime_scope"] == "dynamic_catalogue"
    assert dynamic.metadata["conditional_authority"] is True
    assert "destructive.write" in dynamic.capabilities


def test_dotnet_maf_harness_defaults_are_explicit_effective_authority(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        r'''
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

AIAgent agent = chatClient.AsHarnessAgent(new HarnessAgentOptions
{
    Name = "DefaultHarness",
});
''',
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "DefaultHarness")

    assert agent.metadata["agent_type"] == "HarnessAgent"
    kinds = {item.kind: item for item in agent.tools}

    web = next(
        item
        for item in agent.tools
        if item.metadata.get("provider_tool_type") == "HostedWebSearchTool"
    )
    assert web.metadata["framework_default"] is True
    assert web.capabilities == {"data.read", "network.external"}

    memory = kinds["microsoft_dotnet_harness_file_memory"]
    assert memory.approval is False
    assert memory.capabilities == {"data.read", "data.write"}
    assert memory.resources[0].selector == "<harness-default-file-memory>"

    skills = next(
        item
        for item in agent.tools
        if item.kind == "microsoft_dotnet_agent_skill"
        and item.metadata.get("binding_origin")
        == "HarnessAgent.AgentSkillsProvider"
    )
    assert skills.approval is True
    assert skills.metadata["dynamic_tool_catalogue"] is True
    assert skills.metadata["skill_source"] == "cwd"


def test_dotnet_maf_harness_file_access_preserves_approval_boundary(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        r'''
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

AIAgent agent = chatClient.AsHarnessAgent(new HarnessAgentOptions
{
    Name = "DataAgent",
    DisableWebSearch = true,
    DisableFileMemory = true,
    DisableAgentSkillsProvider = true,
    FileAccessStore = new FileSystemAgentFileStore("working"),
    ToolApprovalAgentOptions = new ToolApprovalAgentOptions
    {
        AutoApprovalRules =
        [
            FileAccessProvider.ReadOnlyToolsAutoApprovalRule
        ],
    },
});
''',
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "DataAgent")
    tools = {
        item.metadata.get("access_mode"): item
        for item in agent.tools
        if item.kind == "microsoft_dotnet_harness_file_access"
    }

    read = tools["read"]
    write_tool = tools["write"]

    assert read.approval is False
    assert read.metadata["auto_approved"] is True
    assert read.capabilities == {"data.read"}

    assert write_tool.approval is True
    assert write_tool.metadata["auto_approved"] is False
    assert {"data.write", "destructive.write"} <= write_tool.capabilities
    assert write_tool.resources[0].selector == "working"


def test_dotnet_maf_harness_background_agents_project_child_authority(
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

AIAgent worker = chatClient.AsAIAgent(
    name: "Worker",
    tools: [AIFunctionFactory.Create(RunCommand)]);

AIAgent parent = chatClient.AsHarnessAgent(new HarnessAgentOptions
{
    Name = "ParentHarness",
    DisableWebSearch = true,
    DisableFileMemory = true,
    DisableAgentSkillsProvider = true,
    BackgroundAgents = [worker],
});
''',
    )

    graph, _ = scan(tmp_path)
    parent = next(item for item in graph.agents if item.name == "ParentHarness")
    delegated = next(
        item
        for item in parent.tools
        if item.kind == "delegated_agent" and item.name == "Worker"
    )

    assert delegated.metadata["background_execution"] is True
    assert delegated.metadata["authority_binding_basis"] == (
        "microsoft_dotnet_harness_background_agent"
    )
    assert "process.execute" in delegated.capabilities
    assert "process.execute" in parent.capabilities


def test_dotnet_maf_harness_can_disable_default_authority_surfaces(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        r'''
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

AIAgent agent = chatClient.AsHarnessAgent(new HarnessAgentOptions
{
    Name = "LeanHarness",
    DisableWebSearch = true,
    DisableFileMemory = true,
    DisableAgentSkillsProvider = true,
});
''',
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "LeanHarness")

    assert not any(
        item.metadata.get("provider_tool_type") == "HostedWebSearchTool"
        for item in agent.tools
    )
    assert not any(
        item.kind == "microsoft_dotnet_harness_file_memory"
        for item in agent.tools
    )
    assert not any(
        item.metadata.get("binding_origin")
        == "HarnessAgent.AgentSkillsProvider"
        for item in agent.tools
    )



def test_dotnet_maf_durable_agent_factories_are_inventory_and_authority(
    tmp_path: Path,
) -> None:
    source = write(
        tmp_path,
        r"""
using Azure.AI.OpenAI;
using Azure.Identity;
using Microsoft.Agents.AI;
using Microsoft.Agents.AI.DurableTask;
using Microsoft.Agents.AI.Hosting.AzureFunctions;
using Microsoft.Extensions.AI;

builder.ConfigureDurableAgents(configure =>
{
    configure.AddAIAgentFactory("DestinationRecommenderAgent", sp =>
    {
        var chatClient = new AzureOpenAIClient(endpoint, credential)
            .GetChatClient(deploymentName);

        return chatClient.CreateAIAgent(
            name: "DestinationRecommenderAgent",
            instructions: "Recommend destinations.",
            services: sp);
    });

    configure.AddAIAgentFactory("ItineraryPlannerAgent", sp =>
    {
        var chatClient = new AzureOpenAIClient(endpoint, credential)
            .GetChatClient(deploymentName);

        return chatClient.CreateAIAgent(
            name: "ItineraryPlannerAgent",
            instructions: "Plan itineraries.",
            services: sp,
            tools: [
                AIFunctionFactory.Create(ConvertCurrency),
                AIFunctionFactory.Create(GetExchangeRate)
            ]);
    });
});

static string ConvertCurrency(string value) => value;
static string GetExchangeRate(string value) => value;
""",
    )

    assert is_microsoft_agent_framework_dotnet_file(source)
    graph, _ = scan(tmp_path)

    durable = {
        item.name: item
        for item in graph.agents
        if item.metadata.get("durable_registration") is True
    }
    assert set(durable) == {
        "DestinationRecommenderAgent",
        "ItineraryPlannerAgent",
    }
    assert all(
        item.metadata["agent_type"] == "DurableAIAgent"
        for item in durable.values()
    )
    assert all(
        item.metadata["binding_origin"] == "AddAIAgentFactory"
        for item in durable.values()
    )

    destination = durable["DestinationRecommenderAgent"]
    assert destination.tools == []

    itinerary = durable["ItineraryPlannerAgent"]
    assert {item.name for item in itinerary.tools} == {
        "ConvertCurrency",
        "GetExchangeRate",
    }
    assert {
        item.name
        for item in graph.agents
        if item.metadata.get("framework") == "microsoft-agent-framework-dotnet"
    } == {
        "DestinationRecommenderAgent",
        "ItineraryPlannerAgent",
    }


def test_dotnet_maf_direct_create_ai_agent_assignment_is_detected(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        r"""
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

AIAgent agent = chatClient.CreateAIAgent(
    name: "FactoryAgent",
    tools: [AIFunctionFactory.Create(GetWeather)]);

static string GetWeather(string city) => "sunny";
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "FactoryAgent")

    assert agent.metadata["framework"] == "microsoft-agent-framework-dotnet"
    assert {item.name for item in agent.tools} == {"GetWeather"}



def test_dotnet_maf_cross_file_function_authority_is_resolved(
    tmp_path: Path,
) -> None:
    program = write(
        tmp_path,
        r"""
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using TravelPlannerFunctions.Tools;

AIAgent agent = chatClient.CreateAIAgent(
    name: "ItineraryPlannerAgent",
    tools: [
        AIFunctionFactory.Create(CurrencyConverterTool.ConvertCurrency),
        AIFunctionFactory.Create(CurrencyConverterTool.GetExchangeRate)
    ]);
""",
    )

    tools_dir = tmp_path / "Tools"
    tools_dir.mkdir()
    (tools_dir / "CurrencyConverterTool.cs").write_text(
        r"""
using System.Net.Http;

namespace TravelPlannerFunctions.Tools;

public class CurrencyConverterTool
{
    private static readonly HttpClient Client = new()
    {
        BaseAddress = new Uri("https://open.er-api.com/v6/")
    };

    public static async Task<string> ConvertCurrency(
        decimal amount,
        string fromCurrency,
        string toCurrency)
    {
        // Documentation only: https://comment-only.example/v1/
        if (amount < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(amount));
        }

        var response = await Client.GetAsync(
            $"latest/{fromCurrency.ToUpper()}");
        return await response.Content.ReadAsStringAsync();
    }

    public static async Task<decimal> GetExchangeRate(
        string fromCurrency,
        string toCurrency)
    {
        await ConvertCurrency(1, fromCurrency, toCurrency);
        return 1m;
    }
}
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(
        item
        for item in graph.agents
        if item.name == "ItineraryPlannerAgent"
    )
    tools = {item.name: item for item in agent.tools}

    for name in ("ConvertCurrency", "GetExchangeRate"):
        tool = tools[name]
        assert tool.location is not None
        assert tool.location.path == program
        assert {"data.read", "network.external"} <= tool.capabilities
        assert tool.metadata["repository_effect_resolved"] is True
        assert tool.metadata["repository_effect_resolution"] == "resolved"
        assert tool.metadata["repository_effect_partial"] is False
        assert tool.metadata["repository_effect_unresolved_calls"] == []
        assert tool.metadata["method_source_resolved"] is True
        assert tool.metadata["repository_effect_sources"] == [
            "Tools/CurrencyConverterTool.cs"
        ]
        assert not any(
            evidence.endswith(":if")
            for evidence in tool.metadata["repository_effect_evidence"]
        )
        assert all(
            not evidence.startswith("/")
            for evidence in tool.metadata["repository_effect_evidence"]
        )

        network_evidence = tool.metadata[
            "repository_effect_capability_evidence"
        ]["network.external"]
        assert network_evidence
        assert all(
            item["path"] == "Tools/CurrencyConverterTool.cs"
            and item["kind"] == "csharp_effect"
            and item["line"] > 1
            for item in network_evidence
        )

        network_facts = [
            fact
            for fact in tool.provenance
            if fact.fact == "capability=network.external"
            and fact.origin == "observed"
        ]
        assert network_facts
        assert all(
            fact.location is not None
            and fact.location.path.name == "CurrencyConverterTool.cs"
            and fact.location.line > 1
            for fact in network_facts
        )

        destination = next(
            item
            for item in tool.destinations
            if item.target == "https://open.er-api.com/v6/"
        )
        assert destination.location is not None
        assert destination.location.path.name == "CurrencyConverterTool.cs"
        assert destination.location.line > 1
        assert destination.metadata["source"] == "csharp_class_base_address"
        assert any(
            fact.fact == "destination=https://open.er-api.com/v6/"
            and fact.origin == "observed"
            and fact.location == destination.location
            for fact in destination.provenance
        )
        assert all(
            item.target != "https://comment-only.example/v1/"
            for item in tool.destinations
        )


def test_dotnet_maf_cross_file_unqualified_method_is_not_guessed_when_ambiguous(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        r"""
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

AIAgent agent = chatClient.CreateAIAgent(
    name: "AmbiguousAgent",
    tools: [AIFunctionFactory.Create(Search)]);
""",
    )

    (tmp_path / "First.cs").write_text(
        r"""
public class First
{
    public static async Task<string> Search(string value)
    {
        using var client = new HttpClient();
        return await client.GetStringAsync("https://one.example/");
    }
}
""",
        encoding="utf-8",
    )
    (tmp_path / "Second.cs").write_text(
        r"""
public class Second
{
    public static async Task<string> Search(string value)
    {
        using var client = new HttpClient();
        return await client.GetStringAsync("https://two.example/");
    }
}
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(
        item for item in graph.agents
        if item.name == "AmbiguousAgent"
    )
    tool = next(item for item in agent.tools if item.name == "Search")

    assert tool.metadata["method_source_resolved"] is False
    assert tool.metadata["repository_effect_resolved"] is False
    assert (
        tool.metadata["repository_effect_resolution"]
        == "ambiguous_method_reference"
    )
    assert tool.destinations == []



def test_dotnet_maf_qualified_overload_is_not_unioned(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        r"""
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

AIAgent agent = chatClient.CreateAIAgent(
    name: "OverloadAgent",
    tools: [AIFunctionFactory.Create(OverloadedTool.Send)]);
""",
    )

    (tmp_path / "OverloadedTool.cs").write_text(
        r"""
public class OverloadedTool
{
    public static async Task<string> Send(string value)
    {
        using var client = new HttpClient();
        return await client.GetStringAsync("https://one.example/");
    }

    public static string Send(int value)
    {
        File.WriteAllText("output.txt", value.ToString());
        return value.ToString();
    }
}
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(
        item for item in graph.agents
        if item.name == "OverloadAgent"
    )
    tool = next(item for item in agent.tools if item.name == "Send")

    assert tool.metadata["repository_effect_resolved"] is False
    assert tool.metadata["repository_effect_resolution"] == "ambiguous_overload"
    assert tool.destinations == []
    assert "network.external" not in tool.capabilities
    assert "data.write" not in tool.capabilities


def test_dotnet_maf_transitive_overload_marks_partial_resolution(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        r"""
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

AIAgent agent = chatClient.CreateAIAgent(
    name: "PartialAgent",
    tools: [AIFunctionFactory.Create(OverloadedTool.Entry)]);
""",
    )

    (tmp_path / "OverloadedTool.cs").write_text(
        r"""
public class OverloadedTool
{
    public static string Entry(string value)
    {
        return Send(value);
    }

    public static async Task<string> Send(string value)
    {
        using var client = new HttpClient();
        return await client.GetStringAsync("https://one.example/");
    }

    public static string Send(int value)
    {
        File.WriteAllText("output.txt", value.ToString());
        return value.ToString();
    }
}
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(
        item for item in graph.agents
        if item.name == "PartialAgent"
    )
    tool = next(item for item in agent.tools if item.name == "Entry")

    assert tool.metadata["method_source_resolved"] is True
    assert tool.metadata["repository_effect_resolved"] is False
    assert tool.metadata["repository_effect_resolution"] == "partial"
    assert tool.metadata["repository_effect_partial"] is True
    assert tool.metadata["repository_effect_unresolved_calls"] == ["Send"]
    assert tool.destinations == []
    assert "network.external" not in tool.capabilities
    assert "data.write" not in tool.capabilities


def test_dotnet_maf_comment_only_effects_are_not_authority(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        r"""
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

AIAgent agent = chatClient.CreateAIAgent(
    name: "CommentAgent",
    tools: [AIFunctionFactory.Create(CommentOnlyTool.Noop)]);
""",
    )

    (tmp_path / "CommentOnlyTool.cs").write_text(
        r"""
public class CommentOnlyTool
{
    // BaseAddress = new Uri("https://comment-base.example/")
    public static string Noop(string value)
    {
        // HttpClient.GetAsync("https://comment-call.example/");
        return value;
    }
}
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(
        item for item in graph.agents
        if item.name == "CommentAgent"
    )
    tool = next(item for item in agent.tools if item.name == "Noop")

    assert tool.metadata["method_source_resolved"] is True
    assert tool.metadata["repository_effect_resolved"] is True
    assert tool.metadata["repository_effect_resolution"] == "resolved"
    assert tool.metadata["repository_effect_capabilities"] == []
    assert tool.destinations == []
    assert not any(
        fact.fact.startswith("capability=")
        for fact in tool.provenance
    )


def test_dotnet_maf_fluent_workflow_builder_preserves_topology(tmp_path: Path) -> None:
    write(
        tmp_path,
        r"""
using Microsoft.Agents.AI;
using Microsoft.Agents.AI.Workflows;

AIAgent salesagent = chatClient.AsAIAgent(name: "Sales");
AIAgent priceagent = chatClient.AsAIAgent(name: "Price");
AIAgent quoteagent = chatClient.AsAIAgent(name: "Quote");

var workflow = new WorkflowBuilder(salesagent)
    .AddEdge(salesagent, priceagent)
    .AddEdge(priceagent, quoteagent)
    .Build();

StreamingRun run = await InProcessExecution.RunStreamingAsync(workflow, userMessage);
""",
    )

    graph, _ = scan(tmp_path)
    workflow = next(item for item in graph.agents if item.name == "workflow")
    assert workflow.metadata["agent_type"] == "Workflow"
    assert workflow.metadata["workflow_kind"] == "sequential"
    assert workflow.metadata["workflow_edges"] == [
        {"source": "salesagent", "target": "priceagent"},
        {"source": "priceagent", "target": "quoteagent"},
    ]
    delegated = [tool for tool in workflow.tools if tool.kind == "delegated_agent"]
    assert {tool.metadata["delegate_target"] for tool in delegated} == {
        "salesagent",
        "priceagent",
        "quoteagent",
    }


def test_dotnet_maf_block_factory_return_is_inventory_target(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        r"""
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

private AIAgent CreateAIAgent()
{
    var chatClient = client.GetChatClient("gpt-4o-mini");

    return chatClient.AsAIAgent(new ChatClientAgentOptions
    {
        Name = "MemoryAgent",
    });
}
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "MemoryAgent")

    assert agent.metadata["framework"] == "microsoft-agent-framework-dotnet"
    assert "CreateAIAgent" in agent.metadata["source_aliases"]


def test_dotnet_maf_fluent_factory_return_preserves_agent_and_tools(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        r"""
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

static string GetWeather(string city) => "sunny";

public static AIAgent CreateAIAgent()
{
    return chatClient
        .CreateAIAgent(
            name: "WebApiAgent",
            tools: [AIFunctionFactory.Create(GetWeather)])
        .AsBuilder()
        .Use(Middleware.FunctionCallMiddleware)
        .Build();
}
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "WebApiAgent")

    assert "CreateAIAgent" in agent.metadata["source_aliases"]
    assert {item.name for item in agent.tools} == {"GetWeather"}


def test_dotnet_maf_expression_bodied_factory_is_inventory_target(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        r"""
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

static string GetWeather(string city) => "sunny";

private static AIAgent CreateAIAgent(IChatClient chatClient) =>
    chatClient.AsAIAgent(
        name: "GovernedAgent",
        tools: [AIFunctionFactory.Create(GetWeather, name: "GetWeather")])
    .WithGovernance(kernel);
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "GovernedAgent")

    assert "CreateAIAgent" in agent.metadata["source_aliases"]
    assert {item.name for item in agent.tools} == {"GetWeather"}


def test_dotnet_maf_dynamic_agent_name_does_not_capture_nested_tool_name(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        r"""
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

static string GetWeather(string city) => "sunny";

AIAgent agent = chatClient.AsAIAgent(
    name: identity.Name,
    instructions: "Help.",
    tools: [
        AIFunctionFactory.Create(GetWeather, name: "GetWeather")
    ]);
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(
        item
        for item in graph.agents
        if item.metadata.get("framework") == "microsoft-agent-framework-dotnet"
    )

    assert agent.name == "agent"
    assert {tool.name for tool in agent.tools} == {"GetWeather"}


def test_dotnet_maf_factory_dynamic_name_does_not_capture_nested_tool_name(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        r"""
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

private static AIAgent CreateAIAgent(
    IChatClient chatClient,
    AgentIdentity identity) =>
    chatClient.AsAIAgent(
        name: identity.Name,
        tools: [
            AIFunctionFactory.Create(GetWeather, name: "GetWeather"),
            AIFunctionFactory.Create(GetTime, name: "GetTime")
        ]);

static string GetWeather(string city) => "sunny";
static string GetTime(string timezone) => "now";
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(
        item
        for item in graph.agents
        if item.metadata.get("framework") == "microsoft-agent-framework-dotnet"
    )

    assert agent.name == "CreateAIAgent"
    assert {tool.name for tool in agent.tools} == {"GetWeather", "GetTime"}


def test_dotnet_maf_chat_client_options_name_remains_supported(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        r"""
using Microsoft.Agents.AI;

AIAgent agent = chatClient.AsAIAgent(
    new ChatClientAgentOptions
    {
        Name = "OptionsAgent",
        ChatOptions = new()
        {
            Tools = [],
        },
    });
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(
        item
        for item in graph.agents
        if item.metadata.get("framework") == "microsoft-agent-framework-dotnet"
    )
    assert agent.name == "OptionsAgent"
