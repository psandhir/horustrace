from pathlib import Path

from horustrace.adapters.github_copilot_sdk import (
    is_github_copilot_sdk_file,
    scan_github_copilot_sdk_file,
)
from horustrace.scanner import scan


def write(tmp_path: Path, text: str, name: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_python_copilot_session_exposes_builtin_authority_and_approve_all(
    tmp_path: Path,
) -> None:
    path = write(
        tmp_path,
        '''
from copilot import CopilotClient
from copilot.session import PermissionHandler

async def main():
    client = CopilotClient()
    session = await client.create_session(
        on_permission_request=PermissionHandler.approve_all,
        working_directory="./repo",
        additional_directories=["../shared"],
    )
''',
        "agent.py",
    )

    assert is_github_copilot_sdk_file(path)
    graph = scan_github_copilot_sdk_file(path)
    agent = next(item for item in graph.agents if item.name == "session")

    assert agent.metadata["framework"] == "github-copilot-sdk"
    assert agent.metadata["runtime"] == "copilot-cli"

    builtins = next(
        tool for tool in agent.tools
        if tool.kind == "github_copilot_builtin_tools"
    )
    assert builtins.approval is False
    assert "process.execute" in builtins.capabilities
    assert "data.write" in builtins.capabilities
    assert "network.external" in builtins.capabilities
    assert "agent.delegate" in builtins.capabilities
    assert {resource.selector for resource in builtins.resources} == {
        "./repo",
        "../shared",
    }
    assert agent.identities[0].provider == "github"


def test_python_copilot_async_context_manager_session_is_detected(
    tmp_path: Path,
) -> None:
    path = write(
        tmp_path,
        '''
from copilot import CopilotClient
from copilot.session import PermissionHandler

async def main():
    async with CopilotClient() as client:
        async with await client.create_session(
            on_permission_request=PermissionHandler.approve_all,
            available_tools=["view"],
        ) as session:
            pass
''',
        "context_manager.py",
    )

    graph = scan_github_copilot_sdk_file(path)
    agent = next(item for item in graph.agents if item.name == "session")
    builtins = next(
        tool for tool in agent.tools
        if tool.kind == "github_copilot_builtin_tools"
    )

    assert builtins.approval is False
    assert builtins.capabilities == {"data.read"}


def test_python_copilot_available_tools_restrict_builtin_authority(
    tmp_path: Path,
) -> None:
    path = write(
        tmp_path,
        '''
from copilot import CopilotClient

async def main():
    client = CopilotClient()
    session = await client.create_session(
        available_tools=["builtin:view", "builtin:edit"],
        excluded_tools=["builtin:web_search"],
    )
''',
        "restricted.py",
    )

    graph = scan_github_copilot_sdk_file(path)
    agent = next(item for item in graph.agents if item.name == "session")
    builtins = next(
        tool for tool in agent.tools
        if tool.kind == "github_copilot_builtin_tools"
    )

    assert builtins.approval is True
    assert builtins.capabilities == {"data.read", "data.write"}
    assert "process.execute" not in agent.capabilities
    assert "network.external" not in agent.capabilities


def test_python_copilot_mcp_custom_tool_and_subagent_authority(
    tmp_path: Path,
) -> None:
    path = write(
        tmp_path,
        '''
import requests
from copilot import CopilotClient, define_tool
from copilot.session import PermissionHandler

@define_tool("publish_issue", description="Publish an issue")
async def publish_issue(params):
    return requests.post("https://issues.example.test/api", json=params).text

async def main():
    client = CopilotClient(github_token=get_token())
    session = await client.create_session(
        on_permission_request=PermissionHandler.approve_all,
        tools=[publish_issue],
        mcp_servers={
            "github": {
                "type": "http",
                "url": "https://api.githubcopilot.com/mcp/",
                "headers": {"Authorization": "Bearer token"},
                "tools": ["create_issue"],
            },
            "local": {
                "type": "local",
                "command": "python",
                "args": ["server.py"],
                "tools": ["*"],
            },
        },
        disabled_mcp_servers=["local"],
        custom_agents=[
            {
                "name": "editor",
                "tools": ["view", "edit", "publish_issue"],
                "prompt": "Make targeted changes",
            }
        ],
    )
''',
        "copilot_app.py",
    )

    graph, _ = scan(tmp_path)
    parent = next(item for item in graph.agents if item.name == "session")
    editor = next(item for item in graph.agents if item.name == "editor")

    assert len(parent.mcp_servers) == 1
    server = parent.mcp_servers[0]
    assert server.name == "github"
    assert server.transport == "streamable-http"
    assert server.url == "https://api.githubcopilot.com/mcp/"
    assert server.authenticated is True
    assert server.allowed_tools == ["create_issue"]

    publish = next(tool for tool in parent.tools if tool.name == "publish_issue")
    assert "network.external" in publish.capabilities
    assert "external.write" in publish.capabilities

    delegated = next(
        tool for tool in parent.tools
        if tool.kind == "delegated_agent" and tool.name == "editor"
    )
    assert "agent.delegate" in delegated.capabilities
    assert "data.write" in delegated.capabilities
    assert "network.external" in delegated.capabilities

    assert "data.read" in editor.capabilities
    assert "data.write" in editor.capabilities
    assert "process.execute" not in editor.capabilities
    assert parent.identities[0].credential_source == "github_token"


def test_python_copilot_maf_bridge_preserves_copilot_runtime_authority(
    tmp_path: Path,
) -> None:
    path = write(
        tmp_path,
        '''
from agent_framework.github import GitHubCopilotAgent

agent = GitHubCopilotAgent(
    default_options={"instructions": "You are a coding assistant."},
)
''',
        "maf_bridge.py",
    )

    graph = scan_github_copilot_sdk_file(path)
    agent = next(item for item in graph.agents if item.name == "agent")

    assert agent.metadata["maf_integration"] is True
    assert agent.metadata["runtime"] == "copilot-cli"
    assert "process.execute" in agent.capabilities
    builtins = next(
        tool for tool in agent.tools
        if tool.kind == "github_copilot_builtin_tools"
    )
    assert builtins.approval is True


def test_dotnet_copilot_session_mcp_and_custom_agent(
    tmp_path: Path,
) -> None:
    path = write(
        tmp_path,
        r'''
using GitHub.Copilot;

await using var client = new CopilotClient();
await using var session = await client.CreateSessionAsync(new SessionConfig
{
    WorkingDirectory = "./repo",
    AdditionalDirectories = ["../shared"],
    AvailableTools = ["view", "edit", "bash"],
    OnPermissionRequest = PermissionHandler.ApproveAll,
    McpServers = new Dictionary<string, McpServerConfig>
    {
        ["docs"] = new McpHttpServerConfig
        {
            Url = "https://learn.example.test/mcp",
            Headers = new Dictionary<string, string>
            {
                ["Authorization"] = "Bearer runtime-token",
            },
            Tools = ["search_docs"],
        },
        ["local"] = new McpStdioServerConfig
        {
            Command = "dotnet",
            Args = ["run", "--project", "Tools.csproj"],
            Tools = ["*"],
        },
    },
    DisabledMcpServers = ["local"],
    CustomAgents =
    [
        new()
        {
            Name = "reviewer",
            Tools = ["view", "edit"],
            Prompt = "Review and make focused edits.",
        },
    ],
});
''',
        "Program.cs",
    )

    graph = scan_github_copilot_sdk_file(path)
    parent = next(item for item in graph.agents if item.name == "session")
    reviewer = next(item for item in graph.agents if item.name == "reviewer")

    builtins = next(
        tool for tool in parent.tools
        if tool.kind == "github_copilot_builtin_tools"
    )
    assert builtins.approval is False
    assert "process.execute" in builtins.capabilities
    assert {resource.selector for resource in builtins.resources} == {
        "./repo",
        "../shared",
    }

    assert len(parent.mcp_servers) == 1
    assert parent.mcp_servers[0].name == "docs"
    assert parent.mcp_servers[0].authenticated is True
    assert parent.mcp_servers[0].allowed_tools == ["search_docs"]

    assert reviewer.capabilities == {"data.read", "data.write"}
    delegated = next(
        tool for tool in parent.tools
        if tool.kind == "delegated_agent" and tool.name == "reviewer"
    )
    assert {"agent.delegate", "data.read", "data.write"} <= delegated.capabilities


def test_dotnet_copilot_custom_tool_and_maf_bridge(
    tmp_path: Path,
) -> None:
    path = write(
        tmp_path,
        r'''
using System.Net.Http;
using GitHub.Copilot;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

static async Task<string> PublishIssue(string body)
{
    using var http = new HttpClient();
    var response = await http.PostAsync(
        "https://issues.example.test/api",
        new StringContent(body));
    return await response.Content.ReadAsStringAsync();
}

AIFunction publish = CopilotTool.DefineTool(
    PublishIssue,
    factoryOptions: new AIFunctionFactoryOptions
    {
        Name = "publish_issue",
    });

await using var copilotClient = new CopilotClient();

AIAgent agent = copilotClient.AsAIAgent(new AIAgentOptions
{
    Tools = [publish],
});
''',
        "Bridge.cs",
    )

    graph = scan_github_copilot_sdk_file(path)
    agent = next(item for item in graph.agents if item.name == "agent")
    tool = next(item for item in agent.tools if item.name == "publish_issue")

    assert agent.metadata["maf_integration"] is True
    assert "process.execute" in agent.capabilities
    assert "network.external" in tool.capabilities
    assert "external.write" in tool.capabilities


def test_copilot_adapter_ignores_unrelated_python_and_csharp(
    tmp_path: Path,
) -> None:
    py = write(
        tmp_path,
        "class CopilotClient:\n    pass\n",
        "unrelated.py",
    )
    cs = write(
        tmp_path,
        "public class CopilotClient { }\n",
        "Unrelated.cs",
    )

    assert not is_github_copilot_sdk_file(py)
    assert not is_github_copilot_sdk_file(cs)
    assert scan_github_copilot_sdk_file(py).agents == []
    assert scan_github_copilot_sdk_file(cs).agents == []
