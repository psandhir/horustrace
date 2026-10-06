from pathlib import Path

from horustrace.scanner import scan


def test_lambda_handler_taint_crosses_helper_into_callable_strands_agent(
    tmp_path: Path,
) -> None:
    (tmp_path / "handler.py").write_text(
        """
import subprocess

from strands import Agent, tool


@tool
def run_command(command: str):
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout


def call_agent(endpoint, query):
    agent = Agent(tools=[run_command])
    return agent(query)


def lambda_handler(event, context):
    endpoint = event.get("endpoint")
    query = event.get("query")
    return call_agent(endpoint, query)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    agent = next(
        item
        for item in graph.agents
        if item.metadata.get("framework") == "strands-agents"
        and item.name == "agent"
    )
    ingress = next(
        item
        for item in agent.inputs
        if item.metadata.get("basis") == "source_bound_runtime_ingress"
    )
    assert ingress.kind == "external"
    assert ingress.metadata["ingress_framework"] == "aws_lambda"
    assert ingress.metadata["runtime_invocation_proven"] is True

    path = next(
        item
        for item in graph.attack_paths
        if item.path_id == "PATH001"
        and item.agent == agent.name
        and item.nodes[-2:] == ["run_command", "process.execute"]
    )
    assert path.metadata["basis"] == "source_bound_ingress_authority"
    assert path.metadata["ingress_basis"] == "source_bound_runtime_ingress"
    assert path.metadata["target_kind"] == "tool"


def test_lambda_handler_constant_helper_payload_is_not_runtime_ingress(
    tmp_path: Path,
) -> None:
    (tmp_path / "handler.py").write_text(
        """
import subprocess

from strands import Agent, tool


@tool
def run_command(command: str):
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout


def call_agent(query):
    agent = Agent(tools=[run_command])
    return agent(query)


def lambda_handler(event, context):
    event.get("query")
    return call_agent("fixed-health-check")
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(
        item
        for item in graph.agents
        if item.metadata.get("framework") == "strands-agents"
        and item.name == "agent"
    )

    assert not any(
        item.metadata.get("basis") == "source_bound_runtime_ingress"
        for item in agent.inputs
    )
    assert not any(
        item.path_id == "PATH001" and item.agent == agent.name
        for item in graph.attack_paths
    )


def test_cli_arg_crosses_helper_into_claude_query_runtime(
    tmp_path: Path,
) -> None:
    (tmp_path / "scheduler.py").write_text(
        """
import argparse
import anyio

from claude_agent_sdk import ClaudeAgentOptions, query


async def run_scheduled_agent(custom_prompt: str | None = None):
    prompt = f"Operator request: {custom_prompt}"
    options = ClaudeAgentOptions(
        allowed_tools=["Bash"],
        permission_mode="bypassPermissions",
    )
    async for message in query(prompt=prompt, options=options):
        return message


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--prompt")
    args = parser.parse_args()

    async def _run():
        return await run_scheduled_agent(custom_prompt=args.prompt)

    anyio.run(_run)


if __name__ == "__main__":
    main()
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    agent = next(
        item
        for item in graph.agents
        if item.metadata.get("framework") == "claude-agent-sdk"
        and item.metadata.get("sdk_entrypoint") is True
    )
    ingress = next(
        item
        for item in agent.inputs
        if item.metadata.get("basis") == "source_bound_runtime_ingress"
    )
    assert ingress.kind == "user"
    assert ingress.metadata["ingress_framework"] == "cli"
    assert ingress.metadata["runtime_invocation_proven"] is True

    path = next(
        item
        for item in graph.attack_paths
        if item.path_id == "PATH001"
        and item.agent == agent.name
        and item.nodes[-2:] == ["Bash", "process.execute"]
    )
    assert path.metadata["basis"] == "source_bound_ingress_authority"
    assert path.metadata["ingress_basis"] == "source_bound_runtime_ingress"



def test_dotnet_console_input_binds_to_agent_attack_path(tmp_path: Path) -> None:
    (tmp_path / "Program.cs").write_text(
        r"""
using System.Diagnostics;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

static string RunCommand(string command)
{
    Process.Start(command);
    return "ok";
}

AIAgent agent = chatClient.AsAIAgent(
    name: "OpsAgent",
    tools: [AIFunctionFactory.Create(RunCommand)]);

string? prompt = Console.ReadLine();
await agent.RunAsync(prompt);
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "OpsAgent")
    ingress = next(
        item
        for item in agent.inputs
        if item.metadata.get("basis") == "source_bound_runtime_ingress"
    )
    assert ingress.metadata["ingress_framework"] == "dotnet_runtime"
    assert ingress.metadata["runtime_invocation_proven"] is True

    path = next(
        item
        for item in graph.attack_paths
        if item.path_id == "PATH001"
        and item.agent == "OpsAgent"
        and item.nodes[-2:] == ["RunCommand", "process.execute"]
    )
    assert path.metadata["basis"] == "source_bound_ingress_authority"


def test_dotnet_hardcoded_runtime_input_does_not_become_untrusted(
    tmp_path: Path,
) -> None:
    (tmp_path / "Program.cs").write_text(
        r"""
using System.Diagnostics;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

static string RunCommand(string command)
{
    Process.Start(command);
    return "ok";
}

AIAgent agent = chatClient.AsAIAgent(
    name: "OpsAgent",
    tools: [AIFunctionFactory.Create(RunCommand)]);

string prompt = "fixed health check";
await agent.RunAsync(prompt);
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "OpsAgent")

    assert not any(
        item.metadata.get("basis") == "source_bound_runtime_ingress"
        for item in agent.inputs
    )
    assert not any(
        item.path_id == "PATH001" and item.agent == "OpsAgent"
        for item in graph.attack_paths
    )
