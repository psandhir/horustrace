import json
from pathlib import Path

from horustrace.cli import main
from horustrace.source_context import (
    classify_source_context,
    is_non_runtime_source_context,
)


def test_source_context_classification() -> None:
    assert classify_source_context(Path("src/app/agent.py")) == "runtime"
    assert classify_source_context(Path("src/cli.py")) == "cli"
    assert (
        classify_source_context(
            Path("backend/scripts/manual_task_continuity_check.py")
        )
        == "application-support"
    )
    assert classify_source_context(Path("backend/tests/test_agent.py")) == "test"
    assert classify_source_context(Path("autogen/adapter.test.py")) == "test"
    assert classify_source_context(Path("claude/commerce/sdk_conformance.py")) == "test"
    assert classify_source_context(Path("interchange/conformance/vectors.json")) == "test"
    assert classify_source_context(Path("adapter.spec.mjs")) == "test"
    assert classify_source_context(Path("examples/demo_agent.py")) == "example"
    assert classify_source_context(Path("openai-agents/example_openai_agents.py")) == "example"
    assert classify_source_context(Path("ag-ui/tool.example.json")) == "example"
    assert classify_source_context(Path("adk_training/lesson_01/agent.py")) == "tutorial"
    assert classify_source_context(Path("notebooks/risky.ipynb")) == "notebook"
    assert classify_source_context(Path("templates/agent.py")) == "template-generated"
    assert classify_source_context(Path("schema.generated.json")) == "template-generated"
    assert classify_source_context(None) == "unknown"



def test_source_context_is_scoped_to_scan_root() -> None:
    root = Path("/tmp/test_fixture_checkout")
    runtime = root / "src" / "agent.py"

    assert classify_source_context(runtime) == "test"
    assert classify_source_context(runtime, root=root) == "runtime"


def test_non_runtime_agent_authority_is_not_promoted_to_live_attack_path(
    tmp_path: Path,
) -> None:
    conformance = tmp_path / "openai-agents" / "conformance"
    conformance.mkdir(parents=True)
    (conformance / "agent.py").write_text(
        """
from agents import Agent, Runner, function_tool
from fastapi import WebSocket

@function_tool
def clear_history():
    return None

agent = Agent(name="ConformanceAgent", tools=[clear_history])

async def websocket_handler(user_input: str, websocket: WebSocket):
    return Runner.run_streamed(agent, input=user_input)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "ConformanceAgent")

    assert agent.metadata["source_context"] == "test"
    assert any(item.agent == "ConformanceAgent" for item in findings)
    assert all(
        item.source_context == "test"
        for item in findings
        if item.agent == "ConformanceAgent"
    )
    assert not any(
        item.agent == "ConformanceAgent"
        for item in graph.attack_paths
    )

def test_non_runtime_source_contexts_include_operational_support() -> None:
    assert is_non_runtime_source_context("cli")
    assert is_non_runtime_source_context("application-support")
    assert is_non_runtime_source_context("test")
    assert is_non_runtime_source_context("example")
    assert not is_non_runtime_source_context("runtime")
    assert not is_non_runtime_source_context("unknown")


def test_cli_excludes_findings_by_source_role_without_hiding_coverage(
    tmp_path: Path,
    capsys,
) -> None:
    runtime = tmp_path / "src"
    runtime.mkdir()
    (runtime / "agent.py").write_text(
        """
from agents import Agent, ShellTool
agent = Agent(name="runtime", tools=[ShellTool(needs_approval=False)])
""",
        encoding="utf-8",
    )
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_agent.py").write_text(
        """
from agents import Agent, ShellTool
agent = Agent(name="test", tools=[ShellTool(needs_approval=False)])
""",
        encoding="utf-8",
    )

    assert main([
        "scan",
        str(tmp_path),
        "--format",
        "json",
        "--fail-on",
        "none",
        "--exclude-source-role",
        "test",
    ]) == 0
    report = json.loads(capsys.readouterr().out)

    assert report["summary"]["findings_by_source_context_before_filter"]["test"] > 0
    assert report["summary"]["excluded_findings_by_source_context"]["test"] > 0
    assert report["summary"]["findings_by_source_context"].get("test", 0) == 0
    assert report["configuration"]["effective"]["exclude_source_contexts"] == ["test"]
    assert all(item["source_context"] != "test" for item in report["findings"])
    assert report["coverage"]["files_scanned"] >= 2


def test_source_context_filter_does_not_clear_incomplete_coverage(
    tmp_path: Path,
    capsys,
) -> None:
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_dynamic_mcp.py").write_text(
        """
from agents import Agent
from agents.mcp import MCPServerStreamableHttp

def endpoint():
    return "https://example.test/mcp"

server = MCPServerStreamableHttp(params={"url": endpoint()})
agent = Agent(name="dynamic", mcp_servers=[server])
""",
        encoding="utf-8",
    )

    assert main([
        "scan",
        str(tmp_path),
        "--format",
        "json",
        "--fail-on",
        "none",
        "--exclude-source-context",
        "test",
    ]) == 0
    report = json.loads(capsys.readouterr().out)

    assert report["coverage"]["incomplete"] is True
    assert any(
        item["kind"] == "dynamic_mcp_endpoint"
        for item in report["coverage"]["diagnostics"]
    )


def test_cli_rejects_unknown_source_context(tmp_path: Path, capsys) -> None:
    assert main([
        "scan",
        str(tmp_path),
        "--exclude-source-context",
        "production",
    ]) == 1
    assert "unknown source context" in capsys.readouterr().err
