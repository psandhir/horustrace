from pathlib import Path

from horustrace.adapters.claude_agent_sdk_typescript import (
    is_claude_agent_sdk_typescript_file,
    scan_claude_agent_sdk_typescript_file,
)
from horustrace.scanner import scan


def _write(tmp_path: Path, source: str, name: str = "agent.ts") -> Path:
    path = tmp_path / name
    path.write_text(source, encoding="utf-8")
    return path


def test_claude_typescript_builtin_permissions_and_filesystem_scope(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
import { query } from "@anthropic-ai/claude-agent-sdk";

const options = {
  tools: ["Read", "Bash", "WebFetch"],
  allowedTools: ["Read"],
  permissionMode: "default",
  cwd: "/workspace",
};

async function run() {
  for await (const message of query({ prompt: "inspect", options })) {
    console.log(message);
  }
}
""",
    )

    assert is_claude_agent_sdk_typescript_file(path)
    graph = scan_claude_agent_sdk_typescript_file(path)
    agent = next(item for item in graph.agents if item.name == "options")

    read = next(item for item in agent.tools if item.name == "Read")
    bash = next(item for item in agent.tools if item.name == "Bash")
    web = next(item for item in agent.tools if item.name == "WebFetch")

    assert read.approval is False
    assert "process.execute" in bash.capabilities
    assert {item.selector for item in bash.resources} == {"/workspace"}
    assert "network.external" in web.capabilities
    assert web.destinations[0].target == "<model-selected-url>"


def test_claude_typescript_sdk_mcp_and_subagent(tmp_path: Path) -> None:
    _write(
        tmp_path,
        """
import {
  query,
  tool,
  createSdkMcpServer,
} from "@anthropic-ai/claude-agent-sdk";
import { z } from "zod";

const deploy = tool(
  "deploy",
  "Deploy release",
  { version: z.string() },
  async ({ version }) => {
    await fetch("https://deploy.example.com/release", {
      method: "POST",
      body: JSON.stringify({ version }),
    });
    return { content: [{ type: "text", text: "ok" }] };
  },
);

const ops = createSdkMcpServer({
  name: "ops",
  version: "1.0",
  tools: [deploy],
});

const options = {
  tools: ["Read", "Agent"],
  mcpServers: { ops },
  allowedTools: ["mcp__ops__deploy"],
  agents: {
    reviewer: {
      description: "reviewer",
      prompt: "review",
      tools: ["Read", "WebFetch"],
    },
  },
};

async function run() {
  for await (const message of query({ prompt: "deploy and review", options })) {
    console.log(message);
  }
}
""",
    )

    graph, _ = scan(tmp_path)
    root = next(
        item
        for item in graph.agents
        if item.name == "options" and item.metadata.get("language") == "typescript"
    )
    reviewer = next(item for item in graph.agents if item.name == "reviewer")

    server = next(item for item in root.mcp_servers if item.name == "ops")
    assert server.metadata["discovered_tools"] == ["deploy"]
    assert "external.write" in server.metadata["discovered_tool_capabilities"]
    assert server.metadata["auto_approved_tool_rules"] == ["mcp__ops__deploy"]

    delegated = next(item for item in root.tools if item.kind == "delegated_agent")
    assert delegated.metadata["delegate_target"] == "reviewer"
    assert "agent.delegate" in delegated.capabilities
    assert "network.external" in delegated.capabilities
    assert any(
        destination.target == "<model-selected-url>"
        for destination in reviewer.effective_destinations
    )
