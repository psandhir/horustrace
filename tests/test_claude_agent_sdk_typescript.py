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


def test_claude_typescript_preset_projects_material_builtin_authority(
    tmp_path: Path,
) -> None:
    path = _write(
        tmp_path,
        """
import { query } from "@anthropic-ai/claude-agent-sdk";

async function run() {
  for await (const message of query({
    prompt: "inspect",
    options: {
      tools: { type: "preset", preset: "claude_code" },
      permissionMode: "default",
    },
  })) {
    console.log(message);
  }
}
""",
    )

    graph = scan_claude_agent_sdk_typescript_file(path)
    agent = next(item for item in graph.agents if item.metadata.get("language") == "typescript")

    assert agent.metadata["tool_surface"] == "preset:claude_code"
    names = {tool.name for tool in agent.tools}
    assert {"Read", "Write", "Bash", "WebFetch", "WebSearch"} <= names
    assert "process.execute" in next(
        tool for tool in agent.tools if tool.name == "Bash"
    ).capabilities


def test_claude_typescript_allowed_tools_restrict_implicit_default(
    tmp_path: Path,
) -> None:
    path = _write(
        tmp_path,
        """
import { query } from "@anthropic-ai/claude-agent-sdk";

const options = {
  allowedTools: ["Read", "Write"],
  permissionMode: "bypassPermissions",
};

async function run() {
  for await (const message of query({ prompt: "inspect", options })) {
    console.log(message);
  }
}
""",
    )

    graph = scan_claude_agent_sdk_typescript_file(path)
    agent = next(item for item in graph.agents if item.name == "options")

    assert {tool.name for tool in agent.tools} == {"Read", "Write"}
    assert agent.metadata["tool_surface"] == "restricted_default"
    assert agent.metadata["tool_surface_restricted_by_allowed_tools"] is True


def test_claude_typescript_imported_option_builder_is_resolved(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path,
        """
export function makeQueryOptions(opts: { cwd?: string }) {
  return {
    allowedTools: ["Read", "Write", "Edit", "Glob", "Grep", "Bash"] as string[],
    permissionMode: "bypassPermissions" as const,
    cwd: opts.cwd,
  };
}
""",
        "client.ts",
    )
    path = _write(
        tmp_path,
        """
import { query } from "@anthropic-ai/claude-agent-sdk";
import { makeQueryOptions } from "./client.js";

const options = makeQueryOptions({ cwd: "/workspace" });
const optionsWithAbort = {
  ...options,
  abortController: controller,
};

async function run() {
  for await (const message of query({ prompt: "inspect", options: optionsWithAbort })) {
    console.log(message);
  }
}
""",
        "agent.ts",
    )

    graph = scan_claude_agent_sdk_typescript_file(path)
    agent = next(item for item in graph.agents if item.name == "optionsWithAbort")

    assert {tool.name for tool in agent.tools} == {
        "Read",
        "Write",
        "Edit",
        "Glob",
        "Grep",
        "Bash",
    }
    assert agent.metadata["permission_mode"] == "bypassPermissions"
    assert agent.metadata["tool_surface"] == "restricted_default"
    assert "process.execute" in next(
        tool for tool in agent.tools if tool.name == "Bash"
    ).capabilities


def test_claude_typescript_composed_builder_constraints_survive_typed_spread(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path,
        """
export function makeQueryOptions() {
  return {
    allowedTools: ["Read", "Write", "Edit", "Glob", "Grep", "Bash"] as string[],
    permissionMode: "bypassPermissions" as const,
  };
}
""",
        "client.ts",
    )
    path = _write(
        tmp_path,
        """
import { query, type Options } from "@anthropic-ai/claude-agent-sdk";
import { makeQueryOptions } from "./client.js";

const options: Options = makeQueryOptions();
const optionsWithAbort: Options = {
  ...options,
  abortController: controller,
};

async function run() {
  for await (const message of query({ prompt: "inspect", options: optionsWithAbort })) {
    console.log(message);
  }
}
""",
        "agent.ts",
    )

    graph = scan_claude_agent_sdk_typescript_file(path)
    agent = next(item for item in graph.agents if item.name == "optionsWithAbort")

    assert {tool.name for tool in agent.tools} == {
        "Read",
        "Write",
        "Edit",
        "Glob",
        "Grep",
        "Bash",
    }
    assert agent.metadata["tool_surface"] == "restricted_default"
    assert agent.metadata["explicit_allowed_tool_surface"] == [
        "Read",
        "Write",
        "Edit",
        "Glob",
        "Grep",
        "Bash",
    ]


def test_claude_typescript_imported_deny_controls_are_enforced(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path,
        """
export const REVIEW_DISALLOWED_TOOLS = [
  "Write", "Edit", "NotebookEdit", "WebFetch", "WebSearch"
];

export const REVIEW_DENY_RULES = [
  ...REVIEW_DISALLOWED_TOOLS,
  "Bash(git push:*)",
  "Bash(git commit:*)",
];
""",
        "readonly.ts",
    )
    _write(
        tmp_path,
        """
import type { Options } from "@anthropic-ai/claude-agent-sdk";
import { REVIEW_DENY_RULES, REVIEW_DISALLOWED_TOOLS } from "./readonly.js";

export function buildReviewOptions(): Options {
  return {
    permissionMode: "default",
    canUseTool: makeReviewCanUseTool(),
    hooks: { PreToolUse: [{ hooks: [makeReviewGuardHook()] }] },
    disallowedTools: REVIEW_DISALLOWED_TOOLS,
    settings: { permissions: { deny: REVIEW_DENY_RULES } },
  };
}
""",
        "options.ts",
    )
    path = _write(
        tmp_path,
        """
import { query } from "@anthropic-ai/claude-agent-sdk";
import { buildReviewOptions } from "./options.js";

async function run() {
  for await (const message of query({
    prompt: "review",
    options: buildReviewOptions(),
  })) {
    console.log(message);
  }
}
""",
        "agent.ts",
    )

    graph = scan_claude_agent_sdk_typescript_file(path)
    agent = next(item for item in graph.agents if item.name.startswith("buildReviewOptions@"))

    names = {tool.name for tool in agent.tools}
    assert {"Write", "Edit", "NotebookEdit", "WebFetch", "WebSearch"}.isdisjoint(names)
    assert {"Read", "Glob", "Grep", "Bash"} <= names
    assert agent.metadata["can_use_tool_configured"] is True
    assert agent.metadata["pre_tool_use_guard"] is True
    assert agent.metadata["enforcing_tool_control"] is True
    assert "Write" in agent.metadata["settings_deny_rules"]

    bash = next(tool for tool in agent.tools if tool.name == "Bash")
    assert bash.metadata["runtime_controlled"] is True
    assert "Bash(git push:*)" in bash.metadata["scoped_deny_rules"]
