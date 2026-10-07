from pathlib import Path

from horustrace.adapters.anthropic_managed_agents_typescript import (
    is_anthropic_managed_agents_typescript_file,
    scan_anthropic_managed_agents_typescript_file,
)
from horustrace.scanner import scan


def _write(tmp_path: Path, source: str, name: str) -> Path:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return path


def test_managed_agents_typescript_resolves_imported_builder(tmp_path: Path) -> None:
    _write(
        tmp_path,
        """
export const HUBSPOT_MCP_SERVER_NAME = "hubspot";
export const GMAIL_MCP_SERVER_NAME = "gmail";
export const SLACK_MCP_SERVER_NAME = "slack";
export const RESEARCH_MCP_SERVER_NAME = "research";

export function buildAgentParams(opts: {
  hubspotMcpUrl: string;
  gmailMcpUrl: string;
  slackMcpUrl: string;
  researchMcpUrl?: string;
}) {
  const mcpServers = [
    { type: "url", name: HUBSPOT_MCP_SERVER_NAME, url: opts.hubspotMcpUrl },
    { type: "url", name: GMAIL_MCP_SERVER_NAME, url: opts.gmailMcpUrl },
    { type: "url", name: SLACK_MCP_SERVER_NAME, url: opts.slackMcpUrl },
  ];
  const tools = [
    {
      type: "mcp_toolset",
      mcp_server_name: HUBSPOT_MCP_SERVER_NAME,
      default_config: {
        enabled: true,
        permission_policy: { type: "always_allow" },
      },
    },
    {
      type: "mcp_toolset",
      mcp_server_name: GMAIL_MCP_SERVER_NAME,
      default_config: {
        enabled: true,
        permission_policy: { type: "always_allow" },
      },
    },
    {
      type: "mcp_toolset",
      mcp_server_name: SLACK_MCP_SERVER_NAME,
      default_config: {
        enabled: true,
        permission_policy: { type: "always_allow" },
      },
    },
  ];

  if (opts.researchMcpUrl) {
    mcpServers.push({
      type: "url",
      name: RESEARCH_MCP_SERVER_NAME,
      url: opts.researchMcpUrl,
    });
    tools.push({
      type: "mcp_toolset",
      mcp_server_name: RESEARCH_MCP_SERVER_NAME,
      default_config: {
        enabled: true,
        permission_policy: { type: "always_allow" },
      },
    });
  }

  return {
    model: "claude-opus-4-7",
    name: "multi-thread-nudge",
    mcp_servers: mcpServers,
    tools,
  };
}
""",
        "agent/agent-definition.ts",
    )
    path = _write(
        tmp_path,
        """
import Anthropic from "@anthropic-ai/sdk";
import { buildAgentParams } from "../agent/agent-definition.js";

const client = new Anthropic();
const hubspotMcpUrl = process.env.HUBSPOT_MCP_URL;
const gmailMcpUrl = process.env.GMAIL_MCP_URL;
const slackMcpUrl = process.env.SLACK_MCP_URL;
const researchMcpUrl = process.env.RESEARCH_MCP_URL || undefined;

const agent = await client.beta.agents.create({
  ...buildAgentParams({
    hubspotMcpUrl,
    gmailMcpUrl,
    slackMcpUrl,
    researchMcpUrl,
  }),
  betas: ["managed-agents-2026-04-01"],
});
""",
        "scripts/create-agent.ts",
    )

    assert is_anthropic_managed_agents_typescript_file(path)
    graph = scan_anthropic_managed_agents_typescript_file(path)

    assert len(graph.agents) == 1
    agent = graph.agents[0]
    assert agent.name == "multi-thread-nudge"
    assert agent.metadata["model"] == "claude-opus-4-7"
    assert agent.metadata["agent_builder"] == "buildAgentParams"

    servers = {server.name: server for server in agent.mcp_servers}
    assert set(servers) == {"hubspot", "gmail", "slack", "research"}
    assert all(server.metadata["dynamic_mcp_endpoint"] is True for server in servers.values())
    assert all(server.approval is False for server in servers.values())
    assert servers["research"].metadata["conditional"] is True


def test_repository_scan_includes_managed_agents_typescript(tmp_path: Path) -> None:
    _write(
        tmp_path,
        """
export const SERVER = "partner";

export function buildAgentParams(opts: { url: string }) {
  const mcpServers = [{ type: "url", name: SERVER, url: opts.url }];
  const tools = [{
    type: "mcp_toolset",
    mcp_server_name: SERVER,
    default_config: { permission_policy: { type: "always_allow" } },
  }];
  return {
    name: "managed-ts",
    model: "claude-sonnet-4-6",
    mcp_servers: mcpServers,
    tools,
  };
}
""",
        "agent/config.ts",
    )
    _write(
        tmp_path,
        """
import Anthropic from "@anthropic-ai/sdk";
import { buildAgentParams } from "../agent/config.js";

const client = new Anthropic();
const agent = await client.beta.agents.create({
  ...buildAgentParams({ url: process.env.MCP_URL! }),
});
""",
        "scripts/create.ts",
    )

    graph, _ = scan(tmp_path)

    agent = next(
        item
        for item in graph.agents
        if item.name == "managed-ts"
        and item.metadata.get("language") == "typescript"
    )
    assert agent.metadata["managed_runtime"] is True
    assert {server.name for server in agent.mcp_servers} == {"partner"}


def test_managed_agents_typescript_preserves_canonical_model_provenance(
    tmp_path: Path,
) -> None:
    path = _write(
        tmp_path,
        """
import Anthropic from "@anthropic-ai/sdk";

const client = new Anthropic();
const agent = await client.beta.agents.create({
  name: "research",
  model: "claude-opus-4-7",
  tools: [],
  betas: ["managed-agents-2026-04-01"],
});
""",
        "create-agent.ts",
    )

    graph = scan_anthropic_managed_agents_typescript_file(path)
    agent = graph.agents[0]

    assert agent.metadata["model"] == "claude-opus-4-7"
    assert agent.metadata["model_provider"] == "anthropic"
    assert agent.metadata["model_hosting"] == "provider_hosted"
    assert agent.metadata["model_resolution"] == "resolved_identifier"

