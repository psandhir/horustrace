from pathlib import Path

from horustrace.adapters.amazon_strands_typescript import (
    is_amazon_strands_typescript_file,
    scan_amazon_strands_typescript_file,
)
from horustrace.scanner import scan


def write(tmp_path: Path, text: str, name: str = "agent.ts") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_strands_typescript_agent_tool_mcp_and_delegation(tmp_path: Path) -> None:
    path = write(
        tmp_path,
        """
import { Agent, McpClient, tool } from '@strands-agents/sdk'
import { fileEditor } from '@strands-agents/sdk/vended-tools/file-editor'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'
import z from 'zod'

const publishTicket = tool({
  name: 'publish_ticket',
  description: 'Publish support ticket',
  inputSchema: z.object({ body: z.string() }),
  callback: async ({ body }) => {
    return fetch('https://tickets.example.test/api', {
      method: 'POST',
      body: JSON.stringify({ body }),
    })
  },
})

const docs = new McpClient({
  transport: new StdioClientTransport({
    command: 'uvx',
    args: ['awslabs.aws-documentation-mcp-server@latest'],
  }),
})

const specialist = new Agent({
  name: 'specialist',
  tools: [publishTicket],
})

const root = new Agent({
  name: 'root',
  systemPrompt: 'Coordinate the work',
  tools: [fileEditor, docs, specialist.asTool()],
})
""",
    )

    assert is_amazon_strands_typescript_file(path)
    graph = scan_amazon_strands_typescript_file(path)

    root = next(item for item in graph.agents if item.name == "root")
    specialist = next(item for item in graph.agents if item.name == "specialist")

    editor = next(item for item in root.tools if item.name == "fileEditor")
    assert editor.capabilities == {"data.read", "data.write"}

    server = next(item for item in root.mcp_servers if item.name == "docs")
    assert server.transport == "stdio"
    assert server.command == "uvx"
    assert server.args == ["awslabs.aws-documentation-mcp-server@latest"]

    publish = next(item for item in specialist.tools if item.name == "publish_ticket")
    assert "network.external" in publish.capabilities
    assert "external.write" in publish.capabilities
    assert [item.target for item in publish.destinations] == [
        "https://tickets.example.test/api"
    ]

    delegated = next(item for item in root.tools if item.kind == "delegated_agent")
    assert delegated.name == "specialist"
    assert "agent.delegate" in delegated.capabilities
    assert root.metadata["delegates_to"] == ["specialist"]
    assert root.identities[0].credential_source == "aws_default_credential_chain"


def test_repository_scan_dispatches_only_strands_typescript(tmp_path: Path) -> None:
    write(
        tmp_path,
        """
import { Agent } from '@strands-agents/sdk'
const agent = new Agent({ systemPrompt: 'hello' })
""",
    )
    write(
        tmp_path,
        """
const unrelated = { Agent: true }
""",
        "unrelated.ts",
    )

    graph, _ = scan(tmp_path)
    agents = [item for item in graph.agents if item.metadata.get("language") == "typescript"]
    assert len(agents) == 1
    assert agents[0].name == "agent"
