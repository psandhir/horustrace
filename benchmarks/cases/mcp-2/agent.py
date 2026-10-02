from pydantic_ai import Agent
from pydantic_ai.mcp import MCPServerStdio

server = MCPServerStdio(
    "npx",
    args=["-y", "@modelcontextprotocol/server-filesystem", "."],
)
agent = Agent("openai:gpt-4o", mcp_servers=[server])
